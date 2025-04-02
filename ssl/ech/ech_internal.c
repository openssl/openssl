/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ech.h>
#include "../ssl_local.h"
#include "ech_local.h"
#include <openssl/rand.h>
#include "../statem/statem_local.h"
#include "internal/ech_helpers.h"
#include <openssl/kdf.h>

#ifndef OPENSSL_NO_ECH

/*
 * Strings used in ECH crypto derivations (odd format for EBCDIC goodness)
 */
/* "ech accept confirmation" */
static const char OSSL_ECH_ACCEPT_CONFIRM_STRING[] = "\x65\x63\x68\x20\x61\x63\x63\x65\x70\x74\x20\x63\x6f\x6e\x66\x69\x72\x6d\x61\x74\x69\x6f\x6e";
/* "hrr ech accept confirmation" */
static const char OSSL_ECH_HRR_CONFIRM_STRING[] = "\x68\x72\x72\x20\x65\x63\x68\x20\x61\x63\x63\x65\x70\x74\x20\x63\x6f\x6e\x66\x69\x72\x6d\x61\x74\x69\x6f\x6e";

/* ECH internal API functions */

# ifdef OSSL_ECH_SUPERVERBOSE
/* ascii-hex print a buffer nicely for debug/interop purposes */
void ossl_ech_pbuf(const char *msg, const unsigned char *buf, const size_t blen)
{
    OSSL_TRACE_BEGIN(TLS) {
        if (msg == NULL) {
            BIO_printf(trc_out, "msg is NULL\n");
        } else if (buf == NULL || blen == 0) {
            BIO_printf(trc_out, "%s: buf is %p\n", msg, (void *)buf);
            BIO_printf(trc_out, "%s: blen is %lu\n", msg, (unsigned long)blen);
        } else {
            BIO_printf(trc_out, "%s (%lu)\n", msg, (unsigned long)blen);
            BIO_dump_indent(trc_out, buf, blen, 4);
        }
    } OSSL_TRACE_END(TLS);
    return;
}

/* trace out transcript */
static void ossl_ech_ptranscript(SSL_CONNECTION *s, const char *msg)
{
    size_t hdatalen = 0;
    unsigned char *hdata = NULL;
    unsigned char ddata[EVP_MAX_MD_SIZE];
    size_t ddatalen;

    if (s == NULL)
        return;
    hdatalen = BIO_get_mem_data(s->s3.handshake_buffer, &hdata);
    ossl_ech_pbuf(msg, hdata, hdatalen);
    if (s->s3.handshake_dgst != NULL) {
        if (ssl_handshake_hash(s, ddata, sizeof(ddata), &ddatalen) == 0) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "ssl_handshake_hash failed\n");
            } OSSL_TRACE_END(TLS);
            ossl_ech_pbuf(msg, ddata, ddatalen);
        }
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "new transbuf:\n");
    } OSSL_TRACE_END(TLS);
    ossl_ech_pbuf(msg, s->ext.ech.transbuf, s->ext.ech.transbuf_len);
    return;
}
# endif

static OSSL_ECHSTORE_ENTRY *ossl_echstore_entry_dup(const OSSL_ECHSTORE_ENTRY *orig)
{
    OSSL_ECHSTORE_ENTRY *ret = NULL;

    if (orig == NULL)
        return NULL;
    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;
    ret->version = orig->version;
    if (orig->public_name != NULL) {
        ret->public_name = OPENSSL_strdup(orig->public_name);
        if (ret->public_name == NULL)
            goto err;
    }
    ret->pub_len = orig->pub_len;
    if (orig->pub != NULL) {
        ret->pub = OPENSSL_memdup(orig->pub, orig->pub_len);
        if (ret->pub == NULL)
            goto err;
    }
    ret->nsuites = orig->nsuites;
    ret->suites = OPENSSL_memdup(orig->suites, sizeof(OSSL_HPKE_SUITE) * ret->nsuites);
    if (ret->suites == NULL)
        goto err;
    ret->max_name_length = orig->max_name_length;
    ret->config_id = orig->config_id;
    if (orig->exts != NULL) {
        ret->exts = sk_OSSL_ECHEXT_deep_copy(orig->exts, ossl_echext_dup,
                                             ossl_echext_free);
        if (ret->exts == NULL)
            goto err;
    }
    ret->loadtime = orig->loadtime;
    if (orig->keyshare != NULL) {
        if (!EVP_PKEY_up_ref(orig->keyshare))
            goto err;
        ret->keyshare = orig->keyshare;
    }
    ret->for_retry = orig->for_retry;
    if (orig->encoded != NULL) {
        ret->encoded_len = orig->encoded_len;
        ret->encoded = OPENSSL_memdup(orig->encoded, ret->encoded_len);
        if (ret->encoded == NULL)
            goto err;
    }
    return ret;
err:
    ossl_echstore_entry_free(ret);
    return NULL;
}

/* duplicate an OSSL_ECHSTORE as needed */
OSSL_ECHSTORE *ossl_echstore_dup(const OSSL_ECHSTORE *old)
{
    OSSL_ECHSTORE *cp = NULL;

    if (old == NULL)
        return NULL;
    cp = OPENSSL_zalloc(sizeof(*cp));
    if (cp == NULL)
        return NULL;
    cp->libctx = old->libctx;
    if (old->propq != NULL) {
        cp->propq = OPENSSL_strdup(old->propq);
        if (cp->propq == NULL)
            goto err;
    }
    if (old->entries != NULL) {
        cp->entries = sk_OSSL_ECHSTORE_ENTRY_deep_copy(old->entries,
                                                       ossl_echstore_entry_dup,
                                                       ossl_echstore_entry_free);
        if (cp->entries == NULL)
            goto err;
    }
    return cp;
err:
    OSSL_ECHSTORE_free(cp);
    return NULL;
}

void ossl_ech_ctx_clear(OSSL_ECH_CTX *ce)
{
    if (ce == NULL)
        return;
    OSSL_ECHSTORE_free(ce->es);
    OPENSSL_free(ce->alpn_outer);
    return;
}

void ossl_ech_conn_clear(OSSL_ECH_CONN *ec)
{
    if (ec == NULL)
        return;
    OSSL_ECHSTORE_free(ec->es);
    OPENSSL_free(ec->outer_hostname);
    OPENSSL_free(ec->alpn_outer);
    OPENSSL_free(ec->former_inner);
    OPENSSL_free(ec->transbuf);
    OPENSSL_free(ec->innerch);
    OPENSSL_free(ec->grease_suite);
    OPENSSL_free(ec->sent);
    OPENSSL_free(ec->returned);
    OPENSSL_free(ec->pub);
    OSSL_HPKE_CTX_free(ec->hpke_ctx);
    EVP_PKEY_free(ec->tmp_pkey);
    OPENSSL_free(ec->encoded_inner);
    return;
}

/* called from ssl/ssl_lib.c: ossl_ssl_connection_new_int */
int ossl_ech_conn_init(SSL_CONNECTION *s, SSL_CTX *ctx,
                       const SSL_METHOD *method)
{
    memset(&s->ext.ech, 0, sizeof(s->ext.ech));
    if (ctx->ext.ech.es != NULL
        && (s->ext.ech.es = ossl_echstore_dup(ctx->ext.ech.es)) == NULL)
        goto err;
    s->ext.ech.cb = ctx->ext.ech.cb;
    if (ctx->ext.ech.alpn_outer != NULL) {
        s->ext.ech.alpn_outer = OPENSSL_memdup(ctx->ext.ech.alpn_outer,
                                               ctx->ext.ech.alpn_outer_len);
        if (s->ext.ech.alpn_outer == NULL)
            goto err;
        s->ext.ech.alpn_outer_len = ctx->ext.ech.alpn_outer_len;
    }
    /* initialise type/cid to unknown */
    s->ext.ech.attempted_type = OSSL_ECH_type_unknown;
    s->ext.ech.attempted_cid = OSSL_ECH_config_id_unset;
    if (s->ext.ech.es != NULL)
        s->ext.ech.attempted = 1;
    if ((ctx->options & SSL_OP_ECH_GREASE) != 0)
        s->options |= SSL_OP_ECH_GREASE;
    return 1;
err:
    OSSL_ECHSTORE_free(s->ext.ech.es);
    s->ext.ech.es = NULL;
    OPENSSL_free(s->ext.ech.alpn_outer);
    s->ext.ech.alpn_outer = NULL;
    s->ext.ech.alpn_outer_len = 0;
    return 0;
}

/*
 * Assemble the set of ECHConfig values to return as retry-configs.
 * The caller (stoc ECH extension handler) needs to OPENSSL_free the rcfgs
 * The rcfgs itself is missing the outer length to make it an ECHConfigList
 * so the caller adds that using WPACKET functions
 */
int ossl_ech_get_retry_configs(SSL_CONNECTION *s, unsigned char **rcfgs,
                               size_t *rcfgslen)
{
    OSSL_ECHSTORE *es = NULL;
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    int i, num = 0;
    size_t retslen = 0;
    unsigned char *tmp = NULL, *rets = NULL;

    if (s == NULL || rcfgs == NULL || rcfgslen == NULL)
        return 0;
    es = s->ext.ech.es;
    if (es != NULL && es->entries != NULL)
        num = sk_OSSL_ECHSTORE_ENTRY_num(es->entries);
    for (i = 0; i != num; i++) {
        ee = sk_OSSL_ECHSTORE_ENTRY_value(es->entries, i);
        if (ee != NULL && ee->for_retry == OSSL_ECH_FOR_RETRY) {
            tmp = (unsigned char *)OPENSSL_realloc(rets,
                                                   retslen + ee->encoded_len);
            if (tmp == NULL)
                goto err;
            rets = tmp;
            memcpy(rets + retslen, ee->encoded, ee->encoded_len);
            retslen += ee->encoded_len;
        }
    }
    *rcfgs = rets;
    *rcfgslen = retslen;
    return 1;
err:
    OPENSSL_free(rets);
    *rcfgs = NULL;
    *rcfgslen = 0;
    return 0;
}

/* GREASEy constants */
# define OSSL_ECH_MAX_GREASE_PUB 0x100 /* buffer size for 'enc' values */
# define OSSL_ECH_MAX_GREASE_CT 0x200 /* max GREASEy ciphertext we'll emit */

/*
 * Send a random value that looks like a real ECH.
 *
 * TODO(ECH): the "best" thing to do here is not yet known. For now, we do
 * GREASEing as currently (20241102) done by chrome:
 *   - always HKDF-SHA256
 *   - always AES-128-GCM
 *   - random config ID, even for requests to same server in same session
 *   - random enc
 *   - random looking payload, randomly 144, 176, 208, 240 bytes, no correlation with server
 */
int ossl_ech_send_grease(SSL_CONNECTION *s, WPACKET *pkt)
{
    OSSL_HPKE_SUITE hpke_suite_in = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE *hpke_suite_in_p = NULL;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    size_t pp_at_start = 0, pp_at_end = 0;
    size_t senderpub_len = OSSL_ECH_MAX_GREASE_PUB;
    size_t cipher_len = 0, cipher_len_jitter = 0;
    unsigned char cid, senderpub[OSSL_ECH_MAX_GREASE_PUB];
    unsigned char cipher[OSSL_ECH_MAX_GREASE_CT];

    if (s == NULL)
        return 0;
    if (s->ssl.ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    WPACKET_get_total_written(pkt, &pp_at_start);
    /* randomly select cipher_len to be one of 144, 176, 208, 244 */
    if (RAND_bytes_ex(s->ssl.ctx->libctx, &cid, 1,
                      RAND_DRBG_STRENGTH) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    cipher_len_jitter = cid % 4;
    cipher_len = 144;
    cipher_len += 32 * cipher_len_jitter;
    /* generate a random (1 octet) client id */
    if (RAND_bytes_ex(s->ssl.ctx->libctx, &cid, 1,
                      RAND_DRBG_STRENGTH) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    s->ext.ech.attempted_cid = cid;
    hpke_suite_in_p = &hpke_suite;
    if (s->ext.ech.grease_suite != NULL) {
        if (OSSL_HPKE_str2suite(s->ext.ech.grease_suite, &hpke_suite_in) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        hpke_suite_in_p = &hpke_suite_in;
    }
    if (OSSL_HPKE_get_grease_value(hpke_suite_in_p, &hpke_suite,
                                   senderpub, &senderpub_len,
                                   cipher, cipher_len,
                                   s->ssl.ctx->libctx, NULL) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!WPACKET_put_bytes_u16(pkt, s->ext.ech.attempted_type)
        || !WPACKET_start_sub_packet_u16(pkt)
        || !WPACKET_put_bytes_u8(pkt, OSSL_ECH_OUTER_CH_TYPE)
        || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
        || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
        || !WPACKET_put_bytes_u8(pkt, cid)
        || !WPACKET_sub_memcpy_u16(pkt, senderpub, senderpub_len)
        || !WPACKET_sub_memcpy_u16(pkt, cipher, cipher_len)
        || !WPACKET_close(pkt)
        ) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* record the ECH sent so we can re-tx same if we hit an HRR */
    OPENSSL_free(s->ext.ech.sent);
    WPACKET_get_total_written(pkt, &pp_at_end);
    s->ext.ech.sent_len = pp_at_end - pp_at_start;
    s->ext.ech.sent = OPENSSL_malloc(s->ext.ech.sent_len);
    if (s->ext.ech.sent == NULL) {
        s->ext.ech.sent_len = 0;
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    memcpy(s->ext.ech.sent, WPACKET_get_curr(pkt) - s->ext.ech.sent_len,
           s->ext.ech.sent_len);
    s->ext.ech.grease = OSSL_ECH_IS_GREASE;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "ECH - sending GREASE\n");
    } OSSL_TRACE_END(TLS);
    return 1;
}

/*
 * Search the ECH store for one that's a match. If no outer_name was set via
 * API then we just take the 1st match where we locally support the HPKE suite.
 * If OTOH, an outer_name was provided via API then we prefer the first that
 * matches that. Name comparison is via case-insensitive exact matches.
 */
int ossl_ech_pick_matching_cfg(SSL_CONNECTION *s, OSSL_ECHSTORE_ENTRY **ee,
                               OSSL_HPKE_SUITE *suite)
{
    int namematch = 0, nameoverride = 0, suitematch = 0, num, cind = 0;
    unsigned int csuite = 0, tsuite = 0, hnlen = 0;
    OSSL_ECHSTORE_ENTRY *lee = NULL, *tee = NULL;
    OSSL_ECHSTORE *es = NULL;
    char *hn = NULL;

    if (s == NULL || s->ext.ech.es == NULL || ee == NULL || suite == NULL)
        return 0;
    *ee = NULL;
    es = s->ext.ech.es;
    if (es->entries == NULL)
        return 0;
    num = sk_OSSL_ECHSTORE_ENTRY_num(es->entries);
    /* allow API-set pref to override */
    hn = s->ext.ech.outer_hostname;
    hnlen = (hn == NULL ? 0 : strlen(hn));
    if (hnlen != 0)
        nameoverride = 1;
    if (s->ext.ech.no_outer == 1) {
        hn = NULL;
        hnlen = 0;
        nameoverride = 1;
    }
    for (cind = 0; cind != num && (suitematch == 0 || namematch == 0); cind++) {
        lee = sk_OSSL_ECHSTORE_ENTRY_value(es->entries, cind);
        if (lee == NULL || lee->version != OSSL_ECH_RFCXXXX_VERSION)
            continue;
        if (nameoverride == 1 && hnlen == 0) {
            namematch = 1;
        } else {
            namematch = 0;
            if (hnlen == 0
                || (lee->public_name != NULL
                    && strlen(lee->public_name) == hnlen
                    && !OPENSSL_strncasecmp(hn, (char *)lee->public_name,
                                            hnlen)))
                namematch = 1;
        }
        suitematch = 0;
        for (csuite = 0; csuite != lee->nsuites && suitematch == 0; csuite++) {
            if (OSSL_HPKE_suite_check(lee->suites[csuite]) == 1) {
                if (tee == NULL) { /* remember 1st suite match for override */
                    tee = lee;
                    tsuite = csuite;
                }
                suitematch = 1;
                if (namematch == 1) { /* pick this one if both "fit" */
                    *suite = lee->suites[csuite];
                    *ee = lee;
                    break;
                }
            }
        }
    }
    if (tee != NULL && nameoverride == 1
        && (namematch == 0 || suitematch == 0)) {
        *suite = tee->suites[tsuite];
        *ee = tee;
    } else if (namematch == 0 || suitematch == 0) {
        /* no joy */
        return 0;
    }
    if (*ee == NULL || (*ee)->pub_len == 0 || (*ee)->pub == NULL)
        return 0;
    return 1;
}

/* Make up the ClientHelloInner and EncodedClientHelloInner buffers */
int ossl_ech_encode_inner(SSL_CONNECTION *s, unsigned char **encoded,
                          size_t *encoded_len)
{
    int rv = 0;
    size_t nraws = 0, ind = 0, innerlen = 0;
    WPACKET inner = { 0 }; /* "fake" pkt for inner */
    BUF_MEM *inner_mem = NULL;
    RAW_EXTENSION *raws = NULL;

    /* basic checks */
    if (s == NULL)
        return 0;
    if (s->ext.ech.es == NULL || s->clienthello == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if ((inner_mem = BUF_MEM_new()) == NULL
        || !WPACKET_init(&inner, inner_mem)
        /* We don't add the type and 3-octet header as usually done */
        /* Add ver/rnd/sess-id/suites to buffer */
        || !WPACKET_put_bytes_u16(&inner, s->client_version)
        || !WPACKET_memcpy(&inner, s->ext.ech.client_random, SSL3_RANDOM_SIZE)
        /* Session ID is forced to zero in the encoded inner */
        || !WPACKET_sub_memcpy_u8(&inner, NULL, 0)
        /* Ciphers supported */
        || !WPACKET_start_sub_packet_u16(&inner)
        || !ssl_cipher_list_to_bytes(s, SSL_get_ciphers(&s->ssl), &inner)
        || !WPACKET_close(&inner)
        /* COMPRESSION */
        || !WPACKET_start_sub_packet_u8(&inner)
        /* Add the NULL compression method */
        || !WPACKET_put_bytes_u8(&inner, 0)
        || !WPACKET_close(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Now handle extensions */
    if (!WPACKET_start_sub_packet_u16(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Grab a pointer to the already constructed extensions */
    raws = s->clienthello->pre_proc_exts;
    nraws = s->clienthello->pre_proc_exts_len;
    if (raws == NULL || nraws < TLSEXT_IDX_num_builtins) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*  We put ECH-compressed stuff first (if any), because we can */
    if (s->ext.ech.n_outer_only > 0) {
        if (!WPACKET_put_bytes_u16(&inner, TLSEXT_TYPE_outer_extensions)
            || !WPACKET_start_sub_packet_u16(&inner)
            /* redundant encoding of more-or-less the same thing */
            || !WPACKET_start_sub_packet_u8(&inner)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* add the types for each of the compressed extensions now */
        for (ind = 0; ind != s->ext.ech.n_outer_only; ind++) {
            if (!WPACKET_put_bytes_u16(&inner, s->ext.ech.outer_only[ind])) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
        /* close the 2 sub-packets with the compressed types */
        if (!WPACKET_close(&inner) || !WPACKET_close(&inner)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    /* now copy the rest, as "proper" exts, into encoded inner */
    for (ind = 0; ind < TLSEXT_IDX_num_builtins; ind++) {
        if (raws[ind].present == 0 || ossl_ech_2bcompressed(ind) == 1)
            continue;
        if (!WPACKET_put_bytes_u16(&inner, raws[ind].type)
            || !WPACKET_sub_memcpy_u16(&inner, PACKET_data(&raws[ind].data),
                                       PACKET_remaining(&raws[ind].data))) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (!WPACKET_close(&inner)  /* close the encoded inner packet */
        || !WPACKET_get_length(&inner, &innerlen)) { /* len for inner CH */
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *encoded = (unsigned char *)inner_mem->data;
    inner_mem->data = NULL; /* keep BUF_MEM_free happy */
    *encoded_len = innerlen;
    /* and clean up */
    rv = 1;
err:
    WPACKET_cleanup(&inner);
    BUF_MEM_free(inner_mem);
    return rv;
}

/*
 * Find ECH acceptance signal in a SH
 * hrr is 1 if this is for an HRR, otherwise for SH
 * acbuf is (a preallocated) 8 octet buffer
 * shbuf is a pointer to the SH buffer
 * shlen is the length of the SH buf
 * return: 1 for success, 0 otherwise
 */
int ossl_ech_find_confirm(SSL_CONNECTION *s, int hrr,
                          unsigned char acbuf[OSSL_ECH_SIGNAL_LEN])
{
    unsigned char *acp = NULL;

    if (hrr == 0) {
        acp = s->s3.server_random + SSL3_RANDOM_SIZE - OSSL_ECH_SIGNAL_LEN;
    } else { /* was set in extension handler */
        if (s->ext.ech.hrrsignal_p == NULL)
            return 0;
        acp = s->ext.ech.hrrsignal;
    }
    memcpy(acbuf, acp, OSSL_ECH_SIGNAL_LEN);
    return 1;
}

/*
 * reset the handshake buffer for transcript after ECH is good
 * buf is the data to put into the transcript (inner CH if no HRR)
 * blen is the length of buf
 * return 1 for success
 */
int ossl_ech_reset_hs_buffer(SSL_CONNECTION *s, const unsigned char *buf,
                             size_t blen)
{
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_pbuf("RESET transcript to", buf, blen);
# endif
    if (s->s3.handshake_buffer != NULL) {
        if (BIO_reset(s->s3.handshake_buffer) < 0)
            return 0;
    } else {
        s->s3.handshake_buffer = BIO_new(BIO_s_mem());
        if (s->s3.handshake_buffer == NULL)
            return 0;
        (void)BIO_set_close(s->s3.handshake_buffer, BIO_CLOSE);
    }
    EVP_MD_CTX_free(s->s3.handshake_dgst);
    s->s3.handshake_dgst = NULL;
    /* providing nothing at all is a real use (mid-HRR) */
    if (buf != NULL && blen > 0)
        BIO_write(s->s3.handshake_buffer, (void *)buf, (int)blen);
    return 1;
}

/*
 * To control the number of zeros added after an EncodedClientHello - we pad
 * to a target number of octets or, if there are naturally more, to a number
 * divisible by the defined increment (we also do the spec-recommended SNI
 * padding thing first)
 */
# define OSSL_ECH_PADDING_TARGET 128 /* ECH cleartext padded to at least this */
# define OSSL_ECH_PADDING_INCREMENT 32 /* ECH padded to a multiple of this */

/*
 * figure out how much padding for cleartext (on client)
 * ee is the chosen ECHConfig
 * return overall length to use including padding or zero on error
 *
 * "Recommended" inner SNI padding scheme as per spec (section 6.1.3)
 * Might remove the mnl stuff later - overall message padding seems
 * better really, BUT... we might want to keep this if others (e.g.
 * browsers) do it so as to not stand out compared to them.
 *
 * The "+ 9" constant below is from the specifiation and is the
 * expansion comparing a string length to an encoded SNI extension.
 * Same is true of the 31/32 formula below.
 *
 * Note that the AEAD tag will be added later, so if we e.g. have
 * a padded cleartext of 128 octets, the ciphertext will be 144
 * octets.
 */
size_t ossl_ech_calc_padding(SSL_CONNECTION *s, OSSL_ECHSTORE_ENTRY *ee,
                             size_t encoded_len)
{
    int length_of_padding = 0, length_with_snipadding = 0;
    int innersnipadding = 0, length_with_padding = 0;
    size_t mnl = 0, isnilen = 0;

    if (s == NULL || ee == NULL)
        return 0;
    mnl = ee->max_name_length;
    if (mnl != 0) {
        /* do weirder padding if SNI present in inner */
        if (s->ext.hostname != NULL) {
            isnilen = strlen(s->ext.hostname) + 9;
            innersnipadding = (mnl > isnilen) ? mnl - isnilen : 0;
        } else {
            innersnipadding = mnl + 9;
        }
    }
    /* padding is after the inner client hello has been encoded */
    length_with_snipadding = innersnipadding + encoded_len;
    length_of_padding = 31 - ((length_with_snipadding - 1) % 32);
    length_with_padding = encoded_len + length_of_padding + innersnipadding;
    /*
     * Finally - make sure final result is longer than padding target
     * and a multiple of our padding increment.
     * TODO(ECH): This is a local addition - we might take it out if
     * it makes us stick out; or if we take out the above more (uselessly:-)
     * complicated scheme, we may only need this in the end.
     */
    if ((length_with_padding % OSSL_ECH_PADDING_INCREMENT) != 0)
        length_with_padding += OSSL_ECH_PADDING_INCREMENT
            - (length_with_padding % OSSL_ECH_PADDING_INCREMENT);
    while (length_with_padding < OSSL_ECH_PADDING_TARGET)
        length_with_padding += OSSL_ECH_PADDING_INCREMENT;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EAAE: padding: mnl: %zu, lws: %d "
                   "lop: %d, clear_len (len with padding): %d, orig: %zu\n",
                   mnl, length_with_snipadding, length_of_padding,
                   length_with_padding, encoded_len);
    } OSSL_TRACE_END(TLS);
    return (size_t)length_with_padding;
}

/*
 * Calculate AAD and do ECH encryption
 * pkt is the packet to send
 * return 1 for success, other otherwise
 *
 * 1. Make up the AAD: the encoded outer, with ECH ciphertext octets zero'd
 * 2. Do the encryption
 * 3. Put the ECH back into the encoding
 * 4. Encode the outer (again!)
 */
int ossl_ech_aad_and_encrypt(SSL_CONNECTION *s, WPACKET *pkt)
{
    int rv = 0;
    size_t cipherlen = 0, aad_len = 0, mypub_len = 0, clear_len = 0;
    size_t encoded_inner_len = 0;
    unsigned char *clear = NULL, *aad = NULL, *mypub = NULL;
    unsigned char *encoded_inner = NULL, *cipher_loc = NULL;

    if (s == NULL)
        return 0;
    if (s->ext.ech.es == NULL || s->ext.ech.es->entries == NULL
        || pkt == NULL || s->ssl.ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* values calculated in tls_construct_ctos_ech */
    encoded_inner = s->ext.ech.encoded_inner;
    encoded_inner_len = s->ext.ech.encoded_inner_len;
    clear_len = s->ext.ech.clearlen;
    cipherlen = s->ext.ech.cipherlen;
    if (!WPACKET_get_total_written(pkt, &aad_len) || aad_len < 4) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    aad_len -= 4; /* ECH/HPKE aad starts after type + 3-octet len */
    aad = WPACKET_get_curr(pkt) - aad_len;
    /* where we'll replace zeros with ciphertext */
    cipher_loc = aad + s->ext.ech.cipher_offset;
    /*
     * close the extensions of the CH - we skipped doing this
     * earlier when encoding extensions, to allow for adding the
     * ECH here (when doing ECH) - see tls_construct_extensions()
     * towards the end
     */
    if (!WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_pbuf("EAAE: aad", aad, aad_len);
# endif
    clear = OPENSSL_zalloc(clear_len); /* zeros incl. padding */
    if (clear == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(clear, encoded_inner, encoded_inner_len);
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_pbuf("EAAE: padded clear", clear, clear_len);
# endif
    /* we're done with this now */
    OPENSSL_free(s->ext.ech.encoded_inner);
    s->ext.ech.encoded_inner = NULL;
    rv = OSSL_HPKE_seal(s->ext.ech.hpke_ctx, cipher_loc,
                        &cipherlen, aad, aad_len, clear, clear_len);
    OPENSSL_free(clear);
    if (rv != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_pbuf("EAAE: cipher", cipher_loc, cipherlen);
    ossl_ech_pbuf("EAAE: hpke mypub", mypub, mypub_len);
    /* re-use aad_len for tracing */
    WPACKET_get_total_written(pkt, &aad_len);
    ossl_ech_pbuf("EAAE pkt aftr", WPACKET_get_curr(pkt) - aad_len, aad_len);
# endif
    return 1;
err:
    return 0;
}

/*
 * print info about the ECH-status of an SSL connection
 * out is the BIO to use (e.g. stdout/whatever)
 * selector OSSL_ECH_SELECT_ALL or just one of the SSL_ECH values
 */
void ossl_ech_status_print(BIO *out, SSL_CONNECTION *s, int selector)
{
    int num = 0, i, has_priv, for_retry;
    size_t j;
    time_t secs = 0;
    char *pn = NULL, *ec = NULL;
    OSSL_ECHSTORE *es = NULL;

# ifdef OSSL_ECH_SUPERVERBOSE
    BIO_printf(out, "ech_status_print\n");
    BIO_printf(out, "s=%p\n", (void *)s);
# endif
    BIO_printf(out, "ech_attempted=%d\n", s->ext.ech.attempted);
    BIO_printf(out, "ech_attempted_type=0x%4x\n",
               s->ext.ech.attempted_type);
    if (s->ext.ech.attempted_cid == OSSL_ECH_config_id_unset)
        BIO_printf(out, "ech_atttempted_cid is unset\n");
    else
        BIO_printf(out, "ech_atttempted_cid=0x%02x\n",
                   s->ext.ech.attempted_cid);
    BIO_printf(out, "ech_done=%d\n", s->ext.ech.done);
    BIO_printf(out, "ech_grease=%d\n", s->ext.ech.grease);
# ifdef OSSL_ECH_SUPERVERBOSE
    BIO_printf(out, "HRR=%d\n", s->hello_retry_request);
# endif
    BIO_printf(out, "ech_backend=%d\n", s->ext.ech.backend);
    BIO_printf(out, "ech_success=%d\n", s->ext.ech.success);
    es = s->ext.ech.es;
    if (es == NULL || es->entries == NULL) {
        BIO_printf(out, "ECH cfg=NONE\n");
    } else {
        num = sk_OSSL_ECHSTORE_ENTRY_num(es->entries);
        BIO_printf(out, "%d ECHConfig values loaded\n", num);
        for (i = 0; i != num; i++) {
            if (selector != OSSL_ECHSTORE_ALL && selector != i)
                continue;
            BIO_printf(out, "cfg(%d): ", i);
            if (OSSL_ECHSTORE_get1_info(es, i, &secs, &pn, &ec,
                                        &has_priv, &for_retry) != 1) {
                OPENSSL_free(pn); /* just in case */
                OPENSSL_free(ec);
                continue;
            }
            BIO_printf(out, "ECH entry: %d public_name: %s age: %d%s\n",
                       i, pn, (int)secs, has_priv ? " (has private key)" : "");
            BIO_printf(out, "\t%s\n", ec);
            OPENSSL_free(pn);
            OPENSSL_free(ec);
        }
    }
    if (s->ext.ech.returned) {
        BIO_printf(out, "ret=");
        for (j = 0; j != s->ext.ech.returned_len; j++) {
            if (j != 0 && j % 16 == 0)
                BIO_printf(out, "\n    ");
            BIO_printf(out, "%02x:", (unsigned)(s->ext.ech.returned[j]));
        }
        BIO_printf(out, "\n");
    }
    return;
}

/*
 * Swap the inner and outer after ECH success on the client
 * return 0 for error, 1 for success
 */
int ossl_ech_swaperoo(SSL_CONNECTION *s)
{
    unsigned char *curr_buf = NULL;
    size_t curr_buflen = 0;

    if (s == NULL)
        return 0;
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_ptranscript(s, "ech_swaperoo, b4");
# endif
    /* un-stash inner key share */
    if (s->ext.ech.tmp_pkey == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    EVP_PKEY_free(s->s3.tmp.pkey);
    s->s3.tmp.pkey = s->ext.ech.tmp_pkey;
    s->s3.group_id = s->ext.ech.group_id;
    s->ext.ech.tmp_pkey = NULL;
    /*
     * When not doing HRR... fix up the transcript to reflect the inner CH.
     * If there's a client hello at the start of the buffer, then that's
     * the outer CH and we want to replace that with the inner. We need to
     * be careful that there could be early data or a server hello following
     * and we can't lose that.
     *
     * For HRR... HRR processing code has already done the necessary.
     */
    if (s->hello_retry_request == SSL_HRR_NONE) {
        BIO *handbuf = s->s3.handshake_buffer;
        PACKET pkt, subpkt;
        unsigned int mt;

        s->s3.handshake_buffer = NULL;
        if (ssl3_init_finished_mac(s) == 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            BIO_free(handbuf);
            return 0;
        }
        if (ssl3_finish_mac(s, s->ext.ech.innerch, s->ext.ech.innerch_len) == 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            BIO_free(handbuf);
            return 0;
        }
        curr_buflen = BIO_get_mem_data(handbuf, &curr_buf);
        if (PACKET_buf_init(&pkt, curr_buf, curr_buflen)
            && PACKET_get_1(&pkt, &mt)
            && mt == SSL3_MT_CLIENT_HELLO
            && PACKET_remaining(&pkt) >= 3) {
            if (!PACKET_get_length_prefixed_3(&pkt, &subpkt)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                BIO_free(handbuf);
                return 0;
            }
            if (PACKET_remaining(&pkt) > 0) {
                if (ssl3_finish_mac(s, PACKET_data(&pkt), PACKET_remaining(&pkt)) == 0) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    BIO_free(handbuf);
                    return 0;
                }
            }
            BIO_free(handbuf);
        }
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_ptranscript(s, "ech_swaperoo, after");
# endif
    /* Declare victory! */
    s->ext.ech.attempted = 1;
    s->ext.ech.success = 1;
    s->ext.ech.done = 1;
    s->ext.ech.grease = OSSL_ECH_NOT_GREASE;
    /* time to call an ECH callback, if there's one */
    if (s->ext.ech.es != NULL && s->ext.ech.done == 1
        && s->hello_retry_request != SSL_HRR_PENDING
        && s->ext.ech.cb != NULL) {
        char pstr[OSSL_ECH_PBUF_SIZE + 1] = { 0 };
        BIO *biom = BIO_new(BIO_s_mem());
        unsigned int cbrv = 0;

        if (biom == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        ossl_ech_status_print(biom, s, OSSL_ECHSTORE_ALL);
        BIO_read(biom, pstr, OSSL_ECH_PBUF_SIZE);
        cbrv = s->ext.ech.cb(&s->ssl, pstr);
        BIO_free(biom);
        if (cbrv != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    return 1;
}

/*
 * do the HKDF for ECH acceptance checking
 * md is the h/s hash
 * for_hrr is 1 if we're doing a HRR
 * hashval/hashlen is the transcript hash
 * hoval is the output, with the ECH acceptance signal
 * return 1 for good, 0 for error
 */
static int ech_hkdf_extract_wrap(SSL_CONNECTION *s, EVP_MD *md, int for_hrr,
                                 unsigned char *hashval, size_t hashlen,
                                 unsigned char hoval[OSSL_ECH_SIGNAL_LEN])
{
    int rv = 0;
    unsigned char notsecret[EVP_MAX_MD_SIZE], zeros[EVP_MAX_MD_SIZE];
    size_t retlen = 0, labellen = 0;
    EVP_PKEY_CTX *pctx = NULL;
    const char *label = NULL;
    unsigned char *p = NULL;

    if (for_hrr == 1) {
        label = OSSL_ECH_HRR_CONFIRM_STRING;
        labellen = sizeof(OSSL_ECH_HRR_CONFIRM_STRING) - 1;
    } else {
        label = OSSL_ECH_ACCEPT_CONFIRM_STRING;
        labellen = sizeof(OSSL_ECH_ACCEPT_CONFIRM_STRING) - 1;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_pbuf("cc: label", (unsigned char *)label, labellen);
# endif
    memset(zeros, 0, EVP_MAX_MD_SIZE);
    /* We don't seem to have an hkdf-extract that's exposed by libcrypto */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL
        || EVP_PKEY_derive_init(pctx) != 1
        || EVP_PKEY_CTX_hkdf_mode(pctx,
                                  EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1
        || EVP_PKEY_CTX_set_hkdf_md(pctx, md) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* pick correct client_random */
    if (s->server)
        p = s->s3.client_random;
    else
        p = s->ext.ech.client_random;
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_pbuf("cc: client_random", p, SSL3_RANDOM_SIZE);
# endif
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, p, SSL3_RANDOM_SIZE) != 1
        || EVP_PKEY_CTX_set1_hkdf_salt(pctx, zeros, hashlen) != 1
        || EVP_PKEY_derive(pctx, NULL, &retlen) != 1
        || hashlen != retlen
        || EVP_PKEY_derive(pctx, notsecret, &retlen) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_pbuf("cc: notsecret", notsecret, hashlen);
# endif
    if (hashlen < OSSL_ECH_SIGNAL_LEN
        || !tls13_hkdf_expand(s, md, notsecret,
                              (const unsigned char *)label, labellen,
                              hashval, hashlen, hoval,
                              OSSL_ECH_SIGNAL_LEN, 1)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    rv = 1;
err:
    EVP_PKEY_CTX_free(pctx);
    return rv;
}

/*
 * ECH accept_confirmation calculation
 * for_hrr is 1 if this is for an HRR, otherwise for SH
 * ac is (a caller allocated) 8 octet buffer
 * shbuf is a pointer to the SH buffer (incl. the type+3-octet length)
 * shlen is the length of the SH buf
 * return: 1 for success, 0 otherwise
 *
 * This is a magic value in the ServerHello.random lower 8 octets
 * that is used to signal that the inner worked.
 *
 * As per spec:
 *
 * accept_confirmation = HKDF-Expand-Label(
 *         HKDF-Extract(0, ClientHelloInner.random),
 *         "ech accept confirmation",
 *         transcript_ech_conf,
 *         8)
 *
 * transcript_ech_conf = ClientHelloInner..ServerHello
 *         with last 8 octets of ServerHello.random==0x00
 *
 * and with differences due to HRR
 */
int ossl_ech_calc_confirm(SSL_CONNECTION *s, int for_hrr,
                          unsigned char acbuf[OSSL_ECH_SIGNAL_LEN],
                          const size_t shlen)
{
    int rv = 0;
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned char *tbuf = NULL, *conf_loc = NULL;
    unsigned char *fixedshbuf = NULL;
    size_t fixedshbuf_len = 0, tlen = 0, chend = 0;
    /* shoffset is: 4 + 2 + 32 - 8 */
    size_t shoffset = SSL3_HM_HEADER_LENGTH + sizeof(uint16_t)
                      + SSL3_RANDOM_SIZE - OSSL_ECH_SIGNAL_LEN;
    unsigned int hashlen = 0;
    unsigned char hashval[EVP_MAX_MD_SIZE];

    if ((md = (EVP_MD *)ssl_handshake_md(s)) == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_ECH_REQUIRED);
        goto end;
    }
    if (ossl_ech_intbuf_fetch(s, &tbuf, &tlen) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_ECH_REQUIRED);
        goto end;
    }
    chend = tlen - shlen - 4;
    fixedshbuf_len = shlen + 4;
    if (s->server) {
        chend = tlen - shlen;
        fixedshbuf_len = shlen;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_pbuf("cx: tbuf b4-b4", tbuf, tlen);
# endif
    /* put zeros in correct place */
    if (for_hrr == 0) { /* zap magic octets at fixed place for SH */
        conf_loc = tbuf + chend + shoffset;
    } else {
        if (s->server == 1) { /* we get to say where we put ECH:-) */
            conf_loc = tbuf + tlen - OSSL_ECH_SIGNAL_LEN;
        } else {
            if (s->ext.ech.hrrsignal_p == NULL) {
                /* No ECH found so we'll exit, but set random output */
                if (RAND_bytes_ex(s->ssl.ctx->libctx, acbuf,
                                  OSSL_ECH_SIGNAL_LEN,
                                  RAND_DRBG_STRENGTH) <= 0) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_ECH_REQUIRED);
                    goto end;
                }
                rv = 1;
                goto end;
            }
            conf_loc = s->ext.ech.hrrsignal_p;
        }
    }
    memset(conf_loc, 0, OSSL_ECH_SIGNAL_LEN);
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_pbuf("cx: tbuf after", tbuf, tlen);
# endif
    if ((ctx = EVP_MD_CTX_new()) == NULL
        || EVP_DigestInit_ex(ctx, md, NULL) <= 0
        || EVP_DigestUpdate(ctx, tbuf, tlen) <= 0
        || EVP_DigestFinal_ex(ctx, hashval, &hashlen) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto end;
    }
    EVP_MD_CTX_free(ctx);
    ctx = NULL;
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_pbuf("cx: hashval", hashval, hashlen);
# endif
    /* calculate and set the final output */
    if (ech_hkdf_extract_wrap(s, md, for_hrr, hashval, hashlen, acbuf) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto end;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ossl_ech_pbuf("cx: result", acbuf, OSSL_ECH_SIGNAL_LEN);
# endif
    /* put confirm value back into transcript */
    if (s->ext.ech.hrrsignal_p == NULL)
        memcpy(conf_loc, acbuf, OSSL_ECH_SIGNAL_LEN);
    else
        memcpy(conf_loc, s->ext.ech.hrrsignal, OSSL_ECH_SIGNAL_LEN);
    /* on a server, we need to reset the hs buffer now */
    if (s->server && s->hello_retry_request == SSL_HRR_NONE)
        ossl_ech_reset_hs_buffer(s, s->ext.ech.innerch, s->ext.ech.innerch_len);
    if (s->server && s->hello_retry_request == SSL_HRR_COMPLETE)
        ossl_ech_reset_hs_buffer(s, tbuf, tlen - fixedshbuf_len);
    rv = 1;
end:
    OPENSSL_free(fixedshbuf);
    EVP_MD_CTX_free(ctx);
    return rv;
}

int ossl_ech_intbuf_add(SSL_CONNECTION *s, const unsigned char *buf,
                        size_t blen, int hash_existing)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned int rv = 0, hashlen = 0;
    unsigned char hashval[EVP_MAX_MD_SIZE], *t1;
    size_t tlen;
    WPACKET tpkt = { 0 };
    BUF_MEM *tpkt_mem = NULL;

    if (s == NULL || buf == NULL || blen == 0)
        goto err;
    if (hash_existing == 1) {
        /* hash existing buffer, needed during HRR */
        if (s->ext.ech.transbuf == NULL
            || (md = (EVP_MD *)ssl_handshake_md(s)) == NULL
            || (ctx = EVP_MD_CTX_new()) == NULL
            || EVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVP_DigestUpdate(ctx, s->ext.ech.transbuf,
                                s->ext.ech.transbuf_len) <= 0
            || EVP_DigestFinal_ex(ctx, hashval, &hashlen) <= 0
            || (tpkt_mem = BUF_MEM_new()) == NULL
            || !WPACKET_init(&tpkt, tpkt_mem)
            || !WPACKET_put_bytes_u8(&tpkt, SSL3_MT_MESSAGE_HASH)
            || !WPACKET_put_bytes_u24(&tpkt, hashlen)
            || !WPACKET_memcpy(&tpkt, hashval, hashlen)
            || !WPACKET_get_length(&tpkt, &tlen)
            || (t1 = OPENSSL_realloc(s->ext.ech.transbuf, tlen + blen)) == NULL)
            goto err;
        s->ext.ech.transbuf = t1;
        memcpy(s->ext.ech.transbuf, tpkt_mem->data, tlen);
        memcpy(s->ext.ech.transbuf + tlen, buf, blen);
        s->ext.ech.transbuf_len = tlen + blen;
    } else {
        /* just add new octets */
        if ((t1 = OPENSSL_realloc(s->ext.ech.transbuf,
                                   s->ext.ech.transbuf_len + blen)) == NULL)
            goto err;
        s->ext.ech.transbuf = t1;
        memcpy(s->ext.ech.transbuf + s->ext.ech.transbuf_len, buf, blen);
        s->ext.ech.transbuf_len += blen;
    }
    rv = 1;
err:
    BUF_MEM_free(tpkt_mem);
    WPACKET_cleanup(&tpkt);
    EVP_MD_CTX_free(ctx);
    return rv;
}

int ossl_ech_intbuf_fetch(SSL_CONNECTION *s, unsigned char **buf, size_t *blen)
{
    if (s == NULL || buf == NULL || blen == NULL || s->ext.ech.transbuf == NULL)
        return 0;
    *buf = s->ext.ech.transbuf;
    *blen = s->ext.ech.transbuf_len;
    return 1;
}
#endif
