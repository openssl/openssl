/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include "../ssl_local.h"
#include <openssl/trace.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include "record_local.h"
#include "internal/cryptlib.h"

static const unsigned char ssl3_pad_1[48] = {
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
};

static const unsigned char ssl3_pad_2[48] = {
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
};

/*
 * Clear the contents of an SSL3_RECORD but retain any memory allocated
 */
void SSL3_RECORD_clear(SSL3_RECORD *r, size_t num_recs)
{
    unsigned char *comp;
    size_t i;

    for (i = 0; i < num_recs; i++) {
        comp = r[i].comp;

        memset(&r[i], 0, sizeof(*r));
        r[i].comp = comp;
    }
}

void SSL3_RECORD_release(SSL3_RECORD *r, size_t num_recs)
{
    size_t i;

    for (i = 0; i < num_recs; i++) {
        OPENSSL_free(r[i].comp);
        r[i].comp = NULL;
    }
}

void SSL3_RECORD_set_seq_num(SSL3_RECORD *r, const unsigned char *seq_num)
{
    memcpy(r->seq_num, seq_num, SEQ_NUM_SIZE);
}

uint32_t ossl_get_max_early_data(SSL_CONNECTION *s)
{
    uint32_t max_early_data;
    SSL_SESSION *sess = s->session;

    /*
     * If we are a client then we always use the max_early_data from the
     * session/psksession. Otherwise we go with the lowest out of the max early
     * data set in the session and the configured max_early_data.
     */
    if (!s->server && sess->ext.max_early_data == 0) {
        if (!ossl_assert(s->psksession != NULL
                         && s->psksession->ext.max_early_data > 0)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        sess = s->psksession;
    }

    if (!s->server)
        max_early_data = sess->ext.max_early_data;
    else if (s->ext.early_data != SSL_EARLY_DATA_ACCEPTED)
        max_early_data = s->recv_max_early_data;
    else
        max_early_data = s->recv_max_early_data < sess->ext.max_early_data
                         ? s->recv_max_early_data : sess->ext.max_early_data;

    return max_early_data;
}

int ossl_early_data_count_ok(SSL_CONNECTION *s, size_t length, size_t overhead,
                             int send)
{
    uint32_t max_early_data;

    max_early_data = ossl_get_max_early_data(s);

    if (max_early_data == 0) {
        SSLfatal(s, send ? SSL_AD_INTERNAL_ERROR : SSL_AD_UNEXPECTED_MESSAGE,
                 SSL_R_TOO_MUCH_EARLY_DATA);
        return 0;
    }

    /* If we are dealing with ciphertext we need to allow for the overhead */
    max_early_data += overhead;

    if (s->early_data_count + length > max_early_data) {
        SSLfatal(s, send ? SSL_AD_INTERNAL_ERROR : SSL_AD_UNEXPECTED_MESSAGE,
                 SSL_R_TOO_MUCH_EARLY_DATA);
        return 0;
    }
    s->early_data_count += length;

    return 1;
}

int ssl3_do_uncompress(SSL_CONNECTION *ssl, SSL3_RECORD *rr)
{
#ifndef OPENSSL_NO_COMP
    int i;

    if (rr->comp == NULL) {
        rr->comp = (unsigned char *)
            OPENSSL_malloc(SSL3_RT_MAX_ENCRYPTED_LENGTH);
    }
    if (rr->comp == NULL)
        return 0;

    i = COMP_expand_block(ssl->expand, rr->comp,
                          SSL3_RT_MAX_PLAIN_LENGTH, rr->data, (int)rr->length);
    if (i < 0)
        return 0;
    else
        rr->length = i;
    rr->data = rr->comp;
#endif
    return 1;
}

int ssl3_do_compress(SSL_CONNECTION *sc, SSL3_RECORD *wr)
{
#ifndef OPENSSL_NO_COMP
    int i;

    i = COMP_compress_block(sc->compress, wr->data,
                            (int)(wr->length + SSL3_RT_MAX_COMPRESSED_OVERHEAD),
                            wr->input, (int)wr->length);
    if (i < 0)
        return 0;
    else
        wr->length = i;

    wr->input = wr->data;
#endif
    return 1;
}

/*-
 * ssl3_enc encrypts/decrypts |n_recs| records in |inrecs|. Calls SSLfatal on
 * internal error, but not otherwise. It is the responsibility of the caller to
 * report a bad_record_mac
 *
 * Returns:
 *    0: if the record is publicly invalid, or an internal error
 *    1: Success or Mac-then-encrypt decryption failed (MAC will be randomised)
 */
int ssl3_enc(SSL_CONNECTION *s, SSL3_RECORD *inrecs, size_t n_recs, int sending,
             SSL_MAC_BUF *mac, size_t macsize)
{
    SSL3_RECORD *rec;
    EVP_CIPHER_CTX *ds;
    size_t l, i;
    size_t bs;
    const EVP_CIPHER *enc;

    assert(sending);
    rec = inrecs;
    /*
     * We shouldn't ever be called with more than one record in the SSLv3 case
     */
    if (n_recs != 1)
        return 0;

    ds = s->enc_write_ctx;
    if (s->enc_write_ctx == NULL)
        enc = NULL;
    else
        enc = EVP_CIPHER_CTX_get0_cipher(s->enc_write_ctx);

    if ((s->session == NULL) || (ds == NULL) || (enc == NULL)) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
    } else {
        int provided = (EVP_CIPHER_get0_provider(enc) != NULL);

        l = rec->length;
        bs = EVP_CIPHER_CTX_get_block_size(ds);

        /* COMPRESS */

        if ((bs != 1) && !provided) {
            /*
             * We only do this for legacy ciphers. Provided ciphers add the
             * padding on the provider side.
             */
            i = bs - (l % bs);

            /* we need to add 'i-1' padding bytes */
            l += i;
            /*
             * the last of these zero bytes will be overwritten with the
             * padding length.
             */
            memset(&rec->input[rec->length], 0, i);
            rec->length += i;
            rec->input[l - 1] = (unsigned char)(i - 1);
        }

        if (EVP_CIPHER_get0_provider(enc) != NULL) {
            int outlen;

            if (!EVP_CipherUpdate(ds, rec->data, &outlen, rec->input,
                                  (unsigned int)l))
                return 0;
            rec->length = outlen;
        } else {
            if (EVP_Cipher(ds, rec->data, rec->input, (unsigned int)l) < 1) {
                /* Shouldn't happen */
                SSLfatal(s, SSL_AD_BAD_RECORD_MAC, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    }
    return 1;
}

#define MAX_PADDING 256
/*-
 * tls1_enc encrypts/decrypts |n_recs| in |recs|. Calls SSLfatal on internal
 * error, but not otherwise. It is the responsibility of the caller to report
 * a bad_record_mac - if appropriate (DTLS just drops the record).
 *
 * Returns:
 *    0: if the record is publicly invalid, or an internal error, or AEAD
 *       decryption failed, or Encrypt-then-mac decryption failed.
 *    1: Success or Mac-then-encrypt decryption failed (MAC will be randomised)
 */
int tls1_enc(SSL_CONNECTION *s, SSL3_RECORD *recs, size_t n_recs, int sending,
             SSL_MAC_BUF *macs, size_t macsize)
{
    EVP_CIPHER_CTX *ds;
    size_t reclen[SSL_MAX_PIPELINES];
    unsigned char buf[SSL_MAX_PIPELINES][EVP_AEAD_TLS1_AAD_LEN];
    int i, pad = 0, tmpr;
    size_t bs, ctr, padnum, loop;
    unsigned char padval;
    const EVP_CIPHER *enc;
    int tlstree_enc = (s->mac_flags & SSL_MAC_FLAG_WRITE_MAC_TLSTREE);

    if (n_recs == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    assert(sending);
    if (EVP_MD_CTX_get0_md(s->write_hash)) {
        int n = EVP_MD_CTX_get_size(s->write_hash);

        if (!ossl_assert(n >= 0)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    ds = s->enc_write_ctx;
    if (s->enc_write_ctx == NULL)
        enc = NULL;
    else {
        int ivlen;

        enc = EVP_CIPHER_CTX_get0_cipher(s->enc_write_ctx);
        /* For TLSv1.1 and later explicit IV */
        if (SSL_USE_EXPLICIT_IV(s)
            && EVP_CIPHER_get_mode(enc) == EVP_CIPH_CBC_MODE)
            ivlen = EVP_CIPHER_get_iv_length(enc);
        else
            ivlen = 0;
        if (ivlen > 1) {
            for (ctr = 0; ctr < n_recs; ctr++) {
                if (recs[ctr].data != recs[ctr].input) {
                    /*
                        * we can't write into the input stream: Can this ever
                        * happen?? (steve)
                        */
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                } else if (RAND_bytes_ex(SSL_CONNECTION_GET_CTX(s)->libctx,
                                         recs[ctr].input,
                                         ivlen, 0) <= 0) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
            }
        }
    }

    if ((s->session == NULL) || (ds == NULL) || (enc == NULL)) {
        for (ctr = 0; ctr < n_recs; ctr++) {
            memmove(recs[ctr].data, recs[ctr].input, recs[ctr].length);
            recs[ctr].input = recs[ctr].data;
        }
    } else {
        int provided = (EVP_CIPHER_get0_provider(enc) != NULL);

        bs = EVP_CIPHER_get_block_size(EVP_CIPHER_CTX_get0_cipher(ds));

        if (n_recs > 1) {
            if ((EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ds))
                  & EVP_CIPH_FLAG_PIPELINE) == 0) {
                /*
                 * We shouldn't have been called with pipeline data if the
                 * cipher doesn't support pipelining
                 */
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_PIPELINE_FAILURE);
                return 0;
            }
        }
        for (ctr = 0; ctr < n_recs; ctr++) {
            reclen[ctr] = recs[ctr].length;

            if ((EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ds))
                        & EVP_CIPH_FLAG_AEAD_CIPHER) != 0) {
                unsigned char *seq;

                seq = RECORD_LAYER_get_write_sequence(&s->rlayer);

                if (SSL_CONNECTION_IS_DTLS(s)) {
                    /* DTLS does not support pipelining */
                    unsigned char dtlsseq[8], *p = dtlsseq;

                    s2n(DTLS_RECORD_LAYER_get_w_epoch(&s->rlayer), p);
                    memcpy(p, &seq[2], 6);
                    memcpy(buf[ctr], dtlsseq, 8);
                } else {
                    memcpy(buf[ctr], seq, 8);
                    for (i = 7; i >= 0; i--) { /* increment */
                        ++seq[i];
                        if (seq[i] != 0)
                            break;
                    }
                }

                buf[ctr][8] = recs[ctr].type;
                buf[ctr][9] = (unsigned char)(s->version >> 8);
                buf[ctr][10] = (unsigned char)(s->version);
                buf[ctr][11] = (unsigned char)(recs[ctr].length >> 8);
                buf[ctr][12] = (unsigned char)(recs[ctr].length & 0xff);
                pad = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_TLS1_AAD,
                                          EVP_AEAD_TLS1_AAD_LEN, buf[ctr]);
                if (pad <= 0) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                }

                reclen[ctr] += pad;
                recs[ctr].length += pad;

            } else if ((bs != 1) && !provided) {
                /*
                 * We only do this for legacy ciphers. Provided ciphers add the
                 * padding on the provider side.
                 */
                padnum = bs - (reclen[ctr] % bs);

                /* Add weird padding of up to 256 bytes */

                if (padnum > MAX_PADDING) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                /* we need to add 'padnum' padding bytes of value padval */
                padval = (unsigned char)(padnum - 1);
                for (loop = reclen[ctr]; loop < reclen[ctr] + padnum; loop++)
                    recs[ctr].input[loop] = padval;
                reclen[ctr] += padnum;
                recs[ctr].length += padnum;
            }
        }
        if (n_recs > 1) {
            unsigned char *data[SSL_MAX_PIPELINES];

            /* Set the output buffers */
            for (ctr = 0; ctr < n_recs; ctr++) {
                data[ctr] = recs[ctr].data;
            }
            if (EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS,
                                    (int)n_recs, data) <= 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_PIPELINE_FAILURE);
                return 0;
            }
            /* Set the input buffers */
            for (ctr = 0; ctr < n_recs; ctr++) {
                data[ctr] = recs[ctr].input;
            }
            if (EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_SET_PIPELINE_INPUT_BUFS,
                                    (int)n_recs, data) <= 0
                || EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_SET_PIPELINE_INPUT_LENS,
                                       (int)n_recs, reclen) <= 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_PIPELINE_FAILURE);
                return 0;
            }
        }

        if (!SSL_CONNECTION_IS_DTLS(s) && tlstree_enc) {
            unsigned char *seq;
            int decrement_seq = 0;

            /*
             * When sending, seq is incremented after MAC calculation.
             * So if we are in ETM mode, we use seq 'as is' in the ctrl-function.
             * Otherwise we have to decrease it in the implementation
             */
            if (!SSL_WRITE_ETM(s))
                decrement_seq = 1;

            seq = RECORD_LAYER_get_write_sequence(&s->rlayer);
            if (EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_TLSTREE, decrement_seq, seq) <= 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }

        if (provided) {
            int outlen;

            /* Provided cipher - we do not support pipelining on this path */
            if (n_recs > 1)  {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }

            if (!EVP_CipherUpdate(ds, recs[0].data, &outlen, recs[0].input,
                                  (unsigned int)reclen[0]))
                return 0;
            recs[0].length = outlen;
        } else {
            /* Legacy cipher */

            tmpr = EVP_Cipher(ds, recs[0].data, recs[0].input,
                              (unsigned int)reclen[0]);
            if ((EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ds))
                 & EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0
                ? (tmpr < 0)
                : (tmpr == 0)) {
                /* AEAD can fail to verify MAC */
                return 0;
            }
        }
    }
    return 1;
}

int n_ssl3_mac(SSL_CONNECTION *sc, SSL3_RECORD *rec, unsigned char *md,
               int sending)
{
    unsigned char *mac_sec, *seq;
    const EVP_MD_CTX *hash;
    unsigned char *p, rec_char;
    size_t md_size;
    size_t npad;
    int t;
    unsigned int md_size_u;
    EVP_MD_CTX *md_ctx;

    /*
     * All read record layer operations should have been moved to the new
     * record layer code
     */
    assert(sending);

    mac_sec = &(sc->s3.write_mac_secret[0]);
    seq = RECORD_LAYER_get_write_sequence(&sc->rlayer);
    hash = sc->write_hash;

    t = EVP_MD_CTX_get_size(hash);
    if (t < 0)
        return 0;
    md_size = t;
    npad = (48 / md_size) * md_size;

    /* Chop the digest off the end :-) */
    md_ctx = EVP_MD_CTX_new();

    if (md_ctx == NULL)
        return 0;

    rec_char = rec->type;
    p = md;
    s2n(rec->length, p);
    if (EVP_MD_CTX_copy_ex(md_ctx, hash) <= 0
        || EVP_DigestUpdate(md_ctx, mac_sec, md_size) <= 0
        || EVP_DigestUpdate(md_ctx, ssl3_pad_1, npad) <= 0
        || EVP_DigestUpdate(md_ctx, seq, 8) <= 0
        || EVP_DigestUpdate(md_ctx, &rec_char, 1) <= 0
        || EVP_DigestUpdate(md_ctx, md, 2) <= 0
        || EVP_DigestUpdate(md_ctx, rec->input, rec->length) <= 0
        || EVP_DigestFinal_ex(md_ctx, md, NULL) <= 0
        || EVP_MD_CTX_copy_ex(md_ctx, hash) <= 0
        || EVP_DigestUpdate(md_ctx, mac_sec, md_size) <= 0
        || EVP_DigestUpdate(md_ctx, ssl3_pad_2, npad) <= 0
        || EVP_DigestUpdate(md_ctx, md, md_size) <= 0
        || EVP_DigestFinal_ex(md_ctx, md, &md_size_u) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    EVP_MD_CTX_free(md_ctx);

    ssl3_record_sequence_update(seq);
    return 1;
}

int tls1_mac_old(SSL_CONNECTION *sc, SSL3_RECORD *rec, unsigned char *md,
                 int sending)
{
    unsigned char *seq;
    EVP_MD_CTX *hash;
    size_t md_size;
    int i;
    EVP_MD_CTX *hmac = NULL, *mac_ctx;
    unsigned char header[13];
    int stream_mac = (sc->mac_flags & SSL_MAC_FLAG_WRITE_MAC_STREAM);
    int tlstree_mac = (sc->mac_flags & SSL_MAC_FLAG_WRITE_MAC_TLSTREE);
    int t;
    int ret = 0;

    /*
     * All read record layer calls should have been moved to the new record
     * layer.
     */
    assert(sending);

    seq = RECORD_LAYER_get_write_sequence(&sc->rlayer);
    hash = sc->write_hash;

    t = EVP_MD_CTX_get_size(hash);
    if (!ossl_assert(t >= 0))
        return 0;
    md_size = t;

    /* I should fix this up TLS TLS TLS TLS TLS XXXXXXXX */
    if (stream_mac) {
        mac_ctx = hash;
    } else {
        hmac = EVP_MD_CTX_new();
        if (hmac == NULL || !EVP_MD_CTX_copy(hmac, hash)) {
            goto end;
        }
        mac_ctx = hmac;
    }

    if (!SSL_CONNECTION_IS_DTLS(sc) && tlstree_mac
        && EVP_MD_CTX_ctrl(mac_ctx, EVP_MD_CTRL_TLSTREE, 0, seq) <= 0) {
        goto end;
    }

    if (SSL_CONNECTION_IS_DTLS(sc)) {
        unsigned char dtlsseq[8], *p = dtlsseq;

        s2n(DTLS_RECORD_LAYER_get_w_epoch(&sc->rlayer), p);
        memcpy(p, &seq[2], 6);

        memcpy(header, dtlsseq, 8);
    } else
        memcpy(header, seq, 8);

    header[8] = rec->type;
    header[9] = (unsigned char)(sc->version >> 8);
    header[10] = (unsigned char)(sc->version);
    header[11] = (unsigned char)(rec->length >> 8);
    header[12] = (unsigned char)(rec->length & 0xff);

    if (EVP_DigestSignUpdate(mac_ctx, header, sizeof(header)) <= 0
        || EVP_DigestSignUpdate(mac_ctx, rec->input, rec->length) <= 0
        || EVP_DigestSignFinal(mac_ctx, md, &md_size) <= 0) {
        goto end;
    }

    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "seq:\n");
        BIO_dump_indent(trc_out, seq, 8, 4);
        BIO_printf(trc_out, "rec:\n");
        BIO_dump_indent(trc_out, rec->data, rec->length, 4);
    } OSSL_TRACE_END(TLS);

    if (!SSL_CONNECTION_IS_DTLS(sc)) {
        for (i = 7; i >= 0; i--) {
            ++seq[i];
            if (seq[i] != 0)
                break;
        }
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "md:\n");
        BIO_dump_indent(trc_out, md, md_size, 4);
    } OSSL_TRACE_END(TLS);
    ret = 1;
 end:
    EVP_MD_CTX_free(hmac);
    return ret;
}
