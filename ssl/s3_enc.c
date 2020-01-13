/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "tls_local.h"
#include <opentls/evp.h>
#include <opentls/md5.h>
#include <opentls/core_names.h>
#include "internal/cryptlib.h"

static int tls3_generate_key_block(tls *s, unsigned char *km, int num)
{
    EVP_MD *md5;
    EVP_MD_CTX *m5;
    EVP_MD_CTX *s1;
    unsigned char buf[16], smd[SHA_DIGEST_LENGTH];
    unsigned char c = 'A';
    unsigned int i, j, k;
    int ret = 0;

#ifdef CHARSET_EBCDIC
    c = os_toascii[c];          /* 'A' in ASCII */
#endif
    k = 0;
    md5 = EVP_MD_fetch(NULL, Otls_DIGEST_NAME_MD5, "-fips");
    m5 = EVP_MD_CTX_new();
    s1 = EVP_MD_CTX_new();
    if (md5 == NULL || m5 == NULL || s1 == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_GENERATE_KEY_BLOCK,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }
    for (i = 0; (int)i < num; i += MD5_DIGEST_LENGTH) {
        k++;
        if (k > sizeof(buf)) {
            /* bug: 'buf' is too small for this ciphersuite */
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_GENERATE_KEY_BLOCK,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }

        for (j = 0; j < k; j++)
            buf[j] = c;
        c++;
        if (!EVP_DigestInit_ex(s1, EVP_sha1(), NULL)
            || !EVP_DigestUpdate(s1, buf, k)
            || !EVP_DigestUpdate(s1, s->session->master_key,
                                 s->session->master_key_length)
            || !EVP_DigestUpdate(s1, s->s3.server_random, tls3_RANDOM_SIZE)
            || !EVP_DigestUpdate(s1, s->s3.client_random, tls3_RANDOM_SIZE)
            || !EVP_DigestFinal_ex(s1, smd, NULL)
            || !EVP_DigestInit_ex(m5, md5, NULL)
            || !EVP_DigestUpdate(m5, s->session->master_key,
                                 s->session->master_key_length)
            || !EVP_DigestUpdate(m5, smd, SHA_DIGEST_LENGTH)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_GENERATE_KEY_BLOCK,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if ((int)(i + MD5_DIGEST_LENGTH) > num) {
            if (!EVP_DigestFinal_ex(m5, smd, NULL)) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_tls3_GENERATE_KEY_BLOCK, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(km, smd, (num - i));
        } else {
            if (!EVP_DigestFinal_ex(m5, km, NULL)) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_tls3_GENERATE_KEY_BLOCK, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        km += MD5_DIGEST_LENGTH;
    }
    OPENtls_cleanse(smd, sizeof(smd));
    ret = 1;
 err:
    EVP_MD_CTX_free(m5);
    EVP_MD_CTX_free(s1);
    EVP_MD_free(md5);
    return ret;
}

int tls3_change_cipher_state(tls *s, int which)
{
    unsigned char *p, *mac_secret;
    unsigned char *ms, *key, *iv;
    EVP_CIPHER_CTX *dd;
    const EVP_CIPHER *c;
#ifndef OPENtls_NO_COMP
    COMP_METHOD *comp;
#endif
    const EVP_MD *m;
    int mdi;
    size_t n, i, j, k, cl;
    int reuse_dd = 0;

    c = s->s3.tmp.new_sym_enc;
    m = s->s3.tmp.new_hash;
    /* m == NULL will lead to a crash later */
    if (!otls_assert(m != NULL)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_CHANGE_CIPHER_STATE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifndef OPENtls_NO_COMP
    if (s->s3.tmp.new_compression == NULL)
        comp = NULL;
    else
        comp = s->s3.tmp.new_compression->method;
#endif

    if (which & tls3_CC_READ) {
        if (s->enc_read_ctx != NULL) {
            reuse_dd = 1;
        } else if ((s->enc_read_ctx = EVP_CIPHER_CTX_new()) == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_CHANGE_CIPHER_STATE,
                     ERR_R_MALLOC_FAILURE);
            goto err;
        } else {
            /*
             * make sure it's initialised in case we exit later with an error
             */
            EVP_CIPHER_CTX_reset(s->enc_read_ctx);
        }
        dd = s->enc_read_ctx;

        if (tls_replace_hash(&s->read_hash, m) == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_CHANGE_CIPHER_STATE,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
#ifndef OPENtls_NO_COMP
        /* COMPRESS */
        COMP_CTX_free(s->expand);
        s->expand = NULL;
        if (comp != NULL) {
            s->expand = COMP_CTX_new(comp);
            if (s->expand == NULL) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_tls3_CHANGE_CIPHER_STATE,
                         tls_R_COMPRESSION_LIBRARY_ERROR);
                goto err;
            }
        }
#endif
        RECORD_LAYER_reset_read_sequence(&s->rlayer);
        mac_secret = &(s->s3.read_mac_secret[0]);
    } else {
        s->statem.enc_write_state = ENC_WRITE_STATE_INVALID;
        if (s->enc_write_ctx != NULL) {
            reuse_dd = 1;
        } else if ((s->enc_write_ctx = EVP_CIPHER_CTX_new()) == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_CHANGE_CIPHER_STATE,
                     ERR_R_MALLOC_FAILURE);
            goto err;
        } else {
            /*
             * make sure it's initialised in case we exit later with an error
             */
            EVP_CIPHER_CTX_reset(s->enc_write_ctx);
        }
        dd = s->enc_write_ctx;
        if (tls_replace_hash(&s->write_hash, m) == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_CHANGE_CIPHER_STATE,
                     ERR_R_MALLOC_FAILURE);
            goto err;
        }
#ifndef OPENtls_NO_COMP
        /* COMPRESS */
        COMP_CTX_free(s->compress);
        s->compress = NULL;
        if (comp != NULL) {
            s->compress = COMP_CTX_new(comp);
            if (s->compress == NULL) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_tls3_CHANGE_CIPHER_STATE,
                         tls_R_COMPRESSION_LIBRARY_ERROR);
                goto err;
            }
        }
#endif
        RECORD_LAYER_reset_write_sequence(&s->rlayer);
        mac_secret = &(s->s3.write_mac_secret[0]);
    }

    if (reuse_dd)
        EVP_CIPHER_CTX_reset(dd);

    p = s->s3.tmp.key_block;
    mdi = EVP_MD_size(m);
    if (mdi < 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_CHANGE_CIPHER_STATE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }
    i = mdi;
    cl = EVP_CIPHER_key_length(c);
    j = cl;
    k = EVP_CIPHER_iv_length(c);
    if ((which == tls3_CHANGE_CIPHER_CLIENT_WRITE) ||
        (which == tls3_CHANGE_CIPHER_SERVER_READ)) {
        ms = &(p[0]);
        n = i + i;
        key = &(p[n]);
        n += j + j;
        iv = &(p[n]);
        n += k + k;
    } else {
        n = i;
        ms = &(p[n]);
        n += i + j;
        key = &(p[n]);
        n += j + k;
        iv = &(p[n]);
        n += k;
    }

    if (n > s->s3.tmp.key_block_length) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_CHANGE_CIPHER_STATE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    memcpy(mac_secret, ms, i);

    if (!EVP_CipherInit_ex(dd, c, NULL, key, iv, (which & tls3_CC_WRITE))) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_CHANGE_CIPHER_STATE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    s->statem.enc_write_state = ENC_WRITE_STATE_VALID;
    return 1;
 err:
    return 0;
}

int tls3_setup_key_block(tls *s)
{
    unsigned char *p;
    const EVP_CIPHER *c;
    const EVP_MD *hash;
    int num;
    int ret = 0;
    tls_COMP *comp;

    if (s->s3.tmp.key_block_length != 0)
        return 1;

    if (!tls_cipher_get_evp(s->session, &c, &hash, NULL, NULL, &comp, 0)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_SETUP_KEY_BLOCK,
                 tls_R_CIPHER_OR_HASH_UNAVAILABLE);
        return 0;
    }

    s->s3.tmp.new_sym_enc = c;
    s->s3.tmp.new_hash = hash;
#ifdef OPENtls_NO_COMP
    s->s3.tmp.new_compression = NULL;
#else
    s->s3.tmp.new_compression = comp;
#endif

    num = EVP_MD_size(hash);
    if (num < 0)
        return 0;

    num = EVP_CIPHER_key_length(c) + num + EVP_CIPHER_iv_length(c);
    num *= 2;

    tls3_cleanup_key_block(s);

    if ((p = OPENtls_malloc(num)) == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_SETUP_KEY_BLOCK,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }

    s->s3.tmp.key_block_length = num;
    s->s3.tmp.key_block = p;

    /* Calls tlsfatal() as required */
    ret = tls3_generate_key_block(s, p, num);

    if (!(s->options & tls_OP_DONT_INSERT_EMPTY_FRAGMENTS)) {
        /*
         * enable vulnerability countermeasure for CBC ciphers with known-IV
         * problem (http://www.opentls.org/~bodo/tls-cbc.txt)
         */
        s->s3.need_empty_fragments = 1;

        if (s->session->cipher != NULL) {
            if (s->session->cipher->algorithm_enc == tls_eNULL)
                s->s3.need_empty_fragments = 0;

#ifndef OPENtls_NO_RC4
            if (s->session->cipher->algorithm_enc == tls_RC4)
                s->s3.need_empty_fragments = 0;
#endif
        }
    }

    return ret;
}

void tls3_cleanup_key_block(tls *s)
{
    OPENtls_clear_free(s->s3.tmp.key_block, s->s3.tmp.key_block_length);
    s->s3.tmp.key_block = NULL;
    s->s3.tmp.key_block_length = 0;
}

int tls3_init_finished_mac(tls *s)
{
    BIO *buf = BIO_new(BIO_s_mem());

    if (buf == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_INIT_FINISHED_MAC,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }
    tls3_free_digest_list(s);
    s->s3.handshake_buffer = buf;
    (void)BIO_set_close(s->s3.handshake_buffer, BIO_CLOSE);
    return 1;
}

/*
 * Free digest list. Also frees handshake buffer since they are always freed
 * together.
 */

void tls3_free_digest_list(tls *s)
{
    BIO_free(s->s3.handshake_buffer);
    s->s3.handshake_buffer = NULL;
    EVP_MD_CTX_free(s->s3.handshake_dgst);
    s->s3.handshake_dgst = NULL;
}

int tls3_finish_mac(tls *s, const unsigned char *buf, size_t len)
{
    int ret;

    if (s->s3.handshake_dgst == NULL) {
        /* Note: this writes to a memory BIO so a failure is a fatal error */
        if (len > INT_MAX) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_FINISH_MAC,
                     tls_R_OVERFLOW_ERROR);
            return 0;
        }
        ret = BIO_write(s->s3.handshake_buffer, (void *)buf, (int)len);
        if (ret <= 0 || ret != (int)len) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_FINISH_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        ret = EVP_DigestUpdate(s->s3.handshake_dgst, buf, len);
        if (!ret) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_FINISH_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    return 1;
}

int tls3_digest_cached_records(tls *s, int keep)
{
    const EVP_MD *md;
    long hdatalen;
    void *hdata;

    if (s->s3.handshake_dgst == NULL) {
        hdatalen = BIO_get_mem_data(s->s3.handshake_buffer, &hdata);
        if (hdatalen <= 0) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_DIGEST_CACHED_RECORDS,
                     tls_R_BAD_HANDSHAKE_LENGTH);
            return 0;
        }

        s->s3.handshake_dgst = EVP_MD_CTX_new();
        if (s->s3.handshake_dgst == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_DIGEST_CACHED_RECORDS,
                     ERR_R_MALLOC_FAILURE);
            return 0;
        }

        md = tls_handshake_md(s);
        if (md == NULL || !EVP_DigestInit_ex(s->s3.handshake_dgst, md, NULL)
            || !EVP_DigestUpdate(s->s3.handshake_dgst, hdata, hdatalen)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_DIGEST_CACHED_RECORDS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    if (keep == 0) {
        BIO_free(s->s3.handshake_buffer);
        s->s3.handshake_buffer = NULL;
    }

    return 1;
}

void tls3_digest_master_key_set_params(const tls_SESSION *session,
                                       Otls_PARAM params[])
{
    int n = 0;
    params[n++] = Otls_PARAM_construct_octet_string(Otls_DIGEST_PARAM_tls3_MS,
                                                    (void *)session->master_key,
                                                    session->master_key_length);
    params[n++] = Otls_PARAM_construct_end();
}

size_t tls3_final_finish_mac(tls *s, const char *sender, size_t len,
                             unsigned char *p)
{
    int ret;
    EVP_MD_CTX *ctx = NULL;

    if (!tls3_digest_cached_records(s, 0)) {
        /* tlsfatal() already called */
        return 0;
    }

    if (EVP_MD_CTX_type(s->s3.handshake_dgst) != NID_md5_sha1) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_FINAL_FINISH_MAC,
                 tls_R_NO_REQUIRED_DIGEST);
        return 0;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_FINAL_FINISH_MAC,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!EVP_MD_CTX_copy_ex(ctx, s->s3.handshake_dgst)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_FINAL_FINISH_MAC,
                 ERR_R_INTERNAL_ERROR);
        ret = 0;
        goto err;
    }

    ret = EVP_MD_CTX_size(ctx);
    if (ret < 0) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_FINAL_FINISH_MAC,
                 ERR_R_INTERNAL_ERROR);
        ret = 0;
        goto err;
    }

    if (sender != NULL) {
        Otls_PARAM digest_cmd_params[3];

        tls3_digest_master_key_set_params(s->session, digest_cmd_params);

        if (EVP_DigestUpdate(ctx, sender, len) <= 0
            || EVP_MD_CTX_set_params(ctx, digest_cmd_params) <= 0
            || EVP_DigestFinal_ex(ctx, p, NULL) <= 0) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_FINAL_FINISH_MAC,
                         ERR_R_INTERNAL_ERROR);
                ret = 0;
        }
    }

 err:
    EVP_MD_CTX_free(ctx);

    return ret;
}

int tls3_generate_master_secret(tls *s, unsigned char *out, unsigned char *p,
                                size_t len, size_t *secret_size)
{
    static const unsigned char *salt[3] = {
#ifndef CHARSET_EBCDIC
        (const unsigned char *)"A",
        (const unsigned char *)"BB",
        (const unsigned char *)"CCC",
#else
        (const unsigned char *)"\x41",
        (const unsigned char *)"\x42\x42",
        (const unsigned char *)"\x43\x43\x43",
#endif
    };
    unsigned char buf[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int i, ret = 1;
    unsigned int n;
    size_t ret_secret_size = 0;

    if (ctx == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_tls3_GENERATE_MASTER_SECRET,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }
    for (i = 0; i < 3; i++) {
        if (EVP_DigestInit_ex(ctx, s->ctx->sha1, NULL) <= 0
            || EVP_DigestUpdate(ctx, salt[i],
                                strlen((const char *)salt[i])) <= 0
            || EVP_DigestUpdate(ctx, p, len) <= 0
            || EVP_DigestUpdate(ctx, &(s->s3.client_random[0]),
                                tls3_RANDOM_SIZE) <= 0
            || EVP_DigestUpdate(ctx, &(s->s3.server_random[0]),
                                tls3_RANDOM_SIZE) <= 0
               /* TODO(size_t) : convert me */
            || EVP_DigestFinal_ex(ctx, buf, &n) <= 0
            || EVP_DigestInit_ex(ctx, s->ctx->md5, NULL) <= 0
            || EVP_DigestUpdate(ctx, p, len) <= 0
            || EVP_DigestUpdate(ctx, buf, n) <= 0
            || EVP_DigestFinal_ex(ctx, out, &n) <= 0) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR,
                     tls_F_tls3_GENERATE_MASTER_SECRET, ERR_R_INTERNAL_ERROR);
            ret = 0;
            break;
        }
        out += n;
        ret_secret_size += n;
    }
    EVP_MD_CTX_free(ctx);

    OPENtls_cleanse(buf, sizeof(buf));
    if (ret)
        *secret_size = ret_secret_size;
    return ret;
}

int tls3_alert_code(int code)
{
    switch (code) {
    case tls_AD_CLOSE_NOTIFY:
        return tls3_AD_CLOSE_NOTIFY;
    case tls_AD_UNEXPECTED_MESSAGE:
        return tls3_AD_UNEXPECTED_MESSAGE;
    case tls_AD_BAD_RECORD_MAC:
        return tls3_AD_BAD_RECORD_MAC;
    case tls_AD_DECRYPTION_FAILED:
        return tls3_AD_BAD_RECORD_MAC;
    case tls_AD_RECORD_OVERFLOW:
        return tls3_AD_BAD_RECORD_MAC;
    case tls_AD_DECOMPRESSION_FAILURE:
        return tls3_AD_DECOMPRESSION_FAILURE;
    case tls_AD_HANDSHAKE_FAILURE:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_NO_CERTIFICATE:
        return tls3_AD_NO_CERTIFICATE;
    case tls_AD_BAD_CERTIFICATE:
        return tls3_AD_BAD_CERTIFICATE;
    case tls_AD_UNSUPPORTED_CERTIFICATE:
        return tls3_AD_UNSUPPORTED_CERTIFICATE;
    case tls_AD_CERTIFICATE_REVOKED:
        return tls3_AD_CERTIFICATE_REVOKED;
    case tls_AD_CERTIFICATE_EXPIRED:
        return tls3_AD_CERTIFICATE_EXPIRED;
    case tls_AD_CERTIFICATE_UNKNOWN:
        return tls3_AD_CERTIFICATE_UNKNOWN;
    case tls_AD_ILLEGAL_PARAMETER:
        return tls3_AD_ILLEGAL_PARAMETER;
    case tls_AD_UNKNOWN_CA:
        return tls3_AD_BAD_CERTIFICATE;
    case tls_AD_ACCESS_DENIED:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_DECODE_ERROR:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_DECRYPT_ERROR:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_EXPORT_RESTRICTION:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_PROTOCOL_VERSION:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_INSUFFICIENT_SECURITY:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_INTERNAL_ERROR:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_USER_CANCELLED:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_NO_RENEGOTIATION:
        return -1;            /* Don't send it :-) */
    case tls_AD_UNSUPPORTED_EXTENSION:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_CERTIFICATE_UNOBTAINABLE:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_UNRECOGNIZED_NAME:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_BAD_CERTIFICATE_HASH_VALUE:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_UNKNOWN_PSK_IDENTITY:
        return TLS1_AD_UNKNOWN_PSK_IDENTITY;
    case tls_AD_INAPPROPRIATE_FALLBACK:
        return TLS1_AD_INAPPROPRIATE_FALLBACK;
    case tls_AD_NO_APPLICATION_PROTOCOL:
        return TLS1_AD_NO_APPLICATION_PROTOCOL;
    case tls_AD_CERTIFICATE_REQUIRED:
        return tls_AD_HANDSHAKE_FAILURE;
    default:
        return -1;
    }
}
