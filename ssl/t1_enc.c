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
#include "record/record_local.h"
#include "internal/ktls.h"
#include "internal/cryptlib.h"
#include <opentls/comp.h>
#include <opentls/evp.h>
#include <opentls/kdf.h>
#include <opentls/rand.h>
#include <opentls/obj_mac.h>
#include <opentls/core_names.h>
#include <opentls/trace.h>

/* seed1 through seed5 are concatenated */
static int tls1_PRF(tls *s,
                    const void *seed1, size_t seed1_len,
                    const void *seed2, size_t seed2_len,
                    const void *seed3, size_t seed3_len,
                    const void *seed4, size_t seed4_len,
                    const void *seed5, size_t seed5_len,
                    const unsigned char *sec, size_t slen,
                    unsigned char *out, size_t olen, int fatal)
{
    const EVP_MD *md = tls_prf_md(s);
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = NULL;
    Otls_PARAM params[8], *p = params;
    const char *mdname;

    if (md == NULL) {
        /* Should never happen */
        if (fatal)
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_PRF,
                     ERR_R_INTERNAL_ERROR);
        else
            tlserr(tls_F_TLS1_PRF, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    kdf = EVP_KDF_fetch(NULL, Otls_KDF_NAME_TLS1_PRF, NULL);
    if (kdf == NULL)
        goto err;
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == NULL)
        goto err;
    mdname = EVP_MD_name(md);
    *p++ = Otls_PARAM_construct_utf8_string(Otls_KDF_PARAM_DIGEST,
                                            (char *)mdname, strlen(mdname) + 1);
    *p++ = Otls_PARAM_construct_octet_string(Otls_KDF_PARAM_SECRET,
                                             (unsigned char *)sec,
                                             (size_t)slen);
    *p++ = Otls_PARAM_construct_octet_string(Otls_KDF_PARAM_SEED,
                                             (void *)seed1, (size_t)seed1_len);
    *p++ = Otls_PARAM_construct_octet_string(Otls_KDF_PARAM_SEED,
                                             (void *)seed2, (size_t)seed2_len);
    *p++ = Otls_PARAM_construct_octet_string(Otls_KDF_PARAM_SEED,
                                             (void *)seed3, (size_t)seed3_len);
    *p++ = Otls_PARAM_construct_octet_string(Otls_KDF_PARAM_SEED,
                                             (void *)seed4, (size_t)seed4_len);
    *p++ = Otls_PARAM_construct_octet_string(Otls_KDF_PARAM_SEED,
                                             (void *)seed5, (size_t)seed5_len);
    *p = Otls_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params)
            && EVP_KDF_derive(kctx, out, olen)) {
        EVP_KDF_CTX_free(kctx);
        return 1;
    }

 err:
    if (fatal)
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_PRF,
                 ERR_R_INTERNAL_ERROR);
    else
        tlserr(tls_F_TLS1_PRF, ERR_R_INTERNAL_ERROR);
    EVP_KDF_CTX_free(kctx);
    return 0;
}

static int tls1_generate_key_block(tls *s, unsigned char *km, size_t num)
{
    int ret;

    /* Calls tlsfatal() as required */
    ret = tls1_PRF(s,
                   TLS_MD_KEY_EXPANSION_CONST,
                   TLS_MD_KEY_EXPANSION_CONST_SIZE, s->s3.server_random,
                   tls3_RANDOM_SIZE, s->s3.client_random, tls3_RANDOM_SIZE,
                   NULL, 0, NULL, 0, s->session->master_key,
                   s->session->master_key_length, km, num, 1);

    return ret;
}

#ifndef OPENtls_NO_KTLS
 /*
  * Count the number of records that were not processed yet from record boundary.
  *
  * This function assumes that there are only fully formed records read in the
  * record layer. If read_ahead is enabled, then this might be false and this
  * function will fail.
  */
static int count_unprocessed_records(tls *s)
{
    tls3_BUFFER *rbuf = RECORD_LAYER_get_rbuf(&s->rlayer);
    PACKET pkt, subpkt;
    int count = 0;

    if (!PACKET_buf_init(&pkt, rbuf->buf + rbuf->offset, rbuf->left))
        return -1;

    while (PACKET_remaining(&pkt) > 0) {
        /* Skip record type and version */
        if (!PACKET_forward(&pkt, 3))
            return -1;

        /* Read until next record */
        if (PACKET_get_length_prefixed_2(&pkt, &subpkt))
            return -1;

        count += 1;
    }

    return count;
}
#endif

int tls1_change_cipher_state(tls *s, int which)
{
    unsigned char *p, *mac_secret;
    unsigned char *ms, *key, *iv;
    EVP_CIPHER_CTX *dd;
    const EVP_CIPHER *c;
#ifndef OPENtls_NO_COMP
    const tls_COMP *comp;
#endif
    const EVP_MD *m;
    int mac_type;
    size_t *mac_secret_size;
    EVP_MD_CTX *mac_ctx;
    EVP_PKEY *mac_key;
    size_t n, i, j, k, cl;
    int reuse_dd = 0;
#ifndef OPENtls_NO_KTLS
# ifdef __FreeBSD__
    struct tls_enable crypto_info;
# else
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    unsigned char geniv[12];
    int count_unprocessed;
    int bit;
# endif
    BIO *bio;
#endif

    c = s->s3.tmp.new_sym_enc;
    m = s->s3.tmp.new_hash;
    mac_type = s->s3.tmp.new_mac_pkey_type;
#ifndef OPENtls_NO_COMP
    comp = s->s3.tmp.new_compression;
#endif

    if (which & tls3_CC_READ) {
        if (s->ext.use_etm)
            s->s3.flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC_READ;
        else
            s->s3.flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC_READ;

        if (s->s3.tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
            s->mac_flags |= tls_MAC_FLAG_READ_MAC_STREAM;
        else
            s->mac_flags &= ~tls_MAC_FLAG_READ_MAC_STREAM;

        if (s->enc_read_ctx != NULL) {
            reuse_dd = 1;
        } else if ((s->enc_read_ctx = EVP_CIPHER_CTX_new()) == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_CHANGE_CIPHER_STATE,
                     ERR_R_MALLOC_FAILURE);
            goto err;
        } else {
            /*
             * make sure it's initialised in case we exit later with an error
             */
            EVP_CIPHER_CTX_reset(s->enc_read_ctx);
        }
        dd = s->enc_read_ctx;
        mac_ctx = tls_replace_hash(&s->read_hash, NULL);
        if (mac_ctx == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_CHANGE_CIPHER_STATE,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
#ifndef OPENtls_NO_COMP
        COMP_CTX_free(s->expand);
        s->expand = NULL;
        if (comp != NULL) {
            s->expand = COMP_CTX_new(comp->method);
            if (s->expand == NULL) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_TLS1_CHANGE_CIPHER_STATE,
                         tls_R_COMPRESSION_LIBRARY_ERROR);
                goto err;
            }
        }
#endif
        /*
         * this is done by dtls1_reset_seq_numbers for DTLS
         */
        if (!tls_IS_DTLS(s))
            RECORD_LAYER_reset_read_sequence(&s->rlayer);
        mac_secret = &(s->s3.read_mac_secret[0]);
        mac_secret_size = &(s->s3.read_mac_secret_size);
    } else {
        s->statem.enc_write_state = ENC_WRITE_STATE_INVALID;
        if (s->ext.use_etm)
            s->s3.flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE;
        else
            s->s3.flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE;

        if (s->s3.tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
            s->mac_flags |= tls_MAC_FLAG_WRITE_MAC_STREAM;
        else
            s->mac_flags &= ~tls_MAC_FLAG_WRITE_MAC_STREAM;
        if (s->enc_write_ctx != NULL && !tls_IS_DTLS(s)) {
            reuse_dd = 1;
        } else if ((s->enc_write_ctx = EVP_CIPHER_CTX_new()) == NULL) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_CHANGE_CIPHER_STATE,
                     ERR_R_MALLOC_FAILURE);
            goto err;
        }
        dd = s->enc_write_ctx;
        if (tls_IS_DTLS(s)) {
            mac_ctx = EVP_MD_CTX_new();
            if (mac_ctx == NULL) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_TLS1_CHANGE_CIPHER_STATE,
                         ERR_R_MALLOC_FAILURE);
                goto err;
            }
            s->write_hash = mac_ctx;
        } else {
            mac_ctx = tls_replace_hash(&s->write_hash, NULL);
            if (mac_ctx == NULL) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_TLS1_CHANGE_CIPHER_STATE,
                         ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
#ifndef OPENtls_NO_COMP
        COMP_CTX_free(s->compress);
        s->compress = NULL;
        if (comp != NULL) {
            s->compress = COMP_CTX_new(comp->method);
            if (s->compress == NULL) {
                tlsfatal(s, tls_AD_INTERNAL_ERROR,
                         tls_F_TLS1_CHANGE_CIPHER_STATE,
                        tls_R_COMPRESSION_LIBRARY_ERROR);
                goto err;
            }
        }
#endif
        /*
         * this is done by dtls1_reset_seq_numbers for DTLS
         */
        if (!tls_IS_DTLS(s))
            RECORD_LAYER_reset_write_sequence(&s->rlayer);
        mac_secret = &(s->s3.write_mac_secret[0]);
        mac_secret_size = &(s->s3.write_mac_secret_size);
    }

    if (reuse_dd)
        EVP_CIPHER_CTX_reset(dd);

    p = s->s3.tmp.key_block;
    i = *mac_secret_size = s->s3.tmp.new_mac_secret_size;

    /* TODO(size_t): convert me */
    cl = EVP_CIPHER_key_length(c);
    j = cl;
    /* Was j=(exp)?5:EVP_CIPHER_key_length(c); */
    /* If GCM/CCM mode only part of IV comes from PRF */
    if (EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE)
        k = EVP_GCM_TLS_FIXED_IV_LEN;
    else if (EVP_CIPHER_mode(c) == EVP_CIPH_CCM_MODE)
        k = EVP_CCM_TLS_FIXED_IV_LEN;
    else
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
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_CHANGE_CIPHER_STATE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    memcpy(mac_secret, ms, i);

    if (!(EVP_CIPHER_flags(c) & EVP_CIPH_FLAG_AEAD_CIPHER)) {
        /* TODO(size_t): Convert this function */
        mac_key = EVP_PKEY_new_mac_key(mac_type, NULL, mac_secret,
                                               (int)*mac_secret_size);
        if (mac_key == NULL
            || EVP_DigestSignInit(mac_ctx, NULL, m, NULL, mac_key) <= 0) {
            EVP_PKEY_free(mac_key);
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_CHANGE_CIPHER_STATE,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
        EVP_PKEY_free(mac_key);
    }

    Otls_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "which = %04X, mac key:\n", which);
        BIO_dump_indent(trc_out, ms, i, 4);
    } Otls_TRACE_END(TLS);

    if (EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE) {
        if (!EVP_CipherInit_ex(dd, c, NULL, key, NULL, (which & tls3_CC_WRITE))
            || !EVP_CIPHER_CTX_ctrl(dd, EVP_CTRL_GCM_SET_IV_FIXED, (int)k,
                                    iv)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_CHANGE_CIPHER_STATE,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else if (EVP_CIPHER_mode(c) == EVP_CIPH_CCM_MODE) {
        int taglen;
        if (s->s3.tmp.
            new_cipher->algorithm_enc & (tls_AES128CCM8 | tls_AES256CCM8))
            taglen = EVP_CCM8_TLS_TAG_LEN;
        else
            taglen = EVP_CCM_TLS_TAG_LEN;
        if (!EVP_CipherInit_ex(dd, c, NULL, NULL, NULL, (which & tls3_CC_WRITE))
            || !EVP_CIPHER_CTX_ctrl(dd, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)
            || !EVP_CIPHER_CTX_ctrl(dd, EVP_CTRL_AEAD_SET_TAG, taglen, NULL)
            || !EVP_CIPHER_CTX_ctrl(dd, EVP_CTRL_CCM_SET_IV_FIXED, (int)k, iv)
            || !EVP_CipherInit_ex(dd, NULL, NULL, key, NULL, -1)) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_CHANGE_CIPHER_STATE,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        if (!EVP_CipherInit_ex(dd, c, NULL, key, iv, (which & tls3_CC_WRITE))) {
            tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_CHANGE_CIPHER_STATE,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    /* Needed for "composite" AEADs, such as RC4-HMAC-MD5 */
    if ((EVP_CIPHER_flags(c) & EVP_CIPH_FLAG_AEAD_CIPHER) && *mac_secret_size
        && !EVP_CIPHER_CTX_ctrl(dd, EVP_CTRL_AEAD_SET_MAC_KEY,
                                (int)*mac_secret_size, mac_secret)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_CHANGE_CIPHER_STATE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifndef OPENtls_NO_KTLS
    if (s->compress)
        goto skip_ktls;

    if (((which & tls3_CC_READ) && (s->mode & tls_MODE_NO_KTLS_RX))
        || ((which & tls3_CC_WRITE) && (s->mode & tls_MODE_NO_KTLS_TX)))
        goto skip_ktls;

    /* ktls supports only the maximum fragment size */
    if (tls_get_max_send_fragment(s) != tls3_RT_MAX_PLAIN_LENGTH)
        goto skip_ktls;

# ifdef __FreeBSD__
    memset(&crypto_info, 0, sizeof(crypto_info));
    switch (s->s3.tmp.new_cipher->algorithm_enc) {
    case tls_AES128GCM:
    case tls_AES256GCM:
        crypto_info.cipher_algorithm = CRYPTO_AES_NIST_GCM_16;
        crypto_info.iv_len = EVP_GCM_TLS_FIXED_IV_LEN;
        break;
    case tls_AES128:
    case tls_AES256:
        if (s->ext.use_etm)
            goto skip_ktls;
        switch (s->s3.tmp.new_cipher->algorithm_mac) {
        case tls_SHA1:
            crypto_info.auth_algorithm = CRYPTO_SHA1_HMAC;
            break;
        case tls_SHA256:
            crypto_info.auth_algorithm = CRYPTO_SHA2_256_HMAC;
            break;
        case tls_SHA384:
            crypto_info.auth_algorithm = CRYPTO_SHA2_384_HMAC;
            break;
        default:
            goto skip_ktls;
        }
        crypto_info.cipher_algorithm = CRYPTO_AES_CBC;
        crypto_info.iv_len = EVP_CIPHER_iv_length(c);
        crypto_info.auth_key = ms;
        crypto_info.auth_key_len = *mac_secret_size;
        break;
    default:
        goto skip_ktls;
    }
    crypto_info.cipher_key = key;
    crypto_info.cipher_key_len = EVP_CIPHER_key_length(c);
    crypto_info.iv = iv;
    crypto_info.tls_vmajor = (s->version >> 8) & 0x000000ff;
    crypto_info.tls_vminor = (s->version & 0x000000ff);
# else
    /* check that cipher is AES_GCM_128 */
    if (EVP_CIPHER_nid(c) != NID_aes_128_gcm
        || EVP_CIPHER_mode(c) != EVP_CIPH_GCM_MODE
        || EVP_CIPHER_key_length(c) != TLS_CIPHER_AES_GCM_128_KEY_SIZE)
        goto skip_ktls;

    /* check version is 1.2 */
    if (s->version != TLS1_2_VERSION)
        goto skip_ktls;
# endif

    if (which & tls3_CC_WRITE)
        bio = s->wbio;
    else
        bio = s->rbio;

    if (!otls_assert(bio != NULL)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_CHANGE_CIPHER_STATE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* All future data will get encrypted by ktls. Flush the BIO or skip ktls */
    if (which & tls3_CC_WRITE) {
       if (BIO_flush(bio) <= 0)
           goto skip_ktls;
    }

    /* ktls doesn't support renegotiation */
    if ((BIO_get_ktls_send(s->wbio) && (which & tls3_CC_WRITE)) ||
        (BIO_get_ktls_recv(s->rbio) && (which & tls3_CC_READ))) {
        tlsfatal(s, tls_AD_NO_RENEGOTIATION, tls_F_TLS1_CHANGE_CIPHER_STATE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

# ifndef __FreeBSD__
    memset(&crypto_info, 0, sizeof(crypto_info));
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
    crypto_info.info.version = s->version;

    EVP_CIPHER_CTX_ctrl(dd, EVP_CTRL_GET_IV,
                        EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN,
                        geniv);
    memcpy(crypto_info.iv, geniv + EVP_GCM_TLS_FIXED_IV_LEN,
           TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(crypto_info.salt, geniv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    memcpy(crypto_info.key, key, EVP_CIPHER_key_length(c));
    if (which & tls3_CC_WRITE)
        memcpy(crypto_info.rec_seq, &s->rlayer.write_sequence,
                TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    else
        memcpy(crypto_info.rec_seq, &s->rlayer.read_sequence,
                TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

    if (which & tls3_CC_READ) {
        count_unprocessed = count_unprocessed_records(s);
        if (count_unprocessed < 0)
            goto skip_ktls;

        /* increment the crypto_info record sequence */
        while (count_unprocessed) {
            for (bit = 7; bit >= 0; bit--) { /* increment */
                ++crypto_info.rec_seq[bit];
                if (crypto_info.rec_seq[bit] != 0)
                    break;
            }
            count_unprocessed--;
        }
    }
# endif

    /* ktls works with user provided buffers directly */
    if (BIO_set_ktls(bio, &crypto_info, which & tls3_CC_WRITE)) {
        if (which & tls3_CC_WRITE)
            tls3_release_write_buffer(s);
        tls_set_options(s, tls_OP_NO_RENEGOTIATION);
    }

 skip_ktls:
#endif                          /* OPENtls_NO_KTLS */
    s->statem.enc_write_state = ENC_WRITE_STATE_VALID;

    Otls_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "which = %04X, key:\n", which);
        BIO_dump_indent(trc_out, key, EVP_CIPHER_key_length(c), 4);
        BIO_printf(trc_out, "iv:\n");
        BIO_dump_indent(trc_out, iv, k, 4);
    } Otls_TRACE_END(TLS);

    return 1;
 err:
    return 0;
}

int tls1_setup_key_block(tls *s)
{
    unsigned char *p;
    const EVP_CIPHER *c;
    const EVP_MD *hash;
    tls_COMP *comp;
    int mac_type = NID_undef;
    size_t num, mac_secret_size = 0;
    int ret = 0;

    if (s->s3.tmp.key_block_length != 0)
        return 1;

    if (!tls_cipher_get_evp(s->session, &c, &hash, &mac_type, &mac_secret_size,
                            &comp, s->ext.use_etm)) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_SETUP_KEY_BLOCK,
                 tls_R_CIPHER_OR_HASH_UNAVAILABLE);
        return 0;
    }

    s->s3.tmp.new_sym_enc = c;
    s->s3.tmp.new_hash = hash;
    s->s3.tmp.new_mac_pkey_type = mac_type;
    s->s3.tmp.new_mac_secret_size = mac_secret_size;
    num = EVP_CIPHER_key_length(c) + mac_secret_size + EVP_CIPHER_iv_length(c);
    num *= 2;

    tls3_cleanup_key_block(s);

    if ((p = OPENtls_malloc(num)) == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR, tls_F_TLS1_SETUP_KEY_BLOCK,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }

    s->s3.tmp.key_block_length = num;
    s->s3.tmp.key_block = p;

    Otls_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "client random\n");
        BIO_dump_indent(trc_out, s->s3.client_random, tls3_RANDOM_SIZE, 4);
        BIO_printf(trc_out, "server random\n");
        BIO_dump_indent(trc_out, s->s3.server_random, tls3_RANDOM_SIZE, 4);
        BIO_printf(trc_out, "master key\n");
        BIO_dump_indent(trc_out,
                        s->session->master_key,
                        s->session->master_key_length, 4);
    } Otls_TRACE_END(TLS);

    if (!tls1_generate_key_block(s, p, num)) {
        /* tlsfatal() already called */
        goto err;
    }

    Otls_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "key block\n");
        BIO_dump_indent(trc_out, p, num, 4);
    } Otls_TRACE_END(TLS);

    if (!(s->options & tls_OP_DONT_INSERT_EMPTY_FRAGMENTS)
        && s->method->version <= TLS1_VERSION) {
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

    ret = 1;
 err:
    return ret;
}

size_t tls1_final_finish_mac(tls *s, const char *str, size_t slen,
                             unsigned char *out)
{
    size_t hashlen;
    unsigned char hash[EVP_MAX_MD_SIZE];

    if (!tls3_digest_cached_records(s, 0)) {
        /* tlsfatal() already called */
        return 0;
    }

    if (!tls_handshake_hash(s, hash, sizeof(hash), &hashlen)) {
        /* tlsfatal() already called */
        return 0;
    }

    if (!tls1_PRF(s, str, slen, hash, hashlen, NULL, 0, NULL, 0, NULL, 0,
                  s->session->master_key, s->session->master_key_length,
                  out, TLS1_FINISH_MAC_LENGTH, 1)) {
        /* tlsfatal() already called */
        return 0;
    }
    OPENtls_cleanse(hash, hashlen);
    return TLS1_FINISH_MAC_LENGTH;
}

int tls1_generate_master_secret(tls *s, unsigned char *out, unsigned char *p,
                                size_t len, size_t *secret_size)
{
    if (s->session->flags & tls_SESS_FLAG_EXTMS) {
        unsigned char hash[EVP_MAX_MD_SIZE * 2];
        size_t hashlen;
        /*
         * Digest cached records keeping record buffer (if present): this won't
         * affect client auth because we're freezing the buffer at the same
         * point (after client key exchange and before certificate verify)
         */
        if (!tls3_digest_cached_records(s, 1)
                || !tls_handshake_hash(s, hash, sizeof(hash), &hashlen)) {
            /* tlsfatal() already called */
            return 0;
        }
        Otls_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "Handshake hashes:\n");
            BIO_dump(trc_out, (char *)hash, hashlen);
        } Otls_TRACE_END(TLS);
        if (!tls1_PRF(s,
                      TLS_MD_EXTENDED_MASTER_SECRET_CONST,
                      TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE,
                      hash, hashlen,
                      NULL, 0,
                      NULL, 0,
                      NULL, 0, p, len, out,
                      tls3_MASTER_SECRET_SIZE, 1)) {
            /* tlsfatal() already called */
            return 0;
        }
        OPENtls_cleanse(hash, hashlen);
    } else {
        if (!tls1_PRF(s,
                      TLS_MD_MASTER_SECRET_CONST,
                      TLS_MD_MASTER_SECRET_CONST_SIZE,
                      s->s3.client_random, tls3_RANDOM_SIZE,
                      NULL, 0,
                      s->s3.server_random, tls3_RANDOM_SIZE,
                      NULL, 0, p, len, out,
                      tls3_MASTER_SECRET_SIZE, 1)) {
           /* tlsfatal() already called */
            return 0;
        }
    }

    Otls_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "Premaster Secret:\n");
        BIO_dump_indent(trc_out, p, len, 4);
        BIO_printf(trc_out, "Client Random:\n");
        BIO_dump_indent(trc_out, s->s3.client_random, tls3_RANDOM_SIZE, 4);
        BIO_printf(trc_out, "Server Random:\n");
        BIO_dump_indent(trc_out, s->s3.server_random, tls3_RANDOM_SIZE, 4);
        BIO_printf(trc_out, "Master Secret:\n");
        BIO_dump_indent(trc_out,
                        s->session->master_key,
                        tls3_MASTER_SECRET_SIZE, 4);
    } Otls_TRACE_END(TLS);

    *secret_size = tls3_MASTER_SECRET_SIZE;
    return 1;
}

int tls1_export_keying_material(tls *s, unsigned char *out, size_t olen,
                                const char *label, size_t llen,
                                const unsigned char *context,
                                size_t contextlen, int use_context)
{
    unsigned char *val = NULL;
    size_t vallen = 0, currentvalpos;
    int rv;

    /*
     * construct PRF arguments we construct the PRF argument ourself rather
     * than passing separate values into the TLS PRF to ensure that the
     * concatenation of values does not create a prohibited label.
     */
    vallen = llen + tls3_RANDOM_SIZE * 2;
    if (use_context) {
        vallen += 2 + contextlen;
    }

    val = OPENtls_malloc(vallen);
    if (val == NULL)
        goto err2;
    currentvalpos = 0;
    memcpy(val + currentvalpos, (unsigned char *)label, llen);
    currentvalpos += llen;
    memcpy(val + currentvalpos, s->s3.client_random, tls3_RANDOM_SIZE);
    currentvalpos += tls3_RANDOM_SIZE;
    memcpy(val + currentvalpos, s->s3.server_random, tls3_RANDOM_SIZE);
    currentvalpos += tls3_RANDOM_SIZE;

    if (use_context) {
        val[currentvalpos] = (contextlen >> 8) & 0xff;
        currentvalpos++;
        val[currentvalpos] = contextlen & 0xff;
        currentvalpos++;
        if ((contextlen > 0) || (context != NULL)) {
            memcpy(val + currentvalpos, context, contextlen);
        }
    }

    /*
     * disallow prohibited labels note that tls3_RANDOM_SIZE > max(prohibited
     * label len) = 15, so size of val > max(prohibited label len) = 15 and
     * the comparisons won't have buffer overflow
     */
    if (memcmp(val, TLS_MD_CLIENT_FINISH_CONST,
               TLS_MD_CLIENT_FINISH_CONST_SIZE) == 0)
        goto err1;
    if (memcmp(val, TLS_MD_SERVER_FINISH_CONST,
               TLS_MD_SERVER_FINISH_CONST_SIZE) == 0)
        goto err1;
    if (memcmp(val, TLS_MD_MASTER_SECRET_CONST,
               TLS_MD_MASTER_SECRET_CONST_SIZE) == 0)
        goto err1;
    if (memcmp(val, TLS_MD_EXTENDED_MASTER_SECRET_CONST,
               TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE) == 0)
        goto err1;
    if (memcmp(val, TLS_MD_KEY_EXPANSION_CONST,
               TLS_MD_KEY_EXPANSION_CONST_SIZE) == 0)
        goto err1;

    rv = tls1_PRF(s,
                  val, vallen,
                  NULL, 0,
                  NULL, 0,
                  NULL, 0,
                  NULL, 0,
                  s->session->master_key, s->session->master_key_length,
                  out, olen, 0);

    goto ret;
 err1:
    tlserr(tls_F_TLS1_EXPORT_KEYING_MATERIAL, tls_R_TLS_ILLEGAL_EXPORTER_LABEL);
    rv = 0;
    goto ret;
 err2:
    tlserr(tls_F_TLS1_EXPORT_KEYING_MATERIAL, ERR_R_MALLOC_FAILURE);
    rv = 0;
 ret:
    OPENtls_clear_free(val, vallen);
    return rv;
}

int tls1_alert_code(int code)
{
    switch (code) {
    case tls_AD_CLOSE_NOTIFY:
        return tls3_AD_CLOSE_NOTIFY;
    case tls_AD_UNEXPECTED_MESSAGE:
        return tls3_AD_UNEXPECTED_MESSAGE;
    case tls_AD_BAD_RECORD_MAC:
        return tls3_AD_BAD_RECORD_MAC;
    case tls_AD_DECRYPTION_FAILED:
        return TLS1_AD_DECRYPTION_FAILED;
    case tls_AD_RECORD_OVERFLOW:
        return TLS1_AD_RECORD_OVERFLOW;
    case tls_AD_DECOMPRESSION_FAILURE:
        return tls3_AD_DECOMPRESSION_FAILURE;
    case tls_AD_HANDSHAKE_FAILURE:
        return tls3_AD_HANDSHAKE_FAILURE;
    case tls_AD_NO_CERTIFICATE:
        return -1;
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
        return TLS1_AD_UNKNOWN_CA;
    case tls_AD_ACCESS_DENIED:
        return TLS1_AD_ACCESS_DENIED;
    case tls_AD_DECODE_ERROR:
        return TLS1_AD_DECODE_ERROR;
    case tls_AD_DECRYPT_ERROR:
        return TLS1_AD_DECRYPT_ERROR;
    case tls_AD_EXPORT_RESTRICTION:
        return TLS1_AD_EXPORT_RESTRICTION;
    case tls_AD_PROTOCOL_VERSION:
        return TLS1_AD_PROTOCOL_VERSION;
    case tls_AD_INSUFFICIENT_SECURITY:
        return TLS1_AD_INSUFFICIENT_SECURITY;
    case tls_AD_INTERNAL_ERROR:
        return TLS1_AD_INTERNAL_ERROR;
    case tls_AD_USER_CANCELLED:
        return TLS1_AD_USER_CANCELLED;
    case tls_AD_NO_RENEGOTIATION:
        return TLS1_AD_NO_RENEGOTIATION;
    case tls_AD_UNSUPPORTED_EXTENSION:
        return TLS1_AD_UNSUPPORTED_EXTENSION;
    case tls_AD_CERTIFICATE_UNOBTAINABLE:
        return TLS1_AD_CERTIFICATE_UNOBTAINABLE;
    case tls_AD_UNRECOGNIZED_NAME:
        return TLS1_AD_UNRECOGNIZED_NAME;
    case tls_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
        return TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
    case tls_AD_BAD_CERTIFICATE_HASH_VALUE:
        return TLS1_AD_BAD_CERTIFICATE_HASH_VALUE;
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
