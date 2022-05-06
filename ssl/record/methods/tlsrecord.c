/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include "internal/e_os.h"
#include "internal/packet.h"
#include "../../ssl_local.h"
#include "../record_local.h"

/* Protocol version specific function pointers */
struct record_functions_st
{
    int (*set_crypto_state)(OSSL_RECORD_LAYER *rl, int level,
                            unsigned char *key, size_t keylen,
                            unsigned char *iv, size_t ivlen,
                            unsigned char *mackey, size_t mackeylen,
                            const EVP_CIPHER *ciph,
                            size_t taglen,
                            /* TODO(RECLAYER): This probably should not be an int */
                            int mactype,
                            const EVP_MD *md,
                            const SSL_COMP *comp,
                            /* TODO(RECLAYER): Remove me */
                            SSL_CONNECTION *s);
    int (*cipher)(OSSL_RECORD_LAYER *rl, SSL3_RECORD *recs, size_t n_recs,
                  int sending, SSL_MAC_BUF *macs, size_t macsize,
                  /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s);
    int (*mac)(OSSL_RECORD_LAYER *rl, SSL3_RECORD *rec, unsigned char *md,
               int sending, /* TODO(RECLAYER): Remove me */SSL_CONNECTION *ssl);
};

struct ossl_record_layer_st
{
    OSSL_LIB_CTX *libctx;
    const char *propq;
    int isdtls;
    int version;
    int role;
    int direction;
    BIO *bio;
    /* Types match the equivalent structures in the SSL object */
    uint64_t options;
    /*
     * TODO(RECLAYER): Should we take the opportunity to make this uint64_t
     * even though upper layer continue to use uint32_t?
     */
    uint32_t mode;

    /* read IO goes into here */
    SSL3_BUFFER rbuf;
    /* each decoded record goes in here */
    SSL3_RECORD rrec[SSL_MAX_PIPELINES];

    /* How many records have we got available in the rrec bufer */
    size_t num_recs;

    /* The record number in the rrec buffer that can be read next */
    size_t curr_rec;

    /* The number of records that have been released via tls_release_record */
    size_t num_released;

    /* Set to true if this is the first record in a connection */
    unsigned int is_first_record;

    /* where we are when reading */
    int rstate;

    /* used internally to point at a raw packet */
    unsigned char *packet;
    size_t packet_length;

    int alert;

    /*
     * Read as many input bytes as possible (for
     * non-blocking reads)
     * TODO(RECLAYER): Why isn't this just an option?
     */
    int read_ahead;

    /* The number of consecutive empty records we have received */
    size_t empty_record_count;

    /* cryptographic state */
    EVP_CIPHER_CTX *enc_read_ctx;
    /* TLSv1.3 static read IV */
    unsigned char read_iv[EVP_MAX_IV_LENGTH];
    /* used for mac generation */
    EVP_MD_CTX *read_hash;
    /* uncompress */
    COMP_CTX *expand;

    /* Only used by SSLv3 */
    unsigned char mac_secret[EVP_MAX_MD_SIZE];

    /* TLSv1.3 static IV */
    unsigned char iv[EVP_MAX_IV_LENGTH];

    size_t taglen;

    /* Function pointers for version specific functions */
    /* Function pointers for version specific functions */
    struct record_functions_st *funcs;
};

# define SSL_AD_NO_ALERT    -1

static void rlayer_fatal(OSSL_RECORD_LAYER *rl, int al, int reason,
                         const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    ERR_vset_error(ERR_LIB_SSL, reason, fmt, args);
    va_end(args);

    rl->alert = al;
}


# define RLAYERfatal(rl, al, r) RLAYERfatal_data((rl), (al), (r), NULL)
# define RLAYERfatal_data                                          \
    (ERR_new(),                                                    \
     ERR_set_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC),      \
     rlayer_fatal)

static int tls_provider_set_tls_parameters(OSSL_RECORD_LAYER *rl,
                                           EVP_CIPHER_CTX *ctx,
                                           const EVP_CIPHER *ciph,
                                           const EVP_MD *md,
                                           SSL_CONNECTION *s)
{
    /*
     * Provided cipher, the TLS padding/MAC removal is performed provider
     * side so we need to tell the ctx about our TLS version and mac size
     */
    OSSL_PARAM params[3], *pprm = params;
    size_t macsize = 0;
    int imacsize = -1;

    if ((EVP_CIPHER_get_flags(ciph) & EVP_CIPH_FLAG_AEAD_CIPHER) == 0
               /*
                * We look at s->ext.use_etm instead of SSL_READ_ETM() or
                * SSL_WRITE_ETM() because this test applies to both reading
                * and writing.
                */
            && !s->ext.use_etm)
        imacsize = EVP_MD_get_size(md);
    if (imacsize >= 0)
        macsize = (size_t)imacsize;

    *pprm++ = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_TLS_VERSION,
                                       &rl->version);
    *pprm++ = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
                                          &macsize);
    *pprm = OSSL_PARAM_construct_end();

    if (!EVP_CIPHER_CTX_set_params(ctx, params)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int tls_any_set_crypto_state(OSSL_RECORD_LAYER *rl, int level,
                                    unsigned char *key, size_t keylen,
                                    unsigned char *iv, size_t ivlen,
                                    unsigned char *mackey, size_t mackeylen,
                                    const EVP_CIPHER *ciph,
                                    size_t taglen,
                                    /* TODO(RECLAYER): This probably should not be an int */
                                    int mactype,
                                    const EVP_MD *md,
                                    const SSL_COMP *comp,
                                    /* TODO(RECLAYER): Remove me */
                                    SSL_CONNECTION *s)
{
    if (level != OSSL_RECORD_PROTECTION_LEVEL_NONE) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* No crypto protection at the "NONE" level so nothing to be done */

    return 1;
}

/* TODO(RECLAYER): Handle OPENSSL_NO_COMP */
static int ssl3_set_crypto_state(OSSL_RECORD_LAYER *rl, int level,
                                 unsigned char *key, size_t keylen,
                                 unsigned char *iv, size_t ivlen,
                                 unsigned char *mackey, size_t mackeylen,
                                 const EVP_CIPHER *ciph,
                                 size_t taglen,
                                 /* TODO(RECLAYER): This probably should not be an int */
                                 int mactype,
                                 const EVP_MD *md,
                                 const SSL_COMP *comp,
                                 /* TODO(RECLAYER): Remove me */
                                 SSL_CONNECTION *s)
{
    EVP_CIPHER_CTX *ciph_ctx;

    if (md == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if ((rl->enc_read_ctx = EVP_CIPHER_CTX_new()) == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ciph_ctx = rl->enc_read_ctx;

    rl->read_hash = EVP_MD_CTX_new();
    if (rl->read_hash == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#ifndef OPENSSL_NO_COMP
    if (comp != NULL) {
        rl->expand = COMP_CTX_new(comp->method);
        if (rl->expand == NULL) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR,
                        SSL_R_COMPRESSION_LIBRARY_ERROR);
            return 0;
        }
    }
#endif

    if (!EVP_DecryptInit_ex(ciph_ctx, ciph, NULL, key, iv)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (EVP_CIPHER_get0_provider(ciph) != NULL
            && !tls_provider_set_tls_parameters(rl, ciph_ctx, ciph, md, s)) {
        /* RLAYERfatal already called */
        return 0;
    }

    if (mackeylen > sizeof(rl->mac_secret)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    memcpy(rl->mac_secret, mackey, mackeylen);

    return 1;
}

/* TODO(RECLAYER): Handle OPENSSL_NO_COMP */
static int tls1_set_crypto_state(OSSL_RECORD_LAYER *rl, int level,
                                 unsigned char *key, size_t keylen,
                                 unsigned char *iv, size_t ivlen,
                                 unsigned char *mackey, size_t mackeylen,
                                 const EVP_CIPHER *ciph,
                                 size_t taglen,
                                 /* TODO(RECLAYER): This probably should not be an int */
                                 int mactype,
                                 const EVP_MD *md,
                                 const SSL_COMP *comp,
                                 /* TODO(RECLAYER): Remove me */
                                 SSL_CONNECTION *s)
{
    EVP_CIPHER_CTX *ciph_ctx;
    EVP_PKEY *mac_key;

    if (level != OSSL_RECORD_PROTECTION_LEVEL_APPLICATION)
        return 0;

    if (s->ext.use_etm)
        s->s3.flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC_READ;
    else
        s->s3.flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC_READ;

    if (s->s3.tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
        s->mac_flags |= SSL_MAC_FLAG_READ_MAC_STREAM;
    else
        s->mac_flags &= ~SSL_MAC_FLAG_READ_MAC_STREAM;

    if (s->s3.tmp.new_cipher->algorithm2 & TLS1_TLSTREE)
        s->mac_flags |= SSL_MAC_FLAG_READ_MAC_TLSTREE;
    else
        s->mac_flags &= ~SSL_MAC_FLAG_READ_MAC_TLSTREE;

    if ((rl->enc_read_ctx = EVP_CIPHER_CTX_new()) == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ciph_ctx = rl->enc_read_ctx;

    rl->read_hash = EVP_MD_CTX_new();
    if (rl->read_hash == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#ifndef OPENSSL_NO_COMP
    if (comp != NULL) {
        rl->expand = COMP_CTX_new(comp->method);
        if (rl->expand == NULL) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR,
                        SSL_R_COMPRESSION_LIBRARY_ERROR);
            return 0;
        }
    }
#endif
    /*
     * this is done by dtls1_reset_seq_numbers for DTLS
     */
    if (!rl->isdtls)
        RECORD_LAYER_reset_read_sequence(&s->rlayer);

    /*
     * If we have an AEAD Cipher, then there is no separate MAC, so we can skip
     * setting up the MAC key.
     */
    if (!(EVP_CIPHER_get_flags(ciph) & EVP_CIPH_FLAG_AEAD_CIPHER)) {
        if (mactype == EVP_PKEY_HMAC) {
            mac_key = EVP_PKEY_new_raw_private_key_ex(rl->libctx, "HMAC",
                                                      rl->propq, mackey,
                                                      mackeylen);
        } else {
            /*
             * If its not HMAC then the only other types of MAC we support are
             * the GOST MACs, so we need to use the old style way of creating
             * a MAC key.
             */
            mac_key = EVP_PKEY_new_mac_key(mactype, NULL, mackey,
                                           (int)mackeylen);
        }
        if (mac_key == NULL
            || EVP_DigestSignInit_ex(rl->read_hash, NULL, EVP_MD_get0_name(md),
                                     rl->libctx, rl->propq, mac_key,
                                     NULL) <= 0) {
            EVP_PKEY_free(mac_key);
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        EVP_PKEY_free(mac_key);
    }

    if (EVP_CIPHER_get_mode(ciph) == EVP_CIPH_GCM_MODE) {
        if (!EVP_DecryptInit_ex(ciph_ctx, ciph, NULL, key, NULL)
                || !EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_GCM_SET_IV_FIXED,
                                        (int)ivlen, iv)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else if (EVP_CIPHER_get_mode(ciph) == EVP_CIPH_CCM_MODE) {
        if (!EVP_DecryptInit_ex(ciph_ctx, ciph, NULL, NULL, NULL)
                || !EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_AEAD_SET_IVLEN, 12,
                                        NULL)
                || !EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_AEAD_SET_TAG,
                                        (int)taglen, NULL)
                || !EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_CCM_SET_IV_FIXED,
                                        (int)ivlen, iv)
                   /*
                    * TODO(RECLAYER): Why do we defer setting the key until here?
                    * why not in the initial EVP_DecryptInit_ex() call?
                    */
                || !EVP_DecryptInit_ex(ciph_ctx, NULL, NULL, key, NULL)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        if (!EVP_DecryptInit_ex(ciph_ctx, ciph, NULL, key, iv)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    /* Needed for "composite" AEADs, such as RC4-HMAC-MD5 */
    if ((EVP_CIPHER_get_flags(ciph) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0
        && mackeylen != 0
        && !EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_AEAD_SET_MAC_KEY,
                                (int)mackeylen, mackey)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (EVP_CIPHER_get0_provider(ciph) != NULL
            && !tls_provider_set_tls_parameters(rl, ciph_ctx, ciph, md, s)) {
        /* RLAYERfatal already called */
        return 0;
    }

    return 1;
}

static int tls13_set_crypto_state(OSSL_RECORD_LAYER *rl, int level,
                                  unsigned char *key, size_t keylen,
                                  unsigned char *iv, size_t ivlen,
                                  unsigned char *mackey, size_t mackeylen,
                                  const EVP_CIPHER *ciph,
                                  size_t taglen,
                                  /* TODO(RECLAYER): This probably should not be an int */
                                  int mactype,
                                  const EVP_MD *md,
                                  const SSL_COMP *comp,
                                  /* TODO(RECLAYER): Remove me */
                                  SSL_CONNECTION *s)
{
    EVP_CIPHER_CTX *ciph_ctx;
    int mode;

    if (ivlen > sizeof(rl->iv)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    memcpy(rl->iv, iv, ivlen);

    ciph_ctx = rl->enc_read_ctx = EVP_CIPHER_CTX_new();
    if (ciph_ctx == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    RECORD_LAYER_reset_read_sequence(&s->rlayer);
    rl->taglen = taglen;

    mode = EVP_CIPHER_get_mode(ciph);

    if (EVP_DecryptInit_ex(ciph_ctx, ciph, NULL, NULL, NULL) <= 0
        || !EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL)
        || (mode == EVP_CIPH_CCM_MODE
            && !EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_AEAD_SET_TAG,  taglen, NULL))
        || EVP_DecryptInit_ex(ciph_ctx, NULL, NULL, key, NULL) <= 0) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        return 0;
    }

    return 1;
}

static int tls_any_cipher(OSSL_RECORD_LAYER *rl, SSL3_RECORD *recs, size_t n_recs,
                          int sending, SSL_MAC_BUF *macs, size_t macsize,
                          /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s)
{
    size_t ctr;

    for (ctr = 0; ctr < n_recs; ctr++) {
        memmove(recs[ctr].data, recs[ctr].input, recs[ctr].length);
        recs[ctr].input = recs[ctr].data;
    }

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
static int ssl3_cipher(OSSL_RECORD_LAYER *rl, SSL3_RECORD *inrecs, size_t n_recs,
                       int sending, SSL_MAC_BUF *mac, size_t macsize,
                       /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s)
{
    SSL3_RECORD *rec;
    EVP_CIPHER_CTX *ds;
    size_t l, i;
    size_t bs;
    const EVP_CIPHER *enc;
    int provided;

    rec = inrecs;
    /*
     * We shouldn't ever be called with more than one record in the SSLv3 case
     */
    if (n_recs != 1)
        return 0;
    if (sending) {
        ds = s->enc_write_ctx;
        if (s->enc_write_ctx == NULL)
            enc = NULL;
        else
            enc = EVP_CIPHER_CTX_get0_cipher(s->enc_write_ctx);
    } else {
        ds = rl->enc_read_ctx;
        if (rl->enc_read_ctx == NULL)
            enc = NULL;
        else
            enc = EVP_CIPHER_CTX_get0_cipher(rl->enc_read_ctx);
    }

    provided = (EVP_CIPHER_get0_provider(enc) != NULL);

    l = rec->length;
    bs = EVP_CIPHER_CTX_get_block_size(ds);

    /* COMPRESS */

    if ((bs != 1) && sending && !provided) {
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

    if (!sending) {
        if (l == 0 || l % bs != 0) {
            /* Publicly invalid */
            return 0;
        }
        /* otherwise, rec->length >= bs */
    }

    if (provided) {
        int outlen;

        if (!EVP_CipherUpdate(ds, rec->data, &outlen, rec->input,
                                (unsigned int)l))
            return 0;
        rec->length = outlen;

        if (!sending && mac != NULL) {
            /* Now get a pointer to the MAC */
            OSSL_PARAM params[2], *p = params;

            /* Get the MAC */
            mac->alloced = 0;

            *p++ = OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_TLS_MAC,
                                                    (void **)&mac->mac,
                                                    macsize);
            *p = OSSL_PARAM_construct_end();

            if (!EVP_CIPHER_CTX_get_params(ds, params)) {
                /* Shouldn't normally happen */
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    } else {
        if (EVP_Cipher(ds, rec->data, rec->input, (unsigned int)l) < 1) {
            /* Shouldn't happen */
            RLAYERfatal(rl, SSL_AD_BAD_RECORD_MAC, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (!sending)
            return ssl3_cbc_remove_padding_and_mac(&rec->length,
                                        rec->orig_len,
                                        rec->data,
                                        (mac != NULL) ? &mac->mac : NULL,
                                        (mac != NULL) ? &mac->alloced : NULL,
                                        bs,
                                        macsize,
                                        rl->libctx);
    }

    return 1;
}

#define MAX_PADDING 256
/*-
 * tls1_cipher encrypts/decrypts |n_recs| in |recs|. Calls SSLfatal on internal
 * error, but not otherwise. It is the responsibility of the caller to report
 * a bad_record_mac - if appropriate (DTLS just drops the record).
 *
 * Returns:
 *    0: if the record is publicly invalid, or an internal error, or AEAD
 *       decryption failed, or Encrypt-then-mac decryption failed.
 *    1: Success or Mac-then-encrypt decryption failed (MAC will be randomised)
 */
static int tls1_cipher(OSSL_RECORD_LAYER *rl, SSL3_RECORD *recs, size_t n_recs,
                       int sending, SSL_MAC_BUF *macs, size_t macsize,
                       /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s)
{
    EVP_CIPHER_CTX *ds;
    size_t reclen[SSL_MAX_PIPELINES];
    unsigned char buf[SSL_MAX_PIPELINES][EVP_AEAD_TLS1_AAD_LEN];
    int i, pad = 0, tmpr, provided;
    size_t bs, ctr, padnum, loop;
    unsigned char padval;
    const EVP_CIPHER *enc;
    int tlstree_enc = sending ? (s->mac_flags & SSL_MAC_FLAG_WRITE_MAC_TLSTREE)
                              : (s->mac_flags & SSL_MAC_FLAG_READ_MAC_TLSTREE);
    SSL_CTX *sctx = SSL_CONNECTION_GET_CTX(s);

    if (n_recs == 0) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (sending) {
        int ivlen;

        if (EVP_MD_CTX_get0_md(s->write_hash)) {
            int n = EVP_MD_CTX_get_size(s->write_hash);
            if (!ossl_assert(n >= 0)) {
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
        ds = s->enc_write_ctx;
        if (!ossl_assert(s->enc_write_ctx)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }

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
                    RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                } else if (RAND_bytes_ex(sctx->libctx, recs[ctr].input,
                                            ivlen, 0) <= 0) {
                    RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
            }
        }
    } else {
        if (EVP_MD_CTX_get0_md(rl->read_hash)) {
            int n = EVP_MD_CTX_get_size(rl->read_hash);
            if (!ossl_assert(n >= 0)) {
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
        ds = rl->enc_read_ctx;
        if (!ossl_assert(rl->enc_read_ctx)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        enc = EVP_CIPHER_CTX_get0_cipher(rl->enc_read_ctx);
    }

    if ((s->session == NULL) || (enc == NULL)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    provided = (EVP_CIPHER_get0_provider(enc) != NULL);

    bs = EVP_CIPHER_get_block_size(EVP_CIPHER_CTX_get0_cipher(ds));

    if (n_recs > 1) {
        if ((EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ds))
                & EVP_CIPH_FLAG_PIPELINE) == 0) {
            /*
                * We shouldn't have been called with pipeline data if the
                * cipher doesn't support pipelining
                */
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_PIPELINE_FAILURE);
            return 0;
        }
    }
    for (ctr = 0; ctr < n_recs; ctr++) {
        reclen[ctr] = recs[ctr].length;

        if ((EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ds))
                    & EVP_CIPH_FLAG_AEAD_CIPHER) != 0) {
            unsigned char *seq;

            seq = sending ? RECORD_LAYER_get_write_sequence(&s->rlayer)
                : RECORD_LAYER_get_read_sequence(&s->rlayer);

            if (SSL_CONNECTION_IS_DTLS(s)) {
                /* DTLS does not support pipelining */
                unsigned char dtlsseq[8], *p = dtlsseq;

                s2n(sending ? DTLS_RECORD_LAYER_get_w_epoch(&s->rlayer) :
                    DTLS_RECORD_LAYER_get_r_epoch(&s->rlayer), p);
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
            buf[ctr][9] = (unsigned char)(rl->version >> 8);
            buf[ctr][10] = (unsigned char)(rl->version);
            buf[ctr][11] = (unsigned char)(recs[ctr].length >> 8);
            buf[ctr][12] = (unsigned char)(recs[ctr].length & 0xff);
            pad = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_TLS1_AAD,
                                        EVP_AEAD_TLS1_AAD_LEN, buf[ctr]);
            if (pad <= 0) {
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }

            if (sending) {
                reclen[ctr] += pad;
                recs[ctr].length += pad;
            }

        } else if ((bs != 1) && sending && !provided) {
            /*
                * We only do this for legacy ciphers. Provided ciphers add the
                * padding on the provider side.
                */
            padnum = bs - (reclen[ctr] % bs);

            /* Add weird padding of up to 256 bytes */

            if (padnum > MAX_PADDING) {
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            /* we need to add 'padnum' padding bytes of value padval */
            padval = (unsigned char)(padnum - 1);
            for (loop = reclen[ctr]; loop < reclen[ctr] + padnum; loop++)
                recs[ctr].input[loop] = padval;
            reclen[ctr] += padnum;
            recs[ctr].length += padnum;
        }

        if (!sending) {
            if (reclen[ctr] == 0 || reclen[ctr] % bs != 0) {
                /* Publicly invalid */
                return 0;
            }
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
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_PIPELINE_FAILURE);
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
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_PIPELINE_FAILURE);
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
        if (sending && !SSL_WRITE_ETM(s))
            decrement_seq = 1;

        seq = sending ? RECORD_LAYER_get_write_sequence(&s->rlayer)
                        : RECORD_LAYER_get_read_sequence(&s->rlayer);
        if (EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_TLSTREE, decrement_seq, seq) <= 0) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (provided) {
        int outlen;

        /* Provided cipher - we do not support pipelining on this path */
        if (n_recs > 1)  {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (!EVP_CipherUpdate(ds, recs[0].data, &outlen, recs[0].input,
                                (unsigned int)reclen[0]))
            return 0;
        recs[0].length = outlen;

        /*
            * The length returned from EVP_CipherUpdate above is the actual
            * payload length. We need to adjust the data/input ptr to skip over
            * any explicit IV
            */
        if (!sending) {
            if (EVP_CIPHER_get_mode(enc) == EVP_CIPH_GCM_MODE) {
                    recs[0].data += EVP_GCM_TLS_EXPLICIT_IV_LEN;
                    recs[0].input += EVP_GCM_TLS_EXPLICIT_IV_LEN;
            } else if (EVP_CIPHER_get_mode(enc) == EVP_CIPH_CCM_MODE) {
                    recs[0].data += EVP_CCM_TLS_EXPLICIT_IV_LEN;
                    recs[0].input += EVP_CCM_TLS_EXPLICIT_IV_LEN;
            } else if (bs != 1 && SSL_USE_EXPLICIT_IV(s)) {
                recs[0].data += bs;
                recs[0].input += bs;
                recs[0].orig_len -= bs;
            }

            /* Now get a pointer to the MAC (if applicable) */
            if (macs != NULL) {
                OSSL_PARAM params[2], *p = params;

                /* Get the MAC */
                macs[0].alloced = 0;

                *p++ = OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_TLS_MAC,
                                                        (void **)&macs[0].mac,
                                                        macsize);
                *p = OSSL_PARAM_construct_end();

                if (!EVP_CIPHER_CTX_get_params(ds, params)) {
                    /* Shouldn't normally happen */
                    RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR,
                                ERR_R_INTERNAL_ERROR);
                    return 0;
                }
            }
        }
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

        if (!sending) {
            for (ctr = 0; ctr < n_recs; ctr++) {
                /* Adjust the record to remove the explicit IV/MAC/Tag */
                if (EVP_CIPHER_get_mode(enc) == EVP_CIPH_GCM_MODE) {
                    recs[ctr].data += EVP_GCM_TLS_EXPLICIT_IV_LEN;
                    recs[ctr].input += EVP_GCM_TLS_EXPLICIT_IV_LEN;
                    recs[ctr].length -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
                } else if (EVP_CIPHER_get_mode(enc) == EVP_CIPH_CCM_MODE) {
                    recs[ctr].data += EVP_CCM_TLS_EXPLICIT_IV_LEN;
                    recs[ctr].input += EVP_CCM_TLS_EXPLICIT_IV_LEN;
                    recs[ctr].length -= EVP_CCM_TLS_EXPLICIT_IV_LEN;
                } else if (bs != 1 && SSL_USE_EXPLICIT_IV(s)) {
                    if (recs[ctr].length < bs)
                        return 0;
                    recs[ctr].data += bs;
                    recs[ctr].input += bs;
                    recs[ctr].length -= bs;
                    recs[ctr].orig_len -= bs;
                }

                /*
                    * If using Mac-then-encrypt, then this will succeed but
                    * with a random MAC if padding is invalid
                    */
                if (!tls1_cbc_remove_padding_and_mac(&recs[ctr].length,
                                        recs[ctr].orig_len,
                                        recs[ctr].data,
                                        (macs != NULL) ? &macs[ctr].mac : NULL,
                                        (macs != NULL) ? &macs[ctr].alloced
                                                    : NULL,
                                        bs,
                                        pad ? (size_t)pad : macsize,
                                        (EVP_CIPHER_get_flags(enc)
                                        & EVP_CIPH_FLAG_AEAD_CIPHER) != 0,
                                        sctx->libctx))
                    return 0;
            }
        }
    }
    return 1;
}

static int tls13_cipher(OSSL_RECORD_LAYER *rl, SSL3_RECORD *recs, size_t n_recs,
                        int sending, SSL_MAC_BUF *mac, size_t macsize,
                        /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[EVP_MAX_IV_LENGTH], recheader[SSL3_RT_HEADER_LENGTH];
    size_t ivlen, offset, loop, hdrlen;
    unsigned char *staticiv;
    unsigned char *seq;
    int lenu, lenf;
    SSL3_RECORD *rec = &recs[0];
    WPACKET wpkt;
    const EVP_CIPHER *cipher;
    int mode;

    if (n_recs != 1) {
        /* Should not happen */
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (sending) {
        ctx = s->enc_write_ctx;
        staticiv = s->write_iv;
        seq = RECORD_LAYER_get_write_sequence(&s->rlayer);
    } else {
        ctx = rl->enc_read_ctx;
        staticiv = rl->iv;
        seq = RECORD_LAYER_get_read_sequence(&s->rlayer);
    }

    cipher = EVP_CIPHER_CTX_get0_cipher(ctx);
    if (cipher == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    mode = EVP_CIPHER_get_mode(cipher);

    /*
     * If we're sending an alert and ctx != NULL then we must be forcing
     * plaintext alerts. If we're reading and ctx != NULL then we allow
     * plaintext alerts at certain points in the handshake. If we've got this
     * far then we have already validated that a plaintext alert is ok here.
     */
    if (ctx == NULL || rec->type == SSL3_RT_ALERT) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
        return 1;
    }

    ivlen = EVP_CIPHER_CTX_get_iv_length(ctx);

    if (!sending) {
        /*
         * Take off tag. There must be at least one byte of content type as
         * well as the tag
         */
        if (rec->length < rl->taglen + 1)
            return 0;
        rec->length -= rl->taglen;
    }

    /* Set up IV */
    if (ivlen < SEQ_NUM_SIZE) {
        /* Should not happen */
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    offset = ivlen - SEQ_NUM_SIZE;
    memcpy(iv, staticiv, offset);
    for (loop = 0; loop < SEQ_NUM_SIZE; loop++)
        iv[offset + loop] = staticiv[offset + loop] ^ seq[loop];

    /* Increment the sequence counter */
    for (loop = SEQ_NUM_SIZE; loop > 0; loop--) {
        ++seq[loop - 1];
        if (seq[loop - 1] != 0)
            break;
    }
    if (loop == 0) {
        /* Sequence has wrapped */
        return 0;
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, sending) <= 0
            || (!sending && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                                rl->taglen,
                                                rec->data + rec->length) <= 0)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Set up the AAD */
    if (!WPACKET_init_static_len(&wpkt, recheader, sizeof(recheader), 0)
            || !WPACKET_put_bytes_u8(&wpkt, rec->type)
            || !WPACKET_put_bytes_u16(&wpkt, rec->rec_version)
            || !WPACKET_put_bytes_u16(&wpkt, rec->length + rl->taglen)
            || !WPACKET_get_total_written(&wpkt, &hdrlen)
            || hdrlen != SSL3_RT_HEADER_LENGTH
            || !WPACKET_finish(&wpkt)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        WPACKET_cleanup(&wpkt);
        return 0;
    }

    /*
     * For CCM we must explicitly set the total plaintext length before we add
     * any AAD.
     */
    if ((mode == EVP_CIPH_CCM_MODE
                 && EVP_CipherUpdate(ctx, NULL, &lenu, NULL,
                                     (unsigned int)rec->length) <= 0)
            || EVP_CipherUpdate(ctx, NULL, &lenu, recheader,
                                sizeof(recheader)) <= 0
            || EVP_CipherUpdate(ctx, rec->data, &lenu, rec->input,
                                (unsigned int)rec->length) <= 0
            || EVP_CipherFinal_ex(ctx, rec->data + lenu, &lenf) <= 0
            || (size_t)(lenu + lenf) != rec->length) {
        return 0;
    }
    if (sending) {
        /* Add the tag */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, rl->taglen,
                                rec->data + rec->length) <= 0) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        rec->length += rl->taglen;
    }

    return 1;
}

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

static int ssl3_mac(OSSL_RECORD_LAYER *rl, SSL3_RECORD *rec, unsigned char *md,
                    int sending, SSL_CONNECTION *ssl)
{
    unsigned char *mac_sec, *seq;
    const EVP_MD_CTX *hash;
    unsigned char *p, rec_char;
    size_t md_size;
    size_t npad;
    int t;

    if (sending) {
        mac_sec = &(ssl->s3.write_mac_secret[0]);
        seq = RECORD_LAYER_get_write_sequence(&ssl->rlayer);
        hash = ssl->write_hash;
    } else {
        mac_sec = &(rl->mac_secret[0]);
        seq = RECORD_LAYER_get_read_sequence(&ssl->rlayer);
        hash = rl->read_hash;
    }

    t = EVP_MD_CTX_get_size(hash);
    if (t < 0)
        return 0;
    md_size = t;
    npad = (48 / md_size) * md_size;

    if (!sending
        && EVP_CIPHER_CTX_get_mode(rl->enc_read_ctx) == EVP_CIPH_CBC_MODE
        && ssl3_cbc_record_digest_supported(hash)) {
#ifdef OPENSSL_NO_DEPRECATED_3_0
        return 0;
#else
        /*
         * This is a CBC-encrypted record. We must avoid leaking any
         * timing-side channel information about how many blocks of data we
         * are hashing because that gives an attacker a timing-oracle.
         */

        /*-
         * npad is, at most, 48 bytes and that's with MD5:
         *   16 + 48 + 8 (sequence bytes) + 1 + 2 = 75.
         *
         * With SHA-1 (the largest hash speced for SSLv3) the hash size
         * goes up 4, but npad goes down by 8, resulting in a smaller
         * total size.
         */
        unsigned char header[75];
        size_t j = 0;
        memcpy(header + j, mac_sec, md_size);
        j += md_size;
        memcpy(header + j, ssl3_pad_1, npad);
        j += npad;
        memcpy(header + j, seq, 8);
        j += 8;
        header[j++] = rec->type;
        header[j++] = (unsigned char)(rec->length >> 8);
        header[j++] = (unsigned char)(rec->length & 0xff);

        /* Final param == is SSLv3 */
        if (ssl3_cbc_digest_record(EVP_MD_CTX_get0_md(hash),
                                   md, &md_size,
                                   header, rec->input,
                                   rec->length, rec->orig_len,
                                   mac_sec, md_size, 1) <= 0)
            return 0;
#endif
    } else {
        unsigned int md_size_u;
        /* Chop the digest off the end :-) */
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

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
    }

    ssl3_record_sequence_update(seq);
    return 1;
}

static int tls1_mac(OSSL_RECORD_LAYER *rl, SSL3_RECORD *rec, unsigned char *md,
                    int sending, SSL_CONNECTION *ssl)
{
    unsigned char *seq;
    EVP_MD_CTX *hash;
    size_t md_size;
    int i;
    EVP_MD_CTX *hmac = NULL, *mac_ctx;
    unsigned char header[13];
    int stream_mac = sending ? (ssl->mac_flags & SSL_MAC_FLAG_WRITE_MAC_STREAM)
                             : (ssl->mac_flags & SSL_MAC_FLAG_READ_MAC_STREAM);
    int tlstree_mac = sending ? (ssl->mac_flags & SSL_MAC_FLAG_WRITE_MAC_TLSTREE)
                              : (ssl->mac_flags & SSL_MAC_FLAG_READ_MAC_TLSTREE);
    int t;
    int ret = 0;

    if (sending) {
        seq = RECORD_LAYER_get_write_sequence(&ssl->rlayer);
        hash = ssl->write_hash;
    } else {
        seq = RECORD_LAYER_get_read_sequence(&ssl->rlayer);
        hash = rl->read_hash;
    }

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

    if (!rl->isdtls
            && tlstree_mac
            && EVP_MD_CTX_ctrl(mac_ctx, EVP_MD_CTRL_TLSTREE, 0, seq) <= 0) {
        goto end;
    }

    if (rl->isdtls) {
        unsigned char dtlsseq[8], *p = dtlsseq;

        s2n(sending ? DTLS_RECORD_LAYER_get_w_epoch(&ssl->rlayer) :
            DTLS_RECORD_LAYER_get_r_epoch(&ssl->rlayer), p);
        memcpy(p, &seq[2], 6);

        memcpy(header, dtlsseq, 8);
    } else
        memcpy(header, seq, 8);

    header[8] = rec->type;
    header[9] = (unsigned char)(ssl->version >> 8);
    header[10] = (unsigned char)(ssl->version);
    header[11] = (unsigned char)(rec->length >> 8);
    header[12] = (unsigned char)(rec->length & 0xff);

    if (!sending && !SSL_READ_ETM(ssl)
        && EVP_CIPHER_CTX_get_mode(rl->enc_read_ctx) == EVP_CIPH_CBC_MODE
        && ssl3_cbc_record_digest_supported(mac_ctx)) {
        OSSL_PARAM tls_hmac_params[2], *p = tls_hmac_params;

        *p++ = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE,
                                           &rec->orig_len);
        *p++ = OSSL_PARAM_construct_end();

        if (!EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(mac_ctx),
                                     tls_hmac_params)) {
            goto end;
        }
    }

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

    if (!SSL_CONNECTION_IS_DTLS(ssl)) {
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

struct record_functions_st tls_any_funcs = {
    tls_any_set_crypto_state,
    tls_any_cipher,
    NULL
};

struct record_functions_st tls_1_3_funcs = {
    tls13_set_crypto_state,
    tls13_cipher,
    NULL
};

struct record_functions_st tls_1_2_funcs = {
    tls1_set_crypto_state,
    tls1_cipher,
    tls1_mac
};

struct record_functions_st tls_1_1_funcs = {
    tls1_set_crypto_state,
    tls1_cipher,
    tls1_mac
};

struct record_functions_st tls_1_0_funcs = {
    tls1_set_crypto_state,
    tls1_cipher,
    tls1_mac
};

struct record_functions_st ssl_3_0_funcs = {
    ssl3_set_crypto_state,
    ssl3_cipher,
    ssl3_mac
};

static int tls_set1_bio(OSSL_RECORD_LAYER *rl, BIO *bio);

static int rlayer_allow_compression(OSSL_RECORD_LAYER *rl)
{
    if (rl->options & SSL_OP_NO_COMPRESSION)
        return 0;
#if 0
    /* TODO(RECLAYER): Implement ssl_security inside the record layer */
    return ssl_security(s, SSL_SECOP_COMPRESSION, 0, 0, NULL);
#else
    return 1;
#endif
}

static int rlayer_setup_read_buffer(OSSL_RECORD_LAYER *rl)
{
    unsigned char *p;
    size_t len, align = 0, headerlen;
    SSL3_BUFFER *b;

    b = &rl->rbuf;

    if (rl->isdtls)
        headerlen = DTLS1_RT_HEADER_LENGTH;
    else
        headerlen = SSL3_RT_HEADER_LENGTH;

#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD!=0
    align = (-SSL3_RT_HEADER_LENGTH) & (SSL3_ALIGN_PAYLOAD - 1);
#endif

    if (b->buf == NULL) {
        len = SSL3_RT_MAX_PLAIN_LENGTH
            + SSL3_RT_MAX_ENCRYPTED_OVERHEAD + headerlen + align;
#ifndef OPENSSL_NO_COMP
        if (rlayer_allow_compression(rl))
            len += SSL3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
        if (b->default_len > len)
            len = b->default_len;
        if ((p = OPENSSL_malloc(len)) == NULL) {
            /*
             * We've got a malloc failure, and we're still initialising buffers.
             * We assume we're so doomed that we won't even be able to send an
             * alert.
             */
            RLAYERfatal(rl, SSL_AD_NO_ALERT, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        b->buf = p;
        b->len = len;
    }

    return 1;
}

static int rlayer_release_read_buffer(OSSL_RECORD_LAYER *rl)
{
    SSL3_BUFFER *b;

    b = &rl->rbuf;
    if (rl->options & SSL_OP_CLEANSE_PLAINTEXT)
        OPENSSL_cleanse(b->buf, b->len);
    OPENSSL_free(b->buf);
    b->buf = NULL;
    return 1;
}

static void tls_reset_packet_length(OSSL_RECORD_LAYER *rl)
{
    rl->packet_length = 0;
}

/*
 * Return values are as per SSL_read()
 */
static int tls_read_n(OSSL_RECORD_LAYER *rl, size_t n, size_t max, int extend,
                      int clearold, size_t *readbytes)
{
    /*
     * If extend == 0, obtain new n-byte packet; if extend == 1, increase
     * packet by another n bytes. The packet will be in the sub-array of
     * s->rlayer.rbuf.buf specified by s->rlayer.packet and
     * s->rlayer.packet_length. (If s->rlayer.read_ahead is set, 'max' bytes may
     * be stored in rbuf [plus s->rlayer.packet_length bytes if extend == 1].)
     * if clearold == 1, move the packet to the start of the buffer; if
     * clearold == 0 then leave any old packets where they were
     */
    size_t len, left, align = 0;
    unsigned char *pkt;
    SSL3_BUFFER *rb;

    if (n == 0)
        return OSSL_RECORD_RETURN_NON_FATAL_ERR;

    rb = &rl->rbuf;
    if (rb->buf == NULL) {
        if (!rlayer_setup_read_buffer(rl)) {
            /* RLAYERfatal() already called */
            return OSSL_RECORD_RETURN_FATAL;
        }
    }

    left = rb->left;
#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD != 0
    align = (size_t)rb->buf + SSL3_RT_HEADER_LENGTH;
    align = SSL3_ALIGN_PAYLOAD - 1 - ((align - 1) % SSL3_ALIGN_PAYLOAD);
#endif

    if (!extend) {
        /* start with empty packet ... */
        if (left == 0) {
            rb->offset = align;
        } else if (align != 0 && left >= SSL3_RT_HEADER_LENGTH) {
            /*
             * check if next packet length is large enough to justify payload
             * alignment...
             */
            pkt = rb->buf + rb->offset;
            if (pkt[0] == SSL3_RT_APPLICATION_DATA
                    && (pkt[3] << 8 | pkt[4]) >= 128) {
                /*
                 * Note that even if packet is corrupted and its length field
                 * is insane, we can only be led to wrong decision about
                 * whether memmove will occur or not. Header values has no
                 * effect on memmove arguments and therefore no buffer
                 * overrun can be triggered.
                 */
                memmove(rb->buf + align, pkt, left);
                rb->offset = align;
            }
        }
        rl->packet = rb->buf + rb->offset;
        rl->packet_length = 0;
        /* ... now we can act as if 'extend' was set */
    }

    len = rl->packet_length;
    pkt = rb->buf + align;
    /*
     * Move any available bytes to front of buffer: 'len' bytes already
     * pointed to by 'packet', 'left' extra ones at the end
     */
    if (rl->packet != pkt && clearold == 1) {
        memmove(pkt, rl->packet, len + left);
        rl->packet = pkt;
        rb->offset = len + align;
    }

    /*
     * For DTLS/UDP reads should not span multiple packets because the read
     * operation returns the whole packet at once (as long as it fits into
     * the buffer).
     */
    if (rl->isdtls) {
        if (left == 0 && extend)
            return 0;
        if (left > 0 && n > left)
            n = left;
    }

    /* if there is enough in the buffer from a previous read, take some */
    if (left >= n) {
        rl->packet_length += n;
        rb->left = left - n;
        rb->offset += n;
        *readbytes = n;
        return OSSL_RECORD_RETURN_SUCCESS;
    }

    /* else we need to read more data */

    if (n > rb->len - rb->offset) {
        /* does not happen */
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return OSSL_RECORD_RETURN_FATAL;
    }

    /*
     * Ktls always reads full records.
     * Also, we always act like read_ahead is set for DTLS.
     */
    if (!BIO_get_ktls_recv(rl->bio) && !rl->read_ahead
            && !rl->isdtls) {
        /* ignore max parameter */
        max = n;
    } else {
        if (max < n)
            max = n;
        if (max > rb->len - rb->offset)
            max = rb->len - rb->offset;
    }

    while (left < n) {
        size_t bioread = 0;
        int ret;

        /*
         * Now we have len+left bytes at the front of s->s3.rbuf.buf and
         * need to read in more until we have len+n (up to len+max if
         * possible)
         */

        clear_sys_error();
        if (rl->bio != NULL) {
            ret = BIO_read(rl->bio, pkt + len + left, max - left);
            if (ret > 0) {
                bioread = ret;
                ret = OSSL_RECORD_RETURN_SUCCESS;
            } else if (BIO_should_retry(rl->bio)) {
                ret = OSSL_RECORD_RETURN_RETRY;
            } else if (BIO_eof(rl->bio)) {
                ret = OSSL_RECORD_RETURN_EOF;
            } else {
                ret = OSSL_RECORD_RETURN_FATAL;
            }
        } else {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_READ_BIO_NOT_SET);
            ret = OSSL_RECORD_RETURN_FATAL;
        }

        if (ret <= OSSL_RECORD_RETURN_RETRY) {
            rb->left = left;
            if (rl->mode & SSL_MODE_RELEASE_BUFFERS && !rl->isdtls)
                if (len + left == 0)
                    rlayer_release_read_buffer(rl);
            return ret;
        }
        left += bioread;
        /*
         * reads should *never* span multiple packets for DTLS because the
         * underlying transport protocol is message oriented as opposed to
         * byte oriented as in the TLS case.
         */
        if (rl->isdtls) {
            if (n > left)
                n = left;       /* makes the while condition false */
        }
    }

    /* done reading, now the book-keeping */
    rb->offset += n;
    rb->left = left - n;
    rl->packet_length += n;
    *readbytes = n;
    return OSSL_RECORD_RETURN_SUCCESS;
}

/*
 * Peeks ahead into "read_ahead" data to see if we have a whole record waiting
 * for us in the buffer.
 */
static int tls_record_app_data_waiting(OSSL_RECORD_LAYER *rl)
{
    SSL3_BUFFER *rbuf;
    size_t left, len;
    unsigned char *p;

    rbuf = &rl->rbuf;

    p = SSL3_BUFFER_get_buf(rbuf);
    if (p == NULL)
        return 0;

    left = SSL3_BUFFER_get_left(rbuf);

    if (left < SSL3_RT_HEADER_LENGTH)
        return 0;

    p += SSL3_BUFFER_get_offset(rbuf);

    /*
     * We only check the type and record length, we will sanity check version
     * etc later
     */
    if (*p != SSL3_RT_APPLICATION_DATA)
        return 0;

    p += 3;
    n2s(p, len);

    if (left < SSL3_RT_HEADER_LENGTH + len)
        return 0;

    return 1;
}

/*
 * MAX_EMPTY_RECORDS defines the number of consecutive, empty records that
 * will be processed per call to ssl3_get_record. Without this limit an
 * attacker could send empty records at a faster rate than we can process and
 * cause ssl3_get_record to loop forever.
 */
#define MAX_EMPTY_RECORDS 32

#define SSL2_RT_HEADER_LENGTH   2

/*-
 * Call this to buffer new input records in rl->rrec.
 * It will return a OSSL_RECORD_RETURN_* value.
 * When it finishes successfully (OSSL_RECORD_RETURN_SUCCESS), |rl->num_recs|
 * records have been decoded. For each record 'i':
 * rrec[i].type    - is the type of record
 * rrec[i].data,   - data
 * rrec[i].length, - number of bytes
 * Multiple records will only be returned if the record types are all
 * SSL3_RT_APPLICATION_DATA. The number of records returned will always be <=
 * |max_pipelines|
 */
static int tls_get_more_records(OSSL_RECORD_LAYER *rl, 
                                /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s)
{
    int enc_err, rret;
    int i;
    size_t more, n;
    SSL3_RECORD *rr, *thisrr;
    SSL3_BUFFER *rbuf;
    SSL_SESSION *sess;
    unsigned char *p;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int version;
    size_t mac_size = 0;
    int imac_size;
    size_t num_recs = 0, max_recs, j;
    PACKET pkt, sslv2pkt;
    int using_ktls;
    SSL_MAC_BUF *macbufs = NULL;
    int ret = OSSL_RECORD_RETURN_FATAL;
    SSL *ssl = SSL_CONNECTION_GET_SSL(s);

    rr = rl->rrec;
    rbuf = &rl->rbuf;

    max_recs = s->max_pipelines;
    if (max_recs == 0)
        max_recs = 1;
    sess = s->session;

    /*
     * KTLS reads full records. If there is any data left,
     * then it is from before enabling ktls.
     */
    using_ktls = BIO_get_ktls_recv(rl->bio) && SSL3_BUFFER_get_left(rbuf) == 0;

    do {
        thisrr = &rr[num_recs];

        /* check if we have the header */
        if ((rl->rstate != SSL_ST_READ_BODY) ||
            (rl->packet_length < SSL3_RT_HEADER_LENGTH)) {
            size_t sslv2len;
            unsigned int type;

            rret = tls_read_n(rl, SSL3_RT_HEADER_LENGTH,
                              SSL3_BUFFER_get_len(rbuf), 0,
                              num_recs == 0 ? 1 : 0, &n);

            if (rret < OSSL_RECORD_RETURN_SUCCESS) {
#ifndef OPENSSL_NO_KTLS
                if (!BIO_get_ktls_recv(rl->bio) || rret == 0)
                    return rret;     /* error or non-blocking */
                switch (errno) {
                case EBADMSG:
                    RLAYERfatal(rl, SSL_AD_BAD_RECORD_MAC,
                                SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
                    break;
                case EMSGSIZE:
                    RLAYERfatal(rl, SSL_AD_RECORD_OVERFLOW,
                                SSL_R_PACKET_LENGTH_TOO_LONG);
                    break;
                case EINVAL:
                    RLAYERfatal(rl, SSL_AD_PROTOCOL_VERSION,
                                SSL_R_WRONG_VERSION_NUMBER);
                    break;
                default:
                    break;
                }
#endif
                return rret;
            }
            rl->rstate = SSL_ST_READ_BODY;

            p = rl->packet;
            if (!PACKET_buf_init(&pkt, p, rl->packet_length)) {
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return OSSL_RECORD_RETURN_FATAL;
            }
            sslv2pkt = pkt;
            if (!PACKET_get_net_2_len(&sslv2pkt, &sslv2len)
                    || !PACKET_get_1(&sslv2pkt, &type)) {
                RLAYERfatal(rl, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
                return OSSL_RECORD_RETURN_FATAL;
            }
            /*
             * The first record received by the server may be a V2ClientHello.
             */
            if (rl->role == OSSL_RECORD_ROLE_SERVER
                    && rl->is_first_record
                    && (sslv2len & 0x8000) != 0
                    && (type == SSL2_MT_CLIENT_HELLO)) {
                /*
                 *  SSLv2 style record
                 *
                 * |num_recs| here will actually always be 0 because
                 * |num_recs > 0| only ever occurs when we are processing
                 * multiple app data records - which we know isn't the case here
                 * because it is an SSLv2ClientHello. We keep it using
                 * |num_recs| for the sake of consistency
                 */
                thisrr->type = SSL3_RT_HANDSHAKE;
                thisrr->rec_version = SSL2_VERSION;

                thisrr->length = sslv2len & 0x7fff;

                if (thisrr->length > SSL3_BUFFER_get_len(rbuf)
                    - SSL2_RT_HEADER_LENGTH) {
                    RLAYERfatal(rl, SSL_AD_RECORD_OVERFLOW,
                                SSL_R_PACKET_LENGTH_TOO_LONG);
                    return OSSL_RECORD_RETURN_FATAL;
                }

                if (thisrr->length < MIN_SSL2_RECORD_LEN) {
                    RLAYERfatal(rl, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_TOO_SHORT);
                    return OSSL_RECORD_RETURN_FATAL;
                }
            } else {
                /* SSLv3+ style record */

                /* Pull apart the header into the SSL3_RECORD */
                if (!PACKET_get_1(&pkt, &type)
                        || !PACKET_get_net_2(&pkt, &version)
                        || !PACKET_get_net_2_len(&pkt, &thisrr->length)) {
                    if (s->msg_callback)
                        s->msg_callback(0, 0, SSL3_RT_HEADER, p, 5, ssl,
                                        s->msg_callback_arg);
                    RLAYERfatal(rl, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
                    return OSSL_RECORD_RETURN_FATAL;
                }
                thisrr->type = type;
                thisrr->rec_version = version;

                if (s->msg_callback)
                    s->msg_callback(0, version, SSL3_RT_HEADER, p, 5, ssl,
                                    s->msg_callback_arg);

                /*
                 * Lets check version. In TLSv1.3 we only check this field
                 * when encryption is occurring (see later check). For the
                 * ServerHello after an HRR we haven't actually selected TLSv1.3
                 * yet, but we still treat it as TLSv1.3, so we must check for
                 * that explicitly
                 */
                if (!s->first_packet && !SSL_CONNECTION_IS_TLS13(s)
                        && s->hello_retry_request != SSL_HRR_PENDING
                        && version != (unsigned int)s->version) {
                    if ((s->version & 0xFF00) == (version & 0xFF00)
                        && !s->enc_write_ctx && !s->write_hash) {
                        if (thisrr->type == SSL3_RT_ALERT) {
                            /*
                             * The record is using an incorrect version number,
                             * but what we've got appears to be an alert. We
                             * haven't read the body yet to check whether its a
                             * fatal or not - but chances are it is. We probably
                             * shouldn't send a fatal alert back. We'll just
                             * end.
                             */
                            RLAYERfatal(rl, SSL_AD_NO_ALERT,
                                        SSL_R_WRONG_VERSION_NUMBER);
                            return OSSL_RECORD_RETURN_FATAL;
                        }
                        /*
                         * Send back error using their minor version number :-)
                         */
                        s->version = (unsigned short)version;
                    }
                    RLAYERfatal(rl, SSL_AD_PROTOCOL_VERSION,
                                SSL_R_WRONG_VERSION_NUMBER);
                    return OSSL_RECORD_RETURN_FATAL;
                }

                if ((version >> 8) != SSL3_VERSION_MAJOR) {
                    if (rl->is_first_record) {
                        /* Go back to start of packet, look at the five bytes
                         * that we have. */
                        p = rl->packet;
                        if (HAS_PREFIX((char *)p, "GET ") ||
                            HAS_PREFIX((char *)p, "POST ") ||
                            HAS_PREFIX((char *)p, "HEAD ") ||
                            HAS_PREFIX((char *)p, "PUT ")) {
                            RLAYERfatal(rl, SSL_AD_NO_ALERT, SSL_R_HTTP_REQUEST);
                            return OSSL_RECORD_RETURN_FATAL;
                        } else if (HAS_PREFIX((char *)p, "CONNE")) {
                            RLAYERfatal(rl, SSL_AD_NO_ALERT,
                                        SSL_R_HTTPS_PROXY_REQUEST);
                            return OSSL_RECORD_RETURN_FATAL;
                        }

                        /* Doesn't look like TLS - don't send an alert */
                        RLAYERfatal(rl, SSL_AD_NO_ALERT,
                                    SSL_R_WRONG_VERSION_NUMBER);
                        return OSSL_RECORD_RETURN_FATAL;
                    } else {
                        RLAYERfatal(rl, SSL_AD_PROTOCOL_VERSION,
                                    SSL_R_WRONG_VERSION_NUMBER);
                        return OSSL_RECORD_RETURN_FATAL;
                    }
                }

                if (SSL_CONNECTION_IS_TLS13(s)
                        && rl->enc_read_ctx != NULL
                        && !using_ktls) {
                    if (thisrr->type != SSL3_RT_APPLICATION_DATA
                            && (thisrr->type != SSL3_RT_CHANGE_CIPHER_SPEC
                                || !SSL_IS_FIRST_HANDSHAKE(s))
                            && (thisrr->type != SSL3_RT_ALERT
                                || s->statem.enc_read_state
                                   != ENC_READ_STATE_ALLOW_PLAIN_ALERTS)) {
                        RLAYERfatal(rl, SSL_AD_UNEXPECTED_MESSAGE,
                                    SSL_R_BAD_RECORD_TYPE);
                        return OSSL_RECORD_RETURN_FATAL;
                    }
                    if (thisrr->rec_version != TLS1_2_VERSION) {
                        RLAYERfatal(rl, SSL_AD_DECODE_ERROR,
                                    SSL_R_WRONG_VERSION_NUMBER);
                        return OSSL_RECORD_RETURN_FATAL;
                    }
                }

                if (thisrr->length >
                    SSL3_BUFFER_get_len(rbuf) - SSL3_RT_HEADER_LENGTH) {
                    RLAYERfatal(rl, SSL_AD_RECORD_OVERFLOW,
                                SSL_R_PACKET_LENGTH_TOO_LONG);
                    return OSSL_RECORD_RETURN_FATAL;
                }
            }

            /* now rl->rstate == SSL_ST_READ_BODY */
        }

        if (SSL_CONNECTION_IS_TLS13(s)) {
            size_t len = SSL3_RT_MAX_TLS13_ENCRYPTED_LENGTH;

            /* KTLS strips the inner record type. */
            if (using_ktls)
                len = SSL3_RT_MAX_ENCRYPTED_LENGTH;

            if (thisrr->length > len) {
                RLAYERfatal(rl, SSL_AD_RECORD_OVERFLOW,
                            SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
                return OSSL_RECORD_RETURN_FATAL;
            }
        } else {
            size_t len = SSL3_RT_MAX_ENCRYPTED_LENGTH;

#ifndef OPENSSL_NO_COMP
            /*
             * If OPENSSL_NO_COMP is defined then SSL3_RT_MAX_ENCRYPTED_LENGTH
             * does not include the compression overhead anyway.
             */
            if (s->expand == NULL)
                len -= SSL3_RT_MAX_COMPRESSED_OVERHEAD;
#endif

            /* KTLS may use all of the buffer */
            if (using_ktls)
                len = SSL3_BUFFER_get_left(rbuf);

            if (thisrr->length > len) {
                RLAYERfatal(rl, SSL_AD_RECORD_OVERFLOW,
                            SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
                return OSSL_RECORD_RETURN_FATAL;
            }
        }

        /*
         * rl->rstate == SSL_ST_READ_BODY, get and decode the data. Calculate
         * how much more data we need to read for the rest of the record
         */
        if (thisrr->rec_version == SSL2_VERSION) {
            more = thisrr->length + SSL2_RT_HEADER_LENGTH
                - SSL3_RT_HEADER_LENGTH;
        } else {
            more = thisrr->length;
        }

        if (more > 0) {
            /* now rl->packet_length == SSL3_RT_HEADER_LENGTH */

            rret = tls_read_n(rl, more, more, 1, 0, &n);
            if (rret < OSSL_RECORD_RETURN_SUCCESS)
                return rret;     /* error or non-blocking io */
        }

        /* set state for later operations */
        rl->rstate = SSL_ST_READ_HEADER;

        /*
         * At this point, rl->packet_length == SSL3_RT_HEADER_LENGTH
         * + thisrr->length, or rl->packet_length == SSL2_RT_HEADER_LENGTH
         * + thisrr->length and we have that many bytes in rl->packet
         */
        if (thisrr->rec_version == SSL2_VERSION)
            thisrr->input = &(rl->packet[SSL2_RT_HEADER_LENGTH]);
        else
            thisrr->input = &(rl->packet[SSL3_RT_HEADER_LENGTH]);

        /*
         * ok, we can now read from 'rl->packet' data into 'thisrr'.
         * thisrr->input points at thisrr->length bytes, which need to be copied
         * into thisrr->data by either the decryption or by the decompression.
         * When the data is 'copied' into the thisrr->data buffer,
         * thisrr->input will be updated to point at the new buffer
         */

        /*
         * We now have - encrypted [ MAC [ compressed [ plain ] ] ]
         * thisrr->length bytes of encrypted compressed stuff.
         */

        /* decrypt in place in 'thisrr->input' */
        thisrr->data = thisrr->input;
        thisrr->orig_len = thisrr->length;

        /* Mark this record as not read by upper layers yet */
        thisrr->read = 0;

        num_recs++;

        /* we have pulled in a full packet so zero things */
        tls_reset_packet_length(rl);
        rl->is_first_record = 0;
    } while (num_recs < max_recs
             && thisrr->type == SSL3_RT_APPLICATION_DATA
             && SSL_USE_EXPLICIT_IV(s)
             && rl->enc_read_ctx != NULL
             && (EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(rl->enc_read_ctx))
                 & EVP_CIPH_FLAG_PIPELINE) != 0
             && tls_record_app_data_waiting(rl));

    if (num_recs == 1
            && thisrr->type == SSL3_RT_CHANGE_CIPHER_SPEC
            && (SSL_CONNECTION_IS_TLS13(s) || s->hello_retry_request != SSL_HRR_NONE)
            && SSL_IS_FIRST_HANDSHAKE(s)) {
        /*
         * CCS messages must be exactly 1 byte long, containing the value 0x01
         */
        if (thisrr->length != 1 || thisrr->data[0] != 0x01) {
            RLAYERfatal(rl, SSL_AD_ILLEGAL_PARAMETER,
                        SSL_R_INVALID_CCS_MESSAGE);
            return OSSL_RECORD_RETURN_FATAL;
        }
        /*
         * CCS messages are ignored in TLSv1.3. We treat it like an empty
         * handshake record
         */
        thisrr->type = SSL3_RT_HANDSHAKE;
        if (++(rl->empty_record_count) > MAX_EMPTY_RECORDS) {
            RLAYERfatal(rl, SSL_AD_UNEXPECTED_MESSAGE,
                        SSL_R_UNEXPECTED_CCS_MESSAGE);
            return OSSL_RECORD_RETURN_FATAL;
        }
        thisrr->read = 1;
        rl->num_recs = 0;
        rl->curr_rec = 0;
        rl->num_released = 0;

        return OSSL_RECORD_RETURN_SUCCESS;
    }

    if (using_ktls)
        goto skip_decryption;

    if (rl->read_hash != NULL) {
        const EVP_MD *tmpmd = EVP_MD_CTX_get0_md(rl->read_hash);

        if (tmpmd != NULL) {
            imac_size = EVP_MD_get_size(tmpmd);
            if (!ossl_assert(imac_size >= 0 && imac_size <= EVP_MAX_MD_SIZE)) {
                    RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
                    return OSSL_RECORD_RETURN_FATAL;
            }
            mac_size = (size_t)imac_size;
        }
    }

    /*
     * If in encrypt-then-mac mode calculate mac from encrypted record. All
     * the details below are public so no timing details can leak.
     */
    if (SSL_READ_ETM(s) && rl->read_hash) {
        unsigned char *mac;

        for (j = 0; j < num_recs; j++) {
            thisrr = &rr[j];

            if (thisrr->length < mac_size) {
                RLAYERfatal(rl, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_TOO_SHORT);
                return OSSL_RECORD_RETURN_FATAL;
            }
            thisrr->length -= mac_size;
            mac = thisrr->data + thisrr->length;
            i = rl->funcs->mac(rl, thisrr, md, 0 /* not send */, s);
            if (i == 0 || CRYPTO_memcmp(md, mac, mac_size) != 0) {
                RLAYERfatal(rl, SSL_AD_BAD_RECORD_MAC,
                            SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
                return OSSL_RECORD_RETURN_FATAL;
            }
        }
        /*
         * We've handled the mac now - there is no MAC inside the encrypted
         * record
         */
        mac_size = 0;
    }

    if (mac_size > 0) {
        macbufs = OPENSSL_zalloc(sizeof(*macbufs) * num_recs);
        if (macbufs == NULL) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
            return OSSL_RECORD_RETURN_FATAL;
        }
    }

    /*
     * TODO(RECLAYER): Only call rl functions once TLSv1.3/SSLv3 is moved to new
     * record layer code
     */
    enc_err = rl->funcs->cipher(rl, rr, num_recs, 0, macbufs, mac_size, s);

    /*-
     * enc_err is:
     *    0: if the record is publicly invalid, or an internal error, or AEAD
     *       decryption failed, or ETM decryption failed.
     *    1: Success or MTE decryption failed (MAC will be randomised)
     */
    if (enc_err == 0) {
        if (ossl_statem_in_error(s)) {
            /* SSLfatal() already got called */
            goto end;
        }
        if (num_recs == 1 && ossl_statem_skip_early_data(s)) {
            /*
             * Valid early_data that we cannot decrypt will fail here. We treat
             * it like an empty record.
             */

            thisrr = &rr[0];

            if (!ossl_early_data_count_ok(s, thisrr->length,
                                     EARLY_DATA_CIPHERTEXT_OVERHEAD, 0)) {
                /* SSLfatal() already called */
                goto end;
            }

            thisrr->length = 0;
            thisrr->read = 1;
            rl->num_recs = 0;
            rl->curr_rec = 0;
            rl->num_released = 0;
            RECORD_LAYER_reset_read_sequence(&s->rlayer);
            ret = 1;
            goto end;
        }
        RLAYERfatal(rl, SSL_AD_BAD_RECORD_MAC,
                    SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
        goto end;
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "dec %lu\n", (unsigned long)rr[0].length);
        BIO_dump_indent(trc_out, rr[0].data, rr[0].length, 4);
    } OSSL_TRACE_END(TLS);

    /* r->length is now the compressed data plus mac */
    if ((sess != NULL)
            && (rl->enc_read_ctx != NULL)
            && (!SSL_READ_ETM(s) && EVP_MD_CTX_get0_md(rl->read_hash) != NULL)) {
        /* rl->read_hash != NULL => mac_size != -1 */

        for (j = 0; j < num_recs; j++) {
            SSL_MAC_BUF *thismb = &macbufs[j];
            thisrr = &rr[j];

            i = rl->funcs->mac(rl, thisrr, md, 0 /* not send */, s);
            if (i == 0 || thismb == NULL || thismb->mac == NULL
                || CRYPTO_memcmp(md, thismb->mac, (size_t)mac_size) != 0)
                enc_err = 0;
            if (thisrr->length > SSL3_RT_MAX_COMPRESSED_LENGTH + mac_size)
                enc_err = 0;
        }
    }

    if (enc_err == 0) {
        if (ossl_statem_in_error(s)) {
            /* We already called SSLfatal() */
            goto end;
        }
        /*
         * A separate 'decryption_failed' alert was introduced with TLS 1.0,
         * SSL 3.0 only has 'bad_record_mac'.  But unless a decryption
         * failure is directly visible from the ciphertext anyway, we should
         * not reveal which kind of error occurred -- this might become
         * visible to an attacker (e.g. via a logfile)
         */
        RLAYERfatal(rl, SSL_AD_BAD_RECORD_MAC,
                    SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
        goto end;
    }

 skip_decryption:

    for (j = 0; j < num_recs; j++) {
        thisrr = &rr[j];

        /* thisrr->length is now just compressed */
        if (s->expand != NULL) {
            if (thisrr->length > SSL3_RT_MAX_COMPRESSED_LENGTH) {
                RLAYERfatal(rl, SSL_AD_RECORD_OVERFLOW,
                            SSL_R_COMPRESSED_LENGTH_TOO_LONG);
                goto end;
            }
            if (!ssl3_do_uncompress(s, thisrr)) {
                RLAYERfatal(rl, SSL_AD_DECOMPRESSION_FAILURE,
                            SSL_R_BAD_DECOMPRESSION);
                goto end;
            }
        }

        if (SSL_CONNECTION_IS_TLS13(s)
                && rl->enc_read_ctx != NULL
                && thisrr->type != SSL3_RT_ALERT) {
            /*
             * The following logic are irrelevant in KTLS: the kernel provides
             * unprotected record and thus record type represent the actual
             * content type, and padding is already removed and thisrr->type and
             * thisrr->length should have the correct values.
             */
            if (!using_ktls) {
                size_t end;

                if (thisrr->length == 0
                        || thisrr->type != SSL3_RT_APPLICATION_DATA) {
                    RLAYERfatal(rl, SSL_AD_UNEXPECTED_MESSAGE,
                                SSL_R_BAD_RECORD_TYPE);
                    goto end;
                }

                /* Strip trailing padding */
                for (end = thisrr->length - 1; end > 0 && thisrr->data[end] == 0;
                     end--)
                    continue;

                thisrr->length = end;
                thisrr->type = thisrr->data[end];
            }
            if (thisrr->type != SSL3_RT_APPLICATION_DATA
                    && thisrr->type != SSL3_RT_ALERT
                    && thisrr->type != SSL3_RT_HANDSHAKE) {
                RLAYERfatal(rl, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_BAD_RECORD_TYPE);
                goto end;
            }
            if (s->msg_callback)
                s->msg_callback(0, s->version, SSL3_RT_INNER_CONTENT_TYPE,
                                &thisrr->type, 1, ssl, s->msg_callback_arg);
        }

        /*
         * TLSv1.3 alert and handshake records are required to be non-zero in
         * length.
         */
        if (SSL_CONNECTION_IS_TLS13(s)
                && (thisrr->type == SSL3_RT_HANDSHAKE
                    || thisrr->type == SSL3_RT_ALERT)
                && thisrr->length == 0) {
            RLAYERfatal(rl, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_BAD_LENGTH);
            goto end;
        }

        /*
         * Usually thisrr->length is the length of a single record, but when
         * KTLS handles the decryption, thisrr->length may be larger than
         * SSL3_RT_MAX_PLAIN_LENGTH because the kernel may have coalesced
         * multiple records.
         * Therefore we have to rely on KTLS to check the plaintext length
         * limit in the kernel.
         */
        if (thisrr->length > SSL3_RT_MAX_PLAIN_LENGTH && !using_ktls) {
            RLAYERfatal(rl, SSL_AD_RECORD_OVERFLOW, SSL_R_DATA_LENGTH_TOO_LONG);
            goto end;
        }

        /*
         * Check if the received packet overflows the current
         * Max Fragment Length setting.
         * Note: USE_MAX_FRAGMENT_LENGTH_EXT and KTLS are mutually exclusive.
         */
        if (s->session != NULL && USE_MAX_FRAGMENT_LENGTH_EXT(s->session)
                && thisrr->length > GET_MAX_FRAGMENT_LENGTH(s->session)) {
            RLAYERfatal(rl, SSL_AD_RECORD_OVERFLOW, SSL_R_DATA_LENGTH_TOO_LONG);
            goto end;
        }

        thisrr->off = 0;
        /*-
         * So at this point the following is true
         * thisrr->type   is the type of record
         * thisrr->length == number of bytes in record
         * thisrr->off    == offset to first valid byte
         * thisrr->data   == where to take bytes from, increment after use :-).
         */

        /* just read a 0 length packet */
        if (thisrr->length == 0) {
            if (++(rl->empty_record_count) > MAX_EMPTY_RECORDS) {
                RLAYERfatal(rl, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_RECORD_TOO_SMALL);
                goto end;
            }
        } else {
            rl->empty_record_count = 0;
        }
    }

    if (s->early_data_state == SSL_EARLY_DATA_READING) {
        thisrr = &rr[0];
        if (thisrr->type == SSL3_RT_APPLICATION_DATA
                && !ossl_early_data_count_ok(s, thisrr->length, 0, 0)) {
            /* SSLfatal already called */
            goto end;
        }
    }

    rl->num_recs = num_recs;
    rl->curr_rec = 0;
    rl->num_released = 0;
    ret = OSSL_RECORD_RETURN_SUCCESS;
 end:
    if (macbufs != NULL) {
        for (j = 0; j < num_recs; j++) {
            if (macbufs[j].alloced)
                OPENSSL_free(macbufs[j].mac);
        }
        OPENSSL_free(macbufs);
    }
    return ret;
}

static int tls_read_record(OSSL_RECORD_LAYER *rl, void **rechandle,
                           int *rversion, int *type, unsigned char **data,
                           size_t *datalen, uint16_t *epoch,
                           unsigned char *seq_num,
                           /* TODO(RECLAYER): Remove me */ SSL_CONNECTION *s)
{
    SSL3_RECORD *rec;

    /*
     * tls_get_more_records() can return success without actually reading
     * anything useful (i.e. if empty records are read). We loop here until
     * we have something useful. tls_get_more_records() will eventually fail if
     * too many sequential empty records are read.
     */
    while (rl->curr_rec >= rl->num_recs) {
        int ret;

        if (rl->num_released != rl->num_recs) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_RECORDS_NOT_RELEASED);
            return OSSL_RECORD_RETURN_FATAL;
        }

        ret = tls_get_more_records(rl, s);

        if (ret != OSSL_RECORD_RETURN_SUCCESS)
            return ret;
    }

    /*
     * We have now got rl->num_recs records buffered in rl->rrec. rl->curr_rec
     * points to the next one to read.
     */
    rec = &rl->rrec[rl->curr_rec++];

    *rechandle = rec;
    *rversion = rec->rec_version;
    *type = rec->type;
    *data = rec->data;
    *datalen = rec->length;

    return OSSL_RECORD_RETURN_SUCCESS;
}

static int tls_release_record(OSSL_RECORD_LAYER *rl, void *rechandle)
{
    if (!ossl_assert(rl->num_released < rl->curr_rec)
            || !ossl_assert(rechandle == &rl->rrec[rl->num_released])) {
        /* Should not happen */
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_INVALID_RECORD);
        return OSSL_RECORD_RETURN_FATAL;
    }

    rl->num_released++;

    return OSSL_RECORD_RETURN_SUCCESS;
}

static OSSL_RECORD_LAYER *tls_new_record_layer(OSSL_LIB_CTX *libctx,
                                               const char *propq, int vers,
                                               int role, int direction,
                                               int level, unsigned char *key,
                                               size_t keylen,
                                               unsigned char *iv,
                                               size_t ivlen,
                                               unsigned char *mackey,
                                               size_t mackeylen,
                                               const EVP_CIPHER *ciph,
                                               size_t taglen,
                                               /* TODO(RECLAYER): This probably should not be an int */
                                               int mactype,
                                               const EVP_MD *md,
                                               const SSL_COMP *comp,
                                               BIO *transport, BIO_ADDR *local,
                                               BIO_ADDR *peer,
                                               const OSSL_PARAM *settings,
                                               const OSSL_PARAM *options,
                                               /* TODO(RECLAYER): Remove me */
                                               SSL_CONNECTION *s)
{
    OSSL_RECORD_LAYER *rl = OPENSSL_zalloc(sizeof(*rl));
    const OSSL_PARAM *p;

    if (rl == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (transport != NULL && !BIO_up_ref(transport)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * TODO(RECLAYER): Need to handle the case where the params are updated
     * after the record layer has been created.
     */
    p = OSSL_PARAM_locate_const(options, OSSL_LIBSSL_RECORD_LAYER_PARAM_OPTIONS);
    if (p != NULL && !OSSL_PARAM_get_uint64(p, &rl->options)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_FAILED_TO_GET_PARAMETER);
        goto err;
    }

    p = OSSL_PARAM_locate_const(options, OSSL_LIBSSL_RECORD_LAYER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_get_uint32(p, &rl->mode)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_FAILED_TO_GET_PARAMETER);
        goto err;
    }

    if (level == OSSL_RECORD_PROTECTION_LEVEL_APPLICATION) {
        /*
         * We ignore any read_ahead setting prior to the application protection
         * level. Otherwise we may read ahead data in a lower protection level
         * that is destined for a higher protection level. To simplify the logic
         * we don't support that at this stage.
         */
        /*
         * TODO(RECLAYER): Handle the case of read_ahead at the application
         * level and a key update/reneg occurs.
         */
        p = OSSL_PARAM_locate_const(options, OSSL_LIBSSL_RECORD_LAYER_PARAM_READ_AHEAD);
        if (p != NULL && !OSSL_PARAM_get_int(p, &rl->read_ahead)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_FAILED_TO_GET_PARAMETER);
            goto err;
        }
    }

    rl->libctx = libctx;
    rl->propq = propq;

    rl->version = vers;
    rl->role = role;
    rl->direction = direction;

    if (level == 0)
        rl->is_first_record = 1;

    if (!tls_set1_bio(rl, transport))
        goto err;

    switch (vers) {
    case TLS_ANY_VERSION:
        rl->funcs = &tls_any_funcs;
        break;
    case TLS1_3_VERSION:
        rl->funcs = &tls_1_3_funcs;
        break;
    case TLS1_2_VERSION:
        rl->funcs = &tls_1_2_funcs;
        break;
    case TLS1_1_VERSION:
        rl->funcs = &tls_1_1_funcs;
        break;
    case TLS1_VERSION:
        rl->funcs = &tls_1_0_funcs;
        break;
    case SSL3_VERSION:
        rl->funcs = &ssl_3_0_funcs;
        break;
    default:
        /* Should not happen */
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!rl->funcs->set_crypto_state(rl, level, key, keylen, iv, ivlen,
                                     mackey, mackeylen, ciph, taglen,
                                     mactype, md, comp, s)) {
        /* RLAYERfatal already called */
        goto err;
    }

    return rl;
 err:
    OPENSSL_free(rl);
    return NULL;
}

static OSSL_RECORD_LAYER *dtls_new_record_layer(OSSL_LIB_CTX *libctx,
                                                const char *propq, int vers,
                                                int role, int direction,
                                                int level, unsigned char *key,
                                                size_t keylen,
                                                unsigned char *iv,
                                                size_t ivlen,
                                                unsigned char *mackey,
                                                size_t mackeylen,
                                                const EVP_CIPHER *ciph,
                                                size_t taglen,
                                                /* TODO(RECLAYER): This probably should not be an int */
                                                int mactype,
                                                const EVP_MD *md,
                                                const SSL_COMP *comp,
                                                BIO *transport, BIO_ADDR *local,
                                                BIO_ADDR *peer,
                                                const OSSL_PARAM *settings,
                                                const OSSL_PARAM *options,
                                                /* TODO(RECLAYER): Remove me */
                                                SSL_CONNECTION *s)
{
    OSSL_RECORD_LAYER *rl = tls_new_record_layer(libctx, propq, vers, role,
                                                 direction, level, key, keylen,
                                                 iv, ivlen, mackey, mackeylen,
                                                 ciph, taglen, mactype, md,
                                                 comp, transport, local, peer,
                                                 settings, options, s);

    if (rl == NULL)
        return NULL;

    rl->isdtls = 1;

    return rl;
}

static void tls_free(OSSL_RECORD_LAYER *rl)
{
    /* TODO(RECLAYER): Cleanse sensitive fields */
    BIO_free(rl->bio);
    OPENSSL_free(rl);
}

static int tls_reset(OSSL_RECORD_LAYER *rl)
{
    memset(rl, 0, sizeof(*rl));
    return 1;
}

static int tls_unprocessed_read_pending(OSSL_RECORD_LAYER *rl)
{
    return SSL3_BUFFER_get_left(&rl->rbuf) != 0;;
}

static int tls_processed_read_pending(OSSL_RECORD_LAYER *rl)
{
    return rl->curr_rec < rl->num_recs;
}

static size_t tls_app_data_pending(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static int tls_write_pending(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static size_t tls_get_max_record_len(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static size_t tls_get_max_records(OSSL_RECORD_LAYER *rl)
{
    return 0;
}

static int tls_write_records(OSSL_RECORD_LAYER *rl,
                             OSSL_RECORD_TEMPLATE **templates, size_t numtempl,
                             size_t allowance, size_t *sent)
{
    return 0;
}

static int tls_retry_write_records(OSSL_RECORD_LAYER *rl, size_t allowance,
                                   size_t *sent)
{
    return 0;
}


static int tls_get_alert_code(OSSL_RECORD_LAYER *rl)
{
    return rl->alert;
}

static int tls_set1_bio(OSSL_RECORD_LAYER *rl, BIO *bio)
{
    if (bio != NULL && !BIO_up_ref(bio))
        return 0;
    BIO_free(rl->bio);
    rl->bio = bio;

    return 1;
}

static SSL3_BUFFER *tls_get0_rbuf(OSSL_RECORD_LAYER *rl)
{
    return &rl->rbuf;
}

static unsigned char *tls_get0_packet(OSSL_RECORD_LAYER *rl)
{
    return rl->packet;
}

static void tls_set0_packet(OSSL_RECORD_LAYER *rl, unsigned char *packet,
                            size_t packetlen)
{
    rl->packet = packet;
    rl->packet_length = packetlen;
}

static size_t tls_get_packet_length(OSSL_RECORD_LAYER *rl)
{
    return rl->packet_length;
}

const OSSL_RECORD_METHOD ossl_tls_record_method = {
    tls_new_record_layer,
    tls_free,
    tls_reset,
    tls_unprocessed_read_pending,
    tls_processed_read_pending,
    tls_app_data_pending,
    tls_write_pending,
    tls_get_max_record_len,
    tls_get_max_records,
    tls_write_records,
    tls_retry_write_records,
    tls_read_record,
    tls_release_record,
    tls_get_alert_code,
    tls_set1_bio,

    /*
     * TODO(RECLAYER): Remove these. These function pointers are temporary hacks
     * during the record layer refactoring. They need to be removed before the
     * refactor is complete.
     */
    tls_read_n,
    tls_get0_rbuf,
    tls_get0_packet,
    tls_set0_packet,
    tls_get_packet_length,
    tls_reset_packet_length
};

const OSSL_RECORD_METHOD ossl_dtls_record_method = {
    dtls_new_record_layer,
    tls_free,
    tls_reset,
    tls_unprocessed_read_pending,
    tls_processed_read_pending,
    tls_app_data_pending,
    tls_write_pending,
    tls_get_max_record_len,
    tls_get_max_records,
    tls_write_records,
    tls_retry_write_records,
    tls_read_record,
    tls_release_record,
    tls_get_alert_code,
    tls_set1_bio,

    /*
     * TODO(RECLAYER): Remove these. These function pointers are temporary hacks
     * during the record layer refactoring. They need to be removed before the
     * refactor is complete.
     */
    tls_read_n,
    tls_get0_rbuf,
    tls_get0_packet,
    tls_set0_packet,
    tls_get_packet_length,
    tls_reset_packet_length
};
