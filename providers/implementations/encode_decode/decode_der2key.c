/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>         /* PEM_BUFSIZE and public PEM functions */
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include "internal/cryptlib.h"   /* ossl_assert() */
#include "internal/asn1.h"
#include "crypto/ecx.h"
#include "prov/bio.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "endecoder_local.h"

#define SET_ERR_MARK() ERR_set_mark()
#define CLEAR_ERR_MARK()                                                \
    do {                                                                \
        int err = ERR_peek_last_error();                                \
                                                                        \
        if (ERR_GET_LIB(err) == ERR_LIB_ASN1                            \
            && (ERR_GET_REASON(err) == ASN1_R_HEADER_TOO_LONG           \
                || ERR_GET_REASON(err) == ASN1_R_UNSUPPORTED_TYPE       \
                || ERR_GET_REASON(err) == ERR_R_NESTED_ASN1_ERROR))     \
            ERR_pop_to_mark();                                          \
        else                                                            \
            ERR_clear_last_mark();                                      \
    } while(0)
#define RESET_ERR_MARK()                                                \
    do {                                                                \
        CLEAR_ERR_MARK();                                               \
        SET_ERR_MARK();                                                 \
    } while(0)

static int read_der(PROV_CTX *provctx, OSSL_CORE_BIO *cin,
                    unsigned char **data, long *len)
{
    BUF_MEM *mem = NULL;
    BIO *in = bio_new_from_core_bio(provctx, cin);
    int ok = (asn1_d2i_read_bio(in, &mem) >= 0);

    if (ok) {
        *data = (unsigned char *)mem->data;
        *len = (long)mem->length;
        OPENSSL_free(mem);
    }
    BIO_free(in);
    return ok;
}

static int der_from_p8(unsigned char **new_der, long *new_der_len,
                       unsigned char *input_der, long input_der_len,
                       OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    const unsigned char *derp;
    X509_SIG *p8 = NULL;
    int ok = 0;

    if (!ossl_assert(new_der != NULL && *new_der == NULL)
        || !ossl_assert(new_der_len != NULL))
        return 0;

    derp = input_der;
    if ((p8 = d2i_X509_SIG(NULL, &derp, input_der_len)) != NULL) {
        char pbuf[PEM_BUFSIZE];
        size_t plen = 0;

        if (!pw_cb(pbuf, sizeof(pbuf), &plen, NULL, pw_cbarg)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_READ_KEY);
        } else {
            const X509_ALGOR *alg = NULL;
            const ASN1_OCTET_STRING *oct = NULL;
            int len = 0;

            X509_SIG_get0(p8, &alg, &oct);
            if (PKCS12_pbe_crypt(alg, pbuf, plen, oct->data, oct->length,
                                 new_der, &len, 0) != NULL)
                ok = 1;
            *new_der_len = len;
        }
    }
    X509_SIG_free(p8);
    return ok;
}

/* ---------------------------------------------------------------------- */

static OSSL_FUNC_decoder_freectx_fn der2key_freectx;
static OSSL_FUNC_decoder_gettable_params_fn der2key_gettable_params;
static OSSL_FUNC_decoder_get_params_fn der2key_get_params;
static OSSL_FUNC_decoder_decode_fn der2key_decode;
static OSSL_FUNC_decoder_export_object_fn der2key_export_object;

typedef void *(extract_key_fn)(EVP_PKEY *);
typedef void (free_key_fn)(void *);
struct keytype_desc_st {
    int type;                 /* EVP key type */
    const char *name;         /* Keytype */
    const OSSL_DISPATCH *fns; /* Keymgmt (to pilfer functions from) */

    /*
     * These must be the correct EVP_PKEY_get1_{TYPE}() and {TYPE}_free()
     * function for the key.
     */
    extract_key_fn *extract_key;
    free_key_fn *free_key;
};

/*
 * Context used for DER to key decoding.
 */
struct der2key_ctx_st {
    PROV_CTX *provctx;
    const struct keytype_desc_st *desc;
};

static struct der2key_ctx_st *
der2key_newctx(void *provctx, const struct keytype_desc_st *desc)
{
    struct der2key_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;
        ctx->desc = desc;
    }
    return ctx;
}

static void der2key_freectx(void *vctx)
{
    struct der2key_ctx_st *ctx = vctx;

    OPENSSL_free(ctx);
}

static const OSSL_PARAM *der2key_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_DECODER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int der2key_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "DER"))
        return 0;

    return 1;
}

static int der2key_decode(void *vctx, OSSL_CORE_BIO *cin,
                          OSSL_CALLBACK *data_cb, void *data_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct der2key_ctx_st *ctx = vctx;
    void *libctx = PROV_LIBRARY_CONTEXT_OF(ctx->provctx);
    unsigned char *der = NULL;
    const unsigned char *derp;
    long der_len = 0;
    unsigned char *new_der = NULL;
    long new_der_len;
    EVP_PKEY *pkey = NULL;
    void *key = NULL;
    int ok = 0;

    SET_ERR_MARK();
    if (!read_der(ctx->provctx, cin, &der, &der_len))
        goto err;

    /*
     * Opportunistic attempt to decrypt.  If it doesn't work, we try to
     * decode our input unencrypted.
     */
    if (der_from_p8(&new_der, &new_der_len, der, der_len, pw_cb, pw_cbarg)) {
        OPENSSL_free(der);
        der = new_der;
        der_len = new_der_len;
    }
    RESET_ERR_MARK();

    derp = der;
    pkey = d2i_PrivateKey_ex(ctx->desc->type, NULL, &derp, der_len,
                             libctx, NULL);
    if (pkey == NULL) {
        RESET_ERR_MARK();
        derp = der;
        pkey = d2i_PUBKEY_ex(NULL, &derp, der_len, libctx, NULL);
    }

    if (pkey == NULL) {
        RESET_ERR_MARK();
        derp = der;
        pkey = d2i_KeyParams(ctx->desc->type, NULL, &derp, der_len);
    }
 err:
    /*
     * Prune low-level ASN.1 parse errors from error queue, assuming that
     * this is called by decoder_process() in a loop trying several formats.
     */
    CLEAR_ERR_MARK();

    if (pkey != NULL) {
        /*
         * Tear out the low-level key pointer from the pkey,
         * but only if it matches the expected key type.
         *
         * TODO(3.0): The check should be done with EVP_PKEY_is_a(), but
         * as long as we still have #legacy internal keys, it's safer to
         * use the type numbers inside the provider.
         */
        if (EVP_PKEY_id(pkey) == ctx->desc->type)
            key = ctx->desc->extract_key(pkey);

        /*
         * ctx->desc->extract_key() is expected to have incremented |key|'s
         * reference count, so it should be safe to free |pkey| now.
         */
        EVP_PKEY_free(pkey);
    }

    OPENSSL_free(der);

    if (key != NULL) {
        OSSL_PARAM params[4];
        int object_type = OSSL_OBJECT_PKEY;

        params[0] =
            OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] =
            OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             (char *)ctx->desc->name, 0);
        /* The address of the key becomes the octet string */
        params[2] =
            OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                              &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();

        ok = data_cb(params, data_cbarg);
    }
    ctx->desc->free_key(key);

    return ok;
}

static int der2key_export_object(void *vctx,
                                 const void *reference, size_t reference_sz,
                                 OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    struct der2key_ctx_st *ctx = vctx;
    OSSL_FUNC_keymgmt_export_fn *export =
        ossl_prov_get_keymgmt_export(ctx->desc->fns);
    void *keydata;

    if (reference_sz == sizeof(keydata) && export != NULL) {
        /* The contents of the reference is the address to our object */
        keydata = *(void **)reference;

        return export(keydata, OSSL_KEYMGMT_SELECT_ALL,
                      export_cb, export_cbarg);
    }
    return 0;
}

#define IMPLEMENT_NEWCTX(KEYTYPEstr, KEYTYPE, keytype, extract, free)   \
    static const struct keytype_desc_st keytype##_desc =                \
        { EVP_PKEY_##KEYTYPE, KEYTYPEstr,                               \
          ossl_##keytype##_keymgmt_functions,                           \
          (extract_key_fn *)extract,                                    \
          (free_key_fn *)free };                                        \
    static OSSL_FUNC_decoder_newctx_fn der2##keytype##_newctx;          \
    static void *der2##keytype##_newctx(void *provctx)                  \
    {                                                                   \
        return der2key_newctx(provctx, &keytype##_desc);                \
    }                                                                   \
    const OSSL_DISPATCH ossl_der_to_##keytype##_decoder_functions[] = { \
        { OSSL_FUNC_DECODER_NEWCTX,                                     \
          (void (*)(void))der2##keytype##_newctx },                     \
        { OSSL_FUNC_DECODER_FREECTX,                                    \
          (void (*)(void))der2key_freectx },                            \
        { OSSL_FUNC_DECODER_GETTABLE_PARAMS,                            \
          (void (*)(void))der2key_gettable_params },                    \
        { OSSL_FUNC_DECODER_GET_PARAMS,                                 \
          (void (*)(void))der2key_get_params },                         \
        { OSSL_FUNC_DECODER_DECODE,                                     \
          (void (*)(void))der2key_decode },                             \
        { OSSL_FUNC_DECODER_EXPORT_OBJECT,                              \
          (void (*)(void))der2key_export_object },                      \
        { 0, NULL }                                                     \
    }

#ifndef OPENSSL_NO_DH
IMPLEMENT_NEWCTX("DH", DH, dh, EVP_PKEY_get1_DH, DH_free);
IMPLEMENT_NEWCTX("DHX", DHX, dhx, EVP_PKEY_get1_DH, DH_free);
#endif
#ifndef OPENSSL_NO_DSA
IMPLEMENT_NEWCTX("DSA", DSA, dsa, EVP_PKEY_get1_DSA, DSA_free);
#endif
#ifndef OPENSSL_NO_EC
IMPLEMENT_NEWCTX("EC", EC, ec, EVP_PKEY_get1_EC_KEY, EC_KEY_free);
IMPLEMENT_NEWCTX("X25519", X25519, x25519,
                 evp_pkey_get1_X25519, ecx_key_free);
IMPLEMENT_NEWCTX("X448", X448, x448,
                 evp_pkey_get1_X448, ecx_key_free);
IMPLEMENT_NEWCTX("ED25519", ED25519, ed25519,
                 evp_pkey_get1_ED25519, ecx_key_free);
IMPLEMENT_NEWCTX("ED448", ED448, ed448, evp_pkey_get1_ED448, ecx_key_free);
#endif
IMPLEMENT_NEWCTX("RSA", RSA, rsa, EVP_PKEY_get1_RSA, RSA_free);
IMPLEMENT_NEWCTX("RSA-PSS", RSA_PSS, rsapss, EVP_PKEY_get1_RSA, RSA_free);
