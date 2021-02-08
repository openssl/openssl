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
#include "crypto/dh.h"
#include "crypto/dsa.h"
#include "crypto/ec.h"
#include "crypto/ecx.h"
#include "crypto/rsa.h"
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
static OSSL_FUNC_decoder_decode_fn der2key_decode;
static OSSL_FUNC_decoder_export_object_fn der2key_export_object;

struct der2key_ctx_st;           /* Forward declaration */
typedef void *(extract_key_fn)(EVP_PKEY *);
typedef void (adjust_key_fn)(void *, struct der2key_ctx_st *ctx);
typedef void (free_key_fn)(void *);
struct keytype_desc_st {
    const char *keytype_name;
    const OSSL_DISPATCH *fns; /* Keymgmt (to pilfer functions from) */

    /* The input structure name */
    const char *structure_name;

    /*
     * The EVP_PKEY_xxx type macro.  Should be zero for type specific
     * structures, non-zero when the outermost structure is PKCS#8 or
     * SubjectPublicKeyInfo.  This determines which of the function
     * pointers below will be used.
     */
    int evp_type;

    /* The selection mask for OSSL_FUNC_decoder_does_selection() */
    int selection_mask;

    /* For type specific decoders, we use the corresponding d2i */
    d2i_of_void *d2i_private_key;
    d2i_of_void *d2i_public_key;
    d2i_of_void *d2i_key_params;

    /*
     * For PKCS#8 decoders, we use EVP_PKEY extractors, EVP_PKEY_get1_{TYPE}()
     */
    extract_key_fn *extract_key;
    /*
     * For any key, we may need to make provider specific adjustments, such
     * as ensure the key carries the correct library context.
     */
    adjust_key_fn *adjust_key;
    /* {type}_free() */
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

static const OSSL_PARAM *
der2key_gettable_params(void *provctx, const struct keytype_desc_st *desc)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_DECODER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };
    static const OSSL_PARAM gettables_w_structure[] = {
        { OSSL_DECODER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        { OSSL_DECODER_PARAM_INPUT_STRUCTURE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return desc->structure_name != NULL ? gettables_w_structure :  gettables;
}

static int der2key_get_params(OSSL_PARAM params[],
                              const struct keytype_desc_st *desc)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "DER"))
        return 0;
    if (desc->structure_name != NULL) {
        p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_STRUCTURE);
        if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, desc->structure_name))
            return 0;
    }

    return 1;
}

static int der2key_check_selection(int selection,
                                   const struct keytype_desc_st *desc)
{
    /*
     * The selections are kinda sorta "levels", i.e. each selection given
     * here is assumed to include those following.
     */
    int checks[] = {
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
    };
    size_t i;

    /* The decoder implementations made here support guessing */
    if (selection == 0)
        return 1;

    for (i = 0; i < OSSL_NELEM(checks); i++) {
        int check1 = (selection & checks[i]) != 0;
        int check2 = (desc->selection_mask & checks[i]) != 0;

        /*
         * If the caller asked for the currently checked bit(s), return
         * whether the decoder description says it's supported.
         */
        if (check1)
            return check2;
    }

    /* This should be dead code, but just to be safe... */
    return 0;
}

static int der2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                          OSSL_CALLBACK *data_cb, void *data_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct der2key_ctx_st *ctx = vctx;
    void *libctx = PROV_LIBCTX_OF(ctx->provctx);
    unsigned char *der = NULL;
    const unsigned char *derp;
    long der_len = 0;
    unsigned char *new_der = NULL;
    long new_der_len;
    EVP_PKEY *pkey = NULL;
    void *key = NULL;
    int orig_selection = selection;
    int ok = 0;

    /*
     * The caller is allowed to specify 0 as a selection mark, to have the
     * structure and key type guessed.  For type-specific structures, this
     * is not recommended, as some structures are very similar.
     * Note that 0 isn't the same as OSSL_KEYMGMT_SELECT_ALL, as the latter
     * signifies a private key structure, where everything else is assumed
     * to be present as well.
     */
    if (selection == 0)
        selection = ctx->desc->selection_mask;
    if ((selection & ctx->desc->selection_mask) == 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    SET_ERR_MARK();
    if (!read_der(ctx->provctx, cin, &der, &der_len))
        goto end;

    if (ctx->desc->extract_key == NULL) {
        /*
         * There's no EVP_PKEY extractor, so we use the type specific
         * functions.
         */
        derp = der;
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            key = ctx->desc->d2i_private_key(NULL, &derp, der_len);
            if (key == NULL && orig_selection != 0)
                goto end;
        }
        if (key == NULL
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            key = ctx->desc->d2i_public_key(NULL, &derp, der_len);
            if (key == NULL && orig_selection != 0)
                goto end;
        }
        if (key == NULL
            && (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0) {
            key = ctx->desc->d2i_key_params(NULL, &derp, der_len);
        }
    } else {
        /*
         * There is a EVP_PKEY extractor, so we use the more generic
         * EVP_PKEY functions, since they know how to unpack PKCS#8 and
         * SubjectPublicKeyInfo.
         */

        /*
         * Opportunistic attempt to decrypt.  If it doesn't work, we try
         * to decode our input unencrypted.
         */
        if (der_from_p8(&new_der, &new_der_len, der, der_len,
                        pw_cb, pw_cbarg)) {
            OPENSSL_free(der);
            der = new_der;
            der_len = new_der_len;
        }
        RESET_ERR_MARK();

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            derp = der;
            pkey = d2i_PrivateKey_ex(ctx->desc->evp_type, NULL, &derp, der_len,
                                     libctx, NULL);
        }

        if (pkey == NULL
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            RESET_ERR_MARK();
            derp = der;
            pkey = d2i_PUBKEY_ex(NULL, &derp, der_len, libctx, NULL);
        }

        if (pkey != NULL) {
            /*
             * Tear out the low-level key pointer from the pkey,
             * but only if it matches the expected key type.
             *
             * TODO: The check should be done with EVP_PKEY_is_a(), but
             * as long as we still have #legacy internal keys, it's safer
             * to use the type numbers inside the provider.
             */
            if (EVP_PKEY_id(pkey) == ctx->desc->evp_type)
                key = ctx->desc->extract_key(pkey);

            /*
             * ctx->desc->extract_key() is expected to have incremented
             * |key|'s reference count, so it should be safe to free |pkey|
             * now.
             */
            EVP_PKEY_free(pkey);
        }
    }

    if (key != NULL && ctx->desc->adjust_key != NULL)
        ctx->desc->adjust_key(key, ctx);

 end:
    /*
     * Prune low-level ASN.1 parse errors from error queue, assuming
     * that this is called by decoder_process() in a loop trying several
     * formats.
     */
    CLEAR_ERR_MARK();

    OPENSSL_free(der);

    if (key != NULL) {
        OSSL_PARAM params[4];
        int object_type = OSSL_OBJECT_PKEY;

        params[0] =
            OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] =
            OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             (char *)ctx->desc->keytype_name,
                                             0);
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

/* ---------------------------------------------------------------------- */

#ifndef OPENSSL_NO_DH
# define dh_evp_type                    EVP_PKEY_DH
# define dh_evp_extract                 (extract_key_fn *)EVP_PKEY_get1_DH
# define dh_d2i_private_key             NULL
# define dh_d2i_public_key              NULL
# define dh_d2i_key_params              (d2i_of_void *)d2i_DHparams
# define dh_free                        (free_key_fn *)DH_free

static void dh_adjust(void *key, struct der2key_ctx_st *ctx)
{
    ossl_dh_set0_libctx(key, PROV_LIBCTX_OF(ctx->provctx));
}

# define dhx_evp_type                   EVP_PKEY_DHX
# define dhx_evp_extract                (extract_key_fn *)EVP_PKEY_get1_DH
# define dhx_d2i_private_key            NULL
# define dhx_d2i_public_key             NULL
# define dhx_d2i_key_params             (d2i_of_void *)d2i_DHxparams
# define dhx_free                       (free_key_fn *)DH_free
# define dhx_adjust                     dh_adjust
#endif

/* ---------------------------------------------------------------------- */

#ifndef OPENSSL_NO_DSA
# define dsa_evp_type                   EVP_PKEY_DSA
# define dsa_evp_extract                (extract_key_fn *)EVP_PKEY_get1_DSA
# define dsa_d2i_private_key            (d2i_of_void *)d2i_DSAPrivateKey
# define dsa_d2i_public_key             (d2i_of_void *)d2i_DSAPublicKey
# define dsa_d2i_key_params             (d2i_of_void *)d2i_DSAparams
# define dsa_free                       (free_key_fn *)DSA_free

static void dsa_adjust(void *key, struct der2key_ctx_st *ctx)
{
    ossl_dsa_set0_libctx(key, PROV_LIBCTX_OF(ctx->provctx));
}
#endif

/* ---------------------------------------------------------------------- */

#ifndef OPENSSL_NO_EC
# define ec_evp_type                    EVP_PKEY_EC
# define ec_evp_extract                 (extract_key_fn *)EVP_PKEY_get1_EC_KEY
# define ec_d2i_private_key             (d2i_of_void *)d2i_ECPrivateKey
# define ec_d2i_public_key              NULL
# define ec_d2i_key_params              (d2i_of_void *)d2i_ECParameters
# define ec_free                        (free_key_fn *)EC_KEY_free

static void ec_adjust(void *key, struct der2key_ctx_st *ctx)
{
    ec_key_set0_libctx(key, PROV_LIBCTX_OF(ctx->provctx));
}

/*
 * ED25519, ED448, X25519, X448 only implement PKCS#8 and SubjectPublicKeyInfo,
 * so no d2i functions to be had.
 */

static void ecx_key_adjust(void *key, struct der2key_ctx_st *ctx)
{
    ecx_key_set0_libctx(key, PROV_LIBCTX_OF(ctx->provctx));
}

# define ed25519_evp_type               EVP_PKEY_ED25519
# define ed25519_evp_extract            (extract_key_fn *)evp_pkey_get1_ED25519
# define ed25519_d2i_private_key        NULL
# define ed25519_d2i_public_key         NULL
# define ed25519_d2i_key_params         NULL
# define ed25519_free                   (free_key_fn *)ecx_key_free
# define ed25519_adjust                 ecx_key_adjust

# define ed448_evp_type                 EVP_PKEY_ED448
# define ed448_evp_extract              (extract_key_fn *)evp_pkey_get1_ED448
# define ed448_d2i_private_key          NULL
# define ed448_d2i_public_key           NULL
# define ed448_d2i_key_params           NULL
# define ed448_free                     (free_key_fn *)ecx_key_free
# define ed448_adjust                   ecx_key_adjust

# define x25519_evp_type                EVP_PKEY_X25519
# define x25519_evp_extract             (extract_key_fn *)evp_pkey_get1_X25519
# define x25519_d2i_private_key         NULL
# define x25519_d2i_public_key          NULL
# define x25519_d2i_key_params          NULL
# define x25519_free                    (free_key_fn *)ecx_key_free
# define x25519_adjust                  ecx_key_adjust

# define x448_evp_type                  EVP_PKEY_X448
# define x448_evp_extract               (extract_key_fn *)evp_pkey_get1_X448
# define x448_d2i_private_key           NULL
# define x448_d2i_public_key            NULL
# define x448_d2i_key_params            NULL
# define x448_free                      (free_key_fn *)ecx_key_free
# define x448_adjust                    ecx_key_adjust

# ifndef OPENSSL_NO_SM2
#  define sm2_evp_type                  EVP_PKEY_SM2
#  define sm2_evp_extract               (extract_key_fn *)EVP_PKEY_get1_EC_KEY
#  define sm2_d2i_private_key           (d2i_of_void *)d2i_ECPrivateKey
#  define sm2_d2i_public_key            NULL
#  define sm2_d2i_key_params            (d2i_of_void *)d2i_ECParameters
#  define sm2_free                      (free_key_fn *)EC_KEY_free
#  define sm2_adjust                    ec_adjust
# endif
#endif

/* ---------------------------------------------------------------------- */

#define rsa_evp_type                    EVP_PKEY_RSA
#define rsa_evp_extract                 (extract_key_fn *)EVP_PKEY_get1_RSA
#define rsa_d2i_private_key             (d2i_of_void *)d2i_RSAPrivateKey
#define rsa_d2i_public_key              (d2i_of_void *)d2i_RSAPublicKey
#define rsa_d2i_key_params              NULL
#define rsa_free                        (free_key_fn *)RSA_free

static void rsa_adjust(void *key, struct der2key_ctx_st *ctx)
{
    ossl_rsa_set0_libctx(key, PROV_LIBCTX_OF(ctx->provctx));
}

#define rsapss_evp_type                 EVP_PKEY_RSA_PSS
#define rsapss_evp_extract              (extract_key_fn *)EVP_PKEY_get1_RSA
#define rsapss_d2i_private_key          (d2i_of_void *)d2i_RSAPrivateKey
#define rsapss_d2i_public_key           (d2i_of_void *)d2i_RSAPublicKey
#define rsapss_d2i_key_params           NULL
#define rsapss_free                     (free_key_fn *)RSA_free
#define rsapss_adjust                   rsa_adjust

/* ---------------------------------------------------------------------- */

/*
 * The DO_ macros help define the selection mask and the method functions
 * for each kind of object we want to decode.
 */
#define DO_type_specific_keypair(keytype)               \
    "type-specific", 0,                                 \
        ( OSSL_KEYMGMT_SELECT_KEYPAIR ),                \
        keytype##_d2i_private_key,                      \
        keytype##_d2i_public_key,                       \
        NULL,                                           \
        NULL,                                           \
        keytype##_adjust,                               \
        keytype##_free

#define DO_type_specific_pub(keytype)                   \
    "type-specific", 0,                                 \
        ( OSSL_KEYMGMT_SELECT_PUBLIC_KEY ),             \
        NULL,                                           \
        keytype##_d2i_public_key,                       \
        NULL,                                           \
        NULL,                                           \
        keytype##_adjust,                               \
        keytype##_free

#define DO_type_specific_priv(keytype)                  \
    "type-specific", 0,                                 \
        ( OSSL_KEYMGMT_SELECT_PRIVATE_KEY ),            \
        keytype##_d2i_private_key,                      \
        NULL,                                           \
        NULL,                                           \
        NULL,                                           \
        keytype##_adjust,                               \
        keytype##_free

#define DO_type_specific_params(keytype)                \
    "type-specific", 0,                                 \
        ( OSSL_KEYMGMT_SELECT_ALL_PARAMETERS ),         \
        NULL,                                           \
        NULL,                                           \
        keytype##_d2i_key_params,                       \
        NULL,                                           \
        keytype##_adjust,                               \
        keytype##_free

#define DO_type_specific(keytype)                       \
    "type-specific", 0,                                 \
        ( OSSL_KEYMGMT_SELECT_ALL ),                    \
        keytype##_d2i_private_key,                      \
        keytype##_d2i_public_key,                       \
        keytype##_d2i_key_params,                       \
        NULL,                                           \
        keytype##_adjust,                               \
        keytype##_free

#define DO_type_specific_no_pub(keytype)                \
    "type-specific", 0,                                 \
        ( OSSL_KEYMGMT_SELECT_PRIVATE_KEY               \
          | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS ),       \
        keytype##_d2i_private_key,                      \
        NULL,                                           \
        keytype##_d2i_key_params,                       \
        NULL,                                           \
        keytype##_adjust,                               \
        keytype##_free

#define DO_PKCS8(keytype)                               \
    "pkcs8", keytype##_evp_type,                        \
        ( OSSL_KEYMGMT_SELECT_PRIVATE_KEY ),            \
        NULL,                                           \
        NULL,                                           \
        NULL,                                           \
        keytype##_evp_extract,                          \
        keytype##_adjust,                               \
        keytype##_free

#define DO_SubjectPublicKeyInfo(keytype)                \
    "SubjectPublicKeyInfo", keytype##_evp_type,         \
        ( OSSL_KEYMGMT_SELECT_PUBLIC_KEY ),             \
        NULL,                                           \
        NULL,                                           \
        NULL,                                           \
        keytype##_evp_extract,                          \
        keytype##_adjust,                               \
        keytype##_free

#define DO_DH(keytype)                                  \
    "DH", 0,                                            \
        ( OSSL_KEYMGMT_SELECT_ALL_PARAMETERS ),         \
        NULL,                                           \
        NULL,                                           \
        keytype##_d2i_key_params,                       \
        NULL,                                           \
        keytype##_adjust,                               \
        keytype##_free

#define DO_DHX(keytype)                                 \
    "DHX", 0,                                           \
        ( OSSL_KEYMGMT_SELECT_ALL_PARAMETERS ),         \
        NULL,                                           \
        NULL,                                           \
        keytype##_d2i_key_params,                       \
        NULL,                                           \
        keytype##_adjust,                               \
        keytype##_free

#define DO_DSA(keytype)                                 \
    "DSA", 0,                                           \
        ( OSSL_KEYMGMT_SELECT_ALL ),                    \
        keytype##_d2i_private_key,                      \
        keytype##_d2i_public_key,                       \
        keytype##_d2i_key_params,                       \
        NULL,                                           \
        keytype##_adjust,                               \
        keytype##_free

#define DO_EC(keytype)                                  \
    "EC", 0,                                            \
        ( OSSL_KEYMGMT_SELECT_PRIVATE_KEY               \
          | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS ),       \
        keytype##_d2i_private_key,                      \
        NULL,                                           \
        keytype##_d2i_key_params,                       \
        NULL,                                           \
        keytype##_adjust,                               \
        keytype##_free

#define DO_RSA(keytype)                                 \
    "RSA", 0,                                           \
        ( OSSL_KEYMGMT_SELECT_KEYPAIR ),                \
        keytype##_d2i_private_key,                      \
        keytype##_d2i_public_key,                       \
        NULL,                                           \
        NULL,                                           \
        keytype##_adjust,                               \
        keytype##_free

/*
 * MAKE_DECODER is the single driver for creating OSSL_DISPATCH tables.
 * It takes the following arguments:
 *
 * keytype_name The implementation key type as a string.
 * keytype      The implementation key type.  This must correspond exactly
 *              to our existing keymgmt keytype names...  in other words,
 *              there must exist an ossl_##keytype##_keymgmt_functions.
 * type         The type name for the set of functions that implement the
 *              decoder for the key type.  This isn't necessarily the same
 *              as keytype.  For example, the key types ed25519, ed448,
 *              x25519 and x448 are all handled by the same functions with
 *              the common type name ecx.
 * kind         The kind of support to implement.  This translates into
 *              the DO_##kind macros above, to populate the keytype_desc_st
 *              structure.
 */
#define MAKE_DECODER(keytype_name, keytype, type, kind)                 \
    static const struct keytype_desc_st kind##_##keytype##_desc =       \
        { keytype_name, ossl_##keytype##_keymgmt_functions,             \
          DO_##kind(keytype) };                                         \
                                                                        \
    static OSSL_FUNC_decoder_newctx_fn kind##_der2##keytype##_newctx;   \
    static OSSL_FUNC_decoder_gettable_params_fn                         \
    kind##_der2##keytype##_gettable_params;                             \
    static OSSL_FUNC_decoder_get_params_fn                              \
    kind##_der2##keytype##_get_params;                                  \
                                                                        \
    static void *kind##_der2##keytype##_newctx(void *provctx)           \
    {                                                                   \
        return der2key_newctx(provctx, &kind##_##keytype##_desc);       \
    }                                                                   \
    static const OSSL_PARAM *                                           \
    kind##_der2##keytype##_gettable_params(void *provctx)               \
    {                                                                   \
        return                                                          \
            der2key_gettable_params(provctx, &kind##_##keytype##_desc); \
    }                                                                   \
    static int kind##_der2##keytype##_get_params(OSSL_PARAM params[])   \
    {                                                                   \
        return der2key_get_params(params, &kind##_##keytype##_desc);    \
    }                                                                   \
    static int kind##_der2##keytype##_does_selection(void *provctx,     \
                                                     int selection)     \
    {                                                                   \
        return der2key_check_selection(selection,                       \
                                       &kind##_##keytype##_desc);       \
    }                                                                   \
    const OSSL_DISPATCH                                                 \
    ossl_##kind##_der_to_##keytype##_decoder_functions[] = {            \
        { OSSL_FUNC_DECODER_NEWCTX,                                     \
          (void (*)(void))kind##_der2##keytype##_newctx },              \
        { OSSL_FUNC_DECODER_FREECTX,                                    \
          (void (*)(void))der2key_freectx },                            \
        { OSSL_FUNC_DECODER_GETTABLE_PARAMS,                            \
          (void (*)(void))kind##_der2##keytype##_gettable_params },     \
        { OSSL_FUNC_DECODER_GET_PARAMS,                                 \
          (void (*)(void))kind##_der2##keytype##_get_params },          \
        { OSSL_FUNC_DECODER_DOES_SELECTION,                             \
          (void (*)(void))kind##_der2##keytype##_does_selection },      \
        { OSSL_FUNC_DECODER_DECODE,                                     \
          (void (*)(void))der2key_decode },                             \
        { OSSL_FUNC_DECODER_EXPORT_OBJECT,                              \
          (void (*)(void))der2key_export_object },                      \
        { 0, NULL }                                                     \
    }

#ifndef OPENSSL_NO_DH
MAKE_DECODER("DH", dh, dh, PKCS8);
MAKE_DECODER("DH", dh, dh, SubjectPublicKeyInfo);
MAKE_DECODER("DH", dh, dh, type_specific_params);
MAKE_DECODER("DH", dh, dh, DH);
MAKE_DECODER("DHX", dhx, dhx, PKCS8);
MAKE_DECODER("DHX", dhx, dhx, SubjectPublicKeyInfo);
MAKE_DECODER("DHX", dhx, dhx, type_specific_params);
MAKE_DECODER("DHX", dhx, dhx, DHX);
#endif
#ifndef OPENSSL_NO_DSA
MAKE_DECODER("DSA", dsa, dsa, PKCS8);
MAKE_DECODER("DSA", dsa, dsa, SubjectPublicKeyInfo);
MAKE_DECODER("DSA", dsa, dsa, type_specific);
MAKE_DECODER("DSA", dsa, dsa, DSA);
#endif
#ifndef OPENSSL_NO_EC
MAKE_DECODER("EC", ec, ec, PKCS8);
MAKE_DECODER("EC", ec, ec, SubjectPublicKeyInfo);
MAKE_DECODER("EC", ec, ec, type_specific_no_pub);
MAKE_DECODER("EC", ec, ec, EC);
MAKE_DECODER("X25519", x25519, ecx, PKCS8);
MAKE_DECODER("X25519", x25519, ecx, SubjectPublicKeyInfo);
MAKE_DECODER("X448", x448, ecx, PKCS8);
MAKE_DECODER("X448", x448, ecx, SubjectPublicKeyInfo);
MAKE_DECODER("ED25519", ed25519, ecx, PKCS8);
MAKE_DECODER("ED25519", ed25519, ecx, SubjectPublicKeyInfo);
MAKE_DECODER("ED448", ed448, ecx, PKCS8);
MAKE_DECODER("ED448", ed448, ecx, SubjectPublicKeyInfo);
# ifndef OPENSSL_NO_SM2
MAKE_DECODER("SM2", sm2, ec, PKCS8);
MAKE_DECODER("SM2", sm2, ec, SubjectPublicKeyInfo);
# endif
#endif
MAKE_DECODER("RSA", rsa, rsa, PKCS8);
MAKE_DECODER("RSA", rsa, rsa, SubjectPublicKeyInfo);
MAKE_DECODER("RSA", rsa, rsa, type_specific_keypair);
MAKE_DECODER("RSA", rsa, rsa, RSA);
MAKE_DECODER("RSA-PSS", rsapss, rsapss, PKCS8);
MAKE_DECODER("RSA-PSS", rsapss, rsapss, SubjectPublicKeyInfo);
