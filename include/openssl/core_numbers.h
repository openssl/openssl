/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CORE_NUMBERS_H
# define OPENSSL_CORE_NUMBERS_H

# include <stdarg.h>
# include <openssl/core.h>

# ifdef __cplusplus
extern "C" {
# endif

/*-
 * Identities
 * ----------
 *
 * All series start with 1, to allow 0 to be an array terminator.
 * For any FUNC identity, we also provide a function signature typedef
 * and a static inline function to extract a function pointer from a
 * OSSL_DISPATCH element in a type safe manner.
 *
 * Names:
 * for any function base name 'foo' (uppercase form 'FOO'), we will have
 * the following:
 * - a macro for the identity with the name OSSL_FUNC_'FOO' or derivates
 *   thereof (to be specified further down)
 * - a function signature typedef with the name OSSL_'foo'_fn
 * - a function pointer extractor function with the name OSSL_'foo'
 */

/*
 * Helper macro to create the function signature typedef and the extractor
 * |type| is the return-type of the function, |name| is the name of the
 * function to fetch, and |args| is a parenthesized list of parameters
 * for the function (that is, it is |name|'s function signature).
 */
#define OSSL_CORE_MAKE_FUNC(type,name,args)                             \
    typedef type (OSSL_##name##_fn)args;                                \
    static ossl_inline \
    OSSL_##name##_fn *OSSL_get_##name(const OSSL_DISPATCH *opf)         \
    {                                                                   \
        return (OSSL_##name##_fn *)opf->function;                       \
    }

/*
 * Core function identities, for the two OSSL_DISPATCH tables being passed
 * in the OSSL_provider_init call.
 *
 * 0 serves as a marker for the end of the OSSL_DISPATCH array, and must
 * therefore NEVER be used as a function identity.
 */
/* Functions provided by the Core to the provider, reserved numbers 1-1023 */
# define OSSL_FUNC_CORE_GETTABLE_PARAMS        1
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *,
                    core_gettable_params,(const OSSL_PROVIDER *prov))
# define OSSL_FUNC_CORE_GET_PARAMS             2
OSSL_CORE_MAKE_FUNC(int,core_get_params,(const OSSL_PROVIDER *prov,
                                         OSSL_PARAM params[]))
# define OSSL_FUNC_CORE_THREAD_START           3
OSSL_CORE_MAKE_FUNC(int,core_thread_start,(const OSSL_PROVIDER *prov,
                                           OSSL_thread_stop_handler_fn handfn))
# define OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT    4
OSSL_CORE_MAKE_FUNC(OPENSSL_CTX *,core_get_library_context,
                    (const OSSL_PROVIDER *prov))
# define OSSL_FUNC_CORE_NEW_ERROR              5
OSSL_CORE_MAKE_FUNC(void,core_new_error,(const OSSL_PROVIDER *prov))
# define OSSL_FUNC_CORE_SET_ERROR_DEBUG        6
OSSL_CORE_MAKE_FUNC(void,core_set_error_debug,
                    (const OSSL_PROVIDER *prov,
                     const char *file, int line, const char *func))
# define OSSL_FUNC_CORE_VSET_ERROR             7
OSSL_CORE_MAKE_FUNC(void,core_vset_error,
                    (const OSSL_PROVIDER *prov,
                     uint32_t reason, const char *fmt, va_list args))

/* Memory allocation, freeing, clearing. */
#define OSSL_FUNC_CRYPTO_MALLOC               10
OSSL_CORE_MAKE_FUNC(void *,
        CRYPTO_malloc, (size_t num, const char *file, int line))
#define OSSL_FUNC_CRYPTO_ZALLOC               11
OSSL_CORE_MAKE_FUNC(void *,
        CRYPTO_zalloc, (size_t num, const char *file, int line))
#define OSSL_FUNC_CRYPTO_FREE                 12
OSSL_CORE_MAKE_FUNC(void,
        CRYPTO_free, (void *ptr, const char *file, int line))
#define OSSL_FUNC_CRYPTO_CLEAR_FREE           13
OSSL_CORE_MAKE_FUNC(void,
        CRYPTO_clear_free, (void *ptr, size_t num, const char *file, int line))
#define OSSL_FUNC_CRYPTO_REALLOC              14
OSSL_CORE_MAKE_FUNC(void *,
        CRYPTO_realloc, (void *addr, size_t num, const char *file, int line))
#define OSSL_FUNC_CRYPTO_CLEAR_REALLOC        15
OSSL_CORE_MAKE_FUNC(void *,
        CRYPTO_clear_realloc, (void *addr, size_t old_num, size_t num,
                               const char *file, int line))
#define OSSL_FUNC_CRYPTO_SECURE_MALLOC        16
OSSL_CORE_MAKE_FUNC(void *,
        CRYPTO_secure_malloc, (size_t num, const char *file, int line))
#define OSSL_FUNC_CRYPTO_SECURE_ZALLOC        17
OSSL_CORE_MAKE_FUNC(void *,
        CRYPTO_secure_zalloc, (size_t num, const char *file, int line))
#define OSSL_FUNC_CRYPTO_SECURE_FREE          18
OSSL_CORE_MAKE_FUNC(void,
        CRYPTO_secure_free, (void *ptr, const char *file, int line))
#define OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE    19
OSSL_CORE_MAKE_FUNC(void,
        CRYPTO_secure_clear_free, (void *ptr, size_t num, const char *file,
                                   int line))
#define OSSL_FUNC_CRYPTO_SECURE_ALLOCATED     20
OSSL_CORE_MAKE_FUNC(int,
        CRYPTO_secure_allocated, (const void *ptr))
#define OSSL_FUNC_OPENSSL_CLEANSE             21
OSSL_CORE_MAKE_FUNC(void,
        OPENSSL_cleanse, (void *ptr, size_t len))

/* Bio functions provided by the core */
#define OSSL_FUNC_BIO_NEW_FILE                22
#define OSSL_FUNC_BIO_NEW_MEMBUF              23
#define OSSL_FUNC_BIO_READ_EX                 24
#define OSSL_FUNC_BIO_FREE                    25

OSSL_CORE_MAKE_FUNC(BIO *, BIO_new_file, (const char *filename, const char *mode))
OSSL_CORE_MAKE_FUNC(BIO *, BIO_new_membuf, (const void *buf, int len))
OSSL_CORE_MAKE_FUNC(int, BIO_read_ex, (BIO *bio, void *data, size_t data_len,
                                       size_t *bytes_read))
OSSL_CORE_MAKE_FUNC(int, BIO_free, (BIO *bio))

/* Functions provided by the provider to the Core, reserved numbers 1024-1535 */
# define OSSL_FUNC_PROVIDER_TEARDOWN         1024
OSSL_CORE_MAKE_FUNC(void,provider_teardown,(void *provctx))
# define OSSL_FUNC_PROVIDER_GETTABLE_PARAMS  1025
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *,
                    provider_gettable_params,(void *provctx))
# define OSSL_FUNC_PROVIDER_GET_PARAMS       1026
OSSL_CORE_MAKE_FUNC(int,provider_get_params,(void *provctx,
                                             OSSL_PARAM params[]))
# define OSSL_FUNC_PROVIDER_QUERY_OPERATION  1027
OSSL_CORE_MAKE_FUNC(const OSSL_ALGORITHM *,provider_query_operation,
                    (void *provctx, int operation_id, const int *no_store))
# define OSSL_FUNC_PROVIDER_GET_REASON_STRINGS 1028
OSSL_CORE_MAKE_FUNC(const OSSL_ITEM *,provider_get_reason_strings,
                    (void *provctx))

/* Operations */

# define OSSL_OP_DIGEST                              1
# define OSSL_OP_CIPHER                              2   /* Symmetric Ciphers */
# define OSSL_OP_MAC                                 3
# define OSSL_OP_KDF                                 4
# define OSSL_OP_KEYMGMT                            10
# define OSSL_OP_KEYEXCH                            11
# define OSSL_OP_SIGNATURE                          12
/* Highest known operation number */
# define OSSL_OP__HIGHEST                           12

/* Digests */

# define OSSL_FUNC_DIGEST_NEWCTX                     1
# define OSSL_FUNC_DIGEST_INIT                       2
# define OSSL_FUNC_DIGEST_UPDATE                     3
# define OSSL_FUNC_DIGEST_FINAL                      4
# define OSSL_FUNC_DIGEST_DIGEST                     5
# define OSSL_FUNC_DIGEST_FREECTX                    6
# define OSSL_FUNC_DIGEST_DUPCTX                     7
# define OSSL_FUNC_DIGEST_GET_PARAMS                 8
# define OSSL_FUNC_DIGEST_SET_CTX_PARAMS             9
# define OSSL_FUNC_DIGEST_GET_CTX_PARAMS            10
# define OSSL_FUNC_DIGEST_GETTABLE_PARAMS           11
# define OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS       12
# define OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS       13

OSSL_CORE_MAKE_FUNC(void *, OP_digest_newctx, (void *provctx))
OSSL_CORE_MAKE_FUNC(int, OP_digest_init, (void *dctx))
OSSL_CORE_MAKE_FUNC(int, OP_digest_update,
                    (void *dctx, const unsigned char *in, size_t inl))
OSSL_CORE_MAKE_FUNC(int, OP_digest_final,
                    (void *dctx,
                     unsigned char *out, size_t *outl, size_t outsz))
OSSL_CORE_MAKE_FUNC(int, OP_digest_digest,
                    (void *provctx, const unsigned char *in, size_t inl,
                     unsigned char *out, size_t *outl, size_t outsz))

OSSL_CORE_MAKE_FUNC(void, OP_digest_freectx, (void *dctx))
OSSL_CORE_MAKE_FUNC(void *, OP_digest_dupctx, (void *dctx))

OSSL_CORE_MAKE_FUNC(int, OP_digest_get_params, (OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(int, OP_digest_set_ctx_params,
                    (void *vctx, const OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(int, OP_digest_get_ctx_params,
                    (void *vctx, OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_digest_gettable_params, (void))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_digest_settable_ctx_params, (void))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_digest_gettable_ctx_params, (void))

/* Symmetric Ciphers */

# define OSSL_FUNC_CIPHER_NEWCTX                     1
# define OSSL_FUNC_CIPHER_ENCRYPT_INIT               2
# define OSSL_FUNC_CIPHER_DECRYPT_INIT               3
# define OSSL_FUNC_CIPHER_UPDATE                     4
# define OSSL_FUNC_CIPHER_FINAL                      5
# define OSSL_FUNC_CIPHER_CIPHER                     6
# define OSSL_FUNC_CIPHER_FREECTX                    7
# define OSSL_FUNC_CIPHER_DUPCTX                     8
# define OSSL_FUNC_CIPHER_GET_PARAMS                 9
# define OSSL_FUNC_CIPHER_GET_CTX_PARAMS            10
# define OSSL_FUNC_CIPHER_SET_CTX_PARAMS            11
# define OSSL_FUNC_CIPHER_GETTABLE_PARAMS           12
# define OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS       13
# define OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS       14

OSSL_CORE_MAKE_FUNC(void *, OP_cipher_newctx, (void *provctx))
OSSL_CORE_MAKE_FUNC(int, OP_cipher_encrypt_init, (void *cctx,
                                                  const unsigned char *key,
                                                  size_t keylen,
                                                  const unsigned char *iv,
                                                  size_t ivlen))
OSSL_CORE_MAKE_FUNC(int, OP_cipher_decrypt_init, (void *cctx,
                                                  const unsigned char *key,
                                                  size_t keylen,
                                                  const unsigned char *iv,
                                                  size_t ivlen))
OSSL_CORE_MAKE_FUNC(int, OP_cipher_update,
                    (void *cctx,
                     unsigned char *out, size_t *outl, size_t outsize,
                     const unsigned char *in, size_t inl))
OSSL_CORE_MAKE_FUNC(int, OP_cipher_final,
                    (void *cctx,
                     unsigned char *out, size_t *outl, size_t outsize))
OSSL_CORE_MAKE_FUNC(int, OP_cipher_cipher,
                    (void *cctx,
                     unsigned char *out, size_t *outl, size_t outsize,
                     const unsigned char *in, size_t inl))
OSSL_CORE_MAKE_FUNC(void, OP_cipher_freectx, (void *cctx))
OSSL_CORE_MAKE_FUNC(void *, OP_cipher_dupctx, (void *cctx))
OSSL_CORE_MAKE_FUNC(int, OP_cipher_get_params, (OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(int, OP_cipher_get_ctx_params, (void *cctx,
                                                    OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(int, OP_cipher_set_ctx_params, (void *cctx,
                                                    const OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_cipher_gettable_params,     (void))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_cipher_settable_ctx_params, (void))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_cipher_gettable_ctx_params, (void))

/* MACs */

# define OSSL_FUNC_MAC_NEWCTX                        1
# define OSSL_FUNC_MAC_DUPCTX                        2
# define OSSL_FUNC_MAC_FREECTX                       3
# define OSSL_FUNC_MAC_INIT                          4
# define OSSL_FUNC_MAC_UPDATE                        5
# define OSSL_FUNC_MAC_FINAL                         6
# define OSSL_FUNC_MAC_GET_PARAMS                    7
# define OSSL_FUNC_MAC_GET_CTX_PARAMS                8
# define OSSL_FUNC_MAC_SET_CTX_PARAMS                9
# define OSSL_FUNC_MAC_GETTABLE_PARAMS              10
# define OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS          11
# define OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS          12

OSSL_CORE_MAKE_FUNC(void *, OP_mac_newctx, (void *provctx))
OSSL_CORE_MAKE_FUNC(void *, OP_mac_dupctx, (void *src))
OSSL_CORE_MAKE_FUNC(void, OP_mac_freectx, (void *mctx))
OSSL_CORE_MAKE_FUNC(size_t, OP_mac_size, (void *mctx))
OSSL_CORE_MAKE_FUNC(int, OP_mac_init, (void *mctx))
OSSL_CORE_MAKE_FUNC(int, OP_mac_update,
                    (void *mctx, const unsigned char *in, size_t inl))
OSSL_CORE_MAKE_FUNC(int, OP_mac_final,
                    (void *mctx,
                     unsigned char *out, size_t *outl, size_t outsize))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_mac_gettable_params, (void))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_mac_gettable_ctx_params, (void))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_mac_settable_ctx_params, (void))
OSSL_CORE_MAKE_FUNC(int, OP_mac_get_params, (OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(int, OP_mac_get_ctx_params,
                    (void *mctx, OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(int, OP_mac_set_ctx_params,
                    (void *mctx, const OSSL_PARAM params[]))

/* KDFs and PRFs */

# define OSSL_FUNC_KDF_NEWCTX                        1
# define OSSL_FUNC_KDF_DUPCTX                        2
# define OSSL_FUNC_KDF_FREECTX                       3
# define OSSL_FUNC_KDF_RESET                         4
# define OSSL_FUNC_KDF_DERIVE                        5
# define OSSL_FUNC_KDF_GETTABLE_PARAMS               6
# define OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS           7
# define OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS           8
# define OSSL_FUNC_KDF_GET_PARAMS                    9
# define OSSL_FUNC_KDF_GET_CTX_PARAMS               10
# define OSSL_FUNC_KDF_SET_CTX_PARAMS               11

OSSL_CORE_MAKE_FUNC(void *, OP_kdf_newctx, (void *provctx))
OSSL_CORE_MAKE_FUNC(void *, OP_kdf_dupctx, (void *src))
OSSL_CORE_MAKE_FUNC(void, OP_kdf_freectx, (void *kctx))
OSSL_CORE_MAKE_FUNC(void, OP_kdf_reset, (void *kctx))
OSSL_CORE_MAKE_FUNC(int, OP_kdf_derive, (void *kctx, unsigned char *key,
                                          size_t keylen))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_kdf_gettable_params, (void))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_kdf_gettable_ctx_params, (void))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_kdf_settable_ctx_params, (void))
OSSL_CORE_MAKE_FUNC(int, OP_kdf_get_params, (OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(int, OP_kdf_get_ctx_params,
                    (void *kctx, OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(int, OP_kdf_set_ctx_params,
                    (void *kctx, const OSSL_PARAM params[]))

/*-
 * Key management
 *
 * Key domain parameter references can be created in several manners:
 * - by importing the domain parameter material via an OSSL_PARAM array.
 * - by generating key domain parameters, given input via an OSSL_PARAM
 *   array.
 *
 * Key references can be created in several manners:
 * - by importing the key material via an OSSL_PARAM array.
 * - by generating a key, given optional domain parameters and
 *   additional keygen parameters.
 *   If domain parameters are given, they must have been generated using
 *   the domain parameter generator functions.
 *   If the domain parameters comes from a different provider, results
 *   are undefined.
 *   THE CALLER MUST ENSURE THAT CORRECT DOMAIN PARAMETERS ARE USED.
 * - by loading an internal key, given a binary blob that forms an identity.
 *   THE CALLER MUST ENSURE THAT A CORRECT IDENTITY IS USED.
 */

/* Key domain parameter creation and destruction */
# define OSSL_FUNC_KEYMGMT_IMPORTDOMPARAMS          1
# define OSSL_FUNC_KEYMGMT_GENDOMPARAMS             2
# define OSSL_FUNC_KEYMGMT_FREEDOMPARAMS            3
OSSL_CORE_MAKE_FUNC(void *, OP_keymgmt_importdomparams,
                    (void *provctx, const OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(void *, OP_keymgmt_gendomparams,
                    (void *provctx, const OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(void, OP_keymgmt_freedomparams, (void *domparams))

/* Key domain parameter export */
# define OSSL_FUNC_KEYMGMT_EXPORTDOMPARAMS          4
OSSL_CORE_MAKE_FUNC(int, OP_keymgmt_exportdomparams,
                    (void *domparams, OSSL_PARAM params[]))

/* Key domain parameter discovery */
# define OSSL_FUNC_KEYMGMT_IMPORTDOMPARAM_TYPES     5
# define OSSL_FUNC_KEYMGMT_EXPORTDOMPARAM_TYPES     6
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_keymgmt_importdomparam_types,
                    (void))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_keymgmt_exportdomparam_types,
                    (void))

/* Key creation and destruction */
# define OSSL_FUNC_KEYMGMT_IMPORTKEY               10
# define OSSL_FUNC_KEYMGMT_GENKEY                  11
# define OSSL_FUNC_KEYMGMT_LOADKEY                 12
# define OSSL_FUNC_KEYMGMT_FREEKEY                 13
OSSL_CORE_MAKE_FUNC(void *, OP_keymgmt_importkey,
                    (void *provctx, const OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(void *, OP_keymgmt_genkey,
                    (void *provctx,
                     void *domparams, const OSSL_PARAM genkeyparams[]))
OSSL_CORE_MAKE_FUNC(void *, OP_keymgmt_loadkey,
                    (void *provctx, void *id, size_t idlen))
OSSL_CORE_MAKE_FUNC(void, OP_keymgmt_freekey, (void *key))

/* Key export */
# define OSSL_FUNC_KEYMGMT_EXPORTKEY               14
OSSL_CORE_MAKE_FUNC(int, OP_keymgmt_exportkey,
                    (void *key, OSSL_PARAM params[]))

/* Key discovery */
# define OSSL_FUNC_KEYMGMT_IMPORTKEY_TYPES         15
# define OSSL_FUNC_KEYMGMT_EXPORTKEY_TYPES         16
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_keymgmt_importkey_types, (void))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_keymgmt_exportkey_types, (void))

/* Key Exchange */

# define OSSL_FUNC_KEYEXCH_NEWCTX                      1
# define OSSL_FUNC_KEYEXCH_INIT                        2
# define OSSL_FUNC_KEYEXCH_DERIVE                      3
# define OSSL_FUNC_KEYEXCH_SET_PEER                    4
# define OSSL_FUNC_KEYEXCH_FREECTX                     5
# define OSSL_FUNC_KEYEXCH_DUPCTX                      6
# define OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS              7
# define OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS         8

OSSL_CORE_MAKE_FUNC(void *, OP_keyexch_newctx, (void *provctx))
OSSL_CORE_MAKE_FUNC(int, OP_keyexch_init, (void *ctx, void *provkey))
OSSL_CORE_MAKE_FUNC(int, OP_keyexch_derive, (void *ctx,  unsigned char *secret,
                                             size_t *secretlen, size_t outlen))
OSSL_CORE_MAKE_FUNC(int, OP_keyexch_set_peer, (void *ctx, void *provkey))
OSSL_CORE_MAKE_FUNC(void, OP_keyexch_freectx, (void *ctx))
OSSL_CORE_MAKE_FUNC(void *, OP_keyexch_dupctx, (void *ctx))
OSSL_CORE_MAKE_FUNC(int, OP_keyexch_set_ctx_params, (void *ctx,
                                                     const OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_keyexch_settable_ctx_params,
                    (void))

/* Signature */

# define OSSL_FUNC_SIGNATURE_NEWCTX                  1
# define OSSL_FUNC_SIGNATURE_SIGN_INIT               2
# define OSSL_FUNC_SIGNATURE_SIGN                    3
# define OSSL_FUNC_SIGNATURE_VERIFY_INIT             4
# define OSSL_FUNC_SIGNATURE_VERIFY                  5
# define OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT     6
# define OSSL_FUNC_SIGNATURE_VERIFY_RECOVER          7
# define OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT        8
# define OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE      9
# define OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL      10
# define OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT     11
# define OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE   12
# define OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL    13
# define OSSL_FUNC_SIGNATURE_FREECTX                14
# define OSSL_FUNC_SIGNATURE_DUPCTX                 15
# define OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS         16
# define OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS    17
# define OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS         18
# define OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS    19
# define OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS      20
# define OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS 21
# define OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS      22
# define OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS 23

OSSL_CORE_MAKE_FUNC(void *, OP_signature_newctx, (void *provctx))
OSSL_CORE_MAKE_FUNC(int, OP_signature_sign_init, (void *ctx, void *provkey))
OSSL_CORE_MAKE_FUNC(int, OP_signature_sign, (void *ctx,  unsigned char *sig,
                                             size_t *siglen, size_t sigsize,
                                             const unsigned char *tbs,
                                             size_t tbslen))
OSSL_CORE_MAKE_FUNC(int, OP_signature_verify_init, (void *ctx, void *provkey))
OSSL_CORE_MAKE_FUNC(int, OP_signature_verify, (void *ctx,
                                               const unsigned char *sig,
                                               size_t siglen,
                                               const unsigned char *tbs,
                                               size_t tbslen))
OSSL_CORE_MAKE_FUNC(int, OP_signature_verify_recover_init, (void *ctx,
                                                            void *provkey))
OSSL_CORE_MAKE_FUNC(int, OP_signature_verify_recover, (void *ctx,
                                                       unsigned char *rout,
                                                       size_t *routlen,
                                                       size_t routsize,
                                                       const unsigned char *sig,
                                                       size_t siglen))
OSSL_CORE_MAKE_FUNC(int, OP_signature_digest_sign_init,
                    (void *ctx, const char *mdname, const char *props,
                     void *provkey))
OSSL_CORE_MAKE_FUNC(int, OP_signature_digest_sign_update,
                    (void *ctx, const unsigned char *data, size_t datalen))
OSSL_CORE_MAKE_FUNC(int, OP_signature_digest_sign_final,
                    (void *ctx, unsigned char *sig, size_t *siglen,
                     size_t sigsize))
OSSL_CORE_MAKE_FUNC(int, OP_signature_digest_verify_init,
                    (void *ctx, const char *mdname, const char *props,
                     void *provkey))
OSSL_CORE_MAKE_FUNC(int, OP_signature_digest_verify_update,
                    (void *ctx, const unsigned char *data, size_t datalen))
OSSL_CORE_MAKE_FUNC(int, OP_signature_digest_verify_final,
                    (void *ctx, const unsigned char *sig, size_t siglen))
OSSL_CORE_MAKE_FUNC(void, OP_signature_freectx, (void *ctx))
OSSL_CORE_MAKE_FUNC(void *, OP_signature_dupctx, (void *ctx))
OSSL_CORE_MAKE_FUNC(int, OP_signature_get_ctx_params,
                    (void *ctx, OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_signature_gettable_ctx_params,
                    (void))
OSSL_CORE_MAKE_FUNC(int, OP_signature_set_ctx_params,
                    (void *ctx, const OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_signature_settable_ctx_params,
                    (void))
OSSL_CORE_MAKE_FUNC(int, OP_signature_get_ctx_md_params,
                    (void *ctx, OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_signature_gettable_ctx_md_params,
                    (void *ctx))
OSSL_CORE_MAKE_FUNC(int, OP_signature_set_ctx_md_params,
                    (void *ctx, const OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(const OSSL_PARAM *, OP_signature_settable_ctx_md_params,
                    (void *ctx))

# ifdef __cplusplus
}
# endif

#endif
