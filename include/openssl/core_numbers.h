/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_CORE_NUMBERS_H
# define OPENtls_CORE_NUMBERS_H

# include <stdarg.h>
# include <opentls/core.h>

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
 * Otls_DISPATCH element in a type safe manner.
 *
 * Names:
 * for any function base name 'foo' (uppercase form 'FOO'), we will have
 * the following:
 * - a macro for the identity with the name Otls_FUNC_'FOO' or derivatives
 *   thereof (to be specified further down)
 * - a function signature typedef with the name Otls_'foo'_fn
 * - a function pointer extractor function with the name Otls_'foo'
 */

/*
 * Helper macro to create the function signature typedef and the extractor
 * |type| is the return-type of the function, |name| is the name of the
 * function to fetch, and |args| is a parenthesized list of parameters
 * for the function (that is, it is |name|'s function signature).
 */
#define Otls_CORE_MAKE_FUNC(type,name,args)                             \
    typedef type (Otls_##name##_fn)args;                                \
    static otls_inline \
    Otls_##name##_fn *Otls_get_##name(const Otls_DISPATCH *opf)         \
    {                                                                   \
        return (Otls_##name##_fn *)opf->function;                       \
    }

/*
 * Core function identities, for the two Otls_DISPATCH tables being passed
 * in the Otls_provider_init call.
 *
 * 0 serves as a marker for the end of the Otls_DISPATCH array, and must
 * therefore NEVER be used as a function identity.
 */
/* Functions provided by the Core to the provider, reserved numbers 1-1023 */
# define Otls_FUNC_CORE_GETTABLE_PARAMS        1
Otls_CORE_MAKE_FUNC(const Otls_PARAM *,
                    core_gettable_params,(const Otls_PROVIDER *prov))
# define Otls_FUNC_CORE_GET_PARAMS             2
Otls_CORE_MAKE_FUNC(int,core_get_params,(const Otls_PROVIDER *prov,
                                         Otls_PARAM params[]))
# define Otls_FUNC_CORE_THREAD_START           3
Otls_CORE_MAKE_FUNC(int,core_thread_start,(const Otls_PROVIDER *prov,
                                           Otls_thread_stop_handler_fn handfn))
# define Otls_FUNC_CORE_GET_LIBRARY_CONTEXT    4
Otls_CORE_MAKE_FUNC(OPENtls_CTX *,core_get_library_context,
                    (const Otls_PROVIDER *prov))
# define Otls_FUNC_CORE_NEW_ERROR              5
Otls_CORE_MAKE_FUNC(void,core_new_error,(const Otls_PROVIDER *prov))
# define Otls_FUNC_CORE_SET_ERROR_DEBUG        6
Otls_CORE_MAKE_FUNC(void,core_set_error_debug,
                    (const Otls_PROVIDER *prov,
                     const char *file, int line, const char *func))
# define Otls_FUNC_CORE_VSET_ERROR             7
Otls_CORE_MAKE_FUNC(void,core_vset_error,
                    (const Otls_PROVIDER *prov,
                     uint32_t reason, const char *fmt, va_list args))

/* Memory allocation, freeing, clearing. */
#define Otls_FUNC_CRYPTO_MALLOC               10
Otls_CORE_MAKE_FUNC(void *,
        CRYPTO_malloc, (size_t num, const char *file, int line))
#define Otls_FUNC_CRYPTO_ZALLOC               11
Otls_CORE_MAKE_FUNC(void *,
        CRYPTO_zalloc, (size_t num, const char *file, int line))
#define Otls_FUNC_CRYPTO_FREE                 12
Otls_CORE_MAKE_FUNC(void,
        CRYPTO_free, (void *ptr, const char *file, int line))
#define Otls_FUNC_CRYPTO_CLEAR_FREE           13
Otls_CORE_MAKE_FUNC(void,
        CRYPTO_clear_free, (void *ptr, size_t num, const char *file, int line))
#define Otls_FUNC_CRYPTO_REALLOC              14
Otls_CORE_MAKE_FUNC(void *,
        CRYPTO_realloc, (void *addr, size_t num, const char *file, int line))
#define Otls_FUNC_CRYPTO_CLEAR_REALLOC        15
Otls_CORE_MAKE_FUNC(void *,
        CRYPTO_clear_realloc, (void *addr, size_t old_num, size_t num,
                               const char *file, int line))
#define Otls_FUNC_CRYPTO_SECURE_MALLOC        16
Otls_CORE_MAKE_FUNC(void *,
        CRYPTO_secure_malloc, (size_t num, const char *file, int line))
#define Otls_FUNC_CRYPTO_SECURE_ZALLOC        17
Otls_CORE_MAKE_FUNC(void *,
        CRYPTO_secure_zalloc, (size_t num, const char *file, int line))
#define Otls_FUNC_CRYPTO_SECURE_FREE          18
Otls_CORE_MAKE_FUNC(void,
        CRYPTO_secure_free, (void *ptr, const char *file, int line))
#define Otls_FUNC_CRYPTO_SECURE_CLEAR_FREE    19
Otls_CORE_MAKE_FUNC(void,
        CRYPTO_secure_clear_free, (void *ptr, size_t num, const char *file,
                                   int line))
#define Otls_FUNC_CRYPTO_SECURE_ALLOCATED     20
Otls_CORE_MAKE_FUNC(int,
        CRYPTO_secure_allocated, (const void *ptr))
#define Otls_FUNC_OPENtls_CLEANSE             21
Otls_CORE_MAKE_FUNC(void,
        OPENtls_cleanse, (void *ptr, size_t len))

/* Bio functions provided by the core */
#define Otls_FUNC_BIO_NEW_FILE                23
#define Otls_FUNC_BIO_NEW_MEMBUF              24
#define Otls_FUNC_BIO_READ_EX                 25
#define Otls_FUNC_BIO_FREE                    26
#define Otls_FUNC_BIO_VPRINTF                 27

Otls_CORE_MAKE_FUNC(BIO *, BIO_new_file, (const char *filename, const char *mode))
Otls_CORE_MAKE_FUNC(BIO *, BIO_new_membuf, (const void *buf, int len))
Otls_CORE_MAKE_FUNC(int, BIO_read_ex, (BIO *bio, void *data, size_t data_len,
                                       size_t *bytes_read))
Otls_CORE_MAKE_FUNC(int, BIO_free, (BIO *bio))
Otls_CORE_MAKE_FUNC(int, BIO_vprintf, (BIO *bio, const char *format,
                                       va_list args))

/* Functions provided by the provider to the Core, reserved numbers 1024-1535 */
# define Otls_FUNC_PROVIDER_TEARDOWN         1024
Otls_CORE_MAKE_FUNC(void,provider_teardown,(void *provctx))
# define Otls_FUNC_PROVIDER_GETTABLE_PARAMS  1025
Otls_CORE_MAKE_FUNC(const Otls_PARAM *,
                    provider_gettable_params,(void *provctx))
# define Otls_FUNC_PROVIDER_GET_PARAMS       1026
Otls_CORE_MAKE_FUNC(int,provider_get_params,(void *provctx,
                                             Otls_PARAM params[]))
# define Otls_FUNC_PROVIDER_QUERY_OPERATION  1027
Otls_CORE_MAKE_FUNC(const Otls_ALGORITHM *,provider_query_operation,
                    (void *provctx, int operation_id, const int *no_store))
# define Otls_FUNC_PROVIDER_GET_REASON_STRINGS 1028
Otls_CORE_MAKE_FUNC(const Otls_ITEM *,provider_get_reason_strings,
                    (void *provctx))

/* Operations */

# define Otls_OP_DIGEST                              1
# define Otls_OP_CIPHER                              2   /* Symmetric Ciphers */
# define Otls_OP_MAC                                 3
# define Otls_OP_KDF                                 4
# define Otls_OP_KEYMGMT                            10
# define Otls_OP_KEYEXCH                            11
# define Otls_OP_SIGNATURE                          12
# define Otls_OP_ASYM_CIPHER                        13
/* New section for non-EVP operations */
# define Otls_OP_SERIALIZER                         20
/* Highest known operation number */
# define Otls_OP__HIGHEST                           20

/* Digests */

# define Otls_FUNC_DIGEST_NEWCTX                     1
# define Otls_FUNC_DIGEST_INIT                       2
# define Otls_FUNC_DIGEST_UPDATE                     3
# define Otls_FUNC_DIGEST_FINAL                      4
# define Otls_FUNC_DIGEST_DIGEST                     5
# define Otls_FUNC_DIGEST_FREECTX                    6
# define Otls_FUNC_DIGEST_DUPCTX                     7
# define Otls_FUNC_DIGEST_GET_PARAMS                 8
# define Otls_FUNC_DIGEST_SET_CTX_PARAMS             9
# define Otls_FUNC_DIGEST_GET_CTX_PARAMS            10
# define Otls_FUNC_DIGEST_GETTABLE_PARAMS           11
# define Otls_FUNC_DIGEST_SETTABLE_CTX_PARAMS       12
# define Otls_FUNC_DIGEST_GETTABLE_CTX_PARAMS       13

Otls_CORE_MAKE_FUNC(void *, OP_digest_newctx, (void *provctx))
Otls_CORE_MAKE_FUNC(int, OP_digest_init, (void *dctx))
Otls_CORE_MAKE_FUNC(int, OP_digest_update,
                    (void *dctx, const unsigned char *in, size_t inl))
Otls_CORE_MAKE_FUNC(int, OP_digest_final,
                    (void *dctx,
                     unsigned char *out, size_t *outl, size_t outsz))
Otls_CORE_MAKE_FUNC(int, OP_digest_digest,
                    (void *provctx, const unsigned char *in, size_t inl,
                     unsigned char *out, size_t *outl, size_t outsz))

Otls_CORE_MAKE_FUNC(void, OP_digest_freectx, (void *dctx))
Otls_CORE_MAKE_FUNC(void *, OP_digest_dupctx, (void *dctx))

Otls_CORE_MAKE_FUNC(int, OP_digest_get_params, (Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(int, OP_digest_set_ctx_params,
                    (void *vctx, const Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(int, OP_digest_get_ctx_params,
                    (void *vctx, Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_digest_gettable_params, (void))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_digest_settable_ctx_params, (void))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_digest_gettable_ctx_params, (void))

/* Symmetric Ciphers */

# define Otls_FUNC_CIPHER_NEWCTX                     1
# define Otls_FUNC_CIPHER_ENCRYPT_INIT               2
# define Otls_FUNC_CIPHER_DECRYPT_INIT               3
# define Otls_FUNC_CIPHER_UPDATE                     4
# define Otls_FUNC_CIPHER_FINAL                      5
# define Otls_FUNC_CIPHER_CIPHER                     6
# define Otls_FUNC_CIPHER_FREECTX                    7
# define Otls_FUNC_CIPHER_DUPCTX                     8
# define Otls_FUNC_CIPHER_GET_PARAMS                 9
# define Otls_FUNC_CIPHER_GET_CTX_PARAMS            10
# define Otls_FUNC_CIPHER_SET_CTX_PARAMS            11
# define Otls_FUNC_CIPHER_GETTABLE_PARAMS           12
# define Otls_FUNC_CIPHER_GETTABLE_CTX_PARAMS       13
# define Otls_FUNC_CIPHER_SETTABLE_CTX_PARAMS       14

Otls_CORE_MAKE_FUNC(void *, OP_cipher_newctx, (void *provctx))
Otls_CORE_MAKE_FUNC(int, OP_cipher_encrypt_init, (void *cctx,
                                                  const unsigned char *key,
                                                  size_t keylen,
                                                  const unsigned char *iv,
                                                  size_t ivlen))
Otls_CORE_MAKE_FUNC(int, OP_cipher_decrypt_init, (void *cctx,
                                                  const unsigned char *key,
                                                  size_t keylen,
                                                  const unsigned char *iv,
                                                  size_t ivlen))
Otls_CORE_MAKE_FUNC(int, OP_cipher_update,
                    (void *cctx,
                     unsigned char *out, size_t *outl, size_t outsize,
                     const unsigned char *in, size_t inl))
Otls_CORE_MAKE_FUNC(int, OP_cipher_final,
                    (void *cctx,
                     unsigned char *out, size_t *outl, size_t outsize))
Otls_CORE_MAKE_FUNC(int, OP_cipher_cipher,
                    (void *cctx,
                     unsigned char *out, size_t *outl, size_t outsize,
                     const unsigned char *in, size_t inl))
Otls_CORE_MAKE_FUNC(void, OP_cipher_freectx, (void *cctx))
Otls_CORE_MAKE_FUNC(void *, OP_cipher_dupctx, (void *cctx))
Otls_CORE_MAKE_FUNC(int, OP_cipher_get_params, (Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(int, OP_cipher_get_ctx_params, (void *cctx,
                                                    Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(int, OP_cipher_set_ctx_params, (void *cctx,
                                                    const Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_cipher_gettable_params,     (void))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_cipher_settable_ctx_params, (void))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_cipher_gettable_ctx_params, (void))

/* MACs */

# define Otls_FUNC_MAC_NEWCTX                        1
# define Otls_FUNC_MAC_DUPCTX                        2
# define Otls_FUNC_MAC_FREECTX                       3
# define Otls_FUNC_MAC_INIT                          4
# define Otls_FUNC_MAC_UPDATE                        5
# define Otls_FUNC_MAC_FINAL                         6
# define Otls_FUNC_MAC_GET_PARAMS                    7
# define Otls_FUNC_MAC_GET_CTX_PARAMS                8
# define Otls_FUNC_MAC_SET_CTX_PARAMS                9
# define Otls_FUNC_MAC_GETTABLE_PARAMS              10
# define Otls_FUNC_MAC_GETTABLE_CTX_PARAMS          11
# define Otls_FUNC_MAC_SETTABLE_CTX_PARAMS          12

Otls_CORE_MAKE_FUNC(void *, OP_mac_newctx, (void *provctx))
Otls_CORE_MAKE_FUNC(void *, OP_mac_dupctx, (void *src))
Otls_CORE_MAKE_FUNC(void, OP_mac_freectx, (void *mctx))
Otls_CORE_MAKE_FUNC(size_t, OP_mac_size, (void *mctx))
Otls_CORE_MAKE_FUNC(int, OP_mac_init, (void *mctx))
Otls_CORE_MAKE_FUNC(int, OP_mac_update,
                    (void *mctx, const unsigned char *in, size_t inl))
Otls_CORE_MAKE_FUNC(int, OP_mac_final,
                    (void *mctx,
                     unsigned char *out, size_t *outl, size_t outsize))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_mac_gettable_params, (void))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_mac_gettable_ctx_params, (void))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_mac_settable_ctx_params, (void))
Otls_CORE_MAKE_FUNC(int, OP_mac_get_params, (Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(int, OP_mac_get_ctx_params,
                    (void *mctx, Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(int, OP_mac_set_ctx_params,
                    (void *mctx, const Otls_PARAM params[]))

/* KDFs and PRFs */

# define Otls_FUNC_KDF_NEWCTX                        1
# define Otls_FUNC_KDF_DUPCTX                        2
# define Otls_FUNC_KDF_FREECTX                       3
# define Otls_FUNC_KDF_RESET                         4
# define Otls_FUNC_KDF_DERIVE                        5
# define Otls_FUNC_KDF_GETTABLE_PARAMS               6
# define Otls_FUNC_KDF_GETTABLE_CTX_PARAMS           7
# define Otls_FUNC_KDF_SETTABLE_CTX_PARAMS           8
# define Otls_FUNC_KDF_GET_PARAMS                    9
# define Otls_FUNC_KDF_GET_CTX_PARAMS               10
# define Otls_FUNC_KDF_SET_CTX_PARAMS               11

Otls_CORE_MAKE_FUNC(void *, OP_kdf_newctx, (void *provctx))
Otls_CORE_MAKE_FUNC(void *, OP_kdf_dupctx, (void *src))
Otls_CORE_MAKE_FUNC(void, OP_kdf_freectx, (void *kctx))
Otls_CORE_MAKE_FUNC(void, OP_kdf_reset, (void *kctx))
Otls_CORE_MAKE_FUNC(int, OP_kdf_derive, (void *kctx, unsigned char *key,
                                          size_t keylen))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_kdf_gettable_params, (void))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_kdf_gettable_ctx_params, (void))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_kdf_settable_ctx_params, (void))
Otls_CORE_MAKE_FUNC(int, OP_kdf_get_params, (Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(int, OP_kdf_get_ctx_params,
                    (void *kctx, Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(int, OP_kdf_set_ctx_params,
                    (void *kctx, const Otls_PARAM params[]))

/*-
 * Key management
 *
 * Key domain parameter references can be created in several manners:
 * - by importing the domain parameter material via an Otls_PARAM array.
 * - by generating key domain parameters, given input via an Otls_PARAM
 *   array.
 *
 * Key references can be created in several manners:
 * - by importing the key material via an Otls_PARAM array.
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
# define Otls_FUNC_KEYMGMT_IMPORTDOMPARAMS          1
# define Otls_FUNC_KEYMGMT_GENDOMPARAMS             2
# define Otls_FUNC_KEYMGMT_FREEDOMPARAMS            3
Otls_CORE_MAKE_FUNC(void *, OP_keymgmt_importdomparams,
                    (void *provctx, const Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(void *, OP_keymgmt_gendomparams,
                    (void *provctx, const Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(void, OP_keymgmt_freedomparams, (void *domparams))

/* Key domain parameter export */
# define Otls_FUNC_KEYMGMT_EXPORTDOMPARAMS          4
Otls_CORE_MAKE_FUNC(int, OP_keymgmt_exportdomparams,
                    (void *domparams, Otls_CALLBACK *param_cb, void *cbarg))

/* Key domain parameter discovery */
/*
 * TODO(v3.0) investigate if we need OP_keymgmt_exportdomparam_types.
 * 'opentls provider' may be a caller...
 */
# define Otls_FUNC_KEYMGMT_IMPORTDOMPARAM_TYPES     5
# define Otls_FUNC_KEYMGMT_EXPORTDOMPARAM_TYPES     6
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_keymgmt_importdomparam_types,
                    (void))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_keymgmt_exportdomparam_types,
                    (void))

/* Key creation and destruction */
# define Otls_FUNC_KEYMGMT_IMPORTKEY               10
# define Otls_FUNC_KEYMGMT_GENKEY                  11
# define Otls_FUNC_KEYMGMT_LOADKEY                 12
# define Otls_FUNC_KEYMGMT_FREEKEY                 13
Otls_CORE_MAKE_FUNC(void *, OP_keymgmt_importkey,
                    (void *provctx, const Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(void *, OP_keymgmt_genkey,
                    (void *provctx,
                     void *domparams, const Otls_PARAM genkeyparams[]))
Otls_CORE_MAKE_FUNC(void *, OP_keymgmt_loadkey,
                    (void *provctx, void *id, size_t idlen))
Otls_CORE_MAKE_FUNC(void, OP_keymgmt_freekey, (void *key))

/* Key export */
# define Otls_FUNC_KEYMGMT_EXPORTKEY               14
Otls_CORE_MAKE_FUNC(int, OP_keymgmt_exportkey,
                    (void *key, Otls_CALLBACK *param_cb, void *cbarg))

/* Key discovery */
/*
 * TODO(v3.0) investigate if we need OP_keymgmt_exportkey_types.
 * 'opentls provider' may be a caller...
 */
# define Otls_FUNC_KEYMGMT_IMPORTKEY_TYPES         15
# define Otls_FUNC_KEYMGMT_EXPORTKEY_TYPES         16
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_keymgmt_importkey_types, (void))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_keymgmt_exportkey_types, (void))

/* Discovery of supported operations */
# define Otls_FUNC_KEYMGMT_QUERY_OPERATION_NAME    17
Otls_CORE_MAKE_FUNC(const char *,OP_keymgmt_query_operation_name,
                    (int operation_id))

/* Key Exchange */

# define Otls_FUNC_KEYEXCH_NEWCTX                      1
# define Otls_FUNC_KEYEXCH_INIT                        2
# define Otls_FUNC_KEYEXCH_DERIVE                      3
# define Otls_FUNC_KEYEXCH_SET_PEER                    4
# define Otls_FUNC_KEYEXCH_FREECTX                     5
# define Otls_FUNC_KEYEXCH_DUPCTX                      6
# define Otls_FUNC_KEYEXCH_SET_CTX_PARAMS              7
# define Otls_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS         8

Otls_CORE_MAKE_FUNC(void *, OP_keyexch_newctx, (void *provctx))
Otls_CORE_MAKE_FUNC(int, OP_keyexch_init, (void *ctx, void *provkey))
Otls_CORE_MAKE_FUNC(int, OP_keyexch_derive, (void *ctx,  unsigned char *secret,
                                             size_t *secretlen, size_t outlen))
Otls_CORE_MAKE_FUNC(int, OP_keyexch_set_peer, (void *ctx, void *provkey))
Otls_CORE_MAKE_FUNC(void, OP_keyexch_freectx, (void *ctx))
Otls_CORE_MAKE_FUNC(void *, OP_keyexch_dupctx, (void *ctx))
Otls_CORE_MAKE_FUNC(int, OP_keyexch_set_ctx_params, (void *ctx,
                                                     const Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_keyexch_settable_ctx_params,
                    (void))

/* Signature */

# define Otls_FUNC_SIGNATURE_NEWCTX                  1
# define Otls_FUNC_SIGNATURE_SIGN_INIT               2
# define Otls_FUNC_SIGNATURE_SIGN                    3
# define Otls_FUNC_SIGNATURE_VERIFY_INIT             4
# define Otls_FUNC_SIGNATURE_VERIFY                  5
# define Otls_FUNC_SIGNATURE_VERIFY_RECOVER_INIT     6
# define Otls_FUNC_SIGNATURE_VERIFY_RECOVER          7
# define Otls_FUNC_SIGNATURE_DIGEST_SIGN_INIT        8
# define Otls_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE      9
# define Otls_FUNC_SIGNATURE_DIGEST_SIGN_FINAL      10
# define Otls_FUNC_SIGNATURE_DIGEST_VERIFY_INIT     11
# define Otls_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE   12
# define Otls_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL    13
# define Otls_FUNC_SIGNATURE_FREECTX                14
# define Otls_FUNC_SIGNATURE_DUPCTX                 15
# define Otls_FUNC_SIGNATURE_GET_CTX_PARAMS         16
# define Otls_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS    17
# define Otls_FUNC_SIGNATURE_SET_CTX_PARAMS         18
# define Otls_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS    19
# define Otls_FUNC_SIGNATURE_GET_CTX_MD_PARAMS      20
# define Otls_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS 21
# define Otls_FUNC_SIGNATURE_SET_CTX_MD_PARAMS      22
# define Otls_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS 23

Otls_CORE_MAKE_FUNC(void *, OP_signature_newctx, (void *provctx))
Otls_CORE_MAKE_FUNC(int, OP_signature_sign_init, (void *ctx, void *provkey))
Otls_CORE_MAKE_FUNC(int, OP_signature_sign, (void *ctx,  unsigned char *sig,
                                             size_t *siglen, size_t sigsize,
                                             const unsigned char *tbs,
                                             size_t tbslen))
Otls_CORE_MAKE_FUNC(int, OP_signature_verify_init, (void *ctx, void *provkey))
Otls_CORE_MAKE_FUNC(int, OP_signature_verify, (void *ctx,
                                               const unsigned char *sig,
                                               size_t siglen,
                                               const unsigned char *tbs,
                                               size_t tbslen))
Otls_CORE_MAKE_FUNC(int, OP_signature_verify_recover_init, (void *ctx,
                                                            void *provkey))
Otls_CORE_MAKE_FUNC(int, OP_signature_verify_recover, (void *ctx,
                                                       unsigned char *rout,
                                                       size_t *routlen,
                                                       size_t routsize,
                                                       const unsigned char *sig,
                                                       size_t siglen))
Otls_CORE_MAKE_FUNC(int, OP_signature_digest_sign_init,
                    (void *ctx, const char *mdname, const char *props,
                     void *provkey))
Otls_CORE_MAKE_FUNC(int, OP_signature_digest_sign_update,
                    (void *ctx, const unsigned char *data, size_t datalen))
Otls_CORE_MAKE_FUNC(int, OP_signature_digest_sign_final,
                    (void *ctx, unsigned char *sig, size_t *siglen,
                     size_t sigsize))
Otls_CORE_MAKE_FUNC(int, OP_signature_digest_verify_init,
                    (void *ctx, const char *mdname, const char *props,
                     void *provkey))
Otls_CORE_MAKE_FUNC(int, OP_signature_digest_verify_update,
                    (void *ctx, const unsigned char *data, size_t datalen))
Otls_CORE_MAKE_FUNC(int, OP_signature_digest_verify_final,
                    (void *ctx, const unsigned char *sig, size_t siglen))
Otls_CORE_MAKE_FUNC(void, OP_signature_freectx, (void *ctx))
Otls_CORE_MAKE_FUNC(void *, OP_signature_dupctx, (void *ctx))
Otls_CORE_MAKE_FUNC(int, OP_signature_get_ctx_params,
                    (void *ctx, Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_signature_gettable_ctx_params,
                    (void))
Otls_CORE_MAKE_FUNC(int, OP_signature_set_ctx_params,
                    (void *ctx, const Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_signature_settable_ctx_params,
                    (void))
Otls_CORE_MAKE_FUNC(int, OP_signature_get_ctx_md_params,
                    (void *ctx, Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_signature_gettable_ctx_md_params,
                    (void *ctx))
Otls_CORE_MAKE_FUNC(int, OP_signature_set_ctx_md_params,
                    (void *ctx, const Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_signature_settable_ctx_md_params,
                    (void *ctx))


/* Asymmetric Ciphers */

# define Otls_FUNC_ASYM_CIPHER_NEWCTX                  1
# define Otls_FUNC_ASYM_CIPHER_ENCRYPT_INIT            2
# define Otls_FUNC_ASYM_CIPHER_ENCRYPT                 3
# define Otls_FUNC_ASYM_CIPHER_DECRYPT_INIT            4
# define Otls_FUNC_ASYM_CIPHER_DECRYPT                 5
# define Otls_FUNC_ASYM_CIPHER_FREECTX                 6
# define Otls_FUNC_ASYM_CIPHER_DUPCTX                  7
# define Otls_FUNC_ASYM_CIPHER_GET_CTX_PARAMS          8
# define Otls_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS     9
# define Otls_FUNC_ASYM_CIPHER_SET_CTX_PARAMS         10
# define Otls_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS    11

Otls_CORE_MAKE_FUNC(void *, OP_asym_cipher_newctx, (void *provctx))
Otls_CORE_MAKE_FUNC(int, OP_asym_cipher_encrypt_init, (void *ctx, void *provkey))
Otls_CORE_MAKE_FUNC(int, OP_asym_cipher_encrypt, (void *ctx, unsigned char *out,
                                                  size_t *outlen,
                                                  size_t outsize,
                                                  const unsigned char *in,
                                                  size_t inlen))
Otls_CORE_MAKE_FUNC(int, OP_asym_cipher_decrypt_init, (void *ctx, void *provkey))
Otls_CORE_MAKE_FUNC(int, OP_asym_cipher_decrypt, (void *ctx, unsigned char *out,
                                                  size_t *outlen,
                                                  size_t outsize,
                                                  const unsigned char *in,
                                                  size_t inlen))
Otls_CORE_MAKE_FUNC(void, OP_asym_cipher_freectx, (void *ctx))
Otls_CORE_MAKE_FUNC(void *, OP_asym_cipher_dupctx, (void *ctx))
Otls_CORE_MAKE_FUNC(int, OP_asym_cipher_get_ctx_params,
                    (void *ctx, Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_asym_cipher_gettable_ctx_params,
                    (void))
Otls_CORE_MAKE_FUNC(int, OP_asym_cipher_set_ctx_params,
                    (void *ctx, const Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_asym_cipher_settable_ctx_params,
                    (void))

/* Serializers */
# define Otls_FUNC_SERIALIZER_NEWCTX                1
# define Otls_FUNC_SERIALIZER_FREECTX               2
# define Otls_FUNC_SERIALIZER_SET_CTX_PARAMS        3
# define Otls_FUNC_SERIALIZER_SETTABLE_CTX_PARAMS   4
# define Otls_FUNC_SERIALIZER_SERIALIZE_DATA       10
# define Otls_FUNC_SERIALIZER_SERIALIZE_OBJECT     11
Otls_CORE_MAKE_FUNC(void *, OP_serializer_newctx, (void *provctx))
Otls_CORE_MAKE_FUNC(void, OP_serializer_freectx, (void *ctx))
Otls_CORE_MAKE_FUNC(int, OP_serializer_set_ctx_params,
                    (void *ctx, const Otls_PARAM params[]))
Otls_CORE_MAKE_FUNC(const Otls_PARAM *, OP_serializer_settable_ctx_params,
                    (void))

Otls_CORE_MAKE_FUNC(int, OP_serializer_serialize_data,
                    (void *ctx, const Otls_PARAM[], BIO *out,
                     Otls_PASSPHRASE_CALLBACK *cb, void *cbarg))
Otls_CORE_MAKE_FUNC(int, OP_serializer_serialize_object,
                    (void *ctx, void *obj, BIO *out,
                     Otls_PASSPHRASE_CALLBACK *cb, void *cbarg))

# ifdef __cplusplus
}
# endif

#endif
