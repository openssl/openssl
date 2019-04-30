/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CORE_NUMBERS_H
# define OSSL_CORE_NUMBERS_H

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

/* Helper macro to create the function signature typedef and the extractor */
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
# define OSSL_FUNC_CORE_GET_PARAM_TYPES        1
OSSL_CORE_MAKE_FUNC(const OSSL_ITEM *,
                    core_get_param_types,(const OSSL_PROVIDER *prov))
# define OSSL_FUNC_CORE_GET_PARAMS             2
OSSL_CORE_MAKE_FUNC(int,core_get_params,(const OSSL_PROVIDER *prov,
                                         const OSSL_PARAM params[]))

/* Functions provided by the provider to the Core, reserved numbers 1024-1535 */
# define OSSL_FUNC_PROVIDER_TEARDOWN         1024
OSSL_CORE_MAKE_FUNC(void,provider_teardown,(void *provctx))
# define OSSL_FUNC_PROVIDER_GET_PARAM_TYPES  1025
OSSL_CORE_MAKE_FUNC(const OSSL_ITEM *,
                    provider_get_param_types,(void *provctx))
# define OSSL_FUNC_PROVIDER_GET_PARAMS       1026
OSSL_CORE_MAKE_FUNC(int,provider_get_params,(void *provctx,
                                             const OSSL_PARAM params[]))
# define OSSL_FUNC_PROVIDER_QUERY_OPERATION  1027
OSSL_CORE_MAKE_FUNC(const OSSL_ALGORITHM *,provider_query_operation,
                    (void *provctx, int operation_id, const int *no_store))

/* Digests */

# define OSSL_OP_DIGEST                     1

# define OSSL_FUNC_DIGEST_NEWCTX            1
# define OSSL_FUNC_DIGEST_INIT              2
# define OSSL_FUNC_DIGEST_UPDATE            3
# define OSSL_FUNC_DIGEST_FINAL             4
# define OSSL_FUNC_DIGEST_DIGEST            5
# define OSSL_FUNC_DIGEST_FREECTX           6
# define OSSL_FUNC_DIGEST_DUPCTX            7
# define OSSL_FUNC_DIGEST_SIZE              8
# define OSSL_FUNC_DIGEST_BLOCK_SIZE        9


OSSL_CORE_MAKE_FUNC(void *, OP_digest_newctx, (void *provctx))
OSSL_CORE_MAKE_FUNC(int, OP_digest_init, (void *dctx))
OSSL_CORE_MAKE_FUNC(int, OP_digest_update,
                    (void *dctx, const unsigned char *in, size_t inl))
OSSL_CORE_MAKE_FUNC(int, OP_digest_final,
                    (void *dctx,
                     unsigned char *out, size_t *outl, size_t outsz))
OSSL_CORE_MAKE_FUNC(int, OP_digest_digest,
                    (void *provctx, const unsigned char *in, size_t inl,
                     unsigned char *out, size_t *out_l, size_t outsz))

OSSL_CORE_MAKE_FUNC(void, OP_digest_cleanctx, (void *dctx))
OSSL_CORE_MAKE_FUNC(void, OP_digest_freectx, (void *dctx))
OSSL_CORE_MAKE_FUNC(void *, OP_digest_dupctx, (void *dctx))
OSSL_CORE_MAKE_FUNC(size_t, OP_digest_size, (void))
OSSL_CORE_MAKE_FUNC(size_t, OP_digest_block_size, (void))


/* Symmetric Ciphers */

# define OSSL_OP_CIPHER                              2

# define OSSL_FUNC_CIPHER_NEWCTX                     1
# define OSSL_FUNC_CIPHER_ENCRYPT_INIT               2
# define OSSL_FUNC_CIPHER_DECRYPT_INIT               3
# define OSSL_FUNC_CIPHER_UPDATE                     4
# define OSSL_FUNC_CIPHER_FINAL                      5
# define OSSL_FUNC_CIPHER_CIPHER                     6
# define OSSL_FUNC_CIPHER_FREECTX                    7
# define OSSL_FUNC_CIPHER_DUPCTX                     8
# define OSSL_FUNC_CIPHER_KEY_LENGTH                 9
# define OSSL_FUNC_CIPHER_IV_LENGTH                 10
# define OSSL_FUNC_CIPHER_BLOCK_SIZE                11
# define OSSL_FUNC_CIPHER_GET_PARAMS                12
# define OSSL_FUNC_CIPHER_CTX_GET_PARAMS            13
# define OSSL_FUNC_CIPHER_CTX_SET_PARAMS            14

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
OSSL_CORE_MAKE_FUNC(size_t, OP_cipher_key_length, (void))
OSSL_CORE_MAKE_FUNC(size_t, OP_cipher_iv_length, (void))
OSSL_CORE_MAKE_FUNC(size_t, OP_cipher_block_size, (void))
OSSL_CORE_MAKE_FUNC(int, OP_cipher_get_params, (const OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(int, OP_cipher_ctx_get_params, (void *cctx,
                                                    const OSSL_PARAM params[]))
OSSL_CORE_MAKE_FUNC(int, OP_cipher_ctx_set_params, (void *cctx,
                                                    const OSSL_PARAM params[]))


# ifdef __cplusplus
}
# endif

#endif
