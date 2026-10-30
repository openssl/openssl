/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_INTERNAL_PARAMS_H)
#define OSSL_INTERNAL_PARAMS_H

#include <stddef.h>
#include <openssl/params.h>

/*
 * Extract the parameter into an allocated buffer.
 * Any existing allocation in *out is cleared and freed.
 *
 * Returns 1 on success, 0 on failure and -1  if there are no matching params.
 *
 * *out and *out_len are guaranteed to be untouched if this function
 * doesn't return success.
 */
int ossl_param_get1_octet_string_from_param(const OSSL_PARAM *p,
    unsigned char **out,
    size_t *out_len);
int ossl_param_get1_octet_string(const OSSL_PARAM *params, const char *name,
    unsigned char **out, size_t *out_len);

/*
 * Concatenate all of the matching params together.
 * *out will point to an allocated buffer on successful return.
 * Any existing allocation in *out is cleared and freed.
 *
 * Passing 0 for maxsize means unlimited size output.
 *
 * Returns 1 on success and 0 on failure.
 *
 * *out and *out_len are guaranteed to be untouched if this function
 * doesn't return success.
 */
int ossl_param_get1_concat_octet_string(size_t n, OSSL_PARAM *params[],
    unsigned char **out, size_t *out_len);

#define INIT_OSSL_PARAM_HASHED(param, keyname, hash, ptr, size, type) \
    do {                                                              \
        OSSL_PARAM *p___ = (param);                                   \
        p___->key = keyname;                                          \
        p___->keyhash = hash;                                         \
        p___->data_type = type;                                       \
        p___->data = ptr;                                             \
        p___->data_size = size;                                       \
        p___->return_size = OSSL_PARAM_UNMODIFIED;                    \
    } while (0)

#define OSSL_PARAM_fast_octet_string(param, keyname, hash, str, size) \
    INIT_OSSL_PARAM_HASHED(param, keyname, hash, str, size, OSSL_PARAM_OCTET_STRING);

#define OSSL_PARAM_fast_octet_ptr(param, keyname, hash, ptr, size) \
    INIT_OSSL_PARAM_HASHED(param, keyname, hash, ptr, size, OSSL_PARAM_OCTET_PTR)

#define OSSL_PARAM_fast_int(param, keyname, hash, intptr) \
    INIT_OSSL_PARAM_HASHED(param, keyname, hash, intptr, sizeof(int), OSSL_PARAM_INTEGER)

#define OSSL_PARAM_fast_size_t(param, keyname, hash, sizetptr) \
    INIT_OSSL_PARAM_HASHED(param, keyname, hash, sizetptr, sizeof(size_t), OSSL_PARAM_UNSIGNED_INTEGER);

#define OSSL_PARAM_fast_utf8_string(param, keyname, hash, str, size) \
    INIT_OSSL_PARAM_HASHED(param, keyname, hash, str, size, OSSL_PARAM_UTF8_STRING)

#define OSSL_PARAM_fast_end(param) \
    INIT_OSSL_PARAM_HASHED(param, NULL, 0, NULL, 0, 0)

#define OSSL_PARAM_fast_uint(param, keyname, hash, intptr) \
    INIT_OSSL_PARAM_HASHED(param, keyname, hash, intptr, sizeof(unsigned int), OSSL_PARAM_UNSIGNED_INTEGER)

#endif /* !defined(OSSL_INTERNAL_PARAMS_H) */
