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
#include <string.h>
#include <openssl/params.h>

/* Basic parameter type run-time construction */
#ifndef OSSL_PARAM_CONSTRUCT_INLINE
#define OSSL_PARAM_CONSTRUCT_INLINE static ossl_unused ossl_inline

#define OSSL_PARAM_construct_int ossl_param_construct_int
#define OSSL_PARAM_construct_uint ossl_param_construct_uint
#define OSSL_PARAM_construct_long ossl_param_construct_long
#define OSSL_PARAM_construct_ulong ossl_param_construct_ulong
#define OSSL_PARAM_construct_int32 ossl_param_construct_int32
#define OSSL_PARAM_construct_uint32 ossl_param_construct_uint32
#define OSSL_PARAM_construct_int64 ossl_param_construct_int64
#define OSSL_PARAM_construct_uint64 ossl_param_construct_uint64
#define OSSL_PARAM_construct_size_t ossl_param_construct_size_t
#define OSSL_PARAM_construct_time_t ossl_param_construct_time_t
#define OSSL_PARAM_construct_BN ossl_param_construct_BN
#define OSSL_PARAM_construct_double ossl_param_construct_double
#define OSSL_PARAM_construct_utf8_string ossl_param_construct_utf8_string
#define OSSL_PARAM_construct_octet_string ossl_param_construct_octet_string
#define OSSL_PARAM_construct_utf8_ptr ossl_param_construct_utf8_ptr
#define OSSL_PARAM_construct_octet_ptr ossl_param_construct_octet_ptr
#define OSSL_PARAM_construct_end ossl_param_construct_end
#endif

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf)
{
    OSSL_PARAM res = OSSL_PARAM_int(key, buf);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_uint(const char *key, unsigned int *buf)
{
    OSSL_PARAM res = OSSL_PARAM_uint(key, buf);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_long(const char *key, long int *buf)
{
    OSSL_PARAM res = OSSL_PARAM_long(key, buf);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_ulong(const char *key, unsigned long int *buf)
{
    OSSL_PARAM res = OSSL_PARAM_ulong(key, buf);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_int32(const char *key, int32_t *buf)
{
    OSSL_PARAM res = OSSL_PARAM_int32(key, buf);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_uint32(const char *key, uint32_t *buf)
{
    OSSL_PARAM res = OSSL_PARAM_uint32(key, buf);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_int64(const char *key, int64_t *buf)
{
    OSSL_PARAM res = OSSL_PARAM_int64(key, buf);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_uint64(const char *key, uint64_t *buf)
{
    OSSL_PARAM res = OSSL_PARAM_uint64(key, buf);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_size_t(const char *key, size_t *buf)
{
    OSSL_PARAM res = OSSL_PARAM_size_t(key, buf);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_time_t(const char *key, time_t *buf)
{
    OSSL_PARAM res = OSSL_PARAM_time_t(key, buf);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
    size_t bsize)
{
    OSSL_PARAM res = OSSL_PARAM_BN(key, buf, bsize);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_double(const char *key, double *buf)
{
    OSSL_PARAM res = OSSL_PARAM_double(key, buf);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
    size_t bsize)
{
    const size_t length = buf != NULL && bsize == 0 ? strlen(buf) : bsize;
    OSSL_PARAM res = OSSL_PARAM_utf8_string(key, buf, length);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf,
    size_t bsize)
{
    OSSL_PARAM res = OSSL_PARAM_octet_string(key, buf, bsize);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf,
    size_t bsize)
{
    OSSL_PARAM res = OSSL_PARAM_utf8_ptr(key, buf, bsize);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf,
    size_t bsize)
{
    OSSL_PARAM res = OSSL_PARAM_octet_ptr(key, buf, bsize);

    return res;
}

OSSL_PARAM_CONSTRUCT_INLINE OSSL_PARAM OSSL_PARAM_construct_end(void)
{
    OSSL_PARAM res = OSSL_PARAM_END;

    return res;
}

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

#endif /* !defined(OSSL_INTERNAL_PARAMS_H) */
