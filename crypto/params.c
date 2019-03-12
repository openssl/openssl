/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/bn.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/cryptoerr.h>

OSSL_PARAM *OSSL_PARAM_locate(OSSL_PARAM *p, const char *key)
{
    for (; p->key != NULL; p++)
        if (strcmp(key, p->key) == 0)
            return (OSSL_PARAM *)p;
    return NULL;
}

static size_t get_width(int type)
{
    switch (type) {
    case OSSL_PARAM_INT:        return sizeof(int);
    case OSSL_PARAM_UINT:       return sizeof(unsigned int);
    case OSSL_PARAM_INT64:      return sizeof(int64_t);
    case OSSL_PARAM_UINT64:     return sizeof(uint64_t);
    case OSSL_PARAM_LONG:       return sizeof(long);
    case OSSL_PARAM_ULONG:      return sizeof(unsigned long);
    case OSSL_PARAM_SIZET:      return sizeof(size_t);
    case OSSL_PARAM_DOUBLE:     return sizeof(double);
    case OSSL_PARAM_POINTER:    return sizeof(void *);
    }
    return -1;
}

static int set_fixed(OSSL_PARAM *p, const char *key,
                     void *val, unsigned long type)
{
    size_t width;

    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_SET_FIXED, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }

    /* Type safety. */
    width = get_width(type);
    if (p->data_type != type || p->size != width) {
        CRYPTOerr(CRYPTO_F_SET_FIXED, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    p->buffer = val;
    return 1;
}

static int reserve_fixed(OSSL_PARAM *p, const char *key,
                         void *val, unsigned long type)
{
    size_t width;

    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_RESERVE_FIXED, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }

    /* Type safety. */
    width = get_width(type);
    if (p->data_type != type) {
        CRYPTOerr(CRYPTO_F_RESERVE_FIXED, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    p->buffer = val;
    p->size = width;
    return 1;
}

static int reserve_ptrsize(OSSL_PARAM *p, const char *key,
                           void *buffer, size_t bufsize)
{
    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_RESERVE_PTRSIZE, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }

    /* Type safety. */
    if (p->data_type != OSSL_PARAM_BIGNUM) {
        CRYPTOerr(CRYPTO_F_RESERVE_PTRSIZE, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    p->buffer = buffer;
    p->size = bufsize;
    return 1;
}

static int get_fixed(OSSL_PARAM *p, const char *key,
                     void *val, unsigned long type)
{
    size_t width;

    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_GET_FIXED, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }

    /* Type safety. */
    width = get_width(type);
    if (p->data_type != type || p->size != width) {
        CRYPTOerr(CRYPTO_F_GET_FIXED, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    switch (type) {
    case OSSL_PARAM_INT:
        *(int *)val = *(int *)p->buffer;
        break;
    case OSSL_PARAM_UINT:
        *(unsigned int *)val = *(unsigned int *)p->buffer;
        break;
    case OSSL_PARAM_INT64:
        *(int64_t *)val = *(int64_t *)p->buffer;
        break;
    case OSSL_PARAM_UINT64:
        *(uint64_t *)val = *(uint64_t *)p->buffer;
        break;
    case OSSL_PARAM_LONG:
        *(long *)val = *(long *)p->buffer;
        break;
    case OSSL_PARAM_ULONG:
        *(unsigned long *)val = *(unsigned long *)p->buffer;
        break;
    case OSSL_PARAM_SIZET:
        *(size_t *)val = *(size_t *)p->buffer;
        break;
    case OSSL_PARAM_DOUBLE:
        *(double *)val = *(double *)p->buffer;
        break;
    case OSSL_PARAM_POINTER:
        memcpy(val, p->buffer, width);
        break;
    default:
        CRYPTOerr(CRYPTO_F_GET_FIXED, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    return 1;
}

static int return_fixed(OSSL_PARAM *p, const char *key,
                         void *val, unsigned long type)
{
    size_t width;

    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_RETURN_FIXED, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }

    /* Type safety. */
    width = get_width(type);
    if (p->data_type != type || p->size != width) {
        CRYPTOerr(CRYPTO_F_RETURN_FIXED, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    switch (type) {
    case OSSL_PARAM_INT:
        *(int *)p->buffer = *(int *)val;
        break;
    case OSSL_PARAM_UINT:
        *(unsigned int *)p->buffer = *(unsigned int *)val;
        break;
    case OSSL_PARAM_INT64:
        *(int64_t *)p->buffer = *(int64_t *)val;
        break;
    case OSSL_PARAM_UINT64:
        *(uint64_t *)p->buffer = *(uint64_t *)val;
        break;
    case OSSL_PARAM_LONG:
        *(long *)p->buffer = *(long *)val;
        break;
    case OSSL_PARAM_ULONG:
        *(unsigned long *)p->buffer = *(unsigned long *)val;
        break;
    case OSSL_PARAM_SIZET:
        *(size_t *)p->buffer = *(size_t *)val;
        break;
    case OSSL_PARAM_DOUBLE:
        *(double *)p->buffer = *(double *)val;
        break;
    case OSSL_PARAM_POINTER:
        memcpy(p->buffer, val, width);
        break;
    default:
        CRYPTOerr(CRYPTO_F_RETURN_FIXED, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    return 1;
}

#define PARAM_FIXED(name, type, PARAM) \
    int OSSL_PARAM_set_##name(OSSL_PARAM *p, const char *key, type *val) \
    { \
        return set_fixed(p, key, val, PARAM); \
    } \
    int OSSL_PARAM_reserve_##name(OSSL_PARAM *p, const char *key, type *val) \
    { \
        return reserve_fixed(p, key, val, PARAM); \
    } \
    int OSSL_PARAM_get_##name(OSSL_PARAM *p, const char *key, type *val) \
    { \
        return get_fixed(p, key, val, PARAM); \
    } \
    int OSSL_PARAM_return_##name(OSSL_PARAM *p, const char *key, type val) \
    { \
        return return_fixed(p, key, &val, PARAM); \
    }

PARAM_FIXED(int, int, OSSL_PARAM_INT)
PARAM_FIXED(uint, unsigned int, OSSL_PARAM_UINT)
PARAM_FIXED(int64, int64_t, OSSL_PARAM_INT64)
PARAM_FIXED(uint64, uint64_t, OSSL_PARAM_UINT64)
PARAM_FIXED(long, long int, OSSL_PARAM_LONG)
PARAM_FIXED(ulong, unsigned long, OSSL_PARAM_ULONG)
PARAM_FIXED(size_t, size_t, OSSL_PARAM_SIZET)
PARAM_FIXED(double, double, OSSL_PARAM_DOUBLE)
PARAM_FIXED(pointer, void*, OSSL_PARAM_POINTER)

int OSSL_PARAM_set_bignum(OSSL_PARAM *p, const char *key, BIGNUM **val)
{
    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_SET_BIGNUM, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }

    if (p->data_type != OSSL_PARAM_BIGNUM) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_SET_BIGNUM, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    p->buffer = *val;
    return 1;
}

int OSSL_PARAM_reserve_bignum(OSSL_PARAM *p, const char *key,
                              void *buffer, size_t bufsize)
{
    return reserve_ptrsize(p, key, buffer, bufsize);
}

int OSSL_PARAM_get_bignum(OSSL_PARAM *p, const char *key, BIGNUM **val)
{
    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_GET_BIGNUM, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }

    /* Type safety. */
    if (p->data_type != OSSL_PARAM_BIGNUM) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_GET_BIGNUM, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    *val = *(BIGNUM **)p->buffer;
    return 1;
}

int OSSL_PARAM_return_bignum(OSSL_PARAM *p, const char *key, BIGNUM *val)
{
    size_t bytes = (size_t)BN_num_bytes(val);
    int r;

    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_RETURN_BIGNUM, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }

    /* Type safety. */
    if (p->data_type != OSSL_PARAM_BIGNUM
            || BN_is_negative(val)) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_RETURN_BIGNUM, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    /* Guess/assume how much space we need. */
    p->used = bytes;
    if (p->size < bytes
            || (r = BN_bn2nativepad(val, p->buffer, bytes)) < 0) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_RETURN_BIGNUM, CRYPTO_R_NO_ROOM);
        return 0;
    }

    p->used = r;
    return 1;
}

int OSSL_PARAM_retrieve_bignum(OSSL_PARAM *p, const char *key, BIGNUM **val)
{
    BIGNUM *b = NULL;

    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_RETRIEVE_BIGNUM, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }

    b = BN_native2bn(p->buffer, (int)p->used, NULL);
    if (b == NULL)
        /* BN conversion should have set the error code. */
        return 0;

    *val = b;
    return 1;
}

int OSSL_PARAM_set_buffer(OSSL_PARAM *p, const char *key,
                          void *buffer, size_t buffsize)
{
    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_SET_BUFFER, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }

    p->buffer = buffer;
    p->size = buffsize;
    return 1;
}

int OSSL_PARAM_reserve_buffer(OSSL_PARAM *p, const char *key,
                              void *buffer, size_t bufsize)
{
    return reserve_ptrsize(p, key, buffer, bufsize);
}

int OSSL_PARAM_get_buffer(OSSL_PARAM *p, const char *key,
                          void **buffer, size_t *buffsize)
{
    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_GET_BUFFER, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }
    *buffer = p->buffer;
    *buffsize = p->size;
    return 1;
}

int OSSL_PARAM_return_buffer(OSSL_PARAM *p, const char *key,
                             void *buffer, size_t bufsize)
{
    if (key != NULL && (p = OSSL_PARAM_locate(p, key)) == NULL) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_RETURN_BUFFER, CRYPTO_R_PARAM_NOT_FOUND);
        ERR_add_error_data(2, "param name=", key);
        return 0;
    }
    return 1;
}
