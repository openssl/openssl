/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_TRACE_H
# define OSSL_TRACE_H

# include <stdarg.h>

# include <openssl/bio.h>

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * OSSL_tracer_fn is the type of the function that the application defines.
 * It MUST return the number of bytes written, or 0 on error (in other words,
 * it can never write zero bytes).
 *
 * The data to write will always be text, and may be several lines.
 */
typedef size_t (*OSSL_tracer_fn)(const char *buf, size_t cnt, void *hookdata);

/*
 * The DEBUG and TRACE types or "channels" that the application can register
 * a hook for.  The DEFAULT type works as a single fallback.
 */
# define OSSL_DEBUG_DEFAULT             0 /* The fallback */
# define OSSL_DEBUG_INIT                1
# define OSSL_DEBUG_TLS                 2
# define OSSL_DEBUG_SSL                 OSSL_DEBUG_TLS
# define OSSL_DEBUG_TLS_CIPHER          3
# define OSSL_DEBUG_SSL_CIPHER          OSSL_DEBUG_TLS_CIPHER
# define OSSL_DEBUG_ENGINE_CONF         4
# define OSSL_DEBUG_ENGINE_TABLE        5
# define OSSL_DEBUG_ENGINE_REF_COUNT    6
# define OSSL_DEBUG_PKCS5V2             7
# define OSSL_DEBUG_PKCS12_KEYGEN       8
# define OSSL_DEBUG_X509V3_POLICY       9
# define OSSL_DEBUG_NUM                10

# define OSSL_TRACE_DEFAULT             0 /* The fallback */
# define OSSL_TRACE_NUM                 1

/* Functions to get a type number from its name */
int OSSL_trace_get_type(const char *name);
int OSSL_debug_get_type(const char *name);

/* Functions to associate a hook with a TRACE and DEBUG type / "channel" */
void OSSL_trace_set(int type, OSSL_tracer_fn fn, void *hookdata);
void OSSL_debug_set(int type, OSSL_tracer_fn fn, void *hookdata);

# ifndef OPENSSL_NO_TRACE

/*
 * Functions to check that a type / "channel" has a hook registered.
 * These are used within OpenSSL libraries to avoid unnecessary work.
 */
int OSSL_trace_is_set(int type);
int OSSL_debug_is_set(int type);

/*
 * Each type / "channel" is implemented as a BIO.  These functions are used to
 * get that BIO, which can then be used with any chose BIO output function.
 */
BIO *OSSL_trace_bio(int type);
BIO *OSSL_debug_bio(int type);

# else
#  define OSSL_trace_is_set(type)       0
#  define OSSL_debug_is_set(type)       0
#  define OSSL_trace_bio(type)          NULL
#  define OSSL_debug_bio(type)          NULL
# endif

/*
 * Convenience functions that are shortcuts for
 * BIO_printf(BIO_trace_bio(type), fmt, ...),
 * BIO_vprintf(BIO_trace_bio(type), fmt, args),
 * BIO_printf(BIO_debug_bio(type), fmt, ...),
 * BIO_vprintf(BIO_debug_bio(type), fmt, args),
 */
int OSSL_trace(int type, char *fmt, ...);
int OSSL_vtrace(int type, char *fmt, va_list args);
int OSSL_debug(int type, char *fmt, ...);
int OSSL_vdebug(int type, char *fmt, va_list args);

#endif
