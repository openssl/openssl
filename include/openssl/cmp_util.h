/*
 * Copyright 2007-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CMP_UTIL_H
#define OPENSSL_CMP_UTIL_H
#pragma once

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_CMP

#include <openssl/macros.h>
#include <openssl/trace.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The CMP and CRMF API in libcrypto is deprecated in favor of the same
 * API provided by libcmp.  The libcmp headers provide the declarations
 * below without deprecation, under libcmp's own symbol names.
 */
#if defined(OSSL_LIBCMP_NAMES)
#define OSSL_LIBCMP_DEPRECATEDIN_4_1
#else
#define OSSL_LIBCMP_DEPRECATEDIN_4_1 OSSL_DEPRECATEDIN_4_1
#endif /* defined(OSSL_LIBCMP_NAMES) */

#if !defined(OPENSSL_NO_DEPRECATED_4_1) || defined(OSSL_LIBCMP_NAMES)

OSSL_LIBCMP_DEPRECATEDIN_4_1
int OSSL_CMP_log_open(void);
OSSL_LIBCMP_DEPRECATEDIN_4_1
void OSSL_CMP_log_close(void);
#define OSSL_CMP_LOG_PREFIX "CMP "

/*
 * generalized logging/error callback mirroring the severity levels of syslog.h
 */
typedef int OSSL_CMP_severity;
#define OSSL_CMP_LOG_EMERG 0
#define OSSL_CMP_LOG_ALERT 1
#define OSSL_CMP_LOG_CRIT 2
#define OSSL_CMP_LOG_ERR 3
#define OSSL_CMP_LOG_WARNING 4
#define OSSL_CMP_LOG_NOTICE 5
#define OSSL_CMP_LOG_INFO 6
#define OSSL_CMP_LOG_DEBUG 7
#define OSSL_CMP_LOG_TRACE 8
#define OSSL_CMP_LOG_MAX OSSL_CMP_LOG_TRACE
typedef int (*OSSL_CMP_log_cb_t)(const char *func, const char *file, int line,
    OSSL_CMP_severity level, const char *msg);

OSSL_LIBCMP_DEPRECATEDIN_4_1
int OSSL_CMP_print_to_bio(BIO *bio, const char *component, const char *file,
    int line, OSSL_CMP_severity level, const char *msg);
/* use of the logging callback for outputting error queue */
OSSL_LIBCMP_DEPRECATEDIN_4_1
void OSSL_CMP_print_errors_cb(OSSL_CMP_log_cb_t log_fn);

#endif /* !defined(OPENSSL_NO_DEPRECATED_4_1) || defined(OSSL_LIBCMP_NAMES) */

#ifdef __cplusplus
}
#endif
#endif /* !defined(OPENSSL_NO_CMP) */
#endif /* !defined(OPENSSL_CMP_UTIL_H) */
