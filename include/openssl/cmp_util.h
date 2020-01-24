/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CMP_UTIL_H
# define OPENSSL_CMP_UTIL_H

# include <openssl/opensslconf.h>
# ifndef OPENSSL_NO_CMP

#  include <openssl/macros.h>
#  include <openssl/trace.h>
#  include <openssl/x509.h>

#  ifdef  __cplusplus
extern "C" {
#  endif

/*
 * convenience functions for CMP-specific logging via the trace API
 */
int  OSSL_CMP_log_open(void);
void OSSL_CMP_log_close(void);
#  define OSSL_CMP_LOG_PREFIX "CMP "
/* in OSSL_CMP_LOG_START, cannot use OPENSSL_FUNC when expands to __func__ */
#  define OSSL_CMP_LOG_START "%s:" OPENSSL_FILE ":" \
    OPENSSL_MSTR(OPENSSL_LINE) ":" OSSL_CMP_LOG_PREFIX
#  define OSSL_CMP_alert(msg) OSSL_CMP_log(ALERT, msg)
#  define OSSL_CMP_err(msg)   OSSL_CMP_log(ERROR, msg)
#  define OSSL_CMP_warn(msg)  OSSL_CMP_log(WARN, msg)
#  define OSSL_CMP_info(msg)  OSSL_CMP_log(INFO, msg)
#  define OSSL_CMP_debug(msg) OSSL_CMP_log(DEBUG, msg)
#  define OSSL_CMP_log(level, msg) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": %s\n", \
                      OPENSSL_FUNC, msg))
#  define OSSL_CMP_log1(level, fmt, arg1) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", \
                      OPENSSL_FUNC, arg1))
#  define OSSL_CMP_log2(level, fmt, arg1, arg2) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", \
                      OPENSSL_FUNC, arg1, arg2))
#  define OSSL_CMP_log3(level, fmt, arg1, arg2, arg3) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", \
                      OPENSSL_FUNC, arg1, arg2, arg3))
#  define OSSL_CMP_log4(level, fmt, arg1, arg2, arg3, arg4) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", \
                      OPENSSL_FUNC, arg1, arg2, arg3, arg4))

/*
 * generalized logging/error callback mirroring the severity levels of syslog.h
 */
typedef int OSSL_CMP_severity;
#  define OSSL_CMP_LOG_EMERG   0
#  define OSSL_CMP_LOG_ALERT   1
#  define OSSL_CMP_LOG_CRIT    2
#  define OSSL_CMP_LOG_ERR     3
#  define OSSL_CMP_LOG_WARNING 4
#  define OSSL_CMP_LOG_NOTICE  5
#  define OSSL_CMP_LOG_INFO    6
#  define OSSL_CMP_LOG_DEBUG   7
typedef int (*OSSL_cmp_log_cb_t)(const char *func, const char *file, int line,
                                 OSSL_CMP_severity level, const char *msg);

/* use of the logging callback for outputting error queue */
void OSSL_CMP_print_errors_cb(OSSL_cmp_log_cb_t log_fn);

#  ifdef  __cplusplus
}
#  endif
# endif /* !defined OPENSSL_NO_CMP */
#endif /* !defined OPENSSL_CMP_UTIL_H */
