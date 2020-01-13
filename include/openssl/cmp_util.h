/*
 * Copyright 2007-2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_CMP_UTIL_H
# define OPENtls_CMP_UTIL_H

# include <opentls/opentlsconf.h>
# ifndef OPENtls_NO_CMP

#  include <opentls/macros.h>
#  include <opentls/trace.h>
#  include <opentls/x509.h>

#  ifdef  __cplusplus
extern "C" {
#  endif

/*
 * convenience functions for CMP-specific logging via the trace API
 */
int  Otls_CMP_log_open(void);
void Otls_CMP_log_close(void);
#  define Otls_CMP_LOG_PREFIX "CMP "
/* in Otls_CMP_LOG_START, cannot use OPENtls_FUNC when expands to __func__ */
#  define Otls_CMP_LOG_START "%s:" OPENtls_FILE ":" \
    OPENtls_MSTR(OPENtls_LINE) ":" Otls_CMP_LOG_PREFIX
#  define Otls_CMP_alert(msg) Otls_CMP_log(ALERT, msg)
#  define Otls_CMP_err(msg)   Otls_CMP_log(ERROR, msg)
#  define Otls_CMP_warn(msg)  Otls_CMP_log(WARN, msg)
#  define Otls_CMP_info(msg)  Otls_CMP_log(INFO, msg)
#  define Otls_CMP_debug(msg) Otls_CMP_log(DEBUG, msg)
#  define Otls_CMP_log(level, msg) \
    Otls_TRACEV(CMP, (trc_out, Otls_CMP_LOG_START#level ": %s\n", \
                      OPENtls_FUNC, msg))
#  define Otls_CMP_log1(level, fmt, arg1) \
    Otls_TRACEV(CMP, (trc_out, Otls_CMP_LOG_START#level ": " fmt "\n", \
                      OPENtls_FUNC, arg1))
#  define Otls_CMP_log2(level, fmt, arg1, arg2) \
    Otls_TRACEV(CMP, (trc_out, Otls_CMP_LOG_START#level ": " fmt "\n", \
                      OPENtls_FUNC, arg1, arg2))
#  define Otls_CMP_log3(level, fmt, arg1, arg2, arg3) \
    Otls_TRACEV(CMP, (trc_out, Otls_CMP_LOG_START#level ": " fmt "\n", \
                      OPENtls_FUNC, arg1, arg2, arg3))
#  define Otls_CMP_log4(level, fmt, arg1, arg2, arg3, arg4) \
    Otls_TRACEV(CMP, (trc_out, Otls_CMP_LOG_START#level ": " fmt "\n", \
                      OPENtls_FUNC, arg1, arg2, arg3, arg4))

/*
 * generalized logging/error callback mirroring the severity levels of syslog.h
 */
typedef int Otls_CMP_severity;
#  define Otls_CMP_LOG_EMERG   0
#  define Otls_CMP_LOG_ALERT   1
#  define Otls_CMP_LOG_CRIT    2
#  define Otls_CMP_LOG_ERR     3
#  define Otls_CMP_LOG_WARNING 4
#  define Otls_CMP_LOG_NOTICE  5
#  define Otls_CMP_LOG_INFO    6
#  define Otls_CMP_LOG_DEBUG   7
typedef int (*Otls_cmp_log_cb_t)(const char *func, const char *file, int line,
                                 Otls_CMP_severity level, const char *msg);

/* use of the logging callback for outputting error queue */
void Otls_CMP_print_errors_cb(Otls_cmp_log_cb_t log_fn);

#  ifdef  __cplusplus
}
#  endif
# endif /* !defined OPENtls_NO_CMP */
#endif /* !defined OPENtls_CMP_UTIL_H */
