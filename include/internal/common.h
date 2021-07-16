/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_COMMON_H
# define OSSL_INTERNAL_COMMON_H
# pragma once

# include <stdlib.h>
# include <string.h>
# include "../../e_os.h" /* To get strncasecmp() on Windows */

# include "internal/nelem.h"

#ifdef NDEBUG
# define ossl_assert(x) ((x) != 0)
#else
__owur static ossl_inline int ossl_assert_int(int expr, const char *exprstr,
                                              const char *file, int line)
{
    if (!expr)
        OPENSSL_die(exprstr, file, line);

    return expr;
}

# define ossl_assert(x) ossl_assert_int((x) != 0, "Assertion failed: "#x, \
                                         __FILE__, __LINE__)

#endif

/* Check if |pre|, which must be a string literal, is a prefix of |str| */
#define HAS_PREFIX(str, pre) (strncmp(str, pre "", sizeof(pre) - 1) == 0)
/* As before, and if check succeeds, advance |str| past the prefix |pre| */
#define CHECK_AND_SKIP_PREFIX(str, pre) \
    (HAS_PREFIX(str, pre) ? ((str) += sizeof(pre) - 1, 1) : 0)
/* Check if the string literal |p| is a case-insensitive prefix of |s| */
#define HAS_CASE_PREFIX(s, p) (strncasecmp(s, p "", sizeof(p) - 1) == 0)
/* As before, and if check succeeds, advance |str| past the prefix |pre| */
#define CHECK_AND_SKIP_CASE_PREFIX(str, pre) \
    (HAS_CASE_PREFIX(str, pre) ? ((str) += sizeof(pre) - 1, 1) : 0)
/* Check if the string literal |suffix| is a case-insensitive suffix of |str| */
#define HAS_CASE_SUFFIX(str, suffix) (strlen(str) < sizeof(suffix) - 1 ? 0 : \
    strcasecmp(str + strlen(str) - sizeof(suffix) + 1, suffix "") == 0)

/*
 * Use this inside a union with the field that needs to be aligned to a
 * reasonable boundary for the platform.  The most pessimistic alignment
 * of the listed types will be used by the compiler.
 */
# define OSSL_UNION_ALIGN       \
    double align;               \
    ossl_uintmax_t align_int;   \
    void *align_ptr

# define OPENSSL_CONF             "openssl.cnf"

# ifndef OPENSSL_SYS_VMS
#  define X509_CERT_AREA          OPENSSLDIR
#  define X509_CERT_DIR           OPENSSLDIR "/certs"
#  define X509_CERT_FILE          OPENSSLDIR "/cert.pem"
#  define X509_PRIVATE_DIR        OPENSSLDIR "/private"
#  define CTLOG_FILE              OPENSSLDIR "/ct_log_list.cnf"
# else
#  define X509_CERT_AREA          "OSSL$DATAROOT:[000000]"
#  define X509_CERT_DIR           "OSSL$DATAROOT:[CERTS]"
#  define X509_CERT_FILE          "OSSL$DATAROOT:[000000]cert.pem"
#  define X509_PRIVATE_DIR        "OSSL$DATAROOT:[PRIVATE]"
#  define CTLOG_FILE              "OSSL$DATAROOT:[000000]ct_log_list.cnf"
# endif

# define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
# define X509_CERT_FILE_EVP       "SSL_CERT_FILE"
# define CTLOG_FILE_EVP           "CTLOG_FILE"

/* size of string representations */
# define DECIMAL_SIZE(type)      ((sizeof(type)*8+2)/3+1)
# define HEX_SIZE(type)          (sizeof(type)*2)

static ossl_inline int ossl_ends_with_dirsep(const char *path)
{
    if (*path != '\0')
        path += strlen(path) - 1;
# if defined __VMS
    if (*path == ']' || *path == '>' || *path == ':')
        return 1;
# elif defined _WIN32
    if (*path == '\\')
        return 1;
# endif
    return *path == '/';
}

static ossl_inline int ossl_is_absolute_path(const char *path)
{
# if defined __VMS
    if (strchr(path, ':') != NULL
        || ((path[0] == '[' || path[0] == '<')
            && path[1] != '.' && path[1] != '-'
            && path[1] != ']' && path[1] != '>'))
        return 1;
# elif defined _WIN32
    if (path[0] == '\\'
        || (path[0] != '\0' && path[1] == ':'))
        return 1;
# endif
    return path[0] == '/';
}

#endif
