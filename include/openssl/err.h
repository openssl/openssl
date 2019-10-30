/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_ERR_H
# define OPENSSL_ERR_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_ERR_H
# endif

# include <openssl/e_os2.h>

# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
#  include <stdlib.h>
# endif

# include <openssl/types.h>
# include <openssl/bio.h>
# include <openssl/lhash.h>

#ifdef  __cplusplus
extern "C" {
#endif

# ifndef OPENSSL_NO_DEPRECATED_3_0
#  ifndef OPENSSL_NO_FILENAMES
#   define ERR_PUT_error(l,f,r,fn,ln)      ERR_put_error(l,f,r,fn,ln)
#  else
#   define ERR_PUT_error(l,f,r,fn,ln)      ERR_put_error(l,f,r,NULL,0)
#  endif
# endif

# include <errno.h>

# define ERR_TXT_MALLOCED        0x01
# define ERR_TXT_STRING          0x02

# if !defined(OPENSSL_NO_DEPRECATED_3_0) || defined(OSSL_FORCE_ERR_STATE)
#  define ERR_FLAG_MARK           0x01
#  define ERR_FLAG_CLEAR          0x02

#  define ERR_NUM_ERRORS  16
struct err_state_st {
    int err_flags[ERR_NUM_ERRORS];
    unsigned long err_buffer[ERR_NUM_ERRORS];
    char *err_data[ERR_NUM_ERRORS];
    size_t err_data_size[ERR_NUM_ERRORS];
    int err_data_flags[ERR_NUM_ERRORS];
    const char *err_file[ERR_NUM_ERRORS];
    int err_line[ERR_NUM_ERRORS];
    const char *err_func[ERR_NUM_ERRORS];
    int top, bottom;
};
# endif

/* library */
# define ERR_LIB_NONE            1
# define ERR_LIB_SYS             2
# define ERR_LIB_BN              3
# define ERR_LIB_RSA             4
# define ERR_LIB_DH              5
# define ERR_LIB_EVP             6
# define ERR_LIB_BUF             7
# define ERR_LIB_OBJ             8
# define ERR_LIB_PEM             9
# define ERR_LIB_DSA             10
# define ERR_LIB_X509            11
/* #define ERR_LIB_METH         12 */
# define ERR_LIB_ASN1            13
# define ERR_LIB_CONF            14
# define ERR_LIB_CRYPTO          15
# define ERR_LIB_EC              16
# define ERR_LIB_SSL             20
/* #define ERR_LIB_SSL23        21 */
/* #define ERR_LIB_SSL2         22 */
/* #define ERR_LIB_SSL3         23 */
/* #define ERR_LIB_RSAREF       30 */
/* #define ERR_LIB_PROXY        31 */
# define ERR_LIB_BIO             32
# define ERR_LIB_PKCS7           33
# define ERR_LIB_X509V3          34
# define ERR_LIB_PKCS12          35
# define ERR_LIB_RAND            36
# define ERR_LIB_DSO             37
# define ERR_LIB_ENGINE          38
# define ERR_LIB_OCSP            39
# define ERR_LIB_UI              40
# define ERR_LIB_COMP            41
# define ERR_LIB_ECDSA           42
# define ERR_LIB_ECDH            43
# define ERR_LIB_OSSL_STORE      44
# define ERR_LIB_FIPS            45
# define ERR_LIB_CMS             46
# define ERR_LIB_TS              47
# define ERR_LIB_HMAC            48
/* # define ERR_LIB_JPAKE       49 */
# define ERR_LIB_CT              50
# define ERR_LIB_ASYNC           51
# define ERR_LIB_KDF             52
# define ERR_LIB_SM2             53
# define ERR_LIB_ESS             54
# define ERR_LIB_PROP            55
# define ERR_LIB_CRMF            56
# define ERR_LIB_PROV            57
# define ERR_LIB_CMP             58
# define ERR_LIB_OSSL_SERIALIZER 59
# define ERR_LIB_HTTP            60

# define ERR_LIB_USER            128

# if 1 || !defined(OPENSSL_NO_DEPRECATED_3_0)
#  define ASN1err(f, r) ERR_raise_data(ERR_LIB_ASN1, (r), NULL)
#  define ASYNCerr(f, r) ERR_raise_data(ERR_LIB_ASYNC, (r), NULL)
#  define BIOerr(f, r) ERR_raise_data(ERR_LIB_BIO, (r), NULL)
#  define BNerr(f, r)  ERR_raise_data(ERR_LIB_BN, (r), NULL)
#  define BUFerr(f, r) ERR_raise_data(ERR_LIB_BUF, (r), NULL)
#  define CMPerr(f, r) ERR_raise_data(ERR_LIB_CMP, (r), NULL)
#  define CMSerr(f, r) ERR_raise_data(ERR_LIB_CMS, (r), NULL)
#  define COMPerr(f, r) ERR_raise_data(ERR_LIB_COMP, (r), NULL)
#  define CONFerr(f, r) ERR_raise_data(ERR_LIB_CONF, (r), NULL)
#  define CRMFerr(f, r) ERR_raise_data(ERR_LIB_CRMF, (r), NULL)
#  define CRYPTOerr(f, r) ERR_raise_data(ERR_LIB_CRYPTO, (r), NULL)
#  define CTerr(f, r) ERR_raise_data(ERR_LIB_CT, (r), NULL)
#  define DHerr(f, r)  ERR_raise_data(ERR_LIB_DH, (r), NULL)
#  define DSAerr(f, r) ERR_raise_data(ERR_LIB_DSA, (r), NULL)
#  define DSOerr(f, r) ERR_raise_data(ERR_LIB_DSO, (r), NULL)
#  define ECDHerr(f, r) ERR_raise_data(ERR_LIB_ECDH, (r), NULL)
#  define ECDSAerr(f, r) ERR_raise_data(ERR_LIB_ECDSA, (r), NULL)
#  define ECerr(f, r)  ERR_raise_data(ERR_LIB_EC, (r), NULL)
#  define ENGINEerr(f, r) ERR_raise_data(ERR_LIB_ENGINE, (r), NULL)
#  define ESSerr(f, r) ERR_raise_data(ERR_LIB_ESS, (r), NULL)
#  define EVPerr(f, r) ERR_raise_data(ERR_LIB_EVP, (r), NULL)
#  define FIPSerr(f, r) ERR_raise_data(ERR_LIB_FIPS, (r), NULL)
#  define HMACerr(f, r) ERR_raise_data(ERR_LIB_HMAC, (r), NULL)
#  define HTTPerr(f, r) ERR_raise_data(ERR_LIB_HTTP, (r), NULL)
#  define KDFerr(f, r) ERR_raise_data(ERR_LIB_KDF, (r), NULL)
#  define OBJerr(f, r) ERR_raise_data(ERR_LIB_OBJ, (r), NULL)
#  define OCSPerr(f, r) ERR_raise_data(ERR_LIB_OCSP, (r), NULL)
#  define OSSL_STOREerr(f, r) ERR_raise_data(ERR_LIB_OSSL_STORE, (r), NULL)
#  define PEMerr(f, r) ERR_raise_data(ERR_LIB_PEM, (r), NULL)
#  define PKCS12err(f, r) ERR_raise_data(ERR_LIB_PKCS12, (r), NULL)
#  define PKCS7err(f, r) ERR_raise_data(ERR_LIB_PKCS7, (r), NULL)
#  define PROPerr(f, r) ERR_raise_data(ERR_LIB_PROP, (r), NULL)
#  define PROVerr(f, r) ERR_raise_data(ERR_LIB_PROV, (r), NULL)
#  define RANDerr(f, r) ERR_raise_data(ERR_LIB_RAND, (r), NULL)
#  define RSAerr(f, r) ERR_raise_data(ERR_LIB_RSA, (r), NULL)
#  define KDFerr(f, r) ERR_raise_data(ERR_LIB_KDF, (r), NULL)
#  define SM2err(f, r) ERR_raise_data(ERR_LIB_SM2, (r), NULL)
#  define SSLerr(f, r) ERR_raise_data(ERR_LIB_SSL, (r), NULL)
#  define SYSerr(f, r) ERR_raise_data(ERR_LIB_SYS, (r), NULL)
#  define TSerr(f, r) ERR_raise_data(ERR_LIB_TS, (r), NULL)
#  define UIerr(f, r) ERR_raise_data(ERR_LIB_UI, (r), NULL)
#  define X509V3err(f, r) ERR_raise_data(ERR_LIB_X509V3, (r), NULL)
#  define X509err(f, r) ERR_raise_data(ERR_LIB_X509, (r), NULL)
# endif

# define ERR_PACK(l,f,r) ( \
        (((unsigned int)(l) & 0x0FF) << 24L) | \
        (((unsigned int)(f) & 0xFFF) << 12L) | \
        (((unsigned int)(r) & 0xFFF)       ) )
# define ERR_GET_LIB(l)          (int)(((l) >> 24L) & 0x0FFL)
# define ERR_GET_FUNC(l)         (int)(((l) >> 12L) & 0xFFFL)
# define ERR_GET_REASON(l)       (int)( (l)         & 0xFFFL)
# define ERR_FATAL_ERROR(l)      (int)( (l)         & ERR_R_FATAL)

# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define SYS_F_FOPEN             0
#  define SYS_F_CONNECT           0
#  define SYS_F_GETSERVBYNAME     0
#  define SYS_F_SOCKET            0
#  define SYS_F_IOCTLSOCKET       0
#  define SYS_F_BIND              0
#  define SYS_F_LISTEN            0
#  define SYS_F_ACCEPT            0
#  define SYS_F_WSASTARTUP        0
#  define SYS_F_OPENDIR           0
#  define SYS_F_FREAD             0
#  define SYS_F_GETADDRINFO       0
#  define SYS_F_GETNAMEINFO       0
#  define SYS_F_SETSOCKOPT        0
#  define SYS_F_GETSOCKOPT        0
#  define SYS_F_GETSOCKNAME       0
#  define SYS_F_GETHOSTBYNAME     0
#  define SYS_F_FFLUSH            0
#  define SYS_F_OPEN              0
#  define SYS_F_CLOSE             0
#  define SYS_F_IOCTL             0
#  define SYS_F_STAT              0
#  define SYS_F_FCNTL             0
#  define SYS_F_FSTAT             0
#  define SYS_F_SENDFILE          0
# endif

/* reasons */
# define ERR_R_SYS_LIB   ERR_LIB_SYS/* 2 */
# define ERR_R_BN_LIB    ERR_LIB_BN/* 3 */
# define ERR_R_RSA_LIB   ERR_LIB_RSA/* 4 */
# define ERR_R_DH_LIB    ERR_LIB_DH/* 5 */
# define ERR_R_EVP_LIB   ERR_LIB_EVP/* 6 */
# define ERR_R_BUF_LIB   ERR_LIB_BUF/* 7 */
# define ERR_R_OBJ_LIB   ERR_LIB_OBJ/* 8 */
# define ERR_R_PEM_LIB   ERR_LIB_PEM/* 9 */
# define ERR_R_DSA_LIB   ERR_LIB_DSA/* 10 */
# define ERR_R_X509_LIB  ERR_LIB_X509/* 11 */
# define ERR_R_ASN1_LIB  ERR_LIB_ASN1/* 13 */
# define ERR_R_EC_LIB    ERR_LIB_EC/* 16 */
# define ERR_R_BIO_LIB   ERR_LIB_BIO/* 32 */
# define ERR_R_PKCS7_LIB ERR_LIB_PKCS7/* 33 */
# define ERR_R_X509V3_LIB ERR_LIB_X509V3/* 34 */
# define ERR_R_ENGINE_LIB ERR_LIB_ENGINE/* 38 */
# define ERR_R_UI_LIB    ERR_LIB_UI/* 40 */
# define ERR_R_ECDSA_LIB ERR_LIB_ECDSA/* 42 */
# define ERR_R_OSSL_STORE_LIB ERR_LIB_OSSL_STORE/* 44 */

# define ERR_R_NESTED_ASN1_ERROR                 58
# define ERR_R_MISSING_ASN1_EOS                  63

/* fatal error */
# define ERR_R_FATAL                             64
# define ERR_R_MALLOC_FAILURE                    (1|ERR_R_FATAL)
# define ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED       (2|ERR_R_FATAL)
# define ERR_R_PASSED_NULL_PARAMETER             (3|ERR_R_FATAL)
# define ERR_R_INTERNAL_ERROR                    (4|ERR_R_FATAL)
# define ERR_R_DISABLED                          (5|ERR_R_FATAL)
# define ERR_R_INIT_FAIL                         (6|ERR_R_FATAL)
# define ERR_R_PASSED_INVALID_ARGUMENT           (7)
# define ERR_R_OPERATION_FAIL                    (8|ERR_R_FATAL)
# define ERR_R_INVALID_PROVIDER_FUNCTIONS        (9|ERR_R_FATAL)
# define ERR_R_INTERRUPTED_OR_CANCELLED          (10)

/*
 * 99 is the maximum possible ERR_R_... code, higher values are reserved for
 * the individual libraries
 */

typedef struct ERR_string_data_st {
    unsigned long error;
    const char *string;
} ERR_STRING_DATA;

DEFINE_LHASH_OF(ERR_STRING_DATA);

/* 12 lines and some on an 80 column terminal */
#define ERR_MAX_DATA_SIZE       1024

/* Building blocks */
void ERR_new(void);
void ERR_set_debug(const char *file, int line, const char *func);
void ERR_set_error(int lib, int reason, const char *fmt, ...);
void ERR_vset_error(int lib, int reason, const char *fmt, va_list args);

/* Main error raising functions */
# define ERR_raise(lib, reason) ERR_raise_data((lib),(reason),NULL)
# define ERR_raise_data                                         \
    (ERR_new(),                                                 \
     ERR_set_debug(OPENSSL_FILE,OPENSSL_LINE,OPENSSL_FUNC),     \
     ERR_set_error)

# ifndef OPENSSL_NO_DEPRECATED_3_0
/* Backward compatibility */
#  define ERR_put_error(lib, func, reason, file, line)          \
    (ERR_new(),                                                 \
     ERR_set_debug((file), (line), OPENSSL_FUNC),               \
     ERR_set_error((lib), (reason), NULL))
# endif

void ERR_set_error_data(char *data, int flags);

unsigned long ERR_get_error(void);
/*
 * TODO(3.0) consider if the following three functions should be deprecated.
 * They all drop the error record from the error queue, so regardless of which
 * one is used, the rest of the information is lost, making them not so useful.
 * The recommendation should be to use the peek functions to extract all the
 * additional data.
 */
unsigned long ERR_get_error_line(const char **file, int *line);
unsigned long ERR_get_error_func(const char **func);
unsigned long ERR_get_error_data(const char **data, int *flags);
unsigned long ERR_get_error_all(const char **file, int *line,
                                const char **func,
                                const char **data, int *flags);
DEPRECATEDIN_3_0(unsigned long ERR_get_error_line_data(const char **file,
                                                     int *line,
                                                     const char **data,
                                                     int *flags))
unsigned long ERR_peek_error(void);
unsigned long ERR_peek_error_line(const char **file, int *line);
unsigned long ERR_peek_error_func(const char **func);
unsigned long ERR_peek_error_data(const char **data, int *flags);
unsigned long ERR_peek_error_all(const char **file, int *line,
                                 const char **func,
                                 const char **data, int *flags);
DEPRECATEDIN_3_0(unsigned long ERR_peek_error_line_data(const char **file,
                                                      int *line,
                                                      const char **data,
                                                      int *flags))
unsigned long ERR_peek_last_error(void);
unsigned long ERR_peek_last_error_line(const char **file, int *line);
unsigned long ERR_peek_last_error_func(const char **func);
unsigned long ERR_peek_last_error_data(const char **data, int *flags);
unsigned long ERR_peek_last_error_all(const char **file, int *line,
                                      const char **func,
                                      const char **data, int *flags);
DEPRECATEDIN_3_0(unsigned long ERR_peek_last_error_line_data(const char **file,
                                                           int *line,
                                                           const char **data,
                                                           int *flags))

void ERR_clear_error(void);

char *ERR_error_string(unsigned long e, char *buf);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
const char *ERR_lib_error_string(unsigned long e);
DEPRECATEDIN_3_0(const char *ERR_func_error_string(unsigned long e))
const char *ERR_reason_error_string(unsigned long e);

void ERR_print_errors_cb(int (*cb) (const char *str, size_t len, void *u),
                         void *u);
# ifndef OPENSSL_NO_STDIO
void ERR_print_errors_fp(FILE *fp);
# endif
void ERR_print_errors(BIO *bp);

void ERR_add_error_data(int num, ...);
void ERR_add_error_vdata(int num, va_list args);

int ERR_load_strings(int lib, ERR_STRING_DATA *str);
int ERR_load_strings_const(const ERR_STRING_DATA *str);
int ERR_unload_strings(int lib, ERR_STRING_DATA *str);
int ERR_load_ERR_strings(void);

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
# define ERR_load_crypto_strings() \
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)
# define ERR_free_strings() while(0) continue
#endif

DEPRECATEDIN_1_1_0(void ERR_remove_thread_state(void *))
DEPRECATEDIN_1_0_0(void ERR_remove_state(unsigned long pid))
DEPRECATEDIN_3_0(ERR_STATE *ERR_get_state(void))

int ERR_get_next_error_library(void);

int ERR_set_mark(void);
int ERR_pop_to_mark(void);
int ERR_clear_last_mark(void);

#ifdef  __cplusplus
}
#endif

#endif
