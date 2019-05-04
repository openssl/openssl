/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CRYPTLIB_H
# define HEADER_CRYPTLIB_H

# include <stdlib.h>
# include <string.h>

# ifdef OPENSSL_USE_APPLINK
#  undef BIO_FLAGS_UPLINK
#  define BIO_FLAGS_UPLINK 0x8000
#  include "ms/uplink.h"
# endif

# include <openssl/crypto.h>
# include <openssl/buffer.h>
# include <openssl/bio.h>
# include <openssl/err.h>
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

/*
 * Use this inside a union with the field that needs to be aligned to a
 * reasonable boundary for the platform.  The most pessimistic alignment
 * of the listed types will be used by the compiler.
 */
# define OSSL_UNION_ALIGN       \
    double align;               \
    ossl_uintmax_t align_int;   \
    void *align_ptr

typedef struct ex_callback_st EX_CALLBACK;

DEFINE_STACK_OF(EX_CALLBACK)

typedef struct app_mem_info_st APP_INFO;

typedef struct mem_st MEM;
DEFINE_LHASH_OF(MEM);

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

void OPENSSL_cpuid_setup(void);
extern unsigned int OPENSSL_ia32cap_P[];
void OPENSSL_showfatal(const char *fmta, ...);
int do_ex_data_init(OPENSSL_CTX *ctx);
void crypto_cleanup_all_ex_data_int(OPENSSL_CTX *ctx);
int openssl_init_fork_handlers(void);

char *ossl_safe_getenv(const char *name);

extern CRYPTO_RWLOCK *memdbg_lock;
int openssl_strerror_r(int errnum, char *buf, size_t buflen);
# if !defined(OPENSSL_NO_STDIO)
FILE *openssl_fopen(const char *filename, const char *mode);
# else
void *openssl_fopen(const char *filename, const char *mode);
# endif

uint32_t OPENSSL_rdtsc(void);
size_t OPENSSL_instrument_bus(unsigned int *, size_t);
size_t OPENSSL_instrument_bus2(unsigned int *, size_t, size_t);

/* ex_data structures */

/*
 * Each structure type (sometimes called a class), that supports
 * exdata has a stack of callbacks for each instance.
 */
struct ex_callback_st {
    long argl;                  /* Arbitrary long */
    void *argp;                 /* Arbitrary void * */
    CRYPTO_EX_new *new_func;
    CRYPTO_EX_free *free_func;
    CRYPTO_EX_dup *dup_func;
};

/*
 * The state for each class.  This could just be a typedef, but
 * a structure allows future changes.
 */
typedef struct ex_callbacks_st {
    STACK_OF(EX_CALLBACK) *meth;
} EX_CALLBACKS;

typedef struct ossl_ex_data_global_st {
    CRYPTO_RWLOCK *ex_data_lock;
    EX_CALLBACKS ex_data[CRYPTO_EX_INDEX__COUNT];
} OSSL_EX_DATA_GLOBAL;


/* OPENSSL_CTX */

# define OPENSSL_CTX_PROVIDER_STORE_RUN_ONCE_INDEX          0
# define OPENSSL_CTX_DEFAULT_METHOD_STORE_RUN_ONCE_INDEX    1
# define OPENSSL_CTX_METHOD_STORE_RUN_ONCE_INDEX            2
# define OPENSSL_CTX_MAX_RUN_ONCE                           3

# define OPENSSL_CTX_DEFAULT_METHOD_STORE_INDEX     0
# define OPENSSL_CTX_PROVIDER_STORE_INDEX           1
# define OPENSSL_CTX_PROPERTY_DEFN_INDEX            2
# define OPENSSL_CTX_PROPERTY_STRING_INDEX          3
# define OPENSSL_CTX_NAMEMAP_INDEX                  4
# define OPENSSL_CTX_MAX_INDEXES                    5

typedef struct openssl_ctx_method {
    void *(*new_func)(OPENSSL_CTX *ctx);
    void (*free_func)(void *);
} OPENSSL_CTX_METHOD;

/* Functions to retrieve pointers to data by index */
void *openssl_ctx_get_data(OPENSSL_CTX *, int /* index */,
                           const OPENSSL_CTX_METHOD * ctx);

void openssl_ctx_default_deinit(void);
OSSL_EX_DATA_GLOBAL *openssl_ctx_get_ex_data_global(OPENSSL_CTX *ctx);
typedef int (openssl_ctx_run_once_fn)(OPENSSL_CTX *ctx);
typedef void (openssl_ctx_onfree_fn)(OPENSSL_CTX *ctx);

int openssl_ctx_run_once(OPENSSL_CTX *ctx, unsigned int idx,
                         openssl_ctx_run_once_fn run_once_fn);
int openssl_ctx_onfree(OPENSSL_CTX *ctx, openssl_ctx_onfree_fn onfreefn);

OPENSSL_CTX *crypto_ex_data_get_openssl_ctx(const CRYPTO_EX_DATA *ad);
int crypto_new_ex_data_ex(OPENSSL_CTX *ctx, int class_index, void *obj,
                          CRYPTO_EX_DATA *ad);
int crypto_get_ex_new_index_ex(OPENSSL_CTX *ctx, int class_index,
                               long argl, void *argp,
                               CRYPTO_EX_new *new_func,
                               CRYPTO_EX_dup *dup_func,
                               CRYPTO_EX_free *free_func);
int crypto_free_ex_index_ex(OPENSSL_CTX *ctx, int class_index, int idx);

/* Function for simple binary search */

/* Flags */
# define OSSL_BSEARCH_VALUE_ON_NOMATCH            0x01
# define OSSL_BSEARCH_FIRST_VALUE_ON_MATCH        0x02

const void *ossl_bsearch(const void *key, const void *base, int num,
                         int size, int (*cmp) (const void *, const void *),
                         int flags);

#endif
