/*
 * Copyright 1995-2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_INTERNAL_CRYPTLIB_H
# define Otls_INTERNAL_CRYPTLIB_H

# include <stdlib.h>
# include <string.h>

# ifdef OPENtls_USE_APPLINK
#  define BIO_FLAGS_UPLINK_INTERNAL 0x8000
#  include "ms/uplink.h"
# else
#  define BIO_FLAGS_UPLINK_INTERNAL 0
# endif

# include <opentls/crypto.h>
# include <opentls/buffer.h>
# include <opentls/bio.h>
# include <opentls/err.h>
# include "internal/nelem.h"

#ifdef NDEBUG
# define otls_assert(x) ((x) != 0)
#else
__owur static otls_inline int otls_assert_int(int expr, const char *exprstr,
                                              const char *file, int line)
{
    if (!expr)
        OPENtls_die(exprstr, file, line);

    return expr;
}

# define otls_assert(x) otls_assert_int((x) != 0, "Assertion failed: "#x, \
                                         __FILE__, __LINE__)

#endif

/*
 * Use this inside a union with the field that needs to be aligned to a
 * reasonable boundary for the platform.  The most pessimistic alignment
 * of the listed types will be used by the compiler.
 */
# define Otls_UNION_ALIGN       \
    double align;               \
    otls_uintmax_t align_int;   \
    void *align_ptr

typedef struct ex_callback_st EX_CALLBACK;
DEFINE_STACK_OF(EX_CALLBACK)

typedef struct mem_st MEM;
DEFINE_LHASH_OF(MEM);

# define OPENtls_CONF             "opentls.cnf"

# ifndef OPENtls_SYS_VMS
#  define X509_CERT_AREA          OPENtlsDIR
#  define X509_CERT_DIR           OPENtlsDIR "/certs"
#  define X509_CERT_FILE          OPENtlsDIR "/cert.pem"
#  define X509_PRIVATE_DIR        OPENtlsDIR "/private"
#  define CTLOG_FILE              OPENtlsDIR "/ct_log_list.cnf"
# else
#  define X509_CERT_AREA          "Otls$DATAROOT:[000000]"
#  define X509_CERT_DIR           "Otls$DATAROOT:[CERTS]"
#  define X509_CERT_FILE          "Otls$DATAROOT:[000000]cert.pem"
#  define X509_PRIVATE_DIR        "Otls$DATAROOT:[PRIVATE]"
#  define CTLOG_FILE              "Otls$DATAROOT:[000000]ct_log_list.cnf"
# endif

# define X509_CERT_DIR_EVP        "tls_CERT_DIR"
# define X509_CERT_FILE_EVP       "tls_CERT_FILE"
# define CTLOG_FILE_EVP           "CTLOG_FILE"

/* size of string representations */
# define DECIMAL_SIZE(type)      ((sizeof(type)*8+2)/3+1)
# define HEX_SIZE(type)          (sizeof(type)*2)

void OPENtls_cpuid_setup(void);
#if defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
    defined(__x86_64) || defined(__x86_64__) || \
    defined(_M_AMD64) || defined(_M_X64)
extern unsigned int OPENtls_ia32cap_P[];
#endif
void OPENtls_showfatal(const char *fmta, ...);
int do_ex_data_init(OPENtls_CTX *ctx);
void crypto_cleanup_all_ex_data_int(OPENtls_CTX *ctx);
int opentls_init_fork_handlers(void);
int opentls_get_fork_id(void);

char *otls_safe_getenv(const char *name);

extern CRYPTO_RWLOCK *memdbg_lock;
int opentls_strerror_r(int errnum, char *buf, size_t buflen);
# if !defined(OPENtls_NO_STDIO)
FILE *opentls_fopen(const char *filename, const char *mode);
# else
void *opentls_fopen(const char *filename, const char *mode);
# endif

uint32_t OPENtls_rdtsc(void);
size_t OPENtls_instrument_bus(unsigned int *, size_t);
size_t OPENtls_instrument_bus2(unsigned int *, size_t, size_t);

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

typedef struct otls_ex_data_global_st {
    CRYPTO_RWLOCK *ex_data_lock;
    EX_CALLBACKS ex_data[CRYPTO_EX_INDEX__COUNT];
} Otls_EX_DATA_GLOBAL;


/* OPENtls_CTX */

# define OPENtls_CTX_PROVIDER_STORE_RUN_ONCE_INDEX          0
# define OPENtls_CTX_DEFAULT_METHOD_STORE_RUN_ONCE_INDEX    1
# define OPENtls_CTX_METHOD_STORE_RUN_ONCE_INDEX            2
# define OPENtls_CTX_MAX_RUN_ONCE                           3

# define OPENtls_CTX_EVP_METHOD_STORE_INDEX         0
# define OPENtls_CTX_PROVIDER_STORE_INDEX           1
# define OPENtls_CTX_PROPERTY_DEFN_INDEX            2
# define OPENtls_CTX_PROPERTY_STRING_INDEX          3
# define OPENtls_CTX_NAMEMAP_INDEX                  4
# define OPENtls_CTX_DRBG_INDEX                     5
# define OPENtls_CTX_DRBG_NONCE_INDEX               6
# define OPENtls_CTX_RAND_CRNGT_INDEX               7
# define OPENtls_CTX_THREAD_EVENT_HANDLER_INDEX     8
# define OPENtls_CTX_FIPS_PROV_INDEX                9
# define OPENtls_CTX_SERIALIZER_STORE_INDEX        10
# define OPENtls_CTX_MAX_INDEXES                   11

typedef struct opentls_ctx_method {
    void *(*new_func)(OPENtls_CTX *ctx);
    void (*free_func)(void *);
} OPENtls_CTX_METHOD;

OPENtls_CTX *opentls_ctx_get_concrete(OPENtls_CTX *ctx);

/* Functions to retrieve pointers to data by index */
void *opentls_ctx_get_data(OPENtls_CTX *, int /* index */,
                           const OPENtls_CTX_METHOD * ctx);

void opentls_ctx_default_deinit(void);
Otls_EX_DATA_GLOBAL *opentls_ctx_get_ex_data_global(OPENtls_CTX *ctx);
typedef int (opentls_ctx_run_once_fn)(OPENtls_CTX *ctx);
typedef void (opentls_ctx_onfree_fn)(OPENtls_CTX *ctx);

int opentls_ctx_run_once(OPENtls_CTX *ctx, unsigned int idx,
                         opentls_ctx_run_once_fn run_once_fn);
int opentls_ctx_onfree(OPENtls_CTX *ctx, opentls_ctx_onfree_fn onfreefn);

OPENtls_CTX *crypto_ex_data_get_opentls_ctx(const CRYPTO_EX_DATA *ad);
int crypto_new_ex_data_ex(OPENtls_CTX *ctx, int class_index, void *obj,
                          CRYPTO_EX_DATA *ad);
int crypto_get_ex_new_index_ex(OPENtls_CTX *ctx, int class_index,
                               long argl, void *argp,
                               CRYPTO_EX_new *new_func,
                               CRYPTO_EX_dup *dup_func,
                               CRYPTO_EX_free *free_func);
int crypto_free_ex_index_ex(OPENtls_CTX *ctx, int class_index, int idx);

/* Function for simple binary search */

/* Flags */
# define Otls_BSEARCH_VALUE_ON_NOMATCH            0x01
# define Otls_BSEARCH_FIRST_VALUE_ON_MATCH        0x02

const void *otls_bsearch(const void *key, const void *base, int num,
                         int size, int (*cmp) (const void *, const void *),
                         int flags);

#endif
