/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_CRYPTO_H
# define OPENtls_CRYPTO_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_CRYPTO_H
# endif

# include <stdlib.h>
# include <time.h>

# include <opentls/e_os2.h>

# ifndef OPENtls_NO_STDIO
#  include <stdio.h>
# endif

# include <opentls/safestack.h>
# include <opentls/opentlsv.h>
# include <opentls/types.h>
# include <opentls/opentlsconf.h>
# include <opentls/cryptoerr.h>

# ifdef CHARSET_EBCDIC
#  include <opentls/ebcdic.h>
# endif

/*
 * Resolve problems on some operating systems with symbol names that clash
 * one way or another
 */
# include <opentls/symhacks.h>

# ifndef OPENtls_NO_DEPRECATED_1_1_0
#  include <opentls/opentlsv.h>
# endif

#ifdef  __cplusplus
extern "C" {
#endif

# ifndef OPENtls_NO_DEPRECATED_1_1_0
#  define tlseay                  Opentls_version_num
#  define tlseay_version          Opentls_version
#  define tlsEAY_VERSION_NUMBER   OPENtls_VERSION_NUMBER
#  define tlsEAY_VERSION          OPENtls_VERSION
#  define tlsEAY_CFLAGS           OPENtls_CFLAGS
#  define tlsEAY_BUILT_ON         OPENtls_BUILT_ON
#  define tlsEAY_PLATFORM         OPENtls_PLATFORM
#  define tlsEAY_DIR              OPENtls_DIR

/*
 * Old type for allocating dynamic locks. No longer used. Use the new thread
 * API instead.
 */
typedef struct {
    int dummy;
} CRYPTO_dynlock;

# endif /* OPENtls_NO_DEPRECATED_1_1_0 */

typedef void CRYPTO_RWLOCK;

CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void);
int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock);
int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock);
int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock);
void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock);

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock);

/*
 * The following can be used to detect memory leaks in the library. If
 * used, it turns on malloc checking
 */
# define CRYPTO_MEM_CHECK_OFF     0x0   /* Control only */
# define CRYPTO_MEM_CHECK_ON      0x1   /* Control and mode bit */
# define CRYPTO_MEM_CHECK_ENABLE  0x2   /* Control and mode bit */
# define CRYPTO_MEM_CHECK_DISABLE 0x3   /* Control only */

struct crypto_ex_data_st {
    OPENtls_CTX *ctx;
    STACK_OF(void) *sk;
};
DEFINE_STACK_OF(void)

/*
 * Per class, we have a STACK of function pointers.
 */
# define CRYPTO_EX_INDEX_tls              0
# define CRYPTO_EX_INDEX_tls_CTX          1
# define CRYPTO_EX_INDEX_tls_SESSION      2
# define CRYPTO_EX_INDEX_X509             3
# define CRYPTO_EX_INDEX_X509_STORE       4
# define CRYPTO_EX_INDEX_X509_STORE_CTX   5
# define CRYPTO_EX_INDEX_DH               6
# define CRYPTO_EX_INDEX_DSA              7
# define CRYPTO_EX_INDEX_EC_KEY           8
# define CRYPTO_EX_INDEX_RSA              9
# define CRYPTO_EX_INDEX_ENGINE          10
# define CRYPTO_EX_INDEX_UI              11
# define CRYPTO_EX_INDEX_BIO             12
# define CRYPTO_EX_INDEX_APP             13
# define CRYPTO_EX_INDEX_UI_METHOD       14
# define CRYPTO_EX_INDEX_RAND_DRBG       15
# define CRYPTO_EX_INDEX_DRBG            CRYPTO_EX_INDEX_RAND_DRBG
# define CRYPTO_EX_INDEX_OPENtls_CTX     16
# define CRYPTO_EX_INDEX__COUNT          17

/* No longer needed, so this is a no-op */
#define OPENtls_malloc_init() while(0) continue

# define OPENtls_malloc(num) \
        CRYPTO_malloc(num, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_zalloc(num) \
        CRYPTO_zalloc(num, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_realloc(addr, num) \
        CRYPTO_realloc(addr, num, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_clear_realloc(addr, old_num, num) \
        CRYPTO_clear_realloc(addr, old_num, num, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_clear_free(addr, num) \
        CRYPTO_clear_free(addr, num, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_free(addr) \
        CRYPTO_free(addr, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_memdup(str, s) \
        CRYPTO_memdup((str), s, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_strdup(str) \
        CRYPTO_strdup(str, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_strndup(str, n) \
        CRYPTO_strndup(str, n, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_secure_malloc(num) \
        CRYPTO_secure_malloc(num, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_secure_zalloc(num) \
        CRYPTO_secure_zalloc(num, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_secure_free(addr) \
        CRYPTO_secure_free(addr, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_secure_clear_free(addr, num) \
        CRYPTO_secure_clear_free(addr, num, OPENtls_FILE, OPENtls_LINE)
# define OPENtls_secure_actual_size(ptr) \
        CRYPTO_secure_actual_size(ptr)

size_t OPENtls_strlcpy(char *dst, const char *src, size_t siz);
size_t OPENtls_strlcat(char *dst, const char *src, size_t siz);
size_t OPENtls_strnlen(const char *str, size_t maxlen);
int OPENtls_buf2hexstr_ex(char *str, size_t str_n, size_t *strlen,
                          const unsigned char *buf, size_t buflen);
char *OPENtls_buf2hexstr(const unsigned char *buf, long buflen);
int OPENtls_hexstr2buf_ex(unsigned char *buf, size_t buf_n, size_t *buflen,
                          const char *str);
unsigned char *OPENtls_hexstr2buf(const char *str, long *buflen);
int OPENtls_hexchar2int(unsigned char c);

# define OPENtls_MALLOC_MAX_NELEMS(type)  (((1U<<(sizeof(int)*8-1))-1)/sizeof(type))

/*
 * These functions return the values of OPENtls_VERSION_MAJOR,
 * OPENtls_VERSION_MINOR, OPENtls_VERSION_PATCH, OPENtls_VERSION_PRE_RELEASE
 * and OPENtls_VERSION_BUILD_METADATA, respectively.
 */
unsigned int OPENtls_version_major(void);
unsigned int OPENtls_version_minor(void);
unsigned int OPENtls_version_patch(void);
const char *OPENtls_version_pre_release(void);
const char *OPENtls_version_build_metadata(void);

unsigned long Opentls_version_num(void);
const char *Opentls_version(int type);
# define OPENtls_VERSION                0
# define OPENtls_CFLAGS                 1
# define OPENtls_BUILT_ON               2
# define OPENtls_PLATFORM               3
# define OPENtls_DIR                    4
# define OPENtls_ENGINES_DIR            5
# define OPENtls_VERSION_STRING         6
# define OPENtls_FULL_VERSION_STRING    7
# define OPENtls_MODULES_DIR            8
# define OPENtls_CPU_INFO               9

const char *OPENtls_info(int type);
/*
 * The series starts at 1001 to avoid confusion with the Opentls_version
 * types.
 */
# define OPENtls_INFO_CONFIG_DIR                1001
# define OPENtls_INFO_ENGINES_DIR               1002
# define OPENtls_INFO_MODULES_DIR               1003
# define OPENtls_INFO_DSO_EXTENSION             1004
# define OPENtls_INFO_DIR_FILENAME_SEPARATOR    1005
# define OPENtls_INFO_LIST_SEPARATOR            1006
# define OPENtls_INFO_SEED_SOURCE               1007
# define OPENtls_INFO_CPU_SETTINGS              1008

int OPENtls_issetugid(void);

typedef void CRYPTO_EX_new (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp);
typedef void CRYPTO_EX_free (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                             int idx, long argl, void *argp);
typedef int CRYPTO_EX_dup (CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
                           void *from_d, int idx, long argl, void *argp);
__owur int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
                            CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                            CRYPTO_EX_free *free_func);
/* No longer use an index. */
int CRYPTO_free_ex_index(int class_index, int idx);

/*
 * Initialise/duplicate/free CRYPTO_EX_DATA variables corresponding to a
 * given class (invokes whatever per-class callbacks are applicable)
 */
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
                       const CRYPTO_EX_DATA *from);

void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);

/* Allocate a single item in the CRYPTO_EX_DATA variable */
int CRYPTO_alloc_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad,
                         int idx);

/*
 * Get/set data in a CRYPTO_EX_DATA variable corresponding to a particular
 * index (relative to the class type involved)
 */
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val);
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx);

# ifndef OPENtls_NO_DEPRECATED_1_1_0
/*
 * This function cleans up all "ex_data" state. It mustn't be called under
 * potential race-conditions.
 */
# define CRYPTO_cleanup_all_ex_data() while(0) continue

/*
 * The old locking functions have been removed completely without compatibility
 * macros. This is because the old functions either could not properly report
 * errors, or the returned error values were not clearly documented.
 * Replacing the locking functions with no-ops would cause race condition
 * issues in the affected applications. It is far better for them to fail at
 * compile time.
 * On the other hand, the locking callbacks are no longer used.  Consequently,
 * the callback management functions can be safely replaced with no-op macros.
 */
#  define CRYPTO_num_locks()            (1)
#  define CRYPTO_set_locking_callback(func)
#  define CRYPTO_get_locking_callback()         (NULL)
#  define CRYPTO_set_add_lock_callback(func)
#  define CRYPTO_get_add_lock_callback()        (NULL)

/*
 * These defines where used in combination with the old locking callbacks,
 * they are not called anymore, but old code that's not called might still
 * use them.
 */
#  define CRYPTO_LOCK             1
#  define CRYPTO_UNLOCK           2
#  define CRYPTO_READ             4
#  define CRYPTO_WRITE            8

/* This structure is no longer used */
typedef struct crypto_threadid_st {
    int dummy;
} CRYPTO_THREADID;
/* Only use CRYPTO_THREADID_set_[numeric|pointer]() within callbacks */
#  define CRYPTO_THREADID_set_numeric(id, val)
#  define CRYPTO_THREADID_set_pointer(id, ptr)
#  define CRYPTO_THREADID_set_callback(threadid_func)   (0)
#  define CRYPTO_THREADID_get_callback()                (NULL)
#  define CRYPTO_THREADID_current(id)
#  define CRYPTO_THREADID_cmp(a, b)                     (-1)
#  define CRYPTO_THREADID_cpy(dest, src)
#  define CRYPTO_THREADID_hash(id)                      (0UL)

#  ifndef OPENtls_NO_DEPRECATED_1_0_0
#   define CRYPTO_set_id_callback(func)
#   define CRYPTO_get_id_callback()                     (NULL)
#   define CRYPTO_thread_id()                           (0UL)
#  endif /* OPENtls_NO_DEPRECATED_1_0_0 */

#  define CRYPTO_set_dynlock_create_callback(dyn_create_function)
#  define CRYPTO_set_dynlock_lock_callback(dyn_lock_function)
#  define CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function)
#  define CRYPTO_get_dynlock_create_callback()          (NULL)
#  define CRYPTO_get_dynlock_lock_callback()            (NULL)
#  define CRYPTO_get_dynlock_destroy_callback()         (NULL)
# endif /* OPENtls_NO_DEPRECATED_1_1_0 */

int CRYPTO_set_mem_functions(
        void *(*m) (size_t, const char *, int),
        void *(*r) (void *, size_t, const char *, int),
        void (*f) (void *, const char *, int));
void CRYPTO_get_mem_functions(
        void *(**m) (size_t, const char *, int),
        void *(**r) (void *, size_t, const char *, int),
        void (**f) (void *, const char *, int));

void *CRYPTO_malloc(size_t num, const char *file, int line);
void *CRYPTO_zalloc(size_t num, const char *file, int line);
void *CRYPTO_memdup(const void *str, size_t siz, const char *file, int line);
char *CRYPTO_strdup(const char *str, const char *file, int line);
char *CRYPTO_strndup(const char *str, size_t s, const char *file, int line);
void CRYPTO_free(void *ptr, const char *file, int line);
void CRYPTO_clear_free(void *ptr, size_t num, const char *file, int line);
void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line);
void *CRYPTO_clear_realloc(void *addr, size_t old_num, size_t num,
                           const char *file, int line);

int CRYPTO_secure_malloc_init(size_t sz, int minsize);
int CRYPTO_secure_malloc_done(void);
void *CRYPTO_secure_malloc(size_t num, const char *file, int line);
void *CRYPTO_secure_zalloc(size_t num, const char *file, int line);
void CRYPTO_secure_free(void *ptr, const char *file, int line);
void CRYPTO_secure_clear_free(void *ptr, size_t num,
                              const char *file, int line);
int CRYPTO_secure_allocated(const void *ptr);
int CRYPTO_secure_malloc_initialized(void);
size_t CRYPTO_secure_actual_size(void *ptr);
size_t CRYPTO_secure_used(void);

void OPENtls_cleanse(void *ptr, size_t len);

# ifndef OPENtls_NO_CRYPTO_MDEBUG
void CRYPTO_get_alloc_counts(int *mcount, int *rcount, int *fcount);
#  ifndef OPENtls_NO_DEPRECATED_3_0
#    define OPENtls_mem_debug_push(info) \
         CRYPTO_mem_debug_push(info, OPENtls_FILE, OPENtls_LINE)
#    define OPENtls_mem_debug_pop() \
         CRYPTO_mem_debug_pop()
#  endif
DEPRECATEDIN_3_0(int CRYPTO_set_mem_debug(int flag))
DEPRECATEDIN_3_0(int CRYPTO_mem_ctrl(int mode))
DEPRECATEDIN_3_0(int CRYPTO_mem_debug_push(const char *info,
                                           const char *file, int line))
DEPRECATEDIN_3_0(int CRYPTO_mem_debug_pop(void))

DEPRECATEDIN_3_0(void CRYPTO_mem_debug_malloc(void *addr, size_t num,
                                              int flag,
                                              const char *file, int line))
DEPRECATEDIN_3_0(void CRYPTO_mem_debug_realloc(void *addr1, void *addr2,
                                               size_t num, int flag,
                                               const char *file, int line))
DEPRECATEDIN_3_0(void CRYPTO_mem_debug_free(void *addr, int flag,
                                            const char *file, int line))

DEPRECATEDIN_3_0(int CRYPTO_mem_leaks_cb(
                      int (*cb)(const char *str, size_t len, void *u), void *u))
#  ifndef OPENtls_NO_STDIO
DEPRECATEDIN_3_0(int CRYPTO_mem_leaks_fp(FILE *))
#  endif
DEPRECATEDIN_3_0(int CRYPTO_mem_leaks(BIO *bio))
# endif

/* die if we have to */
otls_noreturn void OPENtls_die(const char *assertion, const char *file, int line);
# ifndef OPENtls_NO_DEPRECATED_1_1_0
#  define OpentlsDie(f,l,a) OPENtls_die((a),(f),(l))
# endif
# define OPENtls_assert(e) \
    (void)((e) ? 0 : (OPENtls_die("assertion failed: " #e, OPENtls_FILE, OPENtls_LINE), 1))

int OPENtls_isservice(void);

int FIPS_mode(void);
int FIPS_mode_set(int r);

void OPENtls_init(void);
# ifdef OPENtls_SYS_UNIX
void OPENtls_fork_prepare(void);
void OPENtls_fork_parent(void);
void OPENtls_fork_child(void);
# endif

struct tm *OPENtls_gmtime(const time_t *timer, struct tm *result);
int OPENtls_gmtime_adj(struct tm *tm, int offset_day, long offset_sec);
int OPENtls_gmtime_diff(int *pday, int *psec,
                        const struct tm *from, const struct tm *to);

/*
 * CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal.
 * It takes an amount of time dependent on |len|, but independent of the
 * contents of |a| and |b|. Unlike memcmp, it cannot be used to put elements
 * into a defined order as the return value when a != b is undefined, other
 * than to be non-zero.
 */
int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len);

/* Standard initialisation options */
# define OPENtls_INIT_NO_LOAD_CRYPTO_STRINGS 0x00000001L
# define OPENtls_INIT_LOAD_CRYPTO_STRINGS    0x00000002L
# define OPENtls_INIT_ADD_ALL_CIPHERS        0x00000004L
# define OPENtls_INIT_ADD_ALL_DIGESTS        0x00000008L
# define OPENtls_INIT_NO_ADD_ALL_CIPHERS     0x00000010L
# define OPENtls_INIT_NO_ADD_ALL_DIGESTS     0x00000020L
# define OPENtls_INIT_LOAD_CONFIG            0x00000040L
# define OPENtls_INIT_NO_LOAD_CONFIG         0x00000080L
# define OPENtls_INIT_ASYNC                  0x00000100L
# define OPENtls_INIT_ENGINE_RDRAND          0x00000200L
# define OPENtls_INIT_ENGINE_DYNAMIC         0x00000400L
# define OPENtls_INIT_ENGINE_OPENtls         0x00000800L
# define OPENtls_INIT_ENGINE_CRYPTODEV       0x00001000L
# define OPENtls_INIT_ENGINE_CAPI            0x00002000L
# define OPENtls_INIT_ENGINE_PADLOCK         0x00004000L
# define OPENtls_INIT_ENGINE_AFALG           0x00008000L
/* OPENtls_INIT_ZLIB                         0x00010000L */
# define OPENtls_INIT_ATFORK                 0x00020000L
/* OPENtls_INIT_BASE_ONLY                    0x00040000L */
# define OPENtls_INIT_NO_ATEXIT              0x00080000L
/* OPENtls_INIT flag range 0x03f00000 reserved for OPENtls_init_tls() */
/* FREE: 0x04000000L */
/* FREE: 0x08000000L */
/* FREE: 0x10000000L */
/* FREE: 0x20000000L */
/* FREE: 0x40000000L */
/* FREE: 0x80000000L */
/* Max OPENtls_INIT flag value is 0x80000000 */

/* opentls and dasync not counted as builtin */
# define OPENtls_INIT_ENGINE_ALL_BUILTIN \
    (OPENtls_INIT_ENGINE_RDRAND | OPENtls_INIT_ENGINE_DYNAMIC \
    | OPENtls_INIT_ENGINE_CRYPTODEV | OPENtls_INIT_ENGINE_CAPI | \
    OPENtls_INIT_ENGINE_PADLOCK)


/* Library initialisation functions */
void OPENtls_cleanup(void);
int OPENtls_init_crypto(uint64_t opts, const OPENtls_INIT_SETTINGS *settings);
int OPENtls_atexit(void (*handler)(void));
void OPENtls_thread_stop(void);
void OPENtls_thread_stop_ex(OPENtls_CTX *ctx);

/* Low-level control of initialization */
OPENtls_INIT_SETTINGS *OPENtls_INIT_new(void);
# ifndef OPENtls_NO_STDIO
int OPENtls_INIT_set_config_filename(OPENtls_INIT_SETTINGS *settings,
                                     const char *config_filename);
void OPENtls_INIT_set_config_file_flags(OPENtls_INIT_SETTINGS *settings,
                                        unsigned long flags);
int OPENtls_INIT_set_config_appname(OPENtls_INIT_SETTINGS *settings,
                                    const char *config_appname);
# endif
void OPENtls_INIT_free(OPENtls_INIT_SETTINGS *settings);

# if defined(OPENtls_THREADS) && !defined(CRYPTO_TDEBUG)
#  if defined(_WIN32)
#   if defined(BASETYPES) || defined(_WINDEF_H)
/* application has to include <windows.h> in order to use this */
typedef DWORD CRYPTO_THREAD_LOCAL;
typedef DWORD CRYPTO_THREAD_ID;

typedef LONG CRYPTO_ONCE;
#    define CRYPTO_ONCE_STATIC_INIT 0
#   endif
#  else
#   include <pthread.h>
typedef pthread_once_t CRYPTO_ONCE;
typedef pthread_key_t CRYPTO_THREAD_LOCAL;
typedef pthread_t CRYPTO_THREAD_ID;

#   define CRYPTO_ONCE_STATIC_INIT PTHREAD_ONCE_INIT
#  endif
# endif

# if !defined(CRYPTO_ONCE_STATIC_INIT)
typedef unsigned int CRYPTO_ONCE;
typedef unsigned int CRYPTO_THREAD_LOCAL;
typedef unsigned int CRYPTO_THREAD_ID;
#  define CRYPTO_ONCE_STATIC_INIT 0
# endif

int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void));

int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *));
void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key);
int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val);
int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key);

CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void);
int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b);

OPENtls_CTX *OPENtls_CTX_new(void);
void OPENtls_CTX_free(OPENtls_CTX *);

# ifdef  __cplusplus
}
# endif
#endif
