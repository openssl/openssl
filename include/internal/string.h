/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_INTERNAL_STRING_H
# define HEADER_INTERNAL_STRING_H

# include <string.h>
# include <malloc.h>

# ifdef OPENSSL_SYS_WINDOWS

#  define strcasecmp _stricmp
#  define strncasecmp _strnicmp

#  ifdef _WIN64
#   define strlen(s) OPENSSL_strlen31(s)
unsigned int OPENSSL_strlen31(const char *str);
#  endif
#  if defined(_MSC_VER) && _MSC_VER<=1200 && defined(_MT) && defined(isspace)
   /* compensate for bug in VC6 ctype.h */
#   undef isspace
#   undef isdigit
#   undef isalnum
#   undef isupper
#   undef isxdigit
#  endif
# endif

/*
 * The following can be used to detect memory leaks in the library. If
 * used, it turns on malloc checking
 */
# define CRYPTO_MEM_CHECK_OFF     0x0   /* Control only */
# define CRYPTO_MEM_CHECK_ON      0x1   /* Control and mode bit */
# define CRYPTO_MEM_CHECK_ENABLE  0x2   /* Control and mode bit */
# define CRYPTO_MEM_CHECK_DISABLE 0x3   /* Control only */

int CRYPTO_set_mem_debug(int flag);

/*
 * This is the default callbacks, but we can have others as well: this is
 * needed in Win32 where the application malloc and the library malloc may
 * not be the same.
 */
#define OPENSSL_malloc_init() \
    CRYPTO_set_mem_functions(CRYPTO_malloc, CRYPTO_realloc, CRYPTO_free)

int CRYPTO_mem_ctrl(int mode);

# define OPENSSL_malloc(num) \
        CRYPTO_malloc(num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_zalloc(num) \
        CRYPTO_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_realloc(addr, num) \
        CRYPTO_realloc(addr, num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_clear_realloc(addr, old_num, num) \
        CRYPTO_clear_realloc(addr, old_num, num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_clear_free(addr, num) \
        CRYPTO_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_free(addr) \
        CRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_memdup(str, s) \
        CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_strdup(str) \
        CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_strndup(str, n) \
        CRYPTO_strndup(str, n, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_secure_malloc(num) \
        CRYPTO_secure_malloc(num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_secure_zalloc(num) \
        CRYPTO_secure_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_secure_free(addr) \
        CRYPTO_secure_free(addr, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_secure_clear_free(addr, num) \
        CRYPTO_secure_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_secure_actual_size(ptr) \
        CRYPTO_secure_actual_size(ptr)

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

void OPENSSL_cleanse(void *ptr, size_t len);

# ifndef OPENSSL_NO_CRYPTO_MDEBUG
#  define OPENSSL_mem_debug_push(info) \
        CRYPTO_mem_debug_push(info, OPENSSL_FILE, OPENSSL_LINE)
#  define OPENSSL_mem_debug_pop() \
        CRYPTO_mem_debug_pop()
int CRYPTO_mem_debug_push(const char *info, const char *file, int line);
int CRYPTO_mem_debug_pop(void);

/*-
 * Debugging functions (enabled by CRYPTO_set_mem_debug(1))
 * The flag argument has the following significance:
 *   0:   called before the actual memory allocation has taken place
 *   1:   called after the actual memory allocation has taken place
 */
void CRYPTO_mem_debug_malloc(void *addr, size_t num, int flag,
        const char *file, int line);
void CRYPTO_mem_debug_realloc(void *addr1, void *addr2, size_t num, int flag,
        const char *file, int line);
void CRYPTO_mem_debug_free(void *addr, int flag,
        const char *file, int line);

int CRYPTO_mem_leaks_cb(int (*cb) (const char *str, size_t len, void *u),
                        void *u);
#  ifndef OPENSSL_NO_STDIO
int CRYPTO_mem_leaks_fp(FILE *);
#  endif
# ifdef HEADER_BIO_H
int CRYPTO_mem_leaks(BIO *bio);
# endif
# endif

size_t OPENSSL_strlcpy(char *dst, const char *src, size_t siz);
size_t OPENSSL_strlcat(char *dst, const char *src, size_t siz);
size_t OPENSSL_strnlen(const char *str, size_t maxlen);
char *OPENSSL_buf2hexstr(const unsigned char *buffer, long len);
unsigned char *OPENSSL_hexstr2buf(const char *str, long *len);
int OPENSSL_hexchar2int(unsigned char c);

#endif
