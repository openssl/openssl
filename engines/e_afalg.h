/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_ENGINES_E_AFALG_H
# define OSSL_ENGINES_E_AFALG_H

# if defined(__GNUC__) && __GNUC__ >= 4 && \
     (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#  pragma GCC diagnostic ignored "-Wvariadic-macros"
# endif

# ifdef ALG_DEBUG
#  define ALG_DGB(x, ...) fprintf(stderr, "ALG_DBG: " x, __VA_ARGS__)
#  define ALG_INFO(x, ...) fprintf(stderr, "ALG_INFO: " x, __VA_ARGS__)
#  define ALG_WARN(x, ...) fprintf(stderr, "ALG_WARN: " x, __VA_ARGS__)
# else
#  define ALG_DGB(x, ...)
#  define ALG_INFO(x, ...)
#  define ALG_WARN(x, ...)
# endif

# define ALG_ERR(x, ...) fprintf(stderr, "ALG_ERR: " x, __VA_ARGS__)
# define ALG_PERR(x, ...) \
                do { \
                    fprintf(stderr, "ALG_PERR: " x, __VA_ARGS__); \
                    perror(NULL); \
                } while(0)
# define ALG_PWARN(x, ...) \
                do { \
                    fprintf(stderr, "ALG_PERR: " x, __VA_ARGS__); \
                    perror(NULL); \
                } while(0)

# ifndef AES_BLOCK_SIZE
#  define AES_BLOCK_SIZE   16
# endif
# define AES_KEY_SIZE_128 16
# define AES_KEY_SIZE_192 24
# define AES_KEY_SIZE_256 32
# define AES_IV_LEN       16

# define AES_KEY_SIZE_256 32
# define AES_GCM_IV_LEN   12

/* Socket options */
# define ALG_SET_KEY                     1
# define ALG_SET_IV                      2
# define ALG_SET_OP                      3
# define ALG_SET_AEAD_ASSOCLEN           4
# define ALG_SET_AEAD_AUTHSIZE           5

# define MAX_INFLIGHTS 1
# define AFALG_UPDATE_CALLED 0x00000001

typedef enum {
    MODE_UNINIT = 0,
    MODE_SYNC,
    MODE_ASYNC
} op_mode;

enum {
    AES_CBC_128 = 0,
    AES_CBC_192,
    AES_CBC_256,
    AES_GCM_128,
    AES_GCM_192,
    AES_GCM_256
};

struct aes_cipher_handles {
    int key_size;
    EVP_CIPHER *_hidden;
};

typedef struct aes_cipher_handles aes_handles;


struct afalg_aio_st {
    int efd;
    op_mode mode;
    aio_context_t aio_ctx;
    struct io_event events[MAX_INFLIGHTS];
    struct iocb cbt[MAX_INFLIGHTS];
};
typedef struct afalg_aio_st afalg_aio;

/*
 * MAGIC Number to identify correct initialisation
 * of afalg_ctx.
 */
# define MAGIC_INIT_NUM 0x1890671

struct afalg_ctx_st {
    int init_done;
    int sfd;
    int bfd;
# ifdef ALG_ZERO_COPY
    int zc_pipe[2];
# endif
    afalg_aio aio;
};

typedef struct afalg_ctx_st afalg_ctx;

struct afalg_aead_ctx_st {
    afalg_ctx ctx;
    int key_set;
    int iv_set;
    unsigned char *iv;
    int ivlen;
    int taglen;
    int iv_gen;
    int iovlen;
    int aad_len;
    int is_tls;
    int len;
    struct iovec iov[16];
};
typedef struct afalg_aead_ctx_st afalg_aead_ctx;

#endif
