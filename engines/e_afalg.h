/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_AFALG_H
# define HEADER_AFALG_H

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

# define MAX_INFLIGHTS 1

#define DECLARE_AES_CBC(key_size)   \
const EVP_CIPHER *afalg_aes_##key_size##_cbc(void)  \
{   \
    if (_hidden_aes_##key_size##_cbc == NULL \
        && ((_hidden_aes_##key_size##_cbc =  \
            EVP_CIPHER_meth_new(NID_aes_##key_size##_cbc,    \
                                AES_BLOCK_SIZE, \
                                AES_KEY_SIZE_##key_size)) == NULL  \
            || !EVP_CIPHER_meth_set_iv_length(_hidden_aes_##key_size##_cbc,  \
                                            AES_IV_LEN)\
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_##key_size##_cbc, \
                                            EVP_CIPH_CBC_MODE | \
                                            EVP_CIPH_FLAG_DEFAULT_ASN1) \
            || !EVP_CIPHER_meth_set_init(_hidden_aes_##key_size##_cbc,   \
                                            afalg_cipher_init)  \
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_##key_size##_cbc,  \
                                            afalg_do_cipher)    \
            || !EVP_CIPHER_meth_set_cleanup(_hidden_aes_##key_size##_cbc,    \
                                            afalg_cipher_cleanup)   \
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_##key_size##_cbc,\
                                            sizeof(afalg_ctx))))    \
    {   \
        EVP_CIPHER_meth_free(_hidden_aes_##key_size##_cbc);  \
        _hidden_aes_##key_size##_cbc = NULL; \
    }   \
    return _hidden_aes_##key_size##_cbc; \
}


typedef enum {
    MODE_UNINIT = 0,
    MODE_SYNC,
    MODE_ASYNC
} op_mode;

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
#endif
