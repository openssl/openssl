/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "internal/thread_once.h"

#define KEY_SIZE 32

/* Internal state of chacha20 is 512 bits */
#define NEEDED_ENTROPY 512

#define RESEED_TIME 3600 /* 1 hour */
#define RESEED_BYTES (1<<30) /* 1 GiB */

typedef struct RNG_CHACHA20_CTX_st {
    unsigned char buffer[1024];
    int buf_used;
    CRYPTO_RWLOCK *lock;
    int state;
    int entropy; /* bits */
    time_t last_reseed;
    size_t size_read;
    EVP_CIPHER_CTX *ctx;
} RNG_CHACHA20_CTX;

static RNG_CHACHA20_CTX rng;
static CRYPTO_ONCE rng_chacha20_init = CRYPTO_ONCE_STATIC_INIT;

/* Sets the initial state so that seeding it is required. */
static void rng_chacha20_need_seed(RNG_CHACHA20_CTX *ctx)
{
    ctx->state = 0;
    ctx->entropy = 0;
    ctx->last_reseed = time(NULL);
    ctx->size_read = 0;
}

/* Checks that we need to reseed */
static void check_reseed(RNG_CHACHA20_CTX *ctx)
{
    if (ctx->size_read >= RESEED_BYTES || (time(NULL) - ctx->last_reseed) >= RESEED_TIME)
        rng_chacha20_need_seed(ctx);
}

/* Initialize the RNG. Returns 1 on success, 0 on failure. */
DEFINE_RUN_ONCE_STATIC(do_rng_chacha20_init)
{
    memset(rng.buffer, 0, sizeof(rng.buffer));
    rng.lock = NULL;
    rng.ctx = NULL;

    rng.lock = CRYPTO_THREAD_lock_new();
    if (rng.lock == NULL)
        goto err;
    rng.ctx = EVP_CIPHER_CTX_new();
    if (rng.ctx == NULL)
        goto err;
    if (EVP_EncryptInit_ex(rng.ctx, EVP_chacha20(), NULL, rng.buffer, NULL) == 0)
        goto err;

    rng_chacha20_need_seed(&rng);

    return 1;

err:
    CRYPTO_THREAD_lock_free(rng.lock);
    EVP_CIPHER_CTX_free(rng.ctx);
    return 0;
}

/*
 * Gets the global RNG, and initialized it on first use.
 * Returns a pointer to it on success or NULL on failure.
 */
RNG_CHACHA20_CTX *rng_chacha20_get_ctx(void)
{
    if (!RUN_ONCE(&rng_chacha20_init, do_rng_chacha20_init))
        return NULL;
    return &rng;
}

/*
 * Calls the encrypt function to generate new random data and place it
 * in the buffer. It will use part of the generated random data to update
 * the key. If buf != NULL that data will be used to add randomness.
 *
 * Returns 1 on success, 0 on failure.
 */
static int rng_chacha20_encrypt(RNG_CHACHA20_CTX *ctx, const void *buf, int buf_len)
{
    const unsigned char *in = buf;

    do {
        int in_len;
        int out_len;

        in_len = (buf_len > sizeof(ctx->buffer)) ? sizeof(ctx->buffer) : buf_len;
        if (in != NULL)
            memcpy(ctx->buffer, in, in_len);
        memset(ctx->buffer+in_len, 0, sizeof(ctx->buffer)-in_len);

        if (EVP_EncryptUpdate(ctx->ctx, ctx->buffer, &out_len, ctx->buffer, sizeof(ctx->buffer)) == 0)
            goto err;

        if (EVP_EncryptInit_ex(ctx->ctx, NULL, NULL, ctx->buffer, NULL) == 0)
            goto err;

        memset(ctx->buffer, 0, KEY_SIZE);
        ctx->buf_used = KEY_SIZE;
        ctx->size_read += sizeof(ctx->buffer);

        check_reseed(ctx);

        buf_len -= in_len;
        in += in_len;
    } while (buf_len > 0);

    return 1;

err:
    ctx->state = 0;
    return 0;
}

/* Add randomness, see RAND_add() */
static int rng_chacha20_add(const void *buf, int num, double entropy)
{
    RNG_CHACHA20_CTX *ctx = rng_chacha20_get_ctx();
    int ret = 0;

    if (ctx == NULL)
        return 0;

    CRYPTO_THREAD_write_lock(ctx->lock);

    if (rng_chacha20_encrypt(ctx, buf, num) == 0)
        goto out;

    if (ctx->entropy < NEEDED_ENTROPY)
        ctx->entropy += entropy * 8;

    if (ctx->entropy >= NEEDED_ENTROPY) {
        ctx->state = 1;
        ctx->last_reseed = time(NULL);
    }
    ret = 1;

out:
    CRYPTO_THREAD_unlock(ctx->lock);
    return ret;
}

/* Add randomness, see RAND_seed() */
static int rng_chacha20_seed(const void *buf, int num)
{
    return rng_chacha20_add(buf, num, num);
}

/* Return random data, see RAND_bytes() */
static int rng_chacha20_bytes(unsigned char *buf, int num)
{
    unsigned char *out = buf;
    int ret = 0;

    RNG_CHACHA20_CTX *ctx = rng_chacha20_get_ctx();

    if (ctx == NULL)
        return 0;

    CRYPTO_THREAD_write_lock(ctx->lock);

    check_reseed(ctx);

    while (num > 0) {
        int len;

        /* TODO: Do this some other way? Just return error? */
        while (ctx->state == 0) {
            CRYPTO_THREAD_unlock(ctx->lock);
            RAND_poll();
            CRYPTO_THREAD_write_lock(ctx->lock);
        }

        len = ((sizeof(ctx->buffer)-ctx->buf_used) > num) ?
            num : sizeof(ctx->buffer)-ctx->buf_used;

        memcpy(out, ctx->buffer+ctx->buf_used, len);
        memset(ctx->buffer+ctx->buf_used, 0, len);

        ctx->buf_used += len;
        num -= len;
        out += len;

        if (ctx->buf_used == sizeof(ctx->buffer))
            if (rng_chacha20_encrypt(ctx, NULL, 0) == 0)
                goto out;
    }
    ret = 1;

out:
    CRYPTO_THREAD_unlock(ctx->lock);
    return ret;
}

/* Clean up the RNG. */
static void rng_chacha20_cleanup(void)
{
    RNG_CHACHA20_CTX *ctx = rng_chacha20_get_ctx();

    if (ctx == NULL)
        return;

    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    EVP_CIPHER_CTX_free(ctx->ctx);
    CRYPTO_THREAD_lock_free(ctx->lock);
}

/* Returns the status of the RNG, see RAND_status() */
static int rng_chacha20_status(void)
{
    RNG_CHACHA20_CTX *ctx = rng_chacha20_get_ctx();

    if (ctx == NULL)
        return 0;

    return ctx->state;
}

static const RAND_METHOD rand_method_chacha20 = {
    rng_chacha20_seed,
    rng_chacha20_bytes,
    rng_chacha20_cleanup,
    rng_chacha20_add,
    rng_chacha20_bytes,
    rng_chacha20_status
};

/* Return pointer to the chacha20 RNG method. */
const RAND_METHOD *RAND_chacha20(void)
{
    return &rand_method_chacha20;
}

