/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of the Apache Public License 2.0.
 * The terms of this licenses can be found at:
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of the license along with this
 * software. If not, it may be obtained at the above URL.
 */

/*For memory wiping*/
#ifdef _MSC_VER
# include <windows.h>
# include <winbase.h> /* For SecureZeroMemory */
#endif
#if defined __STDC_LIB_EXT1__
# define __STDC_WANT_LIB_EXT1__ 1
#endif

#define VC_GE_2005(version) (version >= 1400)

/* for explicit_bzero() on glibc */
#ifndef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "blake2b.h"

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>

#if defined(__clang__)
# if __has_attribute(optnone)
#  define NOT_OPTIMIZED __attribute__((optnone))
# endif
#elif defined(__GNUC__)
# define GCC_VERSION                                                            \
    (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
# if GCC_VERSION >= 40400
#  define NOT_OPTIMIZED __attribute__((optimize("O0")))
# endif
#endif
#ifndef NOT_OPTIMIZED
# define NOT_OPTIMIZED
#endif

/* The following is required to keep ABI compat with CRYPTO_THREAD_ROUTINE
 * as defined in openssl/crypto.h */
# if !defined(CALLBACK)
#  if defined(_WIN32) || defined(_STDCALL_SUPPORTED)
#   define CALLBACK __stdcall
#  else
#   define CALLBACK
#  endif
# elif !defined(_WIN32) && !defined(_STDCALL_SUPPORTED)
#  undef CALLBACK
# endif

/***************Instance and Position constructors**********/
void init_block_value(block *b, uint8_t in)
{
    memset(b->v, in, sizeof(b->v));
}

void copy_block(block *dst, const block *src)
{
    memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}

void xor_block(block *dst, const block *src)
{
    int i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        dst->v[i] ^= src->v[i];
    }
}

static void load_block(block *dst, const void *input)
{
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        dst->v[i] = load64((const uint8_t *)input + i * sizeof(dst->v[i]));
    }
}

static void store_block(void *output, const block *src)
{
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
    }
}

/***************Memory functions*****************/

int allocate_memory(const argon2_context *context, uint8_t **memory,
                    size_t num, size_t size)
{
    size_t memory_size = num*size;
    if (memory == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    /* 1. Check for multiplication overflow */
    if (size != 0 && memory_size / size != num) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    /* 2. Try to allocate with appropriate allocator */
    if (context->allocate_cbk) {
        (context->allocate_cbk)(memory, memory_size);
    } else {
        *memory = malloc(memory_size);
    }

    if (*memory == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    return ARGON2_OK;
}

void free_memory(const argon2_context *context, uint8_t *memory,
                 size_t num, size_t size)
{
    size_t memory_size = num*size;
    clear_internal_memory(memory, memory_size);
    if (context->free_cbk) {
        (context->free_cbk)(memory, memory_size);
    } else {
        free(memory);
    }
}

#if defined(__OpenBSD__)
#define HAVE_EXPLICIT_BZERO 1
#elif defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2,25)
#define HAVE_EXPLICIT_BZERO 1
#endif
#endif

void NOT_OPTIMIZED secure_wipe_memory(void *v, size_t n)
{
#if defined(_MSC_VER) && VC_GE_2005(_MSC_VER)
    SecureZeroMemory(v, n);
#elif defined memset_s
    memset_s(v, n, 0, n);
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(v, n);
#else
    static void *(*const volatile memset_sec)(void *, int, size_t) = &memset;
    memset_sec(v, 0, n);
#endif
}

/* Memory clear flag defaults to true. */
static int FLAG_clear_internal_memory = 1;
void clear_internal_memory(void *v, size_t n)
{
    if (FLAG_clear_internal_memory && v)
        secure_wipe_memory(v, n);
}

void finalize(const argon2_context *context, argon2_instance_t *instance)
{
    if (context != NULL && instance != NULL) {
        block blockhash;
        uint32_t l;

        copy_block(&blockhash, instance->memory + instance->lane_length - 1);

        /* XOR the last blocks */
        for (l = 1; l < instance->lanes; ++l) {
            uint32_t last_block_in_lane =
                l * instance->lane_length + (instance->lane_length - 1);
            xor_block(&blockhash, instance->memory + last_block_in_lane);
        }

        /* Hash the result */
        {
            uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
            store_block(blockhash_bytes, &blockhash);
            blake2b_long(context->out, context->outlen, blockhash_bytes,
                         ARGON2_BLOCK_SIZE);
            /* clear blockhash and blockhash_bytes */
            clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
            clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
        }

        free_memory(context, (uint8_t *)instance->memory,
                    instance->memory_blocks, sizeof(block));
    }
}

uint32_t index_alpha(const argon2_instance_t *instance,
                     const argon2_position_t *position, uint32_t pseudo_rand,
                     int same_lane)
{
    /*
     * Pass 0:
     *      This lane : all already finished segments plus already constructed
     * blocks in this segment
     *      Other lanes : all already finished segments
     * Pass 1+:
     *      This lane : (SYNC_POINTS - 1) last segments plus already constructed
     * blocks in this segment
     *      Other lanes : (SYNC_POINTS - 1) last segments
     */
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position, absolute_position;

    if (0 == position->pass) {
        /* First pass */
        if (0 == position->slice) {
            /* First slice */
            reference_area_size =
                position->index - 1; /* all but the previous */
        } else {
            if (same_lane) {
                /* The same lane => add current segment */
                reference_area_size =
                    position->slice * instance->segment_length +
                    position->index - 1;
            } else {
                reference_area_size =
                    position->slice * instance->segment_length +
                    ((position->index == 0) ? (-1) : 0);
            }
        }
    } else {
        /* Second pass */
        if (same_lane) {
            reference_area_size = instance->lane_length -
                                  instance->segment_length + position->index -
                                  1;
        } else {
            reference_area_size = instance->lane_length -
                                  instance->segment_length +
                                  ((position->index == 0) ? (-1) : 0);
        }
    }

    /* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
     * relative position */
    relative_position = pseudo_rand;
    relative_position = relative_position * relative_position >> 32;
    relative_position = reference_area_size - 1 -
                        (reference_area_size * relative_position >> 32);

    /* 1.2.5 Computing starting position */
    start_position = 0;

    if (0 != position->pass) {
        start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
                             ? 0
                             : (position->slice + 1) * instance->segment_length;
    }

    /* 1.2.6. Computing absolute position */
    absolute_position = (start_position + relative_position) %
                        instance->lane_length; /* absolute position */
    return absolute_position;
}


#if !defined(ARGON2_NO_THREADS) && defined(OPENSSL_THREADS)

static unsigned long CALLBACK fill_segment_thr(void *thread_data)
{
    argon2_thread_data *my_data = thread_data;
    fill_segment(my_data->instance_ptr, my_data->pos);
    CRYPTO_THREAD_exit(0);
    return 0;
}

/* Multi-threaded version for p > 1 case */
static int fill_memory_blocks_mt(argon2_instance_t *instance) {
    uint32_t r, s;
    int rc = ARGON2_OK;

    CRYPTO_THREAD * thread;
    argon2_thread_data *thr_data = NULL;

    /* 1. Allocating space for threads */
    thread = OPENSSL_zalloc(sizeof(CRYPTO_THREAD)*instance->lanes);
    if (thread == NULL) {
        rc = ARGON2_MEMORY_ALLOCATION_ERROR;
        goto fail;
    }

    thr_data = OPENSSL_zalloc(instance->lanes*sizeof(argon2_thread_data));
    if (thr_data == NULL) {
        rc = ARGON2_MEMORY_ALLOCATION_ERROR;
        goto fail;
    }

    for (r = 0; r < instance->passes; ++r) {
        for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
            uint32_t l, ll;

            /* 2. Calling threads */
            for (l = 0; l < instance->lanes; ++l) {
                argon2_position_t position;

                /* 2.1 Join a thread if limit is exceeded */
                if (l >= instance->threads) {
                    if (CRYPTO_THREAD_join(thread[l - instance->threads], NULL) != 0) {
                        rc = ARGON2_THREAD_FAIL;
                        goto fail;
                    }
                }

                /* 2.2 Create thread */
                position.pass = r;
                position.lane = l;
                position.slice = (uint8_t)s;
                position.index = 0;

                /* preparing the thread input */
                thr_data[l].instance_ptr = instance;
                memcpy(&(thr_data[l].pos), &position,
                       sizeof(argon2_position_t));

                thread[l] = CRYPTO_THREAD_new(&fill_segment_thr,
                                              (void*)&thr_data[l]);

                if (thread[l] == NULL) {
                    /* Wait for already running threads */
                    for (ll = 0; ll < l; ++ll)
                        CRYPTO_THREAD_join(thread[ll], NULL);
                    rc = ARGON2_THREAD_FAIL;
                    goto fail;
                }

                /* fill_segment(instance, position); */
                /*Non-thread equivalent of the lines above */
            }

            /* 3. Joining remaining threads */
            for (l = instance->lanes - instance->threads; l < instance->lanes;
                 ++l) {
                if (CRYPTO_THREAD_join(thread[l], NULL) != 0) {
                    rc = ARGON2_THREAD_FAIL;
                    goto fail;
                }
            }
        }
    }

fail:
    if (thr_data != NULL) {
        OPENSSL_free(thr_data);
    }
    if (thread != NULL) {
        OPENSSL_free(thread);
    }
    return rc;
}

#endif /* ARGON2_NO_THREADS OPENSSL_THREADS */

/* Single-threaded version for p=1 case */
static int fill_memory_blocks_st(argon2_instance_t *instance)
{
    uint32_t r, s, l;

    for (r = 0; r < instance->passes; ++r) {
        for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
            for (l = 0; l < instance->lanes; ++l) {
                argon2_position_t position;

                position.pass = r;
                position.lane = l;
                position.slice = (uint8_t)s;
                position.index = 0;

                fill_segment(instance, position);
            }
        }
    }
    return ARGON2_OK;
}

int fill_memory_blocks(argon2_instance_t *instance)
{
    if (instance == NULL || instance->lanes == 0)
        return ARGON2_INCORRECT_PARAMETER;

#if defined(ARGON2_NO_THREADS) || !defined(OPENSSL_THREADS)
    return fill_memory_blocks_st(instance);
#else
    return instance->threads == 1 ?
        fill_memory_blocks_st(instance) : fill_memory_blocks_mt(instance);
#endif
}

int validate_inputs(const argon2_context *context)
{
    /* due to -Werror=type-limits, some of the comparisons are made as
     * X+1 > Y+1 rather than X > Y, as this caused problems when some
     * lower limits were set to zero. */

    if (NULL == context) {
        return ARGON2_INCORRECT_PARAMETER;
    }

    if (NULL == context->out) {
        return ARGON2_OUTPUT_PTR_NULL;
    }

    /* Validate output length */
    if (ARGON2_MIN_OUTLEN > context->outlen) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }

    if (ARGON2_MAX_OUTLEN < context->outlen) {
        return ARGON2_OUTPUT_TOO_LONG;
    }

    /* Validate password (required param) */
    if (NULL == context->pwd) {
        if (0 != context->pwdlen) {
            return ARGON2_PWD_PTR_MISMATCH;
        }
    }

    if (ARGON2_MIN_PWD_LENGTH+1 > context->pwdlen+1) {
        return ARGON2_PWD_TOO_SHORT;
    }

    if (ARGON2_MAX_PWD_LENGTH < context->pwdlen) {
        return ARGON2_PWD_TOO_LONG;
    }

    /* Validate salt (required param) */
    if (NULL == context->salt) {
        if (0 != context->saltlen) {
            return ARGON2_SALT_PTR_MISMATCH;
        }
    }

    if (ARGON2_MIN_SALT_LENGTH > context->saltlen) {
        return ARGON2_SALT_TOO_SHORT;
    }

    if (ARGON2_MAX_SALT_LENGTH < context->saltlen) {
        return ARGON2_SALT_TOO_LONG;
    }

    /* Validate secret (optional param) */
    if (NULL == context->secret) {
        if (0 != context->secretlen) {
            return ARGON2_SECRET_PTR_MISMATCH;
        }
    } else {
        if (ARGON2_MIN_SECRET+1 > context->secretlen+1) {
            return ARGON2_SECRET_TOO_SHORT;
        }
        if (ARGON2_MAX_SECRET < context->secretlen) {
            return ARGON2_SECRET_TOO_LONG;
        }
    }

    /* Validate associated data (optional param) */
    if (NULL == context->ad) {
        if (0 != context->adlen) {
            return ARGON2_AD_PTR_MISMATCH;
        }
    } else {
        if (ARGON2_MIN_AD_LENGTH+1 > context->adlen+1) {
            return ARGON2_AD_TOO_SHORT;
        }
        if (ARGON2_MAX_AD_LENGTH < context->adlen) {
            return ARGON2_AD_TOO_LONG;
        }
    }

    /* Validate memory cost */
    if (ARGON2_MIN_MEMORY > context->m_cost) {
        return ARGON2_MEMORY_TOO_LITTLE;
    }

    /* again, Werror typelimits */
    if ((unsigned long long) ARGON2_MAX_MEMORY <= ((unsigned long long)context->m_cost)) {
        if ((unsigned long long) ARGON2_MAX_MEMORY != ((unsigned long long)context->m_cost)) {
            return ARGON2_MEMORY_TOO_MUCH;
        }
    }

    if (context->m_cost < 8 * context->lanes) {
        return ARGON2_MEMORY_TOO_LITTLE;
    }

    /* Validate time cost */
    if (ARGON2_MIN_TIME > context->t_cost) {
        return ARGON2_TIME_TOO_SMALL;
    }

    if (ARGON2_MAX_TIME < context->t_cost) {
        return ARGON2_TIME_TOO_LARGE;
    }

    /* Validate lanes */
    if (ARGON2_MIN_LANES > context->lanes) {
        return ARGON2_LANES_TOO_FEW;
    }

    if (ARGON2_MAX_LANES < context->lanes) {
        return ARGON2_LANES_TOO_MANY;
    }

    /* Validate threads */
    if (ARGON2_MIN_THREADS > context->threads) {
        return ARGON2_THREADS_TOO_FEW;
    }

    if (ARGON2_MAX_THREADS < context->threads) {
        return ARGON2_THREADS_TOO_MANY;
    }

    if (NULL != context->allocate_cbk && NULL == context->free_cbk) {
        return ARGON2_FREE_MEMORY_CBK_NULL;
    }

    if (NULL == context->allocate_cbk && NULL != context->free_cbk) {
        return ARGON2_ALLOCATE_MEMORY_CBK_NULL;
    }

    return ARGON2_OK;
}

void fill_first_blocks(uint8_t *blockhash, const argon2_instance_t *instance)
{
    uint32_t l;
    /* Make the first and second block in each lane as G(H0||0||i) or
       G(H0||1||i) */
    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
    for (l = 0; l < instance->lanes; ++l) {
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
        blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash,
                     ARGON2_PREHASH_SEED_LENGTH);
        load_block(&instance->memory[l * instance->lane_length + 0],
                   blockhash_bytes);
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
        blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash,
                     ARGON2_PREHASH_SEED_LENGTH);
        load_block(&instance->memory[l * instance->lane_length + 1],
                   blockhash_bytes);
    }
    clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
}

void initial_hash(uint8_t *blockhash, argon2_context *context,
                  argon2_type type)
{
    EVP_MD_CTX *mdctx;
    uint8_t value[sizeof(uint32_t)];
    unsigned int outlen_tmp;

    if (NULL == context || NULL == blockhash) {
        return;
    }

    if((mdctx = EVP_MD_CTX_create()) == NULL) {
        goto fail;
    }
    if(1 != EVP_DigestInit_ex(mdctx, EVP_blake2b512(), NULL)) {
        goto fail;
    }

    store32((uint8_t *) &value, context->lanes);
    if(1 != EVP_DigestUpdate(mdctx, &value, sizeof(value))) {
        goto fail;
    }

    store32((uint8_t *) &value, context->outlen);
    if(1 != EVP_DigestUpdate(mdctx, &value, sizeof(value))) {
        goto fail;
    }

    store32((uint8_t *) &value, context->m_cost);
    if(1 != EVP_DigestUpdate(mdctx, &value, sizeof(value))) {
        goto fail;
    }

    store32((uint8_t *) &value, context->t_cost);
    if(1 != EVP_DigestUpdate(mdctx, &value, sizeof(value))) {
        goto fail;
    }

    store32((uint8_t *) &value, context->version);
    if(1 != EVP_DigestUpdate(mdctx, &value, sizeof(value))) {
        goto fail;
    }

    store32((uint8_t *) &value, (uint32_t)type);
    if(1 != EVP_DigestUpdate(mdctx, &value, sizeof(value))) {
        goto fail;
    }

    store32((uint8_t *) &value, context->pwdlen);
    if(1 != EVP_DigestUpdate(mdctx, &value, sizeof(value))) {
        goto fail;
    }

    if (context->pwd != NULL) {
        if(1 != EVP_DigestUpdate(mdctx, context->pwd, context->pwdlen)) {
            goto fail;
        }
        if (context->flags & ARGON2_FLAG_CLEAR_PASSWORD) {
            secure_wipe_memory(context->pwd, context->pwdlen);
            context->pwdlen = 0;
        }
    }

    store32((uint8_t *) &value, context->saltlen);
    if(1 != EVP_DigestUpdate(mdctx, &value, sizeof(value))) {
        goto fail;
    }

    if (context->salt != NULL) {
        if(1 != EVP_DigestUpdate(mdctx, context->salt, context->saltlen)) {
            goto fail;
        }
    }

    store32((uint8_t *) &value, context->secretlen);
    if(1 != EVP_DigestUpdate(mdctx, &value, sizeof(value))) {
        goto fail;
    }

    if (context->secret != NULL) {
        if(1 != EVP_DigestUpdate(mdctx, context->secret, context->secretlen)) {
            goto fail;
        }

        if (context->flags & ARGON2_FLAG_CLEAR_SECRET) {
            secure_wipe_memory(context->secret, context->secretlen);
            context->secretlen = 0;
        }
    }

    store32((uint8_t *) &value, context->adlen);
    if(1 != EVP_DigestUpdate(mdctx, &value, sizeof(value))) {
        goto fail;
    }

    if (context->ad != NULL) {
        if(1 != EVP_DigestUpdate(mdctx, context->ad, context->adlen)) {
            goto fail;
        }
    }

    outlen_tmp = ARGON2_PREHASH_DIGEST_LENGTH;
    if(1 != EVP_DigestFinal_ex(mdctx, blockhash, &outlen_tmp)) {
        goto fail;
    }

fail:
    EVP_MD_CTX_destroy(mdctx);
    return;
}

int initialize(argon2_instance_t *instance, argon2_context *context)
{
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    int result = ARGON2_OK;

    if (instance == NULL || context == NULL)
        return ARGON2_INCORRECT_PARAMETER;
    instance->context_ptr = context;

    /* 1. Memory allocation */
    result = allocate_memory(context, (uint8_t **)&(instance->memory),
                             instance->memory_blocks, sizeof(block));
    if (result != ARGON2_OK) {
        return result;
    }

    /* 2. Initial hashing */
    /* H_0 + 8 extra bytes to produce the first blocks */
    /* uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH]; */
    /* Hashing all inputs */
    initial_hash(blockhash, context, instance->type);
    /* Zeroing 8 extra bytes */
    clear_internal_memory(blockhash + ARGON2_PREHASH_DIGEST_LENGTH,
                          ARGON2_PREHASH_SEED_LENGTH -
                              ARGON2_PREHASH_DIGEST_LENGTH);

    /* 3. Creating first blocks, we always have at least two blocks in a slice
     */
    fill_first_blocks(blockhash, instance);
    /* Clearing the hash */
    clear_internal_memory(blockhash, ARGON2_PREHASH_SEED_LENGTH);

    return ARGON2_OK;
}
