/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"

#if defined(OPENSSL_SYS_VMS)
# include <unistd.h>
# include "internal/cryptlib.h"
# include <openssl/rand.h>
# include "internal/rand_int.h"
# include "rand_lcl.h"
# include <descrip.h>
# include <jpidef.h>
# include <ssdef.h>
# include <starlet.h>
# include <efndef>
# ifdef __DECC
#  pragma message disable DOLLARID
# endif

# ifndef OPENSSL_RAND_SEED_OS
#  error "Unsupported seeding method configured; must be os"
# endif

/*
 * Use 32-bit pointers almost everywhere.  Define the type to which to cast a
 * pointer passed to an external function.
 */
# if __INITIAL_POINTER_SIZE == 64
#  define PTR_T __void_ptr64
#  pragma pointer_size save
#  pragma pointer_size 32
# else
#  define PTR_T void *
# endif

static struct items_data_st {
    short length, code;         /* length is number of bytes */
} items_data[] = {
    {4, JPI$_BUFIO},
    {4, JPI$_CPUTIM},
    {4, JPI$_DIRIO},
    {4, JPI$_IMAGECOUNT},
    {8, JPI$_LAST_LOGIN_I},
    {8, JPI$_LOGINTIM},
    {4, JPI$_PAGEFLTS},
    {4, JPI$_PID},
    {4, JPI$_PPGCNT},
    {4, JPI$_WSPEAK},
    {4, JPI$_FINALEXC},
    {0, 0}
};

/*
 * We assume there we get about 4 bits of entropy per byte from the items
 * above, with a bit of scrambling added rand_pool_acquire_entropy()
 */
#define ENTROPY_BITS_PER_BYTE   4

size_t rand_pool_acquire_entropy(RAND_POOL *pool)
{
    /* determine the number of items in the JPI array */
    struct items_data_st item_entry;
    size_t item_entry_count = OSSL_NELEM(items_data);
    /* Create the 32-bit JPI itemlist array to hold item_data content */
    struct {
        uint16_t length, code;
        uint32_t *buffer;
        uint32_t *retlen;
    } item[item_entry_count], *pitem;
    struct items_data_st *pitems_data;
    /* 8 bytes (two longs) per entry max */
    uint32_t data_buffer[(item_entry_count * 2) + 4];
    uint32_t iosb[2];
    uint32_t sys_time[2];
    uint32_t *ptr;
    size_t i, j ;
    size_t tmp_length   = 0;
    size_t total_length = 0;
    size_t bytes_needed = rand_pool_bytes_needed(pool, ENTROPY_BITS_PER_BYTE);
    size_t bytes_remaining = rand_pool_bytes_remaining(pool);

    /* Setup itemlist for GETJPI */
    pitems_data = items_data;
    for (pitem = item; pitems_data->length != 0; pitem++) {
        pitem->length = pitems_data->length;
        pitem->code   = pitems_data->code;
        pitem->buffer = &data_buffer[total_length];
        pitem->retlen = 0;
        /* total_length is in longwords */
        total_length += pitems_data->length / 4;
        pitems_data++;
    }
    pitem->length = pitem->code = 0;

    /* Fill data_buffer with various info bits from this process */
    if (sys$getjpiw(EFN$C_ENF, NULL, NULL, item, &iosb, 0, 0) != SS$_NORMAL)
        return 0;

    /* Now twist that data to seed the SSL random number init */
    for (i = 0; i < total_length; i++) {
        sys$gettim((struct _generic_64 *)&sys_time[0]);
        srand(sys_time[0] * data_buffer[0] * data_buffer[1] + i);

        if (i == (total_length - 1)) { /* for JPI$_FINALEXC */
            ptr = &data_buffer[i];
            for (j = 0; j < 4; j++) {
                data_buffer[i + j] = ptr[j];
                /* OK to use rand() just to scramble the seed */
                data_buffer[i + j] ^= (sys_time[0] ^ rand());
                tmp_length++;
            }
        } else {
            /* OK to use rand() just to scramble the seed */
            data_buffer[i] ^= (sys_time[0] ^ rand());
        }
    }

    total_length += (tmp_length - 1);

    /* Change the total length to number of bytes */
    total_length *= 4;

    /*
     * If we can't feed the requirements from the caller, we're in deep trouble.
     */
    if (!ossl_assert(total_length >= bytes_needed)) {
        char neededstr[20];
        char availablestr[20];

        BIO_snprintf(neededstr, sizeof(neededstr), "%zu", bytes_needed);
        BIO_snprintf(availablestr, sizeof(availablestr), "%zu", total_length);
        RANDerr(RAND_F_RAND_POOL_ACQUIRE_ENTROPY,
                RAND_R_RANDOM_POOL_UNDERFLOW);
        ERR_add_error_data(4, "Needed: ", neededstr, ", Available: ",
                           availablestr);
        return 0;
    }

    /*
     * Try not to overfeed the pool
     */
    if (total_length > bytes_remaining)
        total_length = bytes_remaining;

    rand_pool_add(pool, (PTR_T)data_buffer, total_length,
                  total_length * ENTROPY_BITS_PER_BYTE);
    return rand_pool_entropy_available(pool);
}

int rand_pool_add_nonce_data(RAND_POOL *pool)
{
    struct {
        pid_t pid;
        CRYPTO_THREAD_ID tid;
        uint64_t time;
    } data = { 0 };

    /*
     * Add process id, thread id, and a high resolution timestamp to
     * ensure that the nonce is unique whith high probability for
     * different process instances.
     */
    data.pid = getpid();
    data.tid = CRYPTO_THREAD_get_current_id();
    sys$gettim_prec((struct _generic_64 *)&data.time);

    return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}

int rand_pool_add_additional_data(RAND_POOL *pool)
{
    struct {
        CRYPTO_THREAD_ID tid;
        uint64_t time;
    } data = { 0 };

    /*
     * Add some noise from the thread id and a high resolution timer.
     * The thread id adds a little randomness if the drbg is accessed
     * concurrently (which is the case for the <master> drbg).
     */
    data.tid = CRYPTO_THREAD_get_current_id();
    sys$gettim_prec((struct _generic_64 *)&data.time);

    return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}

#endif
