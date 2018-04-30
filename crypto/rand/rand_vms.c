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
# define __NEW_STARLET 1         /* New starlet definitions since VMS 7.0 */
# include <unistd.h>
# include "internal/cryptlib.h"
# include <openssl/rand.h>
# include "internal/rand_int.h"
# include "rand_lcl.h"
# include <descrip.h>
# include <dvidef.h>
# include <jpidef.h>
# include <rmidef.h>
# include <syidef.h>
# include <ssdef.h>
# include <starlet.h>
# include <efndef.h>
# include <gen64def.h>
# include <iosbdef.h>
# include <iledef.h>
# include <lib$routines.h>
# ifdef __DECC
#  pragma message disable DOLLARID
# endif

# ifndef OPENSSL_RAND_SEED_OS
#  error "Unsupported seeding method configured; must be os"
# endif

/* We need to make sure we have the right size pointer in some cases */
# if __INITIAL_POINTER_SIZE == 64
#  pragma pointer_size save
#  pragma pointer_size 32
# endif
typedef uint32_t *uint32_t__ptr32;
# if __INITIAL_POINTER_SIZE == 64
#  pragma pointer_size restore
# endif

static const struct item_st {
    short length, code;         /* length is number of bytes */
} item_data[] = {
    {4,  JPI$_BUFIO},
    {4,  JPI$_CPUTIM},
    {4,  JPI$_DIRIO},
    {4,  JPI$_IMAGECOUNT},
    {8,  JPI$_LAST_LOGIN_I},
    {8,  JPI$_LOGINTIM},
    {4,  JPI$_PAGEFLTS},
    {4,  JPI$_PID},
    {4,  JPI$_PPGCNT},
    {4,  JPI$_WSPEAK},
    /*
     * Note: the direct result is just a 32-bit address.  However, it points
     * to a list of 4 32-bit words, so we make extra space for them so we can
     * do in-place replacement of values
     */
    {16, JPI$_FINALEXC},
};

/*
 * Input:
 * items_data           - an array of lengths and codes
 * items_data_num       - number of elements in that array, minus one
 *                        (caller MUST have space for one extra NULL element)
 *
 * Output:
 * items                - pre-allocated ILE3 array to be filled.
 *                        It's assume to have items_data_num elements.
 * databuffer           - pre-allocated 32-bit word array.
 *
 * Returns the number of bytes used in databuffer
 */
static size_t prepare_item_list(const struct item_st *items_input,
                                size_t items_input_num,
                                ILE3 *items,
                                uint32_t__ptr32 databuffer)
{
    const struct item_st *pitems_input;
    ILE3 *pitems;
    size_t data_sz = 0;

    for (pitems_input = items_input, pitems = items;
         items_input_num-- > 0;
         pitems_input++, pitems++) {

        /* Special treatment of JPI$_FINALEXC */
        if (pitems->ile3$w_code == JPI$_FINALEXC)
            pitems->ile3$w_length = 4;
        else
            pitems->ile3$w_length = pitems_input->length;

        pitems->ile3$w_code   = pitems_input->code;
        pitems->ile3$ps_bufaddr = databuffer;
        pitems->ile3$ps_retlen_addr = 0;

        databuffer += pitems_input->length / sizeof(*databuffer);
        data_sz += pitems_input->length;
    }
    /* Terminating NULL entry */
    pitems->ile3$w_length = pitems->ile3$w_code = 0;

    return data_sz;
}

static void massage_JPI(ILE3 *items)
{
    /*
     * Special treatment of JPI$_FINALEXC
     * The result of that item's data buffer is a 32-bit address to a list of
     * 4 32-bit words.
     */
    for (; items->ile3$w_length != 0; items++) {
        if (items->ile3$w_code == JPI$_FINALEXC) {
            uint32_t *data = items->ile3$ps_bufaddr;
            uint32_t *ptr = (uint32_t *)*data;
            size_t j;

            /*
             * We know we made space for 4 32-bit words, so we can do in-place
             * replacement.
             */
            for (j = 0; j < 4; j++)
                data[j] = ptr[j];

            break;
        }
    }
}

/*
 * This number expresses how many bits of data contain 1 bit of entropy.
 *
 * For the moment, we assume about 0.5 entropy bits per data bit, or 1
 * bit of entropy per 2 data bits.
 */
#define ENTROPY_FACTOR  2

size_t rand_pool_acquire_entropy(RAND_POOL *pool)
{
    ILE3 items[OSSL_NELEM(item_data) + 1];
    /*
     * All items get 1 or 2 32-bit words of data, except JPI$_FINALEXC
     * We make sure that we have ample space
     */
    uint32_t data_buffer[(OSSL_NELEM(item_data)) * 2 + 4];
    size_t total_length = 0;
    size_t bytes_needed = rand_pool_bytes_needed(pool, ENTROPY_FACTOR);
    size_t bytes_remaining = rand_pool_bytes_remaining(pool);

    total_length += prepare_item_list(item_data, OSSL_NELEM(item_data),
                                      items, &data_buffer[total_length]);

    /* Fill data_buffer with various info bits from this process */
    {
        uint32_t status;

        if ((status = sys$getjpiw(EFN$C_ENF, 0, 0, items, 0, 0, 0))
            != SS$_NORMAL) {
            lib$signal(status);
            return 0;
        }
    }

    massage_JPI(items);

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

    /* We give the pessimistic value for the amount of entropy */
    rand_pool_add(pool, (unsigned char *)data_buffer, total_length,
                  total_length / ENTROPY_FACTOR);
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
    sys$gettim_prec(&data.time);

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
    sys$gettim_prec(&data.time);

    return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}

#endif
