/*
 * Copyright 2001-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"

#if defined(OPENSSL_SYS_VMS)
# include <openssl/rand.h>
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

int RAND_poll_ex(RAND_poll_cb rand_add, void *arg)
{
    /* determine the number of items in the JPI array */
    struct items_data_st item_entry;
    int item_entry_count = OSSL_NELEM(items_data);
    /* Create the JPI itemlist array to hold item_data content */
    struct {
        short length, code;
        int *buffer;
        int *retlen;
    } item[item_entry_count], *pitem;
    struct items_data_st *pitems_data;
    int data_buffer[(item_entry_count * 2) + 4]; /* 8 bytes per entry max */
    int iosb[2];
    int sys_time[2];
    int *ptr;
    int i, j ;
    int tmp_length   = 0;
    int total_length = 0;

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

    /* size of seed is total_length*4 bytes (64bytes) */
    rand_add(arg, (PTR_T)data_buffer, total_length * 4, total_length * 2);
    return 1;
}

#endif
