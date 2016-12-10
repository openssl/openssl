/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/rand.h>
#include "rand_lcl.h"

#if defined(OPENSSL_SYS_VMS)

# include <descrip.h>
# include <jpidef.h>
# include <ssdef.h>
# include <starlet.h>
# ifdef __DECC
#  pragma message disable DOLLARID
# endif

/*
 * Use 32-bit pointers almost everywhere.  Define the type to which to cast a
 * pointer passed to an external function.
 */
# if __INITIAL_POINTER_SIZE == 64
#  define PTR_T __void_ptr64
#  pragma pointer_size save
#  pragma pointer_size 32
# else                          /* __INITIAL_POINTER_SIZE == 64 */
#  define PTR_T void *
# endif                         /* __INITIAL_POINTER_SIZE == 64 [else] */

static struct items_data_st {
    short length, code;         /* length is amount of bytes */
} items_data[] = {
    {
        4, JPI$_BUFIO
    },
    {
        4, JPI$_CPUTIM
    },
    {
        4, JPI$_DIRIO
    },
    {
        8, JPI$_LOGINTIM
    },
    {
        4, JPI$_PAGEFLTS
    },
    {
        4, JPI$_PID
    },
    {
        4, JPI$_WSSIZE
    },
    {
        0, 0
    }
};

int RAND_poll(void)
{
    long pid, iosb[2];
    int status = 0;
    struct {
        short length, code;
        long *buffer;
        int *retlen;
    } item[32], *pitem;
    unsigned char data_buffer[256];
    short total_length = 0;
    struct items_data_st *pitems_data;

    pitems_data = items_data;
    pitem = item;

    /* Setup */
    while (pitems_data->length && (total_length + pitems_data->length <= 256)) {
        pitem->length = pitems_data->length;
        pitem->code = pitems_data->code;
        pitem->buffer = (long *)&data_buffer[total_length];
        pitem->retlen = 0;
        total_length += pitems_data->length;
        pitems_data++;
        pitem ++;
    }
    pitem->length = pitem->code = 0;

    /*
     * Scan through all the processes in the system and add entropy with
     * results from the processes that were possible to look at.
     * However, view the information as only half trustable.
     */
    pid = -1;                   /* search context */
    while ((status = sys$getjpiw(0, &pid, 0, item, iosb, 0, 0))
           != SS$_NOMOREPROC) {
        if (status == SS$_NORMAL) {
            RAND_add((PTR_T) data_buffer, total_length, total_length / 2);
        }
    }
    sys$gettim(iosb);
    RAND_add((PTR_T) iosb, sizeof(iosb), sizeof(iosb) / 2);
    return 1;
}

#endif
