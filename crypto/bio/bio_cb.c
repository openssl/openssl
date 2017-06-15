/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bio_lcl.h"
#include "internal/cryptlib.h"
#include <openssl/err.h>

long BIO_debug_callback(BIO *bio, int cmd, const char *argp,
                        int argi, long argl, long ret)
{
    BIO *b;
    char buf[256];
    char *p;
    long r = 1;
    int len;

    if (BIO_CB_RETURN & cmd)
        r = ret;

    len = sprintf(buf, "BIO[%p]: ", (void *)bio);

    /* Ignore errors and continue printing the other information. */
    if (len < 0)
        len = 0;
    p = buf + len;

    switch (cmd) {
    case BIO_CB_FREE:
        sprintf(p, "Free - %s\n", bio->method->name);
        break;
    case BIO_CB_READ:
        if (bio->method->type & BIO_TYPE_DESCRIPTOR)
            sprintf(p, "read(%d,%lu) - %s fd=%d\n",
                    bio->num, (unsigned long)argi,
                    bio->method->name, bio->num);
        else
            sprintf(p, "read(%d,%lu) - %s\n",
                    bio->num, (unsigned long)argi, bio->method->name);
        break;
    case BIO_CB_WRITE:
        if (bio->method->type & BIO_TYPE_DESCRIPTOR)
            sprintf(p, "write(%d,%lu) - %s fd=%d\n",
                    bio->num, (unsigned long)argi,
                    bio->method->name, bio->num);
        else
            sprintf(p, "write(%d,%lu) - %s\n",
                    bio->num, (unsigned long)argi, bio->method->name);
        break;
    case BIO_CB_PUTS:
        sprintf(p, "puts() - %s\n", bio->method->name);
        break;
    case BIO_CB_GETS:
        sprintf(p, "gets(%lu) - %s\n", (unsigned long)argi,
                bio->method->name);
        break;
    case BIO_CB_CTRL:
        sprintf(p, "ctrl(%lu) - %s\n", (unsigned long)argi,
                bio->method->name);
        break;
    case BIO_CB_RETURN | BIO_CB_READ:
        sprintf(p, "read return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_WRITE:
        sprintf(p, "write return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_GETS:
        sprintf(p, "gets return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_PUTS:
        sprintf(p, "puts return %ld\n", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_CTRL:
        sprintf(p, "ctrl return %ld\n", ret);
        break;
    default:
        sprintf(p, "bio callback - unknown type (%d)\n", cmd);
        break;
    }

    b = (BIO *)bio->cb_arg;
    if (b != NULL)
        BIO_write(b, buf, strlen(buf));
#if !defined(OPENSSL_NO_STDIO)
    else
        fputs(buf, stderr);
#endif
    return (r);
}
