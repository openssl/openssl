/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * The ECDH software is originally written by Douglas Stebila of
 * Sun Microsystems Laboratories.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../e_os.h"

#include <openssl/opensslconf.h> /* for OPENSSL_NO_EC */
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#ifdef OPENSSL_NO_EC
int main(int argc, char *argv[])
{
    printf("No ECDH support\n");
    return (0);
}
#else
# include <openssl/ec.h>

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

int main(int argc, char *argv[])
{
    int ret = 1;
    BIO *out;

    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof rnd_seed);

    out = BIO_new(BIO_s_file());
    if (out == NULL)
        EXIT(1);
    BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);

    /* NAMED CURVES TESTS: moved to evptests.txt */

    /* KATs: moved to evptests.txt  */

    /* NIST SP800-56A co-factor ECDH KATs: moved to evptests.txt */

    ret = 0;

 err:
    ERR_print_errors_fp(stderr);
    BIO_free(out);

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks_fp(stderr) <= 0)
        ret = 1;
#endif
    EXIT(ret);
}
#endif
