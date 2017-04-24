/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "test_main.h"
#include "testutil.h"

#include <stdio.h>

int main(int argc, char *argv[])
{
    int ret;
    if (argc > 1)
        printf("Warning: ignoring extra command-line arguments.\n");

    setup_test();
    register_tests();
    ret = run_tests(argv[0]);

    return finish_test(ret);
}
