/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../testutil.h"
#include "output.h"

#include <stdio.h>

int test_main(int argc, char *argv[])
{
    if (argc > 1)
        test_printf_stderr("Warning: ignoring extra command-line arguments.\n");

    register_tests();
    return run_tests(argv[0]);
}
