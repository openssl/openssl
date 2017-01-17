/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "test_main_custom.h"
#include "testutil.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    int ret;
    setup_test();

    ret = test_main(argc, argv);

    return finish_test(ret);
}
