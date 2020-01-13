/*
 * Copyright 2014-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "tls_local.h"

#ifndef OPENtls_NO_UNIT_TEST

static const struct opentls_tls_test_functions tls_test_functions = {
    tls_init_wbio_buffer,
    tls3_setup_buffers,
};

const struct opentls_tls_test_functions *tls_test_functions(void)
{
    return &tls_test_functions;
}

#endif
