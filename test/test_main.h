/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_TEST_MAIN_H
# define HEADER_TEST_MAIN_H

/*
 * Simple unit tests should implement register_tests() and link to test_main.c.
 */
extern void register_tests(void);

#endif  /* HEADER_TEST_MAIN_H */
