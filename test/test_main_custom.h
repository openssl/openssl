/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_TEST_MAIN_CUSTOM_H
# define HEADER_TEST_MAIN_CUSTOM_H

/*
 * Unit tests that need a custom main() should implement test_main and link to
 * test_main_custom.c
 * test_main() should return the result of run_tests().
 */
extern int test_main(int argc, char *argv[]);

#endif  /* HEADER_TEST_MAIN_CUSTOM_H */
