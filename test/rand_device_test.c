/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/rand.h>
#include "testutil.h"

/*
 * This needs to be in a test executable all by itself so that it can be
 * guaranteed to run before the RAND subsystem has been initialised.
 *
 * If the random device table was used before being initialised, its
 * file descriptors were all 0 (stdin), and a random device opened at
 * that point was forgotten (and leaked) once the table was initialised.
 * Check that a random device opened by the first use of the DRBGs is
 * closed again by RAND_keep_random_devices_open(0).
 */

#if defined(OPENSSL_SYS_UNIX) && !defined(OPENSSL_SYS_VXWORKS)
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAX_FD 256

static int is_open(int fd)
{
    return fcntl(fd, F_GETFD) != -1;
}

static int test_rand_device_closed(void)
{
    unsigned char was_open[MAX_FD];
    struct stat st;
    int fd, found = 0, ret = 1;

    for (fd = 0; fd < MAX_FD; fd++)
        was_open[fd] = is_open(fd);

    if (!TEST_ptr(RAND_get0_private(NULL)))
        return 0;

    for (fd = 0; fd < MAX_FD; fd++) {
        if (was_open[fd] || fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode))
            continue;
        found = 1;
        break;
    }
    if (!found)
        return TEST_skip("no random device was opened for seeding");

    RAND_keep_random_devices_open(0);

    if (!TEST_false(is_open(fd))) {
        TEST_info("random device fd %d is still open", fd);
        ret = 0;
    }
    return ret;
}
#endif

int setup_tests(void)
{
#if defined(OPENSSL_SYS_UNIX) && !defined(OPENSSL_SYS_VXWORKS)
    ADD_TEST(test_rand_device_closed);
#endif
    return 1;
}
