/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Headers for bio_read_test, bio_write_test, for common routines in bio_dgram_test_helpers.c */

#ifndef OSSL_TEST_BIO_DGRAM_HELPERS_H
# define OSSL_TEST_BIO_DGRAM_HELPERS_H

#define PACKET_COUNT 10
extern int write_packets(BIO *bio, int count, BIO_ADDR *dst1, BIO_ADDR *dst2);
extern int fork_and_read_write_packets(int infd, int outfd,
                                       unsigned portnum,
                                       BIO_ADDR *dsthost1, BIO_ADDR *dsthost2);
extern int bind_v4_socket(int infd,
                          BIO_ADDR *dsthost);
extern int bind_v6_socket(int infd,
                          BIO_ADDR *dsthost,
                          unsigned short portnum);

/* this function is *provided* by the test case, and is difference between read/write */
extern int read_socket_and_discard(int fd, int count, unsigned short portnum);
#endif /* OSSL_TEST_ECDSATEST_H */
