/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/bio.h>
#include "testutil.h"
#include "internal/sockets.h"

#if !defined(OPENSSL_NO_DGRAM) && !defined(OPENSSL_NO_SOCK)

static int compare_addr(const BIO_ADDR *a, const BIO_ADDR *b)
{
    struct in_addr xa, xb;
    struct in6_addr xa6, xb6;
    void *pa, *pb;
    size_t slen, tmplen;

    if (BIO_ADDR_family(a) != BIO_ADDR_family(b))
        return 0;

    if (BIO_ADDR_family(a) == AF_INET) {
        pa = &xa;
        pb = &xb;
        slen = sizeof(xa);
    } else if (BIO_ADDR_family(a) == AF_INET6) {
        pa = &xa6;
        pb = &xb6;
        slen = sizeof(xa6);
    } else
        return 0;

    tmplen = slen;
    if (BIO_ADDR_rawaddress(a, pa, &tmplen) < 1)
        return 0;

    tmplen = slen;
    if (BIO_ADDR_rawaddress(b, pb, &tmplen) < 1)
        return 0;

    if (memcmp(pa, pb, slen))
        return 0;

    if (BIO_ADDR_rawport(a) != BIO_ADDR_rawport(b))
        return 0;

    return 1;
}

static int test_bio_dgram_impl(int af, int use_local)
{
    int testresult = 0;
    ossl_ssize_t ret;
    BIO *b1 = NULL, *b2 = NULL;
    int fd1 = -1, fd2 = -1;
    BIO_ADDR *addr1 = NULL, *addr2 = NULL, *addr3 = NULL, *addr4 = NULL;
    struct in_addr ina = {htonl(0x7f000001UL)};
    struct in6_addr ina6 = {0};
    void *pina;
    size_t inal; 
    union BIO_sock_info_u info1 = {0}, info2 = {0};
    char rx_buf[64];
    BIO_MSG tx_msg[2], rx_msg[2];

    ina6.s6_addr[15] = 1;

    if (af == AF_INET) {
        printf("# Testing with AF_INET, local=%d\n", use_local);
        pina = &ina;
        inal = sizeof(ina);
    } else if (af == AF_INET6) {
        printf("# Testing with AF_INET6, local=%d\n", use_local);
        pina = &ina6;
        inal = sizeof(ina6);
    } else
        goto err;

    addr1 = BIO_ADDR_new();
    if (!TEST_ptr(addr1))
        goto err;

    addr2 = BIO_ADDR_new();
    if (!TEST_ptr(addr2))
        goto err;

    addr3 = BIO_ADDR_new();
    if (!TEST_ptr(addr3))
        goto err;

    addr4 = BIO_ADDR_new();
    if (!TEST_ptr(addr4))
        goto err;

    if (BIO_ADDR_rawmake(addr1, af, pina, inal, 0) < 1)
        goto err;

    if (BIO_ADDR_rawmake(addr2, af, pina, inal, 0) < 1)
        goto err;

    fd1 = BIO_socket(af, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (fd1 < 0)
        goto err;

    fd2 = BIO_socket(af, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(fd2, 0))
        goto err;

    if (!TEST_int_gt(BIO_bind(fd1, addr1, 0), 0))
        goto err;

    if (!TEST_int_gt(BIO_bind(fd2, addr2, 0), 0))
        goto err;

    info1.addr = addr1;
    if (!TEST_int_gt(BIO_sock_info(fd1, BIO_SOCK_INFO_ADDRESS, &info1), 0))
        goto err;

    info2.addr = addr2;
    if (!TEST_int_gt(BIO_sock_info(fd2, BIO_SOCK_INFO_ADDRESS, &info2), 0))
        goto err;

    if (!TEST_int_gt(BIO_ADDR_rawport(addr1), 0))
        goto err;

    if (!TEST_int_gt(BIO_ADDR_rawport(addr2), 0))
        goto err;

    b1 = BIO_new_dgram(fd1, 0);
    if (!TEST_ptr(b1))
        goto err;

    b2 = BIO_new_dgram(fd2, 0);
    if (!TEST_ptr(b2))
        goto err;

    if (!TEST_int_gt(BIO_dgram_set_peer(b1, addr2), 0))
        goto err;

    if (!TEST_int_gt(BIO_write(b1, "hello", 5), 0))
        goto err;

    /* Receiving automatically sets peer as source addr */
    if (!TEST_int_eq(BIO_read(b2, rx_buf, sizeof(rx_buf)), 5))
        goto err;

    if (!TEST_int_eq(memcmp(rx_buf, "hello", 5), 0))
        goto err;

    if (!TEST_int_gt(BIO_dgram_get_peer(b2, addr3), 0))
        goto err;

    if (!TEST_int_eq(compare_addr(addr3, addr1), 1))
        goto err;

    /* Clear peer */
    if (!TEST_int_gt(BIO_ADDR_rawmake(addr3, af, pina, inal, 0), 0))
        goto err;

    if (!TEST_int_gt(BIO_dgram_set_peer(b1, addr3), 0))
        goto err;

    if (!TEST_int_gt(BIO_dgram_set_peer(b2, addr3), 0))
        goto err;

    /* Now test using sendmmsg/recvmmsg with no peer set */
    tx_msg[0].data      = "apple";
    tx_msg[0].data_len  = 5;
    tx_msg[0].peer      = NULL;
    tx_msg[0].local     = NULL;
    tx_msg[0].flags     = 0;

    /* First effort should fail due to missing destination address */
    ret = BIO_sendmmsg(b1, tx_msg, sizeof(BIO_MSG), 1, 0);
    if (!TEST_int_le(ret, -32))
        goto err;

    /*
     * Second effort should fail due to local being requested
     * when not enabled
     */
    tx_msg[0].peer  = addr2;
    tx_msg[0].local = addr1;
    ret = BIO_sendmmsg(b1, tx_msg, sizeof(BIO_MSG), 1, 0);
    if (!TEST_int_eq(ret, -3))
        goto err;

    /* Enable local if we are using it */
    if (BIO_dgram_get_local_addr_cap(b1) > 0 && use_local) {
        if (!TEST_int_eq(BIO_dgram_set_local_addr_enable(b1, 1), 1))
            goto err;
    } else {
        tx_msg[0].local = NULL;
    }

    /* Third effort should succeed */
    ret = BIO_sendmmsg(b1, tx_msg, sizeof(BIO_MSG), 1, 0);
    if (!TEST_int_eq(ret, 1))
        goto err;

    /* Now try receiving */
    rx_msg[0].data      = rx_buf;
    rx_msg[0].data_len  = sizeof(rx_buf);
    rx_msg[0].peer      = addr3;
    rx_msg[0].local     = addr4;
    rx_msg[0].flags     = (1UL<<31); /* undefined flag, should be erased */

    memset(rx_buf, 0, sizeof(rx_buf));

    /*
     * Should fail at first due to local being requested when not
     * enabled
     */
    ret = BIO_recvmmsg(b2, rx_msg, sizeof(BIO_MSG), 1, 0);
    if (!TEST_int_eq(ret, -3))
        goto err;

    /* Fields have not been modified */
    if (!TEST_int_eq(rx_msg[0].data_len, sizeof(rx_buf)))
        goto err;

    if (!TEST_ulong_eq(rx_msg[0].flags, 1UL<<31))
        goto err;

    /* Enable local if we are using it */
    if (BIO_dgram_get_local_addr_cap(b2) > 0 && use_local) {
        if (!TEST_int_eq(BIO_dgram_set_local_addr_enable(b2, 1), 1))
            goto err;
    } else {
        rx_msg[0].local = NULL;
    }

    /* Do the receive. */
    ret = BIO_recvmmsg(b2, rx_msg, sizeof(BIO_MSG), 1, 0);
    if (!TEST_int_eq(ret, 1))
        goto err;

    /* data_len should have been updated correctly */
    if (!TEST_int_eq(rx_msg[0].data_len, 5))
        goto err;

    /* flags should have been zeroed */
    if (!TEST_int_eq(rx_msg[0].flags, 0))
        goto err;

    /* peer address should match expected */
    if (!TEST_int_eq(compare_addr(addr3, addr1), 1))
        goto err;

    if (rx_msg[0].local != NULL) {
        /* If we are using local, it should match expected */
        if (!TEST_int_eq(compare_addr(addr4, addr2), 1))
            goto err;
    }

    testresult = 1;
err:
    BIO_free(b1);
    BIO_free(b2);
    if (fd1 >= 0)
        BIO_closesocket(fd1);
    if (fd2 >= 0)
        BIO_closesocket(fd2);
    BIO_ADDR_free(addr1);
    BIO_ADDR_free(addr2);
    BIO_ADDR_free(addr3);
    BIO_ADDR_free(addr4);
    return testresult;
}

static int test_bio_dgram(void)
{
    /* Test without local */
    if (test_bio_dgram_impl(AF_INET, 0) < 1)
        return 0;

    if (test_bio_dgram_impl(AF_INET6, 0) < 1)
        return 0;

    /* Test with local */
    if (test_bio_dgram_impl(AF_INET, 1) < 1)
        return 0;

    if (test_bio_dgram_impl(AF_INET6, 1) < 1)
        return 0;

    return 1;
}

#endif

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

#if !defined(OPENSSL_NO_DGRAM) && !defined(OPENSSL_NO_SOCK)
    ADD_TEST(test_bio_dgram);
#endif
    return 1;
}
