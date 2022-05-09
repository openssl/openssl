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
#if defined(OPENSSL_USE_IPV6)
    struct in6_addr xa6, xb6;
#endif
    void *pa, *pb;
    size_t slen, tmplen;

    if (BIO_ADDR_family(a) != BIO_ADDR_family(b))
        return 0;

    if (BIO_ADDR_family(a) == AF_INET) {
        pa = &xa;
        pb = &xb;
        slen = sizeof(xa);
    }
#if defined(OPENSSL_USE_IPV6)
    else if (BIO_ADDR_family(a) == AF_INET6) {
        pa = &xa6;
        pb = &xb6;
        slen = sizeof(xa6);
    }
#endif
    else {
        return 0;
    }

    tmplen = slen;
    if (!TEST_int_eq(BIO_ADDR_rawaddress(a, pa, &tmplen), 1))
        return 0;

    tmplen = slen;
    if (!TEST_int_eq(BIO_ADDR_rawaddress(b, pb, &tmplen), 1))
        return 0;

    if (!TEST_mem_eq(pa, slen, pb, slen))
        return 0;

    if (!TEST_int_eq(BIO_ADDR_rawport(a), BIO_ADDR_rawport(b)))
        return 0;

    return 1;
}

static int do_sendmmsg(BIO *b, BIO_MSG *msg,
                       size_t num_msg, uint64_t flags,
                       size_t *num_processed)
{
    size_t done;

    for (done = 0; done < num_msg; ) {
        if (!BIO_sendmmsg(b, msg + done, sizeof(BIO_MSG),
                          num_msg - done, flags, num_processed))
            return 0;

        done += *num_processed;
    }

    *num_processed = done;
    return 1;
}

static int do_recvmmsg(BIO *b, BIO_MSG *msg,
                       size_t num_msg, uint64_t flags,
                       size_t *num_processed)
{
    size_t done;

    for (done = 0; done < num_msg; ) {
        if (!BIO_recvmmsg(b, msg + done, sizeof(BIO_MSG),
                          num_msg - done, flags, num_processed))
            return 0;

        done += *num_processed;
    }

    *num_processed = done;
    return 1;
}

static int test_bio_dgram_impl(int af, int use_local)
{
    int testresult = 0;
    BIO *b1 = NULL, *b2 = NULL;
    int fd1 = -1, fd2 = -1;
    BIO_ADDR *addr1 = NULL, *addr2 = NULL, *addr3 = NULL, *addr4 = NULL,
             *addr5 = NULL, *addr6 = NULL;
    struct in_addr ina = {0};
#if defined(OPENSSL_USE_IPV6)
    struct in6_addr ina6 = {0};
#endif
    void *pina;
    size_t inal, i;
    union BIO_sock_info_u info1 = {0}, info2 = {0};
    char rx_buf[128], rx_buf2[128];
    BIO_MSG tx_msg[128], rx_msg[128];
    char tx_buf[128];
    size_t num_processed = 0;

    ina.s_addr = htonl(0x7f000001UL);
    ina6.s6_addr[15] = 1;

    if (af == AF_INET) {
        TEST_info("# Testing with AF_INET, local=%d\n", use_local);
        pina = &ina;
        inal = sizeof(ina);
    }
#if defined(OPENSSL_USE_IPV6)
    else if (af == AF_INET6) {
        TEST_info("# Testing with AF_INET6, local=%d\n", use_local);
        pina = &ina6;
        inal = sizeof(ina6);
    }
#endif
    else {
        goto err;
    }

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

    addr5 = BIO_ADDR_new();
    if (!TEST_ptr(addr5))
        goto err;

    addr6 = BIO_ADDR_new();
    if (!TEST_ptr(addr6))
        goto err;

    if (!TEST_int_eq(BIO_ADDR_rawmake(addr1, af, pina, inal, 0), 1))
        goto err;

    if (!TEST_int_eq(BIO_ADDR_rawmake(addr2, af, pina, inal, 0), 1))
        goto err;

    fd1 = BIO_socket(af, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(fd1, 0))
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

    if (!TEST_mem_eq(rx_buf, 5, "hello", 5))
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

    tx_msg[1].data      = "orange";
    tx_msg[1].data_len  = 6;
    tx_msg[1].peer      = NULL;
    tx_msg[1].local     = NULL;
    tx_msg[1].flags     = 0;

    /* First effort should fail due to missing destination address */
    if (!TEST_false(do_sendmmsg(b1, tx_msg, 2, 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 0))
        goto err;

    /*
     * Second effort should fail due to local being requested
     * when not enabled
     */
    tx_msg[0].peer  = addr2;
    tx_msg[0].local = addr1;
    tx_msg[1].peer  = addr2;
    tx_msg[1].local = addr1;
    if (!TEST_false(do_sendmmsg(b1, tx_msg, 2, 0, &num_processed)
        || !TEST_size_t_eq(num_processed, 0)))
        goto err;

    /* Enable local if we are using it */
    if (BIO_dgram_get_local_addr_cap(b1) > 0 && use_local) {
        if (!TEST_int_eq(BIO_dgram_set_local_addr_enable(b1, 1), 1))
            goto err;
    } else {
        tx_msg[0].local = NULL;
        tx_msg[1].local = NULL;
        use_local = 0;
    }

    /* Third effort should succeed */
    if (!TEST_true(do_sendmmsg(b1, tx_msg, 2, 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 2))
        goto err;

    /* Now try receiving */
    rx_msg[0].data      = rx_buf;
    rx_msg[0].data_len  = sizeof(rx_buf);
    rx_msg[0].peer      = addr3;
    rx_msg[0].local     = addr4;
    rx_msg[0].flags     = (1UL<<31); /* undefined flag, should be erased */
    memset(rx_buf, 0, sizeof(rx_buf));

    rx_msg[1].data      = rx_buf2;
    rx_msg[1].data_len  = sizeof(rx_buf2);
    rx_msg[1].peer      = addr5;
    rx_msg[1].local     = addr6;
    rx_msg[1].flags     = (1UL<<31); /* undefined flag, should be erased */
    memset(rx_buf2, 0, sizeof(rx_buf2));

    /*
     * Should fail at first due to local being requested when not
     * enabled
     */
    if (!TEST_false(do_recvmmsg(b2, rx_msg, 2, 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 0))
        goto err;

    /* Fields have not been modified */
    if (!TEST_int_eq((int)rx_msg[0].data_len, sizeof(rx_buf)))
        goto err;

    if (!TEST_int_eq((int)rx_msg[1].data_len, sizeof(rx_buf2)))
        goto err;

    if (!TEST_ulong_eq((unsigned long)rx_msg[0].flags, 1UL<<31))
        goto err;

    if (!TEST_ulong_eq((unsigned long)rx_msg[1].flags, 1UL<<31))
        goto err;

    /* Enable local if we are using it */
    if (BIO_dgram_get_local_addr_cap(b2) > 0 && use_local) {
        if (!TEST_int_eq(BIO_dgram_set_local_addr_enable(b2, 1), 1))
            goto err;
    } else {
        rx_msg[0].local = NULL;
        rx_msg[1].local = NULL;
        use_local = 0;
    }

    /* Do the receive. */
    if (!TEST_true(do_recvmmsg(b2, rx_msg, 2, 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 2))
        goto err;

    /* data_len should have been updated correctly */
    if (!TEST_int_eq((int)rx_msg[0].data_len, 5))
        goto err;

    if (!TEST_int_eq((int)rx_msg[1].data_len, 6))
        goto err;

    /* flags should have been zeroed */
    if (!TEST_int_eq((int)rx_msg[0].flags, 0))
        goto err;

    if (!TEST_int_eq((int)rx_msg[1].flags, 0))
        goto err;

    /* peer address should match expected */
    if (!TEST_int_eq(compare_addr(addr3, addr1), 1))
        goto err;

    if (!TEST_int_eq(compare_addr(addr5, addr1), 1))
        goto err;

    /*
     * Do not test local address yet as some platforms do not reliably return
     * local addresses for messages queued for RX before local address support
     * was enabled. Instead, send some new messages and test they're received
     * with the correct local addresses.
     */
    if (!TEST_true(do_sendmmsg(b1, tx_msg, 2, 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 2))
        goto err;

    /* Receive the messages. */
    rx_msg[0].data_len = sizeof(rx_buf);
    rx_msg[1].data_len = sizeof(rx_buf2);

    if (!TEST_true(do_recvmmsg(b2, rx_msg, 2, 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 2))
        goto err;

    if (rx_msg[0].local != NULL) {
        /* If we are using local, it should match expected */
        if (!TEST_int_eq(compare_addr(addr4, addr2), 1))
            goto err;

        if (!TEST_int_eq(compare_addr(addr6, addr2), 1))
            goto err;
    }

    /*
     * Try sending more than can be handled in one sendmmsg call (when using the
     * sendmmsg implementation)
     */
    for (i = 0; i < OSSL_NELEM(tx_msg); ++i) {
        tx_buf[i] = (char)i;
        tx_msg[i].data      = tx_buf + i;
        tx_msg[i].data_len  = 1;
        tx_msg[i].peer      = addr2;
        tx_msg[i].local     = use_local ? addr1 : NULL;
        tx_msg[i].flags     = 0;
    }
    if (!TEST_true(do_sendmmsg(b1, tx_msg, OSSL_NELEM(tx_msg), 0, &num_processed))
        || !TEST_size_t_eq(num_processed, OSSL_NELEM(tx_msg)))
        goto err;

    /*
     * Try receiving more than can be handled in one recvmmsg call (when using
     * the recvmmsg implementation)
     */
    for (i = 0; i < OSSL_NELEM(rx_msg); ++i) {
        rx_buf[i] = '\0';
        rx_msg[i].data      = rx_buf + i;
        rx_msg[i].data_len  = 1;
        rx_msg[i].peer      = NULL;
        rx_msg[i].local     = NULL;
        rx_msg[i].flags     = 0;
    }
    if (!TEST_true(do_recvmmsg(b2, rx_msg, OSSL_NELEM(rx_msg), 0, &num_processed))
        || !TEST_size_t_eq(num_processed, OSSL_NELEM(rx_msg)))
        goto err;

    if (!TEST_mem_eq(tx_buf, OSSL_NELEM(tx_msg), rx_buf, OSSL_NELEM(tx_msg)))
        goto err;

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
    BIO_ADDR_free(addr5);
    BIO_ADDR_free(addr6);
    return testresult;
}

struct bio_dgram_case {
    int af, local;
};

static const struct bio_dgram_case bio_dgram_cases[] = {
    /* Test without local */
    { AF_INET,  0 },
#if defined(OPENSSL_USE_IPV6)
    { AF_INET6, 0 },
#endif
    /* Test with local */
    { AF_INET,  1 },
#if defined(OPENSSL_USE_IPV6)
    { AF_INET6, 1 }
#endif
};

static int test_bio_dgram(int idx)
{
    return test_bio_dgram_impl(bio_dgram_cases[idx].af,
                               bio_dgram_cases[idx].local);
}

#endif /* !defined(OPENSSL_NO_DGRAM) && !defined(OPENSSL_NO_SOCK) */

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

#if !defined(OPENSSL_NO_DGRAM) && !defined(OPENSSL_NO_SOCK)
    ADD_ALL_TESTS(test_bio_dgram, OSSL_NELEM(bio_dgram_cases));
#endif
    return 1;
}
