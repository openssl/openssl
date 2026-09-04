/*
 * Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "testutil.h"
#include "internal/sockets.h"
#include "internal/bio_addr.h"

#if !defined(OPENSSL_NO_DGRAM) && !defined(OPENSSL_NO_SOCK)

static int compare_addr(const BIO_ADDR *a, const BIO_ADDR *b)
{
    struct in_addr xa, xb;
#if OPENSSL_USE_IPV6
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
#if OPENSSL_USE_IPV6
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

    for (done = 0; done < num_msg;) {
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

    for (done = 0; done < num_msg;) {
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
    struct in_addr ina;
#if OPENSSL_USE_IPV6
    struct in6_addr ina6;
#endif
    void *pina;
    size_t inal, i;
    union BIO_sock_info_u info1 = { 0 }, info2 = { 0 };
    char rx_buf[128], rx_buf2[128];
    BIO_MSG tx_msg[128], rx_msg[128];
    char tx_buf[128];
    size_t num_processed = 0;

    if (af == AF_INET) {
        TEST_info("# Testing with AF_INET, local=%d\n", use_local);
        pina = &ina;
        inal = sizeof(ina);
    }
#if OPENSSL_USE_IPV6
    else if (af == AF_INET6) {
        TEST_info("# Testing with AF_INET6, local=%d\n", use_local);
        pina = &ina6;
        inal = sizeof(ina6);
    }
#endif
    else {
        goto err;
    }

    memset(pina, 0, inal);
    ina.s_addr = htonl(0x7f000001UL);
#if OPENSSL_USE_IPV6
    ina6.s6_addr[15] = 1;
#endif

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

    if (BIO_bind(fd1, addr1, 0) <= 0
        || BIO_bind(fd2, addr2, 0) <= 0) {
        testresult = TEST_skip("BIO_bind() failed - assuming it's an unavailable address family");
        goto err;
    }

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
    tx_msg[0].data = "apple";
    tx_msg[0].data_len = 5;
    tx_msg[0].peer = NULL;
    tx_msg[0].local = NULL;
    tx_msg[0].flags = 0;

    tx_msg[1].data = "orange";
    tx_msg[1].data_len = 6;
    tx_msg[1].peer = NULL;
    tx_msg[1].local = NULL;
    tx_msg[1].flags = 0;

    /* First effort should fail due to missing destination address */
    if (!TEST_false(do_sendmmsg(b1, tx_msg, 2, 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 0))
        goto err;

    /*
     * Second effort should fail due to local being requested
     * when not enabled
     */
    tx_msg[0].peer = addr2;
    tx_msg[0].local = addr1;
    tx_msg[1].peer = addr2;
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
    rx_msg[0].data = rx_buf;
    rx_msg[0].data_len = sizeof(rx_buf);
    rx_msg[0].peer = addr3;
    rx_msg[0].local = addr4;
    rx_msg[0].flags = (1UL << 31); /* undefined flag, should be erased */
    memset(rx_buf, 0, sizeof(rx_buf));

    rx_msg[1].data = rx_buf2;
    rx_msg[1].data_len = sizeof(rx_buf2);
    rx_msg[1].peer = addr5;
    rx_msg[1].local = addr6;
    rx_msg[1].flags = (1UL << 31); /* undefined flag, should be erased */
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

    if (!TEST_ulong_eq((unsigned long)rx_msg[0].flags, 1UL << 31))
        goto err;

    if (!TEST_ulong_eq((unsigned long)rx_msg[1].flags, 1UL << 31))
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
        tx_msg[i].data = tx_buf + i;
        tx_msg[i].data_len = 1;
        tx_msg[i].peer = addr2;
        tx_msg[i].local = use_local ? addr1 : NULL;
        tx_msg[i].flags = 0;
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
        rx_msg[i].data = rx_buf + i;
        rx_msg[i].data_len = 1;
        rx_msg[i].peer = NULL;
        rx_msg[i].local = NULL;
        rx_msg[i].flags = 0;
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
    { AF_INET, 0 },
#if OPENSSL_USE_IPV6
    { AF_INET6, 0 },
#endif
    /* Test with local */
    { AF_INET, 1 },
#if OPENSSL_USE_IPV6
    { AF_INET6, 1 }
#endif
};

static int test_bio_dgram(int idx)
{
    return test_bio_dgram_impl(bio_dgram_cases[idx].af,
        bio_dgram_cases[idx].local);
}

#if !defined(OPENSSL_NO_CHACHA)
static int random_data(const uint32_t *key, uint8_t *data, size_t data_len, size_t offset)
{
    int ret = 0, outl;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    static const uint8_t zeroes[2048];
    uint32_t counter[4] = { 0 };

    counter[0] = (uint32_t)offset;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;

    cipher = EVP_CIPHER_fetch(NULL, "ChaCha20", NULL);
    if (cipher == NULL)
        goto err;

    if (EVP_EncryptInit_ex2(ctx, cipher, (const uint8_t *)key, (uint8_t *)counter, NULL) == 0)
        goto err;

    while (data_len > 0) {
        outl = data_len > sizeof(zeroes) ? (int)sizeof(zeroes) : (int)data_len;
        if (EVP_EncryptUpdate(ctx, data, &outl, zeroes, outl) != 1)
            goto err;

        data += outl;
        data_len -= outl;
    }

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

static int test_bio_dgram_pair(int idx)
{
    int testresult = 0, blen, mtu1, mtu2, r;
    BIO *bio1 = NULL, *bio2 = NULL;
    uint8_t scratch[2048 + 4], scratch2[2048];
    uint32_t key[8];
    size_t i, num_dgram, num_processed = 0;
    BIO_MSG msgs[2], rmsgs[2];
    BIO_ADDR *addr1 = NULL, *addr2 = NULL, *addr3 = NULL, *addr4 = NULL;
    struct in_addr in_local;
    size_t total = 0;
    const uint32_t ref_caps = BIO_DGRAM_CAP_HANDLES_SRC_ADDR
        | BIO_DGRAM_CAP_HANDLES_DST_ADDR
        | BIO_DGRAM_CAP_PROVIDES_SRC_ADDR
        | BIO_DGRAM_CAP_PROVIDES_DST_ADDR;

    memset(msgs, 0, sizeof(msgs));
    memset(rmsgs, 0, sizeof(rmsgs));

    in_local.s_addr = ntohl(0x7f000001);

    for (i = 0; i < OSSL_NELEM(key); ++i)
        key[i] = test_random();

    if (idx == 0) {
        if (!TEST_int_eq(BIO_new_bio_dgram_pair(&bio1, 0, &bio2, 0), 1))
            goto err;
    } else {
        if (!TEST_ptr(bio1 = bio2 = BIO_new(BIO_s_dgram_mem())))
            goto err;
    }

    mtu1 = BIO_dgram_get_mtu(bio1);
    if (!TEST_int_ge(mtu1, 1280))
        goto err;

    if (idx == 1) {
        size_t bufsz;

        /*
         * Assume the header contains 2 BIO_ADDR structures and a length. We
         * set a buffer big enough for 9 full sized datagrams.
         */
        bufsz = 9 * (mtu1 + (sizeof(BIO_ADDR) * 2) + sizeof(size_t));
        if (!TEST_true(BIO_set_write_buf_size(bio1, (long)bufsz)))
            goto err;
    }

    mtu2 = BIO_dgram_get_mtu(bio2);
    if (!TEST_int_ge(mtu2, 1280))
        goto err;

    if (!TEST_int_eq(mtu1, mtu2))
        goto err;

    if (!TEST_int_le(mtu1, sizeof(scratch) - 4))
        goto err;

    for (i = 0; total < 1 * 1024 * 1024; ++i) {
        if (!TEST_int_eq(random_data(key, scratch, sizeof(scratch), i), 1))
            goto err;

        blen = ((*(uint32_t *)scratch) % mtu1) + 1;
        r = BIO_write(bio1, scratch + 4, blen);
        if (r == -1)
            break;

        if (!TEST_int_eq(r, blen))
            goto err;

        total += blen;
    }

    if (idx <= 1 && !TEST_size_t_lt(total, 1 * 1024 * 1024))
        goto err;

    if (idx == 2 && !TEST_size_t_ge(total, 1 * 1024 * 1024))
        goto err;

    /*
     * The number of datagrams we can fit depends on the size of the default
     * write buffer size, the size of the datagram header and the size of the
     * payload data we send in each datagram. The max payload data is based on
     * the mtu. The default write buffer size is 9 * (sizeof(header) + mtu) so
     * we expect at least 9 maximally sized datagrams to fit in the buffer.
     */
    if (!TEST_size_t_ge(i, 9))
        goto err;

    /* Check we read back the same data */
    num_dgram = i;
    for (i = 0; i < num_dgram; ++i) {
        if (!TEST_int_eq(random_data(key, scratch, sizeof(scratch), i), 1))
            goto err;

        blen = ((*(uint32_t *)scratch) % mtu1) + 1;
        r = BIO_read(bio2, scratch2, sizeof(scratch2));
        if (!TEST_int_eq(r, blen))
            goto err;

        if (!TEST_mem_eq(scratch + 4, blen, scratch2, blen))
            goto err;
    }

    /* Should now be out of data */
    if (!TEST_int_eq(BIO_read(bio2, scratch2, sizeof(scratch2)), -1))
        goto err;

    /* sendmmsg/recvmmsg */
    if (!TEST_int_eq(random_data(key, scratch, sizeof(scratch), 0), 1))
        goto err;

    msgs[0].data = scratch;
    msgs[0].data_len = 19;
    msgs[1].data = scratch + 19;
    msgs[1].data_len = 46;

    if (!TEST_true(BIO_sendmmsg(bio1, msgs, sizeof(BIO_MSG), OSSL_NELEM(msgs), 0,
            &num_processed))
        || !TEST_size_t_eq(num_processed, 2))
        goto err;

    rmsgs[0].data = scratch2;
    rmsgs[0].data_len = 64;
    rmsgs[1].data = scratch2 + 64;
    rmsgs[1].data_len = 64;
    if (!TEST_true(BIO_recvmmsg(bio2, rmsgs, sizeof(BIO_MSG), OSSL_NELEM(rmsgs), 0,
            &num_processed))
        || !TEST_size_t_eq(num_processed, 2))
        goto err;

    if (!TEST_mem_eq(rmsgs[0].data, rmsgs[0].data_len, scratch, 19))
        goto err;

    if (!TEST_mem_eq(rmsgs[1].data, rmsgs[1].data_len, scratch + 19, 46))
        goto err;

    /* sendmmsg/recvmmsg with peer */
    addr1 = BIO_ADDR_new();
    if (!TEST_ptr(addr1))
        goto err;

    if (!TEST_int_eq(BIO_ADDR_rawmake(addr1, AF_INET, &in_local,
                         sizeof(in_local), 1234),
            1))
        goto err;

    addr2 = BIO_ADDR_new();
    if (!TEST_ptr(addr2))
        goto err;

    if (!TEST_int_eq(BIO_ADDR_rawmake(addr2, AF_INET, &in_local,
                         sizeof(in_local), 2345),
            1))
        goto err;

    addr3 = BIO_ADDR_new();
    if (!TEST_ptr(addr3))
        goto err;

    addr4 = BIO_ADDR_new();
    if (!TEST_ptr(addr4))
        goto err;

    msgs[0].peer = addr1;

    /* fails due to lack of caps on peer */
    if (!TEST_false(BIO_sendmmsg(bio1, msgs, sizeof(BIO_MSG),
            OSSL_NELEM(msgs), 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 0))
        goto err;

    if (!TEST_int_eq(BIO_dgram_set_caps(bio2, ref_caps), 1))
        goto err;

    if (!TEST_int_eq(BIO_dgram_get_caps(bio2), ref_caps))
        goto err;

    if (!TEST_int_eq(BIO_dgram_get_effective_caps(bio1), ref_caps))
        goto err;

    if (idx == 0 && !TEST_int_eq(BIO_dgram_get_effective_caps(bio2), 0))
        goto err;

    if (!TEST_int_eq(BIO_dgram_set_caps(bio1, ref_caps), 1))
        goto err;

    /* succeeds with cap now available */
    if (!TEST_true(BIO_sendmmsg(bio1, msgs, sizeof(BIO_MSG), 1, 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 1))
        goto err;

    /* enable local addr support */
    if (!TEST_int_eq(BIO_dgram_set_local_addr_enable(bio2, 1), 1))
        goto err;

    rmsgs[0].data = scratch2;
    rmsgs[0].data_len = 64;
    rmsgs[0].peer = addr3;
    rmsgs[0].local = addr4;
    if (!TEST_true(BIO_recvmmsg(bio2, rmsgs, sizeof(BIO_MSG), OSSL_NELEM(rmsgs), 0,
            &num_processed))
        || !TEST_size_t_eq(num_processed, 1))
        goto err;

    if (!TEST_mem_eq(rmsgs[0].data, rmsgs[0].data_len, msgs[0].data, 19))
        goto err;

    /* We didn't set the source address so this should be zero */
    if (!TEST_int_eq(BIO_ADDR_family(addr3), 0))
        goto err;

    if (!TEST_int_eq(BIO_ADDR_family(addr4), AF_INET))
        goto err;

    if (!TEST_int_eq(BIO_ADDR_rawport(addr4), 1234))
        goto err;

    /* test source address */
    msgs[0].local = addr2;

    if (!TEST_int_eq(BIO_dgram_set_local_addr_enable(bio1, 1), 1))
        goto err;

    if (!TEST_true(BIO_sendmmsg(bio1, msgs, sizeof(BIO_MSG), 1, 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 1))
        goto err;

    rmsgs[0].data = scratch2;
    rmsgs[0].data_len = 64;
    if (!TEST_true(BIO_recvmmsg(bio2, rmsgs, sizeof(BIO_MSG), OSSL_NELEM(rmsgs), 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 1))
        goto err;

    if (!TEST_mem_eq(rmsgs[0].data, rmsgs[0].data_len,
            msgs[0].data, msgs[0].data_len))
        goto err;

    if (!TEST_int_eq(BIO_ADDR_family(addr3), AF_INET))
        goto err;

    if (!TEST_int_eq(BIO_ADDR_rawport(addr3), 2345))
        goto err;

    if (!TEST_int_eq(BIO_ADDR_family(addr4), AF_INET))
        goto err;

    if (!TEST_int_eq(BIO_ADDR_rawport(addr4), 1234))
        goto err;

    /* test truncation, pending */
    r = BIO_write(bio1, scratch, 64);
    if (!TEST_int_eq(r, 64))
        goto err;

    memset(scratch2, 0, 64);
    if (!TEST_int_eq(BIO_dgram_set_no_trunc(bio2, 1), 1))
        goto err;

    if (!TEST_int_eq(BIO_read(bio2, scratch2, 32), -1))
        goto err;

    if (!TEST_int_eq(BIO_pending(bio2), 64))
        goto err;

    if (!TEST_int_eq(BIO_dgram_set_no_trunc(bio2, 0), 1))
        goto err;

    if (!TEST_int_eq(BIO_read(bio2, scratch2, 32), 32))
        goto err;

    if (!TEST_mem_eq(scratch, 32, scratch2, 32))
        goto err;

    testresult = 1;
err:
    if (idx == 0)
        BIO_free(bio1);
    BIO_free(bio2);
    BIO_ADDR_free(addr1);
    BIO_ADDR_free(addr2);
    BIO_ADDR_free(addr3);
    BIO_ADDR_free(addr4);
    return testresult;
}
#endif /* !defined(OPENSSL_NO_CHACHA) */

/* Checks that a half without a usable peer fails cleanly. */
static int check_detached(BIO *bio, int reason)
{
    char buf[16];
    BIO_MSG msg;
    size_t num_processed = 1;

    memset(&msg, 0, sizeof(msg));
    msg.data = buf;
    msg.data_len = sizeof(buf);

    if (!TEST_int_eq(BIO_eof(bio), 1)
        || !TEST_int_eq(BIO_pending(bio), 0))
        return 0;

    ERR_clear_error();
    if (!TEST_int_lt(BIO_read(bio, buf, sizeof(buf)), 0)
        || !TEST_false(BIO_should_retry(bio))
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), reason))
        return 0;

    ERR_clear_error();
    if (!TEST_int_lt(BIO_write(bio, "x", 1), 0)
        || !TEST_false(BIO_should_retry(bio))
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), reason))
        return 0;

    ERR_clear_error();
    if (!TEST_false(BIO_recvmmsg(bio, &msg, sizeof(msg), 1, 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 0)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), reason))
        return 0;

    num_processed = 1;
    ERR_clear_error();
    if (!TEST_false(BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &num_processed))
        || !TEST_size_t_eq(num_processed, 0)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), reason))
        return 0;

    ERR_clear_error();
    return 1;
}

static int test_bio_dgram_pair_free_half(void)
{
    int testresult = 0;
    BIO *bio1 = NULL, *bio2 = NULL, *bio3 = NULL;
    char buf[16];

    if (!TEST_true(BIO_new_bio_dgram_pair(&bio1, 0, &bio2, 0))
        || !TEST_int_eq(BIO_write(bio1, "hello", 5), 5)
        || !TEST_int_eq(BIO_write(bio2, "world", 5), 5))
        goto err;

    /* Freeing one half must leave the other detached but usable. */
    BIO_free(bio1);
    bio1 = NULL;
    if (!check_detached(bio2, BIO_R_BROKEN_PIPE))
        goto err;

    /* Which includes pairing it with a new peer. */
    if (!TEST_ptr(bio3 = BIO_new(BIO_s_dgram_pair()))
        || !TEST_true(BIO_destroy_bio_pair(bio2))
        || !TEST_true(BIO_make_bio_pair(bio2, bio3))
        || !TEST_int_eq(BIO_eof(bio2), 0)
        || !TEST_int_eq(BIO_write(bio2, "again", 5), 5)
        || !TEST_int_eq(BIO_read(bio3, buf, sizeof(buf)), 5)
        || !TEST_mem_eq(buf, 5, "again", 5))
        goto err;

    /* Destroying the pair on the survivor must cope with a freed peer. */
    BIO_free(bio3);
    bio3 = NULL;
    if (!TEST_true(BIO_destroy_bio_pair(bio2))
        || !check_detached(bio2, BIO_R_UNINITIALIZED))
        goto err;

    testresult = 1;
err:
    BIO_free(bio1);
    BIO_free(bio2);
    BIO_free(bio3);
    return testresult;
}

static int test_bio_dgram_pair_destroy(int idx)
{
    int testresult = 0;
    BIO *bio1 = NULL, *bio2 = NULL;
    BIO_ADDR *addr;
    char buf[16];

    if (!TEST_true(BIO_new_bio_dgram_pair(&bio1, 0, &bio2, 0))
        || !TEST_ptr(addr = BIO_ADDR_new())
        || !TEST_true(BIO_dgram_set0_local_addr(bio1, addr)))
        goto err;

    if (!TEST_int_eq(BIO_write(bio1, "hello", 5), 5)
        || !TEST_int_eq(BIO_read(bio2, buf, sizeof(buf)), 5)
        || !TEST_int_eq(BIO_write(bio2, "world", 5), 5)
        || !TEST_int_eq(BIO_read(bio1, buf, sizeof(buf)), 5))
        goto err;

    /* Destroying the pair on either half must detach both cleanly. */
    if (!TEST_true(BIO_destroy_bio_pair(idx == 0 ? bio1 : bio2))
        || !check_detached(bio1, idx == 0 ? BIO_R_UNINITIALIZED : BIO_R_BROKEN_PIPE)
        || !check_detached(bio2, idx == 0 ? BIO_R_BROKEN_PIPE : BIO_R_UNINITIALIZED)
        || !TEST_true(BIO_destroy_bio_pair(bio1))
        || !TEST_true(BIO_destroy_bio_pair(bio2)))
        goto err;

    /* Both halves are free to be paired again. */
    if (!TEST_true(BIO_make_bio_pair(bio1, bio2))
        || !TEST_int_eq(BIO_write(bio1, "again", 5), 5)
        || !TEST_int_eq(BIO_read(bio2, buf, sizeof(buf)), 5)
        || !TEST_mem_eq(buf, 5, "again", 5))
        goto err;

    testresult = 1;
err:
    BIO_free(bio1);
    BIO_free(bio2);
    return testresult;
}

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
#include "threadstest.h"

static BIO *reader_bio;
static int reader_reason, reader_eof, reader_write;

/* Keeps receiving on its half until the peer is freed underneath it. */
static void free_race_reader(void)
{
    char buf[16];
    BIO_MSG msg;
    size_t num_processed;
    int r;

    memset(&msg, 0, sizeof(msg));
    msg.data = buf;
    msg.data_len = sizeof(buf);

    for (;;) {
        if (BIO_recvmmsg(reader_bio, &msg, sizeof(msg), 1, 0, &num_processed))
            continue;
        /* Writes look at the peer too, so keep them in the mix. */
        ERR_clear_error();
        r = BIO_write(reader_bio, "x", 1);
        if (r < 0 && !BIO_should_retry(reader_bio))
            break;
        ERR_clear_error();
        r = BIO_read(reader_bio, buf, sizeof(buf));
        if (r < 0 && !BIO_should_retry(reader_bio))
            break;
    }

    reader_reason = ERR_GET_REASON(ERR_peek_error());
    reader_eof = BIO_eof(reader_bio);
    reader_write = BIO_write(reader_bio, "x", 1);
    ERR_clear_error();
}

static int test_bio_dgram_pair_free_race(void)
{
    int testresult = 0, written = 0, r;
    BIO *bio1 = NULL, *bio2 = NULL;
    thread_t thread;

    if (!TEST_true(BIO_new_bio_dgram_pair(&bio1, 0, &bio2, 0)))
        goto err;

    reader_bio = bio2;
    if (!TEST_true(run_thread(&thread, free_race_reader)))
        goto err;

    /* Keep the reader busy, then pull its peer out from under it. */
    while (written < 1000) {
        r = BIO_write(bio1, "ping", 4);
        if (r == 4)
            written++;
        else if (!BIO_should_retry(bio1))
            break;
    }
    BIO_free(bio1);
    bio1 = NULL;

    if (!TEST_true(wait_for_thread(thread))
        || !TEST_int_eq(written, 1000)
        || !TEST_int_eq(reader_reason, BIO_R_BROKEN_PIPE)
        || !TEST_int_eq(reader_eof, 1)
        || !TEST_int_lt(reader_write, 0))
        goto err;

    testresult = 1;
err:
    BIO_free(bio1);
    BIO_free(bio2);
    return testresult;
}
#endif

static int test_bio_dgram_mfail(void)
{
    BIO *bio;

    MFAIL_start();
    bio = BIO_new(BIO_s_dgram_mem());
    MFAIL_end();

    if (bio == NULL)
        return 0;

    BIO_free(bio);
    return 1;
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
#if !defined(OPENSSL_NO_CHACHA)
    ADD_ALL_TESTS(test_bio_dgram_pair, 3);
#endif
    ADD_TEST(test_bio_dgram_pair_free_half);
    ADD_ALL_TESTS(test_bio_dgram_pair_destroy, 2);
#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
    ADD_TEST(test_bio_dgram_pair_free_race);
#endif
    ADD_MFAIL_TEST(test_bio_dgram_mfail);
#endif

    return 1;
}
