/* test/packettest.c */
/*
 * Written by Matt Caswell for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */


#include "../ssl/packet_locl.h"

#define BUF_LEN 255

static int test_PACKET_remaining(unsigned char buf[BUF_LEN])
{
    PACKET pkt;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            ||  PACKET_remaining(&pkt) != BUF_LEN
            || !PACKET_forward(&pkt, BUF_LEN - 1)
            ||  PACKET_remaining(&pkt) != 1
            || !PACKET_forward(&pkt, 1)
            ||  PACKET_remaining(&pkt) != 0) {
        fprintf(stderr, "test_PACKET_remaining() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_1(unsigned char buf[BUF_LEN])
{
    unsigned int i;
    PACKET pkt;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_get_1(&pkt, &i)
            ||  i != 0x02
            || !PACKET_forward(&pkt, BUF_LEN - 2)
            || !PACKET_get_1(&pkt, &i)
            ||  i != 0xfe
            ||  PACKET_get_1(&pkt, &i)) {
        fprintf(stderr, "test_PACKET_get_1() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_4(unsigned char buf[BUF_LEN])
{
    unsigned long i;
    PACKET pkt;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_get_4(&pkt, &i)
            ||  i != 0x08060402UL
            || !PACKET_forward(&pkt, BUF_LEN - 8)
            || !PACKET_get_4(&pkt, &i)
            ||  i != 0xfefcfaf8UL
            ||  PACKET_get_4(&pkt, &i)) {
        fprintf(stderr, "test_PACKET_get_4() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_net_2(unsigned char buf[BUF_LEN])
{
    unsigned int i;
    PACKET pkt;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_get_net_2(&pkt, &i)
            ||  i != 0x0204
            || !PACKET_forward(&pkt, BUF_LEN - 4)
            || !PACKET_get_net_2(&pkt, &i)
            ||  i != 0xfcfe
            ||  PACKET_get_net_2(&pkt, &i)) {
        fprintf(stderr, "test_PACKET_get_net_2() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_net_3(unsigned char buf[BUF_LEN])
{
    unsigned long i;
    PACKET pkt;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_get_net_3(&pkt, &i)
            ||  i != 0x020406UL
            || !PACKET_forward(&pkt, BUF_LEN - 6)
            || !PACKET_get_net_3(&pkt, &i)
            ||  i != 0xfafcfeUL
            ||  PACKET_get_net_3(&pkt, &i)) {
        fprintf(stderr, "test_PACKET_get_net_3() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_net_4(unsigned char buf[BUF_LEN])
{
    unsigned long i;
    PACKET pkt;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_get_net_4(&pkt, &i)
            ||  i != 0x02040608UL
            || !PACKET_forward(&pkt, BUF_LEN - 8)
            || !PACKET_get_net_4(&pkt, &i)
            ||  i != 0xf8fafcfeUL
            ||  PACKET_get_net_4(&pkt, &i)) {
        fprintf(stderr, "test_PACKET_get_net_4() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_sub_packet(unsigned char buf[BUF_LEN])
{
    PACKET pkt, subpkt;
    unsigned long i;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_get_sub_packet(&pkt, &subpkt, 4)
            || !PACKET_get_net_4(&subpkt, &i)
            ||  i != 0x02040608UL
            ||  PACKET_remaining(&subpkt)
            || !PACKET_forward(&pkt, BUF_LEN - 8)
            || !PACKET_get_sub_packet(&pkt, &subpkt, 4)
            || !PACKET_get_net_4(&subpkt, &i)
            ||  i != 0xf8fafcfeUL
            ||  PACKET_remaining(&subpkt)
            ||  PACKET_get_sub_packet(&pkt, &subpkt, 4)) {
        fprintf(stderr, "test_PACKET_get_sub_packet() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_bytes(unsigned char buf[BUF_LEN])
{
    unsigned char *bytes;
    PACKET pkt;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_get_bytes(&pkt, &bytes, 4)
            ||  bytes[0] != 2 || bytes[1] != 4
            ||  bytes[2] != 6 || bytes[3] != 8
            ||  PACKET_remaining(&pkt) != BUF_LEN -4
            || !PACKET_forward(&pkt, BUF_LEN - 8)
            || !PACKET_get_bytes(&pkt, &bytes, 4)
            ||  bytes[0] != 0xf8 || bytes[1] != 0xfa
            ||  bytes[2] != 0xfc || bytes[3] != 0xfe
            ||  PACKET_remaining(&pkt)) {
        fprintf(stderr, "test_PACKET_get_bytes() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_copy_bytes(unsigned char buf[BUF_LEN])
{
    unsigned char bytes[4];
    PACKET pkt;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_copy_bytes(&pkt, bytes, 4)
            ||  bytes[0] != 2 || bytes[1] != 4
            ||  bytes[2] != 6 || bytes[3] != 8
            ||  PACKET_remaining(&pkt) != BUF_LEN - 4
            || !PACKET_forward(&pkt, BUF_LEN - 8)
            || !PACKET_copy_bytes(&pkt, bytes, 4)
            ||  bytes[0] != 0xf8 || bytes[1] != 0xfa
            ||  bytes[2] != 0xfc || bytes[3] != 0xfe
            ||  PACKET_remaining(&pkt)) {
        fprintf(stderr, "test_PACKET_copy_bytes() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_copy_all(unsigned char buf[BUF_LEN])
{
    unsigned char tmp[BUF_LEN];
    PACKET pkt;
    size_t len;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
               || !PACKET_copy_all(&pkt, tmp, BUF_LEN, &len)
               || len != BUF_LEN
               || memcmp(buf, tmp, BUF_LEN) != 0
               || PACKET_remaining(&pkt) != BUF_LEN
               || PACKET_copy_all(&pkt, tmp, BUF_LEN - 1, &len)) {
        fprintf(stderr, "test_PACKET_copy_bytes() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_memdup(unsigned char buf[BUF_LEN])
{
    unsigned char *data = NULL;
    size_t len;
    PACKET pkt;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_memdup(&pkt, &data, &len)
            ||  len != BUF_LEN
            ||  memcmp(data, PACKET_data(&pkt), len)
            || !PACKET_forward(&pkt, 10)
            || !PACKET_memdup(&pkt, &data, &len)
            ||  len != BUF_LEN - 10
            ||  memcmp(data, PACKET_data(&pkt), len)) {
        fprintf(stderr, "test_PACKET_memdup() failed\n");
        OPENSSL_free(data);
        return 0;
    }

    OPENSSL_free(data);
    return 1;
}

static int test_PACKET_strndup()
{
    char buf[10], buf2[10];
    char *data = NULL;
    PACKET pkt;

    memset(buf, 'x', 10);
    memset(buf2, 'y', 10);
    buf2[5] = '\0';

    if (       !PACKET_buf_init(&pkt, (unsigned char*)buf, 10)
            || !PACKET_strndup(&pkt, &data)
            ||  strlen(data) != 10
            ||  strncmp(data, buf, 10)
            || !PACKET_buf_init(&pkt, (unsigned char*)buf2, 10)
            || !PACKET_strndup(&pkt, &data)
            ||  strlen(data) != 5
            ||  strcmp(data, buf2)) {
        fprintf(stderr, "test_PACKET_strndup failed\n");
        OPENSSL_free(data);
        return 0;
    }

    OPENSSL_free(data);
    return 1;
}

static int test_PACKET_forward(unsigned char buf[BUF_LEN])
{
    unsigned char *byte;
    PACKET pkt;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_forward(&pkt, 1)
            || !PACKET_get_bytes(&pkt, &byte, 1)
            ||  byte[0] != 4
            || !PACKET_forward(&pkt, BUF_LEN - 3)
            || !PACKET_get_bytes(&pkt, &byte, 1)
            ||  byte[0] != 0xfe) {
        fprintf(stderr, "test_PACKET_forward() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_buf_init()
{
    unsigned char buf[BUF_LEN];
    PACKET pkt;

    /* Also tests PACKET_remaining() */
    if (       !PACKET_buf_init(&pkt, buf, 4)
            ||  PACKET_remaining(&pkt) != 4
            || !PACKET_buf_init(&pkt, buf, BUF_LEN)
            ||  PACKET_remaining(&pkt) != BUF_LEN
            ||  PACKET_buf_init(&pkt, buf, -1)) {
        fprintf(stderr, "test_PACKET_buf_init() failed\n");
        return 0;
        }

    return 1;
}

static int test_PACKET_null_init()
{
    PACKET pkt;

    PACKET_null_init(&pkt);
    if (       PACKET_remaining(&pkt) != 0
            || PACKET_forward(&pkt, 1)) {
        fprintf(stderr, "test_PACKET_null_init() failed\n");
        return 0;
        }

    return 1;
}

static int test_PACKET_equal(unsigned char buf[BUF_LEN])
{
    PACKET pkt;

    if (       !PACKET_buf_init(&pkt, buf, 4)
            || !PACKET_equal(&pkt, buf, 4)
            ||  PACKET_equal(&pkt, buf + 1, 4)
            || !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_equal(&pkt, buf, BUF_LEN)
            ||  PACKET_equal(&pkt, buf, BUF_LEN - 1)
            ||  PACKET_equal(&pkt, buf, BUF_LEN + 1)
            ||  PACKET_equal(&pkt, buf, 0)) {
        fprintf(stderr, "test_PACKET_equal() failed\n");
        return 0;
        }

    return 1;
}

static int test_PACKET_get_length_prefixed_1()
{
    unsigned char buf[BUF_LEN];
    const size_t len = 16;
    unsigned int i;
    PACKET pkt, short_pkt, subpkt;

    buf[0] = len;
    for (i = 1; i < BUF_LEN; i++) {
        buf[i] = (i * 2) & 0xff;
    }

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_buf_init(&short_pkt, buf, len)
            || !PACKET_get_length_prefixed_1(&pkt, &subpkt)
            ||  PACKET_remaining(&subpkt) != len
            || !PACKET_get_net_2(&subpkt, &i)
            ||  i != 0x0204
            ||  PACKET_get_length_prefixed_1(&short_pkt, &subpkt)
            ||  PACKET_remaining(&short_pkt) != len) {
        fprintf(stderr, "test_PACKET_get_length_prefixed_1() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_length_prefixed_2()
{
    unsigned char buf[1024];
    const size_t len = 516;  /* 0x0204 */
    unsigned int i;
    PACKET pkt, short_pkt, subpkt;

    for (i = 1; i <= 1024; i++) {
        buf[i-1] = (i * 2) & 0xff;
    }

    if (       !PACKET_buf_init(&pkt, buf, 1024)
            || !PACKET_buf_init(&short_pkt, buf, len)
            || !PACKET_get_length_prefixed_2(&pkt, &subpkt)
            ||  PACKET_remaining(&subpkt) != len
            || !PACKET_get_net_2(&subpkt, &i)
            ||  i != 0x0608
            ||  PACKET_get_length_prefixed_2(&short_pkt, &subpkt)
            ||  PACKET_remaining(&short_pkt) != len) {
        fprintf(stderr, "test_PACKET_get_length_prefixed_2() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_length_prefixed_3()
{
    unsigned char buf[1024];
    const size_t len = 516;  /* 0x000204 */
    unsigned int i;
    PACKET pkt, short_pkt, subpkt;

    for (i = 0; i < 1024; i++) {
        buf[i] = (i * 2) & 0xff;
    }

    if (       !PACKET_buf_init(&pkt, buf, 1024)
            || !PACKET_buf_init(&short_pkt, buf, len)
            || !PACKET_get_length_prefixed_3(&pkt, &subpkt)
            ||  PACKET_remaining(&subpkt) != len
            || !PACKET_get_net_2(&subpkt, &i)
            ||  i != 0x0608
            ||  PACKET_get_length_prefixed_3(&short_pkt, &subpkt)
            ||  PACKET_remaining(&short_pkt) != len) {
        fprintf(stderr, "test_PACKET_get_length_prefixed_3() failed\n");
        return 0;
    }

    return 1;
}

int main(int argc, char **argv)
{
    unsigned char buf[BUF_LEN];
    unsigned int i;

    for (i=1; i<=BUF_LEN; i++) {
        buf[i-1] = (i * 2) & 0xff;
    }
    i = 0;

    if (       !test_PACKET_buf_init()
            || !test_PACKET_null_init()
            || !test_PACKET_remaining(buf)
            || !test_PACKET_equal(buf)
            || !test_PACKET_get_1(buf)
            || !test_PACKET_get_4(buf)
            || !test_PACKET_get_net_2(buf)
            || !test_PACKET_get_net_3(buf)
            || !test_PACKET_get_net_4(buf)
            || !test_PACKET_get_sub_packet(buf)
            || !test_PACKET_get_bytes(buf)
            || !test_PACKET_copy_bytes(buf)
            || !test_PACKET_copy_all(buf)
            || !test_PACKET_memdup(buf)
            || !test_PACKET_strndup()
            || !test_PACKET_forward(buf)
            || !test_PACKET_get_length_prefixed_1()
            || !test_PACKET_get_length_prefixed_2()
            || !test_PACKET_get_length_prefixed_3()) {
        return 1;
    }
    printf("PASS\n");
    return 0;
}
