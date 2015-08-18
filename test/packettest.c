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

static int test_PACKET_remaining(PACKET *pkt)
{
    if (        PACKET_remaining(pkt) != BUF_LEN
            || !PACKET_forward(pkt, BUF_LEN - 1)
            ||  PACKET_remaining(pkt) != 1
            || !PACKET_forward(pkt, 1)
            ||  PACKET_remaining(pkt) != 0) {
        fprintf(stderr, "test_PACKET_remaining() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_1(PACKET *pkt, size_t start)
{
    unsigned int i;

    if (       !PACKET_goto_bookmark(pkt, start)
            || !PACKET_get_1(pkt, &i)
            ||  i != 0x02
            || !PACKET_forward(pkt, BUF_LEN - 2)
            || !PACKET_get_1(pkt, &i)
            ||  i != 0xfe
            ||  PACKET_get_1(pkt, &i)) {
        fprintf(stderr, "test_PACKET_get_1() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_4(PACKET *pkt, size_t start)
{
    unsigned long i;

    if (       !PACKET_goto_bookmark(pkt, start)
            || !PACKET_get_4(pkt, &i)
            ||  i != 0x08060402UL
            || !PACKET_forward(pkt, BUF_LEN - 8)
            || !PACKET_get_4(pkt, &i)
            ||  i != 0xfefcfaf8UL
            ||  PACKET_get_4(pkt, &i)) {
        fprintf(stderr, "test_PACKET_get_4() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_net_2(PACKET *pkt, size_t start)
{
    unsigned int i;

    if (       !PACKET_goto_bookmark(pkt, start)
            || !PACKET_get_net_2(pkt, &i)
            ||  i != 0x0204
            || !PACKET_forward(pkt, BUF_LEN - 4)
            || !PACKET_get_net_2(pkt, &i)
            ||  i != 0xfcfe
            ||  PACKET_get_net_2(pkt, &i)) {
        fprintf(stderr, "test_PACKET_get_net_2() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_net_3(PACKET *pkt, size_t start)
{
    unsigned long i;

    if (       !PACKET_goto_bookmark(pkt, start)
            || !PACKET_get_net_3(pkt, &i)
            ||  i != 0x020406UL
            || !PACKET_forward(pkt, BUF_LEN - 6)
            || !PACKET_get_net_3(pkt, &i)
            ||  i != 0xfafcfeUL
            ||  PACKET_get_net_3(pkt, &i)) {
        fprintf(stderr, "test_PACKET_get_net_3() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_net_4(PACKET *pkt, size_t start)
{
    unsigned long i;

    if (       !PACKET_goto_bookmark(pkt, start)
            || !PACKET_get_net_4(pkt, &i)
            ||  i != 0x02040608UL
            || !PACKET_forward(pkt, BUF_LEN - 8)
            || !PACKET_get_net_4(pkt, &i)
            ||  i != 0xf8fafcfeUL
            ||  PACKET_get_net_4(pkt, &i)) {
        fprintf(stderr, "test_PACKET_get_net_4() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_sub_packet(PACKET *pkt, size_t start)
{
    PACKET subpkt;
    unsigned long i;

    if (       !PACKET_goto_bookmark(pkt, start)
            || !PACKET_get_sub_packet(pkt, &subpkt, 4)
            || !PACKET_get_net_4(&subpkt, &i)
            ||  i != 0x02040608UL
            ||  PACKET_remaining(&subpkt)
            || !PACKET_forward(pkt, BUF_LEN - 8)
            || !PACKET_get_sub_packet(pkt, &subpkt, 4)
            || !PACKET_get_net_4(&subpkt, &i)
            ||  i != 0xf8fafcfeUL
            ||  PACKET_remaining(&subpkt)
            ||  PACKET_get_sub_packet(pkt, &subpkt, 4)) {
        fprintf(stderr, "test_PACKET_get_sub_packet() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_get_bytes(PACKET *pkt, size_t start)
{
    unsigned char *bytes;

    if (       !PACKET_goto_bookmark(pkt, start)
            || !PACKET_get_bytes(pkt, &bytes, 4)
            ||  bytes[0] != 2 || bytes[1] != 4
            ||  bytes[2] != 6 || bytes[3] != 8
            ||  PACKET_remaining(pkt) != BUF_LEN -4
            || !PACKET_forward(pkt, BUF_LEN - 8)
            || !PACKET_get_bytes(pkt, &bytes, 4)
            ||  bytes[0] != 0xf8 || bytes[1] != 0xfa
            ||  bytes[2] != 0xfc || bytes[3] != 0xfe
            ||  PACKET_remaining(pkt)) {
        fprintf(stderr, "test_PACKET_get_bytes() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_copy_bytes(PACKET *pkt, size_t start)
{
    unsigned char bytes[4];

    if (       !PACKET_goto_bookmark(pkt, start)
            || !PACKET_copy_bytes(pkt, bytes, 4)
            ||  bytes[0] != 2 || bytes[1] != 4
            ||  bytes[2] != 6 || bytes[3] != 8
            ||  PACKET_remaining(pkt) != BUF_LEN - 4
            || !PACKET_forward(pkt, BUF_LEN - 8)
            || !PACKET_copy_bytes(pkt, bytes, 4)
            ||  bytes[0] != 0xf8 || bytes[1] != 0xfa
            ||  bytes[2] != 0xfc || bytes[3] != 0xfe
            ||  PACKET_remaining(pkt)) {
        fprintf(stderr, "test_PACKET_copy_bytes() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_move_funcs(PACKET *pkt, size_t start)
{
    unsigned char *byte;
    size_t bm;

    if (       !PACKET_goto_bookmark(pkt, start)
            ||  PACKET_back(pkt, 1)
            || !PACKET_forward(pkt, 1)
            || !PACKET_get_bytes(pkt, &byte, 1)
            ||  byte[0] != 4
            || !PACKET_get_bookmark(pkt, &bm)
            || !PACKET_forward(pkt, BUF_LEN - 2)
            ||  PACKET_forward(pkt, 1)
            || !PACKET_back(pkt, 1)
            || !PACKET_get_bytes(pkt, &byte, 1)
            ||  byte[0] != 0xfe
            || !PACKET_goto_bookmark(pkt, bm)
            || !PACKET_get_bytes(pkt, &byte, 1)
            ||  byte[0] != 6) {
        fprintf(stderr, "test_PACKET_move_funcs() failed\n");
        return 0;
    }

    return 1;
}

static int test_PACKET_buf_init()
{
    unsigned char buf[BUF_LEN];
    size_t len;
    PACKET pkt;

    /* Also tests PACKET_get_len() */
    if (       !PACKET_buf_init(&pkt, buf, 4)
            || !PACKET_length(&pkt, &len)
            ||  len != 4
            || !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_length(&pkt, &len)
            ||  len != BUF_LEN
            ||  pkt.end - pkt.start != BUF_LEN
            ||  pkt.end < pkt.start
            ||  pkt.curr < pkt.start
            ||  pkt.curr > pkt.end
            ||  PACKET_buf_init(&pkt, buf, -1)) {
        fprintf(stderr, "test_PACKET_buf_init() failed\n");
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
    size_t start = 0;
    PACKET pkt;

    for (i=1; i<=BUF_LEN; i++) {
        buf[i-1] = (i * 2) & 0xff;
    }
    i = 0;

    if (       !PACKET_buf_init(&pkt, buf, BUF_LEN)
            || !PACKET_get_bookmark(&pkt, &start)) {
        fprintf(stderr, "setup failed\n");
        return 0;
    }

    if (       !test_PACKET_buf_init()
            || !test_PACKET_remaining(&pkt)
            || !test_PACKET_get_1(&pkt, start)
            || !test_PACKET_get_4(&pkt, start)
            || !test_PACKET_get_net_2(&pkt, start)
            || !test_PACKET_get_net_3(&pkt, start)
            || !test_PACKET_get_net_4(&pkt, start)
            || !test_PACKET_get_sub_packet(&pkt, start)
            || !test_PACKET_get_bytes(&pkt, start)
            || !test_PACKET_copy_bytes(&pkt, start)
            || !test_PACKET_move_funcs(&pkt, start)
            || !test_PACKET_get_length_prefixed_1()
            || !test_PACKET_get_length_prefixed_2()
            || !test_PACKET_get_length_prefixed_3()) {
        return 1;
    }
    printf("PASS\n");
    return 0;
}
