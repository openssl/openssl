/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/buffer.h>
#include "../ssl/packet_locl.h"
#include "testutil.h"
#include "test_main_custom.h"

const static unsigned char simple1 = 0xff;
const static unsigned char simple2[] = { 0x01, 0xff };
const static unsigned char simple3[] = { 0x00, 0x00, 0x00, 0x01, 0xff };
const static unsigned char nestedsub[] = { 0x03, 0xff, 0x01, 0xff };
const static unsigned char seqsub[] = { 0x01, 0xff, 0x01, 0xff };
const static unsigned char empty = 0x00;
const static unsigned char alloc[] = { 0x02, 0xfe, 0xff };
const static unsigned char submem[] = { 0x03, 0x02, 0xfe, 0xff };
const static unsigned char fixed[] = { 0xff, 0xff, 0xff };

static BUF_MEM *buf;

static void testfail(const char *msg, WPACKET *pkt)
{
    fprintf(stderr, "%s", msg);
    WPACKET_cleanup(pkt);
}

static int test_WPACKET_init(void)
{
    WPACKET pkt;
    int i;
    size_t written;
    unsigned char sbuf[3];

    if (!WPACKET_init(&pkt, buf)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
                /* Closing a top level WPACKET should fail */
            ||  WPACKET_close(&pkt)
                /* Finishing a top level WPACKET should succeed */
            || !WPACKET_finish(&pkt)
                /*
                 * Can't call close or finish on a WPACKET that's already
                 * finished.
                 */
            ||  WPACKET_close(&pkt)
            ||  WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(simple1)
            ||  memcmp(buf->data, &simple1, written) != 0) {
        testfail("test_WPACKET_init():1 failed\n", &pkt);
        return 0;
    }

    /* Now try with a one byte length prefix */
    if (!WPACKET_init_len(&pkt, buf, 1)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(simple2)
            ||  memcmp(buf->data, &simple2, written) != 0) {
        testfail("test_WPACKET_init():2 failed\n", &pkt);
        return 0;
    }

    /* And a longer length prefix */
    if (!WPACKET_init_len(&pkt, buf, 4)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(simple3)
            ||  memcmp(buf->data, &simple3, written) != 0) {
        testfail("test_WPACKET_init():3 failed\n", &pkt);
        return 0;
    }

    if (!WPACKET_init_len(&pkt, buf, 1)) {
        testfail("test_WPACKET_init():4 failed\n", &pkt);
        return 0;
    }
    for (i = 1; i < 257; i++) {
        /*
         * Putting more bytes in than fit for the size of the length prefix
         * should fail
         */
        if ((!WPACKET_put_bytes_u8(&pkt, 0xff)) == (i != 256)) {
            testfail("test_WPACKET_init():4 failed\n", &pkt);
            return 0;
        }
    }
    if (!WPACKET_finish(&pkt)) {
        testfail("test_WPACKET_init():4 failed\n", &pkt);
        return 0;
    }

    /* Test initialising from a fixed size buffer */
    if (!WPACKET_init_static_len(&pkt, sbuf, sizeof(sbuf), 0)
                /* Adding 3 bytes should succeed */
            || !WPACKET_put_bytes_u24(&pkt, 0xffffff)
                /* Adding 1 more byte should fail */
            ||  WPACKET_put_bytes_u8(&pkt, 0xff)
                /* Finishing the top level WPACKET should succeed */
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(fixed)
            || memcmp(sbuf, fixed, sizeof(sbuf)) != 0
                /* Initialise with 1 len byte */
            || !WPACKET_init_static_len(&pkt, sbuf, sizeof(sbuf), 1)
                /* Adding 2 bytes should succeed */
            || !WPACKET_put_bytes_u16(&pkt, 0xfeff)
                /* Adding 1 more byte should fail */
            ||  WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(alloc)
            ||  memcmp(sbuf, alloc, written) != 0) {
        testfail("test_WPACKET_init():5 failed\n", &pkt);
        return 0;
    }

    return 1;
}

static int test_WPACKET_set_max_size(void)
{
    WPACKET pkt;
    size_t written;

    if (!WPACKET_init(&pkt, buf)
                /*
                 * No previous lenbytes set so we should be ok to set the max
                 * possible max size
                 */
            || !WPACKET_set_max_size(&pkt, SIZE_MAX)
                /* We should be able to set it smaller too */
            || !WPACKET_set_max_size(&pkt, SIZE_MAX -1)
                /* And setting it bigger again should be ok */
            || !WPACKET_set_max_size(&pkt, SIZE_MAX)
            || !WPACKET_finish(&pkt)) {
        testfail("test_WPACKET_set_max_size():1 failed\n", &pkt);
        return 0;
    }

    if (!WPACKET_init_len(&pkt, buf, 1)
                /*
                 * Should fail because we already consumed 1 byte with the
                 * length
                 */
            ||  WPACKET_set_max_size(&pkt, 0)
                /*
                 * Max size can't be bigger than biggest that will fit in
                 * lenbytes
                 */
            ||  WPACKET_set_max_size(&pkt, 0x0101)
                /* It can be the same as the maximum possible size */
            || !WPACKET_set_max_size(&pkt, 0x0100)
                /* Or it can be less */
            || !WPACKET_set_max_size(&pkt, 0x01)
                /*
                 * Should fail because packet is already filled
                 */
            ||  WPACKET_put_bytes_u8(&pkt, 0xff)
                /*
                 * You can't put in more bytes than max size
                 */
            || !WPACKET_set_max_size(&pkt, 0x02)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
            ||  WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(simple2)
            ||  memcmp(buf->data, &simple2, written) != 0) {
        testfail("test_WPACKET_set_max_size():2 failed\n", &pkt);
        return 0;
    }

    return 1;
}

static int test_WPACKET_start_sub_packet(void)
{
    WPACKET pkt;
    size_t written;
    size_t len;

    if (!WPACKET_init(&pkt, buf)
            || !WPACKET_start_sub_packet(&pkt)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
                /* Can't finish because we have a sub packet */
            ||  WPACKET_finish(&pkt)
            || !WPACKET_close(&pkt)
                /* Sub packet is closed so can't close again */
            ||  WPACKET_close(&pkt)
                /* Now a top level so finish should succeed */
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(simple1)
            ||  memcmp(buf->data, &simple1, written) != 0) {
        testfail("test_WPACKET_start_sub_packet():1 failed\n", &pkt);
        return 0;
    }

   /* Single sub-packet with length prefix */
    if (!WPACKET_init(&pkt, buf)
            || !WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_close(&pkt)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(simple2)
            ||  memcmp(buf->data, &simple2, written) != 0) {
        testfail("test_WPACKET_start_sub_packet():2 failed\n", &pkt);
        return 0;
    }

    /* Nested sub-packets with length prefixes */
    if (!WPACKET_init(&pkt, buf)
            || !WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_get_length(&pkt, &len)
            || len != 1
            || !WPACKET_close(&pkt)
            || !WPACKET_get_length(&pkt, &len)
            || len != 3
            || !WPACKET_close(&pkt)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(nestedsub)
            ||  memcmp(buf->data, &nestedsub, written) != 0) {
        testfail("test_WPACKET_start_sub_packet():3 failed\n", &pkt);
        return 0;
    }

    /* Sequential sub-packets with length prefixes */
    if (!WPACKET_init(&pkt, buf)
            || !WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_close(&pkt)
            || !WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_close(&pkt)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(seqsub)
            ||  memcmp(buf->data, &seqsub, written) != 0) {
        testfail("test_WPACKET_start_sub_packet():4 failed\n", &pkt);
        return 0;
    }

    return 1;
}


static int test_WPACKET_set_flags(void)
{
    WPACKET pkt;
    size_t written;

    /* Set packet to be non-zero length */
    if (!WPACKET_init(&pkt, buf)
            || !WPACKET_set_flags(&pkt, WPACKET_FLAGS_NON_ZERO_LENGTH)
                /* Should fail because of zero length */
            ||  WPACKET_finish(&pkt)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(simple1)
            ||  memcmp(buf->data, &simple1, written) != 0) {
        testfail("test_WPACKET_set_flags():1 failed\n", &pkt);
        return 0;
    }

    /* Repeat above test in a sub-packet */
    if (!WPACKET_init(&pkt, buf)
            || !WPACKET_start_sub_packet(&pkt)
            || !WPACKET_set_flags(&pkt, WPACKET_FLAGS_NON_ZERO_LENGTH)
                /* Should fail because of zero length */
            ||  WPACKET_close(&pkt)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_close(&pkt)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(simple1)
            ||  memcmp(buf->data, &simple1, written) != 0) {
        testfail("test_WPACKET_set_flags():2 failed\n", &pkt);
        return 0;
    }

    /* Set packet to abandon non-zero length */
    if (!WPACKET_init_len(&pkt, buf, 1)
            || !WPACKET_set_flags(&pkt, WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != 0) {
        testfail("test_WPACKET_set_flags():3 failed\n", &pkt);
        return 0;
    }

    /* Repeat above test but only abandon a sub-packet */
    if (!WPACKET_init_len(&pkt, buf, 1)
            || !WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_set_flags(&pkt, WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH)
            || !WPACKET_close(&pkt)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(empty)
            ||  memcmp(buf->data, &empty, written) != 0) {
        testfail("test_WPACKET_set_flags():4 failed\n", &pkt);
        return 0;
    }

    /* And repeat with a non empty sub-packet */
    if (!WPACKET_init(&pkt, buf)
            || !WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_set_flags(&pkt, WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH)
            || !WPACKET_put_bytes_u8(&pkt, 0xff)
            || !WPACKET_close(&pkt)
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(simple2)
            ||  memcmp(buf->data, &simple2, written) != 0) {
        testfail("test_WPACKET_set_flags():5 failed\n", &pkt);
        return 0;
    }
    return 1;
}

static int test_WPACKET_allocate_bytes(void)
{
    WPACKET pkt;
    size_t written;
    unsigned char *bytes;

    if (!WPACKET_init_len(&pkt, buf, 1)
            || !WPACKET_allocate_bytes(&pkt, 2, &bytes)) {
        testfail("test_WPACKET_allocate_bytes():1 failed\n", &pkt);
        return 0;
    }
    bytes[0] = 0xfe;
    bytes[1] = 0xff;
    if (!WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(alloc)
            ||  memcmp(buf->data, &alloc, written) != 0) {
        testfail("test_WPACKET_allocate_bytes():2 failed\n", &pkt);
        return 0;
    }

    /* Repeat with WPACKET_sub_allocate_bytes */
    if (!WPACKET_init_len(&pkt, buf, 1)
            || !WPACKET_sub_allocate_bytes_u8(&pkt, 2, &bytes)) {
        testfail("test_WPACKET_allocate_bytes():3 failed\n", &pkt);
        return 0;
    }
    bytes[0] = 0xfe;
    bytes[1] = 0xff;
    if (!WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(submem)
            ||  memcmp(buf->data, &submem, written) != 0) {
        testfail("test_WPACKET_allocate_bytes():4 failed\n", &pkt);
        return 0;
    }

    return 1;
}

static int test_WPACKET_memcpy(void)
{
    WPACKET pkt;
    size_t written;
    const unsigned char bytes[] = { 0xfe, 0xff };

    if (!WPACKET_init_len(&pkt, buf, 1)
            || !WPACKET_memcpy(&pkt, bytes, sizeof(bytes))
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(alloc)
            ||  memcmp(buf->data, &alloc, written) != 0) {
        testfail("test_WPACKET_memcpy():1 failed\n", &pkt);
        return 0;
    }

    /* Repeat with WPACKET_sub_memcpy() */
    if (!WPACKET_init_len(&pkt, buf, 1)
            || !WPACKET_sub_memcpy_u8(&pkt, bytes, sizeof(bytes))
            || !WPACKET_finish(&pkt)
            || !WPACKET_get_total_written(&pkt, &written)
            ||  written != sizeof(submem)
            ||  memcmp(buf->data, &submem, written) != 0) {
        testfail("test_WPACKET_memcpy():2 failed\n", &pkt);
        return 0;
    }

    return 1;
}

int test_main(int argc, char *argv[])
{
    int testresult = 0;

    buf = BUF_MEM_new();
    if (buf != NULL) {
        ADD_TEST(test_WPACKET_init);
        ADD_TEST(test_WPACKET_set_max_size);
        ADD_TEST(test_WPACKET_start_sub_packet);
        ADD_TEST(test_WPACKET_set_flags);
        ADD_TEST(test_WPACKET_allocate_bytes);
        ADD_TEST(test_WPACKET_memcpy);

        testresult = run_tests(argv[0]);

        BUF_MEM_free(buf);
    }

    return testresult;
}
