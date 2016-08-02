/*
 * Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../ssl_locl.h"
#include "record_locl.h"

/* mod 128 saturating subtract of two 64-bit values in big-endian order */
static int satsub64be(const unsigned char *v1, const unsigned char *v2)
{
    int ret, i;

    if (sizeof(long) == 8)
        do {
            const union {
                long one;
                char little;
            } is_endian = {
                1
            };
            long l;

            if (is_endian.little)
                break;
            /* not reached on little-endians */
            /*
             * following test is redundant, because input is always aligned,
             * but I take no chances...
             */
            if (((size_t)v1 | (size_t)v2) & 0x7)
                break;

            l = *((long *)v1);
            l -= *((long *)v2);
            if (l > 128)
                return 128;
            else if (l < -128)
                return -128;
            else
                return (int)l;
        } while (0);

    ret = 0;
    for (i=0; i<7; i++) {
        if (v1[i] > v2[i]) {
            /* v1 is larger... but by how much? */
            if (v1[i] != v2[i] + 1)
                return 128;
            while (++i <= 6) {
                if (v1[i] != 0x00 || v2[i] != 0xff)
                    return 128; /* too much */
            }
            /* We checked all the way to the penultimate byte,
             * so despite higher bytes changing we actually
             * know that it only changed from (e.g.)
             *       ... (xx)  ff ff ff ??
             * to   ... (xx+1) 00 00 00 ??
             * so we add a 'bias' of 256 for the carry that
             * happened, and will eventually return
             * 256 + v1[7] - v2[7]. */
            ret = 256;
            break;
        } else if (v2[i] > v1[i]) {
            /* v2 is larger... but by how much? */
            if (v2[i] != v1[i] + 1)
                return -128;
            while (++i <= 6) {
                if (v2[i] != 0x00 || v1[i] != 0xff)
                    return -128; /* too much */
            }
            /* Similar to the case above, we know it changed
             * from    ... (xx)  00 00 00 ??
             * to     ... (xx-1) ff ff ff ??
             * so we add a 'bias' of -256 for the borrow,
             * to return -256 + v1[7] - v2[7]. */
            ret = -256;
        }
    }

    ret += (int)v1[7] - (int)v2[7];

    if (ret > 128)
        return 128;
    else if (ret < -128)
        return -128;
    else
        return ret;
}

int dtls1_record_replay_check(SSL *s, DTLS1_BITMAP *bitmap)
{
    int cmp;
    unsigned int shift;
    const unsigned char *seq = s->rlayer.read_sequence;

    cmp = satsub64be(seq, bitmap->max_seq_num);
    if (cmp > 0) {
        SSL3_RECORD_set_seq_num(RECORD_LAYER_get_rrec(&s->rlayer), seq);
        return 1;               /* this record in new */
    }
    shift = -cmp;
    if (shift >= sizeof(bitmap->map) * 8)
        return 0;               /* stale, outside the window */
    else if (bitmap->map & (1UL << shift))
        return 0;               /* record previously received */

    SSL3_RECORD_set_seq_num(RECORD_LAYER_get_rrec(&s->rlayer), seq);
    return 1;
}

void dtls1_record_bitmap_update(SSL *s, DTLS1_BITMAP *bitmap)
{
    int cmp;
    unsigned int shift;
    const unsigned char *seq = RECORD_LAYER_get_read_sequence(&s->rlayer);

    cmp = satsub64be(seq, bitmap->max_seq_num);
    if (cmp > 0) {
        shift = cmp;
        if (shift < sizeof(bitmap->map) * 8)
            bitmap->map <<= shift, bitmap->map |= 1UL;
        else
            bitmap->map = 1UL;
        memcpy(bitmap->max_seq_num, seq, SEQ_NUM_SIZE);
    } else {
        shift = -cmp;
        if (shift < sizeof(bitmap->map) * 8)
            bitmap->map |= 1UL << shift;
    }
}
