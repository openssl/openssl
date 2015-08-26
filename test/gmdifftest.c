/* ====================================================================
 * Copyright (c) 2001-2015 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#include <openssl/crypto.h>
#include <stdio.h>

#define SECS_PER_DAY (24 * 60 * 60)

/*
 * Time checking test code. Check times are identical for a wide range of
 * offsets. This should be run on a machine with 64 bit time_t or it will
 * trigger the very errors the routines fix.
 */

static int check_time(long offset)
{
    struct tm tm1, tm2, o1;
    int off_day, off_sec;
    long toffset;
    time_t t1, t2;
    time(&t1);

    t2 = t1 + offset;
    OPENSSL_gmtime(&t2, &tm2);
    OPENSSL_gmtime(&t1, &tm1);
    o1 = tm1;
    OPENSSL_gmtime_adj(&tm1, 0, offset);
    if ((tm1.tm_year != tm2.tm_year) ||
        (tm1.tm_mon != tm2.tm_mon) ||
        (tm1.tm_mday != tm2.tm_mday) ||
        (tm1.tm_hour != tm2.tm_hour) ||
        (tm1.tm_min != tm2.tm_min) || (tm1.tm_sec != tm2.tm_sec)) {
        fprintf(stderr, "TIME ERROR!!\n");
        fprintf(stderr, "Time1: %d/%d/%d, %d:%02d:%02d\n",
                tm2.tm_mday, tm2.tm_mon + 1, tm2.tm_year + 1900,
                tm2.tm_hour, tm2.tm_min, tm2.tm_sec);
        fprintf(stderr, "Time2: %d/%d/%d, %d:%02d:%02d\n",
                tm1.tm_mday, tm1.tm_mon + 1, tm1.tm_year + 1900,
                tm1.tm_hour, tm1.tm_min, tm1.tm_sec);
        return 0;
    }
    if (!OPENSSL_gmtime_diff(&off_day, &off_sec, &o1, &tm1))
        return 0;
    toffset = (long)off_day *SECS_PER_DAY + off_sec;
    if (offset != toffset) {
        fprintf(stderr, "TIME OFFSET ERROR!!\n");
        fprintf(stderr, "Expected %ld, Got %ld (%d:%d)\n",
                offset, toffset, off_day, off_sec);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    long offset;
    int fails;

    if (sizeof(time_t) < 8) {
        fprintf(stderr, "Skipping; time_t is less than 64-bits\n");
        return 0;
    }
    for (fails = 0, offset = 0; offset < 1000000; offset++) {
        if (!check_time(offset))
            fails++;
        if (!check_time(-offset))
            fails++;
        if (!check_time(offset * 1000))
            fails++;
        if (!check_time(-offset * 1000))
            fails++;
    }

    return fails ? 1 : 0;
}
