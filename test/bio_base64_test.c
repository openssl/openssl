/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

typedef struct {
    char *encoded;
    int encoded_len;
    char *expected_decode;
    int expected_decode_len;
    int last_read_ret;
    char *desc;
} test_case;

static char zbin[4 * 768];
#define z64enc \
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
#define z256enc z64enc z64enc z64enc z64enc
#define z1024enc z256enc z256enc z256enc z256enc
#define z2048enc z1024enc z1024enc

#define softEOF "-EOF\n"
#define gunk4 "#foo"
#define junk gunk4 "\n"
#define gunk16 gunk4 gunk4 gunk4 gunk4
#define gunk64 gunk16 gunk16 gunk16 gunk16
#define gunk256 gunk64 gunk64 gunk64 gunk64
#define gunk gunk256 gunk256 gunk256 gunk256 "\n"

static test_case tests[] = {
    { "", 0, "", 0, 0, "empty input" },
    { softEOF, 5, "", 0, 0, "soft EOF" },
    { junk, 5, "", 0, 0, "non base64 junk" },
    { gunk, 1025, "", 0, 0, "non base64 gunk" },
    { "AA==\n", 5, zbin, 1, 0, "padded byte" },
    { "AAA=\n", 5, zbin, 2, 0, "padded double byte" },
    { "AAAA\n", 5, zbin, 3, 0, "single block" },
    { "A\nAAA\n", 6, zbin, 3, 0, "split single block" },
    { "AAAA\nAA\n", 8, zbin, 0, -1, "missing padding" },
    { "AAAA\nA\n", 7, zbin, 0, -1, "truncated input" },
    { junk "AAAA\n", 10, zbin, 3, 0, "junk + single" },
    { junk "A\nAAA\n", 11, zbin, 3, 0, "junk + split single" },
    { gunk "AAAA\n", 1030, zbin, 3, 0, "gunk + single" },
    { gunk "A\nAAA\n", 1031, zbin, 3, 0, "gunk + split single" },
    { "AAAA\n" softEOF, 10, zbin, 3, 0, "single + soft EOF" },
    { "AAAA\n" junk, 10, "", 0, -1, "single + junk" },
    { z64enc, 65, zbin, 48, 0, "64 encoded bytes" },
    { "A\n" z64enc, 65, zbin, 48, 0, "split 64 encoded bytes" },
    { junk z64enc, 70, zbin, 48, 0, "junk + 64 encoded bytes" },
    { z64enc softEOF, 70, zbin, 48, 0, "64 encoded bytes + soft EOF" },
    { z64enc junk, 70, zbin, 0, -1, "64 encoded bytes + junk" },
    { z256enc, 260, zbin, 192, 0, "256 encoded bytes" },
    { junk z256enc, 265, zbin, 192, 0, "junk + 256 encoded bytes" },
    { z256enc softEOF, 265, zbin, 192, 0, "256 encoded bytes + soft EOF" },
    { z256enc junk, 265, zbin, 0, -1, "256 encoded bytes + junk" },
    { z1024enc, 1040, zbin, 768, 0, "1024 encoded bytes" },
    { junk z1024enc, 1045, zbin, 768, 0, "junk + 1024 encoded bytes" },
    { z1024enc softEOF, 1045, zbin, 768, 0, "1024 encoded bytes + soft EOF" },
    { z1024enc junk, 1045, zbin, 720, -1, "1024 encoded bytes + junk" },
    { z2048enc, 2080, zbin, 1536, 0, "2048 encoded bytes" },
    { junk z2048enc, 2085, zbin, 1536, 0, "junk + 2048 encoded bytes" },
    { z2048enc softEOF, 2085, zbin, 1536, 0, "2048 encoded bytes + softEOF" },
    { z2048enc junk, 2085, zbin, 1488, -1, "2048 encoded bytes + junk" },
    { gunk z2048enc, 3105, zbin, 1536, 0, "gunk + 2048 encoded bytes" },
    { NULL, 0, NULL, 0, 0, NULL }
};

static int single_test(test_case *t, int eof_return)
{
    char *out;
    BIO *bio, *b64;
    int out_len;
    int n, n1, n2;
    int ret;

    bio = BIO_new(BIO_s_mem());
    if (eof_return <= 0)
        BIO_set_mem_eof_return(bio, eof_return);
    else
        eof_return = 0;

    /*
     * When the input is long enough, and the source bio is retriable, test
     * retries by writting it two steps (1024 bytes, then the rest).
     */
    n1 = t->encoded_len;
    if (eof_return < 0 && n1 > 1024)
        n1 = 1024;
    if (n1 > 0)
        BIO_write(bio, t->encoded, n1);

    b64 = BIO_new(BIO_f_base64());
    BIO_push(b64, bio);

    out_len = t->expected_decode_len + 1024;
    out = OPENSSL_malloc(out_len);
    n = BIO_read(b64, out, out_len);

    /* Retry when we have more input */
    if (n1 < t->encoded_len) {
        /* Append the rest of the input, and read again */
        BIO_write(bio, t->encoded + n1, t->encoded_len - n1);
        if (n > 0) {
            n2 = BIO_read(b64, out + n, out_len - n);
            if (n2 > 0)
                n += n2;
        } else if (n == eof_return) {
            n = BIO_read(b64, out, out_len);
        }
    }

    /* Turn retry-related negative results to normal (0) EOF */
    if (n < 0 && n == eof_return)
        n = 0;

    /* Turn off retries */
    if (eof_return < 0)
        BIO_set_mem_eof_return(bio, 0);

    if (n < out_len) {
        /* Perform the last read, checking its result */
        ret = BIO_read(b64, out + n, out_len - n);
    } else {
        /* Should not happen, given extra space in out_len */
        ret = t->last_read_ret - 1;
    }

    /* Should now equal the expected last read return */
    ret = ret == t->last_read_ret ? 0 : -1;

    /* After decoding the expected output, if any */
    if (n == t->expected_decode_len) {
        if (memcmp(t->expected_decode, out, n) != 0)
            ret = -1;
    } else if (t->expected_decode_len != 0 || t->last_read_ret == 0) {
        ret = -1;
    }

    BIO_free_all(b64);
    OPENSSL_free(out);

    return ret;
}

int main(void)
{
    test_case *t;
    int ok = 1;

    for (t = tests; t->encoded != NULL; ++t) {
        if (single_test(t, 0) != 0) {
            fprintf(stderr, "Failed bio_base64_test: %s\n", t->desc);
            ok = 0;
        }
        /*
         * Distinguish between EOF and data error results by choosing an
         * "unnatural" EOF return value.
         */
        if (single_test(t, -1729) != 0) {
            fprintf(stderr, "Failed retry bio_base64_test: %s\n", t->desc);
            ok = 0;
        }
    }
    return ok ? 0 : 1;
}
