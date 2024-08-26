/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "testutil.h"

/* 2048 bytes of "#ooooooooo...\n" + NUL terminator */
static char gunk[2049];

typedef struct {
    char *prefix;
    char *encoded;
    unsigned bytes;
    char *suffix;
    int last_read_ret;
    char *desc;
} test_case;

#define BUFMAX 0xa0000          /* Encode at most 640kB. */
#define sEOF "-EOF\n"           /* '-' as in PEM and MIME boundaries */
#define junk "#foo\n"           /* Skipped initial content */
#define junk2 "#foo\n#bar\n"    /* Edge case in original decoder */
#define edge  "A\nAAA\nAAAA\n"  /* was misdecoded with junk2 as prefix */

static test_case tests[] = {
    { "",         NULL,    0,   "",  0, "empty" },
    { "",         NULL,    0, sEOF,  0, "soft EOF" },
    { junk,       NULL,    0,   "",  0, "non-b64 junk" },
    { gunk,       NULL,    0,   "",  0, "non-b64 gunk" },
    { "",         NULL,    1,   "",  0, "padded byte" },
    { "",         NULL,    2,   "",  0, "padded double byte" },
    { "",         NULL,    3,   "",  0, "single block" },
    { "",   "A\nAAA\n",    3,   "",  0, "split single block" },
    { "", "AAAA\nAA\n",    0,   "", -1, "missing padding" },
    { "",  "AAAA\nA\n",    0,   "", -1, "truncated input" },
    { junk,   "AAAA\n",    3,   "",  0, "junk + single" },
    { junk, "A\nAAA\n",    3,   "",  0, "junk + split single" },
    { junk2,      edge,    6,   "",  0, "edge case decode" },
    { gunk,   "AAAA\n",    3,   "",  0, "gunk + single" },
    { gunk, "A\nAAA\n",    3,   "",  0, "gunk + split single" },
    { "",     "AAAA\n",    3, sEOF,  0, "single + soft EOF" },
    { "",     "AAAA\n",    0, junk, -1, "single + junk" },
    { "",         NULL,   48,   "",  0, "64 encoded bytes" },
    { junk,       NULL,   48,   "",  0, "junk + 64 encoded bytes" },
    { "",         NULL,   48, sEOF,  0, "64 encoded bytes + soft EOF" },
    { "",         NULL,   48, junk, -1, "64 encoded bytes + junk" },
    { "",         NULL,  192,   "",  0, "256 encoded bytes" },
    { junk,       NULL,  192,   "",  0, "junk + 256 encoded bytes" },
    { "",         NULL,  192, sEOF,  0, "256 encoded bytes + soft EOF" },
    { "",         NULL,  192, junk, -1, "256 encoded bytes + junk" },
    { "",         NULL,  768,   "",  0, "1024 encoded bytes" },
    { junk,       NULL,  768,   "",  0, "junk + 1024 encoded bytes" },
    { "",         NULL,  768, sEOF,  0, "1024 encoded bytes + soft EOF" },
    { "",         NULL,  768, junk, -1, "1024 encoded bytes + junk" },
    { "",         NULL, 1536,   "",  0, "2048 encoded bytes" },
    { junk,       NULL, 1536,   "",  0, "junk + 2048 encoded bytes" },
    { "",         NULL, 1536, sEOF,  0, "2048 encoded bytes + soft EOF" },
    { "",         NULL, 1536, junk, -1, "2048 encoded bytes + junk" },
    { gunk,       NULL, 1536,   "",  0, "gunk + 2048 encoded bytes" },
    { NULL,       NULL,    0, NULL,  0, NULL }
};

/* Generate `len` random octets */
static unsigned char *genbytes(unsigned len)
{
    unsigned char *buf = NULL;

    if (len > 0 && len <= BUFMAX && (buf = OPENSSL_malloc(len)) != NULL)
        RAND_bytes(buf, len);

    return buf;
}

/* Append one base64 codepoint, adding newlines after every `llen` bytes */
static int memout(BIO *mem, char c, int llen, int *pos)
{
    if (BIO_write(mem, &c, 1) != 1)
        return 0;
    if (++*pos == llen) {
        *pos = 0;
        c = '\n';
        if (BIO_write(mem, &c, 1) != 1)
            return 0;
    }
    return 1;
}

/* Encode and append one 6-bit slice, randomly prepending some whitespace */
static int memoutws(BIO *mem, char c, unsigned wscnt, unsigned llen, int *pos)
{
    if (wscnt > 0
        && (test_random() % llen) < wscnt
        && memout(mem, ' ', llen, pos) == 0)
        return 0;
    return memout(mem, c, llen, pos);
}

/*
 * Encode an octent string in base64, approximately `llen` bytes per line,
 * with up to roughly `wscnt` additional space characters inserted at random
 * before some of the base64 code points.
 */
static int encode(unsigned const char *buf, unsigned buflen, char *encoded,
                  unsigned llen, unsigned wscnt, BIO *mem)
{
    static const unsigned char b64[65] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int pos = 0;
    char nl = '\n';

    if (buflen < 0)
        return 0;

    /* Use a verbatim encoding when provided */
    if (encoded != NULL) {
        int elen = strlen(encoded);

        return BIO_write(mem, encoded, elen) == elen;
    }

    /* Encode full 3-octet groups */
    while (buflen > 2) {
        unsigned long v = buf[0] << 16 | buf[1] << 8 | buf[2];

        if (memoutws(mem, b64[v >> 18], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[(v >> 12) & 0x3f], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[(v >> 6) & 0x3f], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[v & 0x3f], wscnt, llen, &pos) == 0)
            return 0;
        buf += 3;
        buflen -= 3;
    }

    /* Encode and pad final 1 or 2 octet group */
    if (buflen == 2) {
        unsigned long v = buf[0] << 8 | buf[1];

        if (memoutws(mem, b64[(v >> 10) & 0x3f], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[(v >> 4) & 0x3f], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[(v & 0xf) << 2], wscnt, llen, &pos) == 0
            || memoutws(mem, '=', wscnt, llen, &pos) == 0)
            return 0;
    } else if (buflen == 1) {
        unsigned long v = buf[0];

        if (memoutws(mem, b64[v >> 2], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[(v & 0x3) << 4], wscnt, llen, &pos) == 0
            || memoutws(mem, '=', wscnt, llen, &pos) == 0
            || memoutws(mem, '=', wscnt, llen, &pos) == 0)
            return 0;
    }

    /* Terminate last line */
    if (pos > 0 && BIO_write(mem, &nl, 1) != 1)
        return 0;

    return 1;
}

static int genb64(char *prefix, char *suffix, unsigned const char *buf,
                  unsigned buflen, char *encoded, unsigned llen,
                  unsigned wscnt, char **out)
{
    int preflen = strlen(prefix);
    int sufflen = strlen(suffix);
    int outlen;
    BUF_MEM *bptr;
    BIO *mem = BIO_new(BIO_s_mem());

    if (mem == NULL)
        return -1;

    if (BIO_write(mem, prefix, preflen) != preflen
        || encode(buf, buflen, encoded, llen, wscnt, mem) <= 0
        || BIO_write(mem, suffix, sufflen) != sufflen) {
        BIO_free(mem);
        return -1;
    }

    /* Orphan the memory BIO's data buffer */
    BIO_get_mem_ptr(mem, &bptr);
    *out = bptr->data;
    outlen = bptr->length;
    bptr->data = NULL;
    (void) BIO_set_close(mem, BIO_NOCLOSE);
    BIO_free(mem);
    BUF_MEM_free(bptr);

    return outlen;
}

static int single_test(test_case *t, int eof_return, int llen, int wscnt)
{
    unsigned char *raw;
    unsigned char *out;
    unsigned out_len;
    char *encoded = NULL;
    int elen;
    BIO *bio, *b64;
    int n, n1, n2;
    int ret;

    /*
     * Pre-encoded data always encodes NUL octets.  If all we care about is the
     * length, and not the payload, use random bytes.
     */
    if (t->encoded != NULL)
        raw = OPENSSL_zalloc(t->bytes);
    else
        raw = genbytes(t->bytes);

    if (raw == NULL && t->bytes > 0)
        return -1;

    out_len = t->bytes + 1024;
    out = OPENSSL_malloc(out_len);
    if (out == NULL) {
        OPENSSL_free(raw);
        return -1;
    }

    elen = genb64(t->prefix, t->suffix, raw, t->bytes, t->encoded,
                  llen, wscnt, &encoded);
    if (elen < 0 || (bio = BIO_new(BIO_s_mem())) == NULL) {
        OPENSSL_free(raw);
        OPENSSL_free(out);
        OPENSSL_free(encoded);
        return -1;
    }
    if (eof_return <= 0)
        BIO_set_mem_eof_return(bio, eof_return);
    else
        eof_return = 0;

    /*
     * When the input is long enough, and the source bio is retriable, test
     * retries by writting it in two steps (1024 bytes, then the rest).
     */
    n1 = elen;
    if (eof_return < 0 && n1 > 1024)
        n1 = 1024;
    if (n1 > 0)
        BIO_write(bio, encoded, n1);

    b64 = BIO_new(BIO_f_base64());
    BIO_push(b64, bio);

    n = BIO_read(b64, out, out_len);

    /* Retry when we have more input */
    if (n1 < elen) {
        /* Append the rest of the input, and read again */
        BIO_write(bio, encoded + n1, elen - n1);
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

    if (n < (int) out_len) {
        /* Perform the last read, checking its result */
        ret = BIO_read(b64, out + n, out_len - n);
    } else {
        /* Should not happen, given extra space in out_len */
        ret = t->last_read_ret - 1;
    }

    /* Should now equal the expected last read return */
    ret = ret == t->last_read_ret ? 0 : -1;

    /* Check the decoded content if any */
    if ((t->last_read_ret == 0 && n != (int) t->bytes)
        || (n > 0 && memcmp(raw, out, n) != 0))
        ret = -1;

    BIO_free_all(b64);
    OPENSSL_free(out);
    OPENSSL_free(raw);
    OPENSSL_free(encoded);

    return ret;
}

static unsigned lengths[] = {
    4, 8, 16, 28, 40, 64, 80, 128, 256, 512, 1023, 0
};
static unsigned wscnts[] = { 0, 1, 2, 4, 8, 16, 0xFFFF };

int main(void)
{
    test_case *t;
    int ok = 1;
    unsigned *llen;
    unsigned *wscnt;
    int done;

    memset(gunk, 'o', sizeof(gunk));
    gunk[0] = '#';
    gunk[sizeof(gunk) - 2] = '\n';
    gunk[sizeof(gunk) - 1] = '\0';

    test_random_seed((uint32_t)time(NULL));

    for (t = tests; t->desc != NULL; ++t) {
        done = 0;
        for (llen = lengths; !done && *llen > 0; ++llen) {
            for (wscnt = wscnts;
                 !done && *wscnt >= 0 && *wscnt * 2 < *llen;
                 ++wscnt) {
                if (single_test(t, 0, *llen, *wscnt) != 0) {
                    fprintf(stderr, "Failed %s: retry=no llen=%u, wscnt=%u\n",
                            t->desc, *llen, *wscnt);
                    ok = 0;
                }
                /*
                 * Distinguish between EOF and data error results by choosing an
                 * "unnatural" EOF return value.
                 */
                if (single_test(t, -1729, *llen, *wscnt) != 0) {
                    fprintf(stderr, "Failed %s: retry=yes llen=%u, wscnt=%u\n",
                            t->desc, *llen, *wscnt);
                    ok = 0;
                }
                /* llen and wscnt are unused with verbatim encoded input */
                if (t->encoded)
                    done = 1;
            }
            /* Stop once we're sure to not have multiple lines of data */
            if (*llen > t->bytes + (t->bytes >> 1))
                done = 1;
        }
    }
    return ok ? 0 : 1;
}
