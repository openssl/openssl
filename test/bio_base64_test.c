/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "testutil.h"

/* 2047 bytes of "#ooooooooo..." + NUL terminator */
static char gunk[2048];

typedef struct {
    char *prefix;
    char *encoded;
    unsigned bytes;
    int trunc;
    char *suffix;
    int retry;
    int no_nl;
} test_case;

#define BUFMAX 0xa0000 /* Encode at most 640kB. */
#define sEOF "-EOF" /* '-' as in PEM and MIME boundaries */
#define junk "#foo" /* Skipped initial content */

#define EOF_RETURN (-1729) /* Distinct from -1, etc., internal results */
#define NLEN 6
#define NVAR 5
/*
 * Junk suffixed variants don't make sense with padding or truncated groups
 * because we will typically stop with an error before seeing the suffix, but
 * with retriable BIOs may never look at the suffix after detecting padding.
 */
#define NPAD 6
#define NVARPAD (NVAR * NPAD - NPAD + 1)

static char *prefixes[NVAR] = { "", junk, gunk, "", "" };
static char *suffixes[NVAR] = { "", "", "", sEOF, junk };
static unsigned lengths[6] = { 0, 3, 48, 192, 768, 1536 };
static unsigned linelengths[] = {
    4, 8, 16, 28, 40, 64, 80, 128, 256, 512, 1023, 0
};
static unsigned wscnts[] = { 0, 1, 2, 4, 8, 16, 0xFFFF };

#define B64_WRITE_INJECT_RETRY_NEG 0
#define B64_WRITE_INJECT_RETRY_ZERO 1
#define B64_WRITE_INJECT_SHORT 2
#define B64_WRITE_INJECT_SHORT_THEN_RETRY 3
#define B64_WRITE_INJECT_NONE (-1)
#define B64_WRITE_INJECT_AFTER_SHORT_RETRY (-2)
#define B64_WRITE_INJECT_COUNT 4
#define B64_WRITE_TEST_LINE_INPUT_LEN 48
#define B64_WRITE_TEST_INPUT_LEN_ALIGNED 96
#define B64_WRITE_TEST_INPUT_LEN_TAIL 97
#define B64_WRITE_TEST_INPUT_COUNT 2
#define B64_WRITE_TEST_SECOND_INPUT_LEN 49
#define B64_WRITE_TEST_SHORT_LEN 5
#define B64_WRITE_SCENARIO_FLUSH_ONLY 0
#define B64_WRITE_SCENARIO_SECOND_WRITE_DRAINS 1
#define B64_WRITE_SCENARIO_SECOND_WRITE_INJECTS 2
#define B64_WRITE_SCENARIO_COUNT 3

typedef struct {
    int inject;
} b64_write_test_data;

static BIO_METHOD *b64_write_test_method = NULL;
static const int b64_write_test_input_lens[B64_WRITE_TEST_INPUT_COUNT] = {
    B64_WRITE_TEST_INPUT_LEN_ALIGNED,
    B64_WRITE_TEST_INPUT_LEN_TAIL
};

static int b64_write_test_update_len(int inl, int no_nl)
{
    int update_inl = inl - inl % B64_WRITE_TEST_LINE_INPUT_LEN;
    int ret = update_inl / 3 * 4;

    if (!no_nl)
        ret += update_inl / B64_WRITE_TEST_LINE_INPUT_LEN;
    return ret;
}

static int b64_write_test_update_len_since(int previous_inl, int inl,
    int no_nl)
{
    return b64_write_test_update_len(previous_inl + inl, no_nl)
        - b64_write_test_update_len(previous_inl, no_nl);
}

static int b64_write_test_final_pending(int inl)
{
    return inl % B64_WRITE_TEST_LINE_INPUT_LEN != 0;
}

static int b64_write_test_new(BIO *bio)
{
    b64_write_test_data *data = OPENSSL_zalloc(sizeof(*data));

    if (data == NULL)
        return 0;

    BIO_set_data(bio, data);
    BIO_set_init(bio, 1);
    return 1;
}

static int b64_write_test_free(BIO *bio)
{
    b64_write_test_data *data = BIO_get_data(bio);

    OPENSSL_free(data);
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 0);
    return 1;
}

static int b64_write_test_write(BIO *bio, const char *in, int inl)
{
    b64_write_test_data *data = BIO_get_data(bio);
    BIO *next = BIO_next(bio);
    int ret;

    BIO_clear_retry_flags(bio);
    if (data == NULL || next == NULL)
        return 0;

    switch (data->inject) {
    case B64_WRITE_INJECT_RETRY_NEG:
    case B64_WRITE_INJECT_AFTER_SHORT_RETRY:
        data->inject = B64_WRITE_INJECT_NONE;
        BIO_set_retry_write(bio);
        return -1;

    case B64_WRITE_INJECT_RETRY_ZERO:
        data->inject = B64_WRITE_INJECT_NONE;
        BIO_set_retry_write(bio);
        return 0;

    case B64_WRITE_INJECT_SHORT:
        data->inject = B64_WRITE_INJECT_NONE;
        if (inl > B64_WRITE_TEST_SHORT_LEN)
            inl = B64_WRITE_TEST_SHORT_LEN;
        break;

    case B64_WRITE_INJECT_SHORT_THEN_RETRY:
        data->inject = B64_WRITE_INJECT_AFTER_SHORT_RETRY;
        if (inl > B64_WRITE_TEST_SHORT_LEN)
            inl = B64_WRITE_TEST_SHORT_LEN;
        break;
    }

    ret = BIO_write(next, in, inl);
    BIO_copy_next_retry(bio);
    return ret;
}

static long b64_write_test_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    BIO *next = BIO_next(bio);
    long ret;

    if (next == NULL)
        return 0;

    BIO_clear_retry_flags(bio);
    ret = BIO_ctrl(next, cmd, num, ptr);
    BIO_copy_next_retry(bio);
    return ret;
}

static const BIO_METHOD *bio_f_b64_write_test(void)
{
    int type;

    if (b64_write_test_method == NULL) {
        type = BIO_get_new_index();
        if (type == -1)
            return NULL;

        if ((b64_write_test_method = BIO_meth_new(type | BIO_TYPE_FILTER, "b64 write test")) == NULL
            || !BIO_meth_set_write(b64_write_test_method,
                b64_write_test_write)
            || !BIO_meth_set_ctrl(b64_write_test_method,
                b64_write_test_ctrl)
            || !BIO_meth_set_create(b64_write_test_method,
                b64_write_test_new)
            || !BIO_meth_set_destroy(b64_write_test_method,
                b64_write_test_free)) {
            BIO_meth_free(b64_write_test_method);
            b64_write_test_method = NULL;
            return NULL;
        }
    }

    return b64_write_test_method;
}

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
 * Encode an octet string in base64, approximately `llen` bytes per line,
 * with up to roughly `wscnt` additional space characters inserted at random
 * before some of the base64 code points.
 */
static int encode(unsigned const char *buf, unsigned buflen, char *encoded,
    int trunc, unsigned llen, unsigned wscnt, BIO *mem)
{
    static const unsigned char b64[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int pos = 0;
    char nl = '\n';

    /* Use a verbatim encoding when provided */
    if (encoded != NULL) {
        int elen = (int)strlen(encoded);

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

    while (trunc-- > 0)
        if (memoutws(mem, 'A', wscnt, llen, &pos) == 0)
            return 0;

    /* Terminate last line */
    if (pos > 0 && BIO_write(mem, &nl, 1) != 1)
        return 0;

    return 1;
}

static int genb64(char *prefix, char *suffix, unsigned const char *buf,
    unsigned buflen, int trunc, char *encoded, unsigned llen,
    unsigned wscnt, char **out)
{
    int preflen = (int)strlen(prefix);
    int sufflen = (int)strlen(suffix);
    int outlen;
    char newline = '\n';
    BUF_MEM *bptr;
    BIO *mem = BIO_new(BIO_s_mem());

    if (mem == NULL)
        return -1;

    if ((*prefix && (BIO_write(mem, prefix, preflen) != preflen || BIO_write(mem, &newline, 1) != 1))
        || encode(buf, buflen, encoded, trunc, llen, wscnt, mem) <= 0
        || (*suffix && (BIO_write(mem, suffix, sufflen) != sufflen || BIO_write(mem, &newline, 1) != 1))) {
        BIO_free(mem);
        return -1;
    }

    /* Orphan the memory BIO's data buffer */
    BIO_get_mem_ptr(mem, &bptr);
    *out = bptr->data;
    outlen = (int)bptr->length;
    bptr->data = NULL;
    (void)BIO_set_close(mem, BIO_NOCLOSE);
    BIO_free(mem);
    BUF_MEM_free(bptr);

    return outlen;
}

static int test_bio_base64_run(test_case *t, int llen, int wscnt)
{
    unsigned char *raw = NULL;
    unsigned char *out = NULL;
    unsigned out_len;
    char *encoded = NULL;
    int elen;
    BIO *bio = NULL, *b64 = NULL;
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

    if (raw == NULL && t->bytes > 0) {
        TEST_error("out of memory");
        return -1;
    }

    out_len = t->bytes + 1024;
    out = OPENSSL_malloc(out_len);
    if (out == NULL) {
        TEST_error("out of memory");
        ret = -1;
        goto end;
    }

    elen = genb64(t->prefix, t->suffix, raw, t->bytes, t->trunc, t->encoded,
        llen, wscnt, &encoded);
    if (elen < 0 || (bio = BIO_new(BIO_s_mem())) == NULL) {
        TEST_error("out of memory");
        ret = -1;
        goto end;
    }
    if (t->retry)
        BIO_set_mem_eof_return(bio, EOF_RETURN);
    else
        BIO_set_mem_eof_return(bio, 0);

    /*
     * When the input is long enough, and the source bio is retriable, exercise
     * retries by writing the input to the underlying BIO in two steps (1024
     * bytes, then the rest) and trying to decode some data after each write.
     */
    n1 = elen;
    if (t->retry)
        n1 = elen / 2;
    if (n1 > 0)
        BIO_write(bio, encoded, n1);

    if (!TEST_ptr(b64 = BIO_new(BIO_f_base64()))) {
        ret = -1;
        goto end;
    }
    if (t->no_nl)
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);

    n = BIO_read(b64, out, out_len);

    if (n1 < elen) {
        /* Append the rest of the input, and read again */
        BIO_write(bio, encoded + n1, elen - n1);
        if (n > 0) {
            n2 = BIO_read(b64, out + n, out_len - n);
            if (n2 > 0)
                n += n2;
        } else if (n == EOF_RETURN) {
            n = BIO_read(b64, out, out_len);
        }
    }

    /* Turn retry-related negative results to normal (0) EOF */
    if (n < 0 && n == EOF_RETURN)
        n = 0;

    /* Turn off retries */
    if (t->retry)
        BIO_set_mem_eof_return(bio, 0);

    if (n < (int)out_len)
        /* Perform the last read, checking its result */
        ret = BIO_read(b64, out + n, out_len - n);
    else {
        /* Should not happen, given extra space in out_len */
        TEST_error("Unexpectedly long decode output");
        ret = -1;
    }

    /*
     * Expect an error to be detected with:
     *
     * - truncated groups,
     * - non-base64 suffixes (other than soft EOF) for non-empty or oneline
     *   input
     * - non-base64 prefixes in NO_NL mode
     *
     * Otherwise, check the decoded content
     */
    if (t->trunc > 0
        || ((t->bytes > 0 || t->no_nl) && *t->suffix && *t->suffix != '-')
        || (t->no_nl && *t->prefix)) {
        if ((ret = ret < 0 ? 0 : -1) != 0)
            TEST_error("Final read result was non-negative");
    } else if (ret != 0
        || n != (int)t->bytes
        || (n > 0 && memcmp(raw, out, n) != 0)) {
        TEST_error("Failed to decode expected data");
        ret = -1;
    }

end:
    BIO_free(bio);
    BIO_free(b64);
    OPENSSL_free(raw);
    OPENSSL_free(out);
    OPENSSL_free(encoded);
    return ret;
}

static int generic_case(test_case *t, int verbose)
{
    unsigned *llen;
    unsigned *wscnt;
    int ok = 1;

    for (llen = linelengths; *llen > 0; ++llen) {
        for (wscnt = wscnts; *wscnt * 2 < *llen; ++wscnt) {
            int extra = t->no_nl ? 64 : 0;

            /*
             * Use a longer line for NO_NL tests, in particular, eventually
             * exceeding 1k bytes.
             */
            if (test_bio_base64_run(t, *llen + extra, *wscnt) != 0)
                ok = 0;

            if (verbose) {
                fprintf(stderr, "bio_base64_test: ok=%d", ok);
                if (*t->prefix)
                    fprintf(stderr, ", prefix='%s'", t->prefix);
                if (t->encoded)
                    fprintf(stderr, ", data='%s'", t->encoded);
                else
                    fprintf(stderr, ", datalen=%u", t->bytes);
                if (t->trunc)
                    fprintf(stderr, ", trunc=%d", t->trunc);
                if (*t->suffix)
                    fprintf(stderr, ", suffix='%s'", t->suffix);
                fprintf(stderr, ", linelen=%u", *llen);
                fprintf(stderr, ", wscount=%u", *wscnt);
                if (t->retry)
                    fprintf(stderr, ", retriable");
                if (t->no_nl)
                    fprintf(stderr, ", oneline");
                fputc('\n', stderr);
            }

            /* For verbatim input no effect from varying llen or wscnt */
            if (t->encoded)
                return ok;
        }
        /*
         * Longer 'llen' has no effect once we're sure to not have multiple
         * lines of data
         */
        if (*llen > t->bytes + (t->bytes >> 1))
            break;
    }
    return ok;
}

static int quotrem(int i, unsigned int m, int *q)
{
    *q = i / m;
    return i - *q * m;
}

static int test_bio_base64_generated(int idx)
{
    test_case t;
    int variant;
    int lencase;
    int padcase;
    int q = idx;

    lencase = quotrem(q, NLEN, &q);
    variant = quotrem(q, NVARPAD, &q);
    padcase = quotrem(variant, NPAD, &variant);
    t.retry = quotrem(q, 2, &q);
    t.no_nl = quotrem(q, 2, &q);

    if (q != 0) {
        fprintf(stderr, "Test index out of range: %d", idx);
        return 0;
    }

    t.prefix = prefixes[variant];
    t.encoded = NULL;
    t.bytes = lengths[lencase];
    t.trunc = 0;
    if (padcase && padcase < 3)
        t.bytes += padcase;
    else if (padcase >= 3)
        t.trunc = padcase - 2;
    t.suffix = suffixes[variant];

    if (padcase != 0 && (*t.suffix && *t.suffix != '-')) {
        TEST_error("Unexpected suffix test after padding");
        return 0;
    }

    return generic_case(&t, 0);
}

static int test_bio_base64_corner_case_bug(int idx)
{
    test_case t;
    int q = idx;

    t.retry = quotrem(q, 2, &q);
    t.no_nl = quotrem(q, 2, &q);

    if (q != 0) {
        fprintf(stderr, "Test index out of range: %d", idx);
        return 0;
    }

    /* 9 bytes of skipped non-base64 input + newline */
    t.prefix = "#foo\n#bar";

    /* 9 bytes on 2nd and subsequent lines */
    t.encoded = "A\nAAA\nAAAA\n";
    t.suffix = "";

    /* Expected decode length */
    t.bytes = 6;
    t.trunc = 0; /* ignored */

    return generic_case(&t, 0);
}

static int base64_encode_reference(const char *in, int inl, int no_nl,
    unsigned char **out, size_t *out_len)
{
    BIO *b64 = NULL;
    BIO *mem = NULL;
    BUF_MEM *bptr = NULL;
    int ok = 0;

    *out = NULL;
    *out_len = 0;

    if (!TEST_ptr(b64 = BIO_new(BIO_f_base64()))
        || !TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto done;

    if (no_nl)
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    if (!TEST_ptr_eq(BIO_push(b64, mem), b64)
        || !TEST_int_eq(BIO_write(b64, in, inl), inl)
        || !TEST_true(BIO_flush(b64)))
        goto done;

    BIO_get_mem_ptr(mem, &bptr);
    if (!TEST_ptr(bptr))
        goto done;

    if (bptr->length > 0) {
        if (!TEST_ptr(*out = OPENSSL_memdup(bptr->data, bptr->length)))
            goto done;
        *out_len = bptr->length;
    }
    ok = 1;

done:
    BIO_free_all(b64);
    return ok;
}

static int b64_write_test_check_injected_state(BIO *b64, int mode,
    int update_len,
    int final_pending)
{
    switch (mode) {
    case B64_WRITE_INJECT_RETRY_NEG:
    case B64_WRITE_INJECT_RETRY_ZERO:
        return TEST_true(BIO_should_retry(b64))
            && TEST_int_eq(BIO_wpending(b64), update_len);

    case B64_WRITE_INJECT_SHORT_THEN_RETRY:
        return TEST_true(BIO_should_retry(b64))
            && TEST_int_eq(BIO_wpending(b64),
                update_len - B64_WRITE_TEST_SHORT_LEN);

    case B64_WRITE_INJECT_SHORT:
        return TEST_false(BIO_should_retry(b64))
            && TEST_int_eq(BIO_wpending(b64), final_pending);

    default:
        TEST_error("Invalid base64 write injection mode: %d", mode);
        return 0;
    }
}

static int test_bio_base64_write_retry(int idx)
{
    char msg[B64_WRITE_TEST_INPUT_LEN_TAIL + B64_WRITE_TEST_SECOND_INPUT_LEN];
    BIO *b64 = NULL;
    BIO *inject = NULL;
    BIO *mem = NULL;
    BIO *membio = NULL;
    BUF_MEM *bptr = NULL;
    b64_write_test_data *data;
    unsigned char *expected = NULL;
    size_t expected_len = 0;
    int mode;
    int no_nl;
    int scenario;
    int input_idx;
    int in_len;
    int total_len;
    int update_len;
    int first_final_pending;
    int q = idx;
    int ret;
    int ok = 0;

    mode = quotrem(q, B64_WRITE_INJECT_COUNT, &q);
    no_nl = quotrem(q, 2, &q);
    scenario = quotrem(q, B64_WRITE_SCENARIO_COUNT, &q);
    input_idx = quotrem(q, B64_WRITE_TEST_INPUT_COUNT, &q);
    if (q != 0) {
        fprintf(stderr, "Test index out of range: %d", idx);
        return 0;
    }
    in_len = b64_write_test_input_lens[input_idx];
    total_len = in_len;
    if (scenario != B64_WRITE_SCENARIO_FLUSH_ONLY)
        total_len += B64_WRITE_TEST_SECOND_INPUT_LEN;
    update_len = b64_write_test_update_len_since(0, in_len, no_nl);
    first_final_pending = b64_write_test_final_pending(in_len);
    memset(msg, 'A', in_len);
    memset(msg + in_len, 'B', B64_WRITE_TEST_SECOND_INPUT_LEN);

    if (!TEST_true(base64_encode_reference(msg, total_len, no_nl,
            &expected, &expected_len))
        || !TEST_ptr(b64 = BIO_new(BIO_f_base64()))
        || !TEST_ptr(inject = BIO_new(bio_f_b64_write_test()))
        || !TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto done;

    data = BIO_get_data(inject);
    if (!TEST_ptr(data))
        goto done;
    data->inject = scenario == B64_WRITE_SCENARIO_SECOND_WRITE_INJECTS
        ? B64_WRITE_INJECT_NONE
        : mode;

    if (no_nl)
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    membio = mem;
    if (!TEST_ptr_eq(BIO_push(inject, mem), inject))
        goto done;
    mem = NULL;

    if (!TEST_ptr_eq(BIO_push(b64, inject), b64))
        goto done;
    inject = NULL;

    ret = BIO_write(b64, msg, in_len);
    if (!TEST_int_eq(ret, in_len))
        goto done;

    if (scenario == B64_WRITE_SCENARIO_SECOND_WRITE_INJECTS) {
        if (!TEST_false(BIO_should_retry(b64))
            || !TEST_int_eq(BIO_wpending(b64), first_final_pending))
            goto done;
    } else if (!b64_write_test_check_injected_state(b64, mode, update_len,
                   first_final_pending)) {
        goto done;
    }

    /*
     * Verify both second-write paths: pending encoded output is flushed before
     * newly supplied input is accepted, and an injected second write with no
     * prior encoded-output pending retains its own unwritten output.
     */
    if (scenario != B64_WRITE_SCENARIO_FLUSH_ONLY) {
        if (scenario == B64_WRITE_SCENARIO_SECOND_WRITE_INJECTS)
            data->inject = mode;

        ret = BIO_write(b64, msg + in_len, B64_WRITE_TEST_SECOND_INPUT_LEN);
        if (!TEST_int_eq(ret, B64_WRITE_TEST_SECOND_INPUT_LEN))
            goto done;

        if (scenario == B64_WRITE_SCENARIO_SECOND_WRITE_INJECTS) {
            update_len = b64_write_test_update_len_since(in_len,
                B64_WRITE_TEST_SECOND_INPUT_LEN,
                no_nl);
            if (!b64_write_test_check_injected_state(
                    b64, mode, update_len,
                    b64_write_test_final_pending(total_len)))
                goto done;
        } else if (!TEST_false(BIO_should_retry(b64))
            || !TEST_int_eq(BIO_wpending(b64),
                b64_write_test_final_pending(total_len))) {
            goto done;
        }
    }

    if (!TEST_true(BIO_flush(b64)))
        goto done;

    BIO_get_mem_ptr(membio, &bptr);
    if (!TEST_ptr(bptr)
        || !TEST_mem_eq(expected, expected_len, bptr->data, bptr->length))
        goto done;

    ok = 1;

done:
    BIO_free_all(b64);
    BIO_free_all(inject);
    BIO_free(mem);
    OPENSSL_free(expected);
    return ok;
}

#define MEM_CHK "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB" \
                "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB" \
                "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"

static int test_bio_base64_no_nl(void)
{
    char msg[120];
    BIO *b64 = NULL;
    BIO *mem = NULL;
    BIO *b64_chk;
    BUF_MEM *bptr = NULL;
    int ok = 0;

    memset(msg, 'A', sizeof(msg));

    b64 = BIO_new(BIO_f_base64());
    if (!TEST_ptr(b64))
        goto done;

    mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem))
        goto done;

    b64_chk = BIO_push(b64, mem);
    if (!TEST_ptr_eq(b64, b64_chk))
        goto done;

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, msg, sizeof(msg));
    if (!TEST_true(BIO_flush(b64)))
        goto done;
    BIO_get_mem_ptr(mem, &bptr);
    ok = TEST_mem_eq(MEM_CHK, sizeof(MEM_CHK) - 1, bptr->data, bptr->length);

done:
    BIO_free_all(b64);
    return ok;
}

int setup_tests(void)
{
    int numidx;

    memset(gunk, 'o', sizeof(gunk));
    gunk[0] = '#';
    gunk[sizeof(gunk) - 1] = '\0';

    /*
     * Test 5 variants of prefix or suffix
     *
     *  - both empty
     *  - short junk prefix
     *  - long gunk prefix (> internal BIO 1k buffer size),
     *  - soft EOF suffix
     *  - junk suffix (expect to detect an error)
     *
     * For 6 input lengths of randomly generated raw input:
     *
     *  0, 3, 48, 192, 768 and 1536
     *
     * corresponding to encoded lengths (plus linebreaks and ignored
     * whitespace) of:
     *
     *  0, 4, 64, 256, 1024 and 2048
     *
     * Followed by zero, one or two additional bytes that may involve padding,
     * or else (truncation) 1, 2 or 3 bytes with missing padding.
     * Only the first four variants make sense with padding or truncated
     * groups.
     *
     * With two types of underlying BIO
     *
     *  - Non-retriable underlying BIO
     *  - Retriable underlying BIO
     *
     * And with/without the BIO_FLAGS_BASE64_NO_NL flag, where now an error is
     * expected with the junk and gunk prefixes, however, but the "soft EOF"
     * suffix is still accepted.
     *
     * Internally, each test may loop over a range of encoded line lengths and
     * whitespace average "densities".
     */
    numidx = NLEN * (NVAR * NPAD - NPAD + 1) * 2 * 2;
    ADD_ALL_TESTS(test_bio_base64_generated, numidx);

    /*
     * Corner case in original code that skips ignored input, when the ignored
     * length is one byte longer than the total of the second and later lines
     * of valid input in the first 1k bytes of input.  No content variants,
     * just BIO retry status and oneline flags vary.
     */
    numidx = 2 * 2;
    ADD_ALL_TESTS(test_bio_base64_corner_case_bug, numidx);

    ADD_ALL_TESTS(test_bio_base64_write_retry,
        B64_WRITE_INJECT_COUNT * 2 * B64_WRITE_SCENARIO_COUNT
            * B64_WRITE_TEST_INPUT_COUNT);
    ADD_TEST(test_bio_base64_no_nl);
    return 1;
}

void cleanup_tests(void)
{
    BIO_meth_free(b64_write_test_method);
    b64_write_test_method = NULL;
}
