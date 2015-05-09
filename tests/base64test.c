/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <err.h>
#include <stdio.h>
#include <string.h>

#define BUF_SIZE 128

struct base64_test {
	const unsigned char in[BUF_SIZE];
	const ssize_t in_len;
	const unsigned char out[BUF_SIZE];
	const ssize_t out_len;
	const ssize_t valid_len;
};

/*
 * Many of these tests are based on those found in Go's encoding/base64 tests.
 */
struct base64_test base64_tests[] = {

	/* RFC3548 examples. */
	{ "\x14\xfb\x9c\x03\xd9\x7e", 6, "FPucA9l+", 8, 6, },
	{ "\x14\xfb\x9c\x03\xd9", 5, "FPucA9k=", 8, 5, },
	{ "\x14\xfb\x9c\x03", 4, "FPucAw==", 8, 4, },

	/* RFC4648 examples. */
	{ "", 0, "", 0, 0, },
	{ "f", 1, "Zg==", 4, 1, },
	{ "fo", 2, "Zm8=", 4, 2, },
	{ "foo", 3, "Zm9v", 4, 3, },
	{ "foob", 4, "Zm9vYg==", 8, 4, },
	{ "fooba", 5, "Zm9vYmE=", 8, 5, },
	{ "foobar", 6, "Zm9vYmFy", 8, 6, },

	/* Wikipedia examples. */
	{ "sure.", 5, "c3VyZS4=", 8, 5, },
	{ "sure", 4, "c3VyZQ==", 8, 4, },
	{ "sur", 3, "c3Vy", 4, 3, },
	{ "su", 2, "c3U=", 4, 2, },
	{ "leasure.", 8, "bGVhc3VyZS4=", 12, 8, },
	{ "easure.", 7, "ZWFzdXJlLg==", 12, 7, },
	{ "asure.", 6, "YXN1cmUu", 8, 6, },

	{ "abcd", 4, "YWJjZA==", 8, 4, },

	{
		"Twas brillig, and the slithy toves",
		34,
		"VHdhcyBicmlsbGlnLCBhbmQgdGhlIHNsaXRoeSB0b3Zlcw==",
		48,
		34,
	},
};

#define N_TESTS (sizeof(base64_tests) / sizeof(*base64_tests))

struct base64_test base64_nl_tests[] = {

	/* Corrupt/invalid encodings. */
	{ "", -1, "", 0, 0, },
	{ "", -1, "!!!!", 4, 0, },
	{ "", -1, "====", 4, 0, },
	{ "", -1, "x===", 4, 0, },
	{ "", -1, "=AAA", 4, 0, },
	{ "", -1, "A=AA", 4, 0, },
	{ "", -1, "AA=A", 4, 0, },
	{ "", -1, "AA==A", 5, 0, },
	{ "", -1, "AAA=AAAA", 8, 0, },
	{ "", -1, "AAAAA", 5, 0, },
	{ "", -1, "AAAAAA", 6, 0, },
	{ "", -1, "A=", 2, 0, },
	{ "", -1, "A==", 3, 0, },
	{ "", -1, "AA=", 3, 0, },
	{ "", -1, "AA==", 4, 1, },		/* XXX - output ix 0x0. */
	{ "", -1, "AAA=", 4, 2, },		/* XXX - output ix 2x 0x0. */
	{ "", -1, "AAAA", 4, 3, },		/* XXX - output ix 3x 0x0. */
	{ "", -1, "AAAAAA=", 7, 0, },
	{ "", -1, "YWJjZA=====", 11, 0, },


	/* Encodings with embedded CR/LF. */
	{ "sure", 4, "c3VyZQ==", 8, 4, },
	{ "sure", 4, "c3VyZQ==\r", 9, 4, },
	{ "sure", 4, "c3VyZQ==\n", 9, 4, },
	{ "sure", 4, "c3VyZQ==\r\n", 10, 4, },
	{ "sure", 4, "c3VyZ\r\nQ==", 10, 4, },
	{ "sure", 4, "c3V\ryZ\nQ==", 10, 4, },
	{ "sure", 4, "c3V\nyZ\rQ==", 10, 4, },
	{ "sure", 4, "c3VyZ\nQ==", 9, 4, },
	{ "sure", 4, "c3VyZQ\n==", 9, 4, },
	{ "sure", 4, "c3VyZQ=\n=", 9, 4, },
	{ "sure", 4, "c3VyZQ=\r\n\r\n=", 12, 4, },

	{
		"",
		-1,
		"YWJjZA======================================================"
		"============",
		74,
		0,
	},
};

#define N_NL_TESTS (sizeof(base64_nl_tests) / sizeof(*base64_nl_tests))

struct base64_test base64_no_nl_tests[] = {

	/*
	 * In non-newline mode, the output resulting from corrupt/invalid
	 * encodings is completely crazy. A number of zero bytes is returned
	 * rather than nothing.
	 */

	/* Corrupt/invalid encodings. */
	{ "", -1, "", 0, 0, },
	{ "", -1, "!!!!", 4, 0, },
	{ "", -1, "====", 4, 1, },
	{ "", -1, "x===", 4, 1, },
	{ "", -1, "=AAA", 4, 3, },
	{ "", -1, "A=AA", 4, 3, },
	{ "", -1, "AA=A", 4, 3, },
	{ "", -1, "AA==A", 5, 1, },
	{ "", -1, "AAA=AAAA", 8, 6, },
	{ "", -1, "AAAAA", 5, 3, },
	{ "", -1, "AAAAAA", 6, 3, },
	{ "", -1, "A=", 2, 0, },
	{ "", -1, "A==", 3, 0, },
	{ "", -1, "AA=", 3, 0, },
	{ "", -1, "AA==", 4, 1, },
	{ "", -1, "AAA=", 4, 2, },
	{ "", -1, "AAAA", 4, 3, },
	{ "", -1, "AAAAAA=", 7, 3, },
	{ "", -1, "YWJjZA=====", 11, 4, },

	/* Encodings with embedded CR/LF. */
	{ "sure", 4, "c3VyZQ==", 8, 4, },
	{ "sure", 4, "c3VyZQ==\r", 9, 4, },
	{ "sure", 4, "c3VyZQ==\n", 9, 4, },
	{ "sure", 4, "c3VyZQ==\r\n", 10, 4, },
	{ "sure", -1, "c3VyZ\r\nQ==", 10, 0, },
	{ "sure", -1, "c3V\ryZ\nQ==", 10, 0, },
	{ "sure", -1, "c3V\nyZ\rQ==", 10, 0, },
	{ "sure", -1, "c3VyZ\nQ==", 9, 0, },
	{ "sure", -1, "c3VyZQ\n==", 9, 0, },
	{ "sure", -1, "c3VyZQ=\n=", 9, 0, },
	{ "sure", -1, "c3VyZQ=\r\n\r\n=", 12, 0, },

	/*
	 * This is invalid, yet results in 'abcd' followed by a stream of
	 * zero value bytes.
	 */
	{
		"",
		-1,
		"YWJjZA======================================================"
		"============",
		74,
		52,
	},
};

#define N_NO_NL_TESTS (sizeof(base64_no_nl_tests) / sizeof(*base64_no_nl_tests))

static int
base64_encoding_test(int test_no, struct base64_test *bt, int test_nl)
{
	BIO *bio_b64, *bio_mem;
	unsigned char *buf, *out;
	ssize_t i, len, b64len;
	int failure = 0;

	buf = malloc(BUF_SIZE);
	if (buf == NULL)
		errx(1, "malloc");

	bio_b64 = BIO_new(BIO_f_base64());
	if (bio_b64 == NULL)
		errx(1, "BIO_new failed for BIO_f_base64");

	bio_mem = BIO_new(BIO_s_mem());
	if (bio_mem == NULL)
		errx(1, "BIO_new failed for BIO_s_mem");

	bio_mem = BIO_push(bio_b64, bio_mem);

	if (!test_nl)
		BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

	len = BIO_write(bio_mem, bt->in, bt->in_len);
	if (len != bt->in_len) {
		fprintf(stderr, "FAIL: test %i - only wrote %zi out of %zi "
		    "characters\n", test_no, len, bt->in_len);
		failure = 1;
		goto done;
	}
	if (BIO_flush(bio_mem) < 0) {
		fprintf(stderr, "FAIL: test %i - flush failed\n", test_no);
		failure = 1;
		goto done;
	}

	b64len = 0;
	for (i = 0; i < bt->out_len; i++) {
		if (bt->out[i] == '\r' || bt->out[i] == '\n')
			continue;
		buf[b64len++] = bt->out[i];
	}
	if (test_nl)
		buf[b64len++] = '\n';

	len = BIO_get_mem_data(bio_mem, &out);

	/* An empty string with NL results in no output, rather than '\n'. */
	if (test_nl && b64len == 1 && len == 0)
		goto done;

	if (len != b64len) {
		fprintf(stderr, "FAIL: test %i - encoding resulted in %zi "
		    "characters instead of %zi\n", test_no, len, b64len);
		failure = 1;
		goto done;
	}

	if (memcmp(buf, out, b64len) != 0) {
		fprintf(stderr, "FAIL: test %i - encoding differs:\n", test_no);
		fprintf(stderr, "  encoding: ");
		for (i = 0; i < len; i++)
			fprintf(stderr, "%c", out[i]);
		fprintf(stderr, "\n");
		fprintf(stderr, " test data: ");
		for (i = 0; i < bt->out_len; i++)
			fprintf(stderr, "%c", buf[i]);
		fprintf(stderr, "\n");
		failure = 1;
	}

done:
	BIO_free_all(bio_mem);
	free(buf);

	return failure;
}

static int
base64_decoding_test(int test_no, struct base64_test *bt, int test_nl)
{
	BIO *bio_b64, *bio_mem;
	char *buf, *input;
	ssize_t i, inlen, len;
	int failure = 0;

	buf = malloc(BUF_SIZE);
	if (buf == NULL)
		errx(1, "malloc");

	input = (char *)bt->out;
	inlen = bt->out_len;

	if (test_nl)
		inlen = asprintf(&input, "%s\r\n", bt->out);

	bio_mem = BIO_new_mem_buf(input, inlen);
	if (bio_mem == NULL)
		errx(1, "BIO_new_mem_buf failed");

	bio_b64 = BIO_new(BIO_f_base64());
	if (bio_b64 == NULL)
		errx(1, "BIO_new failed for BIO_f_base64");

	if (!test_nl)
		BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

	bio_mem = BIO_push(bio_b64, bio_mem);

	/*
	 * If we wrote zero characters then a BIO_read will result in a return
	 * value of -1, hence we need to handle this case.
	 */
	len = BIO_read(bio_mem, buf, BUF_SIZE);
	if (len != bt->valid_len && (bt->in_len != 0 || len != -1)) {
		fprintf(stderr, "FAIL: test %i - decoding resulted in %zi "
		    "characters instead of %zi\n", test_no, len, bt->valid_len);
		fprintf(stderr, "  input: ");
		for (i = 0; i < inlen; i++)
			fprintf(stderr, "%c", input[i]);
		fprintf(stderr, "\n");
		fprintf(stderr, "  decoding: ");
		for (i = 0; i < len; i++)
			fprintf(stderr, "0x%x ", buf[i]);
		fprintf(stderr, "\n");
		failure = 1;
		goto done;
	}

	/* See if we expect this to fail decoding. */
	if (bt->in_len == -1)
		goto done;

	if (memcmp(bt->in, buf, bt->in_len) != 0) {
		fprintf(stderr, "FAIL: test %i - decoding differs:\n", test_no);
		fprintf(stderr, "  decoding: ");
		for (i = 0; i < len; i++)
			fprintf(stderr, "0x%x ", buf[i]);
		fprintf(stderr, "\n");
		fprintf(stderr, " test data: ");
		for (i = 0; i < inlen; i++)
			fprintf(stderr, "0x%x ", input[i]);
		fprintf(stderr, "\n");
		failure = 1;
	}

done:
	BIO_free_all(bio_mem);
	free(buf);
	if (test_nl)
		free(input);

	return failure;
}

int
main(int argc, char **argv)
{
	struct base64_test *bt;
	int failed = 0;
	size_t i;

	fprintf(stderr, "Starting combined tests...\n");

	for (i = 0; i < N_TESTS; i++) {
		bt = &base64_tests[i];
		if (bt->in_len != -1)
			failed += base64_encoding_test(i, bt, 0);
		if (bt->out_len != -1)
			failed += base64_decoding_test(i, bt, 0);
		if (bt->in_len != -1)
			failed += base64_encoding_test(i, bt, 1);
		if (bt->out_len != -1)
			failed += base64_decoding_test(i, bt, 1);
	}

	fprintf(stderr, "Starting NL tests...\n");

	for (i = 0; i < N_NL_TESTS; i++) {
		bt = &base64_nl_tests[i];

		if (bt->in_len != -1)
			failed += base64_encoding_test(i, bt, 1);
		if (bt->out_len != -1)
			failed += base64_decoding_test(i, bt, 1);
	}

	fprintf(stderr, "Starting NO NL tests...\n");

	for (i = 0; i < N_NO_NL_TESTS; i++) {
		bt = &base64_no_nl_tests[i];

		if (bt->in_len != -1)
			failed += base64_encoding_test(i, bt, 0);
		if (bt->out_len != -1)
			failed += base64_decoding_test(i, bt, 0);
	}

	return failed;
}
