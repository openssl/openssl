/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include "e_os.h"
#include "testutil.h"


/* List of files, from argv */
static char **files;

static int test_certs(int num)
{
    int count;
    char *name = 0;
    char *header = 0;
    unsigned char *data = 0;
    long len;
    typedef X509 *(*d2i_X509_t)(X509 **, const unsigned char **, long);
    typedef int (*i2d_X509_t)(X509 *, unsigned char **);
    int err = 0;
    BIO *fp = BIO_new_file(files[num], "r");

    if (!TEST_ptr(fp))
        return 0;

    for (count = 0;
         !err && PEM_read_bio(fp, &name, &header, &data, &len);
	 ++count) {
        int trusted = strcmp(name, PEM_STRING_X509_TRUSTED) == 0;
        d2i_X509_t d2i = trusted ? d2i_X509_AUX : d2i_X509;
        i2d_X509_t i2d = trusted ? i2d_X509_AUX : i2d_X509;
        X509 *cert = NULL;
	const unsigned char *p = data;
        unsigned char *buf = NULL;
        unsigned char *bufp;
        long enclen;

	if (!trusted
            && strcmp(name, PEM_STRING_X509) != 0
	    && strcmp(name, PEM_STRING_X509_OLD) != 0) {
	    fprintf(stderr, "unexpected PEM object: %s\n", name);
            err = 1;
	    goto next;
        }
        cert = d2i(NULL, &p, len);

        if (cert == NULL || (p - data) != len) {
	    fprintf(stderr, "error parsing input %s\n", name);
            err = 1;
            goto next;
        }

        /* Test traditional 2-pass encoding into caller allocated buffer */
        enclen = i2d(cert, NULL);
        if (len != enclen) {
	    fprintf(stderr, "encoded length %ld of %s != input length %ld\n",
                    enclen, name, len);
            err = 1;
            goto next;
        }
        if ((buf = bufp = OPENSSL_malloc(len)) == NULL) {
            perror("malloc");
            err = 1;
            goto next;
        }
        enclen = i2d(cert, &bufp);
        if (len != enclen) {
	    fprintf(stderr, "encoded length %ld of %s != input length %ld\n",
                    enclen, name, len);
            err = 1;
            goto next;
        }
        enclen = (long) (bufp - buf);
        if (enclen != len) {
	    fprintf(stderr, "unexpected buffer position after encoding %s\n",
                    name);
            err = 1;
            goto next;
        }
        if (memcmp(buf, data, len) != 0) {
	    fprintf(stderr, "encoded content of %s does not match input\n",
                    name);
            err = 1;
            goto next;
        }
        OPENSSL_free(buf);
        buf = NULL;

        /* Test 1-pass encoding into library allocated buffer */
        enclen = i2d(cert, &buf);
        if (len != enclen) {
	    fprintf(stderr, "encoded length %ld of %s != input length %ld\n",
                    enclen, name, len);
            err = 1;
            goto next;
        }
        if (memcmp(buf, data, len) != 0) {
	    fprintf(stderr, "encoded content of %s does not match input\n",
                    name);
            err = 1;
            goto next;
        }

        if (trusted) {
            /* Encode just the cert and compare with initial encoding */
            OPENSSL_free(buf);
            buf = NULL;

            /* Test 1-pass encoding into library allocated buffer */
            enclen = i2d(cert, &buf);
            if (enclen > len) {
                fprintf(stderr, "encoded length %ld of %s > input length %ld\n",
                        enclen, name, len);
                err = 1;
                goto next;
            }
            if (memcmp(buf, data, enclen) != 0) {
                fprintf(stderr, "encoded cert content does not match input\n");
                err = 1;
                goto next;
            }
        }

	/*
	 * If any of these were null, PEM_read() would have failed.
	 */
    next:
        X509_free(cert);
        OPENSSL_free(buf);
	OPENSSL_free(name);
	OPENSSL_free(header);
	OPENSSL_free(data);
    }
    BIO_free(fp);

    if (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE) {
        /* Reached end of PEM file */
        if (count > 0) {
            ERR_clear_error();
            return 1;
        }
    }

    /* Some other PEM read error */
    return 0;
}

int test_main(int argc, char *argv[])
{
    if (argc < 2) {
        TEST_error("usage: %s certfile...", argv[0]);
        return 0;
    }

    files = &argv[1];
    ADD_ALL_TESTS(test_certs, argc - 1);
    return run_tests(argv[0]);
}
