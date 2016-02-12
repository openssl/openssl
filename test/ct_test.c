/*
 * Tests the Certificate Transparency public and internal APIs.
 *
 * Author:    Rob Percival (robpercival@google.com)
 * Date:        2016-01-26
 *
 * ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.    All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in
 *        the documentation and/or other materials provided with the
 *        distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *        software must display the following acknowledgment:
 *        "This product includes software developed by the OpenSSL Project
 *        for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *        endorse or promote products derived from this software without
 *        prior written permission. For written permission, please contact
 *        licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *        nor may "OpenSSL" appear in their names without prior written
 *        permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *        acknowledgment:
 *        "This product includes software developed by the OpenSSL Project
 *        for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.    IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ct.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "testutil.h"

#if !defined(OPENSSL_NO_CT) && !defined(OPENSSL_NO_UNIT_TEST)

/* Used when declaring buffers to read text files into */
#define CT_TEST_MAX_FILE_SIZE 8096

typedef struct ct_test_fixture {
    const char *test_case_name;
    /* Set the following to test handling of SCTs in X509 certificates */
    const char *certificate_file_path;
    size_t expected_sct_count;
    /* Set the following to test handling of SCTs in TLS format */
    const uint8_t *tls_sct;
    size_t tls_sct_len;
    const SCT *sct;
    /*
     * A file to load the expected SCT text from.
     * This text will be compared to the actual text output during the test.
     * A maximum of |CT_TEST_MAX_FILE_SIZE| bytes will be read of this file.
     */
    const char *sct_text_file_path;

} CT_TEST_FIXTURE;

static CT_TEST_FIXTURE set_up(const char *const test_case_name)
{
    CT_TEST_FIXTURE fixture;
    int setup_ok = 1;

    memset(&fixture, 0, sizeof(fixture));
    fixture.test_case_name = test_case_name;

    if (!setup_ok) {
        exit(EXIT_FAILURE);
    }
    return fixture;
}

static void tear_down(CT_TEST_FIXTURE fixture)
{
    ERR_print_errors_fp(stderr);
}

static X509 *load_pem_cert(const char *file)
{
    BIO *cert_io = BIO_new_file(file, "r");
    X509 *cert = NULL;

    if (cert_io == NULL) goto end;

    cert = PEM_read_bio_X509(cert_io, NULL, NULL, NULL);

end:
    BIO_free(cert_io);
    return cert;
}

static int read_text_file(const char *path, char *buffer, int buffer_length)
{
    BIO *file = BIO_new_file(path, "r");
    int result = -1;

    if (file != NULL) {
        result = BIO_read(file, buffer, buffer_length);
        BIO_free(file);
    }

    return result;
}

static int compare_sct_printout(SCT *sct,
    const char *expected_output)
{
    BIO *text_buffer = NULL;
    char *actual_output = NULL;
    int result = 1;

    text_buffer = BIO_new(BIO_s_mem());
    if (text_buffer == NULL) {
        fprintf(stderr, "Unable to allocate buffer\n");
        goto end;
    }

    SCT_print(sct, text_buffer, 0);

    /* Append null terminator because we're about to use the buffer contents
    * as a string. */
    if (BIO_write(text_buffer, "\0", 1) != 1) {
        fprintf(stderr, "Failed to append null terminator to SCT text\n");
        goto end;
    }

    BIO_get_mem_data(text_buffer, &actual_output);
    result = strcmp(actual_output, expected_output);

    if (result != 0) {
        fprintf(stderr,
            "Expected SCT printout:\n%s\nActual SCT printout:\n%s\n",
            expected_output, actual_output);
    }

end:
    BIO_free(text_buffer);
    return result;
}

static int compare_extension_printout(X509_EXTENSION *extension,
                                      const char *expected_output)
{
    BIO *text_buffer = NULL;
    char *actual_output = NULL;
    int result = 1;

    text_buffer = BIO_new(BIO_s_mem());
    if (text_buffer == NULL) {
        fprintf(stderr, "Unable to allocate buffer\n");
        goto end;
    }

    if (!X509V3_EXT_print(text_buffer, extension, X509V3_EXT_DEFAULT, 0)) {
        fprintf(stderr, "Failed to print extension\n");
        goto end;
    }

    /* Append null terminator because we're about to use the buffer contents
     * as a string. */
    if (BIO_write(text_buffer, "\0", 1) != 1) {
        fprintf(stderr, "Failed to append null terminator to extension text\n");
        goto end;
    }

    BIO_get_mem_data(text_buffer, &actual_output);
    result = strcmp(actual_output, expected_output);

    if (result != 0) {
        fprintf(stderr,
                "Expected SCT printout:\n%s\nActual SCT printout:\n%s\n",
                expected_output, actual_output);
    }

end:
    BIO_free(text_buffer);
    return result;
}

static int execute_cert_test(CT_TEST_FIXTURE fixture)
{
    int result = 0;
    X509 *cert = NULL;
    SCT *sct = NULL;
    char expected_sct_text[CT_TEST_MAX_FILE_SIZE];
    int sct_text_len = 0;

    if (fixture.sct_text_file_path != NULL) {
        sct_text_len = read_text_file(
            fixture.sct_text_file_path,
            expected_sct_text,
            CT_TEST_MAX_FILE_SIZE - 1);

        if (sct_text_len < 0) {
            result = 1;
            fprintf(stderr, "Test data file not found: %s\n",
                fixture.sct_text_file_path);
            goto end;
        }

        expected_sct_text[sct_text_len] = '\0';
    }

    if (fixture.certificate_file_path != NULL) {
        int sct_extension_index;
        X509_EXTENSION *sct_extension = NULL;
        cert = load_pem_cert(fixture.certificate_file_path);

        if (cert == NULL) {
            result = 1;
            fprintf(stderr, "Unable to load certificate: %s\n",
                fixture.certificate_file_path);
            goto end;
        }

        sct_extension_index = X509_get_ext_by_NID(cert, NID_ct_precert_scts, -1);
        sct_extension = X509_get_ext(cert, sct_extension_index);
        if (fixture.expected_sct_count > 0) {
            if (sct_extension == NULL) {
                result = 1;
                fprintf(stderr, "SCT extension not found in: %s\n",
                    fixture.certificate_file_path);
                goto end;
            }

            if (fixture.sct_text_file_path) {
                result = compare_extension_printout(sct_extension,
                                                    expected_sct_text);
                if (result != 0)
                    goto end;
            }
        } else if (sct_extension != NULL) {
            result = 1;
            fprintf(stderr, "Expected no SCTs, but found SCT extension in: %s\n",
                fixture.certificate_file_path);
            goto end;
        }
    }

    if (fixture.tls_sct != NULL) {
        const unsigned char *p = fixture.tls_sct;
        unsigned char *tls_sct;
        size_t tls_sct_len;
        if (o2i_SCT(&sct, &p, fixture.tls_sct_len) == NULL) {
            result = 1;
            fprintf(stderr, "Failed to decode SCT from TLS format\n");
            goto end;
        }

        if (fixture.sct_text_file_path) {
            result = compare_sct_printout(sct, expected_sct_text);
            if (result != 0)
                goto end;
        }

        tls_sct_len = i2o_SCT(sct, &tls_sct);
        if (tls_sct_len != fixture.tls_sct_len ||
            memcmp(fixture.tls_sct, tls_sct, tls_sct_len) != 0) {
            result = 1;
            fprintf(stderr, "Failed to encode SCT into TLS format correctly\n");
            goto end;
        }
    }

end:
    X509_free(cert);
    SCT_free(sct);
    return result;
}

#define SETUP_CT_TEST_FIXTURE() SETUP_TEST_FIXTURE(CT_TEST_FIXTURE, set_up)
#define EXECUTE_CT_TEST() EXECUTE_TEST(execute_cert_test, tear_down)

static int test_no_scts_in_certificate()
{
    SETUP_CT_TEST_FIXTURE();
    fixture.certificate_file_path = "certs/leaf.pem";
    fixture.expected_sct_count = 0;
    EXECUTE_CT_TEST();
}

static int test_one_sct_in_certificate()
{
    SETUP_CT_TEST_FIXTURE();
    fixture.certificate_file_path = "certs/embeddedSCTs1.pem";
    fixture.expected_sct_count = 1;
    fixture.sct_text_file_path = "certs/embeddedSCTs1.sct";
    EXECUTE_CT_TEST();
}

static int test_multiple_scts_in_certificate()
{
    SETUP_CT_TEST_FIXTURE();
    fixture.certificate_file_path = "certs/embeddedSCTs3.pem";
    fixture.expected_sct_count = 3;
    fixture.sct_text_file_path = "certs/embeddedSCTs3.sct";
    EXECUTE_CT_TEST();
}

static int test_decode_tls_sct()
{
    SETUP_CT_TEST_FIXTURE();
    fixture.tls_sct = (unsigned char *)
        "\x00" /* version */
        /* log ID */
        "\xDF\x1C\x2E\xC1\x15\x00\x94\x52\x47\xA9\x61\x68\x32\x5D\xDC\x5C\x79"
        "\x59\xE8\xF7\xC6\xD3\x88\xFC\x00\x2E\x0B\xBD\x3F\x74\xD7\x64"
        "\x00\x00\x01\x3D\xDB\x27\xDF\x93" /* timestamp */
        "\x00\x00" /* extensions length */
        "" /* extensions */
        "\x04\x03" /* hash and signature algorithms */
        "\x00\x47" /* signature length */
        "\x30\x45\x02\x20\x48\x2F\x67\x51\xAF\x35\xDB\xA6\x54\x36\xBE\x1F\xD6"
        "\x64\x0F\x3D\xBF\x9A\x41\x42\x94\x95\x92\x45\x30\x28\x8F\xA3\xE5\xE2"
        "\x3E\x06\x02\x21\x00\xE4\xED\xC0\xDB\x3A\xC5\x72\xB1\xE2\xF5\xE8\xAB"
        "\x6A\x68\x06\x53\x98\x7D\xCF\x41\x02\x7D\xFE\xFF\xA1\x05\x51\x9D\x89"
        "\xED\xBF\x08"; /* signature */
    fixture.tls_sct_len = 118;
    fixture.sct_text_file_path = "ct/tls1.sct";
    EXECUTE_CT_TEST();
}

static int test_encode_tls_sct()
{
    SETUP_CT_TEST_FIXTURE();

    SCT *sct = SCT_new();
    SCT_set_version(sct, 0);
    SCT_set1_log_id(sct, (unsigned char *)
        "\xDF\x1C\x2E\xC1\x15\x00\x94\x52\x47\xA9\x61\x68\x32\x5D\xDC\x5C\x79"
        "\x59\xE8\xF7\xC6\xD3\x88\xFC\x00\x2E\x0B\xBD\x3F\x74\xD7\x64", 32);
    SCT_set_timestamp(sct, 1);
    SCT_set1_extensions(sct, (unsigned char *)"", 0);
    SCT_set_signature_nid(sct, NID_ecdsa_with_SHA256);
    SCT_set1_signature(sct, (unsigned char *)
        "\x45\x02\x20\x48\x2F\x67\x51\xAF\x35\xDB\xA6\x54\x36\xBE"
        "\x1F\xD6\x64\x0F\x3D\xBF\x9A\x41\x42\x94\x95\x92\x45\x30\x28\x8F\xA3"
        "\xE5\xE2\x3E\x06\x02\x21\x00\xE4\xED\xC0\xDB\x3A\xC5\x72\xB1\xE2\xF5"
        "\xE8\xAB\x6A\x68\x06\x53\x98\x7D\xCF\x41\x02\x7D\xFE\xFF\xA1\x05\x51"
        "\x9D\x89\xED\xBF\x08", 71);
    fixture.sct = sct;
    fixture.sct_text_file_path = "ct/tls1.sct";
    EXECUTE_CT_TEST();

    SCT_free(sct);
}

int main(int argc, char *argv[])
{
    int result = 0;

    SSL_library_init();
    SSL_load_error_strings();

    ADD_TEST(test_no_scts_in_certificate);
    ADD_TEST(test_one_sct_in_certificate);
    ADD_TEST(test_multiple_scts_in_certificate);
    ADD_TEST(test_decode_tls_sct);
    ADD_TEST(test_encode_tls_sct);

    result = run_tests(argv[0]);
    ERR_print_errors_fp(stderr);

    return result;
}

#else /* OPENSSL_NO_CT */

int main(int argc, char* argv[])
{
    return EXIT_SUCCESS;
}

#endif /* OPENSSL_NO_CT */
