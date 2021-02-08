/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Siemens AG 2020
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/http.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <string.h>

#include "testutil.h"

static const ASN1_ITEM *x509_it = NULL;
static X509 *x509 = NULL;
#define SERVER "mock.server"
#define PORT   "81"
#define RPATH  "path/any.crt"
static const char *rpath;

/*
 * pretty trivial HTTP mock server:
 * for POST, copy request headers+body from mem BIO 'in' as response to 'out'
 * for GET, first redirect the request then respond with 'rsp' of ASN1 type 'it'
 */
static int mock_http_server(BIO *in, BIO *out,
                            ASN1_VALUE *rsp, const ASN1_ITEM *it)
{
    const char *req;
    long count = BIO_get_mem_data(in, (unsigned char **)&req);
    const char *hdr = (char *)req;
    int is_get = count >= 4 && strncmp(hdr, "GET ", 4) == 0;
    int len;

    /* first line should contain "<GET or POST> <rpath> HTTP/1.x" */
    if (is_get)
        hdr += 4;
    else if (TEST_true(count >= 5 && strncmp(hdr, "POST ", 5) == 0))
        hdr += 5;
    else
        return 0;

    while (*rpath == '/')
        rpath++;
    while (*hdr == '/')
        hdr++;
    len = strlen(rpath);
    if (!TEST_strn_eq(hdr, rpath, len) || !TEST_char_eq(hdr++[len], ' '))
        return 0;
    hdr += len;
    len = strlen("HTTP/1.");
    if (!TEST_strn_eq(hdr, "HTTP/1.", len))
        return 0;
    hdr += len;
    /* check for HTTP version 1.0 .. 1.1 */
    if (!TEST_char_le('0', *hdr) || !TEST_char_le(*hdr++, '1'))
        return 0;
    if (!TEST_char_eq(*hdr++, '\r') || !TEST_char_eq(*hdr++, '\n'))
        return 0;
    count -= (hdr - req);
    if (count <= 0 || out == NULL)
        return 0;

    if (is_get && strcmp(rpath, RPATH) == 0) {
        rpath = "path/new.crt";
        return BIO_printf(out, "HTTP/1.1 301 Moved Permanently\r\n"
                          "Location: /%s\r\n\r\n", rpath) > 0; /* same server */
    }
    if (BIO_printf(out, "HTTP/1.1 200 OK\r\n") <= 0)
        return 0;
    if (is_get) { /* construct new header and body */
        if ((len = ASN1_item_i2d(rsp, NULL, it)) <= 0)
            return 0;
        if (BIO_printf(out, "Content-Type: application/x-x509-ca-cert\r\n"
                       "Content-Length: %d\r\n\r\n", len) <= 0)
            return 0;
        return ASN1_item_i2d_bio(it, out, rsp);
    } else {
        return BIO_write(out, hdr, count) == count; /* echo header and body */
    }
}

static long http_bio_cb_ex(BIO *bio, int oper, const char *argp, size_t len,
                           int cmd, long argl, int ret, size_t *processed)
{

    if (oper == (BIO_CB_CTRL | BIO_CB_RETURN) && cmd == BIO_CTRL_FLUSH)
        ret = mock_http_server(bio, (BIO *)BIO_get_callback_arg(bio),
                               (ASN1_VALUE *)x509, x509_it);
    return ret;
}

static int test_http_x509(int do_get)
{
    X509 *rcert = NULL;
    BIO *wbio = BIO_new(BIO_s_mem());
    BIO *rbio = BIO_new(BIO_s_mem());
    STACK_OF(CONF_VALUE) *headers = NULL;
    int res = 0;

    if (wbio == NULL || rbio == NULL)
        goto err;
    BIO_set_callback_ex(wbio, http_bio_cb_ex);
    BIO_set_callback_arg(wbio, (char *)rbio);

    rpath = RPATH;
    rcert = (X509 *)
        (do_get ?
         OSSL_HTTP_get_asn1("http://"SERVER":"PORT"/"RPATH,
                            NULL /* proxy */, NULL /* no_proxy */,
                            wbio, rbio, NULL /* bio_update_fn */, NULL,
                            headers, 0 /* maxline */,
                            0 /* max_resp_len */, 0 /* timeout */,
                            "application/x-x509-ca-cert", x509_it)
         :
         OSSL_HTTP_post_asn1(SERVER, PORT, RPATH, 0 /* use_ssl */,
                             NULL /* proxy */, NULL /* no_proxy */,
                             wbio, rbio, NULL /* bio_update_fn */, NULL,
                             headers, "application/x-x509-ca-cert",
                             (ASN1_VALUE *)x509, x509_it, 0 /* maxline */,
                             0 /* max_resp_len */, 0 /* timeout */,
                             "application/x-x509-ca-cert", x509_it)
         );
    res = TEST_ptr(rcert) && TEST_int_eq(X509_cmp(x509, rcert), 0);

 err:
    X509_free(rcert);
    BIO_free(wbio);
    BIO_free(rbio);
    sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);
    return res;
}

static int test_http_url_ok(const char *url, const char *exp_host, int exp_ssl)
{
    char *host, *port, *path;
    int num, ssl;
    int res;

    res = TEST_true(OSSL_HTTP_parse_url(url, &host, &port, &num, &path, &ssl))
        && TEST_str_eq(host, exp_host)
        && TEST_str_eq(port, "65535")
        && TEST_int_eq(num, 65535)
        && TEST_str_eq(path, "/pkix")
        && TEST_int_eq(ssl, exp_ssl);
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
    return res;
}

static int test_http_url_dns(void)
{
    return test_http_url_ok("server:65535/pkix", "server", 0);
}

static int test_http_url_ipv4(void)
{
    return test_http_url_ok("https://1.2.3.4:65535/pkix", "1.2.3.4", 1);
}

static int test_http_url_ipv6(void)
{
    return test_http_url_ok("http://[FF01::101]:65535/pkix", "FF01::101", 0);
}

static int test_http_url_invalid(const char *url)
{
    char *host = "1", *port = "1", *path = "1";
    int num = 1, ssl = 1;
    int res;

    res = TEST_false(OSSL_HTTP_parse_url(url, &host, &port, &num, &path, &ssl))
        && TEST_ptr_null(host)
        && TEST_ptr_null(port)
        && TEST_ptr_null(path);
    if (!res) {
        OPENSSL_free(host);
        OPENSSL_free(port);
        OPENSSL_free(path);
    }
    return res;
}

static int test_http_url_invalid_prefix(void)
{
    return test_http_url_invalid("htttps://1.2.3.4:65535/pkix");
}

static int test_http_url_invalid_port(void)
{
    return test_http_url_invalid("https://1.2.3.4:65536/pkix");
}

static int test_http_url_invalid_path(void)
{
    return test_http_url_invalid("https://[FF01::101]pkix");
}

static int test_http_get_x509(void)
{
    return test_http_x509(1);
}

static int test_http_post_x509(void)
{
    return test_http_x509(0);
}

void cleanup_tests(void)
{
    X509_free(x509);
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    x509_it = ASN1_ITEM_rptr(X509);
    if (!TEST_ptr((x509 = load_cert_pem(test_get_argument(0), NULL))))
        return 1;

    ADD_TEST(test_http_url_dns);
    ADD_TEST(test_http_url_ipv4);
    ADD_TEST(test_http_url_ipv6);
    ADD_TEST(test_http_url_invalid_prefix);
    ADD_TEST(test_http_url_invalid_port);
    ADD_TEST(test_http_url_invalid_path);
    ADD_TEST(test_http_get_x509);
    ADD_TEST(test_http_post_x509);
    return 1;
}
