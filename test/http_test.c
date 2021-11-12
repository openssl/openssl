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
static int did_redirect = 0;
static int did_retry = 0;

#define RPATH "/path/result.crt"

typedef struct {
    BIO *out;
    const char *content_type;
    const char *txt;
    char version;
    int keep_alive;
    int retry;
} server_args;

/*-
 * Pretty trivial HTTP mock server:
 * For POST, copy request headers+body from mem BIO |in| as response to |out|.
 * For GET, redirect to RPATH unless already there, else use |content_type| and
 * respond with |txt| if not NULL, else with |rsp| of ASN1 type |it|.
 * Response hdr has HTTP version 1.|version| and |keep_alive| (unless implicit).
 */
static int mock_http_server(BIO *in, BIO *out, char version,
                            int keep_alive, int retry,
                            const char *content_type, const char *txt,
                            ASN1_VALUE *rsp, const ASN1_ITEM *it)
{
    const char *req, *path;
    long count = BIO_get_mem_data(in, (unsigned char **)&req);
    const char *hdr = (char *)req;
    int len;
    int is_get = count >= 4 && CHECK_AND_SKIP_PREFIX(hdr, "GET ");

    /* first line should contain "(GET|POST) <path> HTTP/1.x" */
    if (!is_get
            && !(TEST_true(count >= 5 && CHECK_AND_SKIP_PREFIX(hdr, "POST "))))
        return 0;

    path = hdr;
    hdr = strchr(hdr, ' ');
    if (hdr == NULL)
        return 0;
    len = strlen("HTTP/1.");
    if (!TEST_strn_eq(++hdr, "HTTP/1.", len))
        return 0;
    hdr += len;
    /* check for HTTP version 1.0 .. 1.1 */
    if (!TEST_char_le('0', *hdr) || !TEST_char_le(*hdr++, '1'))
        return 0;
    if (!TEST_char_eq(*hdr++, '\r') || !TEST_char_eq(*hdr++, '\n'))
        return 0;
    count -= (hdr - req);
    if (count < 0 || out == NULL)
        return 0;

    if (!HAS_PREFIX(path, RPATH)) { /* redirect */
        if (!is_get)
            return 0;
        did_redirect = 1;
        return BIO_printf(out, "HTTP/1.%c 301 Moved Permanently\r\n"
                          "Retry-After: 1\r\n"
                          "Location: %s\r\n\r\n",
                          version, RPATH) > 0; /* same server */
    }
    if (retry && !did_retry) {
        did_retry = 1;
        if (BIO_printf(out,
                       "HTTP/1.%c 503 Service Unavailable\r\n", version) <= 0)
            return 0;
        if ((version == '0') == keep_alive) /* otherwise, default */
            if (BIO_printf(out, "Connection: %s\r\n",
                           version == '0' ? "keep-alive" : "close") <= 0)
                return 0;
        return BIO_printf(out, "\r\n") > 0;
    }
    if (BIO_printf(out, "HTTP/1.%c 200 OK\r\n", version) <= 0)
        return 0;
    if ((version == '0') == keep_alive) /* otherwise, default */
        if (BIO_printf(out, "Connection: %s\r\n",
                       version == '0' ? "keep-alive" : "close") <= 0)
            return 0;
    if (is_get) { /* construct new header and body */
        if (txt != NULL)
            len = strlen(txt);
        else if ((len = ASN1_item_i2d(rsp, NULL, it)) <= 0)
            return 0;
        if (BIO_printf(out, "Content-Type: %s\r\n"
                       "Content-Length: %d\r\n\r\n", content_type, len) <= 0)
            return 0;
        if (txt != NULL)
            return BIO_puts(out, txt);
        return ASN1_item_i2d_bio(it, out, rsp);
    } else {
        if (CHECK_AND_SKIP_PREFIX(hdr, "Connection: ")) {
            /* skip req Connection header */
            hdr = strstr(hdr, "\r\n");
            if (hdr == NULL)
                return 0;
            hdr += 2;
        }
        /* echo remaining request header and body */
        return BIO_write(out, hdr, count) == count;
    }
}

/* invoke the mock server after the request BIO was flushed by the client */
static long http_bio_cb_ex(BIO *bio, int oper, const char *argp, size_t len,
                           int cmd, long argl, int ret, size_t *processed)
{
    server_args *args = (server_args *)BIO_get_callback_arg(bio);

    if (oper == (BIO_CB_CTRL | BIO_CB_RETURN) && cmd == BIO_CTRL_FLUSH)
        ret = mock_http_server(bio, args->out, args->version,
                               args->keep_alive, args->retry,
                               args->content_type, args->txt,
                               (ASN1_VALUE *)x509, x509_it);
    return ret;
}

#define text1 "test\n"
#define text2 "more\n"

static int test_http_method(int do_get, int do_txt, int retry)
{
    const OSSL_HTTP_REQ_CTX *rctx = NULL;
    const char *server = NULL, *port = NULL;
    const int use_ssl = 0;
    const char *proxy = NULL, *no_proxy = NULL;
    const int buf_size = 0, timeout = 1 /* also used as a precaution */;
    STACK_OF(CONF_VALUE) *headers = NULL;
    BIO *wbio = BIO_new(BIO_s_mem());
    BIO *rbio = BIO_new(BIO_s_mem());
    const OSSL_HTTP_bio_cb_t bio_update_fn = NULL;
    void *arg = NULL;
    server_args mock_args = { NULL, NULL, NULL, '0', 0, 0 };
    BIO *req;
    unsigned char *x509_der = NULL;
    int der_len = i2d_X509(x509, &x509_der);
    BIO *rsp;
    const char *content_type;
    const unsigned long default_retry_after = 0;
    int rsp_ok = 0, res = 0;

    if (do_txt) {
        content_type = "text/plain";
        req = BIO_new(BIO_s_mem());
        if (req == NULL
                || BIO_puts(req, text1) != sizeof(text1) - 1
                || BIO_puts(req, text2) != sizeof(text2) - 1) {
            BIO_free(req);
            req = NULL;
        }
        mock_args.txt = text1;
    } else {
        content_type = "application/x-x509-ca-cert";
        req = ASN1_item_i2d_mem_bio(x509_it, (ASN1_VALUE *)x509);
        mock_args.txt = NULL;
    }

    if (wbio == NULL || rbio == NULL || req == NULL || x509_der == NULL)
        goto err;

    mock_args.out = rbio;
    mock_args.retry = retry;
    mock_args.content_type = content_type;
    BIO_set_callback_ex(wbio, http_bio_cb_ex);
    BIO_set_callback_arg(wbio, (char *)&mock_args);

    rsp = do_get ?
        (retry ?
         OSSL_HTTP_get_ex(RPATH, proxy, no_proxy,
                          wbio, rbio, bio_update_fn, arg,
                          buf_size, headers, content_type,
                          (do_txt ? OSSL_HTTP_FLAG_EXPECT_ASN1 : 0)
                          | OSSL_HTTP_FLAG_ENABLE_RETRY,
                          OSSL_HTTP_DEFAULT_MAX_RESP_LEN,
                          default_retry_after, timeout) :
         OSSL_HTTP_get(do_txt ? RPATH : "/will-be-redirected", proxy, no_proxy,
                       wbio, rbio, bio_update_fn, arg, buf_size, headers,
                       content_type, !do_txt /* expect_asn1 */,
                       OSSL_HTTP_DEFAULT_MAX_RESP_LEN, timeout)) :
        (retry ?
         OSSL_HTTP_transfer_ex(NULL, server, port, RPATH,
                               use_ssl, proxy, no_proxy,
                               wbio, rbio, bio_update_fn, arg,
                               buf_size, headers, content_type, NULL,
                               x509_der, der_len, NULL, NULL, content_type,
                               (do_txt ? OSSL_HTTP_FLAG_EXPECT_ASN1 : 0)
                               | OSSL_HTTP_FLAG_ENABLE_RETRY,
                               OSSL_HTTP_DEFAULT_MAX_RESP_LEN,
                               default_retry_after, timeout) :
         OSSL_HTTP_transfer(NULL, server, port, RPATH,
                            use_ssl, proxy, no_proxy,
                            wbio, rbio, bio_update_fn, arg,
                            buf_size, headers, content_type,
                            req, content_type, !do_txt /* expect_asn1 */,
                            OSSL_HTTP_DEFAULT_MAX_RESP_LEN, timeout,
                            0 /* no keep_alive */)
         );

    res = TEST_ptr(rsp);
    if (do_get && !do_txt && !retry)
        res = res && TEST_true(did_redirect);
    if (retry)
        res = res && TEST_true(did_retry);
    did_retry = 0;

    if (rsp != NULL) {
        if (do_txt) {
            char rtext[sizeof(text1) + 1 /* more space than needed */];

            rsp_ok = TEST_int_eq(BIO_gets(rsp, rtext, sizeof(rtext)),
                                 sizeof(text1) - 1)
                && TEST_str_eq(rtext, text1);
        } else {
            X509 *rcert = d2i_X509_bio(rsp, NULL);

            rsp_ok = TEST_ptr(rcert) && TEST_int_eq(X509_cmp(x509, rcert), 0);
            X509_free(rcert);
        }
        BIO_free(rsp);
    }

    res = res && rsp_ok
        && TEST_int_eq(OSSL_HTTP_get_status(rctx), 0)
        && TEST_int_eq(OSSL_HTTP_is_alive(rctx), 0)
        && TEST_int_eq(OSSL_HTTP_may_retry(rctx), 0);

 err:
    OPENSSL_free(x509_der);
    BIO_free(req);
    BIO_free(wbio);
    BIO_free(rbio);
    sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);
    return res;
}

static int test_http_keep_alive(char version, int keep_alive, int kept_alive)
{
    const char *server = NULL, *port = NULL;
    const int use_ssl = 0;
    const char *proxy = NULL, *no_proxy = NULL;
    BIO *wbio = BIO_new(BIO_s_mem());
    BIO *rbio = BIO_new(BIO_s_mem());
    const OSSL_HTTP_bio_cb_t bio_update_fn = NULL;
    void *arg = NULL;
    const int buf_size = 0;
    STACK_OF(CONF_VALUE) *headers = NULL;
    const char *req_content_type = NULL;
    BIO *req = NULL /* => GET */;
    const char *const content_type = "application/x-x509-ca-cert";
    const size_t max_resp_len = 0; /* no limit */
    BIO *rsp;
    X509 *rsp_cert = NULL;
    server_args mock_args = { NULL, content_type, NULL, '0', 0, 0 };
    OSSL_HTTP_REQ_CTX *rctx = NULL;
    int i, res = 0;

    if (wbio == NULL || rbio == NULL)
        goto err;
    mock_args.out = rbio;
    mock_args.version = version;
    mock_args.keep_alive = kept_alive;
    BIO_set_callback_ex(wbio, http_bio_cb_ex);
    BIO_set_callback_arg(wbio, (char *)&mock_args);

    for (res = 1, i = 1; res && i <= 2; i++) {
        rsp = i == 1 ?
            OSSL_HTTP_transfer_ex(&rctx, server, port, RPATH,
                                  use_ssl, proxy, no_proxy,
                                  wbio, rbio, bio_update_fn, arg,
                                  buf_size, headers,
                                  req_content_type, req,
                                  NULL /* req_data */, 0 /* req_len */,
                                  NULL /* req_asn1 */, NULL /* it */,
                                  content_type, keep_alive
                                  | OSSL_HTTP_FLAG_EXPECT_ASN1
                                  | OSSL_HTTP_FLAG_ENABLE_RETRY,
                                  max_resp_len, 0 /* default_retry_after */,
                                  LONG_MAX - (long)time(NULL) - 1
                                  /* corner case for timeout */) :
            OSSL_HTTP_transfer(&rctx, server, port, RPATH,
                               use_ssl, proxy, no_proxy,
                               wbio, rbio, bio_update_fn, arg,
                               buf_size, headers,
                               req_content_type, req,
                               content_type, 1 /* expect_asn1 */,
                               max_resp_len, INT_MIN /* timeout corner case */,
                               keep_alive | OSSL_HTTP_FLAG_ENABLE_RETRY);
        if (keep_alive == 2 && kept_alive == 0) {
            res = res && TEST_ptr_null(rsp);
        } else {
            rsp_cert = d2i_X509_bio(rsp, NULL);
            res = res && TEST_ptr(rsp) && TEST_ptr(rsp_cert)
                && TEST_int_eq(X509_cmp(x509, rsp_cert), 0);
            X509_free(rsp_cert);
        }
        if (rctx != NULL)
            res = res
                && TEST_int_eq(OSSL_HTTP_get_status(rctx), 200)
                && TEST_int_eq(OSSL_HTTP_is_alive(rctx),
                               keep_alive != 0 && kept_alive)
                && TEST_int_eq(OSSL_HTTP_may_retry(rctx), 1);
        BIO_free(rsp);
        (void)BIO_reset(rbio); /* discard response contents */
        keep_alive = 0;
    }
    OSSL_HTTP_close(rctx, res);

 err:
    BIO_free(wbio);
    BIO_free(rbio);
    return res;
}

static int test_http_url_ok(const char *url, int exp_ssl, const char *exp_host,
                            const char *exp_port, const char *exp_path)
{
    char *user, *host, *port, *path, *query, *frag;
    int exp_num, num, ssl;
    int res;

    if (!TEST_int_eq(sscanf(exp_port, "%d", &exp_num), 1))
        return 0;
    res = TEST_true(OSSL_HTTP_parse_url(url, &ssl, &user, &host, &port, &num,
                                        &path, &query, &frag))
        && TEST_str_eq(host, exp_host)
        && TEST_str_eq(port, exp_port)
        && TEST_int_eq(num, exp_num)
        && TEST_str_eq(path, exp_path)
        && TEST_int_eq(ssl, exp_ssl);
    if (res && *user != '\0')
        res = TEST_str_eq(user, "user:pass");
    if (res && *frag != '\0')
        res = TEST_str_eq(frag, "fr");
    if (res && *query != '\0')
        res = TEST_str_eq(query, "q");
    OPENSSL_free(user);
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
    OPENSSL_free(query);
    OPENSSL_free(frag);
    return res;
}

static int test_http_url_path_query_ok(const char *url, const char *exp_path_qu)
{
    char *host, *path;
    int res;

    res = TEST_true(OSSL_HTTP_parse_url(url, NULL, NULL, &host, NULL, NULL,
                                        &path, NULL, NULL))
        && TEST_str_eq(host, "host")
        && TEST_str_eq(path, exp_path_qu);
    OPENSSL_free(host);
    OPENSSL_free(path);
    return res;
}

static int test_http_url_dns(void)
{
    return test_http_url_ok("host:65535/path", 0, "host", "65535", "/path");
}

static int test_http_url_path_query(void)
{
    return test_http_url_path_query_ok("http://usr@host:1/p?q=x#frag", "/p?q=x")
        && test_http_url_path_query_ok("http://host?query#frag", "/?query")
        && test_http_url_path_query_ok("http://host:9999#frag", "/");
}

static int test_http_url_userinfo_query_fragment(void)
{
    return test_http_url_ok("user:pass@host/p?q#fr", 0, "host", "80", "/p");
}

static int test_http_url_ipv4(void)
{
    return test_http_url_ok("https://1.2.3.4/p/q", 1, "1.2.3.4", "443", "/p/q");
}

static int test_http_url_ipv6(void)
{
    return test_http_url_ok("http://[FF01::101]:6", 0, "[FF01::101]", "6", "/");
}

static int test_http_url_invalid(const char *url)
{
    char *host = "1", *port = "1", *path = "1";
    int num = 1, ssl = 1;
    int res;

    res = TEST_false(OSSL_HTTP_parse_url(url, &ssl, NULL, &host, &port, &num,
                                         &path, NULL, NULL))
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

static int test_http_get_txt(void)
{
    return test_http_method(1 /* GET */, 1, 0);
}

static int test_http_post_txt(void)
{
    return test_http_method(0 /* POST */, 1, 0);
}

static int test_http_get_x509_redirect(void)
{
    return test_http_method(1 /* GET */, 0, 0);
}

static int test_http_get_x509_retry(void)
{
    return test_http_method(1 /* GET */, 0, 1);
}

static int test_http_post_x509(void)
{
    return test_http_method(0 /* POST */, 0, 0);
}

static int test_http_post_x509_retry(void)
{
    return test_http_method(0 /* POST */, 0, 1);
}

static int test_http_keep_alive_0_no_no(void)
{
    return test_http_keep_alive('0', 0, 0);
}

static int test_http_keep_alive_1_no_no(void)
{
    return test_http_keep_alive('1', 0, 0);
}

static int test_http_keep_alive_0_prefer_yes(void)
{
    return test_http_keep_alive('0', 1, 1);
}

static int test_http_keep_alive_1_prefer_yes(void)
{
    return test_http_keep_alive('1', 1, 1);
}

static int test_http_keep_alive_0_require_yes(void)
{
    return test_http_keep_alive('0', 2, 1);
}

static int test_http_keep_alive_1_require_yes(void)
{
    return test_http_keep_alive('1', 2, 1);
}

static int test_http_keep_alive_0_require_no(void)
{
    return test_http_keep_alive('0', 2, 0);
}

static int test_http_keep_alive_1_require_no(void)
{
    return test_http_keep_alive('1', 2, 0);
}

void cleanup_tests(void)
{
    X509_free(x509);
}

OPT_TEST_DECLARE_USAGE("cert.pem\n")

int setup_tests(void)
{
    if (!test_skip_common_options())
        return 0;

    x509_it = ASN1_ITEM_rptr(X509);
    if (!TEST_ptr((x509 = load_cert_pem(test_get_argument(0), NULL))))
        return 0;

    ADD_TEST(test_http_url_dns);
    ADD_TEST(test_http_url_path_query);
    ADD_TEST(test_http_url_userinfo_query_fragment);
    ADD_TEST(test_http_url_ipv4);
    ADD_TEST(test_http_url_ipv6);
    ADD_TEST(test_http_url_invalid_prefix);
    ADD_TEST(test_http_url_invalid_port);
    ADD_TEST(test_http_url_invalid_path);
    ADD_TEST(test_http_get_txt);
    ADD_TEST(test_http_post_txt);
    ADD_TEST(test_http_get_x509_redirect);
    ADD_TEST(test_http_get_x509_retry);
    ADD_TEST(test_http_post_x509);
    ADD_TEST(test_http_post_x509_retry);
    ADD_TEST(test_http_keep_alive_0_no_no);
    ADD_TEST(test_http_keep_alive_1_no_no);
    ADD_TEST(test_http_keep_alive_0_prefer_yes);
    ADD_TEST(test_http_keep_alive_1_prefer_yes);
    ADD_TEST(test_http_keep_alive_0_require_yes);
    ADD_TEST(test_http_keep_alive_1_require_yes);
    ADD_TEST(test_http_keep_alive_0_require_no);
    ADD_TEST(test_http_keep_alive_1_require_no);
    return 1;
}
