/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "internal/nelem.h"
#include "internal/uri.h"
#include "testutil.h"

/**
 * @struct uri_test_st
 * @brief A URI and the components ossl_uri_parse() must find in it.
 * A NULL component is expected to be absent.
 */
struct uri_test_st {
    const char *uri; /**< the input */
    const char *scheme; /**< expected scheme */
    const char *userinfo; /**< expected userinfo, NULL if absent */
    const char *host; /**< expected host, NULL if there is no authority */
    int host_type; /**< expected OSSL_URI_HOST_ value */
    const char *port; /**< expected port, NULL if absent */
    int port_num; /**< expected port number */
    const char *path; /**< expected path */
    const char *query; /**< expected query, NULL if absent */
    const char *fragment; /**< expected fragment, NULL if absent */
};

static const struct uri_test_st valid_uris[] = {
    { "http://example.com", "http", NULL, "example.com",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "", NULL, NULL },
    { "https://u:p@example.com:8443/a/b?q=1&r#frag", "https", "u:p",
        "example.com", OSSL_URI_HOST_REG_NAME, "8443", 8443, "/a/b",
        "q=1&r", "frag" },
    { "http://example.com:/", "http", NULL, "example.com",
        OSSL_URI_HOST_REG_NAME, "", -1, "/", NULL, NULL },
    { "http://example.com:0/", "http", NULL, "example.com",
        OSSL_URI_HOST_REG_NAME, "0", 0, "/", NULL, NULL },
    { "http://example.com:065535", "http", NULL, "example.com",
        OSSL_URI_HOST_REG_NAME, "065535", 65535, "", NULL, NULL },
    { "http://h:80@example.com/", "http", "h:80", "example.com",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "/", NULL, NULL },
    { "foo://%40something@good.org", "foo", "%40something", "good.org",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "", NULL, NULL },
    { "http://ex%41mple.com/%7e", "http", NULL, "ex%41mple.com",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "/%7e", NULL, NULL },
    { "http://1.2.3.4/", "http", NULL, "1.2.3.4", OSSL_URI_HOST_IPV4, NULL,
        -1, "/", NULL, NULL },
    { "http://255.255.255.255/", "http", NULL, "255.255.255.255",
        OSSL_URI_HOST_IPV4, NULL, -1, "/", NULL, NULL },
    { "http://1.2.3.04/", "http", NULL, "1.2.3.04", OSSL_URI_HOST_REG_NAME,
        NULL, -1, "/", NULL, NULL },
    { "http://1.2.3.256/", "http", NULL, "1.2.3.256",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "/", NULL, NULL },
    { "http://1.2.3/", "http", NULL, "1.2.3", OSSL_URI_HOST_REG_NAME, NULL,
        -1, "/", NULL, NULL },
    { "http://[::1]:6/", "http", NULL, "::1", OSSL_URI_HOST_IPV6, "6", 6, "/",
        NULL, NULL },
    { "http://[FF01::101]", "http", NULL, "FF01::101", OSSL_URI_HOST_IPV6,
        NULL, -1, "", NULL, NULL },
    { "http://[1:2:3:4:5:6:7:8]/", "http", NULL, "1:2:3:4:5:6:7:8",
        OSSL_URI_HOST_IPV6, NULL, -1, "/", NULL, NULL },
    { "http://[::]/", "http", NULL, "::", OSSL_URI_HOST_IPV6, NULL, -1, "/",
        NULL, NULL },
    { "http://[1:2:3:4:5:6:7::]/", "http", NULL, "1:2:3:4:5:6:7::",
        OSSL_URI_HOST_IPV6, NULL, -1, "/", NULL, NULL },
    { "http://[::ffff:1.2.3.4]/", "http", NULL, "::ffff:1.2.3.4",
        OSSL_URI_HOST_IPV6, NULL, -1, "/", NULL, NULL },
    { "http://[1:2:3:4:5:6:1.2.3.4]/", "http", NULL, "1:2:3:4:5:6:1.2.3.4",
        OSSL_URI_HOST_IPV6, NULL, -1, "/", NULL, NULL },
    { "http:///path", "http", NULL, "", OSSL_URI_HOST_REG_NAME, NULL, -1,
        "/path", NULL, NULL },
    { "file:///etc/passwd", "file", NULL, "", OSSL_URI_HOST_REG_NAME, NULL,
        -1, "/etc/passwd", NULL, NULL },
    { "http://user@/", "http", "user", "", OSSL_URI_HOST_REG_NAME, NULL, -1,
        "/", NULL, NULL },
    { "urn:isbn:0451450523", "urn", NULL, NULL, 0, NULL, -1,
        "isbn:0451450523", NULL, NULL },
    { "mailto:a@example.com", "mailto", NULL, NULL, 0, NULL, -1,
        "a@example.com", NULL, NULL },
    { "news:/comp.lang", "news", NULL, NULL, 0, NULL, -1, "/comp.lang", NULL,
        NULL },
    { "a+b-c.d:", "a+b-c.d", NULL, NULL, 0, NULL, -1, "", NULL, NULL },
    { "example.com:80/path", "example.com", NULL, NULL, 0, NULL, -1,
        "80/path", NULL, NULL },
    { "HTTP://EXAMPLE.COM/", "HTTP", NULL, "EXAMPLE.COM",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "/", NULL, NULL },
    { "http://h?", "http", NULL, "h", OSSL_URI_HOST_REG_NAME, NULL, -1, "",
        "", NULL },
    { "http://h#", "http", NULL, "h", OSSL_URI_HOST_REG_NAME, NULL, -1, "",
        NULL, "" },
    { "http://h?q#f", "http", NULL, "h", OSSL_URI_HOST_REG_NAME, NULL, -1, "",
        "q", "f" },
    { "http://h/p#f?q", "http", NULL, "h", OSSL_URI_HOST_REG_NAME, NULL, -1,
        "/p", NULL, "f?q" },
    { "http://h/p?a?b/c#d/e?", "http", NULL, "h", OSSL_URI_HOST_REG_NAME,
        NULL, -1, "/p", "a?b/c", "d/e?" },
    { "http://h/p@q:r", "http", NULL, "h", OSSL_URI_HOST_REG_NAME, NULL, -1,
        "/p@q:r", NULL, NULL },
    { "http://h?q=@attacker.test", "http", NULL, "h", OSSL_URI_HOST_REG_NAME,
        NULL, -1, "", "q=@attacker.test", NULL },
    { "http://h#@attacker.test", "http", NULL, "h", OSSL_URI_HOST_REG_NAME,
        NULL, -1, "", NULL, "@attacker.test" },
    /* Cases from the OSSL_HTTP_parse_url() tests in http_test.c */
    { "http://host/p/2017-01-03T00:00:00", "http", NULL, "host",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "/p/2017-01-03T00:00:00", NULL,
        NULL },
    { "https://host/p/2017-01-03T00:00:00", "https", NULL, "host",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "/p/2017-01-03T00:00:00", NULL,
        NULL },
    { "http://usr@host:1/p?q=x#frag", "http", "usr", "host",
        OSSL_URI_HOST_REG_NAME, "1", 1, "/p", "q=x", "frag" },
    { "http://host?query#frag", "http", NULL, "host", OSSL_URI_HOST_REG_NAME,
        NULL, -1, "", "query", "frag" },
    { "http://host:9999#frag", "http", NULL, "host", OSSL_URI_HOST_REG_NAME,
        "9999", 9999, "", NULL, "frag" },
    { "http://user:pass@host/p?q#fr", "http", "user:pass", "host",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "/p", "q", "fr" },
    { "http://host.example.org/some/path#://not-a-scheme/not.a.host:404",
        "http", NULL, "host.example.org", OSSL_URI_HOST_REG_NAME, NULL, -1,
        "/some/path", NULL, "://not-a-scheme/not.a.host:404" },
    { "http://host/p@attacker.test", "http", NULL, "host",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "/p@attacker.test", NULL, NULL },
    { "http://host/p?q=@attacker.test", "http", NULL, "host",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "/p", "q=@attacker.test", NULL },
    { "http://host/p?q#fr@attacker.test", "http", NULL, "host",
        OSSL_URI_HOST_REG_NAME, NULL, -1, "/p", "q", "fr@attacker.test" },
    { "https://1.2.3.4/p/q", "https", NULL, "1.2.3.4", OSSL_URI_HOST_IPV4,
        NULL, -1, "/p/q", NULL, NULL },
    { "http://[FF01::101]:6", "http", NULL, "FF01::101", OSSL_URI_HOST_IPV6,
        "6", 6, "", NULL, NULL },
    { "htttps://1.2.3.4:65535/pkix", "htttps", NULL, "1.2.3.4",
        OSSL_URI_HOST_IPV4, "65535", 65535, "/pkix", NULL, NULL },
    { "https://1.2.3.4:", "https", NULL, "1.2.3.4", OSSL_URI_HOST_IPV4, "",
        -1, "", NULL, NULL },
    { "host:65535/path", "host", NULL, NULL, 0, NULL, -1, "65535/path", NULL,
        NULL },
    { "user:pass@host/p?q#fr", "user", NULL, NULL, 0, NULL, -1,
        "pass@host/p", "q", "fr" }
};

static const char *invalid_uris[] = {
    "",
    ":",
    "://h",
    "1http://h",
    "ht tp://h",
    "example.com",
    "/relative/path",
    "http://a@b@example.com/",
    "http://exa mple.com/",
    "http://exa\\mple.com/",
    "http://example.com:65536/",
    "http://example.com:4294967376/",
    "http://example.com:+80/",
    "http://example.com:80x/",
    "http://example.com:80:90/",
    "http://%zz/",
    "http://%4/",
    "http://h/%",
    "http://[]/",
    "http://[::1/",
    "http://[::1]x/",
    "http://h[::1]/",
    "http://[:::]/",
    "http://[1:::2]/",
    "http://[1::2::3]/",
    "http://[1:2:3:4:5:6:7]/",
    "http://[1:2:3:4:5:6:7:8:9]/",
    "http://[1:2:3:4:5:6:7:8::]/",
    "http://[12345::]/",
    "http://[::1:]/",
    "http://[:1::]/",
    "http://[1.2.3.4::]/",
    "http://[::1.2.3]/",
    "http://[1:2:3:4:5:6:7:1.2.3.4]/",
    "http://[g::]/",
    "http://[v1.fe:80]/",
    "http://h/p#f#g",
    "http://h/p q",
    "http://h/\x7f",
    "http://h/\xc3\xa9",
    /* Cases from the OSSL_HTTP_parse_url() tests in http_test.c */
    "http://[FF01::101/path]",
    "https://1.2.3.4:65536/pkix",
    "https://[FF01::101]pkix",
    "1.2.3.4:5678//blahblablah",
    "host/p/2017-01-03T00:00:00",
    "host.example.org/some/path#://not-a-scheme/not.a.host:404"
};

static int packet_eq(const PACKET *pkt, const char *expected)
{
    return TEST_mem_eq(PACKET_data(pkt), PACKET_remaining(pkt),
        expected, strlen(expected));
}

/*
 * Copy s to a heap buffer of exactly strlen(s) bytes, with no NUL
 * terminator: memory checkers catch any read past the end.
 */
static uint8_t *unterminated_copy(const char *s, size_t *len)
{
    *len = strlen(s);
    return OPENSSL_memdup(s, *len > 0 ? *len : 1);
}

static int test_valid_uri(int idx)
{
    const struct uri_test_st *t = &valid_uris[idx];
    OSSL_URI uri;
    uint8_t *buf;
    size_t len;
    int ret = 0;

    TEST_info("%s", t->uri);
    if (!TEST_ptr(buf = unterminated_copy(t->uri, &len)))
        return 0;
    if (!TEST_true(ossl_uri_parse(buf, len, &uri))
        || !packet_eq(&uri.scheme, t->scheme)
        || !TEST_int_eq(uri.has_authority, t->host != NULL)
        || !TEST_int_eq(uri.has_userinfo, t->userinfo != NULL)
        || !TEST_int_eq(uri.has_port, t->port != NULL)
        || !TEST_int_eq(uri.port_num, t->port_num)
        || !packet_eq(&uri.path, t->path)
        || !TEST_int_eq(uri.has_query, t->query != NULL)
        || !TEST_int_eq(uri.has_fragment, t->fragment != NULL))
        goto end;
    if (t->userinfo != NULL && !packet_eq(&uri.userinfo, t->userinfo))
        goto end;
    if (t->host != NULL
        && (!packet_eq(&uri.host, t->host)
            || !TEST_int_eq(uri.host_type, t->host_type)))
        goto end;
    if (t->port != NULL && !packet_eq(&uri.port, t->port))
        goto end;
    if (t->query != NULL && !packet_eq(&uri.query, t->query))
        goto end;
    if (t->fragment != NULL && !packet_eq(&uri.fragment, t->fragment))
        goto end;
    ret = 1;
end:
    OPENSSL_free(buf);
    return ret;
}

static int test_invalid_uri(int idx)
{
    OSSL_URI uri;
    uint8_t *buf;
    size_t len;
    int ret;

    TEST_info("%s", invalid_uris[idx]);
    if (!TEST_ptr(buf = unterminated_copy(invalid_uris[idx], &len)))
        return 0;
    ret = TEST_false(ossl_uri_parse(buf, len, &uri));
    OPENSSL_free(buf);
    return ret;
}

/* The length, not a NUL terminator, delimits the input. */
static int test_uri_length(void)
{
    static const uint8_t with_nul[] = "http://good.org\0.bad.org/";
    static const uint8_t prefix[] = "http://good.org/extra";
    OSSL_URI uri;

    return TEST_false(ossl_uri_parse(with_nul, sizeof(with_nul) - 1, &uri))
        && TEST_true(ossl_uri_parse(prefix, strlen("http://good.org"), &uri))
        && packet_eq(&uri.host, "good.org")
        && packet_eq(&uri.path, "")
        && TEST_false(ossl_uri_parse(NULL, 0, &uri));
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_valid_uri, OSSL_NELEM(valid_uris));
    ADD_ALL_TESTS(test_invalid_uri, OSSL_NELEM(invalid_uris));
    ADD_TEST(test_uri_length);
    return 1;
}
