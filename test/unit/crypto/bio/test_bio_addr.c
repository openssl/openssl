/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/sockets.h"

#ifdef OPENSSL_NO_SOCK

int main(void)
{
    return 0;
}

#else

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "bio_local.h"

#include <openssl/bio.h>

/* wraps */

int __wrap_BIO_sock_init(void);
#ifdef AI_PASSIVE
int __wrap_getnameinfo(const struct sockaddr *sa, socklen_t salen,
    char *host, socklen_t hostlen,
    char *serv, socklen_t servlen, int flags);
void __wrap_freeaddrinfo(struct addrinfo *res);
#endif

int __wrap_BIO_sock_init(void)
{
    function_called();
    return mock_type(int);
}

#ifdef AI_PASSIVE
int __wrap_getnameinfo(const struct sockaddr *sa, socklen_t salen,
    char *host, socklen_t hostlen,
    char *serv, socklen_t servlen, int flags)
{
    int rc;

    function_called();
    check_expected_ptr(sa);
    check_expected(salen);
    check_expected(flags);
    rc = mock_type(int);
    if (rc == 0) {
        if (host != NULL)
            strncpy(host, mock_ptr_type(const char *), hostlen - 1);
        if (serv != NULL)
            strncpy(serv, mock_ptr_type(const char *), servlen - 1);
    }
    return rc;
}

void __wrap_freeaddrinfo(struct addrinfo *res)
{
    function_called();
    check_expected_ptr(res);
}
#endif /* AI_PASSIVE */

/* expectations */

static void expect_sock_init(int rc)
{
    expect_function_call(__wrap_BIO_sock_init);
    will_return(__wrap_BIO_sock_init, rc);
}

#ifdef AI_PASSIVE
static void expect_getnameinfo(const struct sockaddr *sa, socklen_t salen,
    int flags, int rc,
    const char *host_out, const char *serv_out)
{
    expect_function_call(__wrap_getnameinfo);
    expect_value(__wrap_getnameinfo, sa, sa);
    expect_value(__wrap_getnameinfo, salen, salen);
    expect_value(__wrap_getnameinfo, flags, flags);
    will_return(__wrap_getnameinfo, rc);
    if (rc == 0) {
        will_return(__wrap_getnameinfo, host_out);
        will_return(__wrap_getnameinfo, serv_out);
    }
}

static void expect_freeaddrinfo(const struct addrinfo *res)
{
    expect_function_call(__wrap_freeaddrinfo);
    expect_value(__wrap_freeaddrinfo, res, res);
}
#endif /* AI_PASSIVE */

/* BIO_ADDR_clear */

static void test_addr_clear(void **state)
{
    BIO_ADDR ap;

    (void)state;
    memset(&ap, 0xFF, sizeof(ap));
    BIO_ADDR_clear(&ap);
    assert_int_equal(ap.sa.sa_family, AF_UNSPEC);
    assert_int_equal(ap.s_in.sin_port, 0);
    assert_int_equal(ap.s_in.sin_addr.s_addr, 0);
}

/* BIO_ADDR_make */

static void test_addr_make_ipv4(void **state)
{
    struct sockaddr_in sa4;
    BIO_ADDR ap;

    (void)state;
    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;
    sa4.sin_port = htons(443);
    sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    assert_int_equal(BIO_ADDR_make(&ap, (const struct sockaddr *)&sa4), 1);
    assert_int_equal(ap.s_in.sin_family, AF_INET);
    assert_int_equal(ap.s_in.sin_port, htons(443));
    assert_int_equal(ap.s_in.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
}

#if OPENSSL_USE_IPV6
static void test_addr_make_ipv6(void **state)
{
    struct sockaddr_in6 sa6;
    BIO_ADDR ap;
    struct in6_addr loopback = IN6ADDR_LOOPBACK_INIT;

    (void)state;
    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_port = htons(443);
    sa6.sin6_addr = loopback;

    assert_int_equal(BIO_ADDR_make(&ap, (const struct sockaddr *)&sa6), 1);
    assert_int_equal(ap.s_in6.sin6_family, AF_INET6);
    assert_int_equal(ap.s_in6.sin6_port, htons(443));
    assert_memory_equal(&ap.s_in6.sin6_addr, &loopback, sizeof(loopback));
}
#endif

#ifndef OPENSSL_NO_UNIX_SOCK
static void test_addr_make_unix(void **state)
{
    struct sockaddr_un sau;
    BIO_ADDR ap;

    (void)state;
    memset(&sau, 0, sizeof(sau));
    sau.sun_family = AF_UNIX;
    strncpy(sau.sun_path, "/tmp/test.sock", sizeof(sau.sun_path) - 1);

    assert_int_equal(BIO_ADDR_make(&ap, (const struct sockaddr *)&sau), 1);
    assert_int_equal(ap.s_un.sun_family, AF_UNIX);
    assert_string_equal(ap.s_un.sun_path, "/tmp/test.sock");
}
#endif

static void test_addr_make_unknown_family(void **state)
{
    struct sockaddr sa;
    BIO_ADDR ap;

    (void)state;
    memset(&sa, 0, sizeof(sa));
    sa.sa_family = AF_UNSPEC;
    assert_int_equal(BIO_ADDR_make(&ap, &sa), 0);
}

/* BIO_ADDR_rawmake */

static void test_rawmake_ipv4(void **state)
{
    struct in_addr addr4;
    BIO_ADDR ap;

    (void)state;
    addr4.s_addr = htonl(INADDR_LOOPBACK);
    assert_int_equal(
        BIO_ADDR_rawmake(&ap, AF_INET, &addr4, sizeof(addr4), htons(80)), 1);
    assert_int_equal(ap.s_in.sin_family, AF_INET);
    assert_int_equal(ap.s_in.sin_port, htons(80));
    assert_int_equal(ap.s_in.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
}

static void test_rawmake_ipv4_wrong_len(void **state)
{
    struct in_addr addr4;
    BIO_ADDR ap;

    (void)state;
    addr4.s_addr = htonl(INADDR_LOOPBACK);
    assert_int_equal(
        BIO_ADDR_rawmake(&ap, AF_INET, &addr4, sizeof(addr4) - 1, 0), 0);
}

#if OPENSSL_USE_IPV6
static void test_rawmake_ipv6(void **state)
{
    struct in6_addr addr6 = IN6ADDR_LOOPBACK_INIT;
    BIO_ADDR ap;

    (void)state;
    assert_int_equal(
        BIO_ADDR_rawmake(&ap, AF_INET6, &addr6, sizeof(addr6), htons(443)), 1);
    assert_int_equal(ap.s_in6.sin6_family, AF_INET6);
    assert_int_equal(ap.s_in6.sin6_port, htons(443));
    assert_memory_equal(&ap.s_in6.sin6_addr, &addr6, sizeof(addr6));
}
#endif

#ifndef OPENSSL_NO_UNIX_SOCK
static void test_rawmake_unix(void **state)
{
    const char *path = "/tmp/test.sock";
    BIO_ADDR ap;

    (void)state;
    assert_int_equal(
        BIO_ADDR_rawmake(&ap, AF_UNIX, path, strlen(path), 0), 1);
    assert_int_equal(ap.s_un.sun_family, AF_UNIX);
    assert_string_equal(ap.s_un.sun_path, path);
}

static void test_rawmake_unix_too_long(void **state)
{
    /* path longer than sun_path must be rejected */
    char path[sizeof(((struct sockaddr_un *)0)->sun_path) + 2];
    BIO_ADDR ap;

    (void)state;
    memset(path, 'x', sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
    assert_int_equal(
        BIO_ADDR_rawmake(&ap, AF_UNIX, path, strlen(path), 0), 0);
}
#endif

static void test_rawmake_unknown_family(void **state)
{
    char data[4] = { 0 };
    BIO_ADDR ap;

    (void)state;
    assert_int_equal(BIO_ADDR_rawmake(&ap, AF_UNSPEC, data, 0, 0), 0);
}

/* BIO_ADDR_family */

static void test_addr_family(void **state)
{
    BIO_ADDR ap;

    (void)state;
    memset(&ap, 0, sizeof(ap));
    ap.sa.sa_family = AF_UNSPEC;
    assert_int_equal(BIO_ADDR_family(&ap), AF_UNSPEC);
    ap.sa.sa_family = AF_INET;
    assert_int_equal(BIO_ADDR_family(&ap), AF_INET);
}

/* BIO_ADDR_rawport */

static void test_rawport_ipv4(void **state)
{
    BIO_ADDR ap;
    struct in_addr addr4;

    (void)state;
    addr4.s_addr = htonl(INADDR_LOOPBACK);
    BIO_ADDR_rawmake(&ap, AF_INET, &addr4, sizeof(addr4), htons(443));
    assert_int_equal(BIO_ADDR_rawport(&ap), htons(443));
}

#if OPENSSL_USE_IPV6
static void test_rawport_ipv6(void **state)
{
    BIO_ADDR ap;
    struct in6_addr addr6 = IN6ADDR_LOOPBACK_INIT;

    (void)state;
    BIO_ADDR_rawmake(&ap, AF_INET6, &addr6, sizeof(addr6), htons(8080));
    assert_int_equal(BIO_ADDR_rawport(&ap), htons(8080));
}
#endif

static void test_rawport_no_port(void **state)
{
    BIO_ADDR ap;

    (void)state;
    memset(&ap, 0, sizeof(ap));
    ap.sa.sa_family = AF_UNSPEC;
    assert_int_equal(BIO_ADDR_rawport(&ap), 0);
}

/* BIO_ADDR_sockaddr and BIO_ADDR_sockaddr_noconst */

static void test_sockaddr_pointers(void **state)
{
    BIO_ADDR ap = { 0 };

    (void)state;
    memset(&ap, 0, sizeof(ap));
    assert_ptr_equal(BIO_ADDR_sockaddr(&ap), &ap.sa);
    assert_ptr_equal(BIO_ADDR_sockaddr_noconst(&ap), &ap.sa);
}

/* BIO_ADDR_sockaddr_size */

static void test_sockaddr_size_ipv4(void **state)
{
    BIO_ADDR ap;

    (void)state;
    memset(&ap, 0, sizeof(ap));
    ap.sa.sa_family = AF_INET;
    assert_int_equal(BIO_ADDR_sockaddr_size(&ap), sizeof(struct sockaddr_in));
}

#if OPENSSL_USE_IPV6
static void test_sockaddr_size_ipv6(void **state)
{
    BIO_ADDR ap;

    (void)state;
    memset(&ap, 0, sizeof(ap));
    ap.sa.sa_family = AF_INET6;
    assert_int_equal(BIO_ADDR_sockaddr_size(&ap), sizeof(struct sockaddr_in6));
}
#endif

#ifndef OPENSSL_NO_UNIX_SOCK
static void test_sockaddr_size_unix(void **state)
{
    BIO_ADDR ap;

    (void)state;
    memset(&ap, 0, sizeof(ap));
    ap.sa.sa_family = AF_UNIX;
    assert_int_equal(BIO_ADDR_sockaddr_size(&ap), sizeof(struct sockaddr_un));
}
#endif

static void test_sockaddr_size_default(void **state)
{
    BIO_ADDR ap;

    (void)state;
    memset(&ap, 0, sizeof(ap));
    ap.sa.sa_family = AF_UNSPEC;
    assert_int_equal(BIO_ADDR_sockaddr_size(&ap), sizeof(BIO_ADDR));
}

/* BIO_ADDR_rawaddress */

static void test_rawaddress_unset(void **state)
{
    BIO_ADDR ap;
    struct in_addr out;
    size_t len;

    (void)state;
    memset(&ap, 0, sizeof(ap));
    ap.sa.sa_family = AF_UNSPEC;
    assert_int_equal(BIO_ADDR_rawaddress(&ap, &out, &len), 0);
}

static void test_rawaddress_ipv4(void **state)
{
    BIO_ADDR ap;
    struct in_addr expected, out;
    size_t len = 0;

    (void)state;
    expected.s_addr = htonl(INADDR_LOOPBACK);
    BIO_ADDR_rawmake(&ap, AF_INET, &expected, sizeof(expected), htons(80));

    assert_int_equal(BIO_ADDR_rawaddress(&ap, &out, &len), 1);
    assert_int_equal(len, sizeof(struct in_addr));
    assert_memory_equal(&out, &expected, sizeof(expected));
}

static void test_rawaddress_ipv4_len_only(void **state)
{
    BIO_ADDR ap;
    struct in_addr addr4;
    size_t len = 0;

    (void)state;
    addr4.s_addr = htonl(INADDR_LOOPBACK);
    BIO_ADDR_rawmake(&ap, AF_INET, &addr4, sizeof(addr4), 0);

    assert_int_equal(BIO_ADDR_rawaddress(&ap, NULL, &len), 1);
    assert_int_equal(len, sizeof(struct in_addr));
}

static void test_rawaddress_ipv4_ptr_only(void **state)
{
    BIO_ADDR ap;
    struct in_addr expected, out;

    (void)state;
    expected.s_addr = htonl(INADDR_LOOPBACK);
    BIO_ADDR_rawmake(&ap, AF_INET, &expected, sizeof(expected), 0);

    assert_int_equal(BIO_ADDR_rawaddress(&ap, &out, NULL), 1);
    assert_memory_equal(&out, &expected, sizeof(expected));
}

#ifndef OPENSSL_NO_UNIX_SOCK
static void test_rawaddress_unix(void **state)
{
    BIO_ADDR ap;
    const char *path = "/tmp/unit.sock";
    char out[64];
    size_t len = 0;

    (void)state;
    BIO_ADDR_rawmake(&ap, AF_UNIX, path, strlen(path), 0);

    assert_int_equal(BIO_ADDR_rawaddress(&ap, out, &len), 1);
    assert_int_equal(len, strlen(path));
    assert_memory_equal(out, path, strlen(path));
}
#endif

/* BIO_ADDR_copy */

static void test_addr_copy_null(void **state)
{
    BIO_ADDR ap;

    (void)state;
    memset(&ap, 0, sizeof(ap));
    assert_int_equal(BIO_ADDR_copy(NULL, NULL), 0);
    assert_int_equal(BIO_ADDR_copy(NULL, &ap), 0);
    assert_int_equal(BIO_ADDR_copy(&ap, NULL), 0);
}

static void test_addr_copy_unspec(void **state)
{
    BIO_ADDR src, dst;

    (void)state;
    memset(&src, 0, sizeof(src));
    src.sa.sa_family = AF_UNSPEC;
    memset(&dst, 0xFF, sizeof(dst));

    assert_int_equal(BIO_ADDR_copy(&dst, &src), 1);
    assert_int_equal(dst.sa.sa_family, AF_UNSPEC);
}

static void test_addr_copy_ipv4(void **state)
{
    BIO_ADDR src, dst;
    struct in_addr addr4;

    (void)state;
    addr4.s_addr = htonl(INADDR_LOOPBACK);
    BIO_ADDR_rawmake(&src, AF_INET, &addr4, sizeof(addr4), htons(443));
    memset(&dst, 0, sizeof(dst));

    assert_int_equal(BIO_ADDR_copy(&dst, &src), 1);
    assert_int_equal(dst.s_in.sin_family, AF_INET);
    assert_int_equal(dst.s_in.sin_port, htons(443));
    assert_int_equal(dst.s_in.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
}

/* BIO_ADDR_new and BIO_ADDR_free */

static void test_addr_new_sets_unspec(void **state)
{
    BIO_ADDR *ap;

    (void)state;
    ap = BIO_ADDR_new();
    assert_non_null(ap);
    assert_int_equal(BIO_ADDR_family(ap), AF_UNSPEC);
    BIO_ADDR_free(ap);
}

/* BIO_ADDR_dup */

static void test_addr_dup_null(void **state)
{
    (void)state;
    assert_null(BIO_ADDR_dup(NULL));
}

static void test_addr_dup_ipv4(void **state)
{
    BIO_ADDR src, *dup;
    struct in_addr addr4;

    (void)state;
    addr4.s_addr = htonl(INADDR_LOOPBACK);
    BIO_ADDR_rawmake(&src, AF_INET, &addr4, sizeof(addr4), htons(8443));

    dup = BIO_ADDR_dup(&src);
    assert_non_null(dup);
    assert_int_equal(dup->s_in.sin_family, AF_INET);
    assert_int_equal(dup->s_in.sin_port, htons(8443));
    assert_int_equal(dup->s_in.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
    BIO_ADDR_free(dup);
}

/* BIO_ADDR_path_string */

#ifndef OPENSSL_NO_UNIX_SOCK
static void test_path_string_unix(void **state)
{
    BIO_ADDR ap;
    char *path;

    (void)state;
    BIO_ADDR_rawmake(&ap, AF_UNIX, "/run/unit.sock", 14, 0);

    path = BIO_ADDR_path_string(&ap);
    assert_non_null(path);
    assert_string_equal(path, "/run/unit.sock");
    OPENSSL_free(path);
}
#endif

static void test_path_string_non_unix(void **state)
{
    BIO_ADDR ap;
    struct in_addr addr4;

    (void)state;
    addr4.s_addr = htonl(INADDR_LOOPBACK);
    BIO_ADDR_rawmake(&ap, AF_INET, &addr4, sizeof(addr4), htons(80));
    assert_null(BIO_ADDR_path_string(&ap));
}

/* BIO_ADDRINFO accessors */

static void test_addrinfo_next_null(void **state)
{
    (void)state;
    assert_null(BIO_ADDRINFO_next(NULL));
}

static void test_addrinfo_next(void **state)
{
    BIO_ADDRINFO a, b;

    (void)state;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    a.bai_next = &b;
    b.bai_next = NULL;
    assert_ptr_equal(BIO_ADDRINFO_next(&a), &b);
    assert_null(BIO_ADDRINFO_next(&b));
}

static void test_addrinfo_family(void **state)
{
    BIO_ADDRINFO bai;

    (void)state;
    assert_int_equal(BIO_ADDRINFO_family(NULL), 0);
    memset(&bai, 0, sizeof(bai));
    bai.bai_family = AF_INET;
    assert_int_equal(BIO_ADDRINFO_family(&bai), AF_INET);
}

static void test_addrinfo_socktype(void **state)
{
    BIO_ADDRINFO bai;

    (void)state;
    assert_int_equal(BIO_ADDRINFO_socktype(NULL), 0);
    memset(&bai, 0, sizeof(bai));
    bai.bai_socktype = SOCK_STREAM;
    assert_int_equal(BIO_ADDRINFO_socktype(&bai), SOCK_STREAM);
}

/* BIO_ADDRINFO_protocol */

static void test_addrinfo_protocol_null(void **state)
{
    (void)state;
    assert_int_equal(BIO_ADDRINFO_protocol(NULL), 0);
}

static void test_addrinfo_protocol_explicit(void **state)
{
    BIO_ADDRINFO bai;

    (void)state;
    memset(&bai, 0, sizeof(bai));
    bai.bai_protocol = IPPROTO_SCTP;
    assert_int_equal(BIO_ADDRINFO_protocol(&bai), IPPROTO_SCTP);
}

static void test_addrinfo_protocol_stream(void **state)
{
    BIO_ADDRINFO bai;

    (void)state;
    memset(&bai, 0, sizeof(bai));
    bai.bai_family = AF_INET;
    bai.bai_socktype = SOCK_STREAM;
    assert_int_equal(BIO_ADDRINFO_protocol(&bai), IPPROTO_TCP);
}

static void test_addrinfo_protocol_dgram(void **state)
{
    BIO_ADDRINFO bai;

    (void)state;
    memset(&bai, 0, sizeof(bai));
    bai.bai_family = AF_INET;
    bai.bai_socktype = SOCK_DGRAM;
    assert_int_equal(BIO_ADDRINFO_protocol(&bai), IPPROTO_UDP);
}

#ifndef OPENSSL_NO_UNIX_SOCK
static void test_addrinfo_protocol_unix(void **state)
{
    BIO_ADDRINFO bai;

    (void)state;
    memset(&bai, 0, sizeof(bai));
    bai.bai_family = AF_UNIX;
    bai.bai_socktype = SOCK_STREAM;
    /* AF_UNIX always returns 0, regardless of socktype */
    assert_int_equal(BIO_ADDRINFO_protocol(&bai), 0);
}
#endif

static void test_addrinfo_sockaddr_size(void **state)
{
    BIO_ADDRINFO bai;

    (void)state;
    assert_int_equal(BIO_ADDRINFO_sockaddr_size(NULL), 0);
    memset(&bai, 0, sizeof(bai));
    bai.bai_addrlen = 28;
    assert_int_equal(BIO_ADDRINFO_sockaddr_size(&bai), 28);
}

static void test_addrinfo_sockaddr(void **state)
{
    BIO_ADDRINFO bai;
    struct sockaddr sa;

    (void)state;
    assert_null(BIO_ADDRINFO_sockaddr(NULL));
    memset(&bai, 0, sizeof(bai));
    bai.bai_addr = &sa;
    assert_ptr_equal(BIO_ADDRINFO_sockaddr(&bai), &sa);
}

static void test_addrinfo_address(void **state)
{
    BIO_ADDRINFO bai;
    struct sockaddr sa;

    (void)state;
    assert_null(BIO_ADDRINFO_address(NULL));
    memset(&bai, 0, sizeof(bai));
    bai.bai_addr = &sa;
    assert_ptr_equal(BIO_ADDRINFO_address(&bai), (BIO_ADDR *)&sa);
}

/* BIO_ADDRINFO_free */

static void test_addrinfo_free_null(void **state)
{
    (void)state;
    BIO_ADDRINFO_free(NULL); /* must not crash */
}

#ifdef AI_PASSIVE
static void test_addrinfo_free_ip(void **state)
{
    /* AF_INET with AI_PASSIVE: freeaddrinfo is called, not manual free */
    struct addrinfo bai;

    (void)state;
    memset(&bai, 0, sizeof(bai));
    bai.ai_family = AF_INET;

    expect_freeaddrinfo(&bai);
    BIO_ADDRINFO_free(&bai);
}
#endif

/* BIO_parse_hostserv */

static void test_parse_host_and_service(void **state)
{
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("host.example:443", &host, &service,
            BIO_PARSE_PRIO_HOST),
        1);
    assert_string_equal(host, "host.example");
    assert_string_equal(service, "443");
    OPENSSL_free(host);
    OPENSSL_free(service);
}

static void test_parse_empty_host(void **state)
{
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv(":80", &host, &service, BIO_PARSE_PRIO_HOST), 1);
    assert_null(host);
    assert_string_equal(service, "80");
    OPENSSL_free(service);
}

static void test_parse_star_host(void **state)
{
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("*:80", &host, &service, BIO_PARSE_PRIO_HOST), 1);
    assert_null(host);
    assert_string_equal(service, "80");
    OPENSSL_free(service);
}

static void test_parse_empty_service(void **state)
{
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("host:", &host, &service, BIO_PARSE_PRIO_HOST), 1);
    assert_string_equal(host, "host");
    assert_null(service);
    OPENSSL_free(host);
}

static void test_parse_star_service(void **state)
{
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("host:*", &host, &service, BIO_PARSE_PRIO_HOST), 1);
    assert_string_equal(host, "host");
    assert_null(service);
    OPENSSL_free(host);
}

static void test_parse_no_colon_host_prio(void **state)
{
    /* no colon + HOST prio: host set, service untouched */
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("myhost", &host, &service, BIO_PARSE_PRIO_HOST), 1);
    assert_string_equal(host, "myhost");
    assert_null(service);
    OPENSSL_free(host);
}

static void test_parse_no_colon_serv_prio(void **state)
{
    /* no colon + SERV prio: service set, host untouched */
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("https", &host, &service, BIO_PARSE_PRIO_SERV), 1);
    assert_null(host);
    assert_string_equal(service, "https");
    OPENSSL_free(service);
}

static void test_parse_bracket_host_and_service(void **state)
{
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("[::1]:443", &host, &service, BIO_PARSE_PRIO_HOST), 1);
    assert_string_equal(host, "::1");
    assert_string_equal(service, "443");
    OPENSSL_free(host);
    OPENSSL_free(service);
}

static void test_parse_bracket_no_service(void **state)
{
    /* "[host]" with no trailing colon: service left untouched */
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("[::1]", &host, &service, BIO_PARSE_PRIO_HOST), 1);
    assert_string_equal(host, "::1");
    assert_null(service);
    OPENSSL_free(host);
}

static void test_parse_bracket_unclosed(void **state)
{
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("[::1", &host, &service, BIO_PARSE_PRIO_HOST), 0);
}

static void test_parse_bracket_bad_suffix(void **state)
{
    /* ']' not followed by ':' or '\0' */
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("[::1]X", &host, &service, BIO_PARSE_PRIO_HOST), 0);
}

static void test_parse_bracket_service_with_colon(void **state)
{
    /* service part contains a colon */
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("[host]:a:b", &host, &service, BIO_PARSE_PRIO_HOST), 0);
}

static void test_parse_ambiguous(void **state)
{
    /* multiple colons without brackets */
    char *host = NULL, *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("host:port:extra", &host, &service,
            BIO_PARSE_PRIO_HOST),
        0);
}

static void test_parse_null_host_param(void **state)
{
    /* host output param NULL */
    char *service = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("host:443", NULL, &service, BIO_PARSE_PRIO_HOST), 1);
    assert_string_equal(service, "443");
    OPENSSL_free(service);
}

static void test_parse_null_service_param(void **state)
{
    /* service output param NULL */
    char *host = NULL;

    (void)state;
    assert_int_equal(
        BIO_parse_hostserv("host:443", &host, NULL, BIO_PARSE_PRIO_HOST), 1);
    assert_string_equal(host, "host");
    OPENSSL_free(host);
}

/* BIO_ADDR_hostname_string and BIO_ADDR_service_string (addr_strings) */

static void make_ipv4_addr(BIO_ADDR *ap, unsigned short port)
{
    struct in_addr addr4;

    addr4.s_addr = htonl(INADDR_LOOPBACK);
    BIO_ADDR_rawmake(ap, AF_INET, &addr4, sizeof(addr4), htons(port));
}

static void test_hostname_string_sock_init_fail(void **state)
{
    BIO_ADDR ap;

    (void)state;
    make_ipv4_addr(&ap, 80);

    expect_sock_init(0);
    assert_null(BIO_ADDR_hostname_string(&ap, 1));
}

static void test_service_string_sock_init_fail(void **state)
{
    BIO_ADDR ap;

    (void)state;
    make_ipv4_addr(&ap, 443);

    expect_sock_init(0);
    assert_null(BIO_ADDR_service_string(&ap, 1));
}

#ifdef AI_PASSIVE
static void test_hostname_string_getnameinfo_fail(void **state)
{
    BIO_ADDR ap;

    (void)state;
    make_ipv4_addr(&ap, 80);

    expect_sock_init(1);
    expect_getnameinfo(BIO_ADDR_sockaddr(&ap),
        BIO_ADDR_sockaddr_size(&ap),
        NI_NUMERICHOST | NI_NUMERICSERV,
        EAI_AGAIN, NULL, NULL);
    assert_null(BIO_ADDR_hostname_string(&ap, 1));
}

static void test_hostname_string_numeric(void **state)
{
    BIO_ADDR ap;
    char *result;

    (void)state;
    make_ipv4_addr(&ap, 80);

    expect_sock_init(1);
    expect_getnameinfo(BIO_ADDR_sockaddr(&ap),
        BIO_ADDR_sockaddr_size(&ap),
        NI_NUMERICHOST | NI_NUMERICSERV,
        0, "127.0.0.1", "80");
    result = BIO_ADDR_hostname_string(&ap, 1);
    assert_non_null(result);
    assert_string_equal(result, "127.0.0.1");
    OPENSSL_free(result);
}

static void test_hostname_string_non_numeric(void **state)
{
    BIO_ADDR ap;
    char *result;

    (void)state;
    make_ipv4_addr(&ap, 80);

    expect_sock_init(1);
    expect_getnameinfo(BIO_ADDR_sockaddr(&ap),
        BIO_ADDR_sockaddr_size(&ap),
        0, /* flags = 0 for non-numeric lookup */
        0, "localhost", "http");
    result = BIO_ADDR_hostname_string(&ap, 0);
    assert_non_null(result);
    assert_string_equal(result, "localhost");
    OPENSSL_free(result);
}

static void test_service_string_numeric(void **state)
{
    BIO_ADDR ap;
    char *result;

    (void)state;
    make_ipv4_addr(&ap, 443);

    expect_sock_init(1);
    expect_getnameinfo(BIO_ADDR_sockaddr(&ap),
        BIO_ADDR_sockaddr_size(&ap),
        NI_NUMERICHOST | NI_NUMERICSERV,
        0, "127.0.0.1", "443");
    result = BIO_ADDR_service_string(&ap, 1);
    assert_non_null(result);
    assert_string_equal(result, "443");
    OPENSSL_free(result);
}
#else

/* inet_ntoa path: no getnameinfo, result is deterministic from the address */
static void test_hostname_string_fallback(void **state)
{
    BIO_ADDR ap;
    char *result;

    (void)state;
    make_ipv4_addr(&ap, 80);

    expect_sock_init(1);
    result = BIO_ADDR_hostname_string(&ap, 1);
    assert_non_null(result);
    assert_string_equal(result, "127.0.0.1");
    OPENSSL_free(result);
}

static void test_service_string_fallback(void **state)
{
    BIO_ADDR ap;
    char *result;

    (void)state;
    make_ipv4_addr(&ap, 443);

    expect_sock_init(1);
    result = BIO_ADDR_service_string(&ap, 1);
    assert_non_null(result);
    assert_string_equal(result, "443");
    OPENSSL_free(result);
}

#endif /* AI_PASSIVE */

/* main */

#define ADDR_TEST(name) cmocka_unit_test(name)

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* BIO_ADDR_clear */
        ADDR_TEST(test_addr_clear),
        /* BIO_ADDR_make */
        ADDR_TEST(test_addr_make_ipv4),
#if OPENSSL_USE_IPV6
        ADDR_TEST(test_addr_make_ipv6),
#endif
#ifndef OPENSSL_NO_UNIX_SOCK
        ADDR_TEST(test_addr_make_unix),
#endif
        ADDR_TEST(test_addr_make_unknown_family),
        /* BIO_ADDR_rawmake */
        ADDR_TEST(test_rawmake_ipv4),
        ADDR_TEST(test_rawmake_ipv4_wrong_len),
#if OPENSSL_USE_IPV6
        ADDR_TEST(test_rawmake_ipv6),
#endif
#ifndef OPENSSL_NO_UNIX_SOCK
        ADDR_TEST(test_rawmake_unix),
        ADDR_TEST(test_rawmake_unix_too_long),
#endif
        ADDR_TEST(test_rawmake_unknown_family),
        /* BIO_ADDR_family */
        ADDR_TEST(test_addr_family),
        /* BIO_ADDR_rawport */
        ADDR_TEST(test_rawport_ipv4),
#if OPENSSL_USE_IPV6
        ADDR_TEST(test_rawport_ipv6),
#endif
        ADDR_TEST(test_rawport_no_port),
        /* BIO_ADDR_sockaddr / BIO_ADDR_sockaddr_noconst */
        ADDR_TEST(test_sockaddr_pointers),
        /* BIO_ADDR_sockaddr_size */
        ADDR_TEST(test_sockaddr_size_ipv4),
#if OPENSSL_USE_IPV6
        ADDR_TEST(test_sockaddr_size_ipv6),
#endif
#ifndef OPENSSL_NO_UNIX_SOCK
        ADDR_TEST(test_sockaddr_size_unix),
#endif
        ADDR_TEST(test_sockaddr_size_default),
        /* BIO_ADDR_rawaddress */
        ADDR_TEST(test_rawaddress_unset),
        ADDR_TEST(test_rawaddress_ipv4),
        ADDR_TEST(test_rawaddress_ipv4_len_only),
        ADDR_TEST(test_rawaddress_ipv4_ptr_only),
#ifndef OPENSSL_NO_UNIX_SOCK
        ADDR_TEST(test_rawaddress_unix),
#endif
        /* BIO_ADDR_copy */
        ADDR_TEST(test_addr_copy_null),
        ADDR_TEST(test_addr_copy_unspec),
        ADDR_TEST(test_addr_copy_ipv4),
        /* BIO_ADDR_new and BIO_ADDR_free */
        ADDR_TEST(test_addr_new_sets_unspec),
        /* BIO_ADDR_dup */
        ADDR_TEST(test_addr_dup_null),
        ADDR_TEST(test_addr_dup_ipv4),
    /* BIO_ADDR_path_string */
#ifndef OPENSSL_NO_UNIX_SOCK
        ADDR_TEST(test_path_string_unix),
#endif
        ADDR_TEST(test_path_string_non_unix),
        /* BIO_ADDRINFO accessors */
        ADDR_TEST(test_addrinfo_next_null),
        ADDR_TEST(test_addrinfo_next),
        ADDR_TEST(test_addrinfo_family),
        ADDR_TEST(test_addrinfo_socktype),
        ADDR_TEST(test_addrinfo_protocol_null),
        ADDR_TEST(test_addrinfo_protocol_explicit),
        ADDR_TEST(test_addrinfo_protocol_stream),
        ADDR_TEST(test_addrinfo_protocol_dgram),
#ifndef OPENSSL_NO_UNIX_SOCK
        ADDR_TEST(test_addrinfo_protocol_unix),
#endif
        ADDR_TEST(test_addrinfo_sockaddr_size),
        ADDR_TEST(test_addrinfo_sockaddr),
        ADDR_TEST(test_addrinfo_address),
        /* BIO_ADDRINFO_free */
        ADDR_TEST(test_addrinfo_free_null),
#ifdef AI_PASSIVE
        ADDR_TEST(test_addrinfo_free_ip),
#endif
        /* BIO_parse_hostserv */
        ADDR_TEST(test_parse_host_and_service),
        ADDR_TEST(test_parse_empty_host),
        ADDR_TEST(test_parse_star_host),
        ADDR_TEST(test_parse_empty_service),
        ADDR_TEST(test_parse_star_service),
        ADDR_TEST(test_parse_no_colon_host_prio),
        ADDR_TEST(test_parse_no_colon_serv_prio),
        ADDR_TEST(test_parse_bracket_host_and_service),
        ADDR_TEST(test_parse_bracket_no_service),
        ADDR_TEST(test_parse_bracket_unclosed),
        ADDR_TEST(test_parse_bracket_bad_suffix),
        ADDR_TEST(test_parse_bracket_service_with_colon),
        ADDR_TEST(test_parse_ambiguous),
        ADDR_TEST(test_parse_null_host_param),
        ADDR_TEST(test_parse_null_service_param),
        /* BIO_ADDR_hostname_string / BIO_ADDR_service_string */
        ADDR_TEST(test_hostname_string_sock_init_fail),
        ADDR_TEST(test_service_string_sock_init_fail),
#ifdef AI_PASSIVE
        ADDR_TEST(test_hostname_string_getnameinfo_fail),
        ADDR_TEST(test_hostname_string_numeric),
        ADDR_TEST(test_hostname_string_non_numeric),
        ADDR_TEST(test_service_string_numeric),
#else
        ADDR_TEST(test_hostname_string_fallback),
        ADDR_TEST(test_service_string_fallback),
#endif
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif /* OPENSSL_NO_SOCK */
