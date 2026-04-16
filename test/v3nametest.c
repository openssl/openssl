/*
 * Copyright 2012-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/e_os2.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include "internal/nelem.h"
#include "testutil.h"

static const char *const names[] = {
    "a", "b", ".", "*", "@",
    ".a", "a.", ".b", "b.", ".*", "*.", "*@", "@*", "a@", "@a", "b@", "..",
    "-example.com", "example-.com",
    "@@", "**", "*.com", "*com", "*.*.com", "*com", "com*", "*example.com",
    "*@example.com", "test@*.example.com", "example.com", "www.example.com",
    "test.www.example.com", "*.example.com", "*.www.example.com",
    "test.*.example.com", "www.*.com",
    ".www.example.com", "*www.example.com",
    "example.net", "xn--rger-koa.example.com",
    "*.xn--rger-koa.example.com", "www.xn--rger-koa.example.com",
    "*.good--example.com", "www.good--example.com",
    "*.xn--bar.com", "xn--foo.xn--bar.com",
    "a.example.com", "b.example.com",
    "postmaster@example.com", "Postmaster@example.com",
    "postmaster@EXAMPLE.COM",
    NULL
};

static const char *const exceptions[] = {
    "set CN: host: [*.example.com] matches [a.example.com]",
    "set CN: host: [*.example.com] matches [b.example.com]",
    "set CN: host: [*.example.com] matches [www.example.com]",
    "set CN: host: [*.example.com] matches [xn--rger-koa.example.com]",
    "set CN: host: [*.www.example.com] matches [test.www.example.com]",
    "set CN: host: [*.www.example.com] matches [.www.example.com]",
    "set CN: host: [*www.example.com] matches [www.example.com]",
    "set CN: host: [test.www.example.com] matches [.www.example.com]",
    "set CN: host: [*.xn--rger-koa.example.com] matches [www.xn--rger-koa.example.com]",
    "set CN: host: [*.xn--bar.com] matches [xn--foo.xn--bar.com]",
    "set CN: host: [*.good--example.com] matches [www.good--example.com]",
    "set CN: host-no-wildcards: [*.www.example.com] matches [.www.example.com]",
    "set CN: host-no-wildcards: [test.www.example.com] matches [.www.example.com]",
    "set emailAddress: email: [postmaster@example.com] does not match [Postmaster@example.com]",
    "set emailAddress: email: [postmaster@EXAMPLE.COM] does not match [Postmaster@example.com]",
    "set emailAddress: email: [Postmaster@example.com] does not match [postmaster@example.com]",
    "set emailAddress: email: [Postmaster@example.com] does not match [postmaster@EXAMPLE.COM]",
    "set dnsName: host: [*.example.com] matches [www.example.com]",
    "set dnsName: host: [*.example.com] matches [a.example.com]",
    "set dnsName: host: [*.example.com] matches [b.example.com]",
    "set dnsName: host: [*.example.com] matches [xn--rger-koa.example.com]",
    "set dnsName: host: [*.www.example.com] matches [test.www.example.com]",
    "set dnsName: host-no-wildcards: [*.www.example.com] matches [.www.example.com]",
    "set dnsName: host-no-wildcards: [test.www.example.com] matches [.www.example.com]",
    "set dnsName: host: [*.www.example.com] matches [.www.example.com]",
    "set dnsName: host: [*www.example.com] matches [www.example.com]",
    "set dnsName: host: [test.www.example.com] matches [.www.example.com]",
    "set dnsName: host: [*.xn--rger-koa.example.com] matches [www.xn--rger-koa.example.com]",
    "set dnsName: host: [*.xn--bar.com] matches [xn--foo.xn--bar.com]",
    "set dnsName: host: [*.good--example.com] matches [www.good--example.com]",
    "set rfc822Name: email: [postmaster@example.com] does not match [Postmaster@example.com]",
    "set rfc822Name: email: [Postmaster@example.com] does not match [postmaster@example.com]",
    "set rfc822Name: email: [Postmaster@example.com] does not match [postmaster@EXAMPLE.COM]",
    "set rfc822Name: email: [postmaster@EXAMPLE.COM] does not match [Postmaster@example.com]",
    NULL
};

static int is_exception(const char *msg)
{
    const char *const *p;

    for (p = exceptions; *p; ++p)
        if (strcmp(msg, *p) == 0)
            return 1;
    return 0;
}

static int set_cn(X509 *crt, ...)
{
    int ret = 0;
    X509_NAME *n = NULL;
    va_list ap;

    va_start(ap, crt);
    n = X509_NAME_new();
    if (n == NULL)
        goto out;

    while (1) {
        int nid;
        const char *name;

        nid = va_arg(ap, int);
        if (nid == 0)
            break;
        name = va_arg(ap, const char *);
        if (!X509_NAME_add_entry_by_NID(n, nid, MBSTRING_ASC,
                (unsigned char *)name, -1, -1, 1))
            goto out;
    }
    if (!X509_set_subject_name(crt, n))
        goto out;
    ret = 1;
out:
    X509_NAME_free(n);
    va_end(ap);
    return ret;
}

/*-
int             X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex,
                        int nid, int crit, ASN1_OCTET_STRING *data);
int             X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
*/

static int set_altname(X509 *crt, ...)
{
    int ret = 0;
    GENERAL_NAMES *gens = NULL;
    GENERAL_NAME *gen = NULL;
    ASN1_IA5STRING *ia5 = NULL;
    va_list ap;
    va_start(ap, crt);
    gens = sk_GENERAL_NAME_new_null();
    if (gens == NULL)
        goto out;
    while (1) {
        int type;
        const char *name;
        type = va_arg(ap, int);
        if (type == 0)
            break;
        name = va_arg(ap, const char *);

        gen = GENERAL_NAME_new();
        if (gen == NULL)
            goto out;
        ia5 = ASN1_IA5STRING_new();
        if (ia5 == NULL)
            goto out;
        if (!ASN1_STRING_set(ia5, name, -1))
            goto out;
        switch (type) {
        case GEN_EMAIL:
        case GEN_DNS:
            GENERAL_NAME_set0_value(gen, type, ia5);
            ia5 = NULL;
            break;
        default:
            abort();
        }
        if (!sk_GENERAL_NAME_push(gens, gen))
            goto out;
        gen = NULL;
    }
    if (!X509_add1_ext_i2d(crt, NID_subject_alt_name, gens, 0, 0))
        goto out;
    ret = 1;
out:
    ASN1_IA5STRING_free(ia5);
    GENERAL_NAME_free(gen);
    GENERAL_NAMES_free(gens);
    va_end(ap);
    return ret;
}

static int set_cn1(X509 *crt, const char *name)
{
    return set_cn(crt, NID_commonName, name, 0);
}

static int set_cn_and_email(X509 *crt, const char *name)
{
    return set_cn(crt, NID_commonName, name,
        NID_pkcs9_emailAddress, "dummy@example.com", 0);
}

static int set_cn2(X509 *crt, const char *name)
{
    return set_cn(crt, NID_commonName, "dummy value",
        NID_commonName, name, 0);
}

static int set_cn3(X509 *crt, const char *name)
{
    return set_cn(crt, NID_commonName, name,
        NID_commonName, "dummy value", 0);
}

static int set_email1(X509 *crt, const char *name)
{
    return set_cn(crt, NID_pkcs9_emailAddress, name, 0);
}

static int set_email2(X509 *crt, const char *name)
{
    return set_cn(crt, NID_pkcs9_emailAddress, "dummy@example.com",
        NID_pkcs9_emailAddress, name, 0);
}

static int set_email3(X509 *crt, const char *name)
{
    return set_cn(crt, NID_pkcs9_emailAddress, name,
        NID_pkcs9_emailAddress, "dummy@example.com", 0);
}

static int set_email_and_cn(X509 *crt, const char *name)
{
    return set_cn(crt, NID_pkcs9_emailAddress, name,
        NID_commonName, "www.example.org", 0);
}

static int set_altname_dns(X509 *crt, const char *name)
{
    return set_altname(crt, GEN_DNS, name, 0);
}

static int set_altname_email(X509 *crt, const char *name)
{
    return set_altname(crt, GEN_EMAIL, name, 0);
}

struct set_name_fn {
    int (*fn)(X509 *, const char *);
    const char *name;
    int host;
    int email;
};

static const struct set_name_fn name_fns[] = {
    { set_cn1, "set CN", 1, 0 },
    { set_cn2, "set CN", 1, 0 },
    { set_cn3, "set CN", 1, 0 },
    { set_cn_and_email, "set CN", 1, 0 },
    { set_email1, "set emailAddress", 0, 1 },
    { set_email2, "set emailAddress", 0, 1 },
    { set_email3, "set emailAddress", 0, 1 },
    { set_email_and_cn, "set emailAddress", 0, 1 },
    { set_altname_dns, "set dnsName", 1, 0 },
    { set_altname_email, "set rfc822Name", 0, 1 },
};

static X509 *make_cert(void)
{
    X509 *crt = NULL;

    if (!TEST_ptr(crt = X509_new()))
        return NULL;
    if (!TEST_true(X509_set_version(crt, X509_VERSION_3))) {
        X509_free(crt);
        return NULL;
    }
    return crt;
}

static int check_message(const struct set_name_fn *fn, const char *op,
    const char *nameincert, int match, const char *name)
{
    char msg[1024];

    if (match < 0)
        return 1;
    BIO_snprintf(msg, sizeof(msg), "%s: %s: [%s] %s [%s]",
        fn->name, op, nameincert,
        match ? "matches" : "does not match", name);
    if (is_exception(msg))
        return 1;
    TEST_error("%s", msg);
    return 0;
}

static int run_cert(X509 *crt, const char *nameincert,
    const struct set_name_fn *fn)
{
    const char *const *pname = names;
    int failed = 0;

    for (; *pname != NULL; ++pname) {
        int samename = OPENSSL_strcasecmp(nameincert, *pname) == 0;
        size_t namelen = strlen(*pname);
        char *name = OPENSSL_malloc(namelen + 1);
        int match, ret;

        if (!TEST_ptr(name))
            return 0;
        memcpy(name, *pname, namelen + 1);

        match = -1;
        if (!TEST_int_ge(ret = X509_check_host(crt, name, namelen, 0, NULL),
                0)) {
            failed = 1;
        } else if (fn->host) {
            if (ret == 1 && !samename)
                match = 1;
            if (ret == 0 && samename)
                match = 0;
        } else if (ret == 1)
            match = 1;
        if (!TEST_true(check_message(fn, "host", nameincert, match, *pname)))
            failed = 1;

        match = -1;
        if (!TEST_int_ge(ret = X509_check_host(crt, name, namelen,
                             X509_CHECK_FLAG_NO_WILDCARDS,
                             NULL),
                0)) {
            failed = 1;
        } else if (fn->host) {
            if (ret == 1 && !samename)
                match = 1;
            if (ret == 0 && samename)
                match = 0;
        } else if (ret == 1)
            match = 1;
        if (!TEST_true(check_message(fn, "host-no-wildcards",
                nameincert, match, *pname)))
            failed = 1;

        match = -1;
        ret = X509_check_email(crt, name, namelen, 0);
        if (fn->email) {
            if (ret && !samename)
                match = 1;
            if (!ret && samename && strchr(nameincert, '@') != NULL)
                match = 0;
        } else if (ret)
            match = 1;
        if (!TEST_true(check_message(fn, "email", nameincert, match, *pname)))
            failed = 1;
        OPENSSL_free(name);
    }

    return failed == 0;
}

static int call_run_cert(int i)
{
    int failed = 0;
    const struct set_name_fn *pfn = &name_fns[i];
    X509 *crt;
    const char *const *pname;

    TEST_info("%s", pfn->name);
    for (pname = names; *pname != NULL; pname++) {
        if (!TEST_ptr(crt = make_cert())
            || !TEST_true(pfn->fn(crt, *pname))
            || !run_cert(crt, *pname, pfn))
            failed = 1;
        X509_free(crt);
    }
    return failed == 0;
}

static struct gennamedata {
    const unsigned char der[22];
    size_t derlen;
} gennames[] = {
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     SEQUENCE {}
       *   }
       * }
       */
        {
            0xa0, 0x13, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x02, 0x30, 0x00 },
        21 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     [APPLICATION 0] {}
       *   }
       * }
       */
        {
            0xa0, 0x13, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x02, 0x60, 0x00 },
        21 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa0, 0x14, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x03, 0x0c, 0x01, 0x61 },
        22 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.2 }
       *   [0] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa0, 0x14, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x02, 0xa0, 0x03, 0x0c, 0x01, 0x61 },
        22 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     UTF8String { "b" }
       *   }
       * }
       */
        {
            0xa0, 0x14, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x03, 0x0c, 0x01, 0x62 },
        22 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     BOOLEAN { TRUE }
       *   }
       * }
       */
        {
            0xa0, 0x14, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x03, 0x01, 0x01, 0xff },
        22 },
    { /*
       * [0] {
       *   OBJECT_IDENTIFIER { 1.2.840.113554.4.1.72585.2.1 }
       *   [0] {
       *     BOOLEAN { FALSE }
       *   }
       * }
       */
        {
            0xa0, 0x14, 0x06, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04,
            0x01, 0x84, 0xb7, 0x09, 0x02, 0x01, 0xa0, 0x03, 0x01, 0x01, 0x00 },
        22 },
    { /* [1 PRIMITIVE] { "a" } */
        {
            0x81, 0x01, 0x61 },
        3 },
    { /* [1 PRIMITIVE] { "b" } */
        {
            0x81, 0x01, 0x62 },
        3 },
    { /* [2 PRIMITIVE] { "a" } */
        {
            0x82, 0x01, 0x61 },
        3 },
    { /* [2 PRIMITIVE] { "b" } */
        {
            0x82, 0x01, 0x62 },
        3 },
    { /*
       * [4] {
       *   SEQUENCE {
       *     SET {
       *       SEQUENCE {
       *         # commonName
       *         OBJECT_IDENTIFIER { 2.5.4.3 }
       *         UTF8String { "a" }
       *       }
       *     }
       *   }
       * }
       */
        {
            0xa4, 0x0e, 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55,
            0x04, 0x03, 0x0c, 0x01, 0x61 },
        16 },
    { /*
       * [4] {
       *   SEQUENCE {
       *     SET {
       *       SEQUENCE {
       *         # commonName
       *         OBJECT_IDENTIFIER { 2.5.4.3 }
       *         UTF8String { "b" }
       *       }
       *     }
       *   }
       * }
       */
        {
            0xa4, 0x0e, 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55,
            0x04, 0x03, 0x0c, 0x01, 0x62 },
        16 },
    { /*
       * [5] {
       *   [1] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa5, 0x05, 0xa1, 0x03, 0x0c, 0x01, 0x61 },
        7 },
    { /*
       * [5] {
       *   [1] {
       *     UTF8String { "b" }
       *   }
       * }
       */
        {
            0xa5, 0x05, 0xa1, 0x03, 0x0c, 0x01, 0x62 },
        7 },
    { /*
       * [5] {
       *   [0] {
       *     UTF8String {}
       *   }
       *   [1] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa5, 0x09, 0xa0, 0x02, 0x0c, 0x00, 0xa1, 0x03, 0x0c, 0x01, 0x61 },
        11 },
    { /*
       * [5] {
       *   [0] {
       *     UTF8String { "a" }
       *   }
       *   [1] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa5, 0x0a, 0xa0, 0x03, 0x0c, 0x01, 0x61, 0xa1, 0x03, 0x0c, 0x01,
            0x61 },
        12 },
    { /*
       * [5] {
       *   [0] {
       *     UTF8String { "b" }
       *   }
       *   [1] {
       *     UTF8String { "a" }
       *   }
       * }
       */
        {
            0xa5, 0x0a, 0xa0, 0x03, 0x0c, 0x01, 0x62, 0xa1, 0x03, 0x0c, 0x01,
            0x61 },
        12 },
    { /* [6 PRIMITIVE] { "a" } */
        {
            0x86, 0x01, 0x61 },
        3 },
    { /* [6 PRIMITIVE] { "b" } */
        {
            0x86, 0x01, 0x62 },
        3 },
    { /* [7 PRIMITIVE] { `11111111` } */
        {
            0x87, 0x04, 0x11, 0x11, 0x11, 0x11 },
        6 },
    { /* [7 PRIMITIVE] { `22222222`} */
        {
            0x87, 0x04, 0x22, 0x22, 0x22, 0x22 },
        6 },
    { /* [7 PRIMITIVE] { `11111111111111111111111111111111` } */
        {
            0x87, 0x10, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 },
        18 },
    { /* [7 PRIMITIVE] { `22222222222222222222222222222222` } */
        {
            0x87, 0x10, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 },
        18 },
    { /* [8 PRIMITIVE] { 1.2.840.113554.4.1.72585.2.1 } */
        {
            0x88, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04, 0x01, 0x84,
            0xb7, 0x09, 0x02, 0x01 },
        15 },
    { /* [8 PRIMITIVE] { 1.2.840.113554.4.1.72585.2.2 } */
        {
            0x88, 0x0d, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04, 0x01, 0x84,
            0xb7, 0x09, 0x02, 0x02 },
        15 },
    { /*
       * Regression test for CVE-2023-0286.
       */
        {
            0xa3, 0x00 },
        2 }
};

static int test_GENERAL_NAME_cmp(void)
{
    size_t i, j;
    GENERAL_NAME **namesa = OPENSSL_malloc(sizeof(*namesa)
        * OSSL_NELEM(gennames));
    GENERAL_NAME **namesb = OPENSSL_malloc(sizeof(*namesb)
        * OSSL_NELEM(gennames));
    int testresult = 0;

    if (!TEST_ptr(namesa) || !TEST_ptr(namesb))
        goto end;

    for (i = 0; i < OSSL_NELEM(gennames); i++) {
        const unsigned char *derp = gennames[i].der;

        /*
         * We create two versions of each GENERAL_NAME so that we ensure when
         * we compare them they are always different pointers.
         */
        namesa[i] = d2i_GENERAL_NAME(NULL, &derp, (long)gennames[i].derlen);
        derp = gennames[i].der;
        namesb[i] = d2i_GENERAL_NAME(NULL, &derp, (long)gennames[i].derlen);
        if (!TEST_ptr(namesa[i]) || !TEST_ptr(namesb[i]))
            goto end;
    }

    /* Every name should be equal to itself and not equal to any others. */
    for (i = 0; i < OSSL_NELEM(gennames); i++) {
        for (j = 0; j < OSSL_NELEM(gennames); j++) {
            if (i == j) {
                if (!TEST_int_eq(GENERAL_NAME_cmp(namesa[i], namesb[j]), 0))
                    goto end;
            } else {
                if (!TEST_int_ne(GENERAL_NAME_cmp(namesa[i], namesb[j]), 0))
                    goto end;
            }
        }
    }
    testresult = 1;

end:
    for (i = 0; i < OSSL_NELEM(gennames); i++) {
        if (namesa != NULL)
            GENERAL_NAME_free(namesa[i]);
        if (namesb != NULL)
            GENERAL_NAME_free(namesb[i]);
    }
    OPENSSL_free(namesa);
    OPENSSL_free(namesb);

    return testresult;
}

/*
 * =============================================================
 * Additional coverage for crypto/x509/v3_genn.c
 * =============================================================
 */

/*
 * Test: GENERAL_NAME_cmp with NULL arguments.
 * Covers paths GNC-1 and GNC-2 (lines 97-98 of v3_genn.c).
 */
static int test_GENERAL_NAME_cmp_null(void)
{
    GENERAL_NAME *a = NULL;
    const unsigned char *p = gennames[7].der; /* [1 PRIMITIVE] "a" = GEN_EMAIL */
    int testresult = 0;

    a = d2i_GENERAL_NAME(NULL, &p, gennames[7].derlen);
    if (!TEST_ptr(a))
        goto end;

    if (!TEST_int_eq(GENERAL_NAME_cmp(NULL, a), -1))
        goto end;
    if (!TEST_int_eq(GENERAL_NAME_cmp(a, NULL), -1))
        goto end;
    if (!TEST_int_eq(GENERAL_NAME_cmp(NULL, NULL), -1))
        goto end;

    testresult = 1;
 end:
    GENERAL_NAME_free(a);
    return testresult;
}

/*
 * Test: GENERAL_NAME_cmp for GEN_X400 names.
 * Covers paths GNC-3 and GNC-4 (lines 100-102 of v3_genn.c).
 * [3 CONSTRUCTED] is the implicit tag for x400Address in GENERAL_NAME CHOICE.
 */
static int test_GENERAL_NAME_cmp_x400(void)
{
    /* [3 CONSTRUCTED] { } — empty ORAddress */
    static const unsigned char x400_a_der[] = {0xa3, 0x00};
    /* [3 CONSTRUCTED] { OCTET_STRING {} } — non-empty ORAddress */
    static const unsigned char x400_b_der[] = {0xa3, 0x02, 0x04, 0x00};

    GENERAL_NAME *a = NULL, *a2 = NULL, *b = NULL;
    const unsigned char *p;
    int testresult = 0;

    p = x400_a_der;
    a = d2i_GENERAL_NAME(NULL, &p, sizeof(x400_a_der));
    if (!TEST_ptr(a) || !TEST_int_eq(a->type, GEN_X400))
        goto end;

    p = x400_a_der;
    a2 = d2i_GENERAL_NAME(NULL, &p, sizeof(x400_a_der));
    if (!TEST_ptr(a2))
        goto end;

    p = x400_b_der;
    b = d2i_GENERAL_NAME(NULL, &p, sizeof(x400_b_der));
    if (!TEST_ptr(b) || !TEST_int_eq(b->type, GEN_X400))
        goto end;

    /* Equal x400 names */
    if (!TEST_int_eq(GENERAL_NAME_cmp(a, a2), 0))
        goto end;

    /* Different x400 names */
    if (!TEST_int_ne(GENERAL_NAME_cmp(a, b), 0))
        goto end;

    testresult = 1;
 end:
    GENERAL_NAME_free(a);
    GENERAL_NAME_free(a2);
    GENERAL_NAME_free(b);
    return testresult;
}

/*
 * Test: GENERAL_NAME_set0_value / GENERAL_NAME_get0_value for GEN_ types
 * not exercised by existing tests (GEN_URI, GEN_DIRNAME, GEN_IPADD, GEN_RID,
 * GEN_EDIPARTY).  Also tests the ptype == NULL branch of get0_value.
 * Covers paths S0V-1..S0V-7 and G0V-1..G0V-8 of v3_genn.c.
 */
static int test_GENERAL_NAME_set0_get0_value(void)
{
    GENERAL_NAME *gn = NULL;
    ASN1_IA5STRING *ia5 = NULL;
    X509_NAME *dirn = NULL;
    ASN1_OCTET_STRING *ip = NULL;
    ASN1_OBJECT *rid = NULL;
    EDIPARTYNAME *edi = NULL;
    static const unsigned char ip_bytes[4] = {192, 168, 1, 1};
    int ptype;
    void *pval;
    int testresult = 0;

    /* --- GEN_URI --- */
    gn = GENERAL_NAME_new();
    ia5 = ASN1_IA5STRING_new();
    if (!TEST_ptr(gn) || !TEST_ptr(ia5))
        goto end;
    if (!TEST_true(ASN1_STRING_set(ia5, "https://example.com", -1)))
        goto end;
    GENERAL_NAME_set0_value(gn, GEN_URI, ia5);
    ia5 = NULL; /* owned by gn */

    pval = GENERAL_NAME_get0_value(gn, &ptype);
    if (!TEST_int_eq(ptype, GEN_URI) || !TEST_ptr(pval))
        goto end;
    /* ptype == NULL must not crash and must return the same value pointer */
    if (!TEST_ptr_eq(GENERAL_NAME_get0_value(gn, NULL), pval))
        goto end;

    GENERAL_NAME_free(gn);
    gn = NULL;

    /* --- GEN_DIRNAME --- */
    gn = GENERAL_NAME_new();
    dirn = X509_NAME_new();
    if (!TEST_ptr(gn) || !TEST_ptr(dirn))
        goto end;
    if (!TEST_true(X509_NAME_add_entry_by_txt(dirn, "CN", MBSTRING_ASC,
                                              (unsigned char *)"test", -1,
                                              -1, 0)))
        goto end;
    GENERAL_NAME_set0_value(gn, GEN_DIRNAME, dirn);
    dirn = NULL; /* owned by gn */

    pval = GENERAL_NAME_get0_value(gn, &ptype);
    if (!TEST_int_eq(ptype, GEN_DIRNAME) || !TEST_ptr(pval))
        goto end;

    GENERAL_NAME_free(gn);
    gn = NULL;

    /* --- GEN_IPADD --- */
    gn = GENERAL_NAME_new();
    ip = ASN1_OCTET_STRING_new();
    if (!TEST_ptr(gn) || !TEST_ptr(ip))
        goto end;
    if (!TEST_true(ASN1_STRING_set(ip, ip_bytes, sizeof(ip_bytes))))
        goto end;
    GENERAL_NAME_set0_value(gn, GEN_IPADD, ip);
    ip = NULL; /* owned by gn */

    pval = GENERAL_NAME_get0_value(gn, &ptype);
    if (!TEST_int_eq(ptype, GEN_IPADD) || !TEST_ptr(pval))
        goto end;

    GENERAL_NAME_free(gn);
    gn = NULL;

    /* --- GEN_RID --- */
    gn = GENERAL_NAME_new();
    rid = OBJ_txt2obj("1.2.3.4.5", 1);
    if (!TEST_ptr(gn) || !TEST_ptr(rid))
        goto end;
    GENERAL_NAME_set0_value(gn, GEN_RID, rid);
    rid = NULL; /* owned by gn */

    pval = GENERAL_NAME_get0_value(gn, &ptype);
    if (!TEST_int_eq(ptype, GEN_RID) || !TEST_ptr(pval))
        goto end;

    GENERAL_NAME_free(gn);
    gn = NULL;

    /* --- GEN_EDIPARTY (with a valid partyName) --- */
    gn = GENERAL_NAME_new();
    edi = EDIPARTYNAME_new();
    if (!TEST_ptr(gn) || !TEST_ptr(edi))
        goto end;
    edi->partyName = ASN1_STRING_type_new(V_ASN1_UTF8STRING);
    if (!TEST_ptr(edi->partyName))
        goto end;
    if (!TEST_true(ASN1_STRING_set(edi->partyName, "TestParty", -1)))
        goto end;
    GENERAL_NAME_set0_value(gn, GEN_EDIPARTY, edi);
    edi = NULL; /* owned by gn */

    pval = GENERAL_NAME_get0_value(gn, &ptype);
    if (!TEST_int_eq(ptype, GEN_EDIPARTY) || !TEST_ptr(pval))
        goto end;

    GENERAL_NAME_free(gn);
    gn = NULL;

    testresult = 1;
 end:
    GENERAL_NAME_free(gn);
    ASN1_IA5STRING_free(ia5);
    X509_NAME_free(dirn);
    ASN1_OCTET_STRING_free(ip);
    ASN1_OBJECT_free(rid);
    EDIPARTYNAME_free(edi);
    return testresult;
}

/*
 * Test: GENERAL_NAME_dup creates an independent deep copy (path DUP-1).
 * Verifies that the copy compares equal to the original and that internal
 * data pointers differ (deep copy, not shallow).
 */
static int test_GENERAL_NAME_dup_copy(void)
{
    GENERAL_NAME *orig = NULL, *copy = NULL;
    ASN1_IA5STRING *ia5 = NULL;
    int orig_type = -1, copy_type = -1;
    void *orig_val, *copy_val;
    int testresult = 0;

    orig = GENERAL_NAME_new();
    ia5  = ASN1_IA5STRING_new();
    if (!TEST_ptr(orig) || !TEST_ptr(ia5))
        goto end;
    if (!TEST_true(ASN1_STRING_set(ia5, "test.example.com", -1)))
        goto end;
    GENERAL_NAME_set0_value(orig, GEN_DNS, ia5);
    ia5 = NULL; /* owned by orig */

    copy = GENERAL_NAME_dup(orig);
    if (!TEST_ptr(copy))
        goto end;

    /* Dup must compare equal to original */
    if (!TEST_int_eq(GENERAL_NAME_cmp(orig, copy), 0))
        goto end;

    /* Dup must be a deep copy — internal data pointers must differ */
    orig_val = GENERAL_NAME_get0_value(orig, &orig_type);
    copy_val = GENERAL_NAME_get0_value(copy, &copy_type);
    if (!TEST_int_eq(orig_type, copy_type))
        goto end;
    if (!TEST_ptr_ne(orig_val, copy_val))
        goto end;

    testresult = 1;
 end:
    GENERAL_NAME_free(orig);
    GENERAL_NAME_free(copy);
    ASN1_IA5STRING_free(ia5);
    return testresult;
}

/*
 * Test: GENERAL_NAME_set0_othername / GENERAL_NAME_get0_otherName round-trip,
 * plus the wrong-type early-return path.
 * Covers paths SOO-2, GOO-1, GOO-2, GOO-3, GOO-4 of v3_genn.c.
 */
static int test_GENERAL_NAME_othername(void)
{
    GENERAL_NAME *gn = NULL, *gn_email = NULL;
    ASN1_OBJECT *oid = NULL, *ret_oid = NULL;
    ASN1_TYPE *val = NULL, *ret_val = NULL;
    ASN1_IA5STRING *ia5 = NULL;
    int testresult = 0;

    oid = OBJ_txt2obj("1.2.840.113549.1.9.1", 1);
    val = ASN1_TYPE_new();
    if (!TEST_ptr(oid) || !TEST_ptr(val))
        goto end;
    ASN1_TYPE_set(val, V_ASN1_NULL, NULL);

    gn = GENERAL_NAME_new();
    if (!TEST_ptr(gn))
        goto end;

    /* set0_othername: success path (SOO-2) */
    if (!TEST_true(GENERAL_NAME_set0_othername(gn, oid, val)))
        goto end;
    oid = NULL; /* ownership transferred */
    val = NULL;

    /* get0_otherName: both poid and pvalue non-NULL (GOO-2) */
    if (!TEST_true(GENERAL_NAME_get0_otherName(gn, &ret_oid, &ret_val)))
        goto end;
    if (!TEST_ptr(ret_oid) || !TEST_ptr(ret_val))
        goto end;

    /* get0_otherName: poid == NULL (GOO-3) */
    ret_val = NULL;
    if (!TEST_true(GENERAL_NAME_get0_otherName(gn, NULL, &ret_val)))
        goto end;
    if (!TEST_ptr(ret_val))
        goto end;

    /* get0_otherName: pvalue == NULL (GOO-4) */
    ret_oid = NULL;
    if (!TEST_true(GENERAL_NAME_get0_otherName(gn, &ret_oid, NULL)))
        goto end;
    if (!TEST_ptr(ret_oid))
        goto end;

    /* get0_otherName: wrong type returns 0 (GOO-1) */
    gn_email = GENERAL_NAME_new();
    ia5 = ASN1_IA5STRING_new();
    if (!TEST_ptr(gn_email) || !TEST_ptr(ia5))
        goto end;
    if (!TEST_true(ASN1_STRING_set(ia5, "user@example.com", -1)))
        goto end;
    GENERAL_NAME_set0_value(gn_email, GEN_EMAIL, ia5);
    ia5 = NULL;
    if (!TEST_false(GENERAL_NAME_get0_otherName(gn_email, &ret_oid, &ret_val)))
        goto end;

    testresult = 1;
 end:
    GENERAL_NAME_free(gn);
    GENERAL_NAME_free(gn_email);
    ASN1_OBJECT_free(oid);
    ASN1_TYPE_free(val);
    ASN1_IA5STRING_free(ia5);
    return testresult;
}

/*
 * Test: OTHERNAME_cmp with NULL arguments (paths OC-1, OC-2).
 * The function explicitly handles NULL with an early return of -1.
 */
static int test_OTHERNAME_cmp_null(void)
{
    GENERAL_NAME *gn = NULL;
    const unsigned char *p = gennames[0].der; /* GEN_OTHERNAME entry */
    int testresult = 0;

    gn = d2i_GENERAL_NAME(NULL, &p, gennames[0].derlen);
    if (!TEST_ptr(gn) || !TEST_int_eq(gn->type, GEN_OTHERNAME))
        goto end;

    if (!TEST_int_eq(OTHERNAME_cmp(NULL, gn->d.otherName), -1))
        goto end;
    if (!TEST_int_eq(OTHERNAME_cmp(gn->d.otherName, NULL), -1))
        goto end;
    if (!TEST_int_eq(OTHERNAME_cmp(NULL, NULL), -1))
        goto end;

    testresult = 1;
 end:
    GENERAL_NAME_free(gn);
    return testresult;
}

/*
 * Test: edipartyname_cmp with NULL d.ediPartyName pointer (paths EPC-1/EPC-2),
 * and with two fresh EDIPARTYNAME_new() structs whose partyNames are equal
 * empty strings (covering the partyName comparison path).
 *
 * Note: EDIPARTYNAME_new() initialises partyName to a non-NULL empty
 * DIRECTORYSTRING (mandatory field).  Therefore the defensive check at
 * v3_genn.c line 86 (a->partyName == NULL || b->partyName == NULL) cannot
 * be reached through contract-safe API usage — it is classified as
 * unreachable_path (blocked by EDIPARTYNAME_new() invariant).
 */
static int test_edipartyname_cmp_null_partyname(void)
{
    GENERAL_NAME *a = NULL, *b = NULL;
    GENERAL_NAME *c = NULL, *d = NULL;
    EDIPARTYNAME *edi_a = NULL, *edi_b = NULL;
    int testresult = 0;

    /* Case 1: d.ediPartyName pointer itself is NULL in both names. */
    a = GENERAL_NAME_new();
    b = GENERAL_NAME_new();
    if (!TEST_ptr(a) || !TEST_ptr(b))
        goto end;
    GENERAL_NAME_set0_value(a, GEN_EDIPARTY, NULL);
    GENERAL_NAME_set0_value(b, GEN_EDIPARTY, NULL);
    /* edipartyname_cmp(NULL, NULL) → a == NULL branch → returns -1 */
    if (!TEST_int_eq(GENERAL_NAME_cmp(a, b), -1))
        goto end;
    GENERAL_NAME_free(a); a = NULL;
    GENERAL_NAME_free(b); b = NULL;

    /*
     * Case 2: Both EDIPARTYNAME structs have an empty (non-NULL) partyName —
     * the expected outcome is equality (0).  This exercises the partyName
     * comparison path in edipartyname_cmp.
     */
    c = GENERAL_NAME_new();
    d = GENERAL_NAME_new();
    edi_a = EDIPARTYNAME_new();
    edi_b = EDIPARTYNAME_new();
    if (!TEST_ptr(c) || !TEST_ptr(d) || !TEST_ptr(edi_a) || !TEST_ptr(edi_b))
        goto end;
    /* nameAssigner=NULL, partyName=non-NULL empty DIRECTORYSTRING (both) */
    GENERAL_NAME_set0_value(c, GEN_EDIPARTY, edi_a);
    GENERAL_NAME_set0_value(d, GEN_EDIPARTY, edi_b);
    edi_a = NULL; /* owned by c */
    edi_b = NULL; /* owned by d */
    if (!TEST_int_eq(GENERAL_NAME_cmp(c, d), 0))
        goto end;

    testresult = 1;
 end:
    GENERAL_NAME_free(a);
    GENERAL_NAME_free(b);
    GENERAL_NAME_free(c);
    GENERAL_NAME_free(d);
    EDIPARTYNAME_free(edi_a);
    EDIPARTYNAME_free(edi_b);
    return testresult;
}

/*
 * BUG TEST: GENERAL_NAME_cmp crashes when an OTHERNAME has a NULL type_id.
 *
 * Root cause: GENERAL_NAME_set0_othername() accepts NULL as the oid argument
 * and stores it directly into oth->type_id without validation.  When
 * GENERAL_NAME_cmp is then called on such a name it reaches OTHERNAME_cmp,
 * which unconditionally passes type_id to OBJ_cmp(); OBJ_cmp dereferences the
 * pointer and crashes with a NULL-pointer dereference.
 *
 * Suggested fix: add a NULL guard in OTHERNAME_cmp before calling OBJ_cmp:
 *     if (a->type_id == NULL || b->type_id == NULL)
 *         return -1;
 *
 * This test is EXPECTED TO CRASH / trigger undefined behaviour in an unpatched
 * build.  Once the fix is applied it should return -1 and pass.
 */
static int test_GENERAL_NAME_cmp_othername_null_typeid_crashbug(void)
{
    GENERAL_NAME *a = NULL, *b = NULL;
    ASN1_TYPE *val_a = NULL, *val_b = NULL;
    int result;
    int testresult = 0;

    a = GENERAL_NAME_new();
    b = GENERAL_NAME_new();
    val_a = ASN1_TYPE_new();
    val_b = ASN1_TYPE_new();
    if (!TEST_ptr(a) || !TEST_ptr(b) || !TEST_ptr(val_a) || !TEST_ptr(val_b))
        goto end;

    ASN1_TYPE_set(val_a, V_ASN1_NULL, NULL);
    ASN1_TYPE_set(val_b, V_ASN1_NULL, NULL);

    /*
     * Pass NULL as the OID; GENERAL_NAME_set0_othername stores it directly
     * into oth->type_id without validation.
     */
    if (!TEST_true(GENERAL_NAME_set0_othername(a, NULL, val_a)))
        goto end;
    val_a = NULL;
    if (!TEST_true(GENERAL_NAME_set0_othername(b, NULL, val_b)))
        goto end;
    val_b = NULL;

    /*
     * On an unpatched build this call reaches OTHERNAME_cmp →
     * OBJ_cmp(NULL, NULL) → NULL pointer dereference → crash.
     * After the fix OBJ_cmp(NULL, NULL) returns 0 (two absent OIDs are
     * treated as identical, consistent with OBJ_cmp's documented "0 if
     * identical" contract), and ASN1_TYPE_cmp on two equal V_ASN1_NULL
     * values also returns 0, so OTHERNAME_cmp must return 0.
     */
    result = GENERAL_NAME_cmp(a, b);
    if (!TEST_int_eq(result, 0))
        goto end;

    testresult = 1;
 end:
    GENERAL_NAME_free(a);
    GENERAL_NAME_free(b);
    ASN1_TYPE_free(val_a);
    ASN1_TYPE_free(val_b);
    return testresult;
}

/*
 * BUG TEST: GENERAL_NAME_get0_otherName crashes when d.otherName is NULL.
 *
 * Root cause: GENERAL_NAME_set0_value() accepts NULL as a value for
 * GEN_OTHERNAME (no validation), storing NULL in d.otherName.  A subsequent
 * call to GENERAL_NAME_get0_otherName() checks only gen->type but does NOT
 * check gen->d.otherName for NULL before dereferencing it at line 237/239 of
 * crypto/x509/v3_genn.c, causing a NULL-pointer dereference crash.
 *
 * Suggested fix: in GENERAL_NAME_get0_otherName(), add after the type check:
 *     if (gen->d.otherName == NULL)
 *         return 0;
 *
 * This test is EXPECTED TO CRASH in an unpatched build.  After the fix it
 * should return 0 (indicating an invalid/absent value) and pass.
 *
 * Note: in the combined test suite this test is masked by the earlier crash in
 * test_GENERAL_NAME_cmp_othername_null_typeid_crashbug.  Run it individually
 * (or after fixing BUG-1) to observe the crash.
 */
static int test_GENERAL_NAME_get0_otherName_null_deref_crashbug(void)
{
    GENERAL_NAME *gn = NULL;
    ASN1_OBJECT *oid = NULL;
    ASN1_TYPE *val = NULL;
    int testresult = 0;

    gn = GENERAL_NAME_new();
    if (!TEST_ptr(gn))
        goto end;

    /*
     * Set GEN_OTHERNAME type with NULL pointer as the otherName value.
     * GENERAL_NAME_set0_value() accepts this without error, leaving
     * gn->d.otherName == NULL.
     */
    GENERAL_NAME_set0_value(gn, GEN_OTHERNAME, NULL);
    if (!TEST_int_eq(gn->type, GEN_OTHERNAME))
        goto end;

    /*
     * On an unpatched build GENERAL_NAME_get0_otherName dereferences
     * gn->d.otherName->type_id with gn->d.otherName == NULL → SEGFAULT.
     * After the fix it should return 0 to signal an absent value.
     */
    if (!TEST_false(GENERAL_NAME_get0_otherName(gn, &oid, &val)))
        goto end;

    testresult = 1;
 end:
    GENERAL_NAME_free(gn);
    return testresult;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(call_run_cert, OSSL_NELEM(name_fns));
    ADD_TEST(test_GENERAL_NAME_cmp);
    ADD_TEST(test_GENERAL_NAME_cmp_null);
    ADD_TEST(test_GENERAL_NAME_cmp_x400);
    ADD_TEST(test_GENERAL_NAME_set0_get0_value);
    ADD_TEST(test_GENERAL_NAME_dup_copy);
    ADD_TEST(test_GENERAL_NAME_othername);
    ADD_TEST(test_OTHERNAME_cmp_null);
    ADD_TEST(test_edipartyname_cmp_null_partyname);
    ADD_TEST(test_GENERAL_NAME_cmp_othername_null_typeid_crashbug);
    ADD_TEST(test_GENERAL_NAME_get0_otherName_null_deref_crashbug);
    return 1;
}
