/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include "testutil.h"

/* UTF-8 for "Österreich" */
static const char utf8_o_umlaut[] = "\xC3\x96sterreich";

static X509_NAME *make_utf8_name(void)
{
    X509_NAME *nm = X509_NAME_new();

    if (nm == NULL)
        return NULL;
    if (!X509_NAME_add_entry_by_NID(nm, NID_countryName, MBSTRING_ASC,
                                    (unsigned char *)"AT", -1, -1, 0)
        || !X509_NAME_add_entry_by_NID(nm, NID_organizationName,
                                      V_ASN1_UTF8STRING,
                                      (unsigned char *)utf8_o_umlaut, -1,
                                      -1, 0)) {
        X509_NAME_free(nm);
        return NULL;
    }
    return nm;
}

static void restore_env(const char *name, char *saved)
{
#if defined(_WIN32)
    char buf[512];

    if (saved != NULL) {
        BIO_snprintf(buf, sizeof(buf), "%s=%s", name, saved);
        _putenv(buf);
    } else {
        BIO_snprintf(buf, sizeof(buf), "%s=", name);
        _putenv(buf);
    }
#else
    if (saved != NULL)
        setenv(name, saved, 1);
    else
        unsetenv(name);
#endif
}

static int test_oneline_escapes_non_ascii(void)
{
    X509_NAME *nm = NULL;
    char *out = NULL;
    int ret = 0;

    if (!TEST_ptr(nm = make_utf8_name())
        || !TEST_ptr(out = X509_NAME_oneline(nm, NULL, 0))
        || !TEST_ptr(strstr(out, "\\xC3\\x96"))
        || !TEST_ptr(strstr(out, "sterreich")))
        goto err;
    ret = 1;
err:
    OPENSSL_free(out);
    X509_NAME_free(nm);
    return ret;
}

static int test_oneline_for_locale_utf8(void)
{
    X509_NAME *nm = NULL;
    char *out = NULL;
    int ret = 0;
    char *saved_lc_all = NULL;
    char *saved_lc_ctype = NULL;
    char *saved_lang = NULL;
    const char *tmp;

    if ((tmp = getenv("LC_ALL")) != NULL)
        saved_lc_all = OPENSSL_strdup(tmp);
    if ((tmp = getenv("LC_CTYPE")) != NULL)
        saved_lc_ctype = OPENSSL_strdup(tmp);
    if ((tmp = getenv("LANG")) != NULL)
        saved_lang = OPENSSL_strdup(tmp);

#if defined(_WIN32)
    _putenv("LC_ALL=C.UTF-8");
    _putenv("LC_CTYPE=");
    _putenv("LANG=");
#else
    setenv("LC_ALL", "C.UTF-8", 1);
    unsetenv("LC_CTYPE");
    unsetenv("LANG");
#endif

    if (!TEST_ptr(nm = make_utf8_name())
        || !TEST_ptr(out = X509_NAME_oneline_for_locale(nm, NULL, 0))
        || !TEST_true(strstr(out, "\\xC3\\x96") == NULL)
        || !TEST_ptr(strstr(out, utf8_o_umlaut)))
        goto err;
    ret = 1;
err:
    OPENSSL_free(out);
    X509_NAME_free(nm);
    restore_env("LC_ALL", saved_lc_all);
    restore_env("LC_CTYPE", saved_lc_ctype);
    restore_env("LANG", saved_lang);
    OPENSSL_free(saved_lc_all);
    OPENSSL_free(saved_lc_ctype);
    OPENSSL_free(saved_lang);
    return ret;
}

static int test_oneline_for_locale_c(void)
{
    X509_NAME *nm = NULL;
    char *out = NULL;
    int ret = 0;
    char *saved_lc_all = NULL;
    const char *tmp;

    if ((tmp = getenv("LC_ALL")) != NULL)
        saved_lc_all = OPENSSL_strdup(tmp);

#if defined(_WIN32)
    _putenv("LC_ALL=C");
#else
    setenv("LC_ALL", "C", 1);
#endif

    if (!TEST_ptr(nm = make_utf8_name())
        || !TEST_ptr(out = X509_NAME_oneline_for_locale(nm, NULL, 0))
        || !TEST_ptr(strstr(out, "\\xC3\\x96")))
        goto err;
    ret = 1;
err:
    OPENSSL_free(out);
    X509_NAME_free(nm);
    restore_env("LC_ALL", saved_lc_all);
    OPENSSL_free(saved_lc_all);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_oneline_escapes_non_ascii);
    ADD_TEST(test_oneline_for_locale_utf8);
    ADD_TEST(test_oneline_for_locale_c);
    return 1;
}
