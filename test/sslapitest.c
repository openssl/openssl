/*
 * Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * We need access to the deprecated low level HMAC APIs for legacy purposes
 * when the deprecated calls are not hidden
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
# define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/srp.h>
#include <openssl/txt_db.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/param_build.h>
#include <openssl/x509v3.h>
#include <openssl/dh.h>
#include <openssl/engine.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"
#include "testutil/output.h"
#include "internal/nelem.h"
#include "internal/tlsgroups.h"
#include "internal/ktls.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/record/methods/recmethod_local.h"
#include "filterprov.h"

int hybrid_provider_init(const OSSL_CORE_HANDLE *handle,
                         const OSSL_DISPATCH *in,
                         const OSSL_DISPATCH **out,
                         void **provctx);

#undef OSSL_NO_USABLE_TLS1_3
#if defined(OPENSSL_NO_TLS1_3) \
    || (defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH))
/*
 * If we don't have ec or dh then there are no built-in groups that are usable
 * with TLSv1.3
 */
# define OSSL_NO_USABLE_TLS1_3
#endif

/* Defined in tls-provider.c */
int tls_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx);

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *defctxnull = NULL;
static OSSL_PROVIDER *hybridprov = NULL;

static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *cert2 = NULL;
static char *privkey2 = NULL;
static char *cert1024 = NULL;
static char *privkey1024 = NULL;
static char *cert3072 = NULL;
static char *privkey3072 = NULL;
static char *cert4096 = NULL;
static char *privkey4096 = NULL;
static char *cert8192 = NULL;
static char *privkey8192 = NULL;
static char *srpvfile = NULL;
static char *tmpfilename = NULL;
static char *dhfile = NULL;

static int is_fips = 0;

/*
 * Test TLSv1.3 Key exchange
 * Test 0 = Test all ECDHE Key exchange with TLSv1.3 client and server
 * Test 1 = Test NID_X9_62_prime256v1 with TLSv1.3 client and server
 * Test 2 = Test NID_secp384r1 with TLSv1.3 client and server
 * Test 3 = Test NID_secp521r1 with TLSv1.3 client and server
 * Test 4 = Test NID_X25519 with TLSv1.3 client and server
 * Test 5 = Test NID_X448 with TLSv1.3 client and server
 * Test 6 = Test all FFDHE Key exchange with TLSv1.3 client and server
 * Test 7 = Test NID_ffdhe2048 with TLSv1.3 client and server
 * Test 8 = Test NID_ffdhe3072 with TLSv1.3 client and server
 * Test 9 = Test NID_ffdhe4096 with TLSv1.3 client and server
 * Test 10 = Test NID_ffdhe6144 with TLSv1.3 client and server
 * Test 11 = Test NID_ffdhe8192 with TLSv1.3 client and server
 * Test 12 = Test all ML-KEM with TLSv1.3 client and server
 * Test 13 = Test MLKEM512
 * Test 14 = Test MLKEM768
 * Test 15 = Test MLKEM1024
 * Test 16 = Test X25519MLKEM768
 * Test 17 = Test SecP256r1MLKEM768
 * Test 18 = Test SecP384r1MLKEM1024
 * Test 19 = Test all ML-KEM with TLSv1.2 client and server
 * Test 20 = Test all FFDHE with TLSv1.2 client and server
 * Test 21 = Test all ECDHE with TLSv1.2 client and server
 */
static int test_key_exchange_id(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;
    int kexch_alg = NID_undef;
    int *kexch_groups = &kexch_alg;
    int kexch_groups_size = 1;
    int max_version = TLS1_3_VERSION;
    char *kexch_name0 = NULL;
    const char *kexch_names = NULL;
    int shared_group0;

    switch (idx) {
# ifndef OPENSSL_NO_ML_KEM
#  ifndef OPENSSL_NO_EC
        case 17:
            kexch_groups = NULL;
            kexch_name0 = "SecP256r1MLKEM768";
            kexch_names = kexch_name0;
            break;
#  endif
# endif
        default:
            /* We're skipping this test */
            return 1;
    }

    if (!is_fips || fips_provider_version_ge(libctx, 3, 5, 0)) {
        TEST_error("Testing against wrong FIPS provider");
        goto end;
    }

    if (is_fips /* && fips_provider_version_lt(libctx, 3, 5, 0) */
            && idx >= 12 && idx <= 19 && idx !=17)
        return TEST_skip("ML-KEM not supported in this version of fips provider");

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(), TLS1_VERSION,
                                       max_version, &sctx, &cctx, cert,
                                       privkey)))
        goto end;

    if (!TEST_true(SSL_CTX_set_ciphersuites(sctx,
                   TLS1_3_RFC_AES_128_GCM_SHA256)))
        goto end;

    if (!TEST_true(SSL_CTX_set_ciphersuites(cctx,
                   TLS1_3_RFC_AES_128_GCM_SHA256)))
        goto end;

    if (!TEST_true(SSL_CTX_set_cipher_list(sctx,
                   TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ":"
                   TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256))
            || !TEST_true(SSL_CTX_set_dh_auto(sctx, 1)))
        goto end;

    /*
     * Must include an EC ciphersuite so that we send supported groups in
     * TLSv1.2
     */
# ifndef OPENSSL_NO_TLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx,
                   TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ":"
                   TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256)))
        goto end;
# endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                             NULL, NULL)))
        goto end;

    if (kexch_groups != NULL) {
        if (!TEST_true(SSL_set1_groups(serverssl, kexch_groups, kexch_groups_size))
            || !TEST_true(SSL_set1_groups(clientssl, kexch_groups, kexch_groups_size)))
            goto end;
    } else {
        if (!TEST_true(SSL_set1_groups_list(serverssl, kexch_names))
            || !TEST_true(SSL_set1_groups_list(clientssl, kexch_names)))
            goto end;
    }

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /*
     * If the handshake succeeds the negotiated kexch alg should be the first
     * one in configured, except in the case of "all" FFDHE and "all" ML-KEM
     * groups (idx == 19, 20), which are TLSv1.3 only so we expect no shared
     * group to exist.
     */
    shared_group0 = SSL_get_shared_group(serverssl, 0);
    switch (idx) {
    case 19:
# if !defined(OPENSSL_NO_EC)
        /* MLKEM + TLS 1.2 and no DH => "secp526r1" */
        if (!TEST_int_eq(shared_group0, NID_X9_62_prime256v1))
            goto end;
        break;
# endif
        /* Fall through */
    case 20:
        if (!TEST_int_eq(shared_group0, 0))
            goto end;
        break;
    default:
        if (kexch_groups != NULL
            && !TEST_int_eq(shared_group0, kexch_groups[0]))
            goto end;
        if (!TEST_str_eq(SSL_group_to_name(serverssl, shared_group0),
                         kexch_name0))
            goto end;
        if (!TEST_str_eq(SSL_get0_group_name(serverssl), kexch_name0)
            || !TEST_str_eq(SSL_get0_group_name(clientssl), kexch_name0))
            goto end;
        if (!TEST_int_eq(SSL_get_negotiated_group(serverssl), shared_group0))
            goto end;
        if (!TEST_int_eq(SSL_get_negotiated_group(clientssl), shared_group0))
            goto end;
        break;
    }

    testresult = 1;
 end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_key_exchange(void)
{
    return test_key_exchange_id(17);
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile srpvfile tmpfile provider config dhfile\n")

int setup_tests(void)
{
    char *modulename;
    char *configfile;

    libctx = OSSL_LIB_CTX_new();
    if (!TEST_ptr(libctx))
        return 0;

    EVP_set_default_properties(libctx, "fips=yes");
    defctxnull = OSSL_PROVIDER_load(NULL, "null");

    /*
     * Verify that the default and fips providers in the default libctx are not
     * available
     */
    if (!TEST_false(OSSL_PROVIDER_available(NULL, "default"))
            || !TEST_false(OSSL_PROVIDER_available(NULL, "fips")))
        return 0;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(certsdir = test_get_argument(0))
            || !TEST_ptr(srpvfile = test_get_argument(1))
            || !TEST_ptr(tmpfilename = test_get_argument(2))
            || !TEST_ptr(modulename = test_get_argument(3))
            || !TEST_ptr(configfile = test_get_argument(4))
            || !TEST_ptr(dhfile = test_get_argument(5)))
        return 0;

    if (!TEST_true(OSSL_LIB_CTX_load_config(libctx, configfile)))
        return 0;

    /* Check we have the expected provider available */
    if (!TEST_true(OSSL_PROVIDER_available(libctx, modulename)))
        return 0;

    if (!TEST_true(OSSL_PROVIDER_add_builtin(libctx, "hybrid",
                                             hybrid_provider_init))
        || !TEST_ptr(hybridprov = OSSL_PROVIDER_load(libctx, "hybrid")))
        return 0;

    if (strcmp(modulename, "fips") == 0) {
        is_fips = 1;
    }

    /*
     * We add, but don't load the test "tls-provider". We'll load it when we
     * need it.
     */
    if (!TEST_true(OSSL_PROVIDER_add_builtin(libctx, "tls-provider",
                                             tls_provider_init)))
        return 0;

    if (!TEST_ptr(EVP_KEYMGMT_fetch(libctx, "SecP256r1MLKEM768", "fips=yes")))
        goto err;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        goto err;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL)
        goto err;

    cert2 = test_mk_file_path(certsdir, "server-ecdsa-cert.pem");
    if (cert2 == NULL)
        goto err;

    privkey2 = test_mk_file_path(certsdir, "server-ecdsa-key.pem");
    if (privkey2 == NULL)
        goto err;

    cert1024 = test_mk_file_path(certsdir, "ee-cert-1024.pem");
    if (cert1024 == NULL)
        goto err;

    privkey1024 = test_mk_file_path(certsdir, "ee-key-1024.pem");
    if (privkey1024 == NULL)
        goto err;

    cert3072 = test_mk_file_path(certsdir, "ee-cert-3072.pem");
    if (cert3072 == NULL)
        goto err;

    privkey3072 = test_mk_file_path(certsdir, "ee-key-3072.pem");
    if (privkey3072 == NULL)
        goto err;

    cert4096 = test_mk_file_path(certsdir, "ee-cert-4096.pem");
    if (cert4096 == NULL)
        goto err;

    privkey4096 = test_mk_file_path(certsdir, "ee-key-4096.pem");
    if (privkey4096 == NULL)
        goto err;

    cert8192 = test_mk_file_path(certsdir, "ee-cert-8192.pem");
    if (cert8192 == NULL)
        goto err;

    privkey8192 = test_mk_file_path(certsdir, "ee-key-8192.pem");
    if (privkey8192 == NULL)
        goto err;

    ADD_TEST(test_key_exchange);
    return 1;

 err:
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(cert2);
    OPENSSL_free(privkey2);
    return 0;
}

void cleanup_tests(void)
{
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(cert2);
    OPENSSL_free(privkey2);
    OPENSSL_free(cert1024);
    OPENSSL_free(privkey1024);
    OPENSSL_free(cert3072);
    OPENSSL_free(privkey3072);
    OPENSSL_free(cert4096);
    OPENSSL_free(privkey4096);
    OPENSSL_free(cert8192);
    OPENSSL_free(privkey8192);
    bio_s_mempacket_test_free();
    bio_s_always_retry_free();
    bio_s_maybe_retry_free();
    OSSL_PROVIDER_unload(defctxnull);
    OSSL_LIB_CTX_free(libctx);
}
