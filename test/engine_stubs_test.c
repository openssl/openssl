/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_ENGINE_STUBS /* switch on stub macros */

#include <openssl/engine.h>
#include "testutil.h"

/* Test stubs for removed ENGINE_* API */
static int test_engine_stubs(void)
{
#ifndef OPENSSL_NO_DEPRECATED_3_0
    ENGINE_load_builtin_engines();
    ENGINE_set_table_flags(0);
    ENGINE_unregister_RSA(NULL);
    ENGINE_register_all_RSA();
    ENGINE_unregister_DSA(NULL);
    ENGINE_register_all_DSA();
    ENGINE_unregister_EC(NULL);
    ENGINE_register_all_EC();
    ENGINE_unregister_DH(NULL);
    ENGINE_register_all_DH();
    ENGINE_unregister_RAND(NULL);
    ENGINE_register_all_RAND();
    ENGINE_unregister_digests(NULL);
    ENGINE_register_all_digests();
    ENGINE_unregister_pkey_meths(NULL);
    ENGINE_register_all_pkey_meths();
    ENGINE_unregister_pkey_asn1_meths(NULL);
    ENGINE_register_all_pkey_asn1_meths();
    ENGINE_unregister_ciphers(NULL);
    ENGINE_register_all_ciphers();
    ENGINE_add_conf_module();

    if (!TEST_ptr_null(ENGINE_get_first()))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_last()))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_next(NULL)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_prev(NULL)))
        return 0;
    if (!TEST_int_eq(ENGINE_add(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_remove(NULL), 0))
        return 0;
    if (!TEST_ptr_null(ENGINE_by_id(NULL)))
        return 0;
    if (!TEST_int_eq(ENGINE_get_table_flags(), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_register_RSA(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_register_DSA(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_register_EC(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_register_DH(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_register_RAND(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_register_ciphers(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_register_digests(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_register_pkey_meths(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_register_pkey_asn1_meths(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_register_complete(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_register_all_complete(), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_ctrl(NULL, 0, 0, NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_cmd_is_executable(NULL, 0), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_ctrl_cmd(NULL, NULL, 0, NULL, NULL, 0), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_ctrl_cmd_string(NULL, NULL, NULL, 0), 0))
        return 0;
    if (!TEST_ptr_null(ENGINE_new()))
        return 0;
    if (!TEST_int_eq(ENGINE_free(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_up_ref(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_id(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_name(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_RSA(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_DSA(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_EC(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_DH(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_RAND(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_destroy_function(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_init_function(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_finish_function(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_ctrl_function(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_load_privkey_function(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_load_pubkey_function(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_load_ssl_client_cert_function(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_ciphers(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_digests(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_pkey_meths(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_pkey_asn1_meths(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_flags(NULL, 0), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_cmd_defns(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_get_ex_new_index(0, NULL, NULL, NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_ex_data(NULL, 0, NULL), 0))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_ex_data(NULL, 0)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_id(NULL)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_name(NULL)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_RSA(NULL)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_DSA(NULL)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_EC(NULL)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_DH(NULL)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_RAND(NULL)))
        return 0;
    if (!TEST_true(ENGINE_get_destroy_function(NULL) == (ENGINE_GEN_INT_FUNC_PTR)NULL))
        return 0;
    if (!TEST_true(ENGINE_get_init_function(NULL) == (ENGINE_GEN_INT_FUNC_PTR)NULL))
        return 0;
    if (!TEST_true(ENGINE_get_finish_function(NULL) == (ENGINE_GEN_INT_FUNC_PTR)NULL))
        return 0;
    if (!TEST_true(ENGINE_get_ctrl_function(NULL) == (ENGINE_CTRL_FUNC_PTR)NULL))
        return 0;
    if (!TEST_true(ENGINE_get_load_privkey_function(NULL) == (ENGINE_LOAD_KEY_PTR)NULL))
        return 0;
    if (!TEST_true(ENGINE_get_load_pubkey_function(NULL) == (ENGINE_LOAD_KEY_PTR)NULL))
        return 0;
    if (!TEST_true(ENGINE_get_ssl_client_cert_function(NULL) == (ENGINE_SSL_CLIENT_CERT_PTR)NULL))
        return 0;
    if (!TEST_true(ENGINE_get_ciphers(NULL) == (ENGINE_CIPHERS_PTR)NULL))
        return 0;
    if (!TEST_true(ENGINE_get_digests(NULL) == (ENGINE_DIGESTS_PTR)NULL))
        return 0;
    if (!TEST_true(ENGINE_get_pkey_meths(NULL) == (ENGINE_PKEY_METHS_PTR)NULL))
        return 0;
    if (!TEST_true(ENGINE_get_pkey_asn1_meths(NULL) == (ENGINE_PKEY_ASN1_METHS_PTR)NULL))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_cipher(NULL, 0)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_digest(NULL, 0)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_pkey_meth(NULL, 0)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_pkey_asn1_meth(NULL, 0)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_pkey_asn1_meth_str(NULL, NULL, 0)))
        return 0;
    if (!TEST_ptr_null(ENGINE_pkey_asn1_find_str(NULL, NULL, 0)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_cmd_defns(NULL)))
        return 0;
    if (!TEST_int_eq(ENGINE_get_flags(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_init(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_finish(NULL), 0))
        return 0;
    if (!TEST_ptr_null(ENGINE_load_private_key(NULL, NULL, NULL, NULL)))
        return 0;
    if (!TEST_ptr_null(ENGINE_load_public_key(NULL, NULL, NULL, NULL)))
        return 0;
    if (!TEST_int_eq(ENGINE_load_ssl_client_cert(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), 0))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_default_RSA()))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_default_DSA()))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_default_EC()))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_default_DH()))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_default_RAND()))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_cipher_engine(0)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_digest_engine(0)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_pkey_meth_engine(0)))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_pkey_asn1_meth_engine(0)))
        return 0;
    if (!TEST_int_eq(ENGINE_set_default_RSA(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_default_string(NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_default_DSA(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_default_EC(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_default_DH(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_default_RAND(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_default_ciphers(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_default_digests(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_default_pkey_meths(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_default_pkey_asn1_meths(NULL), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_set_default(NULL, 0), 0))
        return 0;
    if (!TEST_ptr_null(ENGINE_get_static_state()))
        return 0;
#endif

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
    ENGINE_cleanup();
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
    ENGINE_setup_bsd_cryptodev();
#endif
    if (!TEST_int_eq(ENGINE_load_openssl(), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_load_dynamic(), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_load_cryptodev(), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_load_rdrand(), 0))
        return 0;
#ifndef OPENSSL_NO_STATIC_ENGINE
    if (!TEST_int_eq(ENGINE_load_padlock(), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_load_capi(), 0))
        return 0;
    if (!TEST_int_eq(ENGINE_load_afalg(), 0))
        return 0;
#endif
#endif

    return 1;
}

/* Test stubs for other removed API */
static int test_other_stubs(void)
{
#ifndef OPENSSL_NO_DEPRECATED_3_0
    if (!TEST_int_eq(ERR_load_ENGINE_strings(), 1))
        return 0;

    if (!TEST_int_eq(EVP_PKEY_set1_engine(NULL, NULL), 0))
        return 0;
    if (!TEST_ptr_null(EVP_PKEY_get0_engine(NULL)))
        return 0;
    if (!TEST_ptr_null(DH_get0_engine(NULL)))
        return 0;
    if (!TEST_ptr_null(RSA_get0_engine(NULL)))
        return 0;
    if (!TEST_ptr_null(DSA_get0_engine(NULL)))
        return 0;
    if (!TEST_ptr_null(EC_KEY_get0_engine(NULL)))
        return 0;
    if (!TEST_ptr_null(OSSL_STORE_LOADER_get0_engine(NULL)))
        return 0;
    if (!TEST_int_eq(RAND_set_rand_engine(NULL), 0))
        return 0;
#endif
    if (!TEST_int_eq(TS_CONF_set_crypto_device(NULL, NULL, NULL), 0))
        return 0;
    if (!TEST_int_eq(TS_CONF_set_default_engine(NULL), 0))
        return 0;
    if (!TEST_int_eq(SSL_CTX_set_client_cert_engine(NULL, NULL), 0))
        return 0;

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_engine_stubs);
    ADD_TEST(test_other_stubs);
    return 1;
}
