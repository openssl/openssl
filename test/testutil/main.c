/*
 * Copyright 2016-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some engine deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include "../testutil.h"
#include <openssl/engine.h>
#include "output.h"
#include "tu_local.h"


int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    int setup_res;

    test_open_streams();

    if (!global_init()) {
        test_printf_stderr("Global init failed - aborting\n");
        return ret;
    }

    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC
                        | OPENSSL_INIT_ENGINE_AFALG
                        | OPENSSL_INIT_ENGINE_CRYPTODEV
                        | OPENSSL_INIT_ENGINE_PADLOCK, NULL);
#ifndef OPENSSL_NO_ENGINE
    ERR_set_mark();
    {
        ENGINE *e = ENGINE_by_id("afalg");
        if (e && ENGINE_init(e)) {
            ENGINE_set_default(e, ENGINE_METHOD_ALL);
            ENGINE_finish(e);
        }
        ENGINE_free(e);
        e = ENGINE_by_id("devcrypto");
        if (e && ENGINE_init(e)) {
            ENGINE_set_default(e, ENGINE_METHOD_ALL);
            ENGINE_finish(e);
        }
        ENGINE_free(e);
        e = ENGINE_by_id("padlock");
        if (e && ENGINE_init(e)) {
            ENGINE_set_default(e, ENGINE_METHOD_ALL);
            ENGINE_finish(e);
        }
        ENGINE_free(e);
        e = ENGINE_by_id("dasync");
        if (e && ENGINE_init(e)) {
            ENGINE_register_complete(e);
            ENGINE_finish(e);
        }
        ENGINE_free(e);
    }
    ERR_pop_to_mark();
#endif

    if (!setup_test_framework(argc, argv))
        goto end;

    if ((setup_res = setup_tests()) > 0) {
        ret = run_tests(argv[0]);
        cleanup_tests();
        opt_check_usage();
    } else if (setup_res == 0) {
        opt_help(test_get_options());
    }
end:
#ifndef OPENSSL_NO_ENGINE
    ERR_set_mark();
    {
        ENGINE *e = ENGINE_by_id("afalg");
        if (e) {
            ENGINE_unregister_RSA(e);
            ENGINE_unregister_DSA(e);
            ENGINE_unregister_EC(e);
            ENGINE_unregister_DH(e);
            ENGINE_unregister_RAND(e);
            ENGINE_unregister_ciphers(e);
            ENGINE_unregister_digests(e);
            ENGINE_unregister_pkey_meths(e);
            ENGINE_unregister_pkey_asn1_meths(e);
            ENGINE_remove(e);
        }
        ENGINE_free(e);
        e = ENGINE_by_id("devcrypto");
        if (e) {
            ENGINE_unregister_RSA(e);
            ENGINE_unregister_DSA(e);
            ENGINE_unregister_EC(e);
            ENGINE_unregister_DH(e);
            ENGINE_unregister_RAND(e);
            ENGINE_unregister_ciphers(e);
            ENGINE_unregister_digests(e);
            ENGINE_unregister_pkey_meths(e);
            ENGINE_unregister_pkey_asn1_meths(e);
            ENGINE_remove(e);
        }
        ENGINE_free(e);
        e = ENGINE_by_id("padlock");
        if (e) {
            ENGINE_unregister_RSA(e);
            ENGINE_unregister_DSA(e);
            ENGINE_unregister_EC(e);
            ENGINE_unregister_DH(e);
            ENGINE_unregister_RAND(e);
            ENGINE_unregister_ciphers(e);
            ENGINE_unregister_digests(e);
            ENGINE_unregister_pkey_meths(e);
            ENGINE_unregister_pkey_asn1_meths(e);
            ENGINE_remove(e);
        }
        ENGINE_free(e);
        e = ENGINE_by_id("dasync");
        if (e) {
            ENGINE_unregister_RSA(e);
            ENGINE_unregister_DSA(e);
            ENGINE_unregister_EC(e);
            ENGINE_unregister_DH(e);
            ENGINE_unregister_RAND(e);
            ENGINE_unregister_ciphers(e);
            ENGINE_unregister_digests(e);
            ENGINE_unregister_pkey_meths(e);
            ENGINE_unregister_pkey_asn1_meths(e);
            ENGINE_remove(e);
        }
        ENGINE_free(e);
    }
    ERR_pop_to_mark();
#endif

    ret = pulldown_test_framework(ret);
    test_close_streams();
    return ret;
}
