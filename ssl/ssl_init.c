/*
 * Copyright 2016-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/e_os.h"

#include "internal/err.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/trace.h>
#include <openssl/err.h>
#include "ssl_local.h"
#include "sslerr.h"
#include "internal/thread_once.h"
#include "internal/rio_notifier.h"    /* for ossl_wsa_cleanup() */
#include "internal/dso.h"

static int stopped;

static void pin_library(void)
{
#if !defined(OPENSSL_USE_NODELETE) \
    && !defined(OPENSSL_NO_PINSHARED)
# if defined(WIN32) && !defined(_WIN32_WCE)
    {
        HMODULE handle = NULL;

        /* We don't use the DSO route for WIN32 because there is a better way */
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                          | GET_MODULE_HANDLE_EX_FLAG_PIN,
                          (void *)&stopped, &handle);

    }
# elif !defined(DSO_NONE)
    /*
     * Deliberately leak a reference to ourselves. This will force the library
     * to remain loaded until the atexit() handler is run at process exit.
     */
    (void) DSO_dsobyaddr(&stopped, DSO_FLAG_NO_UNLOAD_ON_FREE);
    /*
     * clear errors eventually left behind runtime linker.
     * those errors are meant to be ignored anyway. Library
     * pinning is just best effort.
     */
    ERR_clear_error();
# endif
#endif
}

static CRYPTO_ONCE ssl_base = CRYPTO_ONCE_STATIC_INIT;
static int ssl_base_inited = 0;
DEFINE_RUN_ONCE_STATIC(ossl_init_ssl_base)
{
#ifndef OPENSSL_NO_COMP
    OSSL_TRACE(INIT, "ossl_init_ssl_base: "
               "SSL_COMP_get_compression_methods()\n");
    /*
     * This will initialise the built-in compression algorithms. The value
     * returned is a STACK_OF(SSL_COMP), but that can be discarded safely
     */
    SSL_COMP_get_compression_methods();
#endif
    ssl_sort_cipher_list();
    pin_library();
    OSSL_TRACE(INIT, "ossl_init_ssl_base: SSL_add_ssl_module()\n");
    ssl_base_inited = 1;
    return 1;
}

static CRYPTO_ONCE ssl_strings = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(ossl_init_load_ssl_strings)
{
    /*
     * OPENSSL_NO_AUTOERRINIT is provided here to prevent at compile time
     * pulling in all the error strings during static linking
     */
#if !defined(OPENSSL_NO_ERR) && !defined(OPENSSL_NO_AUTOERRINIT)
    OSSL_TRACE(INIT, "ossl_init_load_ssl_strings: ossl_err_load_SSL_strings()\n");
    ossl_err_load_SSL_strings();
#endif
    return 1;
}

DEFINE_RUN_ONCE_STATIC_ALT(ossl_init_no_load_ssl_strings,
                           ossl_init_load_ssl_strings)
{
    /* Do nothing in this case */
    return 1;
}

/*
 * If this function is called with a non NULL settings value then it must be
 * called prior to any threads making calls to any OpenSSL functions,
 * i.e. passing a non-null settings value is assumed to be single-threaded.
 */
int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
{
    static int stoperrset = 0;

    if (stopped) {
        if (!stoperrset) {
            /*
             * We only ever set this once to avoid getting into an infinite
             * loop where the error system keeps trying to init and fails so
             * sets an error etc
             */
            stoperrset = 1;
            ERR_raise(ERR_LIB_SSL, ERR_R_INIT_FAIL);
        }
        return 0;
    }

    opts |= OPENSSL_INIT_ADD_ALL_CIPHERS
         |  OPENSSL_INIT_ADD_ALL_DIGESTS;
#ifndef OPENSSL_NO_AUTOLOAD_CONFIG
    if ((opts & OPENSSL_INIT_NO_LOAD_CONFIG) == 0)
        opts |= OPENSSL_INIT_LOAD_CONFIG;
#endif

    if (!OPENSSL_init_crypto(opts, settings))
        return 0;

    if (!RUN_ONCE(&ssl_base, ossl_init_ssl_base))
        return 0;

    if ((opts & OPENSSL_INIT_NO_LOAD_SSL_STRINGS)
        && !RUN_ONCE_ALT(&ssl_strings, ossl_init_no_load_ssl_strings,
                         ossl_init_load_ssl_strings))
        return 0;

    if ((opts & OPENSSL_INIT_LOAD_SSL_STRINGS)
        && !RUN_ONCE(&ssl_strings, ossl_init_load_ssl_strings))
        return 0;

    return 1;
}
