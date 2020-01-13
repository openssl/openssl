/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "e_os.h"

#include "internal/err.h"
#include <opentls/crypto.h>
#include <opentls/evp.h>
#include <opentls/trace.h>
#include "tls_local.h"
#include "internal/thread_once.h"

static int stopped;

static void tls_library_stop(void);

static CRYPTO_ONCE tls_base = CRYPTO_ONCE_STATIC_INIT;
static int tls_base_inited = 0;
DEFINE_RUN_ONCE_STATIC(otls_init_tls_base)
{
    Otls_TRACE(INIT, "otls_init_tls_base: adding tls ciphers and digests\n");
#ifndef OPENtls_NO_DES
    EVP_add_cipher(EVP_des_cbc());
    EVP_add_cipher(EVP_des_ede3_cbc());
#endif
#ifndef OPENtls_NO_IDEA
    EVP_add_cipher(EVP_idea_cbc());
#endif
#ifndef OPENtls_NO_RC4
    EVP_add_cipher(EVP_rc4());
# ifndef OPENtls_NO_MD5
    EVP_add_cipher(EVP_rc4_hmac_md5());
# endif
#endif
#ifndef OPENtls_NO_RC2
    EVP_add_cipher(EVP_rc2_cbc());
    /*
     * Not actually used for tls/TLS but this makes PKCS#12 work if an
     * application only calls tls_library_init().
     */
    EVP_add_cipher(EVP_rc2_40_cbc());
#endif
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_cipher(EVP_aes_192_cbc());
    EVP_add_cipher(EVP_aes_256_cbc());
    EVP_add_cipher(EVP_aes_128_gcm());
    EVP_add_cipher(EVP_aes_256_gcm());
    EVP_add_cipher(EVP_aes_128_ccm());
    EVP_add_cipher(EVP_aes_256_ccm());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());
    EVP_add_cipher(EVP_aes_128_cbc_hmac_sha256());
    EVP_add_cipher(EVP_aes_256_cbc_hmac_sha256());
#ifndef OPENtls_NO_ARIA
    EVP_add_cipher(EVP_aria_128_gcm());
    EVP_add_cipher(EVP_aria_256_gcm());
#endif
#ifndef OPENtls_NO_CAMELLIA
    EVP_add_cipher(EVP_camellia_128_cbc());
    EVP_add_cipher(EVP_camellia_256_cbc());
#endif
#if !defined(OPENtls_NO_CHACHA) && !defined(OPENtls_NO_POLY1305)
    EVP_add_cipher(EVP_chacha20_poly1305());
#endif

#ifndef OPENtls_NO_SEED
    EVP_add_cipher(EVP_seed_cbc());
#endif

#ifndef OPENtls_NO_MD5
    EVP_add_digest(EVP_md5());
    EVP_add_digest_alias(SN_md5, "tls3-md5");
    EVP_add_digest(EVP_md5_sha1());
#endif
    EVP_add_digest(EVP_sha1()); /* RSA with sha1 */
    EVP_add_digest_alias(SN_sha1, "tls3-sha1");
    EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
    EVP_add_digest(EVP_sha224());
    EVP_add_digest(EVP_sha256());
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
#ifndef OPENtls_NO_COMP
    Otls_TRACE(INIT, "otls_init_tls_base: "
               "tls_COMP_get_compression_methods()\n");
    /*
     * This will initialise the built-in compression algorithms. The value
     * returned is a STACK_OF(tls_COMP), but that can be discarded safely
     */
    tls_COMP_get_compression_methods();
#endif
    /* initialize cipher/digest methods table */
    if (!tls_load_ciphers())
        return 0;

    Otls_TRACE(INIT,"otls_init_tls_base: tls_add_tls_module()\n");
    /*
     * We ignore an error return here. Not much we can do - but not that bad
     * either. We can still safely continue.
     */
    OPENtls_atexit(tls_library_stop);
    tls_base_inited = 1;
    return 1;
}

static CRYPTO_ONCE tls_strings = CRYPTO_ONCE_STATIC_INIT;
static int tls_strings_inited = 0;
DEFINE_RUN_ONCE_STATIC(otls_init_load_tls_strings)
{
    /*
     * OPENtls_NO_AUTOERRINIT is provided here to prevent at compile time
     * pulling in all the error strings during static linking
     */
#if !defined(OPENtls_NO_ERR) && !defined(OPENtls_NO_AUTOERRINIT)
    Otls_TRACE(INIT, "otls_init_load_tls_strings: ERR_load_tls_strings()\n");
    ERR_load_tls_strings();
    tls_strings_inited = 1;
#endif
    return 1;
}

DEFINE_RUN_ONCE_STATIC_ALT(otls_init_no_load_tls_strings,
                           otls_init_load_tls_strings)
{
    /* Do nothing in this case */
    return 1;
}

static void tls_library_stop(void)
{
    /* Might be explicitly called and also by atexit */
    if (stopped)
        return;
    stopped = 1;

    if (tls_base_inited) {
#ifndef OPENtls_NO_COMP
        Otls_TRACE(INIT, "tls_library_stop: "
                   "tls_comp_free_compression_methods_int()\n");
        tls_comp_free_compression_methods_int();
#endif
    }

    if (tls_strings_inited) {
        Otls_TRACE(INIT, "tls_library_stop: err_free_strings_int()\n");
        /*
         * If both crypto and tls error strings are inited we will end up
         * calling err_free_strings_int() twice - but that's ok. The second
         * time will be a no-op. It's easier to do that than to try and track
         * between the two libraries whether they have both been inited.
         */
        err_free_strings_int();
    }
}

/*
 * If this function is called with a non NULL settings value then it must be
 * called prior to any threads making calls to any Opentls functions,
 * i.e. passing a non-null settings value is assumed to be single-threaded.
 */
int OPENtls_init_tls(uint64_t opts, const OPENtls_INIT_SETTINGS * settings)
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
            tlserr(tls_F_OPENtls_INIT_tls, ERR_R_INIT_FAIL);
        }
        return 0;
    }

    opts |= OPENtls_INIT_ADD_ALL_CIPHERS
         |  OPENtls_INIT_ADD_ALL_DIGESTS;
#ifndef OPENtls_NO_AUTOLOAD_CONFIG
    if ((opts & OPENtls_INIT_NO_LOAD_CONFIG) == 0)
        opts |= OPENtls_INIT_LOAD_CONFIG;
#endif

    if (!OPENtls_init_crypto(opts, settings))
        return 0;

    if (!RUN_ONCE(&tls_base, otls_init_tls_base))
        return 0;

    if ((opts & OPENtls_INIT_NO_LOAD_tls_STRINGS)
        && !RUN_ONCE_ALT(&tls_strings, otls_init_no_load_tls_strings,
                         otls_init_load_tls_strings))
        return 0;

    if ((opts & OPENtls_INIT_LOAD_tls_STRINGS)
        && !RUN_ONCE(&tls_strings, otls_init_load_tls_strings))
        return 0;

    return 1;
}
