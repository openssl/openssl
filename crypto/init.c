/*
 * Written by Matt Caswell for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <internal/threads.h>
#include <internal/cryptlib_int.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <internal/evp_int.h>
#include <internal/conf.h>
#include <internal/async.h>
#include <internal/engine.h>
#include <openssl/comp.h>
#include <internal/err.h>
#include <stdlib.h>
#include <assert.h>

static int stopped = 0;

static void ossl_init_thread_stop(struct thread_local_inits_st *locals);

static CRYPTO_THREAD_LOCAL threadstopkey;

static void ossl_init_thread_stop_wrap(void *local)
{
    ossl_init_thread_stop((struct thread_local_inits_st *)local);
}

static struct thread_local_inits_st *ossl_init_get_thread_local(int alloc)
{
    struct thread_local_inits_st *local =
        CRYPTO_THREAD_get_local(&threadstopkey);

    if (local == NULL && alloc) {
        local = OPENSSL_zalloc(sizeof *local);
        CRYPTO_THREAD_set_local(&threadstopkey, local);
    }
    if (!alloc) {
        CRYPTO_THREAD_set_local(&threadstopkey, NULL);
    }

    return local;
}

typedef struct ossl_init_stop_st OPENSSL_INIT_STOP;
struct ossl_init_stop_st {
    void (*handler)(void);
    OPENSSL_INIT_STOP *next;
};

static OPENSSL_INIT_STOP *stop_handlers = NULL;
static CRYPTO_RWLOCK *init_lock = NULL;

static CRYPTO_ONCE base = CRYPTO_ONCE_STATIC_INIT;
static int base_inited = 0;
static void ossl_init_base(void)
{
#ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_base: Setting up stop handlers\n");
#endif
    /*
     * We use a dummy thread local key here. We use the destructor to detect
     * when the thread is going to stop (where that feature is available)
     */
    CRYPTO_THREAD_init_local(&threadstopkey, ossl_init_thread_stop_wrap);
#ifndef OPENSSL_SYS_UEFI
    atexit(OPENSSL_cleanup);
#endif
    init_lock = CRYPTO_THREAD_lock_new();
    OPENSSL_cpuid_setup();
    base_inited = 1;
}

static CRYPTO_ONCE load_crypto_strings = CRYPTO_ONCE_STATIC_INIT;
static int load_crypto_strings_inited = 0;
static void ossl_init_no_load_crypto_strings(void)
{
    /* Do nothing in this case */
    return;
}

static void ossl_init_load_crypto_strings(void)
{
    /*
     * OPENSSL_NO_AUTOERRINIT is provided here to prevent at compile time
     * pulling in all the error strings during static linking
     */
#if !defined(OPENSSL_NO_ERR) && !defined(OPENSSL_NO_AUTOERRINIT)
# ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_load_crypto_strings: "
                    "err_load_crypto_strings_intern()\n");
# endif
    err_load_crypto_strings_intern();
#endif
    load_crypto_strings_inited = 1;
}

static CRYPTO_ONCE add_all_ciphers = CRYPTO_ONCE_STATIC_INIT;
static void ossl_init_add_all_ciphers(void)
{
    /*
     * OPENSSL_NO_AUTOALGINIT is provided here to prevent at compile time
     * pulling in all the ciphers during static linking
     */
#ifndef OPENSSL_NO_AUTOALGINIT
# ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_add_all_ciphers: "
                    "openssl_add_all_ciphers_internal()\n");
# endif
    openssl_add_all_ciphers_internal();
# ifndef OPENSSL_NO_ENGINE
#  if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(HAVE_CRYPTODEV)
    ENGINE_setup_bsd_cryptodev();
#  endif
# endif
#endif
}

static CRYPTO_ONCE add_all_digests = CRYPTO_ONCE_STATIC_INIT;
static void ossl_init_add_all_digests(void)
{
    /*
     * OPENSSL_NO_AUTOALGINIT is provided here to prevent at compile time
     * pulling in all the ciphers during static linking
     */
#ifndef OPENSSL_NO_AUTOALGINIT
# ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_add_all_digests: "
                    "openssl_add_all_digests_internal()\n");
# endif
    openssl_add_all_digests_internal();
# ifndef OPENSSL_NO_ENGINE
#  if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(HAVE_CRYPTODEV)
    ENGINE_setup_bsd_cryptodev();
#  endif
# endif
#endif
}

static void ossl_init_no_add_algs(void)
{
    /* Do nothing */
    return;
}

static CRYPTO_ONCE config = CRYPTO_ONCE_STATIC_INIT;
static int config_inited = 0;
static const char *config_filename;
static void ossl_init_config(void)
{
#ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr,
            "OPENSSL_INIT: ossl_init_config: openssl_config_internal(%s)\n",
            config_filename==NULL?"NULL":config_filename);
#endif
    openssl_config_internal(config_filename);
    config_inited = 1;
}
static void ossl_init_no_config(void)
{
#ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr,
            "OPENSSL_INIT: ossl_init_config: openssl_no_config_internal()\n");
#endif
    openssl_no_config_internal();
    config_inited = 1;
}

#ifndef OPENSSL_NO_ASYNC
static CRYPTO_ONCE async = CRYPTO_ONCE_STATIC_INIT;
static int async_inited = 0;
static void ossl_init_async(void)
{
#ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_async: async_init()\n");
#endif
    async_init();
    async_inited = 1;
}
#endif

#ifndef OPENSSL_NO_ENGINE
static CRYPTO_ONCE engine_openssl = CRYPTO_ONCE_STATIC_INIT;
static void ossl_init_engine_openssl(void)
{
# ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_engine_openssl: "
                    "engine_load_openssl_internal()\n");
# endif
    engine_load_openssl_internal();
}
# if !defined(OPENSSL_NO_HW) && \
    (defined(__OpenBSD__) || defined(__FreeBSD__) || defined(HAVE_CRYPTODEV))
static CRYPTO_ONCE engine_cryptodev = CRYPTO_ONCE_STATIC_INIT;
static void ossl_init_engine_cryptodev(void)
{
#  ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_engine_cryptodev: "
                    "engine_load_cryptodev_internal()\n");
#  endif
    engine_load_cryptodev_internal();
}
# endif

# ifndef OPENSSL_NO_RDRAND
static CRYPTO_ONCE engine_rdrand = CRYPTO_ONCE_STATIC_INIT;
static void ossl_init_engine_rdrand(void)
{
#  ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_engine_rdrand: "
                    "engine_load_rdrand_internal()\n");
#  endif
    engine_load_rdrand_internal();
}
# endif
static CRYPTO_ONCE engine_dynamic = CRYPTO_ONCE_STATIC_INIT;
static void ossl_init_engine_dynamic(void)
{
# ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_engine_dynamic: "
                    "engine_load_dynamic_internal()\n");
# endif
    engine_load_dynamic_internal();
}
# ifndef OPENSSL_NO_STATIC_ENGINE
#  if !defined(OPENSSL_NO_HW) && !defined(OPENSSL_NO_HW_PADLOCK)
static CRYPTO_ONCE engine_padlock = CRYPTO_ONCE_STATIC_INIT;
static void ossl_init_engine_padlock(void)
{
#   ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_engine_padlock: "
                    "engine_load_padlock_internal()\n");
#   endif
    engine_load_padlock_internal();
}
#  endif
#  if defined(OPENSSL_SYS_WIN32) && !defined(OPENSSL_NO_CAPIENG)
static CRYPTO_ONCE engine_capi = CRYPTO_ONCE_STATIC_INIT;
static void ossl_init_engine_capi(void)
{
#   ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_engine_capi: "
                    "engine_load_capi_internal()\n");
#   endif
    engine_load_capi_internal();
}
#  endif
static CRYPTO_ONCE engine_dasync = CRYPTO_ONCE_STATIC_INIT;
static void ossl_init_engine_dasync(void)
{
# ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_engine_dasync: "
                    "engine_load_dasync_internal()\n");
# endif
    engine_load_dasync_internal();
}
#  if !defined(OPENSSL_NO_AFALGENG)
static CRYPTO_ONCE engine_afalg = CRYPTO_ONCE_STATIC_INIT;
static void ossl_init_engine_afalg(void)
{
#   ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: ossl_init_engine_afalg: "
                    "engine_load_afalg_internal()\n");
#   endif
    engine_load_afalg_internal();
}
#  endif
# endif
#endif

#ifndef OPENSSL_NO_COMP
static CRYPTO_ONCE zlib = CRYPTO_ONCE_STATIC_INIT;

static int zlib_inited = 0;
static void ossl_init_zlib(void)
{
    /* Do nothing - we need to know about this for the later cleanup */
    zlib_inited = 1;
}
#endif

static void ossl_init_thread_stop(struct thread_local_inits_st *locals)
{
    /* Can't do much about this */
    if (locals == NULL)
        return;

#ifndef OPENSSL_NO_ASYNC
    if (locals->async) {
#ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: ossl_init_thread_stop: "
                        "ASYNC_cleanup_thread()\n");
#endif
        ASYNC_cleanup_thread();
    }
#endif

    if (locals->err_state) {
#ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: ossl_init_thread_stop: "
                        "ERR_remove_thread_state()\n");
#endif
        ERR_remove_thread_state();
    }

    OPENSSL_free(locals);
}

void OPENSSL_thread_stop(void)
{
    ossl_init_thread_stop(
        (struct thread_local_inits_st *)ossl_init_get_thread_local(0));
}

int ossl_init_thread_start(uint64_t opts)
{
    struct thread_local_inits_st *locals = ossl_init_get_thread_local(1);

    if (locals == NULL)
        return 0;

    if (opts & OPENSSL_INIT_THREAD_ASYNC) {
#ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: ossl_init_thread_start: "
                        "marking thread for async\n");
#endif
        locals->async = 1;
    }

    if (opts & OPENSSL_INIT_THREAD_ERR_STATE) {
#ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: ossl_init_thread_start: "
                        "marking thread for err_state\n");
#endif
        locals->err_state = 1;
    }

    return 1;
}

void OPENSSL_cleanup(void)
{
    OPENSSL_INIT_STOP *currhandler, *lasthandler;

    /* If we've not been inited then no need to deinit */
    if (!base_inited)
        return;

    /* Might be explicitly called and also by atexit */
    if (stopped)
        return;
    stopped = 1;

    /*
     * Thread stop may not get automatically called by the thread library for
     * the very last thread in some situations, so call it directly.
     */
    ossl_init_thread_stop(ossl_init_get_thread_local(0));

    currhandler = stop_handlers;
    while (currhandler != NULL) {
        currhandler->handler();
        lasthandler = currhandler;
        currhandler = currhandler->next;
        OPENSSL_free(lasthandler);
    }
    stop_handlers = NULL;

    CRYPTO_THREAD_lock_free(init_lock);

    /*
     * We assume we are single-threaded for this function, i.e. no race
     * conditions for the various "*_inited" vars below.
     */

#ifndef OPENSSL_NO_COMP
    if (zlib_inited) {
#ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: OPENSSL_cleanup: "
                        "COMP_zlib_cleanup()\n");
#endif
        COMP_zlib_cleanup();
    }
#endif

#ifndef OPENSSL_NO_ASYNC
    if (async_inited) {
# ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: OPENSSL_cleanup: "
                        "async_deinit()\n");
# endif
        async_deinit();
    }
#endif

    if (load_crypto_strings_inited) {
#ifdef OPENSSL_INIT_DEBUG
        fprintf(stderr, "OPENSSL_INIT: OPENSSL_cleanup: "
                        "ERR_free_strings()\n");
#endif
        ERR_free_strings();
    }

    CRYPTO_THREAD_cleanup_local(&threadstopkey);

#ifdef OPENSSL_INIT_DEBUG
    fprintf(stderr, "OPENSSL_INIT: OPENSSL_cleanup: "
                    "RAND_cleanup()\n");
    fprintf(stderr, "OPENSSL_INIT: OPENSSL_cleanup: "
                    "CONF_modules_free()\n");
#ifndef OPENSSL_NO_ENGINE
    fprintf(stderr, "OPENSSL_INIT: OPENSSL_cleanup: "
                    "ENGINE_cleanup()\n");
#endif
    fprintf(stderr, "OPENSSL_INIT: OPENSSL_cleanup: "
                    "CRYPTO_cleanup_all_ex_data()\n");
    fprintf(stderr, "OPENSSL_INIT: OPENSSL_cleanup: "
                    "BIO_sock_cleanup()\n");
    fprintf(stderr, "OPENSSL_INIT: OPENSSL_cleanup: "
                    "EVP_cleanup()\n");
    fprintf(stderr, "OPENSSL_INIT: OPENSSL_cleanup: "
                    "OBJ_cleanup()\n");
#endif
    /*
     * Note that cleanup order is important:
     * - RAND_cleanup could call an ENINGE's RAND cleanup function so must be
     * called before ENGINE_cleanup()
     * - ENGINEs use CRYPTO_EX_DATA and therefore, must be cleaned up
     * before the ex data handlers are wiped in CRYPTO_cleanup_all_ex_data().
     * - CONF_modules_free() can end up in ENGINE code so must be called before
     * ENGINE_cleanup()
     */
    RAND_cleanup();
    CONF_modules_free();
#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif
    CRYPTO_cleanup_all_ex_data();
#ifndef OPENSSL_NO_SOCK
    BIO_sock_cleanup();
#endif
    EVP_cleanup();
    OBJ_cleanup();
    base_inited = 0;
}

/*
 * If this function is called with a non NULL settings value then it must be
 * called prior to any threads making calls to any OpenSSL functions,
 * i.e. passing a non-null settings value is assumed to be single-threaded.
 */
int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
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
            CRYPTOerr(CRYPTO_F_OPENSSL_INIT_CRYPTO, ERR_R_INIT_FAIL);
        }
        return 0;
    }

    if (!CRYPTO_THREAD_run_once(&base, ossl_init_base))
        return 0;

    if ((opts & OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS)
            && !CRYPTO_THREAD_run_once(&load_crypto_strings,
                                       ossl_init_no_load_crypto_strings))
        return 0;

    if ((opts & OPENSSL_INIT_LOAD_CRYPTO_STRINGS)
            && !CRYPTO_THREAD_run_once(&load_crypto_strings,
                                       ossl_init_load_crypto_strings))
        return 0;

    if ((opts & OPENSSL_INIT_NO_ADD_ALL_CIPHERS)
            && !CRYPTO_THREAD_run_once(&add_all_ciphers, ossl_init_no_add_algs))
        return 0;

    if ((opts & OPENSSL_INIT_ADD_ALL_CIPHERS)
            && !CRYPTO_THREAD_run_once(&add_all_ciphers,
                                       ossl_init_add_all_ciphers))
        return 0;

    if ((opts & OPENSSL_INIT_NO_ADD_ALL_DIGESTS)
            && !CRYPTO_THREAD_run_once(&add_all_digests, ossl_init_no_add_algs))
        return 0;

    if ((opts & OPENSSL_INIT_ADD_ALL_DIGESTS)
            && !CRYPTO_THREAD_run_once(&add_all_digests,
                                       ossl_init_add_all_digests))
        return 0;

    if ((opts & OPENSSL_INIT_NO_LOAD_CONFIG)
            && !CRYPTO_THREAD_run_once(&config, ossl_init_no_config))
        return 0;

    if (opts & OPENSSL_INIT_LOAD_CONFIG) {
        int ret;
        CRYPTO_THREAD_write_lock(init_lock);
        config_filename = (settings == NULL) ? NULL : settings->config_name;
        ret = CRYPTO_THREAD_run_once(&config, ossl_init_config);
        CRYPTO_THREAD_unlock(init_lock);
        if (!ret)
            return 0;
    }

#ifndef OPENSSL_NO_ASYNC
    if ((opts & OPENSSL_INIT_ASYNC)
            && !CRYPTO_THREAD_run_once(&async, ossl_init_async))
        return 0;
#endif
#ifndef OPENSSL_NO_ENGINE
    if ((opts & OPENSSL_INIT_ENGINE_OPENSSL)
            && !CRYPTO_THREAD_run_once(&engine_openssl,
                                       ossl_init_engine_openssl))
        return 0;
# if !defined(OPENSSL_NO_HW) && \
    (defined(__OpenBSD__) || defined(__FreeBSD__) || defined(HAVE_CRYPTODEV))
    if ((opts & OPENSSL_INIT_ENGINE_CRYPTODEV)
            && !CRYPTO_THREAD_run_once(&engine_cryptodev,
                                       ossl_init_engine_cryptodev))
        return 0;
# endif
# ifndef OPENSSL_NO_RDRAND
    if ((opts & OPENSSL_INIT_ENGINE_RDRAND)
            && !CRYPTO_THREAD_run_once(&engine_rdrand, ossl_init_engine_rdrand))
        return 0;
# endif
    if ((opts & OPENSSL_INIT_ENGINE_DYNAMIC)
            && !CRYPTO_THREAD_run_once(&engine_dynamic,
                                       ossl_init_engine_dynamic))
        return 0;
# ifndef OPENSSL_NO_STATIC_ENGINE
#  if !defined(OPENSSL_NO_HW) && !defined(OPENSSL_NO_HW_PADLOCK)
    if ((opts & OPENSSL_INIT_ENGINE_PADLOCK)
            && !CRYPTO_THREAD_run_once(&engine_padlock,
                                       ossl_init_engine_padlock))
        return 0;
#  endif
#  if defined(OPENSSL_SYS_WIN32) && !defined(OPENSSL_NO_CAPIENG)
    if ((opts & OPENSSL_INIT_ENGINE_CAPI)
            && !CRYPTO_THREAD_run_once(&engine_capi, ossl_init_engine_capi))
        return 0;
#  endif
    if ((opts & OPENSSL_INIT_ENGINE_DASYNC)
            && !CRYPTO_THREAD_run_once(&engine_dasync, ossl_init_engine_dasync))
        return 0;
#  if !defined(OPENSSL_NO_AFALGENG)
    if ((opts & OPENSSL_INIT_ENGINE_AFALG)
            && !CRYPTO_THREAD_run_once(&engine_afalg, ossl_init_engine_afalg))
        return 0;
#  endif
# endif
    if (opts & (OPENSSL_INIT_ENGINE_ALL_BUILTIN
                | OPENSSL_INIT_ENGINE_DASYNC | OPENSSL_INIT_ENGINE_OPENSSL
                | OPENSSL_INIT_ENGINE_AFALG)) {
        ENGINE_register_all_complete();
    }
#endif

#ifndef OPENSSL_NO_COMP
    if ((opts & OPENSSL_INIT_ZLIB)
            && !CRYPTO_THREAD_run_once(&zlib, ossl_init_zlib))
        return 0;
#endif

    return 1;
}

int OPENSSL_atexit(void (*handler)(void))
{
    OPENSSL_INIT_STOP *newhand;

    newhand = OPENSSL_malloc(sizeof(*newhand));
    if (newhand == NULL)
        return 0;

    newhand->handler = handler;
    newhand->next = stop_handlers;
    stop_handlers = newhand;

    return 1;
}
