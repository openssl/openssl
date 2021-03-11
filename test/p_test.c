/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is a very simple provider that does absolutely nothing except respond
 * to provider global parameter requests.  It does this by simply echoing back
 * a parameter request it makes to the loading library.
 */

#include <string.h>
#include <stdio.h>

/*
 * When built as an object file to link the application with, we get the
 * init function name through the macro PROVIDER_INIT_FUNCTION_NAME.  If
 * not defined, we use the standard init function name for the shared
 * object form.
 */
#ifdef PROVIDER_INIT_FUNCTION_NAME
# define OSSL_provider_init PROVIDER_INIT_FUNCTION_NAME
#endif

#include "e_os.h"
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>

typedef struct p_test_ctx {
    char *thisfile;
    char *thisfunc;
    const OSSL_CORE_HANDLE *handle;
} P_TEST_CTX;

static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;
static OSSL_FUNC_core_new_error_fn *c_new_error;
static OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
static OSSL_FUNC_core_vset_error_fn *c_vset_error;

/* Tell the core what params we provide and what type they are */
static const OSSL_PARAM p_param_types[] = {
    { "greeting", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { NULL, 0, NULL, 0, 0 }
};

/* This is a trick to ensure we define the provider functions correctly */
static OSSL_FUNC_provider_gettable_params_fn p_gettable_params;
static OSSL_FUNC_provider_get_params_fn p_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn p_get_reason_strings;
static OSSL_FUNC_provider_teardown_fn p_teardown;

static const OSSL_PARAM *p_gettable_params(void *_)
{
    return p_param_types;
}

static int p_get_params(void *provctx, OSSL_PARAM params[])
{
    P_TEST_CTX *ctx = (P_TEST_CTX *)provctx;
    const OSSL_CORE_HANDLE *hand = ctx->handle;
    OSSL_PARAM *p = params;
    int ok = 1;

    for (; ok && p->key != NULL; p++) {
        if (strcmp(p->key, "greeting") == 0) {
            static char *opensslv;
            static char *provname;
            static char *greeting;
            static OSSL_PARAM counter_request[] = {
                /* Known libcrypto provided parameters */
                { "openssl-version", OSSL_PARAM_UTF8_PTR,
                  &opensslv, sizeof(&opensslv), 0 },
                { "provider-name", OSSL_PARAM_UTF8_PTR,
                  &provname, sizeof(&provname), 0},

                /* This might be present, if there's such a configuration */
                { "greeting", OSSL_PARAM_UTF8_PTR,
                  &greeting, sizeof(&greeting), 0 },

                { NULL, 0, NULL, 0, 0 }
            };
            char buf[256];
            size_t buf_l;

            opensslv = provname = greeting = NULL;

            if (c_get_params(hand, counter_request)) {
                if (greeting) {
                    strcpy(buf, greeting);
                } else {
                    const char *versionp = *(void **)counter_request[0].data;
                    const char *namep = *(void **)counter_request[1].data;

                    sprintf(buf, "Hello OpenSSL %.20s, greetings from %s!",
                            versionp, namep);
                }
            } else {
                sprintf(buf, "Howdy stranger...");
            }

            p->return_size = buf_l = strlen(buf) + 1;
            if (p->data_size >= buf_l)
                strcpy(p->data, buf);
            else
                ok = 0;
        }
    }
    return ok;
}

static void p_set_error(int lib, int reason, const char *file, int line,
                        const char *func, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    c_new_error(NULL);
    c_set_error_debug(NULL, file, line, func);
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, ap);
    va_end(ap);
}

static const OSSL_ITEM *p_get_reason_strings(void *_)
{
    static const OSSL_ITEM reason_strings[] = {
        {1, "dummy reason string"},
        {0, NULL}
    };

    return reason_strings;
}

static const OSSL_DISPATCH p_test_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))p_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))p_get_params },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
        (void (*)(void))p_get_reason_strings},
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))p_teardown },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    P_TEST_CTX *ctx;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            c_new_error = OSSL_FUNC_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            c_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            c_vset_error = OSSL_FUNC_core_vset_error(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    /*
     * We want to test that libcrypto doesn't use the file and func pointers
     * that we provide to it via c_set_error_debug beyond the time that they
     * are valid for. Therefore we dynamically allocate these strings now and
     * free them again when the provider is torn down. If anything tries to
     * use those strings after that point there will be a use-after-free and
     * asan will complain (and hence the tests will fail).
     * This file isn't linked against libcrypto, so we use malloc and strdup
     * instead of OPENSSL_malloc and OPENSSL_strdup
     */
    ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;
    ctx->thisfile = strdup(OPENSSL_FILE);
    ctx->thisfunc = strdup(OPENSSL_FUNC);
    ctx->handle = handle;

    /*
     * Set a spurious error to check error handling works correctly. This will
     * be ignored
     */
    p_set_error(ERR_LIB_PROV, 1, ctx->thisfile, OPENSSL_LINE, ctx->thisfunc, NULL);

    *provctx = (void *)ctx;
    *out = p_test_table;
    return 1;
}

static void p_teardown(void *provctx)
{
    P_TEST_CTX *ctx = (P_TEST_CTX *)provctx;

    free(ctx->thisfile);
    free(ctx->thisfunc);
    free(ctx);
}
