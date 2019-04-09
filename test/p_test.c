/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
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

#include <openssl/core.h>
#include <openssl/core_numbers.h>

static OSSL_core_get_param_types_fn *c_get_param_types = NULL;
static OSSL_core_get_params_fn *c_get_params = NULL;

/* Tell the core what params we provide and what type they are */
static const OSSL_ITEM p_param_types[] = {
    { OSSL_PARAM_UTF8_STRING, "greeting" },
    { 0, NULL }
};

static const OSSL_ITEM *p_get_param_types(const OSSL_PROVIDER *_)
{
    return p_param_types;
}

static int p_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
{
    const OSSL_PARAM *p = params;
    int ok = 1;

    for (; ok && p->key != NULL; p++) {
        if (strcmp(p->key, "greeting") == 0) {
            static char *opensslv = NULL;
            static char *provname = NULL;
            static char *greeting = NULL;
            static OSSL_PARAM counter_request[] = {
                /* Known libcrypto provided parameters */
                { "openssl-version", OSSL_PARAM_UTF8_PTR,
                  &opensslv, sizeof(&opensslv), NULL },
                { "provider-name", OSSL_PARAM_UTF8_PTR,
                  &provname, sizeof(&provname), NULL},

                /* This might be present, if there's such a configuration */
                { "greeting", OSSL_PARAM_UTF8_PTR,
                  &greeting, sizeof(&greeting), NULL },

                { NULL, 0, NULL, 0, NULL }
            };
            char buf[256];
            size_t buf_l;

            if (c_get_params(prov, counter_request)) {
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

            *p->return_size = buf_l = strlen(buf) + 1;
            if (p->data_size >= buf_l)
                strncpy(p->data, buf, buf_l);
            else
                ok = 0;
        }
    }
    return ok;
}

static const OSSL_DISPATCH p_test_table[] = {
    { OSSL_FUNC_PROVIDER_GET_PARAM_TYPES, (void (*)(void))p_get_param_types },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))p_get_params },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out)
{
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAM_TYPES:
            c_get_param_types = OSSL_get_core_get_param_types(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_get_core_get_params(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    *out = p_test_table;
    return 1;
}
