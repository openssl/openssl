/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
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
# define Otls_provider_init PROVIDER_INIT_FUNCTION_NAME
#endif

#include <opentls/core.h>
#include <opentls/core_numbers.h>

static Otls_core_gettable_params_fn *c_gettable_params = NULL;
static Otls_core_get_params_fn *c_get_params = NULL;

/* Tell the core what params we provide and what type they are */
static const Otls_PARAM p_param_types[] = {
    { "greeting", Otls_PARAM_UTF8_STRING, NULL, 0, 0 },
    { NULL, 0, NULL, 0, 0 }
};

/* This is a trick to ensure we define the provider functions correctly */
static Otls_provider_gettable_params_fn p_gettable_params;
static Otls_provider_get_params_fn p_get_params;

static const Otls_PARAM *p_gettable_params(void *_)
{
    return p_param_types;
}

static int p_get_params(void *vprov, Otls_PARAM params[])
{
    const Otls_PROVIDER *prov = vprov;
    Otls_PARAM *p = params;
    int ok = 1;

    for (; ok && p->key != NULL; p++) {
        if (strcmp(p->key, "greeting") == 0) {
            static char *opentlsv;
            static char *provname;
            static char *greeting;
            static Otls_PARAM counter_request[] = {
                /* Known libcrypto provided parameters */
                { "opentls-version", Otls_PARAM_UTF8_PTR,
                  &opentlsv, sizeof(&opentlsv), 0 },
                { "provider-name", Otls_PARAM_UTF8_PTR,
                  &provname, sizeof(&provname), 0},

                /* This might be present, if there's such a configuration */
                { "greeting", Otls_PARAM_UTF8_PTR,
                  &greeting, sizeof(&greeting), 0 },

                { NULL, 0, NULL, 0, 0 }
            };
            char buf[256];
            size_t buf_l;

            opentlsv = provname = greeting = NULL;

            if (c_get_params(prov, counter_request)) {
                if (greeting) {
                    strcpy(buf, greeting);
                } else {
                    const char *versionp = *(void **)counter_request[0].data;
                    const char *namep = *(void **)counter_request[1].data;

                    sprintf(buf, "Hello Opentls %.20s, greetings from %s!",
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

static const Otls_DISPATCH p_test_table[] = {
    { Otls_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))p_gettable_params },
    { Otls_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))p_get_params },
    { 0, NULL }
};

int Otls_provider_init(const Otls_PROVIDER *provider,
                       const Otls_DISPATCH *in,
                       const Otls_DISPATCH **out,
                       void **provctx)
{
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case Otls_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = Otls_get_core_gettable_params(in);
            break;
        case Otls_FUNC_CORE_GET_PARAMS:
            c_get_params = Otls_get_core_get_params(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    /* Because we use this in get_params, we need to pass it back */
    *provctx = (void *)provider;

    *out = p_test_table;
    return 1;
}
