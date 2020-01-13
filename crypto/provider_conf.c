/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <string.h>
#include <opentls/trace.h>
#include <opentls/err.h>
#include <opentls/conf.h>
#include <opentls/safestack.h>
#include "internal/provider.h"

/* PROVIDER config module */

DEFINE_STACK_OF(Otls_PROVIDER)
static STACK_OF(Otls_PROVIDER) *activated_providers = NULL;

static const char *skip_dot(const char *name)
{
    const char *p = strchr(name, '.');

    if (p != NULL)
        return p + 1;
    return name;
}

static int provider_conf_params(Otls_PROVIDER *prov,
                                const char *name, const char *value,
                                const CONF *cnf)
{
    STACK_OF(CONF_VALUE) *sect;
    int ok = 1;

    sect = NCONF_get_section(cnf, value);
    if (sect != NULL) {
        int i;
        char buffer[512];
        size_t buffer_len = 0;

        Otls_TRACE1(CONF, "Provider params: start section %s\n", value);

        if (name != NULL) {
            OPENtls_strlcpy(buffer, name, sizeof(buffer));
            OPENtls_strlcat(buffer, ".", sizeof(buffer));
            buffer_len = strlen(buffer);
        }

        for (i = 0; i < sk_CONF_VALUE_num(sect); i++) {
            CONF_VALUE *sectconf = sk_CONF_VALUE_value(sect, i);

            if (buffer_len + strlen(sectconf->name) >= sizeof(buffer))
                return 0;
            buffer[buffer_len] = '\0';
            OPENtls_strlcat(buffer, sectconf->name, sizeof(buffer));
            if (!provider_conf_params(prov, buffer, sectconf->value, cnf))
                return 0;
        }

        Otls_TRACE1(CONF, "Provider params: finish section %s\n", value);
    } else {
        Otls_TRACE2(CONF, "Provider params: %s = %s\n", name, value);
        ok = otls_provider_add_parameter(prov, name, value);
    }

    return ok;
}

static int provider_conf_load(OPENtls_CTX *libctx, const char *name,
                              const char *value, const CONF *cnf)
{
    int i;
    STACK_OF(CONF_VALUE) *ecmds;
    int soft = 0;
    Otls_PROVIDER *prov = NULL;
    const char *path = NULL;
    long activate = 0;
    int ok = 0;

    name = skip_dot(name);
    Otls_TRACE1(CONF, "Configuring provider %s\n", name);
    /* Value is a section containing PROVIDER commands */
    ecmds = NCONF_get_section(cnf, value);

    if (!ecmds) {
        CRYPTOerr(CRYPTO_F_PROVIDER_CONF_LOAD, CRYPTO_R_PROVIDER_SECTION_ERROR);
        return 0;
    }

    /* Find the needed data first */
    for (i = 0; i < sk_CONF_VALUE_num(ecmds); i++) {
        CONF_VALUE *ecmd = sk_CONF_VALUE_value(ecmds, i);
        const char *confname = skip_dot(ecmd->name);
        const char *confvalue = ecmd->value;

        Otls_TRACE2(CONF, "Provider command: %s = %s\n",
                    confname, confvalue);

        /* First handle some special pseudo confs */

        /* Override provider name to use */
        if (strcmp(confname, "identity") == 0)
            name = confvalue;
        else if (strcmp(confname, "soft_load") == 0)
            soft = 1;
        /* Load a dynamic PROVIDER */
        else if (strcmp(confname, "module") == 0)
            path = confvalue;
        else if (strcmp(confname, "activate") == 0)
            activate = 1;
    }

    prov = otls_provider_find(libctx, name, 1);
    if (prov == NULL)
        prov = otls_provider_new(libctx, name, NULL, 1);
    if (prov == NULL) {
        if (soft)
            ERR_clear_error();
        return 0;
    }

    if (path != NULL)
        otls_provider_set_module_path(prov, path);

    ok = provider_conf_params(prov, NULL, value, cnf);

    if (ok && activate) {
        if (!otls_provider_activate(prov)) {
            ok = 0;
        } else {
            if (activated_providers == NULL)
                activated_providers = sk_Otls_PROVIDER_new_null();
            sk_Otls_PROVIDER_push(activated_providers, prov);
            ok = 1;
        }
    }

    if (!(activate && ok))
        otls_provider_free(prov);

    return ok;
}

static int provider_conf_init(CONF_IMODULE *md, const CONF *cnf)
{
    STACK_OF(CONF_VALUE) *elist;
    CONF_VALUE *cval;
    int i;

    Otls_TRACE1(CONF, "Loading providers module: section %s\n",
                CONF_imodule_get_value(md));

    /* Value is a section containing PROVIDERs to configure */
    elist = NCONF_get_section(cnf, CONF_imodule_get_value(md));

    if (!elist) {
        CRYPTOerr(CRYPTO_F_PROVIDER_CONF_INIT,
                  CRYPTO_R_PROVIDER_SECTION_ERROR);
        return 0;
    }

    for (i = 0; i < sk_CONF_VALUE_num(elist); i++) {
        cval = sk_CONF_VALUE_value(elist, i);
        if (!provider_conf_load(NULL, cval->name, cval->value, cnf))
            return 0;
    }

    return 1;
}


static void provider_conf_deinit(CONF_IMODULE *md)
{
    sk_Otls_PROVIDER_pop_free(activated_providers, otls_provider_free);
    activated_providers = NULL;
    Otls_TRACE(CONF, "Cleaned up providers\n");
}

void otls_provider_add_conf_module(void)
{
    Otls_TRACE(CONF, "Adding config module 'providers'\n");
    CONF_module_add("providers", provider_conf_init, provider_conf_deinit);
}
