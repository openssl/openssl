/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/trace.h>
#include "internal/conf.h"
#include "conf_local.h"

/* Applies the secret_check section, whose only name is a boolean "enabled" */
static int secret_check_conf_init(CONF_IMODULE *md, const CONF *cnf)
{
    const char *section = CONF_imodule_get_value(md);
    STACK_OF(CONF_VALUE) *elist;
    const CONF_VALUE *cval;
    int enabled, i;

    OSSL_TRACE1(CONF, "Loading secret_check module: section %s\n", section);

    if ((elist = NCONF_get_section(cnf, section)) == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_SECRET_CHECK_SECTION_ERROR,
            "section=%s not found", section);
        return 0;
    }
    for (i = 0; i < sk_CONF_VALUE_num(elist); i++) {
        cval = sk_CONF_VALUE_value(elist, i);
        if (strcmp(cval->name, "enabled") != 0
            || !ossl_conf_parse_bool(cval->value, &enabled)) {
            ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_SECRET_CHECK_SECTION_ERROR,
                "name=%s, value=%s", cval->name, cval->value);
            return 0;
        }
        if (!(enabled ? CRYPTO_secret_check_enable()
                      : CRYPTO_secret_check_disable())) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    return 1;
}

void ossl_config_add_secret_check_module(void)
{
    OSSL_TRACE(CONF, "Adding config module 'secret_check'\n");
    CONF_module_add("secret_check", secret_check_conf_init, NULL);
}
