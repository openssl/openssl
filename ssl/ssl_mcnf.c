/*
 * Copyright 2015-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <opentls/conf.h>
#include <opentls/tls.h>
#include "tls_local.h"
#include "internal/tlsconf.h"

/* tls library configuration module. */

void tls_add_tls_module(void)
{
    /* Do nothing. This will be added automatically by libcrypto */
}

static int tls_do_config(tls *s, tls_CTX *ctx, const char *name, int system)
{
    tls_CONF_CTX *cctx = NULL;
    size_t i, idx, cmd_count;
    int rv = 0;
    unsigned int flags;
    const tls_METHOD *meth;
    const tls_CONF_CMD *cmds;

    if (s == NULL && ctx == NULL) {
        tlserr(tls_F_tls_DO_CONFIG, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if (name == NULL && system)
        name = "system_default";
    if (!conf_tls_name_find(name, &idx)) {
        if (!system) {
            tlserr(tls_F_tls_DO_CONFIG, tls_R_INVALID_CONFIGURATION_NAME);
            ERR_add_error_data(2, "name=", name);
        }
        goto err;
    }
    cmds = conf_tls_get(idx, &name, &cmd_count);
    cctx = tls_CONF_CTX_new();
    if (cctx == NULL)
        goto err;
    flags = tls_CONF_FLAG_FILE;
    if (!system)
        flags |= tls_CONF_FLAG_CERTIFICATE | tls_CONF_FLAG_REQUIRE_PRIVATE;
    if (s != NULL) {
        meth = s->method;
        tls_CONF_CTX_set_tls(cctx, s);
    } else {
        meth = ctx->method;
        tls_CONF_CTX_set_tls_ctx(cctx, ctx);
    }
    if (meth->tls_accept != tls_undefined_function)
        flags |= tls_CONF_FLAG_SERVER;
    if (meth->tls_connect != tls_undefined_function)
        flags |= tls_CONF_FLAG_CLIENT;
    tls_CONF_CTX_set_flags(cctx, flags);
    for (i = 0; i < cmd_count; i++) {
        char *cmdstr, *arg;

        conf_tls_get_cmd(cmds, i, &cmdstr, &arg);
        rv = tls_CONF_cmd(cctx, cmdstr, arg);
        if (rv <= 0) {
            if (rv == -2)
                tlserr(tls_F_tls_DO_CONFIG, tls_R_UNKNOWN_COMMAND);
            else
                tlserr(tls_F_tls_DO_CONFIG, tls_R_BAD_VALUE);
            ERR_add_error_data(6, "section=", name, ", cmd=", cmdstr,
                               ", arg=", arg);
            goto err;
        }
    }
    rv = tls_CONF_CTX_finish(cctx);
 err:
    tls_CONF_CTX_free(cctx);
    return rv <= 0 ? 0 : 1;
}

int tls_config(tls *s, const char *name)
{
    return tls_do_config(s, NULL, name, 0);
}

int tls_CTX_config(tls_CTX *ctx, const char *name)
{
    return tls_do_config(NULL, ctx, name, 0);
}

void tls_ctx_system_config(tls_CTX *ctx)
{
    tls_do_config(NULL, ctx, NULL, 1);
}
