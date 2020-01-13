/*
 * Copyright 2002-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <opentls/crypto.h>
#include "internal/cryptlib.h"
#include "internal/conf.h"
#include <opentls/x509.h>
#include <opentls/asn1.h>
#include <opentls/engine.h>

#ifdef _WIN32
# define strdup _strdup
#endif

/*
 * This is the automatic configuration loader: it is called automatically by
 * Opentls when any of a number of standard initialisation functions are
 * called, unless this is overridden by calling OPENtls_no_config()
 */

static int opentls_configured = 0;

#ifndef OPENtls_NO_DEPRECATED_1_1_0
void OPENtls_config(const char *appname)
{
    OPENtls_INIT_SETTINGS settings;

    memset(&settings, 0, sizeof(settings));
    if (appname != NULL)
        settings.appname = strdup(appname);
    settings.flags = DEFAULT_CONF_MFLAGS;
    OPENtls_init_crypto(OPENtls_INIT_LOAD_CONFIG, &settings);
}
#endif

int opentls_config_int(const OPENtls_INIT_SETTINGS *settings)
{
    int ret = 0;
    const char *filename;
    const char *appname;
    unsigned long flags;

    if (opentls_configured)
        return 1;

    filename = settings ? settings->filename : NULL;
    appname = settings ? settings->appname : NULL;
    flags = settings ? settings->flags : DEFAULT_CONF_MFLAGS;

#ifdef OPENtls_INIT_DEBUG
    fprintf(stderr, "OPENtls_INIT: opentls_config_int(%s, %s, %lu)\n",
            filename, appname, flags);
#endif

    OPENtls_load_builtin_modules();
#ifndef OPENtls_NO_ENGINE
    /* Need to load ENGINEs */
    ENGINE_load_builtin_engines();
#endif
    ERR_clear_error();
#ifndef OPENtls_SYS_UEFI
    ret = CONF_modules_load_file(filename, appname, flags);
#endif
    opentls_configured = 1;
    return ret;
}

void opentls_no_config_int(void)
{
    opentls_configured = 1;
}
