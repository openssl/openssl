/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Here is a set of wrappers for the ENGINE API, which are no-ops when the
 * ENGINE API is disabled / removed.
 * We need to suppress deprecation warnings to make this work.
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/types.h> /* Ensure we have the ENGINE type, regardless */
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include "apps.h"

#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a shareable library */
static ENGINE *try_load_engine(const char *engine)
{
    ENGINE *e = NULL;

    if ((e = ENGINE_by_id("dynamic")) != NULL) {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}
#endif

ENGINE *setup_engine_methods(const char *id, unsigned int methods, int debug)
{
    ENGINE *e = NULL;

#ifndef OPENSSL_NO_ENGINE
    if (id != NULL) {
        if (strcmp(id, "auto") == 0) {
            BIO_printf(bio_err, "Enabling auto ENGINE support\n");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(id)) == NULL
            && (e = try_load_engine(id)) == NULL) {
            BIO_printf(bio_err, "Invalid engine \"%s\"\n", id);
            ERR_print_errors(bio_err);
            return NULL;
        }
        if (debug)
            (void)ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio_err, 0);
        if (!ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0,
                             (void *)get_ui_method(), 0, 1)
                || !ENGINE_set_default(e, methods)) {
            BIO_printf(bio_err, "Cannot use engine \"%s\"\n", ENGINE_get_id(e));
            ERR_print_errors(bio_err);
            ENGINE_free(e);
            return NULL;
        }

        BIO_printf(bio_err, "Engine \"%s\" set.\n", ENGINE_get_id(e));
    }
#endif
    return e;
}

void release_engine(ENGINE *e)
{
#ifndef OPENSSL_NO_ENGINE
    /* Free our "structural" reference. */
    ENGINE_free(e);
#endif
}

int init_engine(ENGINE *e)
{
    int rv = 1;

#ifndef OPENSSL_NO_ENGINE
    rv = ENGINE_init(e);
#endif
    return rv;
}

int finish_engine(ENGINE *e)
{
    int rv = 1;

#ifndef OPENSSL_NO_ENGINE
    rv = ENGINE_finish(e);
#endif
    return rv;
}

EVP_PKEY *load_engine_private_key(ENGINE *e, const char *keyid,
                                  const char *pass, const char *desc)
{
    EVP_PKEY *rv = NULL;

#ifndef OPENSSL_NO_ENGINE
    if (init_engine(e)) {
        PW_CB_DATA cb_data;

        cb_data.password = pass;
        cb_data.prompt_info = keyid;

        rv = ENGINE_load_private_key(e, keyid,
                                     (UI_METHOD *)get_ui_method(), &cb_data);
        finish_engine(e);
    }
#else
    BIO_printf(bio_err, "Engines not supported for loading %s\n", desc);
#endif
    return rv;
}

EVP_PKEY *load_engine_public_key(ENGINE *e, const char *keyid,
                                 const char *pass, const char *desc)
{
    EVP_PKEY *rv = NULL;

#ifndef OPENSSL_NO_ENGINE
    if (init_engine(e)) {
        PW_CB_DATA cb_data;

        cb_data.password = pass;
        cb_data.prompt_info = keyid;

        rv = ENGINE_load_public_key(e, keyid,
                                    (UI_METHOD *)get_ui_method(), &cb_data);
        finish_engine(e);
    }
#else
    BIO_printf(bio_err, "Engines not supported for loading %s\n", desc);
#endif
    return rv;
}

