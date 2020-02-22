/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/params.h>
#include "self_test.h"

static void self_test_event_setparams(OSSL_ST_EVENT *ev)
{
    size_t n = 0;

    if (ev->cb != NULL) {
        ev->params[n++] =
            OSSL_PARAM_construct_utf8_string(OSSL_PROV_PARAM_SELF_TEST_PHASE,
                                             (char *)ev->phase, 0);
        ev->params[n++] =
            OSSL_PARAM_construct_utf8_string(OSSL_PROV_PARAM_SELF_TEST_TYPE,
                                             (char *)ev->type, 0);
        ev->params[n++] =
            OSSL_PARAM_construct_utf8_string(OSSL_PROV_PARAM_SELF_TEST_DESC,
                                             (char *)ev->desc, 0);
    }
    ev->params[n++] = OSSL_PARAM_construct_end();
}

void SELF_TEST_EVENT_init(OSSL_ST_EVENT *ev, OSSL_CALLBACK *cb, void *cbarg)
{
    if (ev == NULL)
        return;

    ev->cb = cb;
    ev->cb_arg = cbarg;
    ev->phase = "";
    ev->type = "";
    ev->desc = "";
    self_test_event_setparams(ev);
}

/* Can be used during application testing to log that a test has started. */
void SELF_TEST_EVENT_onbegin(OSSL_ST_EVENT *ev, const char *type,
                             const char *desc)
{
    if (ev != NULL && ev->cb != NULL) {
        ev->phase = OSSL_SELF_TEST_PHASE_START;
        ev->type = type;
        ev->desc = desc;
        self_test_event_setparams(ev);
        (void)ev->cb(ev->params, ev->cb_arg);
    }
}

/*
 * Can be used during application testing to log that a test has either
 * passed or failed.
 */
void SELF_TEST_EVENT_onend(OSSL_ST_EVENT *ev, int ret)
{
    if (ev != NULL && ev->cb != NULL) {
        ev->phase =
            (ret == 1 ? OSSL_SELF_TEST_PHASE_PASS : OSSL_SELF_TEST_PHASE_FAIL);
        self_test_event_setparams(ev);
        (void)ev->cb(ev->params, ev->cb_arg);

        ev->phase = OSSL_SELF_TEST_PHASE_NONE;
        ev->type = OSSL_SELF_TEST_TYPE_NONE;
        ev->desc = OSSL_SELF_TEST_DESC_NONE;
    }
}

/*
 * Used for failure testing.
 *
 * Call the applications SELF_TEST_cb() if it exists.
 * If the application callback decides to return 0 then the first byte of 'bytes'
 * is modified (corrupted). This is used to modify output signatures or
 * ciphertext before they are verified or decrypted.
 */
void SELF_TEST_EVENT_oncorrupt_byte(OSSL_ST_EVENT *ev, unsigned char *bytes)
{
    if (ev != NULL && ev->cb != NULL) {
        ev->phase = OSSL_SELF_TEST_PHASE_CORRUPT;
        self_test_event_setparams(ev);
        if (!ev->cb(ev->params, ev->cb_arg))
            bytes[0] ^= 1;
    }
}

