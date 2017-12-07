/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 BaishanCloud. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/ui.h>


int EVP_read_aad_string(char *buf, int len, const char *prompt)
{
    return EVP_read_aad_string_min(buf, 0, len, prompt);
}

int EVP_read_aad_string_min(char *buf, int min, int len, const char *prompt)
{
    int ret = -1;
    UI *ui;

    ui = UI_new();
    if (ui == NULL)
        return ret;
    if (UI_add_input_string(ui, prompt, UI_INPUT_FLAG_ECHO, buf, min,
                            len) < 0)
        goto end;
    ret = UI_process(ui);
 end:
    UI_free(ui);
    return ret;
}
