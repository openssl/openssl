/*
 * Copyright 2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Opentls license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_APPS_UI_H
# define Otls_APPS_UI_H


# define PW_MIN_LENGTH 4
typedef struct pw_cb_data {
    const void *password;
    const char *prompt_info;
} PW_CB_DATA;

int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_data);

int setup_ui_method(void);
void destroy_ui_method(void);
const UI_METHOD *get_ui_method(void);

extern BIO *bio_err;

#endif
