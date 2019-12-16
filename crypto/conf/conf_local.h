/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

void conf_add_ssl_module(void);

CONF_VALUE *_CONF_get_section(const CONF *conf, const char *section);
char *_CONF_get_string(const CONF *conf, const char *section, const char *name);
