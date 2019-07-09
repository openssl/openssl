/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


struct conf_method_st {
    const char *name;
    CONF *(*create) (CONF_METHOD *meth);
    int (*init) (CONF *conf);
    int (*destroy) (CONF *conf);
    int (*destroy_data) (CONF *conf);
    int (*load_bio) (CONF *conf, BIO *bp, long *eline);
    int (*dump) (const CONF *conf, BIO *bp);
    int (*is_number) (const CONF *conf, char c);
    int (*to_int) (const CONF *conf, char c);
    int (*load) (CONF *conf, const char *name, long *eline);
};

/* Functions implementing the internal CONF/NCONF functionality. */
int conf_new_data(CONF *conf);
void conf_free_data(CONF *conf);
CONF_VALUE *conf_new_section(CONF *conf, const char *section);
CONF_VALUE *conf_get_section(const CONF *conf, const char *section);
STACK_OF(CONF_VALUE) *conf_get_section_values(const CONF *conf,
                                              const char *section);
int conf_add_string(CONF *conf, CONF_VALUE *section, CONF_VALUE *value);
char *conf_get_string(const CONF *conf, const char *section, const char *name);

/* Functions to load modules. */
void conf_add_ssl_module(void);
