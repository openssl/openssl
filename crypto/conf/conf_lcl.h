/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef  HEADER_CONF_LCL_H
# define HEADER_CONF_LCL_H

# include <openssl/lhash.h>
# include <openssl/conf.h>

#ifdef  __cplusplus
extern "C" {
#endif

CONF_VALUE *conf_new_section(CONF *conf, const char *section);
CONF_VALUE *conf_get_section(const CONF *conf, const char *section);
STACK_OF(CONF_VALUE) *conf_get_section_values(const CONF *conf,
                                              const char *section);

int conf_add_string(CONF *conf, CONF_VALUE *section, CONF_VALUE *value);
char *conf_get_string(const CONF *conf, const char *section,
                      const char *name);
long conf_get_number(const CONF *conf, const char *section,
                     const char *name);

int conf_new_data(CONF *conf);
void conf_free_data(CONF *conf);

void conf_add_ssl_module(void);

#ifdef  __cplusplus
}
#endif
#endif
