/*
 * Copyright 2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_INTERNAL_tlsCONF_H
# define Otls_INTERNAL_tlsCONF_H

typedef struct tls_conf_cmd_st tls_CONF_CMD;

const tls_CONF_CMD *conf_tls_get(size_t idx, const char **name, size_t *cnt);
int conf_tls_name_find(const char *name, size_t *idx);
void conf_tls_get_cmd(const tls_CONF_CMD *cmd, size_t idx, char **cmdstr,
                      char **arg);

#endif
