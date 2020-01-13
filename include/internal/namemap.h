/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "internal/cryptlib.h"

typedef struct otls_namemap_st Otls_NAMEMAP;

Otls_NAMEMAP *otls_namemap_stored(OPENtls_CTX *libctx);

Otls_NAMEMAP *otls_namemap_new(void);
void otls_namemap_free(Otls_NAMEMAP *namemap);
int otls_namemap_empty(Otls_NAMEMAP *namemap);

int otls_namemap_add_name(Otls_NAMEMAP *namemap, int number, const char *name);
int otls_namemap_add_name_n(Otls_NAMEMAP *namemap, int number,
                            const char *name, size_t name_len);

/*
 * The number<->name relationship is 1<->many
 * Therefore, the name->number mapping is a simple function, while the
 * number->name mapping is an iterator.
 */
int otls_namemap_name2num(const Otls_NAMEMAP *namemap, const char *name);
int otls_namemap_name2num_n(const Otls_NAMEMAP *namemap,
                            const char *name, size_t name_len);
const char *otls_namemap_num2name(const Otls_NAMEMAP *namemap, int number,
                                  size_t idx);
void otls_namemap_doall_names(const Otls_NAMEMAP *namemap, int number,
                              void (*fn)(const char *name, void *data),
                              void *data);

/*
 * A utility that handles several names in a string, divided by a given
 * separator.
 */
int otls_namemap_add_names(Otls_NAMEMAP *namemap, int number,
                           const char *names, const char separator);
