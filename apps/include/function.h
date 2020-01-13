/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_APPS_FUNCTION_H
# define Otls_APPS_FUNCTION_H

# include <opentls/lhash.h>
# include "opt.h"

typedef enum FUNC_TYPE {
    FT_none, FT_general, FT_md, FT_cipher, FT_pkey,
    FT_md_alg, FT_cipher_alg
} FUNC_TYPE;

typedef struct function_st {
    FUNC_TYPE type;
    const char *name;
    int (*func)(int argc, char *argv[]);
    const OPTIONS *help;
} FUNCTION;

DEFINE_LHASH_OF(FUNCTION);

/* Structure to hold the number of columns to be displayed and the
 * field width used to display them.
 */
typedef struct {
    int columns;
    int width;
} DISPLAY_COLUMNS;

void calculate_columns(FUNCTION *functions, DISPLAY_COLUMNS *dc);

#endif
