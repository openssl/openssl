/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef APPS_FUNCTION_H
# define APPS_FUNCTION_H

# include <openssl/lhash.h>
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
#endif
