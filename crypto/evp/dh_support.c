/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h> /* strcmp */
#include <openssl/dh.h>
#include "internal/nelem.h"
#include "crypto/dh.h"

typedef struct dh_name2id_st{
    const char *name;
    int id;
} DH_GENTYPE_NAME2ID;

static const DH_GENTYPE_NAME2ID dhtype2id[]=
{
    { "fips186_4", DH_PARAMGEN_TYPE_FIPS_186_4 },
    { "fips186_2", DH_PARAMGEN_TYPE_FIPS_186_2 },
    { "group", DH_PARAMGEN_TYPE_GROUP },
    { "generator", DH_PARAMGEN_TYPE_GENERATOR }
};

const char *dh_gen_type_id2name(int id)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(dhtype2id); ++i) {
        if (dhtype2id[i].id == id)
            return dhtype2id[i].name;
    }
    return NULL;
}

int dh_gen_type_name2id(const char *name)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(dhtype2id); ++i) {
        if (strcmp(dhtype2id[i].name, name) == 0)
            return dhtype2id[i].id;
    }
    return -1;
}
