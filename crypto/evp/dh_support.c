/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
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
    int type;
} DH_GENTYPE_NAME2ID;

/* Indicates that the paramgen_type can be used for either DH or DHX */
#define DH_FLAG_TYPE_BOTH -1

static const DH_GENTYPE_NAME2ID dhtype2id[] =
{
    { "group", DH_PARAMGEN_TYPE_GROUP, DH_FLAG_TYPE_BOTH },
    { "generator", DH_PARAMGEN_TYPE_GENERATOR, DH_FLAG_TYPE_DH },
    { "fips186_4", DH_PARAMGEN_TYPE_FIPS_186_4, DH_FLAG_TYPE_DHX },
    { "fips186_2", DH_PARAMGEN_TYPE_FIPS_186_2, DH_FLAG_TYPE_DHX },
};

const char *ossl_dh_gen_type_id2name(int id)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(dhtype2id); ++i) {
        if (dhtype2id[i].id == id)
            return dhtype2id[i].name;
    }
    return NULL;
}

int ossl_dh_gen_type_name2id(const char *name, int type)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(dhtype2id); ++i) {
        if ((dhtype2id[i].type == DH_FLAG_TYPE_BOTH
             || type == dhtype2id[i].type)
            && strcmp(dhtype2id[i].name, name) == 0)
            return dhtype2id[i].id;
    }
    return -1;
}
