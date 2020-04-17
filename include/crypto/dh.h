/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/dh.h>
#include "internal/ffc.h"

DH *dh_new_by_nid_with_libctx(OPENSSL_CTX *libctx, int nid);
DH *dh_new_with_libctx(OPENSSL_CTX *libctx);

int dh_generate_ffc_parameters(DH *dh, int type, int pbits,
                               int qbits, EVP_MD *md, BN_GENCB *cb);
int dh_generate_public_key(BN_CTX *ctx, DH *dh, const BIGNUM *priv_key,
                           BIGNUM *pub_key);
int dh_get_named_group_uid_from_size(int pbits);
const char *dh_gen_type_id2name(int id);
void dh_cache_named_group(DH *dh);

FFC_PARAMS *dh_get0_params(DH *dh);
int dh_get0_nid(const DH *dh);
int dh_ffc_params_fromdata(DH *dh, const OSSL_PARAM params[]);
int dh_key_fromdata(DH *dh, const OSSL_PARAM params[]);

int dh_check_pub_key_partial(const DH *dh, const BIGNUM *pub_key, int *ret);
int dh_check_priv_key(const DH *dh, const BIGNUM *priv_key, int *ret);
int dh_check_pairwise(DH *dh);

const DH_METHOD *dh_get_method(const DH *dh);
