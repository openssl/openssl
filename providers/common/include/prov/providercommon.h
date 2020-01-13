/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/provider.h>

const Otls_PROVIDER *FIPS_get_provider(OPENtls_CTX *ctx);

const char *otls_prov_util_nid_to_name(int nid);

int cipher_capable_aes_cbc_hmac_sha1(void);
int cipher_capable_aes_cbc_hmac_sha256(void);
