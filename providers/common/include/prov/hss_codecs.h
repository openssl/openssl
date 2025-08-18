/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef PROV_HSS_CODECS_H
# define PROV_HSS_CODECS_H
# pragma once

# ifndef OPENSSL_NO_HSS
#  include <openssl/e_os2.h>
#  include "crypto/hss.h"
#  include "prov/provider_ctx.h"

__owur
HSS_KEY *ossl_hss_d2i_PUBKEY(const uint8_t *pubenc, int publen,
                             int evp_type, PROV_CTX *provctx,
                             const char *propq);
__owur
int ossl_hss_i2d_pubkey(const HSS_KEY *key, unsigned char **out);

__owur
int ossl_hss_key_to_text(BIO *out, const HSS_KEY *key, int selection);

# endif /* OPENSSL_NO_HSS */
#endif  /* PROV_HSS_CODECS_H */
