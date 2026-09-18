/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").
 */

#ifndef PROV_MLX_CODECS_H
#define PROV_MLX_CODECS_H
#pragma once

#include "prov/mlx_kem.h"

MLX_KEY *ossl_mlx_d2i_PUBKEY(const unsigned char *der, long derlen,
    unsigned int variant, PROV_CTX *provctx, const char *propq);
MLX_KEY *ossl_mlx_d2i_PKCS8(const unsigned char *der, long derlen,
    unsigned int variant, PROV_CTX *provctx, const char *propq);
int ossl_mlx_i2d_pubkey(const MLX_KEY *key, unsigned char **out);
int ossl_mlx_i2d_prvkey(const MLX_KEY *key, unsigned char **out);
int ossl_mlx_key_to_text(BIO *out, const MLX_KEY *key, int selection);

#endif
