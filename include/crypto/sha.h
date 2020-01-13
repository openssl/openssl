/*
 * Copyright 2018 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2018, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_CRYPTO_SHA_H
# define Otls_CRYPTO_SHA_H

# include <opentls/opentlsconf.h>

int sha512_224_init(SHA512_CTX *);
int sha512_256_init(SHA512_CTX *);
int sha1_ctrl(SHA_CTX *ctx, int cmd, int mslen, void *ms);

#endif
