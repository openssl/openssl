/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_IDEA
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "crypto/evp.h"
#include <openssl/idea.h>
#include "evp_local.h"

BLOCK_CIPHER_defs(idea, IDEA_KEY_SCHEDULE, NID_idea, 8, 16, 8, 64,
    0)

#endif
