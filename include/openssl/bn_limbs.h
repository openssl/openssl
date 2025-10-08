/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file Defines the type of large integer limbs.
 *
 * The large number is composed of words, the size of which is assumed to
 * be optimal for the platform it's built for.  In many large number texts,
 * these words are called "limb".  The BIGNUM library also calls this "word".
 *
 * In OpenSSL code, the BIGNUM "limb" is represented with the type macro
 * BN_ULONG.
 */

#ifndef OPENSSL_BN_LIMBS_H
#define OPENSSL_BN_LIMBS_H
#pragma once

#include <openssl/opensslconf.h>

/*
 * 64-bit processor with LP64 ABI
 */
#ifdef SIXTY_FOUR_BIT_LONG
#define BN_ULONG unsigned long
#define BN_BYTES 8
#endif

/*
 * 64-bit processor other than LP64 ABI
 */
#ifdef SIXTY_FOUR_BIT
#define BN_ULONG unsigned long long
#define BN_BYTES 8
#endif

#ifdef THIRTY_TWO_BIT
#define BN_ULONG unsigned int
#define BN_BYTES 4
#endif

#endif
