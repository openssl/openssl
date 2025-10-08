/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_FN_H
#define OPENSSL_FN_H
#pragma once

#include <stddef.h>
#include <openssl/opensslconf.h>
#include <openssl/bn_limbs.h>
#include "crypto/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @type OSSL_FN_ULONG is the type for the OSSL_FN limb.  It's made to be
 * compatible with BN_ULONG (quite literally).
 *
 * @def OSSL_FN_BYTES is defined with the size of OSSL_FN_ULONG, measured in
 * bytes.  This is mainly useful where 'sizeof(OSSL_FN_ULONG)' isn't suitable,
 * such as the C pre-processor.
 */

#ifdef BN_ULONG
typedef BN_ULONG OSSL_FN_ULONG;
#define OSSL_FN_BYTES BN_BYTES
#endif

#ifndef OSSL_FN_BYTES
#error "OpenSSL doesn't support large numbers on this platform"
#endif

/*
 * For practical reasons, we allow allocating OSSL_FNs in terms of limbs (what
 * the BIGNUM library calls "words"), bytes and bits.  The number of bytes and
 * bits are rounded up to the number of limbs that can fit them.
 */

/**
 * Allocate an OSSL_FN in memory.
 *
 * @param[in]   size    The number of limbs for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_new_limbs(size_t size);

/**
 * Allocate an OSSL_FN in secure memory.
 *
 * @param[in]   size    The number of limbs for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_secure_new_limbs(size_t size);

/**
 * Allocate an OSSL_FN in memory.
 *
 * @param[in]   size    The number of bytes for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_new_bytes(size_t size);

/**
 * Allocate an OSSL_FN in secure memory.
 *
 * @param[in]   size    The number of bytes for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_secure_new_bytes(size_t size);

/**
 * Allocate an OSSL_FN in memory.
 *
 * @param[in]   size    The number of bits for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_new_bits(size_t size);

/**
 * Allocate an OSSL_FN in secure memory.
 *
 * @param[in]   size    The number of bits for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_secure_new_bits(size_t size);

/**
 * Free an OSSL_FN instance if it was dynamically allocated.
 * Free it securely if it was allocated securely.
 *
 * @param[in]   f       The OSSL_FN instance to be freed.
 */
void OSSL_FN_free(OSSL_FN *f);

/**
 * Cleanse and free an OSSL_FN instance if it was dynamically allocated.
 * Cleanse and free it securely if it was allocated securely.
 * Merely cleanse it if it was not dynamically allocated.
 *
 * @param[in]   f       The OSSL_FN instance to be freed.
 */
void OSSL_FN_clear_free(OSSL_FN *f);

#ifdef __cplusplus
}
#endif

#endif
