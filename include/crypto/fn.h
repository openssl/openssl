/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_FN_H
# define OPENSSL_FN_H
# pragma once

# include <stddef.h>
# include <openssl/opensslconf.h>
# include <openssl/bn_limbs.h>
# include <openssl/types.h>
# include "crypto/types.h"

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * @type OSSL_FN_ULONG is the type for the OSSL_FN limb.  It's made to be
 * compatible with BN_ULONG (quite literally).
 *
 * @def OSSL_FN_BYTES is defined with the size of OSSL_FN_ULONG, measured in
 * bytes.  This is mainly useful where 'sizeof(OSSL_FN_ULONG)' isn't suitable,
 * such as the C pre-processor.
 */

# ifdef BN_ULONG
typedef BN_ULONG OSSL_FN_ULONG;
#  define OSSL_FN_BYTES         BN_BYTES
# endif

# ifndef OSSL_FN_BYTES
#  error "OpenSSL doesn't support large numbers on this platform"
# endif

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

/**
 * Cleanse the data of an OSSL_FN instance, effectively making it zero.
 *
 * @param[in]   f       The OSSL_FN instance to be cleared.
 */
void OSSL_FN_clear(OSSL_FN *f);

/**
 * Allocate a new OSSL_FN_CTX, given a set of input numbers.
 *
 * @param[in]   libctx          OpenSSL library context (currently unused)
 * @param[in]   arena_size      Maximum number of bytes consumed in the arena.
 *                              This must have enough space for the maximum
 *                              number of simultaneously active frames, active
 *                              OSSL_FNs, as well as the maximum total number
 *                              of active OSSL_FN limbs.
 * @returns     An allocated OSSL_FN_CTX, or NULL on error.
 **/
OSSL_FN_CTX *OSSL_FN_CTX_new(OSSL_LIB_CTX *libctx, size_t arena_size);

/**
 * Allocate a new OSSL_FN_CTX in secure memory, given a set of input numbers.
 * Other than allocating in secure memory, this function does exactly the same
 * thing as OSSL_FN_CTX_new().
 **/
OSSL_FN_CTX *OSSL_FN_CTX_secure_new(OSSL_LIB_CTX *libctx, size_t arena_size);

/**
 * Free an OSSL_FN_CTX.
 *
 * @param[in]   ctx     The OSSL_FN_CTX to be freed.  This may be NULL.
 */
void OSSL_FN_CTX_free(OSSL_FN_CTX *ctx);

/**
 * Start a new OSSL_FN_CTX frame.  This *must* be called by any function
 * that wants to get a temporary OSSL_FN from the OSSL_FN_CTX.  The function
 * call this must also clean up with a OSSL_FN_CTX_end() call.
 *
 * @param[in]   ctx     The OSSL_FN_CTX to start the frame in.
 * @returns     1 on success, 0 on error.
 */
int OSSL_FN_CTX_start(OSSL_FN_CTX *ctx);

/**
 * End the last OSSL_FN_CTX frame, resetting back to the previous
 * frame.  If a function called OSSL_FN_CTX_start(), it *must* call
 * this function before returning.
 *
 * @param[in]   ctx     The OSSL_FN_CTX to start the frame in.
 * @returns     1 on success, 0 on error.
 */
int OSSL_FN_CTX_end(OSSL_FN_CTX *ctx);

/**
 * Get a suitably sized OSSL_FN from an OSSL_FN_CTX.
 *
 * @param[in]   ctx     The OSSL_FN_CTX
 * @param[in]   limbs   The desired size of the resulting OSSL_FN,
 *                      in number of limbs.
 * @returns     an OSSL_FN pointer on success, NULL on error.
 */
OSSL_FN *OSSL_FN_CTX_get_limbs(OSSL_FN_CTX *ctx, size_t limbs);

/**
 * Get a suitably sized OSSL_FN from an OSSL_FN_CTX.
 *
 * @param[in]   ctx     The OSSL_FN_CTX
 * @param[in]   limbs   The desired size of the resulting OSSL_FN,
 *                      in number of bytes.
 * @returns     an OSSL_FN pointer on success, NULL on error.
 */
OSSL_FN *OSSL_FN_CTX_get_bytes(OSSL_FN_CTX *ctx, size_t bytes);

/**
 * Get a suitably sized OSSL_FN from an OSSL_FN_CTX.
 *
 * @param[in]   ctx     The OSSL_FN_CTX
 * @param[in]   limbs   The desired size of the resulting OSSL_FN,
 *                      in number of bits.
 * @returns     an OSSL_FN pointer on success, NULL on error.
 */
OSSL_FN *OSSL_FN_CTX_get_bits(OSSL_FN_CTX *ctx, size_t bits);

# ifdef  __cplusplus
}
# endif

#endif
