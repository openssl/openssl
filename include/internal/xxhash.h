/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_INTERNAL_XXHASH_H)
#define OSSL_INTERNAL_XXHASH_H

#include "internal/e_os.h"

/**
 * @brief Calculates the non-cryptographic 64-bit XXH3 hash of @p input.
 *
 * @param input The block of data to be hashed, at least @p len bytes in size.
 * @param len   The length of @p input, in bytes.
 * @param seed  The 64-bit seed to alter the hash result predictably.
 *
 * @pre
 *   The memory between @p input and @p input + @p len must be valid,
 *   readable and memory. However, if @p len is `0`, @p input may be
 *   `NULL`.
 *
 * @return The calculated 64-bit XXH3 hash value.
 *
 * @note
 *   seed == 0 uses the fixed default secret; a non-zero seed derives a
 *   custom secret from it for inputs longer than 240 bytes.
 */
uint64_t ossl_xxh3(const void *input, size_t len, uint64_t seed);

#endif /* defined(OSSL_INTERNAL_XXHASH_H) */
