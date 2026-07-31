/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file A set of internal functions to manipulate the OSSL_FN d array, and
 * for introspection.
 */

#ifndef OPENSSL_FN_INTERN_H
#define OPENSSL_FN_INTERN_H
#pragma once

#include <stdbool.h>
#include "crypto/fn.h"

#ifdef __cplusplus
extern "C" {
#endif

#if OSSL_FN_BYTES == 4
/* 32-bit systems */
#define OSSL_FN_ULONG_C(n) UINT32_C(n)
#define OSSL_FN_ULONG64_C(hi32, lo32) OSSL_FN_ULONG_C(lo32), OSSL_FN_ULONG_C(hi32)
#elif OSSL_FN_BYTES == 8
/* 64-bit systems */
#define OSSL_FN_ULONG_C(n) UINT64_C(n)
#define OSSL_FN_ULONG64_C(hi32, lo32) (OSSL_FN_ULONG_C(hi32) << 32 | OSSL_FN_ULONG_C(lo32))
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif

/*
 * OSSL_FN_LIMBS_N gives the number of OSSL_FN_ULONG limbs needed to hold a
 * number of bits, rounded to the limb width (for the group-prime constants,
 * all sizes being exact multiples of their bit counts).
 */
#define OSSL_FN_LIMBS_N(nbits) (((nbits) + (OSSL_FN_BYTES * 8 - 1)) / (OSSL_FN_BYTES * 8))

/*
 * OSSL_FN_HEADER_FIELDS is the shared field list between the runtime
 * struct ossl_fn_st (which appends a flexible array member) and the
 * static-constant union shapes declared by OSSL_FN_STATIC_DECLARE (which
 * append a fixed-size array).  Using the same macro for both guarantees
 * the header layouts stay in lockstep.
 */
#define OSSL_FN_HEADER_FIELDS                  \
    unsigned int is_dynamically_allocated : 1; \
    unsigned int is_securely_allocated : 1;    \
    int dsize

struct ossl_fn_st {
    OSSL_FN_HEADER_FIELDS;
    OSSL_FN_ULONG d[];
};

/*
 * Statically-allocated OSSL_FN storage for constants.
 *
 * These macros allow an OSSL_FN to exist in .rodata, statically initialized
 * at compile time.  This is used to back fixed constants (group parameters,
 * mathematical constants, etc.) so that they can be passed to OSSL_FN
 * functions directly, without materialization at runtime.
 *
 * The underlying mechanism is a union of the flexible-array-member OSSL_FN
 * type and a fixed-size-array type with identical header layout.  The
 * fixed-size member carries the actual limbs; reading through the OSSL_FN
 * member is well-defined because both members share the same initial
 * header fields, spelled identically through OSSL_FN_HEADER_FIELDS.
 */

/*
 * OSSL_FN_STATIC_DECLARE(name, nlimbs) declares a union type named
 * ossl_fn_static_##name and an extern storage object of that type.
 *
 *   name    the suffix used for the union type and storage object
 *   nlimbs  the number of OSSL_FN_ULONG limbs in the fixed array
 */
#define OSSL_FN_STATIC_DECLARE(name, nlimbs) \
    union ossl_fn_static_##name {            \
        OSSL_FN fn;                          \
        struct {                             \
            OSSL_FN_HEADER_FIELDS;           \
            OSSL_FN_ULONG d[nlimbs];         \
        } fixed;                             \
    };                                       \
    extern const union ossl_fn_static_##name \
        ossl_fn_static_##name##_storage

/*
 * OSSL_FN_STATIC_DEFINE(name, nlimbs, ...) defines the storage object
 * declared by OSSL_FN_STATIC_DECLARE, with the given limb values.
 *
 *   ...     the limb values, in little-endian order (least significant
 *           first), exactly as they would appear in a static array
 *           initializer for an OSSL_FN_ULONG array
 *
 * Access the OSSL_FN view of the storage object as
 *   &ossl_fn_static_##name##_storage.fn
 * Access the raw limbs (as a BN_ULONG array, since OSSL_FN_ULONG ==
 * BN_ULONG) as
 *   (BN_ULONG *)ossl_fn_static_##name##_storage.fixed.d
 */
#define OSSL_FN_STATIC_DEFINE(name, nlimbs, ...)           \
    const union ossl_fn_static_##name                      \
        ossl_fn_static_##name##_storage                    \
        = {                                                \
              .fixed = { 0, 0, (nlimbs), { __VA_ARGS__ } } \
          }

int ossl_fn_set_words(OSSL_FN *f, const OSSL_FN_ULONG *words, size_t limbs);
const OSSL_FN_ULONG *ossl_fn_get_words(const OSSL_FN *f);

size_t ossl_fn_get_dsize(const OSSL_FN *f);

void ossl_fn_set_negative(OSSL_FN *f, bool neg);

bool ossl_fn_is_negative(const OSSL_FN *f);
bool ossl_fn_is_dynamically_allocated(const OSSL_FN *f);
bool ossl_fn_is_securely_allocated(const OSSL_FN *f);

OSSL_FN_ULONG ossl_fn_add_words(OSSL_FN_ULONG *r, size_t rl,
    const OSSL_FN_ULONG *a, size_t al,
    const OSSL_FN_ULONG *b, size_t bl);
OSSL_FN_ULONG ossl_fn_sub_words(OSSL_FN_ULONG *r, size_t rl,
    const OSSL_FN_ULONG *a, size_t al,
    const OSSL_FN_ULONG *b, size_t bl);

#ifdef __cplusplus
}
#endif

#endif
