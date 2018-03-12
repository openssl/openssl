/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef KDF_SHAKE_H
#define KDF_SHAKE_H

#include <stdbool.h>
#include <stdint.h>

#if !defined(KeccakP200_excluded)
#define KeccakP200_excluded
#endif

#if !defined(KeccakP400_excluded)
#define KeccakP400_excluded
#endif

#if !defined(KeccakP800_excluded)
#define KeccakP800_excluded
#endif

#ifndef SUPERCOP
#include "sha3/KeccakHash.h"
#else
#include <libkeccak.a.headers/KeccakHash.h>
#endif

#include "picnic_impl.h"

typedef Keccak_HashInstance hash_context;

void oqs_sig_picnic_hash_init(hash_context* ctx, const picnic_instance_t* pp);

#define hash_update(ctx, data, size) oqs_sig_picnic_Keccak_HashUpdate((ctx), (data), (size) << 3)
#define hash_final(ctx) oqs_sig_picnic_Keccak_HashFinal((ctx), NULL)
#define hash_squeeze(buffer, buflen, ctx) oqs_sig_picnic_Keccak_HashSqueeze((ctx), (buffer), (buflen) << 3)

typedef Keccak_HashInstance kdf_shake_t;

#define kdf_shake_init(ctx, pp) oqs_sig_picnic_hash_init((ctx), (pp))
#define kdf_shake_update_key(ctx, key, keylen) hash_update((ctx), (key), (keylen))
#define kdf_shake_finalize_key(ctx) hash_final((ctx))
#define kdf_shake_get_randomness(ctx, dst, count) hash_squeeze((dst), (count), (ctx))
#define kdf_shake_clear(ctx)

#endif
