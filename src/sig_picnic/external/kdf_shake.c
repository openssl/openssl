/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "kdf_shake.h"

void oqs_sig_picnic_hash_init(hash_context* ctx, const picnic_instance_t* pp) {
  if (pp->security_level == 64) {
    Keccak_HashInitialize_SHAKE128(ctx);
  } else {
    Keccak_HashInitialize_SHAKE256(ctx);
  }
}
