/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_RISCV_ARCH_H
# define OSSL_CRYPTO_RISCV_ARCH_H

# include <ctype.h>
# include <stdint.h>

# define RISCV_DEFINE_CAP(NAME, INDEX, BIT_INDEX) +1
extern uint32_t OPENSSL_riscvcap_P[ ((
# include "riscv_arch.def"
) + sizeof(uint32_t) - 1) / sizeof(uint32_t) ];

# ifdef OPENSSL_RISCVCAP_IMPL
#  define RISCV_DEFINE_CAP(NAME, INDEX, BIT_INDEX) +1
uint32_t OPENSSL_riscvcap_P[ ((
#  include "riscv_arch.def"
) + sizeof(uint32_t) - 1) / sizeof(uint32_t) ];
# endif

# define RISCV_DEFINE_CAP(NAME, INDEX, BIT_INDEX)                   \
    static inline int RISCV_HAS_##NAME(void)                        \
    {                                                               \
        return (OPENSSL_riscvcap_P[INDEX] & (1 << BIT_INDEX)) != 0; \
    }
# include "riscv_arch.def"

struct RISCV_capability_s {
    const char *name;
    size_t index;
    size_t bit_offset;
};

# define RISCV_DEFINE_CAP(NAME, INDEX, BIT_INDEX) +1
extern const struct RISCV_capability_s RISCV_capabilities[
# include "riscv_arch.def"
];

# ifdef OPENSSL_RISCVCAP_IMPL
#  define RISCV_DEFINE_CAP(NAME, INDEX, BIT_INDEX) \
    { #NAME, INDEX, BIT_INDEX },
const struct RISCV_capability_s RISCV_capabilities[] = {
#  include "riscv_arch.def"
};
# endif

# define RISCV_DEFINE_CAP(NAME, INDEX, BIT_INDEX) +1
static const size_t kRISCVNumCaps =
# include "riscv_arch.def"
;

/* Extension combination tests. */
#define RISCV_HAS_ZBB_AND_ZBC() (RISCV_HAS_ZBB() && RISCV_HAS_ZBC())
#define RISCV_HAS_ZBKB_AND_ZKND_AND_ZKNE() (RISCV_HAS_ZBKB() && RISCV_HAS_ZKND() && RISCV_HAS_ZKNE())
#define RISCV_HAS_ZKND_AND_ZKNE() (RISCV_HAS_ZKND() && RISCV_HAS_ZKNE())

#endif
