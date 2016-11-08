/*
 * Copyright 2009-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include "../ppc_arch.h"

#ifndef ECP_NISTZ256_ASM
NON_EMPTY_TRANSLATION_UNIT
#else
void ecp_nistz256_mul_mont(unsigned long res[4], const unsigned long a[4],
                           const unsigned long b[4]);

void ecp_nistz256_to_mont(unsigned long res[4], const unsigned long in[4]);
void ecp_nistz256_to_mont(unsigned long res[4], const unsigned long in[4])
{
    static const unsigned long RR[] = { 0x0000000000000003U,
                                        0xfffffffbffffffffU,
                                        0xfffffffffffffffeU,
                                        0x00000004fffffffdU };

    ecp_nistz256_mul_mont(res, in, RR);
}

void ecp_nistz256_from_mont(unsigned long res[4], const unsigned long in[4]);
void ecp_nistz256_from_mont(unsigned long res[4], const unsigned long in[4])
{
    static const unsigned long one[] = { 1, 0, 0, 0 };

    ecp_nistz256_mul_mont(res, in, one);
}
#endif

