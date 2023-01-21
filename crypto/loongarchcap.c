/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include "loongarch_arch.h"

unsigned int OPENSSL_loongarchcap_P = 0;

void OPENSSL_cpuid_setup(void)
{
	unsigned int reg;
	__asm__ volatile(
	    "cpucfg %0, %1 \n\t"
	    : "+&r"(reg)
	    : "r"(LOONGARCH_CFG2)
	);
	OPENSSL_loongarchcap_P = reg;
}
