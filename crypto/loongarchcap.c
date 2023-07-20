/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include "loongarch_arch.h"
#include <sys/auxv.h>

#define CPUCFG_LSX_BIT 6
#define CPUCFG_LASX_BIT 7

#define AT_HWCAP_LSX_BIT 4
#define AT_HWCAP_LASX_BIT 5

unsigned int OPENSSL_loongarchcap_P = 0;

void OPENSSL_cpuid_setup(void)
{
	unsigned long hwcap;
	unsigned int reg = 0;
	hwcap = getauxval(AT_HWCAP);
	if(hwcap & (1<<AT_HWCAP_LSX_BIT))
	{
		reg |= (1<<CPUCFG_LSX_BIT);
	}
	if(hwcap & (1<<AT_HWCAP_LASX_BIT))
	{
		reg |= (1<<CPUCFG_LASX_BIT);
	}
	OPENSSL_loongarchcap_P = reg;
}
