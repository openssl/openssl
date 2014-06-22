/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define OPENSSL_FIPSAPI

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/fips.h>
#include <openssl/fips_rand.h>
#include "e_os.h"

/* FIPS API for PRNG use. Similar to RAND functionality but without
 * ENGINE and additional checking for non-FIPS rand methods.
 */

static const RAND_METHOD *fips_rand_meth = NULL;
static int fips_approved_rand_meth = 0;
static int fips_rand_bits = 0;

/* Allows application to override number of bits and uses non-FIPS methods */
void FIPS_rand_set_bits(int nbits)
	{
	fips_rand_bits = nbits;
	}

int FIPS_rand_set_method(const RAND_METHOD *meth)
	{
	if (!fips_rand_bits)
		{
		if (meth == FIPS_drbg_method())
			fips_approved_rand_meth = 1;
		else if (meth == FIPS_x931_method())
			fips_approved_rand_meth = 2;
		else
			{
			fips_approved_rand_meth = 0;
			if (FIPS_module_mode())
				{
				FIPSerr(FIPS_F_FIPS_RAND_SET_METHOD,
						FIPS_R_NON_FIPS_METHOD);
				return 0;
				}
			}
		}
	fips_rand_meth = meth;
	return 1;
	}

const RAND_METHOD *FIPS_rand_get_method(void)
	{
	return fips_rand_meth;
	}

void FIPS_rand_seed(const void *buf, int num)
	{
	if (!fips_approved_rand_meth && FIPS_module_mode())
		{
		FIPSerr(FIPS_F_FIPS_RAND_SEED, FIPS_R_NON_FIPS_METHOD);
		return;
		}
	if (fips_rand_meth && fips_rand_meth->seed)
		fips_rand_meth->seed(buf,num);
	}

void FIPS_rand_add(const void *buf, int num, double entropy)
	{
	if (!fips_approved_rand_meth && FIPS_module_mode())
		{
		FIPSerr(FIPS_F_FIPS_RAND_ADD, FIPS_R_NON_FIPS_METHOD);
		return;
		}
	if (fips_rand_meth && fips_rand_meth->add)
		fips_rand_meth->add(buf,num,entropy);
	}

int FIPS_rand_bytes(unsigned char *buf, int num)
	{
	if (!fips_approved_rand_meth && FIPS_module_mode())
		{
		FIPSerr(FIPS_F_FIPS_RAND_BYTES, FIPS_R_NON_FIPS_METHOD);
		return 0;
		}
	if (fips_rand_meth && fips_rand_meth->bytes)
		return fips_rand_meth->bytes(buf,num);
	return 0;
	}

int FIPS_rand_pseudo_bytes(unsigned char *buf, int num)
	{
	if (!fips_approved_rand_meth && FIPS_module_mode())
		{
		FIPSerr(FIPS_F_FIPS_RAND_PSEUDO_BYTES, FIPS_R_NON_FIPS_METHOD);
		return 0;
		}
	if (fips_rand_meth && fips_rand_meth->pseudorand)
		return fips_rand_meth->pseudorand(buf,num);
	return -1;
	}

int FIPS_rand_status(void)
	{
	if (!fips_approved_rand_meth && FIPS_module_mode())
		{
		FIPSerr(FIPS_F_FIPS_RAND_STATUS, FIPS_R_NON_FIPS_METHOD);
		return 0;
		}
	if (fips_rand_meth && fips_rand_meth->status)
		return fips_rand_meth->status();
	return 0;
	}

/* Return instantiated strength of PRNG. For DRBG this is an internal
 * parameter. For X9.31 PRNG it is 80 bits (from SP800-131). Any other
 * type of PRNG is not approved and returns 0 in FIPS mode and maximum
 * 256 outside FIPS mode.
 */

int FIPS_rand_strength(void)
	{
	if (fips_rand_bits)
		return fips_rand_bits;
	if (fips_approved_rand_meth == 1)
		return FIPS_drbg_get_strength(FIPS_get_default_drbg());
	else if (fips_approved_rand_meth == 2)
		return 80;
	else if (fips_approved_rand_meth == 0)
		{
		if (FIPS_module_mode())
			return 0;
		else
			return 256;
		}
	return 0;
	}
