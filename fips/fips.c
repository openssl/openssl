/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
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

#include <openssl/fips.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include <openssl/err.h>

#ifdef FIPS

int FIPS_selftest()
    {
    return FIPS_selftest_sha1()
	&& FIPS_selftest_aes()
	&& FIPS_selftest_des();
    }

int FIPS_mode_set(int onoff)
    {
    if(onoff)
	{
	char buf[24];

	/* Don't go into FIPS mode twice, just so we can do automagic
	   seeding */
	if(FIPS_mode)
	    FIPSerr(FIPS_F_FIPS_MODE_SET,FIPS_R_FIPS_MODE_ALREADY_SET);

	/* automagically seed PRNG if not already seeded */
	if(!FIPS_rand_seeded())
	    {
	    RAND_bytes(buf,sizeof buf);
	    FIPS_set_prng_key(buf,buf+8);
	    FIPS_rand_seed(buf+16,8);
	    }

	/* now switch into FIPS mode */
	FIPS_rand_check=&rand_fips_meth;
	RAND_set_rand_method(&rand_fips_meth);
	FIPS_mode=onoff;
	return FIPS_selftest();
	}
    FIPS_mode=onoff;
    return 1;
    }


#if 0
/* here just to cause error codes to exist */
static void dummy()
    {
    FIPSerr(FIPS_F_HASH_FINAL,FIPS_F_NON_FIPS_METHOD);
    }
#endif

#endif
