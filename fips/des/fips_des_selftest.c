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

#include <string.h>
#include <openssl/err.h>
#include <openssl/fips.h>
#include <openssl/des.h>

static struct
    {
    DES_cblock key;
    DES_cblock plaintext;
    unsigned char ciphertext[8];
    } tests[]=
	{
	{
	{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
	{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
	{ 0x8C,0xA6,0x4D,0xE9,0xC1,0xB1,0x23,0xA7 }
	},
	{
	{ 0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10 },
	{ 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF },
	{ 0xED,0x39,0xD9,0x50,0xFA,0x74,0xBC,0xC4 },
	},
	};

int FIPS_selftest_des()
    {
    int n;

    for(n=0 ; n < 2 ; ++n)
	{
	DES_key_schedule key;
	DES_cblock buf;

	DES_set_key(&tests[n].key,&key);
	DES_ecb_encrypt(&tests[n].plaintext,&buf,&key,1);
	if(memcmp(buf,tests[n].ciphertext,sizeof buf))
	    {
	    FIPSerr(FIPS_F_FIPS_SELFTEST_AES,FIPS_R_SELFTEST_FAILED);
	    return 0;
	    }
	}
    return 1;
    }
