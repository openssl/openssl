/* p5_crpt.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "cryptlib.h"

/* PKCS#5 v1.5 compatible PBE functions: see PKCS#5 v2.0 for more info.
 */

void PKCS5_PBE_add(void)
{
#ifndef NO_DES
EVP_PBE_alg_add(NID_pbeWithMD5AndDES_CBC, EVP_des_cbc(), EVP_md5(),
							 PKCS5_PBE_keyivgen);
EVP_PBE_alg_add(NID_pbeWithMD2AndDES_CBC, EVP_des_cbc(), EVP_md2(),
							 PKCS5_PBE_keyivgen);
EVP_PBE_alg_add(NID_pbeWithSHA1AndDES_CBC, EVP_des_cbc(), EVP_sha1(),
							 PKCS5_PBE_keyivgen);
#endif
#ifndef NO_RC2
EVP_PBE_alg_add(NID_pbeWithMD5AndRC2_CBC, EVP_rc2_64_cbc(), EVP_md5(),
							 PKCS5_PBE_keyivgen);
EVP_PBE_alg_add(NID_pbeWithMD2AndRC2_CBC, EVP_rc2_64_cbc(), EVP_md2(),
							 PKCS5_PBE_keyivgen);
EVP_PBE_alg_add(NID_pbeWithSHA1AndRC2_CBC, EVP_rc2_64_cbc(), EVP_sha1(),
							 PKCS5_PBE_keyivgen);
#endif
}

int PKCS5_PBE_keyivgen(const char *pass, int passlen, unsigned char *salt,
			 int saltlen, int iter, EVP_CIPHER *cipher, EVP_MD *md,
			 unsigned char *key, unsigned char *iv)
{
	EVP_MD_CTX ctx;
	unsigned char md_tmp[EVP_MAX_MD_SIZE];
	int i;
	EVP_DigestInit (&ctx, md);
	EVP_DigestUpdate (&ctx, pass, passlen);
	EVP_DigestUpdate (&ctx, salt, saltlen);
	EVP_DigestFinal (&ctx, md_tmp, NULL);
	for (i = 1; i < iter; i++) {
		EVP_DigestInit(&ctx, md);
		EVP_DigestUpdate(&ctx, md_tmp, EVP_MD_size(md));
		EVP_DigestFinal (&ctx, md_tmp, NULL);
	}
	memcpy (key, md_tmp, EVP_CIPHER_key_length(cipher));
	memcpy (iv, md_tmp + (16 - EVP_CIPHER_iv_length(cipher)),
						 EVP_CIPHER_iv_length(cipher));
	return 1;
}
