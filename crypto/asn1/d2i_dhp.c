/* crypto/asn1/d2i_dhp.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef NO_DH
#include <stdio.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/objects.h>
#include <openssl/asn1_mac.h>

DH *d2i_DHparams(DH **a, unsigned char **pp, long length)
	{
	int i=ERR_R_NESTED_ASN1_ERROR;
	ASN1_INTEGER *bs=NULL;
	long v=0;
	M_ASN1_D2I_vars(a,DH *,DH_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(bs,d2i_ASN1_INTEGER);
	if ((ret->p=BN_bin2bn(bs->data,bs->length,ret->p)) == NULL) goto err_bn;
	M_ASN1_D2I_get(bs,d2i_ASN1_INTEGER);
	if ((ret->g=BN_bin2bn(bs->data,bs->length,ret->g)) == NULL) goto err_bn;

	if (!M_ASN1_D2I_end_sequence())
		{
		M_ASN1_D2I_get(bs,d2i_ASN1_INTEGER);
		for (i=0; i<bs->length; i++)
			v=(v<<8)|(bs->data[i]);
		ret->length=(int)v;
		}

	M_ASN1_BIT_STRING_free(bs);

	M_ASN1_D2I_Finish_2(a);

err_bn:
	i=ERR_R_BN_LIB;
err:
	ASN1err(ASN1_F_D2I_DHPARAMS,i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret))) DH_free(ret);
	if (bs != NULL) M_ASN1_BIT_STRING_free(bs);
	return(NULL);
	}
#endif
