/* crypto/asn1/i2d_dhp.c */
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
#include <openssl/asn1_mac.h>
#include <openssl/dh.h>

int i2d_DHparams(DH *a, unsigned char **pp)
	{
	BIGNUM *num[3];
	ASN1_INTEGER bs;
	unsigned int j,i,tot=0,len,max=0;
	int t,ret= -1;
	unsigned char *p;

	if (a == NULL) return(0);
	num[0]=a->p;
	num[1]=a->g;
	if (a->length != 0)
		{
		if ((num[2]=BN_new()) == NULL) goto err;
		if (!BN_set_word(num[2],a->length)) goto err;
		}
	else	
		num[2]=NULL;

	for (i=0; i<3; i++)
		{
		if (num[i] == NULL) continue;
		j=BN_num_bits(num[i]);
		len=((j == 0)?0:((j/8)+1));
		if (len > max) max=len;
		len=ASN1_object_size(0,len,
			(num[i]->neg)?V_ASN1_NEG_INTEGER:V_ASN1_INTEGER);
		tot+=len;
		}

	t=ASN1_object_size(1,tot,V_ASN1_SEQUENCE);
	if (pp == NULL)
		{
		if (num[2] != NULL)
			BN_free(num[2]);
		return(t);
		}

	p= *pp;
	ASN1_put_object(&p,1,tot,V_ASN1_SEQUENCE,V_ASN1_UNIVERSAL);

	bs.type=V_ASN1_INTEGER;
	bs.data=(unsigned char *)Malloc(max+4);
	if (bs.data == NULL)
		{
		ASN1err(ASN1_F_I2D_DHPARAMS,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	for (i=0; i<3; i++)
		{
		if (num[i] == NULL) continue;
		bs.length=BN_bn2bin(num[i],bs.data);
		i2d_ASN1_INTEGER(&bs,&p);
		}
	Free(bs.data);
	ret=t;
err:
	if (num[2] != NULL) BN_free(num[2]);
	*pp=p;
	return(ret);
	}
#endif
