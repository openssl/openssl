/* a_null.c */
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
#include "cryptlib.h"
#include <openssl/asn1.h>

/* ASN1 functions for NULL type. For compatibility with other ASN1 code
 * it returns a pointer to an "ASN1_NULL" structure. The new/free functions
 * don't need to do any allocating because nothing is stored in a NULL.
 */

int i2d_ASN1_NULL(ASN1_NULL *a, unsigned char **pp)
	{
	if(!a) return 0;
	if (pp) ASN1_put_object(pp,0,0,V_ASN1_NULL,V_ASN1_UNIVERSAL);
	return 2;
	}

ASN1_NULL *d2i_ASN1_NULL(ASN1_NULL **a, unsigned char **pp, long length)
	{
	ASN1_NULL *ret = NULL;
	unsigned char *p;
	long len;
	int inf,tag,xclass;
	int i=0;

	p= *pp;
	inf=ASN1_get_object(&p,&len,&tag,&xclass,length);
	if (inf & 0x80)
		{
		i=ASN1_R_BAD_OBJECT_HEADER;
		goto err;
		}

	if (tag != V_ASN1_NULL)
		{
		i=ASN1_R_EXPECTING_A_NULL;
		goto err;
		}

	if (len != 0)
		{
		i=ASN1_R_NULL_IS_WRONG_LENGTH;
		goto err;
		}
	ret=(ASN1_NULL *)1;
	if (a != NULL) (*a)=ret;
	*pp=p;
	return(ret);
err:
	ASN1err(ASN1_F_D2I_ASN1_NULL,i);
	return(ret);
	}

ASN1_NULL *ASN1_NULL_new(void)
{
	return (ASN1_NULL *)1;
}

void ASN1_NULL_free(ASN1_NULL *a)
{
	return;
}
