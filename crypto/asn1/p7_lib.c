/* crypto/asn1/p7_lib.c */
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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/asn1_mac.h>
#include <openssl/pkcs7.h>
#include <openssl/objects.h>

int i2d_PKCS7(PKCS7 *a, unsigned char **pp)
	{
	M_ASN1_I2D_vars(a);

	if (a->asn1 != NULL)
		{
		if (pp == NULL)
			return((int)a->length);
		memcpy(*pp,a->asn1,(int)a->length);
		*pp+=a->length;
		return((int)a->length);
		}

	ret+=4; /* sequence, BER header plus '0 0' end padding */
	M_ASN1_I2D_len(a->type,i2d_ASN1_OBJECT);
	if (a->d.ptr != NULL)
		{
		ret+=4; /* explicit tag [ 0 ] BER plus '0 0' */
		switch (OBJ_obj2nid(a->type))
			{
		case NID_pkcs7_data:
			M_ASN1_I2D_len(a->d.data,i2d_ASN1_OCTET_STRING);
			break;
		case NID_pkcs7_signed:
			M_ASN1_I2D_len(a->d.sign,i2d_PKCS7_SIGNED);
			break;
		case NID_pkcs7_enveloped:
			M_ASN1_I2D_len(a->d.enveloped,i2d_PKCS7_ENVELOPE);
			break;
		case NID_pkcs7_signedAndEnveloped:
			M_ASN1_I2D_len(a->d.signed_and_enveloped,
				i2d_PKCS7_SIGN_ENVELOPE);
			break;
		case NID_pkcs7_digest:
			M_ASN1_I2D_len(a->d.digest,i2d_PKCS7_DIGEST);
			break;
		case NID_pkcs7_encrypted:
			M_ASN1_I2D_len(a->d.encrypted,i2d_PKCS7_ENCRYPT);
			break;
		default:
			break;
			}
		}
	r=ret;
	if (pp == NULL) return(r);
	p= *pp;
	M_ASN1_I2D_INF_seq_start(V_ASN1_SEQUENCE,V_ASN1_UNIVERSAL);
	M_ASN1_I2D_put(a->type,i2d_ASN1_OBJECT);

	if (a->d.ptr != NULL)
		{
		M_ASN1_I2D_INF_seq_start(0,V_ASN1_CONTEXT_SPECIFIC);
		switch (OBJ_obj2nid(a->type))
			{
		case NID_pkcs7_data:
			M_ASN1_I2D_put(a->d.data,i2d_ASN1_OCTET_STRING);
			break;
		case NID_pkcs7_signed:
			M_ASN1_I2D_put(a->d.sign,i2d_PKCS7_SIGNED);
			break;
		case NID_pkcs7_enveloped:
			M_ASN1_I2D_put(a->d.enveloped,i2d_PKCS7_ENVELOPE);
			break;
		case NID_pkcs7_signedAndEnveloped:
			M_ASN1_I2D_put(a->d.signed_and_enveloped,
				i2d_PKCS7_SIGN_ENVELOPE);
			break;
		case NID_pkcs7_digest:
			M_ASN1_I2D_put(a->d.digest,i2d_PKCS7_DIGEST);
			break;
		case NID_pkcs7_encrypted:
			M_ASN1_I2D_put(a->d.encrypted,i2d_PKCS7_ENCRYPT);
			break;
		default:
			break;
			}
		M_ASN1_I2D_INF_seq_end();
		}
	M_ASN1_I2D_INF_seq_end();
	M_ASN1_I2D_finish();
	}

PKCS7 *d2i_PKCS7(PKCS7 **a, unsigned char **pp, long length)
	{
	M_ASN1_D2I_vars(a,PKCS7 *,PKCS7_new);

	if ((a != NULL) && ((*a) != NULL))
		{
		if ((*a)->asn1 != NULL)
			{
			Free((*a)->asn1);
			(*a)->asn1=NULL;
			}
		(*a)->length=0;
		}

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(ret->type,d2i_ASN1_OBJECT);
	if (!M_ASN1_D2I_end_sequence())
		{
		int Tinf,Ttag,Tclass;
		long Tlen;

		if (M_ASN1_next != (V_ASN1_CONSTRUCTED|
			V_ASN1_CONTEXT_SPECIFIC|0))
			{
			c.error=ASN1_R_BAD_PKCS7_CONTENT;
			c.line=__LINE__;
			goto err;
			}

		ret->detached=0;

		c.q=c.p;
		Tinf=ASN1_get_object(&c.p,&Tlen,&Ttag,&Tclass,
			(c.inf & 1)?(length+ *pp-c.q):c.slen);
		if (Tinf & 0x80) { c.line=__LINE__; goto err; }
		c.slen-=(c.p-c.q);

		switch (OBJ_obj2nid(ret->type))
			{
		case NID_pkcs7_data:
			M_ASN1_D2I_get(ret->d.data,d2i_ASN1_OCTET_STRING);
			break;
		case NID_pkcs7_signed:
			M_ASN1_D2I_get(ret->d.sign,d2i_PKCS7_SIGNED);
			if (ret->d.sign->contents->d.ptr == NULL)
				ret->detached=1;
			break;
		case NID_pkcs7_enveloped:
			M_ASN1_D2I_get(ret->d.enveloped,d2i_PKCS7_ENVELOPE);
			break;
		case NID_pkcs7_signedAndEnveloped:
			M_ASN1_D2I_get(ret->d.signed_and_enveloped,
				d2i_PKCS7_SIGN_ENVELOPE);
			break;
		case NID_pkcs7_digest:
			M_ASN1_D2I_get(ret->d.digest,d2i_PKCS7_DIGEST);
			break;
		case NID_pkcs7_encrypted:
			M_ASN1_D2I_get(ret->d.encrypted,d2i_PKCS7_ENCRYPT);
			break;
		default:
			c.error=ASN1_R_BAD_PKCS7_TYPE;
			c.line=__LINE__;
			goto err;
			/* break; */
			}
		if (Tinf == (1|V_ASN1_CONSTRUCTED))
			{
			if (!ASN1_check_infinite_end(&c.p,c.slen))
				{
				c.error=ERR_R_MISSING_ASN1_EOS;
				c.line=__LINE__;
				goto err;
				}
			}
		}
	else
		ret->detached=1;
		
	M_ASN1_D2I_Finish(a,PKCS7_free,ASN1_F_D2I_PKCS7);
	}

PKCS7 *PKCS7_new(void)
	{
	PKCS7 *ret=NULL;
	ASN1_CTX c;

	M_ASN1_New_Malloc(ret,PKCS7);
	ret->type=OBJ_nid2obj(NID_undef);
	ret->asn1=NULL;
	ret->length=0;
	ret->detached=0;
	ret->d.ptr=NULL;
	return(ret);
	M_ASN1_New_Error(ASN1_F_PKCS7_NEW);
	}

void PKCS7_free(PKCS7 *a)
	{
	if (a == NULL) return;

	PKCS7_content_free(a);
	if (a->type != NULL)
		{
		ASN1_OBJECT_free(a->type);
		}
	Free(a);
	}

void PKCS7_content_free(PKCS7 *a)
	{
	if(a == NULL)
	    return;

	if (a->asn1 != NULL) Free(a->asn1);

	if (a->d.ptr != NULL)
		{
		if (a->type == NULL) return;

		switch (OBJ_obj2nid(a->type))
			{
		case NID_pkcs7_data:
			M_ASN1_OCTET_STRING_free(a->d.data);
			break;
		case NID_pkcs7_signed:
			PKCS7_SIGNED_free(a->d.sign);
			break;
		case NID_pkcs7_enveloped:
			PKCS7_ENVELOPE_free(a->d.enveloped);
			break;
		case NID_pkcs7_signedAndEnveloped:
			PKCS7_SIGN_ENVELOPE_free(a->d.signed_and_enveloped);
			break;
		case NID_pkcs7_digest:
			PKCS7_DIGEST_free(a->d.digest);
			break;
		case NID_pkcs7_encrypted:
			PKCS7_ENCRYPT_free(a->d.encrypted);
			break;
		default:
			/* MEMORY LEAK */
			break;
			}
		}
	a->d.ptr=NULL;
	}

