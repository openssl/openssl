/* crypto/asn1/t_pkey.c */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Binary polynomial ECC support in OpenSSL originally developed by 
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/objects.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif

#ifndef OPENSSL_NO_RSA
#ifndef OPENSSL_NO_FP_API
int RSA_print_fp(FILE *fp, const RSA *x, int off)
	{
	BIO *b;
	int ret;

	if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		RSAerr(RSA_F_RSA_PRINT_FP,ERR_R_BUF_LIB);
		return(0);
		}
	BIO_set_fp(b,fp,BIO_NOCLOSE);
	ret=RSA_print(b,x,off);
	BIO_free(b);
	return(ret);
	}
#endif

int RSA_print(BIO *bp, const RSA *x, int off)
	{
	EVP_PKEY *pk;
	int ret;
	pk = EVP_PKEY_new();
	if (!pk || !EVP_PKEY_set1_RSA(pk, (RSA *)x))
		return 0;
	ret = EVP_PKEY_print_private(bp, pk, off, NULL);
	EVP_PKEY_free(pk);
	return ret;
	}

#endif /* OPENSSL_NO_RSA */

#ifndef OPENSSL_NO_DSA
#ifndef OPENSSL_NO_FP_API
int DSA_print_fp(FILE *fp, const DSA *x, int off)
	{
	BIO *b;
	int ret;

	if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		DSAerr(DSA_F_DSA_PRINT_FP,ERR_R_BUF_LIB);
		return(0);
		}
	BIO_set_fp(b,fp,BIO_NOCLOSE);
	ret=DSA_print(b,x,off);
	BIO_free(b);
	return(ret);
	}
#endif

int DSA_print(BIO *bp, const DSA *x, int off)
	{
	EVP_PKEY *pk;
	int ret;
	pk = EVP_PKEY_new();
	if (!pk || !EVP_PKEY_set1_DSA(pk, (DSA *)x))
		return 0;
	ret = EVP_PKEY_print_private(bp, pk, off, NULL);
	EVP_PKEY_free(pk);
	return ret;
	}

#endif /* !OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_FP_API
int ECPKParameters_print_fp(FILE *fp, const EC_GROUP *x, int off)
	{
	BIO *b;
	int ret;

	if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		ECerr(EC_F_ECPKPARAMETERS_PRINT_FP,ERR_R_BUF_LIB);
		return(0);
		}
	BIO_set_fp(b, fp, BIO_NOCLOSE);
	ret = ECPKParameters_print(b, x, off);
	BIO_free(b);
	return(ret);
	}

int EC_KEY_print_fp(FILE *fp, const EC_KEY *x, int off)
	{
	BIO *b;
	int ret;
 
	if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		ECerr(EC_F_EC_KEY_PRINT_FP, ERR_R_BIO_LIB);
		return(0);
		}
	BIO_set_fp(b, fp, BIO_NOCLOSE);
	ret = EC_KEY_print(b, x, off);
	BIO_free(b);
	return(ret);
	}
#endif

int EC_KEY_print(BIO *bp, const EC_KEY *x, int off)
	{
	EVP_PKEY *pk;
	int ret;
	pk = EVP_PKEY_new();
	if (!pk || !EVP_PKEY_set1_EC_KEY(pk, (EC_KEY *)x))
		return 0;
	ret = EVP_PKEY_print_private(bp, pk, off, NULL);
	EVP_PKEY_free(pk);
	return ret;
	}

#endif /* OPENSSL_NO_EC */

int ASN1_bn_print(BIO *bp, const char *number, const BIGNUM *num,
			unsigned char *buf, int off)
	{
	int n,i;
	const char *neg;

	if (num == NULL) return(1);
	neg = (BN_is_negative(num))?"-":"";
	if(!BIO_indent(bp,off,128))
		return 0;
	if (BN_is_zero(num))
		{
		if (BIO_printf(bp, "%s 0\n", number) <= 0)
			return 0;
		return 1;
		}

	if (BN_num_bytes(num) <= BN_BYTES)
		{
		if (BIO_printf(bp,"%s %s%lu (%s0x%lx)\n",number,neg,
			(unsigned long)num->d[0],neg,(unsigned long)num->d[0])
			<= 0) return(0);
		}
	else
		{
		buf[0]=0;
		if (BIO_printf(bp,"%s%s",number,
			(neg[0] == '-')?" (Negative)":"") <= 0)
			return(0);
		n=BN_bn2bin(num,&buf[1]);
	
		if (buf[1] & 0x80)
			n++;
		else	buf++;

		for (i=0; i<n; i++)
			{
			if ((i%15) == 0)
				{
				if(BIO_puts(bp,"\n") <= 0
				   || !BIO_indent(bp,off+4,128))
				    return 0;
				}
			if (BIO_printf(bp,"%02x%s",buf[i],((i+1) == n)?"":":")
				<= 0) return(0);
			}
		if (BIO_write(bp,"\n",1) <= 0) return(0);
		}
	return(1);
	}

#ifndef OPENSSL_NO_DH
#ifndef OPENSSL_NO_FP_API
int DHparams_print_fp(FILE *fp, const DH *x)
	{
	BIO *b;
	int ret;

	if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		DHerr(DH_F_DHPARAMS_PRINT_FP,ERR_R_BUF_LIB);
		return(0);
		}
	BIO_set_fp(b,fp,BIO_NOCLOSE);
	ret=DHparams_print(b, x);
	BIO_free(b);
	return(ret);
	}
#endif

int DHparams_print(BIO *bp, const DH *x)
	{
	unsigned char *m=NULL;
	int reason=ERR_R_BUF_LIB,ret=0;
	size_t buf_len=0, i;

	if (x->p)
		buf_len = (size_t)BN_num_bytes(x->p);
	else
		{
		reason = ERR_R_PASSED_NULL_PARAMETER;
		goto err;
		}
	if (x->g)
		if (buf_len < (i = (size_t)BN_num_bytes(x->g)))
			buf_len = i;
	m=(unsigned char *)OPENSSL_malloc(buf_len+10);
	if (m == NULL)
		{
		reason=ERR_R_MALLOC_FAILURE;
		goto err;
		}

	if (BIO_printf(bp,"Diffie-Hellman-Parameters: (%d bit)\n",
		BN_num_bits(x->p)) <= 0)
		goto err;
	if (!ASN1_bn_print(bp,"prime:",x->p,m,4)) goto err;
	if (!ASN1_bn_print(bp,"generator:",x->g,m,4)) goto err;
	if (x->length != 0)
		{
		if (BIO_printf(bp,"    recommended-private-length: %d bits\n",
			(int)x->length) <= 0) goto err;
		}
	ret=1;
	if (0)
		{
err:
		DHerr(DH_F_DHPARAMS_PRINT,reason);
		}
	if (m != NULL) OPENSSL_free(m);
	return(ret);
	}
#endif

#ifndef OPENSSL_NO_DSA
#ifndef OPENSSL_NO_FP_API
int DSAparams_print_fp(FILE *fp, const DSA *x)
	{
	BIO *b;
	int ret;

	if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		DSAerr(DSA_F_DSAPARAMS_PRINT_FP,ERR_R_BUF_LIB);
		return(0);
		}
	BIO_set_fp(b,fp,BIO_NOCLOSE);
	ret=DSAparams_print(b, x);
	BIO_free(b);
	return(ret);
	}
#endif

int DSAparams_print(BIO *bp, const DSA *x)
	{
	EVP_PKEY *pk;
	int ret;
	pk = EVP_PKEY_new();
	if (!pk || !EVP_PKEY_set1_DSA(pk, (DSA *)x))
		return 0;
	ret = EVP_PKEY_print_params(bp, pk, 4, NULL);
	EVP_PKEY_free(pk);
	return ret;
	}

#endif /* !OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_EC
#ifndef OPENSSL_NO_FP_API
int ECParameters_print_fp(FILE *fp, const EC_KEY *x)
	{
	BIO *b;
	int ret;
 
	if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		ECerr(EC_F_ECPARAMETERS_PRINT_FP, ERR_R_BIO_LIB);
		return(0);
		}
	BIO_set_fp(b, fp, BIO_NOCLOSE);
	ret = ECParameters_print(b, x);
	BIO_free(b);
	return(ret);
	}
#endif

int ECParameters_print(BIO *bp, const EC_KEY *x)
	{
	EVP_PKEY *pk;
	int ret;
	pk = EVP_PKEY_new();
	if (!pk || !EVP_PKEY_set1_EC_KEY(pk, (EC_KEY *)x))
		return 0;
	ret = EVP_PKEY_print_params(bp, pk, 4, NULL);
	EVP_PKEY_free(pk);
	return ret;
	}

#endif
