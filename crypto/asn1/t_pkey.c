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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/bn.h>
#ifndef NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef NO_DH
#include <openssl/dh.h>
#endif
#ifndef NO_DSA
#include <openssl/dsa.h>
#endif

static int print(BIO *fp,const char *str,BIGNUM *num,
		unsigned char *buf,int off);
#ifndef NO_RSA
#ifndef NO_FP_API
int RSA_print_fp(FILE *fp, RSA *x, int off)
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

int RSA_print(BIO *bp, RSA *x, int off)
	{
	char str[128];
	const char *s;
	unsigned char *m=NULL;
	int ret=0;
	size_t buf_len=0, i;

	if (x->n)
		buf_len = (size_t)BN_num_bytes(x->n);
	if (x->e)
		if (buf_len < (i = (size_t)BN_num_bytes(x->e)))
			buf_len = i;
	if (x->d)
		if (buf_len < (i = (size_t)BN_num_bytes(x->d)))
			buf_len = i;
	if (x->p)
		if (buf_len < (i = (size_t)BN_num_bytes(x->p)))
			buf_len = i;
	if (x->q)
		if (buf_len < (i = (size_t)BN_num_bytes(x->q)))
			buf_len = i;
	if (x->dmp1)
		if (buf_len < (i = (size_t)BN_num_bytes(x->dmp1)))
			buf_len = i;
	if (x->dmq1)
		if (buf_len < (i = (size_t)BN_num_bytes(x->dmq1)))
			buf_len = i;
	if (x->iqmp)
		if (buf_len < (i = (size_t)BN_num_bytes(x->iqmp)))
			buf_len = i;

	m=(unsigned char *)OPENSSL_malloc(buf_len+10);
	if (m == NULL)
		{
		RSAerr(RSA_F_RSA_PRINT,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (off)
		{
		if (off > 128) off=128;
		memset(str,' ',off);
		}
	if (x->d != NULL)
		{
		if (off && (BIO_write(bp,str,off) <= 0)) goto err;
		if (BIO_printf(bp,"Private-Key: (%d bit)\n",BN_num_bits(x->n))
			<= 0) goto err;
		}

	if (x->d == NULL)
		sprintf(str,"Modulus (%d bit):",BN_num_bits(x->n));
	else
		strcpy(str,"modulus:");
	if (!print(bp,str,x->n,m,off)) goto err;
	s=(x->d == NULL)?"Exponent:":"publicExponent:";
	if (!print(bp,s,x->e,m,off)) goto err;
	if (!print(bp,"privateExponent:",x->d,m,off)) goto err;
	if (!print(bp,"prime1:",x->p,m,off)) goto err;
	if (!print(bp,"prime2:",x->q,m,off)) goto err;
	if (!print(bp,"exponent1:",x->dmp1,m,off)) goto err;
	if (!print(bp,"exponent2:",x->dmq1,m,off)) goto err;
	if (!print(bp,"coefficient:",x->iqmp,m,off)) goto err;
	ret=1;
err:
	if (m != NULL) OPENSSL_free(m);
	return(ret);
	}
#endif /* NO_RSA */

#ifndef NO_DSA
#ifndef NO_FP_API
int DSA_print_fp(FILE *fp, DSA *x, int off)
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

int DSA_print(BIO *bp, DSA *x, int off)
	{
	char str[128];
	unsigned char *m=NULL;
	int ret=0;
	size_t buf_len=0,i;

	if (x->p)
		buf_len = (size_t)BN_num_bytes(x->p);
	if (x->q)
		if (buf_len < (i = (size_t)BN_num_bytes(x->q)))
			buf_len = i;
	if (x->g)
		if (buf_len < (i = (size_t)BN_num_bytes(x->g)))
			buf_len = i;
	if (x->priv_key)
		if (buf_len < (i = (size_t)BN_num_bytes(x->priv_key)))
			buf_len = i;
	if (x->pub_key)
		if (buf_len < (i = (size_t)BN_num_bytes(x->pub_key)))
			buf_len = i;

	m=(unsigned char *)OPENSSL_malloc(buf_len+10);
	if (m == NULL)
		{
		DSAerr(DSA_F_DSA_PRINT,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (off)
		{
		if (off > 128) off=128;
		memset(str,' ',off);
		}
	if (x->priv_key != NULL)
		{
		if (off && (BIO_write(bp,str,off) <= 0)) goto err;
		if (BIO_printf(bp,"Private-Key: (%d bit)\n",BN_num_bits(x->p))
			<= 0) goto err;
		}

	if ((x->priv_key != NULL) && !print(bp,"priv:",x->priv_key,m,off))
		goto err;
	if ((x->pub_key  != NULL) && !print(bp,"pub: ",x->pub_key,m,off))
		goto err;
	if ((x->p != NULL) && !print(bp,"P:   ",x->p,m,off)) goto err;
	if ((x->q != NULL) && !print(bp,"Q:   ",x->q,m,off)) goto err;
	if ((x->g != NULL) && !print(bp,"G:   ",x->g,m,off)) goto err;
	ret=1;
err:
	if (m != NULL) OPENSSL_free(m);
	return(ret);
	}
#endif /* !NO_DSA */

static int print(BIO *bp, const char *number, BIGNUM *num, unsigned char *buf,
	     int off)
	{
	int n,i;
	char str[128];
	const char *neg;

	if (num == NULL) return(1);
	neg=(num->neg)?"-":"";
	if (off)
		{
		if (off > 128) off=128;
		memset(str,' ',off);
		if (BIO_write(bp,str,off) <= 0) return(0);
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
				str[0]='\n';
				memset(&(str[1]),' ',off+4);
				if (BIO_write(bp,str,off+1+4) <= 0) return(0);
				}
			if (BIO_printf(bp,"%02x%s",buf[i],((i+1) == n)?"":":")
				<= 0) return(0);
			}
		if (BIO_write(bp,"\n",1) <= 0) return(0);
		}
	return(1);
	}

#ifndef NO_DH
#ifndef NO_FP_API
int DHparams_print_fp(FILE *fp, DH *x)
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

int DHparams_print(BIO *bp, DH *x)
	{
	unsigned char *m=NULL;
	int reason=ERR_R_BUF_LIB,ret=0;
	size_t buf_len=0, i;

	if (x->p)
		buf_len = (size_t)BN_num_bytes(x->p);
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
	if (!print(bp,"prime:",x->p,m,4)) goto err;
	if (!print(bp,"generator:",x->g,m,4)) goto err;
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

#ifndef NO_DSA
#ifndef NO_FP_API
int DSAparams_print_fp(FILE *fp, DSA *x)
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

int DSAparams_print(BIO *bp, DSA *x)
	{
	unsigned char *m=NULL;
	int reason=ERR_R_BUF_LIB,ret=0;
	size_t buf_len=0, i;

	if (x->p)
		buf_len = (size_t)BN_num_bytes(x->p);
	if (x->q)
		if (buf_len < (i = (size_t)BN_num_bytes(x->q)))
			buf_len = i;
	if (x->g)
		if (buf_len < (i = (size_t)BN_num_bytes(x->g)))
			buf_len = i;
	m=(unsigned char *)OPENSSL_malloc(buf_len+10);
	if (m == NULL)
		{
		reason=ERR_R_MALLOC_FAILURE;
		goto err;
		}

	if (BIO_printf(bp,"DSA-Parameters: (%d bit)\n",
		BN_num_bits(x->p)) <= 0)
		goto err;
	if (!print(bp,"p:",x->p,m,4)) goto err;
	if (!print(bp,"q:",x->q,m,4)) goto err;
	if (!print(bp,"g:",x->g,m,4)) goto err;
	ret=1;
err:
	if (m != NULL) OPENSSL_free(m);
	DSAerr(DSA_F_DSAPARAMS_PRINT,reason);
	return(ret);
	}

#endif /* !NO_DSA */

