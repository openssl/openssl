/* crypto/x509/x_all.c */
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
#undef SSLEAY_MACROS
#include <openssl/stack.h>
#include "cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

int X509_verify(X509 *a, EVP_PKEY *r)
	{
	return(ASN1_verify((int (*)())i2d_X509_CINF,a->sig_alg,
		a->signature,(char *)a->cert_info,r));
	}

int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r)
	{
	return( ASN1_verify((int (*)())i2d_X509_REQ_INFO,
		a->sig_alg,a->signature,(char *)a->req_info,r));
	}

int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r)
	{
	return(ASN1_verify((int (*)())i2d_X509_CRL_INFO,
		a->sig_alg, a->signature,(char *)a->crl,r));
	}

int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r)
	{
	return(ASN1_verify((int (*)())i2d_NETSCAPE_SPKAC,
		a->sig_algor,a->signature, (char *)a->spkac,r));
	}

int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md)
	{
	return(ASN1_sign((int (*)())i2d_X509_CINF, x->cert_info->signature,
		x->sig_alg, x->signature, (char *)x->cert_info,pkey,md));
	}

int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md)
	{
	return(ASN1_sign((int (*)())i2d_X509_REQ_INFO,x->sig_alg, NULL,
		x->signature, (char *)x->req_info,pkey,md));
	}

int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md)
	{
	return(ASN1_sign((int (*)())i2d_X509_CRL_INFO,x->crl->sig_alg,
		x->sig_alg, x->signature, (char *)x->crl,pkey,md));
	}

int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVP_PKEY *pkey, const EVP_MD *md)
	{
	return(ASN1_sign((int (*)())i2d_NETSCAPE_SPKAC, x->sig_algor,NULL,
		x->signature, (char *)x->spkac,pkey,md));
	}

X509_ATTRIBUTE *X509_ATTRIBUTE_dup(X509_ATTRIBUTE *xa)
	{
	return((X509_ATTRIBUTE *)ASN1_dup((int (*)())i2d_X509_ATTRIBUTE,
		(char *(*)())d2i_X509_ATTRIBUTE,(char *)xa));
	}

X509 *X509_dup(X509 *x509)
	{
	return((X509 *)ASN1_dup((int (*)())i2d_X509,
		(char *(*)())d2i_X509,(char *)x509));
	}

X509_EXTENSION *X509_EXTENSION_dup(X509_EXTENSION *ex)
	{
	return((X509_EXTENSION *)ASN1_dup(
		(int (*)())i2d_X509_EXTENSION,
		(char *(*)())d2i_X509_EXTENSION,(char *)ex));
	}

#ifndef NO_FP_API
X509 *d2i_X509_fp(FILE *fp, X509 **x509)
	{
	return((X509 *)ASN1_d2i_fp((char *(*)())X509_new,
		(char *(*)())d2i_X509, (fp),(unsigned char **)(x509)));
	}

int i2d_X509_fp(FILE *fp, X509 *x509)
	{
	return(ASN1_i2d_fp(i2d_X509,fp,(unsigned char *)x509));
	}
#endif

X509 *d2i_X509_bio(BIO *bp, X509 **x509)
	{
	return((X509 *)ASN1_d2i_bio((char *(*)())X509_new,
		(char *(*)())d2i_X509, (bp),(unsigned char **)(x509)));
	}

int i2d_X509_bio(BIO *bp, X509 *x509)
	{
	return(ASN1_i2d_bio(i2d_X509,bp,(unsigned char *)x509));
	}

X509_CRL *X509_CRL_dup(X509_CRL *crl)
	{
	return((X509_CRL *)ASN1_dup((int (*)())i2d_X509_CRL,
		(char *(*)())d2i_X509_CRL,(char *)crl));
	}

#ifndef NO_FP_API
X509_CRL *d2i_X509_CRL_fp(FILE *fp, X509_CRL **crl)
	{
	return((X509_CRL *)ASN1_d2i_fp((char *(*)())
		X509_CRL_new,(char *(*)())d2i_X509_CRL, (fp),
		(unsigned char **)(crl)));
	}

int i2d_X509_CRL_fp(FILE *fp, X509_CRL *crl)
	{
	return(ASN1_i2d_fp(i2d_X509_CRL,fp,(unsigned char *)crl));
	}
#endif

X509_CRL *d2i_X509_CRL_bio(BIO *bp, X509_CRL **crl)
	{
	return((X509_CRL *)ASN1_d2i_bio((char *(*)())
		X509_CRL_new,(char *(*)())d2i_X509_CRL, (bp),
		(unsigned char **)(crl)));
	}

int i2d_X509_CRL_bio(BIO *bp, X509_CRL *crl)
	{
	return(ASN1_i2d_bio(i2d_X509_CRL,bp,(unsigned char *)crl));
	}

PKCS7 *PKCS7_dup(PKCS7 *p7)
	{
	return((PKCS7 *)ASN1_dup((int (*)())i2d_PKCS7,
		(char *(*)())d2i_PKCS7,(char *)p7));
	}

#ifndef NO_FP_API
PKCS7 *d2i_PKCS7_fp(FILE *fp, PKCS7 **p7)
	{
	return((PKCS7 *)ASN1_d2i_fp((char *(*)())
		PKCS7_new,(char *(*)())d2i_PKCS7, (fp),
		(unsigned char **)(p7)));
	}

int i2d_PKCS7_fp(FILE *fp, PKCS7 *p7)
	{
	return(ASN1_i2d_fp(i2d_PKCS7,fp,(unsigned char *)p7));
	}
#endif

PKCS7 *d2i_PKCS7_bio(BIO *bp, PKCS7 **p7)
	{
	return((PKCS7 *)ASN1_d2i_bio((char *(*)())
		PKCS7_new,(char *(*)())d2i_PKCS7, (bp),
		(unsigned char **)(p7)));
	}

int i2d_PKCS7_bio(BIO *bp, PKCS7 *p7)
	{
	return(ASN1_i2d_bio(i2d_PKCS7,bp,(unsigned char *)p7));
	}

X509_REQ *X509_REQ_dup(X509_REQ *req)
	{
	return((X509_REQ *)ASN1_dup((int (*)())i2d_X509_REQ,
		(char *(*)())d2i_X509_REQ,(char *)req));
	}

#ifndef NO_FP_API
X509_REQ *d2i_X509_REQ_fp(FILE *fp, X509_REQ **req)
	{
	return((X509_REQ *)ASN1_d2i_fp((char *(*)())
		X509_REQ_new, (char *(*)())d2i_X509_REQ, (fp),
		(unsigned char **)(req)));
	}

int i2d_X509_REQ_fp(FILE *fp, X509_REQ *req)
	{
	return(ASN1_i2d_fp(i2d_X509_REQ,fp,(unsigned char *)req));
	}
#endif

X509_REQ *d2i_X509_REQ_bio(BIO *bp, X509_REQ **req)
	{
	return((X509_REQ *)ASN1_d2i_bio((char *(*)())
		X509_REQ_new, (char *(*)())d2i_X509_REQ, (bp),
		(unsigned char **)(req)));
	}

int i2d_X509_REQ_bio(BIO *bp, X509_REQ *req)
	{
	return(ASN1_i2d_bio(i2d_X509_REQ,bp,(unsigned char *)req));
	}

#ifndef NO_RSA
RSA *RSAPublicKey_dup(RSA *rsa)
	{
	return((RSA *)ASN1_dup((int (*)())i2d_RSAPublicKey,
		(char *(*)())d2i_RSAPublicKey,(char *)rsa));
	}

RSA *RSAPrivateKey_dup(RSA *rsa)
	{
	return((RSA *)ASN1_dup((int (*)())i2d_RSAPrivateKey,
		(char *(*)())d2i_RSAPrivateKey,(char *)rsa));
	}

#ifndef NO_FP_API
RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa)
	{
	return((RSA *)ASN1_d2i_fp((char *(*)())
		RSA_new,(char *(*)())d2i_RSAPrivateKey, (fp),
		(unsigned char **)(rsa)));
	}

int i2d_RSAPrivateKey_fp(FILE *fp, RSA *rsa)
	{
	return(ASN1_i2d_fp(i2d_RSAPrivateKey,fp,(unsigned char *)rsa));
	}

RSA *d2i_RSAPublicKey_fp(FILE *fp, RSA **rsa)
	{
	return((RSA *)ASN1_d2i_fp((char *(*)())
		RSA_new,(char *(*)())d2i_RSAPublicKey, (fp),
		(unsigned char **)(rsa)));
	}

int i2d_RSAPublicKey_fp(FILE *fp, RSA *rsa)
	{
	return(ASN1_i2d_fp(i2d_RSAPublicKey,fp,(unsigned char *)rsa));
	}
#endif

RSA *d2i_RSAPrivateKey_bio(BIO *bp, RSA **rsa)
	{
	return((RSA *)ASN1_d2i_bio((char *(*)())
		RSA_new,(char *(*)())d2i_RSAPrivateKey, (bp),
		(unsigned char **)(rsa)));
	}

int i2d_RSAPrivateKey_bio(BIO *bp, RSA *rsa)
	{
	return(ASN1_i2d_bio(i2d_RSAPrivateKey,bp,(unsigned char *)rsa));
	}

RSA *d2i_RSAPublicKey_bio(BIO *bp, RSA **rsa)
	{
	return((RSA *)ASN1_d2i_bio((char *(*)())
		RSA_new,(char *(*)())d2i_RSAPublicKey, (bp),
		(unsigned char **)(rsa)));
	}

int i2d_RSAPublicKey_bio(BIO *bp, RSA *rsa)
	{
	return(ASN1_i2d_bio(i2d_RSAPublicKey,bp,(unsigned char *)rsa));
	}
#endif

#ifndef NO_DSA
#ifndef NO_FP_API
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa)
	{
	return((DSA *)ASN1_d2i_fp((char *(*)())
		DSA_new,(char *(*)())d2i_DSAPrivateKey, (fp),
		(unsigned char **)(dsa)));
	}

int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa)
	{
	return(ASN1_i2d_fp(i2d_DSAPrivateKey,fp,(unsigned char *)dsa));
	}
#endif

DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa)
	{
	return((DSA *)ASN1_d2i_bio((char *(*)())
		DSA_new,(char *(*)())d2i_DSAPrivateKey, (bp),
		(unsigned char **)(dsa)));
	}

int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa)
	{
	return(ASN1_i2d_bio(i2d_DSAPrivateKey,bp,(unsigned char *)dsa));
	}
#endif

X509_ALGOR *X509_ALGOR_dup(X509_ALGOR *xn)
	{
	return((X509_ALGOR *)ASN1_dup((int (*)())i2d_X509_ALGOR,
	(char *(*)())d2i_X509_ALGOR,(char *)xn));
	}

X509_NAME *X509_NAME_dup(X509_NAME *xn)
	{
	return((X509_NAME *)ASN1_dup((int (*)())i2d_X509_NAME,
		(char *(*)())d2i_X509_NAME,(char *)xn));
	}

X509_NAME_ENTRY *X509_NAME_ENTRY_dup(X509_NAME_ENTRY *ne)
	{
	return((X509_NAME_ENTRY *)ASN1_dup((int (*)())i2d_X509_NAME_ENTRY,
		(char *(*)())d2i_X509_NAME_ENTRY,(char *)ne));
	}

int X509_digest(X509 *data, EVP_MD *type, unsigned char *md,
	     unsigned int *len)
	{
	return(ASN1_digest((int (*)())i2d_X509,type,(char *)data,md,len));
	}

int X509_NAME_digest(X509_NAME *data, EVP_MD *type, unsigned char *md,
	     unsigned int *len)
	{
	return(ASN1_digest((int (*)())i2d_X509_NAME,type,(char *)data,md,len));
	}

int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL *data, EVP_MD *type,
	     unsigned char *md, unsigned int *len)
	{
	return(ASN1_digest((int (*)())i2d_PKCS7_ISSUER_AND_SERIAL,type,
		(char *)data,md,len));
	}


#ifndef NO_FP_API
X509_SIG *d2i_PKCS8_fp(FILE *fp, X509_SIG **p8)
	{
	return((X509_SIG *)ASN1_d2i_fp((char *(*)())X509_SIG_new,
		(char *(*)())d2i_X509_SIG, (fp),(unsigned char **)(p8)));
	}

int i2d_PKCS8_fp(FILE *fp, X509_SIG *p8)
	{
	return(ASN1_i2d_fp(i2d_X509_SIG,fp,(unsigned char *)p8));
	}
#endif

X509_SIG *d2i_PKCS8_bio(BIO *bp, X509_SIG **p8)
	{
	return((X509_SIG *)ASN1_d2i_bio((char *(*)())X509_SIG_new,
		(char *(*)())d2i_X509_SIG, (bp),(unsigned char **)(p8)));
	}

int i2d_PKCS8_bio(BIO *bp, X509_SIG *p8)
	{
	return(ASN1_i2d_bio(i2d_X509_SIG,bp,(unsigned char *)p8));
	}

#ifndef NO_FP_API
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
						 PKCS8_PRIV_KEY_INFO **p8inf)
	{
	return((PKCS8_PRIV_KEY_INFO *)ASN1_d2i_fp(
		(char *(*)())PKCS8_PRIV_KEY_INFO_new,
		(char *(*)())d2i_PKCS8_PRIV_KEY_INFO, (fp),
				(unsigned char **)(p8inf)));
	}

int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, PKCS8_PRIV_KEY_INFO *p8inf)
	{
	return(ASN1_i2d_fp(i2d_PKCS8_PRIV_KEY_INFO,fp,(unsigned char *)p8inf));
	}
#endif

PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,
						 PKCS8_PRIV_KEY_INFO **p8inf)
	{
	return((PKCS8_PRIV_KEY_INFO *)ASN1_d2i_bio(
		(char *(*)())PKCS8_PRIV_KEY_INFO_new,
		(char *(*)())d2i_PKCS8_PRIV_KEY_INFO, (bp),
				(unsigned char **)(p8inf)));
	}

int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp, PKCS8_PRIV_KEY_INFO *p8inf)
	{
	return(ASN1_i2d_bio(i2d_PKCS8_PRIV_KEY_INFO,bp,(unsigned char *)p8inf));
	}
