/* crypto/pem/pem_all.c */
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
#include "cryptlib.h"
#include "bio.h"
#include "evp.h"
#include "x509.h"
#include "pkcs7.h"
#include "pem.h"

#ifndef NO_FP_API
/* The X509 functions */
X509 *PEM_read_X509(fp,x,cb)
FILE *fp;
X509 **x;
int (*cb)();
	{
	return((X509 *)PEM_ASN1_read((char *(*)())d2i_X509,
		PEM_STRING_X509,fp,(char **)x,cb));
	}
#endif

X509 *PEM_read_bio_X509(bp,x,cb)
BIO *bp;
X509 **x;
int (*cb)();
	{
	return((X509 *)PEM_ASN1_read_bio((char *(*)())d2i_X509,
		PEM_STRING_X509,bp,(char **)x,cb));
	}

#ifndef NO_FP_API
int PEM_write_X509(fp,x)
FILE *fp;
X509 *x;
	{
	return(PEM_ASN1_write((int (*)())i2d_X509,PEM_STRING_X509,fp,
		(char *)x, NULL,NULL,0,NULL));
	}
#endif

int PEM_write_bio_X509(bp,x)
BIO *bp;
X509 *x;
	{
	return(PEM_ASN1_write_bio((int (*)())i2d_X509,PEM_STRING_X509,bp,
		(char *)x, NULL,NULL,0,NULL));
	}

#ifndef NO_FP_API
/* The X509_REQ functions */
X509_REQ *PEM_read_X509_REQ(fp,x,cb)
FILE *fp;
X509_REQ **x;
int (*cb)();
	{
	return((X509_REQ *)PEM_ASN1_read((char *(*)())d2i_X509_REQ,
		PEM_STRING_X509_REQ,fp,(char **)x,cb));
	}
#endif

X509_REQ *PEM_read_bio_X509_REQ(bp,x,cb)
BIO *bp;
X509_REQ **x;
int (*cb)();
	{
	return((X509_REQ *)PEM_ASN1_read_bio((char *(*)())d2i_X509_REQ,
		PEM_STRING_X509_REQ,bp,(char **)x,cb));
	}

#ifndef NO_FP_API
int PEM_write_X509_REQ(fp,x)
FILE *fp;
X509_REQ *x;
	{
	return(PEM_ASN1_write((int (*)())i2d_X509_REQ,PEM_STRING_X509_REQ,fp,
		(char *)x, NULL,NULL,0,NULL));
	}
#endif

int PEM_write_bio_X509_REQ(bp,x)
BIO *bp;
X509_REQ *x;
	{
	return(PEM_ASN1_write_bio((int (*)())i2d_X509_REQ,PEM_STRING_X509_REQ,
		bp,(char *)x, NULL,NULL,0,NULL));
	}

#ifndef NO_FP_API
/* The X509_CRL functions */
X509_CRL *PEM_read_X509_CRL(fp,x,cb)
FILE *fp;
X509_CRL **x;
int (*cb)();
	{
	return((X509_CRL *)PEM_ASN1_read((char *(*)())d2i_X509_CRL,
		PEM_STRING_X509_CRL,fp,(char **)x,cb));
	}
#endif

X509_CRL *PEM_read_bio_X509_CRL(bp,x,cb)
BIO *bp;
X509_CRL **x;
int (*cb)();
	{
	return((X509_CRL *)PEM_ASN1_read_bio((char *(*)())d2i_X509_CRL,
		PEM_STRING_X509_CRL,bp,(char **)x,cb));
	}

#ifndef NO_FP_API
int PEM_write_X509_CRL(fp,x)
FILE *fp;
X509_CRL *x;
	{
	return(PEM_ASN1_write((int (*)())i2d_X509_CRL,PEM_STRING_X509_CRL,fp,
		(char *)x, NULL,NULL,0,NULL));
	}
#endif

int PEM_write_bio_X509_CRL(bp,x)
BIO *bp;
X509_CRL *x;
	{
	return(PEM_ASN1_write_bio((int (*)())i2d_X509_CRL,PEM_STRING_X509_CRL,
		bp,(char *)x, NULL,NULL,0,NULL));
	}

#ifndef NO_RSA
#ifndef NO_FP_API
/* The RSAPrivateKey functions */
RSA *PEM_read_RSAPrivateKey(fp,x,cb)
FILE *fp;
RSA **x;
int (*cb)();
	{
	return((RSA *)PEM_ASN1_read((char *(*)())d2i_RSAPrivateKey,
		PEM_STRING_RSA,fp,(char **)x,cb));
	}

RSA *PEM_read_RSAPublicKey(fp,x,cb)
FILE *fp;
RSA **x;
int (*cb)();
	{
	return((RSA *)PEM_ASN1_read((char *(*)())d2i_RSAPublicKey,
		PEM_STRING_RSA_PUBLIC,fp,(char **)x,cb));
	}
#endif

RSA *PEM_read_bio_RSAPrivateKey(bp,x,cb)
BIO *bp;
RSA **x;
int (*cb)();
	{
	return((RSA *)PEM_ASN1_read_bio((char *(*)())d2i_RSAPrivateKey,
		PEM_STRING_RSA,bp,(char **)x,cb));
	}

RSA *PEM_read_bio_RSAPublicKey(bp,x,cb)
BIO *bp;
RSA **x;
int (*cb)();
	{
	return((RSA *)PEM_ASN1_read_bio((char *(*)())d2i_RSAPublicKey,
		PEM_STRING_RSA_PUBLIC,bp,(char **)x,cb));
	}

#ifndef NO_FP_API
int PEM_write_RSAPrivateKey(fp,x,enc,kstr,klen,cb)
FILE *fp;
RSA *x;
EVP_CIPHER *enc;
unsigned char *kstr;
int klen;
int (*cb)();
	{
	return(PEM_ASN1_write((int (*)())i2d_RSAPrivateKey,PEM_STRING_RSA,fp,
		(char *)x,enc,kstr,klen,cb));
	}

int PEM_write_RSAPublicKey(fp,x)
FILE *fp;
RSA *x;
	{
	return(PEM_ASN1_write((int (*)())i2d_RSAPublicKey,
		PEM_STRING_RSA_PUBLIC,fp,
		(char *)x,NULL,NULL,0,NULL));
	}
#endif

int PEM_write_bio_RSAPrivateKey(bp,x,enc,kstr,klen,cb)
BIO *bp;
RSA *x;
EVP_CIPHER *enc;
unsigned char *kstr;
int klen;
int (*cb)();
	{
	return(PEM_ASN1_write_bio((int (*)())i2d_RSAPrivateKey,PEM_STRING_RSA,
		bp,(char *)x,enc,kstr,klen,cb));
	}

int PEM_write_bio_RSAPublicKey(bp,x)
BIO *bp;
RSA *x;
	{
	return(PEM_ASN1_write_bio((int (*)())i2d_RSAPublicKey,
		PEM_STRING_RSA_PUBLIC,
		bp,(char *)x,NULL,NULL,0,NULL));
	}
#endif /* !NO_RSA */

#ifndef NO_DSA
#ifndef NO_FP_API
/* The DSAPrivateKey functions */
DSA *PEM_read_DSAPrivateKey(fp,x,cb)
FILE *fp;
DSA **x;
int (*cb)();
	{
	return((DSA *)PEM_ASN1_read((char *(*)())d2i_DSAPrivateKey,
		PEM_STRING_DSA,fp,(char **)x,cb));
	}
#endif

DSA *PEM_read_bio_DSAPrivateKey(bp,x,cb)
BIO *bp;
DSA **x;
int (*cb)();
	{
	return((DSA *)PEM_ASN1_read_bio((char *(*)())d2i_DSAPrivateKey,
		PEM_STRING_DSA,bp,(char **)x,cb));
	}

#ifndef NO_FP_API
int PEM_write_DSAPrivateKey(fp,x,enc,kstr,klen,cb)
FILE *fp;
DSA *x;
EVP_CIPHER *enc;
unsigned char *kstr;
int klen;
int (*cb)();
	{
	return(PEM_ASN1_write((int (*)())i2d_DSAPrivateKey,PEM_STRING_DSA,fp,
		(char *)x,enc,kstr,klen,cb));
	}
#endif

int PEM_write_bio_DSAPrivateKey(bp,x,enc,kstr,klen,cb)
BIO *bp;
DSA *x;
EVP_CIPHER *enc;
unsigned char *kstr;
int klen;
int (*cb)();
	{
	return(PEM_ASN1_write_bio((int (*)())i2d_DSAPrivateKey,PEM_STRING_DSA,
		bp,(char *)x,enc,kstr,klen,cb));
	}
#endif

#ifndef NO_FP_API
/* The PrivateKey functions */
EVP_PKEY *PEM_read_PrivateKey(fp,x,cb)
FILE *fp;
EVP_PKEY **x;
int (*cb)();
	{
	return((EVP_PKEY *)PEM_ASN1_read((char *(*)())d2i_PrivateKey,
		PEM_STRING_EVP_PKEY,fp,(char **)x,cb));
	}
#endif

EVP_PKEY *PEM_read_bio_PrivateKey(bp,x,cb)
BIO *bp;
EVP_PKEY **x;
int (*cb)();
	{
	return((EVP_PKEY *)PEM_ASN1_read_bio((char *(*)())d2i_PrivateKey,
		PEM_STRING_EVP_PKEY,bp,(char **)x,cb));
	}

#ifndef NO_FP_API
int PEM_write_PrivateKey(fp,x,enc,kstr,klen,cb)
FILE *fp;
EVP_PKEY *x;
EVP_CIPHER *enc;
unsigned char *kstr;
int klen;
int (*cb)();
	{
	return(PEM_ASN1_write((int (*)())i2d_PrivateKey,
		((x->type == EVP_PKEY_DSA)?PEM_STRING_DSA:PEM_STRING_RSA),
		fp,(char *)x,enc,kstr,klen,cb));
	}
#endif

int PEM_write_bio_PrivateKey(bp,x,enc,kstr,klen,cb)
BIO *bp;
EVP_PKEY *x;
EVP_CIPHER *enc;
unsigned char *kstr;
int klen;
int (*cb)();
	{
	return(PEM_ASN1_write_bio((int (*)())i2d_PrivateKey,
		((x->type == EVP_PKEY_DSA)?PEM_STRING_DSA:PEM_STRING_RSA),
		bp,(char *)x,enc,kstr,klen,cb));
	}

#ifndef NO_FP_API
/* The PKCS7 functions */
PKCS7 *PEM_read_PKCS7(fp,x,cb)
FILE *fp;
PKCS7 **x;
int (*cb)();
	{
	return((PKCS7 *)PEM_ASN1_read((char *(*)())d2i_PKCS7,
		PEM_STRING_PKCS7,fp,(char **)x,cb));
	}
#endif

PKCS7 *PEM_read_bio_PKCS7(bp,x,cb)
BIO *bp;
PKCS7 **x;
int (*cb)();
	{
	return((PKCS7 *)PEM_ASN1_read_bio((char *(*)())d2i_PKCS7,
		PEM_STRING_PKCS7,bp,(char **)x,cb));
	}

#ifndef NO_FP_API
int PEM_write_PKCS7(fp,x)
FILE *fp;
PKCS7 *x;
	{
	return(PEM_ASN1_write((int (*)())i2d_PKCS7,PEM_STRING_PKCS7,fp,
		(char *)x, NULL,NULL,0,NULL));
	}
#endif

int PEM_write_bio_PKCS7(bp,x)
BIO *bp;
PKCS7 *x;
	{
	return(PEM_ASN1_write_bio((int (*)())i2d_PKCS7,PEM_STRING_PKCS7,bp,
		(char *)x, NULL,NULL,0,NULL));
	}

#ifndef NO_DH
#ifndef NO_FP_API
/* The DHparams functions */
DH *PEM_read_DHparams(fp,x,cb)
FILE *fp;
DH **x;
int (*cb)();
	{
	return((DH *)PEM_ASN1_read((char *(*)())d2i_DHparams,
		PEM_STRING_DHPARAMS,fp,(char **)x,cb));
	}
#endif

DH *PEM_read_bio_DHparams(bp,x,cb)
BIO *bp;
DH **x;
int (*cb)();
	{
	return((DH *)PEM_ASN1_read_bio((char *(*)())d2i_DHparams,
		PEM_STRING_DHPARAMS,bp,(char **)x,cb));
	}

#ifndef NO_FP_API
int PEM_write_DHparams(fp,x)
FILE *fp;
DH *x;
	{
	return(PEM_ASN1_write((int (*)())i2d_DHparams,PEM_STRING_DHPARAMS,fp,
		(char *)x, NULL,NULL,0,NULL));
	}
#endif

int PEM_write_bio_DHparams(bp,x)
BIO *bp;
DH *x;
	{
	return(PEM_ASN1_write_bio((int (*)())i2d_DHparams,PEM_STRING_DHPARAMS,
		bp,(char *)x, NULL,NULL,0,NULL));
	}
#endif

#ifndef NO_DSA
#ifndef NO_FP_API
/* The DSAparams functions */
DSA *PEM_read_DSAparams(fp,x,cb)
FILE *fp;
DSA **x;
int (*cb)();
	{
	return((DSA *)PEM_ASN1_read((char *(*)())d2i_DSAparams,
		PEM_STRING_DSAPARAMS,fp,(char **)x,cb));
	}
#endif

DSA *PEM_read_bio_DSAparams(bp,x,cb)
BIO *bp;
DSA **x;
int (*cb)();
	{
	return((DSA *)PEM_ASN1_read_bio((char *(*)())d2i_DSAparams,
		PEM_STRING_DSAPARAMS,bp,(char **)x,cb));
	}

#ifndef NO_FP_API
int PEM_write_DSAparams(fp,x)
FILE *fp;
DSA *x;
	{
	return(PEM_ASN1_write((int (*)())i2d_DSAparams,PEM_STRING_DSAPARAMS,fp,
		(char *)x, NULL,NULL,0,NULL));
	}
#endif

int PEM_write_bio_DSAparams(bp,x)
BIO *bp;
DSA *x;
	{
	return(PEM_ASN1_write_bio((int (*)())i2d_DSAparams,PEM_STRING_DSAPARAMS,
		bp,(char *)x, NULL,NULL,0,NULL));
	}
#endif

