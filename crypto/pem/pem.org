/* crypto/pem/pem.org */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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

/* WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING 
 *
 * Always modify pem.org since pem.h is automatically generated from
 * it during SSLeay configuration.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 */

#ifndef HEADER_PEM_H
#define HEADER_PEM_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "evp.h"
#include "x509.h"

#define PEM_OBJ_UNDEF		0
#define PEM_OBJ_X509		1
#define PEM_OBJ_X509_REQ	2
#define PEM_OBJ_CRL		3
#define PEM_OBJ_SSL_SESSION	4
#define PEM_OBJ_PRIV_KEY	10
#define PEM_OBJ_PRIV_RSA	11
#define PEM_OBJ_PRIV_DSA	12
#define PEM_OBJ_PRIV_DH		13
#define PEM_OBJ_PUB_RSA		14
#define PEM_OBJ_PUB_DSA		15
#define PEM_OBJ_PUB_DH		16
#define PEM_OBJ_DHPARAMS	17
#define PEM_OBJ_DSAPARAMS	18
#define PEM_OBJ_PRIV_RSA_PUBLIC	19

#define PEM_ERROR		30
#define PEM_DEK_DES_CBC         40
#define PEM_DEK_IDEA_CBC        45
#define PEM_DEK_DES_EDE         50
#define PEM_DEK_DES_ECB         60
#define PEM_DEK_RSA             70
#define PEM_DEK_RSA_MD2         80
#define PEM_DEK_RSA_MD5         90

#define PEM_MD_MD2		NID_md2
#define PEM_MD_MD5		NID_md5
#define PEM_MD_SHA		NID_sha
#define PEM_MD_MD2_RSA		NID_md2WithRSAEncryption
#define PEM_MD_MD5_RSA		NID_md5WithRSAEncryption
#define PEM_MD_SHA_RSA		NID_sha1WithRSAEncryption

#define PEM_STRING_X509_OLD	"X509 CERTIFICATE"
#define PEM_STRING_X509		"CERTIFICATE"
#define PEM_STRING_X509_REQ_OLD	"NEW CERTIFICATE REQUEST"
#define PEM_STRING_X509_REQ	"CERTIFICATE REQUEST"
#define PEM_STRING_X509_CRL	"X509 CRL"
#define PEM_STRING_EVP_PKEY	"PRIVATE KEY"
#define PEM_STRING_RSA		"RSA PRIVATE KEY"
#define PEM_STRING_RSA_PUBLIC	"RSA PUBLIC KEY"
#define PEM_STRING_DSA		"DSA PRIVATE KEY"
#define PEM_STRING_PKCS7	"PKCS7"
#define PEM_STRING_DHPARAMS	"DH PARAMETERS"
#define PEM_STRING_SSL_SESSION	"SSL SESSION PARAMETERS"
#define PEM_STRING_DSAPARAMS	"DSA PARAMETERS"

#ifndef HEADER_ENVELOPE_H

#define EVP_ENCODE_CTX_SIZE  92
#define EVP_MD_SIZE  48
#define EVP_MD_CTX_SIZE  152
#define EVP_CIPHER_SIZE  28
#define EVP_CIPHER_CTX_SIZE  4212
#define EVP_MAX_MD_SIZE  20

typedef struct evp_encode_ctx_st
	{
	char data[EVP_ENCODE_CTX_SIZE];
	} EVP_ENCODE_CTX;

typedef struct env_md_ctx_st
	{
	char data[EVP_MD_CTX_SIZE];
	} EVP_MD_CTX;

typedef struct evp_cipher_st
	{
	char data[EVP_CIPHER_SIZE];
	} EVP_CIPHER;

typedef struct evp_cipher_ctx_st
	{
	char data[EVP_CIPHER_CTX_SIZE];
	} EVP_CIPHER_CTX;
#endif


typedef struct PEM_Encode_Seal_st
	{
	EVP_ENCODE_CTX encode;
	EVP_MD_CTX md;
	EVP_CIPHER_CTX cipher;
	} PEM_ENCODE_SEAL_CTX;

/* enc_type is one off */
#define PEM_TYPE_ENCRYPTED      10
#define PEM_TYPE_MIC_ONLY       20
#define PEM_TYPE_MIC_CLEAR      30
#define PEM_TYPE_CLEAR		40

typedef struct pem_recip_st
	{
	char *name;
	X509_NAME *dn;

	int cipher;
	int key_enc;
	char iv[8];
	} PEM_USER;

typedef struct pem_ctx_st
	{
	int type;		/* what type of object */

	struct	{
		int version;	
		int mode;		
		} proc_type;

	char *domain;

	struct	{
		int cipher;
		unsigned char iv[8];
		} DEK_info;
		
	PEM_USER *originator;

	int num_recipient;
	PEM_USER **recipient;

#ifdef HEADER_STACK_H
	STACK *x509_chain;	/* certificate chain */
#else
	char *x509_chain;	/* certificate chain */
#endif
	EVP_MD *md;		/* signature type */

	int md_enc;		/* is the md encrypted or not? */
	int md_len;		/* length of md_data */
	char *md_data;		/* message digest, could be pkey encrypted */

	EVP_CIPHER *dec;	/* date encryption cipher */
	int key_len;		/* key length */
	unsigned char *key;	/* key */
	unsigned char iv[8];	/* the iv */

	
	int  data_enc;		/* is the data encrypted */
	int data_len;
	unsigned char *data;
	} PEM_CTX;

#ifdef SSLEAY_MACROS

#define PEM_write_SSL_SESSION(fp,x) \
		PEM_ASN1_write((int (*)())i2d_SSL_SESSION, \
			PEM_STRING_SSL_SESSION,fp, (char *)x, NULL,NULL,0,NULL)
#define PEM_write_X509(fp,x) \
		PEM_ASN1_write((int (*)())i2d_X509,PEM_STRING_X509,fp, \
			(char *)x, NULL,NULL,0,NULL)
#define PEM_write_X509_REQ(fp,x) PEM_ASN1_write( \
		(int (*)())i2d_X509_REQ,PEM_STRING_X509_REQ,fp,(char *)x, \
			NULL,NULL,0,NULL)
#define PEM_write_X509_CRL(fp,x) \
		PEM_ASN1_write((int (*)())i2d_X509_CRL,PEM_STRING_X509_CRL, \
			fp,(char *)x, NULL,NULL,0,NULL)
#define	PEM_write_RSAPrivateKey(fp,x,enc,kstr,klen,cb) \
		PEM_ASN1_write((int (*)())i2d_RSAPrivateKey,PEM_STRING_RSA,fp,\
			(char *)x,enc,kstr,klen,cb)
#define	PEM_write_RSAPublicKey(fp,x) \
		PEM_ASN1_write((int (*)())i2d_RSAPublicKey,\
			PEM_STRING_RSA_PUBLIC,fp,(char *)x,NULL,NULL,0,NULL)
#define	PEM_write_DSAPrivateKey(fp,x,enc,kstr,klen,cb) \
		PEM_ASN1_write((int (*)())i2d_DSAPrivateKey,PEM_STRING_DSA,fp,\
			(char *)x,enc,kstr,klen,cb)
#define	PEM_write_PrivateKey(bp,x,enc,kstr,klen,cb) \
		PEM_ASN1_write((int (*)())i2d_PrivateKey,\
		(((x)->type == EVP_PKEY_DSA)?PEM_STRING_DSA:PEM_STRING_RSA),\
			bp,(char *)x,enc,kstr,klen,cb)
#define PEM_write_PKCS7(fp,x) \
		PEM_ASN1_write((int (*)())i2d_PKCS7,PEM_STRING_PKCS7,fp, \
			(char *)x, NULL,NULL,0,NULL)
#define PEM_write_DHparams(fp,x) \
		PEM_ASN1_write((int (*)())i2d_DHparams,PEM_STRING_DHPARAMS,fp,\
			(char *)x,NULL,NULL,0,NULL)

#define	PEM_read_SSL_SESSION(fp,x,cb) (SSL_SESSION *)PEM_ASN1_read( \
	(char *(*)())d2i_SSL_SESSION,PEM_STRING_SSL_SESSION,fp,(char **)x,cb)
#define	PEM_read_X509(fp,x,cb) (X509 *)PEM_ASN1_read( \
	(char *(*)())d2i_X509,PEM_STRING_X509,fp,(char **)x,cb)
#define	PEM_read_X509_REQ(fp,x,cb) (X509_REQ *)PEM_ASN1_read( \
	(char *(*)())d2i_X509_REQ,PEM_STRING_X509_REQ,fp,(char **)x,cb)
#define	PEM_read_X509_CRL(fp,x,cb) (X509_CRL *)PEM_ASN1_read( \
	(char *(*)())d2i_X509_CRL,PEM_STRING_X509_CRL,fp,(char **)x,cb)
#define	PEM_read_RSAPrivateKey(fp,x,cb) (RSA *)PEM_ASN1_read( \
	(char *(*)())d2i_RSAPrivateKey,PEM_STRING_RSA,fp,(char **)x,cb)
#define	PEM_read_RSAPublicKey(fp,x,cb) (RSA *)PEM_ASN1_read( \
	(char *(*)())d2i_RSAPublicKey,PEM_STRING_RSA_PUBLIC,fp,(char **)x,cb)
#define	PEM_read_DSAPrivateKey(fp,x,cb) (DSA *)PEM_ASN1_read( \
	(char *(*)())d2i_DSAPrivateKey,PEM_STRING_DSA,fp,(char **)x,cb)
#define	PEM_read_PrivateKey(fp,x,cb) (EVP_PKEY *)PEM_ASN1_read( \
	(char *(*)())d2i_PrivateKey,PEM_STRING_EVP_PKEY,fp,(char **)x,cb)
#define	PEM_read_PKCS7(fp,x,cb) (PKCS7 *)PEM_ASN1_read( \
	(char *(*)())d2i_PKCS7,PEM_STRING_PKCS7,fp,(char **)x,cb)
#define	PEM_read_DHparams(fp,x,cb) (DH *)PEM_ASN1_read( \
	(char *(*)())d2i_DHparams,PEM_STRING_DHPARAMS,fp,(char **)x,cb)

#define PEM_write_bio_SSL_SESSION(bp,x) \
		PEM_ASN1_write_bio((int (*)())i2d_SSL_SESSION, \
			PEM_STRING_SSL_SESSION,bp, (char *)x, NULL,NULL,0,NULL)
#define PEM_write_bio_X509(bp,x) \
		PEM_ASN1_write_bio((int (*)())i2d_X509,PEM_STRING_X509,bp, \
			(char *)x, NULL,NULL,0,NULL)
#define PEM_write_bio_X509_REQ(bp,x) PEM_ASN1_write_bio( \
		(int (*)())i2d_X509_REQ,PEM_STRING_X509_REQ,bp,(char *)x, \
			NULL,NULL,0,NULL)
#define PEM_write_bio_X509_CRL(bp,x) \
		PEM_ASN1_write_bio((int (*)())i2d_X509_CRL,PEM_STRING_X509_CRL,\
			bp,(char *)x, NULL,NULL,0,NULL)
#define	PEM_write_bio_RSAPrivateKey(bp,x,enc,kstr,klen,cb) \
		PEM_ASN1_write_bio((int (*)())i2d_RSAPrivateKey,PEM_STRING_RSA,\
			bp,(char *)x,enc,kstr,klen,cb)
#define	PEM_write_bio_RSAPublicKey(bp,x) \
		PEM_ASN1_write_bio((int (*)())i2d_RSAPublicKey, \
			PEM_STRING_RSA_PUBLIC,\
			bp,(char *)x,NULL,NULL,0,NULL)
#define	PEM_write_bio_DSAPrivateKey(bp,x,enc,kstr,klen,cb) \
		PEM_ASN1_write_bio((int (*)())i2d_DSAPrivateKey,PEM_STRING_DSA,\
			bp,(char *)x,enc,kstr,klen,cb)
#define	PEM_write_bio_PrivateKey(bp,x,enc,kstr,klen,cb) \
		PEM_ASN1_write_bio((int (*)())i2d_PrivateKey,\
		(((x)->type == EVP_PKEY_DSA)?PEM_STRING_DSA:PEM_STRING_RSA),\
			bp,(char *)x,enc,kstr,klen,cb)
#define PEM_write_bio_PKCS7(bp,x) \
		PEM_ASN1_write_bio((int (*)())i2d_PKCS7,PEM_STRING_PKCS7,bp, \
			(char *)x, NULL,NULL,0,NULL)
#define PEM_write_bio_DHparams(bp,x) \
		PEM_ASN1_write_bio((int (*)())i2d_DHparams,PEM_STRING_DHPARAMS,\
			bp,(char *)x,NULL,NULL,0,NULL)
#define PEM_write_bio_DSAparams(bp,x) \
		PEM_ASN1_write_bio((int (*)())i2d_DSAparams, \
			PEM_STRING_DSAPARAMS,bp,(char *)x,NULL,NULL,0,NULL)

#define	PEM_read_bio_SSL_SESSION(bp,x,cb) (SSL_SESSION *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_SSL_SESSION,PEM_STRING_SSL_SESSION,bp,(char **)x,cb)
#define	PEM_read_bio_X509(bp,x,cb) (X509 *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_X509,PEM_STRING_X509,bp,(char **)x,cb)
#define	PEM_read_bio_X509_REQ(bp,x,cb) (X509_REQ *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_X509_REQ,PEM_STRING_X509_REQ,bp,(char **)x,cb)
#define	PEM_read_bio_X509_CRL(bp,x,cb) (X509_CRL *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_X509_CRL,PEM_STRING_X509_CRL,bp,(char **)x,cb)
#define	PEM_read_bio_RSAPrivateKey(bp,x,cb) (RSA *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_RSAPrivateKey,PEM_STRING_RSA,bp,(char **)x,cb)
#define	PEM_read_bio_RSAPublicKey(bp,x,cb) (RSA *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_RSAPublicKey,PEM_STRING_RSA_PUBLIC,bp,(char **)x,cb)
#define	PEM_read_bio_DSAPrivateKey(bp,x,cb) (DSA *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_DSAPrivateKey,PEM_STRING_DSA,bp,(char **)x,cb)
#define	PEM_read_bio_PrivateKey(bp,x,cb) (EVP_PKEY *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_PrivateKey,PEM_STRING_EVP_PKEY,bp,(char **)x,cb)

#define	PEM_read_bio_PKCS7(bp,x,cb) (PKCS7 *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_PKCS7,PEM_STRING_PKCS7,bp,(char **)x,cb)
#define	PEM_read_bio_DHparams(bp,x,cb) (DH *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_DHparams,PEM_STRING_DHPARAMS,bp,(char **)x,cb)
#define	PEM_read_bio_DSAparams(bp,x,cb) (DSA *)PEM_ASN1_read_bio( \
	(char *(*)())d2i_DSAparams,PEM_STRING_DSAPARAMS,bp,(char **)x,cb)

#endif

#ifndef NOPROTO
int	PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher);
int	PEM_do_header (EVP_CIPHER_INFO *cipher, unsigned char *data,long *len,
		int (*callback)());

#ifdef HEADER_BIO_H
int	PEM_read_bio(BIO *bp, char **name, char **header,
		unsigned char **data,long *len);
int	PEM_write_bio(BIO *bp,char *name,char *hdr,unsigned char *data,
		long len);
char *	PEM_ASN1_read_bio(char *(*d2i)(),char *name,BIO *bp,char **x,
		int (*cb)());
int	PEM_ASN1_write_bio(int (*i2d)(),char *name,BIO *bp,char *x,
		EVP_CIPHER *enc,unsigned char *kstr,int klen,int (*callback)());
STACK *	PEM_X509_INFO_read_bio(BIO *bp, STACK *sk, int (*cb)());
int	PEM_X509_INFO_write_bio(BIO *bp,X509_INFO *xi, EVP_CIPHER *enc,
		unsigned char *kstr, int klen, int (*cb)());
#endif

#ifndef WIN16
int	PEM_read(FILE *fp, char **name, char **header,
		unsigned char **data,long *len);
int	PEM_write(FILE *fp,char *name,char *hdr,unsigned char *data,long len);
char *	PEM_ASN1_read(char *(*d2i)(),char *name,FILE *fp,char **x,
		int (*cb)());
int	PEM_ASN1_write(int (*i2d)(),char *name,FILE *fp,char *x,
		EVP_CIPHER *enc,unsigned char *kstr,int klen,int (*callback)());
STACK *	PEM_X509_INFO_read(FILE *fp, STACK *sk, int (*cb)());
#endif

int	PEM_SealInit(PEM_ENCODE_SEAL_CTX *ctx, EVP_CIPHER *type,
		EVP_MD *md_type, unsigned char **ek, int *ekl,
		unsigned char *iv, EVP_PKEY **pubk, int npubk);
void	PEM_SealUpdate(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *out, int *outl,
		unsigned char *in, int inl);
int	PEM_SealFinal(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *sig,int *sigl,
		unsigned char *out, int *outl, EVP_PKEY *priv);

void    PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type);
void    PEM_SignUpdate(EVP_MD_CTX *ctx,unsigned char *d,unsigned int cnt);
int	PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
		unsigned int *siglen, EVP_PKEY *pkey);

void	ERR_load_PEM_strings(void);

void	PEM_proc_type(char *buf, int type);
void	PEM_dek_info(char *buf, char *type, int len, char *str);

#ifndef SSLEAY_MACROS

#ifndef WIN16
X509 *PEM_read_X509(FILE *fp,X509 **x,int (*cb)());
X509_REQ *PEM_read_X509_REQ(FILE *fp,X509_REQ **x,int (*cb)());
X509_CRL *PEM_read_X509_CRL(FILE *fp,X509_CRL **x,int (*cb)());
RSA *PEM_read_RSAPrivateKey(FILE *fp,RSA **x,int (*cb)());
RSA *PEM_read_RSAPublicKey(FILE *fp,RSA **x,int (*cb)());
DSA *PEM_read_DSAPrivateKey(FILE *fp,DSA **x,int (*cb)());
EVP_PKEY *PEM_read_PrivateKey(FILE *fp,EVP_PKEY **x,int (*cb)());
PKCS7 *PEM_read_PKCS7(FILE *fp,PKCS7 **x,int (*cb)());
DH *PEM_read_DHparams(FILE *fp,DH **x,int (*cb)());
DSA *PEM_read_DSAparams(FILE *fp,DSA **x,int (*cb)());
int PEM_write_X509(FILE *fp,X509 *x);
int PEM_write_X509_REQ(FILE *fp,X509_REQ *x);
int PEM_write_X509_CRL(FILE *fp,X509_CRL *x);
int PEM_write_RSAPrivateKey(FILE *fp,RSA *x,EVP_CIPHER *enc,unsigned char *kstr,
        int klen,int (*cb)());
int PEM_write_RSAPublicKey(FILE *fp,RSA *x);
int PEM_write_DSAPrivateKey(FILE *fp,DSA *x,EVP_CIPHER *enc,unsigned char *kstr,
        int klen,int (*cb)());
int PEM_write_PrivateKey(FILE *fp,EVP_PKEY *x,EVP_CIPHER *enc,
	unsigned char *kstr,int klen,int (*cb)());
int PEM_write_PKCS7(FILE *fp,PKCS7 *x);
int PEM_write_DHparams(FILE *fp,DH *x);
int PEM_write_DSAparams(FILE *fp,DSA *x);
#endif

#ifdef HEADER_BIO_H
X509 *PEM_read_bio_X509(BIO *bp,X509 **x,int (*cb)());
X509_REQ *PEM_read_bio_X509_REQ(BIO *bp,X509_REQ **x,int (*cb)());
X509_CRL *PEM_read_bio_X509_CRL(BIO *bp,X509_CRL **x,int (*cb)());
RSA *PEM_read_bio_RSAPrivateKey(BIO *bp,RSA **x,int (*cb)());
RSA *PEM_read_bio_RSAPublicKey(BIO *bp,RSA **x,int (*cb)());
DSA *PEM_read_bio_DSAPrivateKey(BIO *bp,DSA **x,int (*cb)());
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp,EVP_PKEY **x,int (*cb)());
PKCS7 *PEM_read_bio_PKCS7(BIO *bp,PKCS7 **x,int (*cb)());
DH *PEM_read_bio_DHparams(BIO *bp,DH **x,int (*cb)());
DSA *PEM_read_bio_DSAparams(BIO *bp,DSA **x,int (*cb)());
int PEM_write_bio_X509(BIO *bp,X509 *x);
int PEM_write_bio_X509_REQ(BIO *bp,X509_REQ *x);
int PEM_write_bio_X509_CRL(BIO *bp,X509_CRL *x);
int PEM_write_bio_RSAPrivateKey(BIO *fp,RSA *x,EVP_CIPHER *enc,
        unsigned char *kstr,int klen,int (*cb)());
int PEM_write_bio_RSAPublicKey(BIO *fp,RSA *x);
int PEM_write_bio_DSAPrivateKey(BIO *fp,DSA *x,EVP_CIPHER *enc,
        unsigned char *kstr,int klen,int (*cb)());
int PEM_write_bio_PrivateKey(BIO *fp,EVP_PKEY *x,EVP_CIPHER *enc,
        unsigned char *kstr,int klen,int (*cb)());
int PEM_write_bio_PKCS7(BIO *bp,PKCS7 *x);
int PEM_write_bio_DHparams(BIO *bp,DH *x);
int PEM_write_bio_DSAparams(BIO *bp,DSA *x);
#endif

#endif /* SSLEAY_MACROS */


#else

int	PEM_get_EVP_CIPHER_INFO();
int	PEM_do_header();
int	PEM_read_bio();
int	PEM_write_bio();
#ifndef WIN16
int	PEM_read();
int	PEM_write();
STACK *	PEM_X509_INFO_read();
char *	PEM_ASN1_read();
int	PEM_ASN1_write();
#endif
STACK *	PEM_X509_INFO_read_bio();
int	PEM_X509_INFO_write_bio();
char *	PEM_ASN1_read_bio();
int	PEM_ASN1_write_bio();
int	PEM_SealInit();
void	PEM_SealUpdate();
int	PEM_SealFinal();
int	PEM_SignFinal();

void	ERR_load_PEM_strings();

void	PEM_proc_type();
void	PEM_dek_info();

#ifndef SSLEAY_MACROS
#ifndef WIN16
X509 *PEM_read_X509();
X509_REQ *PEM_read_X509_REQ();
X509_CRL *PEM_read_X509_CRL();
RSA *PEM_read_RSAPrivateKey();
RSA *PEM_read_RSAPublicKey();
DSA *PEM_read_DSAPrivateKey();
EVP_PKEY *PEM_read_PrivateKey();
PKCS7 *PEM_read_PKCS7();
DH *PEM_read_DHparams();
DSA *PEM_read_DSAparams();
int PEM_write_X509();
int PEM_write_X509_REQ();
int PEM_write_X509_CRL();
int PEM_write_RSAPrivateKey();
int PEM_write_RSAPublicKey();
int PEM_write_DSAPrivateKey();
int PEM_write_PrivateKey();
int PEM_write_PKCS7();
int PEM_write_DHparams();
int PEM_write_DSAparams();
#endif

X509 *PEM_read_bio_X509();
X509_REQ *PEM_read_bio_X509_REQ();
X509_CRL *PEM_read_bio_X509_CRL();
RSA *PEM_read_bio_RSAPrivateKey();
RSA *PEM_read_bio_RSAPublicKey();
DSA *PEM_read_bio_DSAPrivateKey();
EVP_PKEY *PEM_read_bio_PrivateKey();
PKCS7 *PEM_read_bio_PKCS7();
DH *PEM_read_bio_DHparams();
DSA *PEM_read_bio_DSAparams();
int PEM_write_bio_X509();
int PEM_write_bio_X509_REQ();
int PEM_write_bio_X509_CRL();
int PEM_write_bio_RSAPrivateKey();
int PEM_write_bio_RSAPublicKey();
int PEM_write_bio_DSAPrivateKey();
int PEM_write_bio_PrivateKey();
int PEM_write_bio_PKCS7();
int PEM_write_bio_DHparams();
int PEM_write_bio_DSAparams();

#endif /* SSLEAY_MACROS */

#endif

/* BEGIN ERROR CODES */
/* Error codes for the PEM functions. */

/* Function codes. */
#define PEM_F_DEF_CALLBACK				 100
#define PEM_F_LOAD_IV					 101
#define PEM_F_PEM_ASN1_READ				 102
#define PEM_F_PEM_ASN1_READ_BIO				 103
#define PEM_F_PEM_ASN1_WRITE				 104
#define PEM_F_PEM_ASN1_WRITE_BIO			 105
#define PEM_F_PEM_DO_HEADER				 106
#define PEM_F_PEM_GET_EVP_CIPHER_INFO			 107
#define PEM_F_PEM_READ					 108
#define PEM_F_PEM_READ_BIO				 109
#define PEM_F_PEM_SEALFINAL				 110
#define PEM_F_PEM_SEALINIT				 111
#define PEM_F_PEM_SIGNFINAL				 112
#define PEM_F_PEM_WRITE					 113
#define PEM_F_PEM_WRITE_BIO				 114
#define PEM_F_PEM_X509_INFO_READ			 115
#define PEM_F_PEM_X509_INFO_READ_BIO			 116
#define PEM_F_PEM_X509_INFO_WRITE_BIO			 117

/* Reason codes. */
#define PEM_R_BAD_BASE64_DECODE				 100
#define PEM_R_BAD_DECRYPT				 101
#define PEM_R_BAD_END_LINE				 102
#define PEM_R_BAD_IV_CHARS				 103
#define PEM_R_BAD_PASSWORD_READ				 104
#define PEM_R_NOT_DEK_INFO				 105
#define PEM_R_NOT_ENCRYPTED				 106
#define PEM_R_NOT_PROC_TYPE				 107
#define PEM_R_NO_START_LINE				 108
#define PEM_R_PROBLEMS_GETTING_PASSWORD			 109
#define PEM_R_PUBLIC_KEY_NO_RSA				 110
#define PEM_R_READ_KEY					 111
#define PEM_R_SHORT_HEADER				 112
#define PEM_R_UNSUPPORTED_CIPHER			 113
#define PEM_R_UNSUPPORTED_ENCRYPTION			 114
 
#ifdef  __cplusplus
}
#endif
#endif

