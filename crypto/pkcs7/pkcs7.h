/* crypto/pkcs7/pkcs7.h */
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

#ifndef HEADER_PKCS7_H
#define HEADER_PKCS7_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "bio.h"
#include "x509.h"

/*
Encryption_ID		DES-CBC
Digest_ID		MD5
Digest_Encryption_ID	rsaEncryption
Key_Encryption_ID	rsaEncryption
*/

typedef struct pkcs7_issuer_and_serial_st
	{
	X509_NAME *issuer;
	ASN1_INTEGER *serial;
	} PKCS7_ISSUER_AND_SERIAL;

typedef struct pkcs7_signer_info_st
	{
	ASN1_INTEGER 			*version;	/* version 1 */
	PKCS7_ISSUER_AND_SERIAL		*issuer_and_serial;
	X509_ALGOR			*digest_alg;
	STACK /* X509_ATTRIBUTE */	*auth_attr;	/* [ 0 ] */
	X509_ALGOR			*digest_enc_alg;
	ASN1_OCTET_STRING		*enc_digest;
	STACK /* X509_ATTRIBUTE */	*unauth_attr;	/* [ 1 ] */

	/* The private key to sign with */
	EVP_PKEY			*pkey;
	} PKCS7_SIGNER_INFO;

typedef struct pkcs7_recip_info_st
	{
	ASN1_INTEGER			*version;	/* version 0 */
	PKCS7_ISSUER_AND_SERIAL		*issuer_and_serial;
	X509_ALGOR			*key_enc_algor;
	ASN1_OCTET_STRING		*enc_key;
	X509				*cert; /* get the pub-key from this */
	} PKCS7_RECIP_INFO;

typedef struct pkcs7_signed_st
	{
	ASN1_INTEGER			*version;	/* version 1 */
	STACK /* X509_ALGOR's */	*md_algs;	/* md used */
	STACK /* X509 */		*cert;		/* [ 0 ] */
	STACK /* X509_CRL */		*crl;		/* [ 1 ] */
	STACK /* PKCS7_SIGNER_INFO */	*signer_info;

	struct pkcs7_st			*contents;
	} PKCS7_SIGNED;
/* The above structure is very very similar to PKCS7_SIGN_ENVELOPE.
 * How about merging the two */

typedef struct pkcs7_enc_content_st
	{
	ASN1_OBJECT			*content_type;
	X509_ALGOR			*algorithm;
	ASN1_OCTET_STRING		*enc_data;	/* [ 0 ] */
	} PKCS7_ENC_CONTENT;

typedef struct pkcs7_enveloped_st
	{
	ASN1_INTEGER			*version;	/* version 0 */
	STACK /* PKCS7_RECIP_INFO */	*recipientinfo;
	PKCS7_ENC_CONTENT		*enc_data;
	} PKCS7_ENVELOPE;
	
typedef struct pkcs7_signedandenveloped_st
	{
	ASN1_INTEGER			*version;	/* version 1 */
	STACK /* X509_ALGOR's */	*md_algs;	/* md used */
	STACK /* X509 */		*cert;		/* [ 0 ] */
	STACK /* X509_CRL */		*crl;		/* [ 1 ] */
	STACK /* PKCS7_SIGNER_INFO */	*signer_info;

	PKCS7_ENC_CONTENT		*enc_data;
	STACK /* PKCS7_RECIP_INFO */	*recipientinfo;
	} PKCS7_SIGN_ENVELOPE;

typedef struct pkcs7_digest_st
	{
	ASN1_INTEGER			*version;	/* version 0 */
	X509_ALGOR			*md;		/* md used */
	struct pkcs7_st 		*contents;
	ASN1_OCTET_STRING		*digest;
	} PKCS7_DIGEST;

typedef struct pkcs7_encrypted_st
	{
	ASN1_INTEGER			*version;	/* version 0 */
	PKCS7_ENC_CONTENT		*enc_data;
	} PKCS7_ENCRYPT;

typedef struct pkcs7_st
	{
	/* The following is non NULL if it contains ASN1 encoding of
	 * this structure */
	unsigned char *asn1;
	long length;

#define PKCS7_S_HEADER	0
#define PKCS7_S_BODY	1
#define PKCS7_S_TAIL	2
	int state; /* used during processing */

	int detached;

	ASN1_OBJECT *type;
	/* content as defined by the type */
	/* all encryption/message digests are applied to the 'contents',
	 * leaving out the 'type' field. */
	union	{
		char *ptr;

		/* NID_pkcs7_data */
		ASN1_OCTET_STRING *data;

		/* NID_pkcs7_signed */
		PKCS7_SIGNED *sign;

		/* NID_pkcs7_enveloped */
		PKCS7_ENVELOPE *enveloped;

		/* NID_pkcs7_signedAndEnveloped */
		PKCS7_SIGN_ENVELOPE *signed_and_enveloped;

		/* NID_pkcs7_digest */
		PKCS7_DIGEST *digest;

		/* NID_pkcs7_encrypted */
		PKCS7_ENCRYPT *encrypted;
		} d;
	} PKCS7;

#define PKCS7_OP_SET_DETACHED_SIGNATURE	1
#define PKCS7_OP_GET_DETACHED_SIGNATURE	2

#define PKCS7_type_is_signed(a) (OBJ_obj2nid((a)->type) == NID_pkcs7_signed)
#define PKCS7_type_is_data(a)   (OBJ_obj2nid((a)->type) == NID_pkcs7_data)

#define PKCS7_set_detached(p,v) \
		PKCS7_ctrl(p,PKCS7_OP_SET_DETACHED_SIGNATURE,v,NULL)
#define PKCS7_get_detached(p) \
		PKCS7_ctrl(p,PKCS7_OP_GET_DETACHED_SIGNATURE,0,NULL)

#ifdef SSLEAY_MACROS

#define PKCS7_ISSUER_AND_SERIAL_digest(data,type,md,len) \
        ASN1_digest((int (*)())i2d_PKCS7_ISSUER_AND_SERIAL,type,\
	                (char *)data,md,len)
#endif


#ifndef NOPROTO
PKCS7_ISSUER_AND_SERIAL *PKCS7_ISSUER_AND_SERIAL_new(void );
void			PKCS7_ISSUER_AND_SERIAL_free(
				PKCS7_ISSUER_AND_SERIAL *a);
int 			i2d_PKCS7_ISSUER_AND_SERIAL(
				PKCS7_ISSUER_AND_SERIAL *a,unsigned char **pp);
PKCS7_ISSUER_AND_SERIAL *d2i_PKCS7_ISSUER_AND_SERIAL(
				PKCS7_ISSUER_AND_SERIAL **a,
				unsigned char **pp, long length);

#ifndef SSLEAY_MACROS
int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL *data,EVP_MD *type,
	unsigned char *md,unsigned int *len);
#ifndef NO_FP_API
PKCS7 *d2i_PKCS7_fp(FILE *fp,PKCS7 *p7);
int i2d_PKCS7_fp(FILE *fp,PKCS7 *p7);
#endif
PKCS7 *PKCS7_dup(PKCS7 *p7);
PKCS7 *d2i_PKCS7_bio(BIO *bp,PKCS7 *p7);
int i2d_PKCS7_bio(BIO *bp,PKCS7 *p7);
#endif

PKCS7_SIGNER_INFO	*PKCS7_SIGNER_INFO_new(void);
void			PKCS7_SIGNER_INFO_free(PKCS7_SIGNER_INFO *a);
int 			i2d_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO *a,
				unsigned char **pp);
PKCS7_SIGNER_INFO	*d2i_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO **a,
				unsigned char **pp,long length);

PKCS7_RECIP_INFO	*PKCS7_RECIP_INFO_new(void);
void			PKCS7_RECIP_INFO_free(PKCS7_RECIP_INFO *a);
int 			i2d_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO *a,
				unsigned char **pp);
PKCS7_RECIP_INFO	*d2i_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO **a,
				unsigned char **pp,long length);

PKCS7_SIGNED		*PKCS7_SIGNED_new(void);
void			PKCS7_SIGNED_free(PKCS7_SIGNED *a);
int 			i2d_PKCS7_SIGNED(PKCS7_SIGNED *a,
				unsigned char **pp);
PKCS7_SIGNED		*d2i_PKCS7_SIGNED(PKCS7_SIGNED **a,
				unsigned char **pp,long length);

PKCS7_ENC_CONTENT	*PKCS7_ENC_CONTENT_new(void);
void			PKCS7_ENC_CONTENT_free(PKCS7_ENC_CONTENT *a);
int 			i2d_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT *a,
				unsigned char **pp);
PKCS7_ENC_CONTENT	*d2i_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT **a,
				unsigned char **pp,long length);

PKCS7_ENVELOPE		*PKCS7_ENVELOPE_new(void);
void			PKCS7_ENVELOPE_free(PKCS7_ENVELOPE *a);
int 			i2d_PKCS7_ENVELOPE(PKCS7_ENVELOPE *a,
				unsigned char **pp);
PKCS7_ENVELOPE		*d2i_PKCS7_ENVELOPE(PKCS7_ENVELOPE **a,
				unsigned char **pp,long length);

PKCS7_SIGN_ENVELOPE	*PKCS7_SIGN_ENVELOPE_new(void);
void			PKCS7_SIGN_ENVELOPE_free(PKCS7_SIGN_ENVELOPE *a);
int 			i2d_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE *a,
				unsigned char **pp);
PKCS7_SIGN_ENVELOPE	*d2i_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE **a,
				unsigned char **pp,long length);

PKCS7_DIGEST		*PKCS7_DIGEST_new(void);
void			PKCS7_DIGEST_free(PKCS7_DIGEST *a);
int 			i2d_PKCS7_DIGEST(PKCS7_DIGEST *a,
				unsigned char **pp);
PKCS7_DIGEST		*d2i_PKCS7_DIGEST(PKCS7_DIGEST **a,
				unsigned char **pp,long length);

PKCS7_ENCRYPT		*PKCS7_ENCRYPT_new(void);
void			PKCS7_ENCRYPT_free(PKCS7_ENCRYPT *a);
int 			i2d_PKCS7_ENCRYPT(PKCS7_ENCRYPT *a,
				unsigned char **pp);
PKCS7_ENCRYPT		*d2i_PKCS7_ENCRYPT(PKCS7_ENCRYPT **a,
				unsigned char **pp,long length);

PKCS7			*PKCS7_new(void);
void			PKCS7_free(PKCS7 *a);
void			PKCS7_content_free(PKCS7 *a);
int 			i2d_PKCS7(PKCS7 *a,
				unsigned char **pp);
PKCS7			*d2i_PKCS7(PKCS7 **a,
				unsigned char **pp,long length);

void ERR_load_PKCS7_strings(void);


long PKCS7_ctrl(PKCS7 *p7, int cmd, long larg, char *parg);

int PKCS7_set_type(PKCS7 *p7, int type);
int PKCS7_set_content(PKCS7 *p7, PKCS7 *p7_data);
int PKCS7_SIGNER_INFO_set(PKCS7_SIGNER_INFO *p7i, X509 *x509, EVP_PKEY *pkey,
	EVP_MD *dgst);
int PKCS7_add_signer(PKCS7 *p7, PKCS7_SIGNER_INFO *p7i);
int PKCS7_add_certificate(PKCS7 *p7, X509 *x509);
int PKCS7_add_crl(PKCS7 *p7, X509_CRL *x509);
int PKCS7_content_new(PKCS7 *p7, int nid);
int PKCS7_dataSign(PKCS7 *p7, BIO *bio);
int PKCS7_dataVerify(X509_STORE *cert_store, X509_STORE_CTX *ctx,
	BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si); 

BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio);
/*int PKCS7_DataFinal(PKCS7 *p7, BIO *bio); */

PKCS7_SIGNER_INFO *PKCS7_add_signature(PKCS7 *p7, X509 *x509,
	EVP_PKEY *pkey, EVP_MD *dgst);
X509 *PKCS7_cert_from_signer_info(PKCS7 *p7, PKCS7_SIGNER_INFO *si);
STACK *PKCS7_get_signer_info(PKCS7 *p7);

PKCS7_RECIP_INFO *PKCS7_add_recipient(PKCS7 *p7, X509 *x509);
int PKCS7_add_recipient_info(PKCS7 *p7, PKCS7_RECIP_INFO *ri);
int PKCS7_RECIP_INFO_set(PKCS7_RECIP_INFO *p7i, X509 *x509);
int PKCS7_set_cipher(PKCS7 *p7, EVP_CIPHER *cipher);



#else

PKCS7_ISSUER_AND_SERIAL *PKCS7_ISSUER_AND_SERIAL_new();
void			PKCS7_ISSUER_AND_SERIAL_free();
int 			i2d_PKCS7_ISSUER_AND_SERIAL();
PKCS7_ISSUER_AND_SERIAL *d2i_PKCS7_ISSUER_AND_SERIAL();

#ifndef SSLEAY_MACROS
int			PKCS7_ISSUER_AND_SERIAL_digest();
#ifndef NO_FP_API
PKCS7 *d2i_PKCS7_fp();
int i2d_PKCS7_fp();
#endif
PKCS7 *PKCS7_dup();
PKCS7 *d2i_PKCS7_bio();
int i2d_PKCS7_bio();

#endif

PKCS7_SIGNER_INFO	*PKCS7_SIGNER_INFO_new();
void			PKCS7_SIGNER_INFO_free();
int 			i2d_PKCS7_SIGNER_INFO();
PKCS7_SIGNER_INFO	*d2i_PKCS7_SIGNER_INFO();
PKCS7_RECIP_INFO	*PKCS7_RECIP_INFO_new();
void			PKCS7_RECIP_INFO_free();
int 			i2d_PKCS7_RECIP_INFO();
PKCS7_RECIP_INFO	*d2i_PKCS7_RECIP_INFO();
PKCS7_SIGNED		*PKCS7_SIGNED_new();
void			PKCS7_SIGNED_free();
int 			i2d_PKCS7_SIGNED();
PKCS7_SIGNED		*d2i_PKCS7_SIGNED();
PKCS7_ENC_CONTENT	*PKCS7_ENC_CONTENT_new();
void			PKCS7_ENC_CONTENT_free();
int 			i2d_PKCS7_ENC_CONTENT();
PKCS7_ENC_CONTENT	*d2i_PKCS7_ENC_CONTENT();
PKCS7_ENVELOPE		*PKCS7_ENVELOPE_new();
void			PKCS7_ENVELOPE_free();
int 			i2d_PKCS7_ENVELOPE();
PKCS7_ENVELOPE		*d2i_PKCS7_ENVELOPE();
PKCS7_SIGN_ENVELOPE	*PKCS7_SIGN_ENVELOPE_new();
void			PKCS7_SIGN_ENVELOPE_free();
int 			i2d_PKCS7_SIGN_ENVELOPE();
PKCS7_SIGN_ENVELOPE	*d2i_PKCS7_SIGN_ENVELOPE();
PKCS7_DIGEST		*PKCS7_DIGEST_new();
void			PKCS7_DIGEST_free();
int 			i2d_PKCS7_DIGEST();
PKCS7_DIGEST		*d2i_PKCS7_DIGEST();
PKCS7_ENCRYPT		*PKCS7_ENCRYPT_new();
void			PKCS7_ENCRYPT_free();
int 			i2d_PKCS7_ENCRYPT();
PKCS7_ENCRYPT		*d2i_PKCS7_ENCRYPT();
PKCS7			*PKCS7_new();
void			PKCS7_free();
void			PKCS7_content_free();
int 			i2d_PKCS7();
PKCS7			*d2i_PKCS7();

void ERR_load_PKCS7_strings();

long PKCS7_ctrl();
int PKCS7_set_type();
int PKCS7_set_content();
int PKCS7_SIGNER_INFO_set();
int PKCS7_add_signer();
int PKCS7_add_certificate();
int PKCS7_add_crl();
int PKCS7_content_new();
int PKCS7_dataSign();
int PKCS7_dataVerify();
BIO *PKCS7_dataInit();
PKCS7_SIGNER_INFO *PKCS7_add_signature();
X509 *PKCS7_cert_from_signer_info();
STACK *PKCS7_get_signer_info();

PKCS7_RECIP_INFO *PKCS7_add_recipient();
int PKCS7_add_recipient_info();
int PKCS7_RECIP_INFO_set();
int PKCS7_set_cipher();

#endif

/* BEGIN ERROR CODES */
/* Error codes for the PKCS7 functions. */

/* Function codes. */
#define PKCS7_F_PKCS7_ADD_CERTIFICATE			 100
#define PKCS7_F_PKCS7_ADD_CRL				 101
#define PKCS7_F_PKCS7_ADD_RECIPIENT_INFO		 102
#define PKCS7_F_PKCS7_ADD_SIGNER			 103
#define PKCS7_F_PKCS7_CTRL				 104
#define PKCS7_F_PKCS7_DATAINIT				 105
#define PKCS7_F_PKCS7_DATASIGN				 106
#define PKCS7_F_PKCS7_DATAVERIFY			 107
#define PKCS7_F_PKCS7_SET_CIPHER			 108
#define PKCS7_F_PKCS7_SET_CONTENT			 109
#define PKCS7_F_PKCS7_SET_TYPE				 110

/* Reason codes. */
#define PKCS7_R_INTERNAL_ERROR				 100
#define PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE	 101
#define PKCS7_R_SIGNATURE_FAILURE			 102
#define PKCS7_R_UNABLE_TO_FIND_CERTIFICATE		 103
#define PKCS7_R_UNABLE_TO_FIND_MEM_BIO			 104
#define PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST		 105
#define PKCS7_R_UNKNOWN_DIGEST_TYPE			 106
#define PKCS7_R_UNSUPPORTED_CIPHER_TYPE			 107
#define PKCS7_R_UNSUPPORTED_CONTENT_TYPE		 108
#define PKCS7_R_WRONG_CONTENT_TYPE			 109
 
#ifdef  __cplusplus
}
#endif
#endif

