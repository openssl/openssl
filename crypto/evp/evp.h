/* crypto/evp/evp.h */
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

#ifndef HEADER_ENVELOPE_H
#define HEADER_ENVELOPE_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef NO_MD2
#include "md2.h"
#endif
#ifndef NO_MD5
#include "md5.h"
#endif
#if !defined(NO_SHA) || !defined(NO_SHA1)
#include "sha.h"
#endif
#ifndef NO_DES
#include "des.h"
#endif
#ifndef NO_RC4
#include "rc4.h"
#endif
#ifndef NO_RC2
#include "rc2.h"
#endif
#ifndef NO_BLOWFISH
#include "blowfish.h"
#endif
#ifndef NO_IDEA
#include "idea.h"
#endif
#ifndef NO_MDC2
#include "mdc2.h"
#endif

#define EVP_RC2_KEY_SIZE	16
#define EVP_RC4_KEY_SIZE	16
#define EVP_BLOWFISH_KEY_SIZE	16
#define EVP_MAX_MD_SIZE		20
#define EVP_MAX_KEY_LENGTH	24
#define EVP_MAX_IV_LENGTH	8

#ifndef NO_RSA
#include "rsa.h"
#else
#define RSA	long
#endif

#ifndef NO_DSA
#include "dsa.h"
#else
#define DSA	long
#endif

#ifndef NO_DH
#include "dh.h"
#else
#define DH	long
#endif

#include "objects.h"

#define EVP_PK_RSA	0x0001
#define EVP_PK_DSA	0x0002
#define EVP_PK_DH	0x0004
#define EVP_PKT_SIGN	0x0010
#define EVP_PKT_ENC	0x0020
#define EVP_PKT_EXCH	0x0040
#define EVP_PKS_RSA	0x0100
#define EVP_PKS_DSA	0x0200
#define EVP_PKT_EXP	0x1000 /* <= 512 bit key */

#define EVP_PKEY_NONE	NID_undef
#define EVP_PKEY_RSA	NID_rsaEncryption
#define EVP_PKEY_RSA2	NID_rsa
#define EVP_PKEY_DSA	NID_dsa
#define EVP_PKEY_DSA2	NID_dsaWithSHA
#define EVP_PKEY_DSA3	NID_dsaWithSHA1
#define EVP_PKEY_DH	NID_dhKeyAgreement

typedef struct evp_pkey_st
	{
	int type;
	int save_type;
	int references;
	union	{
		char *ptr;
		struct rsa_st *rsa;	/* RSA */
		struct dsa_st *dsa;	/* DSA */
		struct dh_st *dh;	/* DH */
		} pkey;
	int save_parameters;
#ifdef HEADER_STACK_H
	STACK /* X509_ATTRIBUTE */ *attributes; /* [ 0 ] */
#else
	char /* X509_ATTRIBUTE */ *attributes; /* [ 0 ] */
#endif
	} EVP_PKEY;

#ifndef EVP_MD
typedef struct env_md_st
	{
	int type;
	int pkey_type;
	int md_size;
	void (*init)();
	void (*update)();
	void (*final)();

	int (*sign)();
	int (*verify)();
	int required_pkey_type[4]; /*EVP_PKEY_xxx */
	} EVP_MD;

#define EVP_PKEY_NULL_method	NULL,NULL,{0,0,0,0}

#ifndef NO_DSA
#define EVP_PKEY_DSA_method	DSA_sign,DSA_verify, \
				{EVP_PKEY_DSA,EVP_PKEY_DSA2,EVP_PKEY_DSA3,0}
#else
#define EVP_PKEY_DSA_method	EVP_PKEY_NULL_method
#endif

#ifndef NO_RSA
#define EVP_PKEY_RSA_method	RSA_sign,RSA_verify, \
				{EVP_PKEY_RSA,EVP_PKEY_RSA2,0,0}
#define EVP_PKEY_RSA_ASN1_OCTET_STRING_method \
				RSA_sign_ASN1_OCTET_STRING, \
				RSA_verify_ASN1_OCTET_STRING, \
				{EVP_PKEY_RSA,EVP_PKEY_RSA2,0,0}
#else
#define EVP_PKEY_RSA_method	EVP_PKEY_NULL_method
#define EVP_PKEY_RSA_ASN1_OCTET_STRING_method EVP_PKEY_NULL_method
#endif

#endif /* !EVP_MD */

typedef struct env_md_ctx_st
	{
	EVP_MD *digest;
	union	{
		unsigned char base[4];
#ifndef NO_MD2
		MD2_CTX md2;
#endif
#ifndef NO_MD5
		MD5_CTX md5;
#endif
#if !defined(NO_SHA) || !defined(NO_SHA1)
		SHA_CTX sha;
#endif
#ifndef NO_MDC2
		MDC2_CTX mdc2;
#endif
		} md;
	} EVP_MD_CTX;

typedef struct evp_cipher_st
	{
	int nid;
	int block_size;
	int key_len;
	int iv_len;
	void (*init)();		/* init for encryption */
	void (*do_cipher)();	/* encrypt data */
	void (*cleanup)();	/* used by cipher method */ 
	} EVP_CIPHER;

typedef struct evp_cipher_info_st
	{
	EVP_CIPHER *cipher;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	} EVP_CIPHER_INFO;

typedef struct evp_cipher_ctx_st
	{
	EVP_CIPHER *cipher;
	int encrypt;		/* encrypt or decrypt */
	int buf_len;		/* number we have left */
	unsigned char buf[8];
	char *app_data;		/* aplication stuff */
	union	{
#ifndef NO_RC4
		struct
			{
			unsigned char key[EVP_RC4_KEY_SIZE];
			RC4_KEY ks;	/* working key */
			} rc4;
#endif
#ifndef NO_DES
		struct
			{
			des_key_schedule ks;/* key schedule */
			} des_ecb;

		struct
			{
			C_Block oiv;	/* original iv */
			C_Block iv;	/* working iv */
			des_key_schedule ks;/* key schedule */
			} des_cbc;

		struct
			{
			C_Block oiv;	/* original iv */
			C_Block iv;	/* working iv */
			C_Block inw;
			C_Block outw;
			des_key_schedule ks;/* key schedule */
			} desx_cbc;

		struct
			{
			C_Block oiv;	/* original iv */
			C_Block iv;	/* working iv */
			des_key_schedule ks;/* key schedule */
			des_key_schedule ks2;/* key schedule (for ede) */
			des_key_schedule ks3;/* key schedule (for ede3) */
			int num;	/* used by cfb mode */
			} des_cfb;

		struct
			{
			C_Block oiv;	/* original iv */
			C_Block iv;	/* working iv */
			des_key_schedule ks1;/* ksched 1 */
			des_key_schedule ks2;/* ksched 2 */
			des_key_schedule ks3;/* ksched 3 */
			} des_ede;
#endif
#ifndef NO_IDEA
		struct
			{
			IDEA_KEY_SCHEDULE ks;/* key schedule */
			} idea_ecb;
		struct
			{
			unsigned char oiv[8];/* original iv */
			unsigned char iv[8]; /* working iv */
			IDEA_KEY_SCHEDULE ks;/* key schedule */
			} idea_cbc;
		struct
			{
			unsigned char oiv[8];/* original iv */
			unsigned char iv[8]; /* working iv */
			IDEA_KEY_SCHEDULE ks;/* key schedule */
			int num;	/* used by cfb mode */
			} idea_cfb;
#endif
#ifndef NO_RC2
		struct
			{
			RC2_KEY ks;/* key schedule */
			} rc2_ecb;
		struct
			{
			unsigned char oiv[8];/* original iv */
			unsigned char iv[8]; /* working iv */
			RC2_KEY ks;/* key schedule */
			} rc2_cbc;
		struct
			{
			unsigned char oiv[8];/* original iv */
			unsigned char iv[8]; /* working iv */
			RC2_KEY ks;/* key schedule */
			int num;	/* used by cfb mode */
			} rc2_cfb;
#endif
#ifndef NO_BLOWFISH
		struct
			{
			BF_KEY ks;/* key schedule */
			} bf_ecb;
		struct
			{
			unsigned char oiv[8];/* original iv */
			unsigned char iv[8]; /* working iv */
			BF_KEY ks;/* key schedule */
			} bf_cbc;
		struct
			{
			unsigned char oiv[8];/* original iv */
			unsigned char iv[8]; /* working iv */
			BF_KEY ks;/* key schedule */
			int num;	/* used by cfb mode */
			} bf_cfb;
#endif
		} c;
	} EVP_CIPHER_CTX;

typedef struct evp_Encode_Ctx_st
	{
	int num;	/* number saved in a partial encode/decode */
	int length;	/* The length is either the output line length
			 * (in input bytes) or the shortest input line
			 * length that is ok.  Once decoding begins,
			 * the length is adjusted up each time a longer
			 * line is decoded */
	unsigned char enc_data[80];	/* data to encode */
	int line_num;	/* number read on current line */
	} EVP_ENCODE_CTX;

#define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
					(char *)(rsa))
#define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA,\
					(char *)(dsa))
#define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH,\
					(char *)(dh))

/* Add some extra combinations */
#define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a))
#define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a))
#define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a))
#define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a))

#define EVP_MD_type(e)			((e)->type)
#define EVP_MD_pkey_type(e)		((e)->pkey_type)
#define EVP_MD_size(e)			((e)->md_size)
#define EVP_MD_CTX_size(e)		((e)->digest->md_size)
#define EVP_MD_CTX_type(e)		((e)->digest)

#define EVP_CIPHER_nid(e)		((e)->nid)
#define EVP_CIPHER_block_size(e)	((e)->block_size)
#define EVP_CIPHER_key_length(e)	((e)->key_len)
#define EVP_CIPHER_iv_length(e)		((e)->iv_len)

#define EVP_CIPHER_CTX_cipher(e)	((e)->cipher)
#define EVP_CIPHER_CTX_nid(e)		((e)->cipher->nid)
#define EVP_CIPHER_CTX_block_size(e)	((e)->cipher->block_size)
#define EVP_CIPHER_CTX_key_length(e)	((e)->cipher->key_len)
#define EVP_CIPHER_CTX_iv_length(e)	((e)->cipher->iv_len)
#define EVP_CIPHER_CTX_get_app_data(e)	((e)->app_data)
#define EVP_CIPHER_CTX_set_app_data(e,d) ((e)->app_data=(char *)(d))

#define EVP_ENCODE_LENGTH(l)	(((l+2)/3*4)+(l/48+1)*2+80)
#define EVP_DECODE_LENGTH(l)	((l+3)/4*3+80)

#define EVP_SignInit(a,b)		EVP_DigestInit(a,b)
#define EVP_SignUpdate(a,b,c)		EVP_DigestUpdate(a,b,c)
#define	EVP_VerifyInit(a,b)		EVP_DigestInit(a,b)
#define	EVP_VerifyUpdate(a,b,c)		EVP_DigestUpdate(a,b,c)
#define EVP_OpenUpdate(a,b,c,d,e)	EVP_DecryptUpdate(a,b,c,d,e)
#define EVP_SealUpdate(a,b,c,d,e)	EVP_EncryptUpdate(a,b,c,d,e)	

#define BIO_set_md(b,md)		BIO_ctrl(b,BIO_C_SET_MD,0,(char *)md)
#define BIO_get_md(b,mdp)		BIO_ctrl(b,BIO_C_GET_MD,0,(char *)mdp)
#define BIO_get_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_GET_MD_CTX,0,(char *)mdcp)
#define BIO_get_cipher_status(b)	BIO_ctrl(b,BIO_C_GET_CIPHER_STATUS,0,NULL)

#define	EVP_Cipher(c,o,i,l)	(c)->cipher->do_cipher((c),(o),(i),(l))

#ifndef NOPROTO

void	EVP_DigestInit(EVP_MD_CTX *ctx, EVP_MD *type);
void	EVP_DigestUpdate(EVP_MD_CTX *ctx,unsigned char *d,unsigned int cnt);
void	EVP_DigestFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s);

int	EVP_read_pw_string(char *buf,int length,char *prompt,int verify);
void	EVP_set_pw_prompt(char *prompt);
char *	EVP_get_pw_prompt(void);

int	EVP_BytesToKey(EVP_CIPHER *type,EVP_MD *md,unsigned char *salt,
		unsigned char *data, int datal, int count,
		unsigned char *key,unsigned char *iv);

EVP_CIPHER *EVP_get_cipherbyname(char *name);

void	EVP_EncryptInit(EVP_CIPHER_CTX *ctx,EVP_CIPHER *type,
		unsigned char *key, unsigned char *iv);
void	EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
		int *outl, unsigned char *in, int inl);
void	EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

void	EVP_DecryptInit(EVP_CIPHER_CTX *ctx,EVP_CIPHER *type,
		unsigned char *key, unsigned char *iv);
void	EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
		int *outl, unsigned char *in, int inl);
int	EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

void	EVP_CipherInit(EVP_CIPHER_CTX *ctx,EVP_CIPHER *type, unsigned char *key,
		unsigned char *iv,int enc);
void	EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
		int *outl, unsigned char *in, int inl);
int	EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

int	EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s,
		EVP_PKEY *pkey);

int	EVP_VerifyFinal(EVP_MD_CTX *ctx,unsigned char *sigbuf,
		unsigned int siglen,EVP_PKEY *pkey);

int	EVP_OpenInit(EVP_CIPHER_CTX *ctx,EVP_CIPHER *type,unsigned char *ek,
		int ekl,unsigned char *iv,EVP_PKEY *priv);
int	EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int	EVP_SealInit(EVP_CIPHER_CTX *ctx, EVP_CIPHER *type, unsigned char **ek,
		int *ekl, unsigned char *iv,EVP_PKEY **pubk, int npubk);
void	EVP_SealFinal(EVP_CIPHER_CTX *ctx,unsigned char *out,int *outl);

void	EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
void	EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,
		int *outl,unsigned char *in,int inl);
void	EVP_EncodeFinal(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl);
int	EVP_EncodeBlock(unsigned char *t, unsigned char *f, int n);

void	EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
int	EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl,
		unsigned char *in, int inl);
int	EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned
		char *out, int *outl);
int	EVP_DecodeBlock(unsigned char *t, unsigned
		char *f, int n);

void	ERR_load_EVP_strings(void );

void EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);

#ifdef HEADER_BIO_H
BIO_METHOD *BIO_f_md(void);
BIO_METHOD *BIO_f_base64(void);
BIO_METHOD *BIO_f_cipher(void);
void BIO_set_cipher(BIO *b,EVP_CIPHER *c,unsigned char *k,
	unsigned char *i, int enc);
#endif

EVP_MD *EVP_md_null(void);
EVP_MD *EVP_md2(void);
EVP_MD *EVP_md5(void);
EVP_MD *EVP_sha(void);
EVP_MD *EVP_sha1(void);
EVP_MD *EVP_dss(void);
EVP_MD *EVP_dss1(void);
EVP_MD *EVP_mdc2(void);

EVP_CIPHER *EVP_enc_null(void);		/* does nothing :-) */
EVP_CIPHER *EVP_des_ecb(void);
EVP_CIPHER *EVP_des_ede(void);
EVP_CIPHER *EVP_des_ede3(void);
EVP_CIPHER *EVP_des_cfb(void);
EVP_CIPHER *EVP_des_ede_cfb(void);
EVP_CIPHER *EVP_des_ede3_cfb(void);
EVP_CIPHER *EVP_des_ofb(void);
EVP_CIPHER *EVP_des_ede_ofb(void);
EVP_CIPHER *EVP_des_ede3_ofb(void);
EVP_CIPHER *EVP_des_cbc(void);
EVP_CIPHER *EVP_des_ede_cbc(void);
EVP_CIPHER *EVP_des_ede3_cbc(void);
EVP_CIPHER *EVP_desx_cbc(void);
EVP_CIPHER *EVP_rc4(void);
EVP_CIPHER *EVP_idea_ecb(void);
EVP_CIPHER *EVP_idea_cfb(void);
EVP_CIPHER *EVP_idea_ofb(void);
EVP_CIPHER *EVP_idea_cbc(void);
EVP_CIPHER *EVP_rc2_ecb(void);
EVP_CIPHER *EVP_rc2_cbc(void);
EVP_CIPHER *EVP_rc2_cfb(void);
EVP_CIPHER *EVP_rc2_ofb(void);
EVP_CIPHER *EVP_bf_ecb(void);
EVP_CIPHER *EVP_bf_cbc(void);
EVP_CIPHER *EVP_bf_cfb(void);
EVP_CIPHER *EVP_bf_ofb(void);

void SSLeay_add_all_algorithms(void);
void SSLeay_add_all_ciphers(void);
void SSLeay_add_all_digests(void);

int EVP_add_cipher(EVP_CIPHER *cipher);
int EVP_add_digest(EVP_MD *digest);
int EVP_add_alias(char *name,char *alias);
int EVP_delete_alias(char *name);

EVP_CIPHER *EVP_get_cipherbyname(char *name);
EVP_MD *EVP_get_digestbyname(char *name);
void EVP_cleanup(void);

int		EVP_PKEY_type(int type);
int		EVP_PKEY_size(EVP_PKEY *pkey);
int 		EVP_PKEY_assign(EVP_PKEY *pkey,int type,char *key);
EVP_PKEY *	EVP_PKEY_new(void);
void		EVP_PKEY_free(EVP_PKEY *pkey);
EVP_PKEY *	d2i_PublicKey(int type,EVP_PKEY **a, unsigned char **pp,
			long length);
int		i2d_PublicKey(EVP_PKEY *a, unsigned char **pp);

EVP_PKEY *	d2i_PrivateKey(int type,EVP_PKEY **a, unsigned char **pp,
			long length);
int		i2d_PrivateKey(EVP_PKEY *a, unsigned char **pp);

int EVP_PKEY_copy_parameters(EVP_PKEY *to,EVP_PKEY *from);
int EVP_PKEY_missing_parameters(EVP_PKEY *pkey);
int EVP_PKEY_save_parameters(EVP_PKEY *pkey,int mode);

#else

void	EVP_DigestInit();
void	EVP_DigestUpdate();
void	EVP_DigestFinal();

int	EVP_read_pw_string();
void	EVP_set_pw_prompt();
char *	EVP_get_pw_prompt();

int	EVP_BytesToKey();

EVP_CIPHER *EVP_get_cipherbyname();

void	EVP_EncryptInit();
void	EVP_EncryptUpdate();
void	EVP_EncryptFinal();

void	EVP_DecryptInit();
void	EVP_DecryptUpdate();
int	EVP_DecryptFinal();

void	EVP_CipherInit();
void	EVP_CipherUpdate();
int	EVP_CipherFinal();

int	EVP_SignFinal();

int	EVP_VerifyFinal();

int	EVP_OpenInit();
int	EVP_OpenFinal();

int	EVP_SealInit();
void	EVP_SealFinal();

void	EVP_EncodeInit();
void	EVP_EncodeUpdate();
void	EVP_EncodeFinal();
int	EVP_EncodeBlock();

void	EVP_DecodeInit();
int	EVP_DecodeUpdate();
int	EVP_DecodeFinal();
int	EVP_DecodeBlock();

void	ERR_load_EVP_strings();

void EVP_CIPHER_CTX_cleanup();

#ifdef HEADER_BIO_H
BIO_METHOD *BIO_f_md();
BIO_METHOD *BIO_f_base64();
BIO_METHOD *BIO_f_cipher();
void BIO_set_cipher();
#endif

EVP_MD *EVP_md_null();
EVP_MD *EVP_md2();
EVP_MD *EVP_md5();
EVP_MD *EVP_sha();
EVP_MD *EVP_sha1();
EVP_MD *EVP_dss();
EVP_MD *EVP_dss1();
EVP_MD *EVP_mdc2();

EVP_CIPHER *EVP_enc_null();
EVP_CIPHER *EVP_des_ecb();
EVP_CIPHER *EVP_des_ede();
EVP_CIPHER *EVP_des_ede3();
EVP_CIPHER *EVP_des_cfb();
EVP_CIPHER *EVP_des_ede_cfb();
EVP_CIPHER *EVP_des_ede3_cfb();
EVP_CIPHER *EVP_des_ofb();
EVP_CIPHER *EVP_des_ede_ofb();
EVP_CIPHER *EVP_des_ede3_ofb();
EVP_CIPHER *EVP_des_cbc();
EVP_CIPHER *EVP_des_ede_cbc();
EVP_CIPHER *EVP_des_ede3_cbc();
EVP_CIPHER *EVP_desx_cbc();
EVP_CIPHER *EVP_rc4();
EVP_CIPHER *EVP_idea_ecb();
EVP_CIPHER *EVP_idea_cfb();
EVP_CIPHER *EVP_idea_ofb();
EVP_CIPHER *EVP_idea_cbc();
EVP_CIPHER *EVP_rc2_ecb();
EVP_CIPHER *EVP_rc2_cbc();
EVP_CIPHER *EVP_rc2_cfb();
EVP_CIPHER *EVP_rc2_ofb();
EVP_CIPHER *EVP_bf_ecb();
EVP_CIPHER *EVP_bf_cbc();
EVP_CIPHER *EVP_bf_cfb();
EVP_CIPHER *EVP_bf_ofb();

void SSLeay_add_all_algorithms();
void SSLeay_add_all_ciphers();
void SSLeay_add_all_digests();

int EVP_add_cipher();
int EVP_add_digest();
int EVP_add_alias();
int EVP_delete_alias();

EVP_CIPHER *EVP_get_cipherbyname();
EVP_MD *EVP_get_digestbyname();
void EVP_cleanup();

int		EVP_PKEY_type();
int		EVP_PKEY_size();
int 		EVP_PKEY_assign();
EVP_PKEY *	EVP_PKEY_new();
void		EVP_PKEY_free();
EVP_PKEY *	d2i_PublicKey();
int		i2d_PublicKey();

EVP_PKEY *	d2i_PrivateKey();
int		i2d_PrivateKey();

int EVP_PKEY_copy_parameters();
int EVP_PKEY_missing_parameters();
int EVP_PKEY_save_parameters();

#endif

/* BEGIN ERROR CODES */
/* Error codes for the EVP functions. */

/* Function codes. */
#define EVP_F_D2I_PKEY					 100
#define EVP_F_EVP_DECRYPTFINAL				 101
#define EVP_F_EVP_OPENINIT				 102
#define EVP_F_EVP_PKEY_COPY_PARAMETERS			 103
#define EVP_F_EVP_PKEY_NEW				 104
#define EVP_F_EVP_SEALINIT				 105
#define EVP_F_EVP_SIGNFINAL				 106
#define EVP_F_EVP_VERIFYFINAL				 107

/* Reason codes. */
#define EVP_R_BAD_DECRYPT				 100
#define EVP_R_DIFFERENT_KEY_TYPES			 101
#define EVP_R_IV_TOO_LARGE				 102
#define EVP_R_MISSING_PARMATERS				 103
#define EVP_R_NO_SIGN_FUNCTION_CONFIGURED		 104
#define EVP_R_NO_VERIFY_FUNCTION_CONFIGURED		 105
#define EVP_R_PUBLIC_KEY_NOT_RSA			 106
#define EVP_R_UNSUPPORTED_CIPHER			 107
#define EVP_R_WRONG_FINAL_BLOCK_LENGTH			 108
#define EVP_R_WRONG_PUBLIC_KEY_TYPE			 109
 
#ifdef  __cplusplus
}
#endif
#endif

