/* ssl/s3_enc.c */
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
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "ssl_locl.h"

static unsigned char ssl3_pad_1[48]={
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 };

static unsigned char ssl3_pad_2[48]={
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c };

static int ssl3_handshake_mac(SSL *s, EVP_MD_CTX *in_ctx,
	const char *sender, int len, unsigned char *p);

static void ssl3_generate_key_block(SSL *s, unsigned char *km, int num)
	{
	MD5_CTX m5;
	SHA_CTX s1;
	unsigned char buf[8],smd[SHA_DIGEST_LENGTH];
	unsigned char c='A';
	int i,j,k;

#ifdef CHARSET_EBCDIC
	c = os_toascii[c]; /*'A' in ASCII */
#endif
	k=0;
	for (i=0; i<num; i+=MD5_DIGEST_LENGTH)
		{
		k++;
		for (j=0; j<k; j++)
			buf[j]=c;
		c++;
		SHA1_Init(  &s1);
		SHA1_Update(&s1,buf,k);
		SHA1_Update(&s1,s->session->master_key,
			s->session->master_key_length);
		SHA1_Update(&s1,s->s3->server_random,SSL3_RANDOM_SIZE);
		SHA1_Update(&s1,s->s3->client_random,SSL3_RANDOM_SIZE);
		SHA1_Final( smd,&s1);

		MD5_Init(  &m5);
		MD5_Update(&m5,s->session->master_key,
			s->session->master_key_length);
		MD5_Update(&m5,smd,SHA_DIGEST_LENGTH);
		if ((i+MD5_DIGEST_LENGTH) > num)
			{
			MD5_Final(smd,&m5);
			memcpy(km,smd,(num-i));
			}
		else
			MD5_Final(km,&m5);

		km+=MD5_DIGEST_LENGTH;
		}
	memset(smd,0,SHA_DIGEST_LENGTH);
	}

int ssl3_change_cipher_state(SSL *s, int which)
	{
	unsigned char *p,*key_block,*mac_secret;
	unsigned char exp_key[EVP_MAX_KEY_LENGTH];
	unsigned char exp_iv[EVP_MAX_KEY_LENGTH];
	unsigned char *ms,*key,*iv,*er1,*er2;
	EVP_CIPHER_CTX *dd;
	const EVP_CIPHER *c;
	COMP_METHOD *comp;
	const EVP_MD *m;
	MD5_CTX md;
	int exp,n,i,j,k,cl;

	exp=SSL_C_IS_EXPORT(s->s3->tmp.new_cipher);
	c=s->s3->tmp.new_sym_enc;
	m=s->s3->tmp.new_hash;
	if (s->s3->tmp.new_compression == NULL)
		comp=NULL;
	else
		comp=s->s3->tmp.new_compression->method;
	key_block=s->s3->tmp.key_block;

	if (which & SSL3_CC_READ)
		{
		if ((s->enc_read_ctx == NULL) &&
			((s->enc_read_ctx=(EVP_CIPHER_CTX *)
			Malloc(sizeof(EVP_CIPHER_CTX))) == NULL))
			goto err;
		dd= s->enc_read_ctx;
		s->read_hash=m;
		/* COMPRESS */
		if (s->expand != NULL)
			{
			COMP_CTX_free(s->expand);
			s->expand=NULL;
			}
		if (comp != NULL)
			{
			s->expand=COMP_CTX_new(comp);
			if (s->expand == NULL)
				{
				SSLerr(SSL_F_SSL3_CHANGE_CIPHER_STATE,SSL_R_COMPRESSION_LIBRARY_ERROR);
				goto err2;
				}
			if (s->s3->rrec.comp == NULL)
				s->s3->rrec.comp=(unsigned char *)
					Malloc(SSL3_RT_MAX_PLAIN_LENGTH);
			if (s->s3->rrec.comp == NULL)
				goto err;
			}
		memset(&(s->s3->read_sequence[0]),0,8);
		mac_secret= &(s->s3->read_mac_secret[0]);
		}
	else
		{
		if ((s->enc_write_ctx == NULL) &&
			((s->enc_write_ctx=(EVP_CIPHER_CTX *)
			Malloc(sizeof(EVP_CIPHER_CTX))) == NULL))
			goto err;
		dd= s->enc_write_ctx;
		s->write_hash=m;
		/* COMPRESS */
		if (s->compress != NULL)
			{
			COMP_CTX_free(s->compress);
			s->compress=NULL;
			}
		if (comp != NULL)
			{
			s->compress=COMP_CTX_new(comp);
			if (s->compress == NULL)
				{
				SSLerr(SSL_F_SSL3_CHANGE_CIPHER_STATE,SSL_R_COMPRESSION_LIBRARY_ERROR);
				goto err2;
				}
			}
		memset(&(s->s3->write_sequence[0]),0,8);
		mac_secret= &(s->s3->write_mac_secret[0]);
		}

	EVP_CIPHER_CTX_init(dd);

	p=s->s3->tmp.key_block;
	i=EVP_MD_size(m);
	cl=EVP_CIPHER_key_length(c);
	j=exp ? (cl < SSL_C_EXPORT_KEYLENGTH(s->s3->tmp.new_cipher) ?
		 cl : SSL_C_EXPORT_KEYLENGTH(s->s3->tmp.new_cipher)) : cl;
	/* Was j=(exp)?5:EVP_CIPHER_key_length(c); */
	k=EVP_CIPHER_iv_length(c);
	if (	(which == SSL3_CHANGE_CIPHER_CLIENT_WRITE) ||
		(which == SSL3_CHANGE_CIPHER_SERVER_READ))
		{
		ms=  &(p[ 0]); n=i+i;
		key= &(p[ n]); n+=j+j;
		iv=  &(p[ n]); n+=k+k;
		er1= &(s->s3->client_random[0]);
		er2= &(s->s3->server_random[0]);
		}
	else
		{
		n=i;
		ms=  &(p[ n]); n+=i+j;
		key= &(p[ n]); n+=j+k;
		iv=  &(p[ n]); n+=k;
		er1= &(s->s3->server_random[0]);
		er2= &(s->s3->client_random[0]);
		}

	if (n > s->s3->tmp.key_block_length)
		{
		SSLerr(SSL_F_SSL3_CHANGE_CIPHER_STATE,SSL_R_INTERNAL_ERROR);
		goto err2;
		}

	memcpy(mac_secret,ms,i);
	if (exp)
		{
		/* In here I set both the read and write key/iv to the
		 * same value since only the correct one will be used :-).
		 */
		MD5_Init(&md);
		MD5_Update(&md,key,j);
		MD5_Update(&md,er1,SSL3_RANDOM_SIZE);
		MD5_Update(&md,er2,SSL3_RANDOM_SIZE);
		MD5_Final(&(exp_key[0]),&md);
		key= &(exp_key[0]);

		if (k > 0)
			{
			MD5_Init(&md);
			MD5_Update(&md,er1,SSL3_RANDOM_SIZE);
			MD5_Update(&md,er2,SSL3_RANDOM_SIZE);
			MD5_Final(&(exp_iv[0]),&md);
			iv= &(exp_iv[0]);
			}
		}

	s->session->key_arg_length=0;

	EVP_CipherInit(dd,c,key,iv,(which & SSL3_CC_WRITE));

	memset(&(exp_key[0]),0,sizeof(exp_key));
	memset(&(exp_iv[0]),0,sizeof(exp_iv));
	return(1);
err:
	SSLerr(SSL_F_SSL3_CHANGE_CIPHER_STATE,ERR_R_MALLOC_FAILURE);
err2:
	return(0);
	}

int ssl3_setup_key_block(SSL *s)
	{
	unsigned char *p;
	const EVP_CIPHER *c;
	const EVP_MD *hash;
	int num;
	SSL_COMP *comp;

	if (s->s3->tmp.key_block_length != 0)
		return(1);

	if (!ssl_cipher_get_evp(s->session,&c,&hash,&comp))
		{
		SSLerr(SSL_F_SSL3_SETUP_KEY_BLOCK,SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
		return(0);
		}

	s->s3->tmp.new_sym_enc=c;
	s->s3->tmp.new_hash=hash;
	s->s3->tmp.new_compression=comp;

	num=EVP_CIPHER_key_length(c)+EVP_MD_size(hash)+EVP_CIPHER_iv_length(c);
	num*=2;

	ssl3_cleanup_key_block(s);

	if ((p=Malloc(num)) == NULL)
		goto err;

	s->s3->tmp.key_block_length=num;
	s->s3->tmp.key_block=p;

	ssl3_generate_key_block(s,p,num);

	return(1);
err:
	SSLerr(SSL_F_SSL3_SETUP_KEY_BLOCK,ERR_R_MALLOC_FAILURE);
	return(0);
	}

void ssl3_cleanup_key_block(SSL *s)
	{
	if (s->s3->tmp.key_block != NULL)
		{
		memset(s->s3->tmp.key_block,0,
			s->s3->tmp.key_block_length);
		Free(s->s3->tmp.key_block);
		s->s3->tmp.key_block=NULL;
		}
	s->s3->tmp.key_block_length=0;
	}

int ssl3_enc(SSL *s, int send)
	{
	SSL3_RECORD *rec;
	EVP_CIPHER_CTX *ds;
	unsigned long l;
	int bs,i;
	const EVP_CIPHER *enc;

	if (send)
		{
		ds=s->enc_write_ctx;
		rec= &(s->s3->wrec);
		if (s->enc_write_ctx == NULL)
			enc=NULL;
		else
			enc=EVP_CIPHER_CTX_cipher(s->enc_write_ctx);
		}
	else
		{
		ds=s->enc_read_ctx;
		rec= &(s->s3->rrec);
		if (s->enc_read_ctx == NULL)
			enc=NULL;
		else
			enc=EVP_CIPHER_CTX_cipher(s->enc_read_ctx);
		}

	if ((s->session == NULL) || (ds == NULL) ||
		(enc == NULL))
		{
		memcpy(rec->data,rec->input,rec->length);
		rec->input=rec->data;
		}
	else
		{
		l=rec->length;
		bs=EVP_CIPHER_block_size(ds->cipher);

		/* COMPRESS */

		/* This should be using (bs-1) and bs instead of 7 and 8 */
		if ((bs != 1) && send)
			{
			i=bs-((int)l%bs);

			/* we need to add 'i-1' padding bytes */
			l+=i;
			rec->length+=i;
			rec->input[l-1]=(i-1);
			}

		EVP_Cipher(ds,rec->data,rec->input,l);

		if ((bs != 1) && !send)
			{
			i=rec->data[l-1]+1;
			if (i > bs)
				{
				SSLerr(SSL_F_SSL3_ENC,SSL_R_BLOCK_CIPHER_PAD_IS_WRONG);
				ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECRYPT_ERROR);
				return(0);
				}
			rec->length-=i;
			}
		}
	return(1);
	}

void ssl3_init_finished_mac(SSL *s)
	{
	EVP_DigestInit(&(s->s3->finish_dgst1),s->ctx->md5);
	EVP_DigestInit(&(s->s3->finish_dgst2),s->ctx->sha1);
	}

void ssl3_finish_mac(SSL *s, const unsigned char *buf, int len)
	{
	EVP_DigestUpdate(&(s->s3->finish_dgst1),buf,len);
	EVP_DigestUpdate(&(s->s3->finish_dgst2),buf,len);
	}

int ssl3_cert_verify_mac(SSL *s, EVP_MD_CTX *ctx, unsigned char *p)
	{
	return(ssl3_handshake_mac(s,ctx,NULL,0,p));
	}

int ssl3_final_finish_mac(SSL *s, EVP_MD_CTX *ctx1, EVP_MD_CTX *ctx2,
	     const char *sender, int len, unsigned char *p)
	{
	int ret;

	ret=ssl3_handshake_mac(s,ctx1,sender,len,p);
	p+=ret;
	ret+=ssl3_handshake_mac(s,ctx2,sender,len,p);
	return(ret);
	}

static int ssl3_handshake_mac(SSL *s, EVP_MD_CTX *in_ctx,
	     const char *sender, int len, unsigned char *p)
	{
	unsigned int ret;
	int npad,n;
	unsigned int i;
	unsigned char md_buf[EVP_MAX_MD_SIZE];
	EVP_MD_CTX ctx;

	EVP_MD_CTX_copy(&ctx,in_ctx);

	n=EVP_MD_CTX_size(&ctx);
	npad=(48/n)*n;

	if (sender != NULL)
		EVP_DigestUpdate(&ctx,sender,len);
	EVP_DigestUpdate(&ctx,s->session->master_key,
		s->session->master_key_length);
	EVP_DigestUpdate(&ctx,ssl3_pad_1,npad);
	EVP_DigestFinal(&ctx,md_buf,&i);

	EVP_DigestInit(&ctx,EVP_MD_CTX_md(&ctx));
	EVP_DigestUpdate(&ctx,s->session->master_key,
		s->session->master_key_length);
	EVP_DigestUpdate(&ctx,ssl3_pad_2,npad);
	EVP_DigestUpdate(&ctx,md_buf,i);
	EVP_DigestFinal(&ctx,p,&ret);

	memset(&ctx,0,sizeof(EVP_MD_CTX));

	return((int)ret);
	}

int ssl3_mac(SSL *ssl, unsigned char *md, int send)
	{
	SSL3_RECORD *rec;
	unsigned char *mac_sec,*seq;
	EVP_MD_CTX md_ctx;
	const EVP_MD *hash;
	unsigned char *p,rec_char;
	unsigned int md_size;
	int npad,i;

	if (send)
		{
		rec= &(ssl->s3->wrec);
		mac_sec= &(ssl->s3->write_mac_secret[0]);
		seq= &(ssl->s3->write_sequence[0]);
		hash=ssl->write_hash;
		}
	else
		{
		rec= &(ssl->s3->rrec);
		mac_sec= &(ssl->s3->read_mac_secret[0]);
		seq= &(ssl->s3->read_sequence[0]);
		hash=ssl->read_hash;
		}

	md_size=EVP_MD_size(hash);
	npad=(48/md_size)*md_size;

	/* Chop the digest off the end :-) */

	EVP_DigestInit(  &md_ctx,hash);
	EVP_DigestUpdate(&md_ctx,mac_sec,md_size);
	EVP_DigestUpdate(&md_ctx,ssl3_pad_1,npad);
	EVP_DigestUpdate(&md_ctx,seq,8);
	rec_char=rec->type;
	EVP_DigestUpdate(&md_ctx,&rec_char,1);
	p=md;
	s2n(rec->length,p);
	EVP_DigestUpdate(&md_ctx,md,2);
	EVP_DigestUpdate(&md_ctx,rec->input,rec->length);
	EVP_DigestFinal( &md_ctx,md,NULL);

	EVP_DigestInit(  &md_ctx,hash);
	EVP_DigestUpdate(&md_ctx,mac_sec,md_size);
	EVP_DigestUpdate(&md_ctx,ssl3_pad_2,npad);
	EVP_DigestUpdate(&md_ctx,md,md_size);
	EVP_DigestFinal( &md_ctx,md,&md_size);

	for (i=7; i>=0; i--)
		if (++seq[i]) break; 

	return(md_size);
	}

int ssl3_generate_master_secret(SSL *s, unsigned char *out, unsigned char *p,
	     int len)
	{
	static const unsigned char *salt[3]={
#ifndef CHARSET_EBCDIC
		(const unsigned char *)"A",
		(const unsigned char *)"BB",
		(const unsigned char *)"CCC",
#else
		(const unsigned char *)"\x41",
		(const unsigned char *)"\x42\x42",
		(const unsigned char *)"\x43\x43\x43",
#endif
		};
	unsigned char buf[EVP_MAX_MD_SIZE];
	EVP_MD_CTX ctx;
	int i,ret=0;
	unsigned int n;

	for (i=0; i<3; i++)
		{
		EVP_DigestInit(&ctx,s->ctx->sha1);
		EVP_DigestUpdate(&ctx,salt[i],strlen((const char *)salt[i]));
		EVP_DigestUpdate(&ctx,p,len);
		EVP_DigestUpdate(&ctx,&(s->s3->client_random[0]),
			SSL3_RANDOM_SIZE);
		EVP_DigestUpdate(&ctx,&(s->s3->server_random[0]),
			SSL3_RANDOM_SIZE);
		EVP_DigestFinal(&ctx,buf,&n);

		EVP_DigestInit(&ctx,s->ctx->md5);
		EVP_DigestUpdate(&ctx,p,len);
		EVP_DigestUpdate(&ctx,buf,n);
		EVP_DigestFinal(&ctx,out,&n);
		out+=n;
		ret+=n;
		}
	return(ret);
	}

int ssl3_alert_code(int code)
	{
	switch (code)
		{
	case SSL_AD_CLOSE_NOTIFY:	return(SSL3_AD_CLOSE_NOTIFY);
	case SSL_AD_UNEXPECTED_MESSAGE:	return(SSL3_AD_UNEXPECTED_MESSAGE);
	case SSL_AD_BAD_RECORD_MAC:	return(SSL3_AD_BAD_RECORD_MAC);
	case SSL_AD_DECRYPTION_FAILED:	return(SSL3_AD_BAD_RECORD_MAC);
	case SSL_AD_RECORD_OVERFLOW:	return(SSL3_AD_BAD_RECORD_MAC);
	case SSL_AD_DECOMPRESSION_FAILURE:return(SSL3_AD_DECOMPRESSION_FAILURE);
	case SSL_AD_HANDSHAKE_FAILURE:	return(SSL3_AD_HANDSHAKE_FAILURE);
	case SSL_AD_NO_CERTIFICATE:	return(SSL3_AD_NO_CERTIFICATE);
	case SSL_AD_BAD_CERTIFICATE:	return(SSL3_AD_BAD_CERTIFICATE);
	case SSL_AD_UNSUPPORTED_CERTIFICATE:return(SSL3_AD_UNSUPPORTED_CERTIFICATE);
	case SSL_AD_CERTIFICATE_REVOKED:return(SSL3_AD_CERTIFICATE_REVOKED);
	case SSL_AD_CERTIFICATE_EXPIRED:return(SSL3_AD_CERTIFICATE_EXPIRED);
	case SSL_AD_CERTIFICATE_UNKNOWN:return(SSL3_AD_CERTIFICATE_UNKNOWN);
	case SSL_AD_ILLEGAL_PARAMETER:	return(SSL3_AD_ILLEGAL_PARAMETER);
	case SSL_AD_UNKNOWN_CA:		return(SSL3_AD_BAD_CERTIFICATE);
	case SSL_AD_ACCESS_DENIED:	return(SSL3_AD_HANDSHAKE_FAILURE);
	case SSL_AD_DECODE_ERROR:	return(SSL3_AD_HANDSHAKE_FAILURE);
	case SSL_AD_DECRYPT_ERROR:	return(SSL3_AD_HANDSHAKE_FAILURE);
	case SSL_AD_EXPORT_RESTRICTION:	return(SSL3_AD_HANDSHAKE_FAILURE);
	case SSL_AD_PROTOCOL_VERSION:	return(SSL3_AD_HANDSHAKE_FAILURE);
	case SSL_AD_INSUFFICIENT_SECURITY:return(SSL3_AD_HANDSHAKE_FAILURE);
	case SSL_AD_INTERNAL_ERROR:	return(SSL3_AD_HANDSHAKE_FAILURE);
	case SSL_AD_USER_CANCELLED:	return(SSL3_AD_HANDSHAKE_FAILURE);
	case SSL_AD_NO_RENEGOTIATION:	return(-1); /* Don't send it :-) */
	default:			return(-1);
		}
	}

