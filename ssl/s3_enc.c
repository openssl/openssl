/* ssl/s3_enc.c */
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

#include <stdio.h>
#include "evp.h"
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

int ssl3_change_cipher_state(s,which)
SSL *s;
int which;
	{
	unsigned char *p,*key_block,*mac_secret;
	unsigned char exp_key[EVP_MAX_KEY_LENGTH];
	unsigned char exp_iv[EVP_MAX_KEY_LENGTH];
	unsigned char *ms,*key,*iv,*er1,*er2;
	EVP_CIPHER_CTX *dd;
	EVP_CIPHER *c;
	SSL_COMPRESSION *comp;
	EVP_MD *m;
	MD5_CTX md;
	int exp,n,i,j,k;

	exp=(s->s3->tmp.new_cipher->algorithms & SSL_EXPORT)?1:0;
	c=s->s3->tmp.new_sym_enc;
	m=s->s3->tmp.new_hash;
	comp=s->s3->tmp.new_compression;
	key_block=s->s3->tmp.key_block;

	if (which & SSL3_CC_READ)
		{
		if ((s->enc_read_ctx == NULL) &&
			((s->enc_read_ctx=(EVP_CIPHER_CTX *)
			Malloc(sizeof(EVP_CIPHER_CTX))) == NULL))
			goto err;
		dd= s->enc_read_ctx;
		s->read_hash=m;
		s->read_compression=comp;
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
		s->write_compression=comp;
		memset(&(s->s3->write_sequence[0]),0,8);
		mac_secret= &(s->s3->write_mac_secret[0]);
		}

	p=s->s3->tmp.key_block;
	i=EVP_MD_size(m);
	j=(exp)?5:EVP_CIPHER_key_length(c);
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

		MD5_Init(&md);
		MD5_Update(&md,er1,SSL3_RANDOM_SIZE);
		MD5_Update(&md,er2,SSL3_RANDOM_SIZE);
		MD5_Final(&(exp_iv[0]),&md);
		iv= &(exp_iv[0]);
		}

	s->session->key_arg_length=k;
	if (k > 0)
		memcpy(&(s->session->key_arg[0]),iv,k);

	EVP_CipherInit(dd,c,key,iv,(which & SSL3_CC_WRITE));
	memset(&(exp_key[0]),0,sizeof(exp_key));
	memset(&(exp_iv[0]),0,sizeof(exp_iv));
	return(1);
err:
	SSLerr(SSL_F_SSL3_CHANGE_CIPHER_STATE,ERR_R_MALLOC_FAILURE);
err2:
	return(0);
	}

int ssl3_setup_key_block(s)
SSL *s;
	{
	unsigned char *p;
	EVP_CIPHER *c;
	EVP_MD *hash;
	int num,exp;

	if (s->s3->tmp.key_block_length != 0)
		return(1);

	if (!ssl_cipher_get_evp(s->session->cipher,&c,&hash))
		{
		SSLerr(SSL_F_SSL3_SETUP_KEY_BLOCK,SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
		return(0);
		}

	s->s3->tmp.new_sym_enc=c;
	s->s3->tmp.new_hash=hash;

	exp=(s->session->cipher->algorithms & SSL_EXPORT)?1:0;

	num=EVP_CIPHER_key_length(c)+EVP_MD_size(hash)+EVP_CIPHER_iv_length(c);
	num*=2;

	ssl3_cleanup_key_block(s);

	if ((p=(unsigned char *)Malloc(num)) == NULL)
		goto err;

	s->s3->tmp.key_block_length=num;
	s->s3->tmp.key_block=p;

	ssl3_generate_key_block(s,p,num);

	return(1);
err:
	SSLerr(SSL_F_SSL3_SETUP_KEY_BLOCK,ERR_R_MALLOC_FAILURE);
	return(0);
	}

void ssl3_cleanup_key_block(s)
SSL *s;
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

int ssl3_enc(s,send)
SSL *s;
int send;
	{
	SSL3_RECORD *rec;
	EVP_CIPHER_CTX *ds;
	unsigned long l;
	int bs,i;
	EVP_CIPHER *enc;
	SSL_COMPRESSION *comp;

	if (send)
		{
		ds=s->enc_write_ctx;
		rec= &(s->s3->wrec);
		if (s->enc_write_ctx == NULL)
			{ enc=NULL; comp=NULL; }
		else
			{
			enc=EVP_CIPHER_CTX_cipher(s->enc_write_ctx);
			comp=s->write_compression;
			}
		}
	else
		{
		ds=s->enc_read_ctx;
		rec= &(s->s3->rrec);
		if (s->enc_read_ctx == NULL)
			{ enc=NULL; comp=NULL; }
		else
			{
			enc=EVP_CIPHER_CTX_cipher(s->enc_read_ctx);
			comp=s->read_compression;
			}
		}

	if ((s->session == NULL) || (ds == NULL) ||
		((enc == NULL) && (comp == NULL)))
		{
		memcpy(rec->data,rec->input,rec->length);
		rec->input=rec->data;
		}
	else
		{
		l=rec->length;
		bs=EVP_CIPHER_block_size(ds->cipher);

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
				ssl3_send_alert(s,SSL3_AL_FATAL,SSL3_AD_BAD_RECORD_MAC);
				return(0);
				}
			rec->length-=i;
			}
		}
	return(1);
	}

void ssl3_init_finished_mac(s)
SSL *s;
	{
	EVP_DigestInit(&(s->s3->finish_dgst1),EVP_md5());
	EVP_DigestInit(&(s->s3->finish_dgst2),EVP_sha1());
	}

void ssl3_finish_mac(s,buf,len)
SSL *s;
unsigned char *buf;
int len;
	{
	EVP_DigestUpdate(&(s->s3->finish_dgst1),buf,len);
	EVP_DigestUpdate(&(s->s3->finish_dgst2),buf,len);
	}

int ssl3_final_finish_mac(s,in_ctx,sender,p)
SSL *s;
EVP_MD_CTX *in_ctx;
unsigned char *sender;
unsigned char *p;
	{
	unsigned int ret;
	int npad,n;
	unsigned int i;
	unsigned char md_buf[EVP_MAX_MD_SIZE];
	EVP_MD_CTX ctx;

	memcpy(&ctx,in_ctx,sizeof(EVP_MD_CTX));

	n=EVP_MD_CTX_size(&ctx);
	npad=(48/n)*n;

	if (sender != NULL)
		EVP_DigestUpdate(&ctx,sender,4);
	EVP_DigestUpdate(&ctx,s->session->master_key,
		s->session->master_key_length);
	EVP_DigestUpdate(&ctx,ssl3_pad_1,npad);
	EVP_DigestFinal(&ctx,md_buf,&i);

	EVP_DigestInit(&ctx,EVP_MD_CTX_type(&ctx));
	EVP_DigestUpdate(&ctx,s->session->master_key,
		s->session->master_key_length);
	EVP_DigestUpdate(&ctx,ssl3_pad_2,npad);
	EVP_DigestUpdate(&ctx,md_buf,i);
	EVP_DigestFinal(&ctx,p,&ret);

	memset(&ctx,0,sizeof(EVP_MD_CTX));

	return((int)ret);
	}

int ssl3_mac(ssl,md,send)
SSL *ssl;
unsigned char *md;
int send;
	{
	SSL3_RECORD *rec;
	unsigned char *mac_sec,*seq;
	EVP_MD_CTX md_ctx;
	EVP_MD *hash;
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

#ifdef MAC_DEBUG
printf("npad=%d md_size=%d",npad,md_size);
printf("\nmsec=");
for (i=0; i<md_size; i++) printf("%02X ",mac_sec[i]);
printf("\npad1=");
for (i=0; i<npad; i++) printf("%02X ",ssl3_pad_1[i]);
printf("\nseq =");
for (i=0; i<8; i++) printf("%02X ",seq[i]);
printf("\nreqt=%02X len=%04X\n",rec->type,rec->length);
for (i=0; i<rec->length; i++) printf("%02X",rec->input[i]);
printf("\n");
#endif

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

#ifdef MAC_DEBUG
printf("md=");
for (i=0; i<md_size; i++) printf("%02X ",md[i]);
printf("\n");
#endif

	return(md_size);
	}

int ssl3_generate_master_secret(s,out,p,len)
SSL *s;
unsigned char *out;
unsigned char *p;
int len;
	{
	static unsigned char *salt[3]={
		(unsigned char *)"A",
		(unsigned char *)"BB",
		(unsigned char *)"CCC",
		};
	unsigned char buf[EVP_MAX_MD_SIZE];
	EVP_MD_CTX ctx;
	int i,ret=0;
	unsigned int n;

	for (i=0; i<3; i++)
		{
		EVP_DigestInit(&ctx,EVP_sha1());
		EVP_DigestUpdate(&ctx,salt[i],strlen((char *)salt[i]));
		EVP_DigestUpdate(&ctx,p,len);
		EVP_DigestUpdate(&ctx,&(s->s3->client_random[0]),
			SSL3_RANDOM_SIZE);
		EVP_DigestUpdate(&ctx,&(s->s3->server_random[0]),
			SSL3_RANDOM_SIZE);
		EVP_DigestFinal(&ctx,buf,&n);

		EVP_DigestInit(&ctx,EVP_md5());
		EVP_DigestUpdate(&ctx,p,len);
		EVP_DigestUpdate(&ctx,buf,n);
		EVP_DigestFinal(&ctx,out,&n);
		out+=n;
		ret+=n;
		}
	return(ret);
	}

