/* ssl/s3_both.c */
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
#include "buffer.h"
#include "rand.h"
#include "objects.h"
#include "evp.h"
#include "x509.h"
#include "ssl_locl.h"

#define BREAK	break

/* SSL3err(SSL_F_SSL3_GET_FINISHED,SSL_R_EXCESSIVE_MESSAGE_SIZE);
 */

int ssl3_send_finished(s,a,b,sender,slen)
SSL *s;
int a;
int b;
unsigned char *sender;
int slen;
	{
	unsigned char *p,*d;
	int i;
	unsigned long l;

	if (s->state == a)
		{
		d=(unsigned char *)s->init_buf->data;
		p= &(d[4]);

		i=s->method->ssl3_enc->final_finish_mac(s,
			&(s->s3->finish_dgst1),
			&(s->s3->finish_dgst2),
			sender,slen,p);
		p+=i;
		l=i;

		*(d++)=SSL3_MT_FINISHED;
		l2n3(l,d);
		s->init_num=(int)l+4;
		s->init_off=0;

		s->state=b;
		}

	/* SSL3_ST_SEND_xxxxxx_HELLO_B */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
	}

int ssl3_get_finished(s,a,b)
SSL *s;
int a;
int b;
	{
	int al,i,ok;
	long n;
	unsigned char *p;

	/* the mac has already been generated when we received the
	 * change cipher spec message and is in s->s3->tmp.in_dgst[12]
	 */ 

	n=ssl3_get_message(s,
		a,
		b,
		SSL3_MT_FINISHED,
		64, /* should actually be 36+4 :-) */
		&ok);

	if (!ok) return((int)n);

	/* If this occurs if we has missed a message */
	if (!s->s3->change_cipher_spec)
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_GOT_A_FIN_BEFORE_A_CCS);
		goto f_err;
		}
	s->s3->change_cipher_spec=0;

	p=(unsigned char *)s->init_buf->data;

	i=s->method->ssl3_enc->finish_mac_length;

	if (i != n)
		{
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_BAD_DIGEST_LENGTH);
		goto f_err;
		}

	if (memcmp(  p,    (char *)&(s->s3->tmp.finish_md[0]),i) != 0)
		{
		al=SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
		goto f_err;
		}

	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
	return(0);
	}

/* for these 2 messages, we need to
 * ssl->enc_read_ctx			re-init
 * ssl->s3->read_sequence		zero
 * ssl->s3->read_mac_secret		re-init
 * ssl->session->read_sym_enc		assign
 * ssl->session->read_compression	assign
 * ssl->session->read_hash		assign
 */
int ssl3_send_change_cipher_spec(s,a,b)
SSL *s;
int a,b;
	{ 
	unsigned char *p;

	if (s->state == a)
		{
		p=(unsigned char *)s->init_buf->data;
		*p=SSL3_MT_CCS;
		s->init_num=1;
		s->init_off=0;

		s->state=b;
		}

	/* SSL3_ST_CW_CHANGE_B */
	return(ssl3_do_write(s,SSL3_RT_CHANGE_CIPHER_SPEC));
	}

unsigned long ssl3_output_cert_chain(s,x)
SSL *s;
X509 *x;
	{
	unsigned char *p;
	int n,i;
	unsigned long l=7;
	BUF_MEM *buf;
	X509_STORE_CTX xs_ctx;
	X509_OBJECT obj;

	/* TLSv1 sends a chain with nothing in it, instead of an alert */
	buf=s->init_buf;
	if (!BUF_MEM_grow(buf,(int)(10)))
		{
		SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN,ERR_R_BUF_LIB);
		return(0);
		}
	if (x != NULL)
		{
		X509_STORE_CTX_init(&xs_ctx,s->ctx->cert_store,NULL,NULL);

		for (;;)
			{
			n=i2d_X509(x,NULL);
			if (!BUF_MEM_grow(buf,(int)(n+l+3)))
				{
				SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN,ERR_R_BUF_LIB);
				return(0);
				}
			p=(unsigned char *)&(buf->data[l]);
			l2n3(n,p);
			i2d_X509(x,&p);
			l+=n+3;
			if (X509_NAME_cmp(X509_get_subject_name(x),
				X509_get_issuer_name(x)) == 0) break;

			i=X509_STORE_get_by_subject(&xs_ctx,X509_LU_X509,
				X509_get_issuer_name(x),&obj);
			if (i <= 0) break;
			x=obj.data.x509;
			/* Count is one too high since the X509_STORE_get uped the
			 * ref count */
			X509_free(x);
			}

		X509_STORE_CTX_cleanup(&xs_ctx);
		}

	l-=7;
	p=(unsigned char *)&(buf->data[4]);
	l2n3(l,p);
	l+=3;
	p=(unsigned char *)&(buf->data[0]);
	*(p++)=SSL3_MT_CERTIFICATE;
	l2n3(l,p);
	l+=4;
	return(l);
	}

long ssl3_get_message(s,st1,stn,mt,max,ok)
SSL *s;
int st1,stn,mt;
long max;
int *ok;
	{
	unsigned char *p;
	unsigned long l;
	long n;
	int i,al;

	if (s->s3->tmp.reuse_message)
		{
		s->s3->tmp.reuse_message=0;
		if ((mt >= 0) && (s->s3->tmp.message_type != mt))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_MESSAGE,SSL_R_UNEXPECTED_MESSAGE);
			goto f_err;
			}
		*ok=1;
		return((int)s->s3->tmp.message_size);
		}

	p=(unsigned char *)s->init_buf->data;

	if (s->state == st1)
		{
		i=ssl3_read_bytes(s,SSL3_RT_HANDSHAKE,
			(char *)&(p[s->init_num]),
			4-s->init_num);
		if (i < (4-s->init_num))
			{
			*ok=0;
			return(ssl3_part_read(s,i));
			}

		if ((mt >= 0) && (*p != mt))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_MESSAGE,SSL_R_UNEXPECTED_MESSAGE);
			goto f_err;
			}
		s->s3->tmp.message_type= *(p++);

		n2l3(p,l);
		if (l > (unsigned long)max)
			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_MESSAGE,SSL_R_EXCESSIVE_MESSAGE_SIZE);
			goto f_err;
			}
		if (l && !BUF_MEM_grow(s->init_buf,(int)l))
			{
			SSLerr(SSL_F_SSL3_GET_MESSAGE,ERR_R_BUF_LIB);
			goto err;
			}
		s->s3->tmp.message_size=l;
		s->state=stn;

		s->init_num=0;
		}

	/* next state (stn) */
	p=(unsigned char *)s->init_buf->data;
	n=s->s3->tmp.message_size;
	if (n > 0)
		{
		i=ssl3_read_bytes(s,SSL3_RT_HANDSHAKE,
			(char *)&(p[s->init_num]),(int)n);
		if (i != (int)n)
			{
			*ok=0;
			return(ssl3_part_read(s,i));
			}
		}
	*ok=1;
	return(n);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	*ok=0;
	return(-1);
	}

int ssl_cert_type(x,pkey)
X509 *x;
EVP_PKEY *pkey;
	{
	EVP_PKEY *pk;
	int ret= -1,i,j;

	if (pkey == NULL)
		pk=X509_get_pubkey(x);
	else
		pk=pkey;
	if (pk == NULL) goto err;

	i=pk->type;
	if (i == EVP_PKEY_RSA)
		{
		ret=SSL_PKEY_RSA_ENC;
		if (x != NULL)
			{
			j=X509_get_ext_count(x);
			/* check to see if this is a signing only certificate */
			/* EAY EAY EAY EAY */
			}
		}
	else if (i == EVP_PKEY_DSA)
		{
		ret=SSL_PKEY_DSA_SIGN;
		}
	else if (i == EVP_PKEY_DH)
		{
		/* if we just have a key, we needs to be guess */

		if (x == NULL)
			ret=SSL_PKEY_DH_DSA;
		else
			{
			j=X509_get_signature_type(x);
			if (j == EVP_PKEY_RSA)
				ret=SSL_PKEY_DH_RSA;
			else if (j== EVP_PKEY_DSA)
				ret=SSL_PKEY_DH_DSA;
			else ret= -1;
			}
		}
	else
		ret= -1;

err:
	return(ret);
	}

int ssl_verify_alarm_type(type)
long type;
	{
	int al;

	switch(type)
		{
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	case X509_V_ERR_UNABLE_TO_GET_CRL:
		al=SSL_AD_UNKNOWN_CA;
		break;
	case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
	case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
	case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_CRL_NOT_YET_VALID:
		al=SSL_AD_BAD_CERTIFICATE;
		break;
	case X509_V_ERR_CERT_SIGNATURE_FAILURE:
	case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		al=SSL_AD_DECRYPT_ERROR;
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_CRL_HAS_EXPIRED:
		al=SSL_AD_CERTIFICATE_EXPIRED;
		break;
	case X509_V_ERR_CERT_REVOKED:
		al=SSL_AD_CERTIFICATE_REVOKED;
		break;
	case X509_V_ERR_OUT_OF_MEM:
		al=SSL_AD_INTERNAL_ERROR;
		break;
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
	case X509_V_ERR_CERT_CHAIN_TOO_LONG:
		al=SSL_AD_UNKNOWN_CA;
		break;
	case X509_V_ERR_APPLICATION_VERIFICATION:
		al=SSL_AD_HANDSHAKE_FAILURE;
		break;
	default:
		al=SSL_AD_CERTIFICATE_UNKNOWN;
		break;
		}
	return(al);
	}

int ssl3_setup_buffers(s)
SSL *s;
	{
	unsigned char *p;
	unsigned int extra;

	if (s->s3->rbuf.buf == NULL)
		{
		if (s->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER)
			extra=SSL3_RT_MAX_EXTRA;
		else
			extra=0;
		if ((p=(unsigned char *)Malloc(SSL3_RT_MAX_PACKET_SIZE+extra))
			== NULL)
			goto err;
		s->s3->rbuf.buf=p;
		}

	if (s->s3->wbuf.buf == NULL)
		{
		if ((p=(unsigned char *)Malloc(SSL3_RT_MAX_PACKET_SIZE))
			== NULL)
			goto err;
		s->s3->wbuf.buf=p;
		}
	s->packet= &(s->s3->rbuf.buf[0]);
	return(1);
err:
	SSLerr(SSL_F_SSL3_SETUP_BUFFERS,ERR_R_MALLOC_FAILURE);
	return(0);
	}
