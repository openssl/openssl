/* ssl/s3_lib.c */
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
#include <openssl/objects.h>
#include "ssl_locl.h"

const char *ssl3_version_str="SSLv3" OPENSSL_VERSION_PTEXT;

#define SSL3_NUM_CIPHERS	(sizeof(ssl3_ciphers)/sizeof(SSL_CIPHER))

static long ssl3_default_timeout(void );

OPENSSL_GLOBAL SSL_CIPHER ssl3_ciphers[]={
/* The RSA ciphers */
/* Cipher 01 */
	{
	1,
	SSL3_TXT_RSA_NULL_MD5,
	SSL3_CK_RSA_NULL_MD5,
	SSL_kRSA|SSL_aRSA|SSL_eNULL |SSL_MD5|SSL_SSLV3,
	SSL_NOT_EXP,
	0,
	0,
	0,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 02 */
	{
	1,
	SSL3_TXT_RSA_NULL_SHA,
	SSL3_CK_RSA_NULL_SHA,
	SSL_kRSA|SSL_aRSA|SSL_eNULL |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP,
	0,
	0,
	0,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},

/* anon DH */
/* Cipher 17 */
	{
	1,
	SSL3_TXT_ADH_RC4_40_MD5,
	SSL3_CK_ADH_RC4_40_MD5,
	SSL_kEDH |SSL_aNULL|SSL_RC4  |SSL_MD5 |SSL_SSLV3,
	SSL_EXPORT|SSL_EXP40,
	0,
	40,
	128,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 18 */
	{
	1,
	SSL3_TXT_ADH_RC4_128_MD5,
	SSL3_CK_ADH_RC4_128_MD5,
	SSL_kEDH |SSL_aNULL|SSL_RC4  |SSL_MD5 |SSL_SSLV3,
	SSL_NOT_EXP,
	0,
	128,
	128,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 19 */
	{
	1,
	SSL3_TXT_ADH_DES_40_CBC_SHA,
	SSL3_CK_ADH_DES_40_CBC_SHA,
	SSL_kEDH |SSL_aNULL|SSL_DES|SSL_SHA1|SSL_SSLV3,
	SSL_EXPORT|SSL_EXP40,
	0,
	40,
	128,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 1A */
	{
	1,
	SSL3_TXT_ADH_DES_64_CBC_SHA,
	SSL3_CK_ADH_DES_64_CBC_SHA,
	SSL_kEDH |SSL_aNULL|SSL_DES  |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP,
	0,
	56,
	56,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 1B */
	{
	1,
	SSL3_TXT_ADH_DES_192_CBC_SHA,
	SSL3_CK_ADH_DES_192_CBC_SHA,
	SSL_kEDH |SSL_aNULL|SSL_3DES |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP,
	0,
	168,
	168,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},

/* RSA again */
/* Cipher 03 */
	{
	1,
	SSL3_TXT_RSA_RC4_40_MD5,
	SSL3_CK_RSA_RC4_40_MD5,
	SSL_kRSA|SSL_aRSA|SSL_RC4  |SSL_MD5 |SSL_SSLV3,
	SSL_EXPORT|SSL_EXP40,
	0,
	40,
	128,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 04 */
	{
	1,
	SSL3_TXT_RSA_RC4_128_MD5,
	SSL3_CK_RSA_RC4_128_MD5,
	SSL_kRSA|SSL_aRSA|SSL_RC4  |SSL_MD5|SSL_SSLV3,
	SSL_NOT_EXP|SSL_MEDIUM,
	0,
	128,
	128,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 05 */
	{
	1,
	SSL3_TXT_RSA_RC4_128_SHA,
	SSL3_CK_RSA_RC4_128_SHA,
	SSL_kRSA|SSL_aRSA|SSL_RC4  |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_MEDIUM,
	0,
	128,
	128,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 06 */
	{
	1,
	SSL3_TXT_RSA_RC2_40_MD5,
	SSL3_CK_RSA_RC2_40_MD5,
	SSL_kRSA|SSL_aRSA|SSL_RC2  |SSL_MD5 |SSL_SSLV3,
	SSL_EXPORT|SSL_EXP40,
	0,
	40,
	128,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 07 */
	{
	1,
	SSL3_TXT_RSA_IDEA_128_SHA,
	SSL3_CK_RSA_IDEA_128_SHA,
	SSL_kRSA|SSL_aRSA|SSL_IDEA |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_MEDIUM,
	0,
	128,
	128,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 08 */
	{
	1,
	SSL3_TXT_RSA_DES_40_CBC_SHA,
	SSL3_CK_RSA_DES_40_CBC_SHA,
	SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1|SSL_SSLV3,
	SSL_EXPORT|SSL_EXP40,
	0,
	40,
	56,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 09 */
	{
	1,
	SSL3_TXT_RSA_DES_64_CBC_SHA,
	SSL3_CK_RSA_DES_64_CBC_SHA,
	SSL_kRSA|SSL_aRSA|SSL_DES  |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_LOW,
	0,
	56,
	56,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 0A */
	{
	1,
	SSL3_TXT_RSA_DES_192_CBC3_SHA,
	SSL3_CK_RSA_DES_192_CBC3_SHA,
	SSL_kRSA|SSL_aRSA|SSL_3DES |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_HIGH,
	0,
	168,
	168,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},

/*  The DH ciphers */
/* Cipher 0B */
	{
	0,
	SSL3_TXT_DH_DSS_DES_40_CBC_SHA,
	SSL3_CK_DH_DSS_DES_40_CBC_SHA,
	SSL_kDHd |SSL_aDH|SSL_DES|SSL_SHA1|SSL_SSLV3,
	SSL_EXPORT|SSL_EXP40,
	0,
	40,
	56,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 0C */
	{
	0,
	SSL3_TXT_DH_DSS_DES_64_CBC_SHA,
	SSL3_CK_DH_DSS_DES_64_CBC_SHA,
	SSL_kDHd |SSL_aDH|SSL_DES  |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_LOW,
	0,
	56,
	56,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 0D */
	{
	0,
	SSL3_TXT_DH_DSS_DES_192_CBC3_SHA,
	SSL3_CK_DH_DSS_DES_192_CBC3_SHA,
	SSL_kDHd |SSL_aDH|SSL_3DES |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_HIGH,
	0,
	168,
	168,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 0E */
	{
	0,
	SSL3_TXT_DH_RSA_DES_40_CBC_SHA,
	SSL3_CK_DH_RSA_DES_40_CBC_SHA,
	SSL_kDHr |SSL_aDH|SSL_DES|SSL_SHA1|SSL_SSLV3,
	SSL_EXPORT|SSL_EXP40,
	0,
	40,
	56,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 0F */
	{
	0,
	SSL3_TXT_DH_RSA_DES_64_CBC_SHA,
	SSL3_CK_DH_RSA_DES_64_CBC_SHA,
	SSL_kDHr |SSL_aDH|SSL_DES  |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_LOW,
	0,
	56,
	56,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 10 */
	{
	0,
	SSL3_TXT_DH_RSA_DES_192_CBC3_SHA,
	SSL3_CK_DH_RSA_DES_192_CBC3_SHA,
	SSL_kDHr |SSL_aDH|SSL_3DES |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_HIGH,
	0,
	168,
	168,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},

/* The Ephemeral DH ciphers */
/* Cipher 11 */
	{
	1,
	SSL3_TXT_EDH_DSS_DES_40_CBC_SHA,
	SSL3_CK_EDH_DSS_DES_40_CBC_SHA,
	SSL_kEDH|SSL_aDSS|SSL_DES|SSL_SHA1|SSL_SSLV3,
	SSL_EXPORT|SSL_EXP40,
	0,
	40,
	56,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 12 */
	{
	1,
	SSL3_TXT_EDH_DSS_DES_64_CBC_SHA,
	SSL3_CK_EDH_DSS_DES_64_CBC_SHA,
	SSL_kEDH|SSL_aDSS|SSL_DES  |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_LOW,
	0,
	56,
	56,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 13 */
	{
	1,
	SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA,
	SSL3_CK_EDH_DSS_DES_192_CBC3_SHA,
	SSL_kEDH|SSL_aDSS|SSL_3DES |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_HIGH,
	0,
	168,
	168,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 14 */
	{
	1,
	SSL3_TXT_EDH_RSA_DES_40_CBC_SHA,
	SSL3_CK_EDH_RSA_DES_40_CBC_SHA,
	SSL_kEDH|SSL_aRSA|SSL_DES|SSL_SHA1|SSL_SSLV3,
	SSL_EXPORT|SSL_EXP40,
	0,
	40,
	56,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 15 */
	{
	1,
	SSL3_TXT_EDH_RSA_DES_64_CBC_SHA,
	SSL3_CK_EDH_RSA_DES_64_CBC_SHA,
	SSL_kEDH|SSL_aRSA|SSL_DES  |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_LOW,
	0,
	56,
	56,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},
/* Cipher 16 */
	{
	1,
	SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA,
	SSL3_CK_EDH_RSA_DES_192_CBC3_SHA,
	SSL_kEDH|SSL_aRSA|SSL_3DES |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP|SSL_HIGH,
	0,
	168,
	168,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},

/* Fortezza */
/* Cipher 1C */
	{
	0,
	SSL3_TXT_FZA_DMS_NULL_SHA,
	SSL3_CK_FZA_DMS_NULL_SHA,
	SSL_kFZA|SSL_aFZA |SSL_eNULL |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP,
	0,
	0,
	0,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},

/* Cipher 1D */
	{
	0,
	SSL3_TXT_FZA_DMS_FZA_SHA,
	SSL3_CK_FZA_DMS_FZA_SHA,
	SSL_kFZA|SSL_aFZA |SSL_eFZA |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP,
	0,
	0,
	0,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},

/* Cipher 1E */
	{
	0,
	SSL3_TXT_FZA_DMS_RC4_SHA,
	SSL3_CK_FZA_DMS_RC4_SHA,
	SSL_kFZA|SSL_aFZA |SSL_RC4  |SSL_SHA1|SSL_SSLV3,
	SSL_NOT_EXP,
	0,
	128,
	128,
	SSL_ALL_CIPHERS,
	SSL_ALL_STRENGTHS,
	},

#if TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES
	/* New TLS Export CipherSuites */
	/* Cipher 60 */
	    {
	    1,
	    TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_MD5,
	    TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5,
	    SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5|SSL_TLSV1,
	    SSL_EXPORT|SSL_EXP56,
	    0,
	    56,
	    128,
	    SSL_ALL_CIPHERS,
	    SSL_ALL_STRENGTHS,
	    },
	/* Cipher 61 */
	    {
	    1,
	    TLS1_TXT_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
	    TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
	    SSL_kRSA|SSL_aRSA|SSL_RC2|SSL_MD5|SSL_TLSV1,
	    SSL_EXPORT|SSL_EXP56,
	    0,
	    56,
	    128,
	    SSL_ALL_CIPHERS,
	    SSL_ALL_STRENGTHS,
	    },
	/* Cipher 62 */
	    {
	    1,
	    TLS1_TXT_RSA_EXPORT1024_WITH_DES_CBC_SHA,
	    TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA,
	    SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA|SSL_TLSV1,
	    SSL_EXPORT|SSL_EXP56,
	    0,
	    56,
	    56,
	    SSL_ALL_CIPHERS,
	    SSL_ALL_STRENGTHS,
	    },
	/* Cipher 63 */
	    {
	    1,
	    TLS1_TXT_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
	    TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
	    SSL_kEDH|SSL_aDSS|SSL_DES|SSL_SHA|SSL_TLSV1,
	    SSL_EXPORT|SSL_EXP56,
	    0,
	    56,
	    56,
	    SSL_ALL_CIPHERS,
	    SSL_ALL_STRENGTHS,
	    },
	/* Cipher 64 */
	    {
	    1,
	    TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_SHA,
	    TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA,
	    SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_SHA|SSL_TLSV1,
	    SSL_EXPORT|SSL_EXP56,
	    0,
	    56,
	    128,
	    SSL_ALL_CIPHERS,
	    SSL_ALL_STRENGTHS,
	    },
	/* Cipher 65 */
	    {
	    1,
	    TLS1_TXT_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
	    TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
	    SSL_kEDH|SSL_aDSS|SSL_RC4|SSL_SHA|SSL_TLSV1,
	    SSL_EXPORT|SSL_EXP56,
	    0,
	    56,
	    128,
	    SSL_ALL_CIPHERS,
	    SSL_ALL_STRENGTHS,
	    },
	/* Cipher 66 */
	    {
	    1,
	    TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA,
	    TLS1_CK_DHE_DSS_WITH_RC4_128_SHA,
	    SSL_kEDH|SSL_aDSS|SSL_RC4|SSL_SHA|SSL_TLSV1,
	    SSL_NOT_EXP,
	    0,
	    128,
	    128,
	    SSL_ALL_CIPHERS,
	    SSL_ALL_STRENGTHS
	    },
#endif

/* end of list */
	};

static SSL3_ENC_METHOD SSLv3_enc_data={
	ssl3_enc,
	ssl3_mac,
	ssl3_setup_key_block,
	ssl3_generate_master_secret,
	ssl3_change_cipher_state,
	ssl3_final_finish_mac,
	MD5_DIGEST_LENGTH+SHA_DIGEST_LENGTH,
	ssl3_cert_verify_mac,
	SSL3_MD_CLIENT_FINISHED_CONST,4,
	SSL3_MD_SERVER_FINISHED_CONST,4,
	ssl3_alert_code,
	};

static SSL_METHOD SSLv3_data= {
	SSL3_VERSION,
	ssl3_new,
	ssl3_clear,
	ssl3_free,
	ssl_undefined_function,
	ssl_undefined_function,
	ssl3_read,
	ssl3_peek,
	ssl3_write,
	ssl3_shutdown,
	ssl3_renegotiate,
	ssl3_renegotiate_check,
	ssl3_ctrl,
	ssl3_ctx_ctrl,
	ssl3_get_cipher_by_char,
	ssl3_put_cipher_by_char,
	ssl3_pending,
	ssl3_num_ciphers,
	ssl3_get_cipher,
	ssl_bad_method,
	ssl3_default_timeout,
	&SSLv3_enc_data,
	ssl_undefined_function,
	ssl3_callback_ctrl,
	ssl3_ctx_callback_ctrl,
	};

static long ssl3_default_timeout(void)
	{
	/* 2 hours, the 24 hours mentioned in the SSLv3 spec
	 * is way too long for http, the cache would over fill */
	return(60*60*2);
	}

SSL_METHOD *sslv3_base_method(void)
	{
	return(&SSLv3_data);
	}

int ssl3_num_ciphers(void)
	{
	return(SSL3_NUM_CIPHERS);
	}

SSL_CIPHER *ssl3_get_cipher(unsigned int u)
	{
	if (u < SSL3_NUM_CIPHERS)
		return(&(ssl3_ciphers[SSL3_NUM_CIPHERS-1-u]));
	else
		return(NULL);
	}

/* The problem is that it may not be the correct record type */
int ssl3_pending(SSL *s)
	{
	return(s->s3->rrec.length);
	}

int ssl3_new(SSL *s)
	{
	SSL3_STATE *s3;

	if ((s3=OPENSSL_malloc(sizeof *s3)) == NULL) goto err;
	memset(s3,0,sizeof *s3);

	s->s3=s3;

	s->method->ssl_clear(s);
	return(1);
err:
	return(0);
	}

void ssl3_free(SSL *s)
	{
	if(s == NULL)
	    return;

	ssl3_cleanup_key_block(s);
	if (s->s3->rbuf.buf != NULL)
		OPENSSL_free(s->s3->rbuf.buf);
	if (s->s3->wbuf.buf != NULL)
		OPENSSL_free(s->s3->wbuf.buf);
	if (s->s3->rrec.comp != NULL)
		OPENSSL_free(s->s3->rrec.comp);
#ifndef NO_DH
	if (s->s3->tmp.dh != NULL)
		DH_free(s->s3->tmp.dh);
#endif
	if (s->s3->tmp.ca_names != NULL)
		sk_X509_NAME_pop_free(s->s3->tmp.ca_names,X509_NAME_free);
	memset(s->s3,0,sizeof *s->s3);
	OPENSSL_free(s->s3);
	s->s3=NULL;
	}

void ssl3_clear(SSL *s)
	{
	unsigned char *rp,*wp;

	ssl3_cleanup_key_block(s);
	if (s->s3->tmp.ca_names != NULL)
		sk_X509_NAME_pop_free(s->s3->tmp.ca_names,X509_NAME_free);

	if (s->s3->rrec.comp != NULL)
		{
		OPENSSL_free(s->s3->rrec.comp);
		s->s3->rrec.comp=NULL;
		}
#ifndef NO_DH
	if (s->s3->tmp.dh != NULL)
		DH_free(s->s3->tmp.dh);
#endif

	rp=s->s3->rbuf.buf;
	wp=s->s3->wbuf.buf;

	memset(s->s3,0,sizeof *s->s3);
	if (rp != NULL) s->s3->rbuf.buf=rp;
	if (wp != NULL) s->s3->wbuf.buf=wp;

	ssl_free_wbio_buffer(s);

	s->packet_length=0;
	s->s3->renegotiate=0;
	s->s3->total_renegotiations=0;
	s->s3->num_renegotiations=0;
	s->s3->in_read_app_data=0;
	s->version=SSL3_VERSION;
	}

long ssl3_ctrl(SSL *s, int cmd, long larg, char *parg)
	{
	int ret=0;

#if !defined(NO_DSA) || !defined(NO_RSA)
	if (
#ifndef NO_RSA
	    cmd == SSL_CTRL_SET_TMP_RSA ||
	    cmd == SSL_CTRL_SET_TMP_RSA_CB ||
#endif
#ifndef NO_DSA
	    cmd == SSL_CTRL_SET_TMP_DH ||
	    cmd == SSL_CTRL_SET_TMP_DH_CB ||
#endif
		0)
		{
		if (!ssl_cert_inst(&s->cert))
		    	{
			SSLerr(SSL_F_SSL3_CTRL, ERR_R_MALLOC_FAILURE);
			return(0);
			}
		}
#endif

	switch (cmd)
		{
	case SSL_CTRL_GET_SESSION_REUSED:
		ret=s->hit;
		break;
	case SSL_CTRL_GET_CLIENT_CERT_REQUEST:
		break;
	case SSL_CTRL_GET_NUM_RENEGOTIATIONS:
		ret=s->s3->num_renegotiations;
		break;
	case SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS:
		ret=s->s3->num_renegotiations;
		s->s3->num_renegotiations=0;
		break;
	case SSL_CTRL_GET_TOTAL_RENEGOTIATIONS:
		ret=s->s3->total_renegotiations;
		break;
	case SSL_CTRL_GET_FLAGS:
		ret=(int)(s->s3->flags);
		break;
#ifndef NO_RSA
	case SSL_CTRL_NEED_TMP_RSA:
		if ((s->cert != NULL) && (s->cert->rsa_tmp == NULL) &&
		    ((s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL) ||
		     (EVP_PKEY_size(s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey) > (512/8))))
			ret = 1;
		break;
	case SSL_CTRL_SET_TMP_RSA:
		{
			RSA *rsa = (RSA *)parg;
			if (rsa == NULL)
				{
				SSLerr(SSL_F_SSL3_CTRL, ERR_R_PASSED_NULL_PARAMETER);
				return(ret);
				}
			if ((rsa = RSAPrivateKey_dup(rsa)) == NULL)
				{
				SSLerr(SSL_F_SSL3_CTRL, ERR_R_RSA_LIB);
				return(ret);
				}
			if (s->cert->rsa_tmp != NULL)
				RSA_free(s->cert->rsa_tmp);
			s->cert->rsa_tmp = rsa;
			ret = 1;
		}
		break;
	case SSL_CTRL_SET_TMP_RSA_CB:
		{
		SSLerr(SSL_F_SSL3_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return(ret);
		}
		break;
#endif
#ifndef NO_DH
	case SSL_CTRL_SET_TMP_DH:
		{
			DH *dh = (DH *)parg;
			if (dh == NULL)
				{
				SSLerr(SSL_F_SSL3_CTRL, ERR_R_PASSED_NULL_PARAMETER);
				return(ret);
				}
			if ((dh = DHparams_dup(dh)) == NULL)
				{
				SSLerr(SSL_F_SSL3_CTRL, ERR_R_DH_LIB);
				return(ret);
				}
			if (!(s->options & SSL_OP_SINGLE_DH_USE))
				{
				if (!DH_generate_key(dh))
					{
					DH_free(dh);
					SSLerr(SSL_F_SSL3_CTRL, ERR_R_DH_LIB);
					return(ret);
					}
				}
			if (s->cert->dh_tmp != NULL)
				DH_free(s->cert->dh_tmp);
			s->cert->dh_tmp = dh;
			ret = 1;
		}
		break;
	case SSL_CTRL_SET_TMP_DH_CB:
		{
		SSLerr(SSL_F_SSL3_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return(ret);
		}
		break;
#endif
	default:
		break;
		}
	return(ret);
	}

long ssl3_callback_ctrl(SSL *s, int cmd, void (*fp)())
	{
	int ret=0;

#if !defined(NO_DSA) || !defined(NO_RSA)
	if (
#ifndef NO_RSA
	    cmd == SSL_CTRL_SET_TMP_RSA_CB ||
#endif
#ifndef NO_DSA
	    cmd == SSL_CTRL_SET_TMP_DH_CB ||
#endif
		0)
		{
		if (!ssl_cert_inst(&s->cert))
			{
			SSLerr(SSL_F_SSL3_CALLBACK_CTRL, ERR_R_MALLOC_FAILURE);
			return(0);
			}
		}
#endif

	switch (cmd)
		{
#ifndef NO_RSA
	case SSL_CTRL_SET_TMP_RSA_CB:
		{
		s->cert->rsa_tmp_cb = (RSA *(*)(SSL *, int, int))fp;
		}
		break;
#endif
#ifndef NO_DH
	case SSL_CTRL_SET_TMP_DH_CB:
		{
		s->cert->dh_tmp_cb = (DH *(*)(SSL *, int, int))fp;
		}
		break;
#endif
	default:
		break;
		}
	return(ret);
	}

long ssl3_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, char *parg)
	{
	CERT *cert;

	cert=ctx->cert;

	switch (cmd)
		{
#ifndef NO_RSA
	case SSL_CTRL_NEED_TMP_RSA:
		if (	(cert->rsa_tmp == NULL) &&
			((cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL) ||
			 (EVP_PKEY_size(cert->pkeys[SSL_PKEY_RSA_ENC].privatekey) > (512/8)))
			)
			return(1);
		else
			return(0);
		/* break; */
	case SSL_CTRL_SET_TMP_RSA:
		{
		RSA *rsa;
		int i;

		rsa=(RSA *)parg;
		i=1;
		if (rsa == NULL)
			i=0;
		else
			{
			if ((rsa=RSAPrivateKey_dup(rsa)) == NULL)
				i=0;
			}
		if (!i)
			{
			SSLerr(SSL_F_SSL3_CTX_CTRL,ERR_R_RSA_LIB);
			return(0);
			}
		else
			{
			if (cert->rsa_tmp != NULL)
				RSA_free(cert->rsa_tmp);
			cert->rsa_tmp=rsa;
			return(1);
			}
		}
		/* break; */
	case SSL_CTRL_SET_TMP_RSA_CB:
		{
		SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return(0);
		}
		break;
#endif
#ifndef NO_DH
	case SSL_CTRL_SET_TMP_DH:
		{
		DH *new=NULL,*dh;

		dh=(DH *)parg;
		if ((new=DHparams_dup(dh)) == NULL)
			{
			SSLerr(SSL_F_SSL3_CTX_CTRL,ERR_R_DH_LIB);
			return 0;
			}
		if (!(ctx->options & SSL_OP_SINGLE_DH_USE))
			{
			if (!DH_generate_key(new))
				{
				SSLerr(SSL_F_SSL3_CTX_CTRL,ERR_R_DH_LIB);
				DH_free(new);
				return 0;
				}
			}
		if (cert->dh_tmp != NULL)
			DH_free(cert->dh_tmp);
		cert->dh_tmp=new;
		return 1;
		}
		/*break; */
	case SSL_CTRL_SET_TMP_DH_CB:
		{
		SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return(0);
		}
		break;
#endif
	/* A Thawte special :-) */
	case SSL_CTRL_EXTRA_CHAIN_CERT:
		if (ctx->extra_certs == NULL)
			{
			if ((ctx->extra_certs=sk_X509_new_null()) == NULL)
				return(0);
			}
		sk_X509_push(ctx->extra_certs,(X509 *)parg);
		break;

	default:
		return(0);
		}
	return(1);
	}

long ssl3_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp)())
	{
	CERT *cert;

	cert=ctx->cert;

	switch (cmd)
		{
#ifndef NO_RSA
	case SSL_CTRL_SET_TMP_RSA_CB:
		{
		cert->rsa_tmp_cb = (RSA *(*)(SSL *, int, int))fp;
		}
		break;
#endif
#ifndef NO_DH
	case SSL_CTRL_SET_TMP_DH_CB:
		{
		cert->dh_tmp_cb = (DH *(*)(SSL *, int, int))fp;
		}
		break;
#endif
	default:
		return(0);
		}
	return(1);
	}

/* This function needs to check if the ciphers required are actually
 * available */
SSL_CIPHER *ssl3_get_cipher_by_char(const unsigned char *p)
	{
	static int init=1;
	static SSL_CIPHER *sorted[SSL3_NUM_CIPHERS];
	SSL_CIPHER c,*cp= &c,**cpp;
	unsigned long id;
	int i;

	if (init)
		{
		CRYPTO_w_lock(CRYPTO_LOCK_SSL);

		for (i=0; i<SSL3_NUM_CIPHERS; i++)
			sorted[i]= &(ssl3_ciphers[i]);

		qsort(	(char *)sorted,
			SSL3_NUM_CIPHERS,sizeof(SSL_CIPHER *),
			FP_ICC ssl_cipher_ptr_id_cmp);

		CRYPTO_w_unlock(CRYPTO_LOCK_SSL);

		init=0;
		}

	id=0x03000000L|((unsigned long)p[0]<<8L)|(unsigned long)p[1];
	c.id=id;
	cpp=(SSL_CIPHER **)OBJ_bsearch((char *)&cp,
		(char *)sorted,
		SSL3_NUM_CIPHERS,sizeof(SSL_CIPHER *),
		FP_ICC ssl_cipher_ptr_id_cmp);
	if ((cpp == NULL) || !(*cpp)->valid)
		return(NULL);
	else
		return(*cpp);
	}

int ssl3_put_cipher_by_char(const SSL_CIPHER *c, unsigned char *p)
	{
	long l;

	if (p != NULL)
		{
		l=c->id;
		if ((l & 0xff000000) != 0x03000000) return(0);
		p[0]=((unsigned char)(l>> 8L))&0xFF;
		p[1]=((unsigned char)(l     ))&0xFF;
		}
	return(2);
	}

SSL_CIPHER *ssl3_choose_cipher(SSL *s, STACK_OF(SSL_CIPHER) *have,
	     STACK_OF(SSL_CIPHER) *pref)
	{
	SSL_CIPHER *c,*ret=NULL;
	int i,j,ok;
	CERT *cert;
	unsigned long alg,mask,emask;

	/* Let's see which ciphers we can support */
	cert=s->cert;

	sk_SSL_CIPHER_set_cmp_func(pref,ssl_cipher_ptr_id_cmp);

#ifdef CIPHER_DEBUG
	printf("Have:\n");
	for(i=0 ; i < sk_num(pref) ; ++i)
	    {
	    c=(SSL_CIPHER *)sk_value(pref,i);
	    printf("%p:%s\n",c,c->name);
	    }
#endif

	for (i=0; i<sk_SSL_CIPHER_num(have); i++)
		{
		c=sk_SSL_CIPHER_value(have,i);

		ssl_set_cert_masks(cert,c);
		mask=cert->mask;
		emask=cert->export_mask;
			
		alg=c->algorithms&(SSL_MKEY_MASK|SSL_AUTH_MASK);
		if (SSL_C_IS_EXPORT(c))
			{
			ok=((alg & emask) == alg)?1:0;
#ifdef CIPHER_DEBUG
			printf("%d:[%08lX:%08lX]%p:%s (export)\n",ok,alg,emask,
			       c,c->name);
#endif
			}
		else
			{
			ok=((alg & mask) == alg)?1:0;
#ifdef CIPHER_DEBUG
			printf("%d:[%08lX:%08lX]%p:%s\n",ok,alg,mask,c,
			       c->name);
#endif
			}

		if (!ok) continue;
	
		j=sk_SSL_CIPHER_find(pref,c);
		if (j >= 0)
			{
			ret=sk_SSL_CIPHER_value(pref,j);
			break;
			}
		}
	return(ret);
	}

int ssl3_get_req_cert_type(SSL *s, unsigned char *p)
	{
	int ret=0;
	unsigned long alg;

	alg=s->s3->tmp.new_cipher->algorithms;

#ifndef NO_DH
	if (alg & (SSL_kDHr|SSL_kEDH))
		{
#  ifndef NO_RSA
		p[ret++]=SSL3_CT_RSA_FIXED_DH;
#  endif
#  ifndef NO_DSA
		p[ret++]=SSL3_CT_DSS_FIXED_DH;
#  endif
		}
	if ((s->version == SSL3_VERSION) &&
		(alg & (SSL_kEDH|SSL_kDHd|SSL_kDHr)))
		{
#  ifndef NO_RSA
		p[ret++]=SSL3_CT_RSA_EPHEMERAL_DH;
#  endif
#  ifndef NO_DSA
		p[ret++]=SSL3_CT_DSS_EPHEMERAL_DH;
#  endif
		}
#endif /* !NO_DH */
#ifndef NO_RSA
	p[ret++]=SSL3_CT_RSA_SIGN;
#endif
#ifndef NO_DSA
	p[ret++]=SSL3_CT_DSS_SIGN;
#endif
	return(ret);
	}

int ssl3_shutdown(SSL *s)
	{

	/* Don't do anything much if we have not done the handshake or
	 * we don't want to send messages :-) */
	if ((s->quiet_shutdown) || (s->state == SSL_ST_BEFORE))
		{
		s->shutdown=(SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
		return(1);
		}

	if (!(s->shutdown & SSL_SENT_SHUTDOWN))
		{
		s->shutdown|=SSL_SENT_SHUTDOWN;
#if 1
		ssl3_send_alert(s,SSL3_AL_WARNING,SSL_AD_CLOSE_NOTIFY);
#endif
		/* our shutdown alert has been sent now, and if it still needs
	 	 * to be written, s->s3->alert_dispatch will be true */
		}
	else if (s->s3->alert_dispatch)
		{
		/* resend it if not sent */
#if 1
		ssl3_dispatch_alert(s);
#endif
		}
	else if (!(s->shutdown & SSL_RECEIVED_SHUTDOWN))
		{
		/* If we are waiting for a close from our peer, we are closed */
		ssl3_read_bytes(s,0,NULL,0);
		}

	if ((s->shutdown == (SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN)) &&
		!s->s3->alert_dispatch)
		return(1);
	else
		return(0);
	}

int ssl3_write(SSL *s, const void *buf, int len)
	{
	int ret,n;

#if 0
	if (s->shutdown & SSL_SEND_SHUTDOWN)
		{
		s->rwstate=SSL_NOTHING;
		return(0);
		}
#endif
	clear_sys_error();
	if (s->s3->renegotiate) ssl3_renegotiate_check(s);

	/* This is an experimental flag that sends the
	 * last handshake message in the same packet as the first
	 * use data - used to see if it helps the TCP protocol during
	 * session-id reuse */
	/* The second test is because the buffer may have been removed */
	if ((s->s3->flags & SSL3_FLAGS_POP_BUFFER) && (s->wbio == s->bbio))
		{
		/* First time through, we write into the buffer */
		if (s->s3->delay_buf_pop_ret == 0)
			{
			ret=ssl3_write_bytes(s,SSL3_RT_APPLICATION_DATA,
					     buf,len);
			if (ret <= 0) return(ret);

			s->s3->delay_buf_pop_ret=ret;
			}

		s->rwstate=SSL_WRITING;
		n=BIO_flush(s->wbio);
		if (n <= 0) return(n);
		s->rwstate=SSL_NOTHING;

		/* We have flushed the buffer, so remove it */
		ssl_free_wbio_buffer(s);
		s->s3->flags&= ~SSL3_FLAGS_POP_BUFFER;

		ret=s->s3->delay_buf_pop_ret;
		s->s3->delay_buf_pop_ret=0;
		}
	else
		{
		ret=ssl3_write_bytes(s,SSL3_RT_APPLICATION_DATA,
				     buf,len);
		if (ret <= 0) return(ret);
		}

	return(ret);
	}

int ssl3_read(SSL *s, void *buf, int len)
	{
	int ret;
	
	clear_sys_error();
	if (s->s3->renegotiate) ssl3_renegotiate_check(s);
	s->s3->in_read_app_data=1;
	ret=ssl3_read_bytes(s,SSL3_RT_APPLICATION_DATA,buf,len);
	if ((ret == -1) && (s->s3->in_read_app_data == 0))
		{
		/* ssl3_read_bytes decided to call s->handshake_func, which
		 * called ssl3_read_bytes to read handshake data.
		 * However, ssl3_read_bytes actually found application data
		 * and thinks that application data makes sense here (signalled
		 * by resetting 'in_read_app_data', strangely); so disable
		 * handshake processing and try to read application data again. */
		s->in_handshake++;
		ret=ssl3_read_bytes(s,SSL3_RT_APPLICATION_DATA,buf,len);
		s->in_handshake--;
		}
	else
		s->s3->in_read_app_data=0;

	return(ret);
	}

int ssl3_peek(SSL *s, char *buf, int len)
	{
	SSL3_RECORD *rr;
	int n;

	rr= &(s->s3->rrec);
	if ((rr->length == 0) || (rr->type != SSL3_RT_APPLICATION_DATA))
		{
		n=ssl3_read(s,buf,1);
		if (n <= 0) return(n);
		rr->length++;
		rr->off--;
		}

	if ((unsigned int)len > rr->length)
		n=rr->length;
	else
		n=len;
	memcpy(buf,&(rr->data[rr->off]),(unsigned int)n);
	return(n);
	}

int ssl3_renegotiate(SSL *s)
	{
	if (s->handshake_func == NULL)
		return(1);

	if (s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS)
		return(0);

	s->s3->renegotiate=1;
	return(1);
	}

int ssl3_renegotiate_check(SSL *s)
	{
	int ret=0;

	if (s->s3->renegotiate)
		{
		if (	(s->s3->rbuf.left == 0) &&
			(s->s3->wbuf.left == 0) &&
			!SSL_in_init(s))
			{
/*
if we are the server, and we have sent a 'RENEGOTIATE' message, we
need to go to SSL_ST_ACCEPT.
*/
			/* SSL_ST_ACCEPT */
			s->state=SSL_ST_RENEGOTIATE;
			s->s3->renegotiate=0;
			s->s3->num_renegotiations++;
			s->s3->total_renegotiations++;
			ret=1;
			}
		}
	return(ret);
	}

