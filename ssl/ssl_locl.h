/* ssl/ssl_locl.h */
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

#ifndef HEADER_SSL_LOCL_H
#define HEADER_SSL_LOCL_H
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>

#include "e_os.h"

#include "buffer.h"
#include "bio.h"
#include "crypto.h"
#include "evp.h"
#include "stack.h"
#include "x509.h"
#include "err.h"
#include "ssl.h"


#define c2l(c,l)	(l = ((unsigned long)(*((c)++)))     , \
			 l|=(((unsigned long)(*((c)++)))<< 8), \
			 l|=(((unsigned long)(*((c)++)))<<16), \
			 l|=(((unsigned long)(*((c)++)))<<24))

/* NOTE - c is not incremented as per c2l */
#define c2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((unsigned long)(*(--(c))))<<24; \
			case 7: l2|=((unsigned long)(*(--(c))))<<16; \
			case 6: l2|=((unsigned long)(*(--(c))))<< 8; \
			case 5: l2|=((unsigned long)(*(--(c))));     \
			case 4: l1 =((unsigned long)(*(--(c))))<<24; \
			case 3: l1|=((unsigned long)(*(--(c))))<<16; \
			case 2: l1|=((unsigned long)(*(--(c))))<< 8; \
			case 1: l1|=((unsigned long)(*(--(c))));     \
				} \
			}

#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)    )&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24)&0xff))

#define n2l(c,l)	(l =((unsigned long)(*((c)++)))<<24, \
			 l|=((unsigned long)(*((c)++)))<<16, \
			 l|=((unsigned long)(*((c)++)))<< 8, \
			 l|=((unsigned long)(*((c)++))))

#define l2n(l,c)	(*((c)++)=(unsigned char)(((l)>>24)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16)&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((l)    )&0xff))

/* NOTE - c is not incremented as per l2c */
#define l2cn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 8: *(--(c))=(unsigned char)(((l2)>>24)&0xff); \
			case 7: *(--(c))=(unsigned char)(((l2)>>16)&0xff); \
			case 6: *(--(c))=(unsigned char)(((l2)>> 8)&0xff); \
			case 5: *(--(c))=(unsigned char)(((l2)    )&0xff); \
			case 4: *(--(c))=(unsigned char)(((l1)>>24)&0xff); \
			case 3: *(--(c))=(unsigned char)(((l1)>>16)&0xff); \
			case 2: *(--(c))=(unsigned char)(((l1)>> 8)&0xff); \
			case 1: *(--(c))=(unsigned char)(((l1)    )&0xff); \
				} \
			}

#define n2s(c,s)	(s =((unsigned int)(*((c)++)))<< 8, \
			 s|=((unsigned int)(*((c)++))))
#define s2n(s,c)	(*((c)++)=(unsigned char)(((s)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((s)    )&0xff))

#define n2l3(c,l)	(l =((unsigned long)(*((c)++)))<<16, \
			 l|=((unsigned long)(*((c)++)))<< 8, \
			 l|=((unsigned long)(*((c)++))))

#define l2n3(l,c)	(*((c)++)=(unsigned char)(((l)>>16)&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((l)    )&0xff))

/* LOCAL STUFF */

#define SSL_DECRYPT	0
#define SSL_ENCRYPT	1

#define TWO_BYTE_BIT	0x80
#define SEC_ESC_BIT	0x40
#define TWO_BYTE_MASK	0x7fff
#define THREE_BYTE_MASK	0x3fff

#define INC32(a)	((a)=((a)+1)&0xffffffffL)
#define DEC32(a)	((a)=((a)-1)&0xffffffffL)
#define MAX_MAC_SIZE	20 /* up from 16 for SSLv3 */

#define SSL_MKEY_MASK		0x0000001FL
#define SSL_kRSA		0x00000001L /* RSA key exchange */
#define SSL_kDHr		0x00000002L /* DH cert RSA CA cert */
#define SSL_kDHd		0x00000004L /* DH cert DSA CA cert */
#define SSL_kFZA		0x00000008L
#define SSL_kEDH		0x00000010L /* tmp DH key no DH cert */
#define SSL_EDH			(SSL_kEDH|(SSL_AUTH_MASK^SSL_aNULL))

#define SSL_AUTH_MASK		0x000003e0L
#define SSL_aRSA		0x00000020L /* Authenticate with RSA */
#define SSL_aDSS 		0x00000040L /* Authenticate with DSS */
#define SSL_DSS 		SSL_aDSS
#define SSL_aFZA 		0x00000080L
#define SSL_aNULL 		0x00000100L /* no Authenticate, ADH */
#define SSL_aDH 		0x00000200L /* no Authenticate, ADH */

#define SSL_NULL		(SSL_eNULL)
#define SSL_ADH			(SSL_kEDH|SSL_aNULL)
#define SSL_RSA			(SSL_kRSA|SSL_aRSA)
#define SSL_DH			(SSL_kDHr|SSL_kDHd|SSL_kEDH)
#define SSL_FZA			(SSL_aFZA|SSL_kFZA|SSL_eFZA)

#define SSL_ENC_MASK		0x0001Fc00L
#define SSL_DES			0x00000400L
#define SSL_3DES		0x00000800L
#define SSL_RC4			0x00001000L
#define SSL_RC2			0x00002000L
#define SSL_IDEA		0x00004000L
#define SSL_eFZA		0x00008000L
#define SSL_eNULL		0x00010000L

#define SSL_MAC_MASK		0x00060000L
#define SSL_MD5			0x00020000L
#define SSL_SHA1		0x00040000L
#define SSL_SHA			(SSL_SHA1)

#define SSL_EXP_MASK		0x00300000L
#define SSL_EXP			0x00100000L
#define SSL_NOT_EXP		0x00200000L
#define SSL_EXPORT		SSL_EXP

#define SSL_SSL_MASK		0x00c00000L
#define SSL_SSLV2		0x00400000L
#define SSL_SSLV3		0x00800000L

#define SSL_STRONG_MASK		0x07000000L
#define SSL_LOW			0x01000000L
#define SSL_MEDIUM		0x02000000L
#define SSL_HIGH		0x04000000L

/* we have used 0fffffff - 4 bits left to go */
#define SSL_ALL			0xffffffffL
#define SSL_ALL_CIPHERS		(SSL_MKEY_MASK|SSL_AUTH_MASK|SSL_ENC_MASK|\
				SSL_MAC_MASK|SSL_EXP_MASK)

/* Mostly for SSLv3 */
#define SSL_PKEY_RSA_ENC	0
#define SSL_PKEY_RSA_SIGN	1
#define SSL_PKEY_DSA_SIGN	2
#define SSL_PKEY_DH_RSA		3
#define SSL_PKEY_DH_DSA		4
#define SSL_PKEY_NUM		5

/* SSL_kRSA <- RSA_ENC | (RSA_TMP & RSA_SIGN) |
 * 	    <- (EXPORT & (RSA_ENC | RSA_TMP) & RSA_SIGN)
 * SSL_kDH  <- DH_ENC & (RSA_ENC | RSA_SIGN | DSA_SIGN)
 * SSL_kEDH <- RSA_ENC | RSA_SIGN | DSA_SIGN
 * SSL_aRSA <- RSA_ENC | RSA_SIGN
 * SSL_aDSS <- DSA_SIGN
 */

/*
#define CERT_INVALID		0
#define CERT_PUBLIC_KEY		1
#define CERT_PRIVATE_KEY	2
*/

typedef struct cert_pkey_st
	{
	X509 *x509;
/*	EVP_PKEY *publickey; *//* when extracted */
	EVP_PKEY *privatekey;
	} CERT_PKEY;

typedef struct cert_st
	{
	int cert_type;

#ifdef undef
	X509 *x509;
	EVP_PKEY *publickey; /* when extracted */
	EVP_PKEY *privatekey;

	pkeys[SSL_PKEY_RSA_ENC].x509
/*	pkeys[SSL_PKEY_RSA_ENC].publickey */
	pkeys[SSL_PKEY_RSA_ENC].privatekey
#endif

	/* Current active set */
	CERT_PKEY *key;

	/* The following masks are for the key and auth
	 * algorithms that are supported by the certs below */
	int valid;
	unsigned long mask;
	unsigned long export_mask;

	RSA *rsa_tmp;
	DH *dh_tmp;
	RSA *(*rsa_tmp_cb)();
	DH *(*dh_tmp_cb)();
	CERT_PKEY pkeys[SSL_PKEY_NUM];

	STACK *cert_chain;

	int references;
	} CERT;

/*#define MAC_DEBUG	*/

/*#define ERR_DEBUG	*/
/*#define ABORT_DEBUG	*/
/*#define PKT_DEBUG 1   */
/*#define DES_DEBUG	*/
/*#define DES_OFB_DEBUG	*/
/*#define SSL_DEBUG	*/
/*#define RSA_DEBUG	*/ 
/*#define IDEA_DEBUG	*/ 

#ifndef NOPROTO
#define FP_ICC  (int (*)(const void *,const void *))
#else
#define FP_ICC
#endif

#define ssl_put_cipher_by_char(ssl,ciph,ptr) \
		((ssl)->method->put_cipher_by_char((ciph),(ptr)))
#define ssl_get_cipher_by_char(ssl,ptr) \
		((ssl)->method->get_cipher_by_char(ptr))

/* This is for the SSLv3/TLSv1.0 differences in crypto/hash stuff
 * It is a bit of a mess of functions, but hell, think of it as
 * an opaque strucute :-) */
typedef struct ssl3_enc_method
	{
	int (*enc)();
	int (*mac)();
	int (*setup_key_block)();
	int (*generate_master_secret)();
	int (*change_cipher_state)();
	int (*final_finish_mac)();
	int finish_mac_length;
	int (*cert_verify_mac)();
	unsigned char client_finished[20];
	int client_finished_len;
	unsigned char server_finished[20];
	int server_finished_len;
	int (*alert_value)();
	} SSL3_ENC_METHOD;

extern SSL3_ENC_METHOD ssl3_undef_enc_method;
extern SSL_CIPHER ssl2_ciphers[];
extern SSL_CIPHER ssl3_ciphers[];

#ifndef NOPROTO

SSL_METHOD *ssl_bad_method(int ver);
SSL_METHOD *sslv2_base_method(void);
SSL_METHOD *sslv23_base_method(void);
SSL_METHOD *sslv3_base_method(void);

void ssl_clear_cipher_ctx(SSL *s);
int ssl_clear_bad_session(SSL *s);
CERT *ssl_cert_new(void);
void ssl_cert_free(CERT *c);
int ssl_set_cert_type(CERT *c, int type);
int ssl_get_new_session(SSL *s, int session);
int ssl_get_prev_session(SSL *s, unsigned char *session,int len);
int ssl_cipher_id_cmp(SSL_CIPHER *a,SSL_CIPHER *b);
int ssl_cipher_ptr_id_cmp(SSL_CIPHER **ap,SSL_CIPHER **bp);
STACK *ssl_bytes_to_cipher_list(SSL *s,unsigned char *p,int num,STACK **skp);
int ssl_cipher_list_to_bytes(SSL *s,STACK *sk,unsigned char *p);
STACK *ssl_create_cipher_list(SSL_METHOD *meth,STACK **pref,
	STACK **sorted,char *str);
void ssl_update_cache(SSL *s, int mode);
int ssl_cipher_get_evp(SSL_CIPHER *c, EVP_CIPHER **enc, EVP_MD **md);
int ssl_verify_cert_chain(SSL *s,STACK *sk);
int ssl_undefined_function(SSL *s);
X509 *ssl_get_server_send_cert(SSL *);
EVP_PKEY *ssl_get_sign_pkey(SSL *,SSL_CIPHER *);
int ssl_cert_type(X509 *x,EVP_PKEY *pkey);
void ssl_set_cert_masks(CERT *c);
STACK *ssl_get_ciphers_by_id(SSL *s);
int ssl_verify_alarm_type(long type);

int ssl2_enc_init(SSL *s, int client);
void ssl2_generate_key_material(SSL *s);
void ssl2_enc(SSL *s,int send_data);
void ssl2_mac(SSL *s,unsigned char *mac,int send_data);
SSL_CIPHER *ssl2_get_cipher_by_char(unsigned char *p);
int ssl2_put_cipher_by_char(SSL_CIPHER *c,unsigned char *p);
int ssl2_part_read(SSL *s, unsigned long f, int i);
int ssl2_do_write(SSL *s);
int ssl2_set_certificate(SSL *s, int type, int len, unsigned char *data);
void ssl2_return_error(SSL *s,int reason);
void ssl2_write_error(SSL *s);
int ssl2_num_ciphers(void);
SSL_CIPHER *ssl2_get_cipher(unsigned int u);
int	ssl2_new(SSL *s);
void	ssl2_free(SSL *s);
int	ssl2_accept(SSL *s);
int	ssl2_connect(SSL *s);
int	ssl2_read(SSL *s, char *buf, int len);
int	ssl2_peek(SSL *s, char *buf, int len);
int	ssl2_write(SSL *s, char *buf, int len);
int	ssl2_shutdown(SSL *s);
void	ssl2_clear(SSL *s);
long	ssl2_ctrl(SSL *s,int cmd, long larg, char *parg);
long	ssl2_ctx_ctrl(SSL_CTX *s,int cmd, long larg, char *parg);
int	ssl2_pending(SSL *s);

SSL_CIPHER *ssl3_get_cipher_by_char(unsigned char *p);
int ssl3_put_cipher_by_char(SSL_CIPHER *c,unsigned char *p);
void ssl3_init_finished_mac(SSL *s);
int ssl3_send_server_certificate(SSL *s);
int ssl3_get_finished(SSL *s,int state_a,int state_b);
int ssl3_setup_key_block(SSL *s);
int ssl3_send_change_cipher_spec(SSL *s,int state_a,int state_b);
int ssl3_change_cipher_state(SSL *s,int which);
void ssl3_cleanup_key_block(SSL *s);
int ssl3_do_write(SSL *s,int type);
void ssl3_send_alert(SSL *s,int level, int desc);
int ssl3_generate_master_secret(SSL *s, unsigned char *out,
	unsigned char *p, int len);
int ssl3_get_req_cert_type(SSL *s,unsigned char *p);
long ssl3_get_message(SSL *s, int st1, int stn, int mt, long max, int *ok);
int ssl3_send_finished(SSL *s, int a, int b, unsigned char *sender,int slen);
int ssl3_num_ciphers(void);
SSL_CIPHER *ssl3_get_cipher(unsigned int u);
int ssl3_renegotiate(SSL *ssl); 
int ssl3_renegotiate_check(SSL *ssl); 
int ssl3_dispatch_alert(SSL *s);
int ssl3_read_bytes(SSL *s, int type, char *buf, int len);
int ssl3_part_read(SSL *s, int i);
int ssl3_write_bytes(SSL *s, int type, char *buf, int len);
int ssl3_final_finish_mac(SSL *s, EVP_MD_CTX *ctx1,EVP_MD_CTX *ctx2,
	unsigned char *sender, int slen,unsigned char *p);
int ssl3_cert_verify_mac(SSL *s, EVP_MD_CTX *in, unsigned char *p);
void ssl3_finish_mac(SSL *s, unsigned char *buf, int len);
int ssl3_enc(SSL *s, int send_data);
int ssl3_mac(SSL *ssl, unsigned char *md, int send_data);
unsigned long ssl3_output_cert_chain(SSL *s, X509 *x);
SSL_CIPHER *ssl3_choose_cipher(SSL *ssl,STACK *have,STACK *pref);
int	ssl3_setup_buffers(SSL *s);
int	ssl3_new(SSL *s);
void	ssl3_free(SSL *s);
int	ssl3_accept(SSL *s);
int	ssl3_connect(SSL *s);
int	ssl3_read(SSL *s, char *buf, int len);
int	ssl3_peek(SSL *s,char *buf, int len);
int	ssl3_write(SSL *s, char *buf, int len);
int	ssl3_shutdown(SSL *s);
void	ssl3_clear(SSL *s);
long	ssl3_ctrl(SSL *s,int cmd, long larg, char *parg);
long	ssl3_ctx_ctrl(SSL_CTX *s,int cmd, long larg, char *parg);
int	ssl3_pending(SSL *s);

int ssl23_accept(SSL *s);
int ssl23_connect(SSL *s);
int ssl23_read_bytes(SSL *s, int n);
int ssl23_write_bytes(SSL *s);

int tls1_new(SSL *s);
void tls1_free(SSL *s);
void tls1_clear(SSL *s);
long tls1_ctrl(SSL *s,int cmd, long larg, char *parg);
SSL_METHOD *tlsv1_base_method(void );


int ssl_init_wbio_buffer(SSL *s, int push);

int tls1_change_cipher_state(SSL *s, int which);
int tls1_setup_key_block(SSL *s);
int tls1_enc(SSL *s, int snd);
int tls1_final_finish_mac(SSL *s, EVP_MD_CTX *in1_ctx, EVP_MD_CTX *in2_ctx,
	unsigned char *str, int slen, unsigned char *p);
int tls1_cert_verify_mac(SSL *s, EVP_MD_CTX *in, unsigned char *p);
int tls1_mac(SSL *ssl, unsigned char *md, int snd);
int tls1_generate_master_secret(SSL *s, unsigned char *out,
	unsigned char *p, int len);
int tls1_alert_code(int code);
int ssl3_alert_code(int code);


#else

SSL_METHOD *ssl_bad_method();
SSL_METHOD *sslv2_base_method();
SSL_METHOD *sslv23_base_method();
SSL_METHOD *sslv3_base_method();

void ssl_clear_cipher_ctx();
int ssl_clear_bad_session();
CERT *ssl_cert_new();
void ssl_cert_free();
int ssl_set_cert_type();
int ssl_get_new_session();
int ssl_get_prev_session();
int ssl_cipher_id_cmp();
int ssl_cipher_ptr_id_cmp();
STACK *ssl_bytes_to_cipher_list();
int ssl_cipher_list_to_bytes();
STACK *ssl_create_cipher_list();
void ssl_update_cache();
int ssl_session_get_ciphers();
int ssl_verify_cert_chain();
int ssl_undefined_function();
X509 *ssl_get_server_send_cert();
EVP_PKEY *ssl_get_sign_pkey();
int ssl_cert_type();
void ssl_set_cert_masks();
STACK *ssl_get_ciphers_by_id();
int ssl_verify_alarm_type();

int ssl2_enc_init();
void ssl2_generate_key_material();
void ssl2_enc();
void ssl2_mac();
SSL_CIPHER *ssl2_get_cipher_by_char();
int ssl2_put_cipher_by_char();
int ssl2_part_read();
int ssl2_do_write();
int ssl2_set_certificate();
void ssl2_return_error();
void ssl2_write_error();
int ssl2_num_ciphers();
SSL_CIPHER *ssl2_get_cipher();
int	ssl2_new();
void	ssl2_free();
int	ssl2_accept();
int	ssl2_connect();
int	ssl2_read();
int	ssl2_peek();
int	ssl2_write();
int	ssl2_shutdown();
void	ssl2_clear();
long	ssl2_ctrl();
long	ssl2_ctx_ctrl();
int	ssl2_pending();

SSL_CIPHER *ssl3_get_cipher_by_char();
int ssl3_put_cipher_by_char();
void ssl3_init_finished_mac();
int ssl3_send_server_certificate();
int ssl3_get_finished();
int ssl3_setup_key_block();
int ssl3_send_change_cipher_spec();
int ssl3_change_cipher_state();
void ssl3_cleanup_key_block();
int ssl3_do_write();
void ssl3_send_alert();
int ssl3_generate_master_secret();
int ssl3_get_req_cert_type();
long ssl3_get_message();
int ssl3_send_finished();
int ssl3_num_ciphers();
SSL_CIPHER *ssl3_get_cipher();
int ssl3_renegotiate();
int ssl3_renegotiate_check();
int ssl3_dispatch_alert();
int ssl3_read_bytes();
int ssl3_part_read();
int ssl3_write_bytes();
int ssl3_final_finish_mac();
void ssl3_finish_mac();
int ssl3_enc();
int ssl3_mac();
unsigned long ssl3_output_cert_chain();
SSL_CIPHER *ssl3_choose_cipher();
int	ssl3_setup_buffers();
int	ssl3_new();
void	ssl3_free();
int	ssl3_accept();
int	ssl3_connect();
int	ssl3_read();
int	ssl3_peek();
int	ssl3_write();
int	ssl3_shutdown();
void	ssl3_clear();
long	ssl3_ctrl();
long	ssl3_ctx_ctrl();
int	ssl3_pending();

int ssl23_accept();
int ssl23_connect();
int ssl23_read_bytes();
int ssl23_write_bytes();

int ssl_init_wbio_buffer();

#endif

#endif
