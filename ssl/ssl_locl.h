/* $OpenBSD: ssl_locl.h,v 1.58 2014/07/10 10:09:54 jsing Exp $ */
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
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by 
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#ifndef HEADER_SSL_LOCL_H
#define HEADER_SSL_LOCL_H

#include <sys/types.h>

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/opensslconf.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/stack.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

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

#define l2n8(l,c)	(*((c)++)=(unsigned char)(((l)>>56)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>48)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>40)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>32)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24)&0xff), \
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

#define n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| \
			    (((unsigned int)(c[1]))    )),c+=2)
#define s2n(s,c)	((c[0]=(unsigned char)(((s)>> 8)&0xff), \
			  c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

#define n2l3(c,l)	((l =(((unsigned long)(c[0]))<<16)| \
			     (((unsigned long)(c[1]))<< 8)| \
			     (((unsigned long)(c[2]))    )),c+=3)

#define l2n3(l,c)	((c[0]=(unsigned char)(((l)>>16)&0xff), \
			  c[1]=(unsigned char)(((l)>> 8)&0xff), \
			  c[2]=(unsigned char)(((l)    )&0xff)),c+=3)

/* LOCAL STUFF */

#define SSL_DECRYPT	0
#define SSL_ENCRYPT	1

/*
 * Define the Bitmasks for SSL_CIPHER.algorithms.
 * This bits are used packed as dense as possible. If new methods/ciphers
 * etc will be added, the bits a likely to change, so this information
 * is for internal library use only, even though SSL_CIPHER.algorithms
 * can be publicly accessed.
 * Use the according functions for cipher management instead.
 *
 * The bit mask handling in the selection and sorting scheme in
 * ssl_create_cipher_list() has only limited capabilities, reflecting
 * that the different entities within are mutually exclusive:
 * ONLY ONE BIT PER MASK CAN BE SET AT A TIME.
 */

/* Bits for algorithm_mkey (key exchange algorithm) */
#define SSL_kRSA		0x00000001L /* RSA key exchange */
#define SSL_kDHr		0x00000002L /* DH cert, RSA CA cert */ /* no such ciphersuites supported! */
#define SSL_kDHd		0x00000004L /* DH cert, DSA CA cert */ /* no such ciphersuite supported! */
#define SSL_kEDH		0x00000008L /* tmp DH key no DH cert */
#define SSL_kKRB5		0x00000010L /* Kerberos5 key exchange */
#define SSL_kECDHr		0x00000020L /* ECDH cert, RSA CA cert */
#define SSL_kECDHe		0x00000040L /* ECDH cert, ECDSA CA cert */
#define SSL_kEECDH		0x00000080L /* ephemeral ECDH */
#define SSL_kPSK		0x00000100L /* PSK */
#define SSL_kGOST       0x00000200L /* GOST key exchange */
#define SSL_kSRP        0x00000400L /* SRP */

/* Bits for algorithm_auth (server authentication) */
#define SSL_aRSA		0x00000001L /* RSA auth */
#define SSL_aDSS 		0x00000002L /* DSS auth */
#define SSL_aNULL 		0x00000004L /* no auth (i.e. use ADH or AECDH) */
#define SSL_aDH 		0x00000008L /* Fixed DH auth (kDHd or kDHr) */ /* no such ciphersuites supported! */
#define SSL_aECDH 		0x00000010L /* Fixed ECDH auth (kECDHe or kECDHr) */
#define SSL_aKRB5               0x00000020L /* KRB5 auth */
#define SSL_aECDSA              0x00000040L /* ECDSA auth*/
#define SSL_aPSK                0x00000080L /* PSK auth */
#define SSL_aGOST94				0x00000100L /* GOST R 34.10-94 signature auth */
#define SSL_aGOST01 			0x00000200L /* GOST R 34.10-2001 signature auth */


/* Bits for algorithm_enc (symmetric encryption) */
#define SSL_DES			0x00000001L
#define SSL_3DES		0x00000002L
#define SSL_RC4			0x00000004L
#define SSL_RC2			0x00000008L
#define SSL_IDEA		0x00000010L
#define SSL_eNULL		0x00000020L
#define SSL_AES128		0x00000040L
#define SSL_AES256		0x00000080L
#define SSL_CAMELLIA128		0x00000100L
#define SSL_CAMELLIA256		0x00000200L
#define SSL_eGOST2814789CNT	0x00000400L
#define SSL_SEED		0x00000800L
#define SSL_AES128GCM		0x00001000L
#define SSL_AES256GCM		0x00002000L
#define SSL_CHACHA20POLY1305	0x00004000L

#define SSL_AES        		(SSL_AES128|SSL_AES256|SSL_AES128GCM|SSL_AES256GCM)
#define SSL_CAMELLIA		(SSL_CAMELLIA128|SSL_CAMELLIA256)


/* Bits for algorithm_mac (symmetric authentication) */

#define SSL_MD5			0x00000001L
#define SSL_SHA1		0x00000002L
#define SSL_GOST94      0x00000004L
#define SSL_GOST89MAC   0x00000008L
#define SSL_SHA256		0x00000010L
#define SSL_SHA384		0x00000020L
/* Not a real MAC, just an indication it is part of cipher */
#define SSL_AEAD		0x00000040L

/* Bits for algorithm_ssl (protocol version) */
#define SSL_SSLV2		0x00000001L
#define SSL_SSLV3		0x00000002L
#define SSL_TLSV1		SSL_SSLV3	/* for now */
#define SSL_TLSV1_2		0x00000004L


/* Bits for algorithm2 (handshake digests and other extra flags) */

#define SSL_HANDSHAKE_MAC_MD5 0x10
#define SSL_HANDSHAKE_MAC_SHA 0x20
#define SSL_HANDSHAKE_MAC_GOST94 0x40
#define SSL_HANDSHAKE_MAC_SHA256 0x80
#define SSL_HANDSHAKE_MAC_SHA384 0x100
#define SSL_HANDSHAKE_MAC_DEFAULT (SSL_HANDSHAKE_MAC_MD5 | SSL_HANDSHAKE_MAC_SHA)

/* When adding new digest in the ssl_ciph.c and increment SSM_MD_NUM_IDX
 * make sure to update this constant too */
#define SSL_MAX_DIGEST 6

#define TLS1_PRF_DGST_MASK	(0xff << TLS1_PRF_DGST_SHIFT)

#define TLS1_PRF_DGST_SHIFT 10
#define TLS1_PRF_MD5 (SSL_HANDSHAKE_MAC_MD5 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA1 (SSL_HANDSHAKE_MAC_SHA << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA256 (SSL_HANDSHAKE_MAC_SHA256 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA384 (SSL_HANDSHAKE_MAC_SHA384 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_GOST94 (SSL_HANDSHAKE_MAC_GOST94 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF (TLS1_PRF_MD5 | TLS1_PRF_SHA1)

/* Stream MAC for GOST ciphersuites from cryptopro draft
 * (currently this also goes into algorithm2) */
#define TLS1_STREAM_MAC 0x04

/*
 * SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD is an algorithm2 flag that
 * indicates that the variable part of the nonce is included as a prefix of
 * the record (AES-GCM, for example, does this with an 8-byte variable nonce.)
 */
#define SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD (1 << 22)
 
/*
 * SSL_CIPHER_ALGORITHM2_AEAD is an algorithm2 flag that indicates the cipher
 * is implemented via an EVP_AEAD.
 */
#define SSL_CIPHER_ALGORITHM2_AEAD (1 << 23)

/*
 * SSL_CIPHER_AEAD_FIXED_NONCE_LEN returns the number of bytes of fixed nonce
 * for an SSL_CIPHER with the SSL_CIPHER_ALGORITHM2_AEAD flag.
 */
#define SSL_CIPHER_AEAD_FIXED_NONCE_LEN(ssl_cipher) \
	(((ssl_cipher->algorithm2 >> 24) & 0xf) * 2)

/*
 * Cipher strength information.
 */
#define SSL_STRONG_MASK		0x000001fcL
#define SSL_STRONG_NONE		0x00000004L
#define SSL_LOW			0x00000020L
#define SSL_MEDIUM		0x00000040L
#define SSL_HIGH		0x00000080L

/* Check if an SSL structure is using DTLS. */
#define SSL_IS_DTLS(s) (s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_DTLS)

/* See if we need explicit IV. */
#define SSL_USE_EXPLICIT_IV(s) \
	(s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_EXPLICIT_IV)

/* See if we use signature algorithms extension. */
#define SSL_USE_SIGALGS(s) \
	(s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_SIGALGS)

/* Allow TLS 1.2 ciphersuites: applies to DTLS 1.2 as well as TLS 1.2. */
#define SSL_USE_TLS1_2_CIPHERS(s) \
	(s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_TLS1_2_CIPHERS)

/* Mostly for SSLv3 */
#define SSL_PKEY_RSA_ENC	0
#define SSL_PKEY_RSA_SIGN	1
#define SSL_PKEY_DSA_SIGN	2
#define SSL_PKEY_DH_RSA		3
#define SSL_PKEY_DH_DSA		4
#define SSL_PKEY_ECC            5
#define SSL_PKEY_GOST94		6
#define SSL_PKEY_GOST01		7
#define SSL_PKEY_NUM		8

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

/* From ECC-TLS draft, used in encoding the curve type in 
 * ECParameters
 */
#define EXPLICIT_PRIME_CURVE_TYPE  1   
#define EXPLICIT_CHAR2_CURVE_TYPE  2
#define NAMED_CURVE_TYPE           3

typedef struct cert_pkey_st {
	X509 *x509;
	EVP_PKEY *privatekey;
	/* Digest to use when signing */
	const EVP_MD *digest;
} CERT_PKEY;

typedef struct cert_st {
	/* Current active set */
	CERT_PKEY *key; /* ALWAYS points to an element of the pkeys array
			 * Probably it would make more sense to store
			 * an index, not a pointer. */

	/* The following masks are for the key and auth
	 * algorithms that are supported by the certs below */
	int valid;
	unsigned long mask_k;
	unsigned long mask_a;
	RSA *rsa_tmp;
	RSA *(*rsa_tmp_cb)(SSL *ssl, int is_export, int keysize);
	DH *dh_tmp;
	DH *(*dh_tmp_cb)(SSL *ssl, int is_export, int keysize);
	EC_KEY *ecdh_tmp;
	/* Callback for generating ephemeral ECDH keys */
	EC_KEY *(*ecdh_tmp_cb)(SSL *ssl, int is_export, int keysize);

	CERT_PKEY pkeys[SSL_PKEY_NUM];

	int references; /* >1 only if SSL_copy_session_id is used */
} CERT;


typedef struct sess_cert_st {
	STACK_OF(X509) *cert_chain; /* as received from peer */

	/* The 'peer_...' members are used only by clients. */
	int peer_cert_type;

	CERT_PKEY *peer_key; /* points to an element of peer_pkeys (never NULL!) */
	CERT_PKEY peer_pkeys[SSL_PKEY_NUM];
	/* Obviously we don't have the private keys of these,
	 * so maybe we shouldn't even use the CERT_PKEY type here. */

	RSA *peer_rsa_tmp;
	DH *peer_dh_tmp;
	EC_KEY *peer_ecdh_tmp;

	int references; /* actually always 1 at the moment */
} SESS_CERT;


/*#define SSL_DEBUG	*/
/*#define RSA_DEBUG	*/ 

#define ssl_put_cipher_by_char(ssl,ciph,ptr) \
		((ssl)->method->put_cipher_by_char((ciph),(ptr)))
#define ssl_get_cipher_by_char(ssl,ptr) \
		((ssl)->method->get_cipher_by_char(ptr))

/* This is for the SSLv3/TLSv1.0 differences in crypto/hash stuff
 * It is a bit of a mess of functions, but hell, think of it as
 * an opaque structure :-) */
typedef struct ssl3_enc_method {
	int (*enc)(SSL *, int);
	int (*mac)(SSL *, unsigned char *, int);
	int (*setup_key_block)(SSL *);
	int (*generate_master_secret)(SSL *, unsigned char *,
	    unsigned char *, int);
	int (*change_cipher_state)(SSL *, int);
	int (*final_finish_mac)(SSL *,  const char *, int, unsigned char *);
	int finish_mac_length;
	int (*cert_verify_mac)(SSL *, int, unsigned char *);
	const char *client_finished_label;
	int client_finished_label_len;
	const char *server_finished_label;
	int server_finished_label_len;
	int (*alert_value)(int);
	int (*export_keying_material)(SSL *, unsigned char *, size_t,
	    const char *, size_t, const unsigned char *, size_t,
	    int use_context);
	/* Flags indicating protocol version requirements. */
	unsigned int enc_flags;
} SSL3_ENC_METHOD;

/*
 * Flag values for enc_flags.
 */

/* Uses explicit IV. */
#define SSL_ENC_FLAG_EXPLICIT_IV        (1 << 0)

/* Uses signature algorithms extension. */
#define SSL_ENC_FLAG_SIGALGS            (1 << 1)

/* Uses SHA256 default PRF. */
#define SSL_ENC_FLAG_SHA256_PRF         (1 << 2)

/* Is DTLS. */
#define SSL_ENC_FLAG_DTLS               (1 << 3)

/* Allow TLS 1.2 ciphersuites: applies to DTLS 1.2 as well as TLS 1.2. */
#define SSL_ENC_FLAG_TLS1_2_CIPHERS     (1 << 4)

/*
 * ssl_aead_ctx_st contains information about an AEAD that is being used to
 * encrypt an SSL connection.
 */
struct ssl_aead_ctx_st {
	EVP_AEAD_CTX ctx;
	/*
	 * fixed_nonce contains any bytes of the nonce that are fixed for all
	 * records.
	 */
	unsigned char fixed_nonce[8];
	unsigned char fixed_nonce_len;
	unsigned char variable_nonce_len;
	unsigned char tag_len;
	/*
	 * variable_nonce_in_record is non-zero if the variable nonce
	 * for a record is included as a prefix before the ciphertext.
	 */
	char variable_nonce_in_record;
};

extern SSL3_ENC_METHOD ssl3_undef_enc_method;
extern SSL_CIPHER ssl3_ciphers[];

SSL_METHOD *ssl_bad_method(int ver);

extern SSL3_ENC_METHOD TLSv1_enc_data;
extern SSL3_ENC_METHOD TLSv1_1_enc_data;
extern SSL3_ENC_METHOD TLSv1_2_enc_data;
extern SSL3_ENC_METHOD SSLv3_enc_data;
extern SSL3_ENC_METHOD DTLSv1_enc_data;

void ssl_clear_cipher_ctx(SSL *s);
int ssl_clear_bad_session(SSL *s);
CERT *ssl_cert_new(void);
CERT *ssl_cert_dup(CERT *cert);
int ssl_cert_inst(CERT **o);
void ssl_cert_free(CERT *c);
SESS_CERT *ssl_sess_cert_new(void);
void ssl_sess_cert_free(SESS_CERT *sc);
int ssl_set_peer_cert_type(SESS_CERT *c, int type);
int ssl_get_new_session(SSL *s, int session);
int ssl_get_prev_session(SSL *s, unsigned char *session, int len,
    const unsigned char *limit);
int ssl_cipher_id_cmp(const SSL_CIPHER *a, const SSL_CIPHER *b);
DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN(SSL_CIPHER, SSL_CIPHER, ssl_cipher_id);
int ssl_cipher_ptr_id_cmp(const SSL_CIPHER * const *ap,
    const SSL_CIPHER * const *bp);
STACK_OF(SSL_CIPHER) *ssl_bytes_to_cipher_list(SSL *s, unsigned char *p,
    int num, STACK_OF(SSL_CIPHER) **skp);
int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk,
    unsigned char *p, int (*put_cb)(const SSL_CIPHER *, unsigned char *));
STACK_OF(SSL_CIPHER) *ssl_create_cipher_list(const SSL_METHOD *meth,
    STACK_OF(SSL_CIPHER) **pref, STACK_OF(SSL_CIPHER) **sorted,
    const char *rule_str);
void ssl_update_cache(SSL *s, int mode);
int ssl_cipher_get_evp(const SSL_SESSION *s, const EVP_CIPHER **enc,
    const EVP_MD **md, int *mac_pkey_type, int *mac_secret_size);
int ssl_cipher_get_evp_aead(const SSL_SESSION *s, const EVP_AEAD **aead);
int ssl_get_handshake_digest(int i, long *mask, const EVP_MD **md);

int ssl_verify_cert_chain(SSL *s, STACK_OF(X509) *sk);
int ssl_undefined_function(SSL *s);
int ssl_undefined_void_function(void);
int ssl_undefined_const_function(const SSL *s);
CERT_PKEY *ssl_get_server_send_pkey(const SSL *s);
X509 *ssl_get_server_send_cert(const SSL *);
EVP_PKEY *ssl_get_sign_pkey(SSL *s, const SSL_CIPHER *c, const EVP_MD **pmd);
int ssl_cert_type(X509 *x, EVP_PKEY *pkey);
void ssl_set_cert_masks(CERT *c, const SSL_CIPHER *cipher);
STACK_OF(SSL_CIPHER) *ssl_get_ciphers_by_id(SSL *s);
int ssl_verify_alarm_type(long type);
void ssl_load_ciphers(void);

const SSL_CIPHER *ssl3_get_cipher_by_char(const unsigned char *p);
int ssl3_put_cipher_by_char(const SSL_CIPHER *c, unsigned char *p);
void ssl3_init_finished_mac(SSL *s);
int ssl3_send_server_certificate(SSL *s);
int ssl3_send_newsession_ticket(SSL *s);
int ssl3_send_cert_status(SSL *s);
int ssl3_get_finished(SSL *s, int state_a, int state_b);
int ssl3_setup_key_block(SSL *s);
int ssl3_send_change_cipher_spec(SSL *s, int state_a, int state_b);
int ssl3_change_cipher_state(SSL *s, int which);
void ssl3_cleanup_key_block(SSL *s);
int ssl3_do_write(SSL *s, int type);
int ssl3_send_alert(SSL *s, int level, int desc);
int ssl3_generate_master_secret(SSL *s, unsigned char *out,
    unsigned char *p, int len);
int ssl3_get_req_cert_type(SSL *s, unsigned char *p);
long ssl3_get_message(SSL *s, int st1, int stn, int mt, long max, int *ok);
int ssl3_send_finished(SSL *s, int a, int b, const char *sender, int slen);
int ssl3_num_ciphers(void);
const SSL_CIPHER *ssl3_get_cipher(unsigned int u);
int ssl3_renegotiate(SSL *ssl);

int ssl3_renegotiate_check(SSL *ssl);

int ssl3_dispatch_alert(SSL *s);
int ssl3_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek);
int ssl3_write_bytes(SSL *s, int type, const void *buf, int len);
int ssl3_final_finish_mac(SSL *s, const char *sender, int slen,
    unsigned char *p);
int ssl3_cert_verify_mac(SSL *s, int md_nid, unsigned char *p);
void ssl3_finish_mac(SSL *s, const unsigned char *buf, int len);
int ssl3_enc(SSL *s, int send_data);
int n_ssl3_mac(SSL *ssl, unsigned char *md, int send_data);
void ssl3_free_digest_list(SSL *s);
unsigned long ssl3_output_cert_chain(SSL *s, X509 *x);
SSL_CIPHER *ssl3_choose_cipher(SSL *ssl, STACK_OF(SSL_CIPHER) *clnt,
    STACK_OF(SSL_CIPHER) *srvr);
int	ssl3_setup_buffers(SSL *s);
int	ssl3_setup_read_buffer(SSL *s);
int	ssl3_setup_write_buffer(SSL *s);
int	ssl3_release_read_buffer(SSL *s);
int	ssl3_release_write_buffer(SSL *s);
int	ssl3_digest_cached_records(SSL *s);
int	ssl3_new(SSL *s);
void	ssl3_free(SSL *s);
int	ssl3_accept(SSL *s);
int	ssl3_connect(SSL *s);
int	ssl3_read(SSL *s, void *buf, int len);
int	ssl3_peek(SSL *s, void *buf, int len);
int	ssl3_write(SSL *s, const void *buf, int len);
int	ssl3_shutdown(SSL *s);
void	ssl3_clear(SSL *s);
long	ssl3_ctrl(SSL *s, int cmd, long larg, void *parg);
long	ssl3_ctx_ctrl(SSL_CTX *s, int cmd, long larg, void *parg);
long	ssl3_callback_ctrl(SSL *s, int cmd, void (*fp)(void));
long	ssl3_ctx_callback_ctrl(SSL_CTX *s, int cmd, void (*fp)(void));
int	ssl3_pending(const SSL *s);

void ssl3_record_sequence_increment(unsigned char *seq);
int ssl3_do_change_cipher_spec(SSL *ssl);
long ssl3_default_timeout(void);

int ssl23_read(SSL *s, void *buf, int len);
int ssl23_peek(SSL *s, void *buf, int len);
int ssl23_write(SSL *s, const void *buf, int len);
int ssl23_put_cipher_by_char(const SSL_CIPHER *c, unsigned char *p);
long ssl23_default_timeout(void);

long tls1_default_timeout(void);
int dtls1_do_write(SSL *s, int type);
int ssl3_read_n(SSL *s, int n, int max, int extend);
int dtls1_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek);
int ssl3_write_pending(SSL *s, int type, const unsigned char *buf,
    unsigned int len);
unsigned char *dtls1_set_message_header(SSL *s, unsigned char *p,
    unsigned char mt, unsigned long len, unsigned long frag_off,
    unsigned long frag_len);

int dtls1_write_app_data_bytes(SSL *s, int type, const void *buf, int len);
int dtls1_write_bytes(SSL *s, int type, const void *buf, int len);

int dtls1_send_change_cipher_spec(SSL *s, int a, int b);
int dtls1_send_finished(SSL *s, int a, int b, const char *sender, int slen);
unsigned long dtls1_output_cert_chain(SSL *s, X509 *x);
int dtls1_read_failed(SSL *s, int code);
int dtls1_buffer_message(SSL *s, int ccs);
int dtls1_retransmit_message(SSL *s, unsigned short seq,
    unsigned long frag_off, int *found);
int dtls1_get_queue_priority(unsigned short seq, int is_ccs);
int dtls1_retransmit_buffered_messages(SSL *s);
void dtls1_clear_record_buffer(SSL *s);
void dtls1_get_message_header(unsigned char *data,
    struct hm_header_st *msg_hdr);
void dtls1_get_ccs_header(unsigned char *data, struct ccs_header_st *ccs_hdr);
void dtls1_reset_seq_numbers(SSL *s, int rw);
void dtls1_build_sequence_number(unsigned char *dst, unsigned char *seq,
    unsigned short epoch);
long dtls1_default_timeout(void);
struct timeval* dtls1_get_timeout(SSL *s, struct timeval* timeleft);
int dtls1_check_timeout_num(SSL *s);
int dtls1_handle_timeout(SSL *s);
const SSL_CIPHER *dtls1_get_cipher(unsigned int u);
void dtls1_start_timer(SSL *s);
void dtls1_stop_timer(SSL *s);
int dtls1_is_timer_expired(SSL *s);
void dtls1_double_timeout(SSL *s);
int dtls1_send_newsession_ticket(SSL *s);
unsigned int dtls1_min_mtu(void);

/* some client-only functions */
int ssl3_client_hello(SSL *s);
int ssl3_get_server_hello(SSL *s);
int ssl3_get_certificate_request(SSL *s);
int ssl3_get_new_session_ticket(SSL *s);
int ssl3_get_cert_status(SSL *s);
int ssl3_get_server_done(SSL *s);
int ssl3_send_client_verify(SSL *s);
int ssl3_send_client_certificate(SSL *s);
int ssl_do_client_cert_cb(SSL *s, X509 **px509, EVP_PKEY **ppkey);
int ssl3_send_client_key_exchange(SSL *s);
int ssl3_get_key_exchange(SSL *s);
int ssl3_get_server_certificate(SSL *s);
int ssl3_check_cert_and_algorithm(SSL *s);
int ssl3_check_finished(SSL *s);
# ifndef OPENSSL_NO_NEXTPROTONEG
int ssl3_send_next_proto(SSL *s);
# endif

int dtls1_client_hello(SSL *s);
int dtls1_send_client_certificate(SSL *s);
int dtls1_send_client_key_exchange(SSL *s);
int dtls1_send_client_verify(SSL *s);

/* some server-only functions */
int ssl3_get_client_hello(SSL *s);
int ssl3_send_server_hello(SSL *s);
int ssl3_send_hello_request(SSL *s);
int ssl3_send_server_key_exchange(SSL *s);
int ssl3_send_certificate_request(SSL *s);
int ssl3_send_server_done(SSL *s);
int ssl3_check_client_hello(SSL *s);
int ssl3_get_client_certificate(SSL *s);
int ssl3_get_client_key_exchange(SSL *s);
int ssl3_get_cert_verify(SSL *s);
#ifndef OPENSSL_NO_NEXTPROTONEG
int ssl3_get_next_proto(SSL *s);
#endif

int dtls1_send_hello_request(SSL *s);
int dtls1_send_server_hello(SSL *s);
int dtls1_send_server_certificate(SSL *s);
int dtls1_send_server_key_exchange(SSL *s);
int dtls1_send_certificate_request(SSL *s);
int dtls1_send_server_done(SSL *s);

int ssl23_accept(SSL *s);
int ssl23_connect(SSL *s);
int ssl23_read_bytes(SSL *s, int n);
int ssl23_write_bytes(SSL *s);

int tls1_new(SSL *s);
void tls1_free(SSL *s);
void tls1_clear(SSL *s);
long tls1_ctrl(SSL *s, int cmd, long larg, void *parg);
long tls1_callback_ctrl(SSL *s, int cmd, void (*fp)(void));

int dtls1_new(SSL *s);
int dtls1_accept(SSL *s);
int dtls1_connect(SSL *s);
void dtls1_free(SSL *s);
void dtls1_clear(SSL *s);
long dtls1_ctrl(SSL *s, int cmd, long larg, void *parg);
int dtls1_shutdown(SSL *s);

long dtls1_get_message(SSL *s, int st1, int stn, int mt, long max, int *ok);
int dtls1_get_record(SSL *s);
int do_dtls1_write(SSL *s, int type, const unsigned char *buf,
    unsigned int len);
int dtls1_dispatch_alert(SSL *s);
int dtls1_enc(SSL *s, int snd);

int ssl_init_wbio_buffer(SSL *s, int push);
void ssl_free_wbio_buffer(SSL *s);

int tls1_change_cipher_state(SSL *s, int which);
int tls1_setup_key_block(SSL *s);
int tls1_enc(SSL *s, int snd);
int tls1_final_finish_mac(SSL *s, const char *str, int slen, unsigned char *p);
int tls1_cert_verify_mac(SSL *s, int md_nid, unsigned char *p);
int tls1_mac(SSL *ssl, unsigned char *md, int snd);
int tls1_generate_master_secret(SSL *s, unsigned char *out,
    unsigned char *p, int len);
int tls1_export_keying_material(SSL *s, unsigned char *out, size_t olen,
    const char *label, size_t llen, const unsigned char *p, size_t plen,
    int use_context);
int tls1_alert_code(int code);
int ssl3_alert_code(int code);
int ssl_ok(SSL *s);

int ssl_check_srvr_ecc_cert_and_alg(X509 *x, SSL *s);

SSL_COMP *ssl3_comp_find(STACK_OF(SSL_COMP) *sk, int n);

int tls1_ec_curve_id2nid(int curve_id);
int tls1_ec_nid2curve_id(int nid);

unsigned char *ssl_add_clienthello_tlsext(SSL *s, unsigned char *p,
    unsigned char *limit);

unsigned char *ssl_add_serverhello_tlsext(SSL *s, unsigned char *p,
    unsigned char *limit);

int ssl_parse_clienthello_tlsext(SSL *s, unsigned char **data,
    unsigned char *d, int n, int *al);
int ssl_parse_serverhello_tlsext(SSL *s, unsigned char **data,
    unsigned char *d, int n, int *al);
int ssl_prepare_clienthello_tlsext(SSL *s);
int ssl_prepare_serverhello_tlsext(SSL *s);
int ssl_check_clienthello_tlsext_early(SSL *s);
int ssl_check_clienthello_tlsext_late(SSL *s);
int ssl_check_serverhello_tlsext(SSL *s);

#define tlsext_tick_md	EVP_sha256
int tls1_process_ticket(SSL *s, unsigned char *session_id, int len,
    const unsigned char *limit, SSL_SESSION **ret);

int tls12_get_sigandhash(unsigned char *p, const EVP_PKEY *pk,
    const EVP_MD *md);
int tls12_get_sigid(const EVP_PKEY *pk);
const EVP_MD *tls12_get_hash(unsigned char hash_alg);

EVP_MD_CTX* ssl_replace_hash(EVP_MD_CTX **hash, const EVP_MD *md);
void ssl_clear_hash_ctx(EVP_MD_CTX **hash);
int ssl_add_serverhello_renegotiate_ext(SSL *s, unsigned char *p,
    int *len, int maxlen);
int ssl_parse_serverhello_renegotiate_ext(SSL *s, unsigned char *d,
    int len, int *al);
int ssl_add_clienthello_renegotiate_ext(SSL *s, unsigned char *p,
    int *len, int maxlen);
int ssl_parse_clienthello_renegotiate_ext(SSL *s, unsigned char *d,
    int len, int *al);
long ssl_get_algorithm2(SSL *s);
int tls1_process_sigalgs(SSL *s, const unsigned char *data, int dsize);
int tls12_get_req_sig_algs(SSL *s, unsigned char *p);

int ssl_add_clienthello_use_srtp_ext(SSL *s, unsigned char *p,
    int *len, int maxlen);
int ssl_parse_clienthello_use_srtp_ext(SSL *s, unsigned char *d,
    int len, int *al);
int ssl_add_serverhello_use_srtp_ext(SSL *s, unsigned char *p,
    int *len, int maxlen);
int ssl_parse_serverhello_use_srtp_ext(SSL *s, unsigned char *d,
    int len, int *al);

/* s3_cbc.c */
void ssl3_cbc_copy_mac(unsigned char *out, const SSL3_RECORD *rec,
    unsigned md_size, unsigned orig_len);
int ssl3_cbc_remove_padding(const SSL *s, SSL3_RECORD *rec,
    unsigned block_size, unsigned mac_size);
int tls1_cbc_remove_padding(const SSL *s, SSL3_RECORD *rec,
    unsigned block_size, unsigned mac_size);
char ssl3_cbc_record_digest_supported(const EVP_MD_CTX *ctx);
void ssl3_cbc_digest_record(const EVP_MD_CTX *ctx, unsigned char *md_out,
    size_t *md_out_size, const unsigned char header[13],
    const unsigned char *data, size_t data_plus_mac_size,
    size_t data_plus_mac_plus_padding_size, const unsigned char *mac_secret,
    unsigned mac_secret_length, char is_sslv3);

#endif
