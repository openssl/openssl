/* ssl/tls1.h */
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

#ifndef HEADER_TLS1_H 
#define HEADER_TLS1_H 

#include <openssl/buffer.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES	1

#define TLS1_VERSION			0x0301
#define TLS1_VERSION_MAJOR		0x03
#define TLS1_VERSION_MINOR		0x01

#define TLS1_AD_DECRYPTION_FAILED	21
#define TLS1_AD_RECORD_OVERFLOW		22
#define TLS1_AD_UNKNOWN_CA		48	/* fatal */
#define TLS1_AD_ACCESS_DENIED		49	/* fatal */
#define TLS1_AD_DECODE_ERROR		50	/* fatal */
#define TLS1_AD_DECRYPT_ERROR		51
#define TLS1_AD_EXPORT_RESTRICTION	60	/* fatal */
#define TLS1_AD_PROTOCOL_VERSION	70	/* fatal */
#define TLS1_AD_INSUFFICIENT_SECURITY	71	/* fatal */
#define TLS1_AD_INTERNAL_ERROR		80	/* fatal */
#define TLS1_AD_USER_CANCELLED		90
#define TLS1_AD_NO_RENEGOTIATION	100

/* Additional TLS ciphersuites from draft-ietf-tls-56-bit-ciphersuites-00.txt
 * (available if TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES is defined, see
 * s3_lib.c).  We actually treat them like SSL 3.0 ciphers, which we probably
 * shouldn't. */
#define TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5		0x03000060
#define TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5	0x03000061
#define TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA		0x03000062
#define TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA	0x03000063
#define TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA		0x03000064
#define TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA	0x03000065
#define TLS1_CK_DHE_DSS_WITH_RC4_128_SHA		0x03000066

/* AES ciphersuites from RFC3268 */

#define TLS1_CK_RSA_WITH_AES_128_SHA			0x0300002F
#define TLS1_CK_DH_DSS_WITH_AES_128_SHA			0x03000030
#define TLS1_CK_DH_RSA_WITH_AES_128_SHA			0x03000031
#define TLS1_CK_DHE_DSS_WITH_AES_128_SHA		0x03000032
#define TLS1_CK_DHE_RSA_WITH_AES_128_SHA		0x03000033
#define TLS1_CK_ADH_WITH_AES_128_SHA			0x03000034

#define TLS1_CK_RSA_WITH_AES_256_SHA			0x03000035
#define TLS1_CK_DH_DSS_WITH_AES_256_SHA			0x03000036
#define TLS1_CK_DH_RSA_WITH_AES_256_SHA			0x03000037
#define TLS1_CK_DHE_DSS_WITH_AES_256_SHA		0x03000038
#define TLS1_CK_DHE_RSA_WITH_AES_256_SHA		0x03000039
#define TLS1_CK_ADH_WITH_AES_256_SHA			0x0300003A

/* XXX
 * Inconsistency alert:
 * The OpenSSL names of ciphers with ephemeral DH here include the string
 * "DHE", while elsewhere it has always been "EDH".
 * (The alias for the list of all such ciphers also is "EDH".)
 * The specifications speak of "EDH"; maybe we should allow both forms
 * for everything. */
#define TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_MD5		"EXP1024-RC4-MD5"
#define TLS1_TXT_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5	"EXP1024-RC2-CBC-MD5"
#define TLS1_TXT_RSA_EXPORT1024_WITH_DES_CBC_SHA	"EXP1024-DES-CBC-SHA"
#define TLS1_TXT_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA	"EXP1024-DHE-DSS-DES-CBC-SHA"
#define TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_SHA		"EXP1024-RC4-SHA"
#define TLS1_TXT_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA	"EXP1024-DHE-DSS-RC4-SHA"
#define TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA		"DHE-DSS-RC4-SHA"

/* AES ciphersuites from RFC3268 */
#define TLS1_TXT_RSA_WITH_AES_128_SHA			"AES128-SHA"
#define TLS1_TXT_DH_DSS_WITH_AES_128_SHA		"DH-DSS-AES128-SHA"
#define TLS1_TXT_DH_RSA_WITH_AES_128_SHA		"DH-RSA-AES128-SHA"
#define TLS1_TXT_DHE_DSS_WITH_AES_128_SHA		"DHE-DSS-AES128-SHA"
#define TLS1_TXT_DHE_RSA_WITH_AES_128_SHA		"DHE-RSA-AES128-SHA"
#define TLS1_TXT_ADH_WITH_AES_128_SHA			"ADH-AES128-SHA"

#define TLS1_TXT_RSA_WITH_AES_256_SHA			"AES256-SHA"
#define TLS1_TXT_DH_DSS_WITH_AES_256_SHA		"DH-DSS-AES256-SHA"
#define TLS1_TXT_DH_RSA_WITH_AES_256_SHA		"DH-RSA-AES256-SHA"
#define TLS1_TXT_DHE_DSS_WITH_AES_256_SHA		"DHE-DSS-AES256-SHA"
#define TLS1_TXT_DHE_RSA_WITH_AES_256_SHA		"DHE-RSA-AES256-SHA"
#define TLS1_TXT_ADH_WITH_AES_256_SHA			"ADH-AES256-SHA"


#define TLS_CT_RSA_SIGN			1
#define TLS_CT_DSS_SIGN			2
#define TLS_CT_RSA_FIXED_DH		3
#define TLS_CT_DSS_FIXED_DH		4
#define TLS_CT_NUMBER			4

#define TLS1_FINISH_MAC_LENGTH		12

#define TLS_MD_MAX_CONST_SIZE			20
#define TLS_MD_CLIENT_FINISH_CONST		"client finished"
#define TLS_MD_CLIENT_FINISH_CONST_SIZE		15
#define TLS_MD_SERVER_FINISH_CONST		"server finished"
#define TLS_MD_SERVER_FINISH_CONST_SIZE		15
#define TLS_MD_SERVER_WRITE_KEY_CONST		"server write key"
#define TLS_MD_SERVER_WRITE_KEY_CONST_SIZE	16
#define TLS_MD_KEY_EXPANSION_CONST		"key expansion"
#define TLS_MD_KEY_EXPANSION_CONST_SIZE		13
#define TLS_MD_CLIENT_WRITE_KEY_CONST		"client write key"
#define TLS_MD_CLIENT_WRITE_KEY_CONST_SIZE	16
#define TLS_MD_SERVER_WRITE_KEY_CONST		"server write key"
#define TLS_MD_SERVER_WRITE_KEY_CONST_SIZE	16
#define TLS_MD_IV_BLOCK_CONST			"IV block"
#define TLS_MD_IV_BLOCK_CONST_SIZE		8
#define TLS_MD_MASTER_SECRET_CONST		"master secret"
#define TLS_MD_MASTER_SECRET_CONST_SIZE		13

#ifdef CHARSET_EBCDIC
#undef TLS_MD_CLIENT_FINISH_CONST
#define TLS_MD_CLIENT_FINISH_CONST    "\x63\x6c\x69\x65\x6e\x74\x20\x66\x69\x6e\x69\x73\x68\x65\x64"  /*client finished*/
#undef TLS_MD_SERVER_FINISH_CONST
#define TLS_MD_SERVER_FINISH_CONST    "\x73\x65\x72\x76\x65\x72\x20\x66\x69\x6e\x69\x73\x68\x65\x64"  /*server finished*/
#undef TLS_MD_SERVER_WRITE_KEY_CONST
#define TLS_MD_SERVER_WRITE_KEY_CONST "\x73\x65\x72\x76\x65\x72\x20\x77\x72\x69\x74\x65\x20\x6b\x65\x79"  /*server write key*/
#undef TLS_MD_KEY_EXPANSION_CONST
#define TLS_MD_KEY_EXPANSION_CONST    "\x6b\x65\x79\x20\x65\x78\x70\x61\x6e\x73\x69\x6f\x6e"  /*key expansion*/
#undef TLS_MD_CLIENT_WRITE_KEY_CONST
#define TLS_MD_CLIENT_WRITE_KEY_CONST "\x63\x6c\x69\x65\x6e\x74\x20\x77\x72\x69\x74\x65\x20\x6b\x65\x79"  /*client write key*/
#undef TLS_MD_SERVER_WRITE_KEY_CONST
#define TLS_MD_SERVER_WRITE_KEY_CONST "\x73\x65\x72\x76\x65\x72\x20\x77\x72\x69\x74\x65\x20\x6b\x65\x79"  /*server write key*/
#undef TLS_MD_IV_BLOCK_CONST
#define TLS_MD_IV_BLOCK_CONST         "\x49\x56\x20\x62\x6c\x6f\x63\x6b"  /*IV block*/
#undef TLS_MD_MASTER_SECRET_CONST
#define TLS_MD_MASTER_SECRET_CONST    "\x6d\x61\x73\x74\x65\x72\x20\x73\x65\x63\x72\x65\x74"  /*master secret*/
#endif

#ifdef  __cplusplus
}
#endif
#endif

