/* rsaref/rsaref.h */
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

#ifndef HEADER_RSAREF_H
#define HEADER_RSAREF_H

#ifndef NO_RSA
#include <openssl/rsa.h>

#ifdef __cplusplus
extern "C" {
#endif
 
/* RSAeuro */
/*#define  RSAref_MAX_BITS		2048*/

/* RSAref */
#define  RSAref_MAX_BITS		1024

#define RSAref_MIN_BITS		508
#define RSAref_MAX_LEN		((RSAref_MAX_BITS+7)/8)
#define RSAref_MAX_PBITS	(RSAref_MAX_BITS+1)/2
#define RSAref_MAX_PLEN		((RSAref_MAX_PBITS+7)/8)

typedef struct RSArefPublicKey_st
	{
	unsigned int bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
	} RSArefPublicKey;

typedef struct RSArefPrivateKey_st
	{
	unsigned int bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
	unsigned char d[RSAref_MAX_LEN];
	unsigned char prime[2][RSAref_MAX_PLEN];/* p & q */
	unsigned char pexp[2][RSAref_MAX_PLEN];	/* dmp1 & dmq1 */
	unsigned char coef[RSAref_MAX_PLEN];	/* iqmp */
	} RSArefPrivateKey;

typedef struct RSARandomState_st
	{
	unsigned int needed;
	unsigned char state[16];
	unsigned int outputnum;
	unsigned char output[16];
	} RSARandomState;

#define RE_CONTENT_ENCODING 0x0400
#define RE_DATA 0x0401
#define RE_DIGEST_ALGORITHM 0x0402
#define RE_ENCODING 0x0403
#define RE_KEY 0x0404
#define RE_KEY_ENCODING 0x0405
#define RE_LEN 0x0406
#define RE_MODULUS_LEN 0x0407
#define RE_NEED_RANDOM 0x0408
#define RE_PRIVATE_KEY 0x0409
#define RE_PUBLIC_KEY 0x040a
#define RE_SIGNATURE 0x040b
#define RE_SIGNATURE_ENCODING 0x040c
#define RE_ENCRYPTION_ALGORITHM 0x040d

int RSAPrivateDecrypt(unsigned char *to, int *outlen, unsigned char *from,
	int len, RSArefPrivateKey *RSAkey);
int RSAPrivateEncrypt(unsigned char *to, int *outlen, unsigned char *from,
	int len, RSArefPrivateKey *RSAkey);
int RSAPublicDecrypt(unsigned char *to, int *outlen, unsigned char *from,
	int len, RSArefPublicKey *RSAkey);
int RSAPublicEncrypt(unsigned char *to, int *outlen, unsigned char *from,
	int len, RSArefPublicKey *RSAkey,RSARandomState *rnd);
int R_RandomInit(RSARandomState *rnd);
int R_GetRandomBytesNeeded(unsigned int *,RSARandomState *rnd);
int R_RandomUpdate(RSARandomState *rnd, unsigned char *data, unsigned int n);
int R_RandomFinal(RSARandomState *rnd);

void ERR_load_RSAREF_strings(void );
RSA_METHOD *RSA_PKCS1_RSAref(void );

#ifdef  __cplusplus
}
#endif
#endif

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

/* Error codes for the RSAREF functions. */

/* Function codes. */
#define RSAREF_F_BN_REF_MOD_EXP				 100
#define RSAREF_F_RSAREF_BN2BIN				 101
#define RSAREF_F_RSA_BN2BIN				 102
#define RSAREF_F_RSA_PRIVATE_DECRYPT			 103
#define RSAREF_F_RSA_PRIVATE_ENCRYPT			 104
#define RSAREF_F_RSA_PUBLIC_DECRYPT			 105
#define RSAREF_F_RSA_PUBLIC_ENCRYPT			 106
#define RSAREF_F_RSA_REF_BN2BIN				 107
#define RSAREF_F_RSA_REF_MOD_EXP			 108
#define RSAREF_F_RSA_REF_PRIVATE_DECRYPT		 109
#define RSAREF_F_RSA_REF_PRIVATE_ENCRYPT		 110
#define RSAREF_F_RSA_REF_PUBLIC_DECRYPT			 111
#define RSAREF_F_RSA_REF_PUBLIC_ENCRYPT			 112

/* Reason codes. */
#define RSAREF_R_CONTENT_ENCODING			 0x0400
#define RSAREF_R_DATA					 0x0401
#define RSAREF_R_DIGEST_ALGORITHM			 0x0402
#define RSAREF_R_ENCODING				 0x0403
#define RSAREF_R_ENCRYPTION_ALGORITHM			 0x040d
#define RSAREF_R_KEY					 0x0404
#define RSAREF_R_KEY_ENCODING				 0x0405
#define RSAREF_R_LEN					 0x0406
#define RSAREF_R_MODULUS_LEN				 0x0407
#define RSAREF_R_NEED_RANDOM				 0x0408
#define RSAREF_R_PRIVATE_KEY				 0x0409
#define RSAREF_R_PUBLIC_KEY				 0x040a
#define RSAREF_R_SIGNATURE				 0x040b
#define RSAREF_R_SIGNATURE_ENCODING			 0x040c

#endif
