/* crypto/des/des_old.h -*- mode:C; c-file-style: "eay" -*- */

/* WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 * The function names in here are deprecated and are only present to
 * provide an interface compatible with libdes.  OpenSSL now provides
 * functions where "des_" has been replaced with "DES_" in the names,
 * to make it possible to make incompatible changes that are needed
 * for C type security and other stuff.
 *
 * Please consider starting to use the DES_ functions rather than the
 * des_ ones.  The des_ functions will dissapear completely before
 * OpenSSL 1.0!
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 */

/* Written by Richard Levitte (richard@levitte.org) for the OpenSSL
 * project 2001.
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#ifndef HEADER_DES_OLD_H
#define HEADER_DES_OLD_H

#ifdef OPENSSL_NO_DES
#error DES is disabled.
#endif

#ifdef _KERBEROS_DES_H
#error <openssl/des_old.h> replaces <kerberos/des.h>.
#endif

#include <openssl/opensslconf.h> /* DES_LONG */
#include <openssl/e_os2.h>	/* OPENSSL_EXTERN */
#include <openssl/symhacks.h>

#ifdef OPENSSL_BUILD_SHLIBCRYPTO
# undef OPENSSL_EXTERN
# define OPENSSL_EXTERN OPENSSL_EXPORT
#endif

#ifdef  __cplusplus
extern "C" {
#endif

typedef unsigned char des_cblock[8];
typedef struct des_ks_struct
	{
	union	{
		des_cblock _;
		/* make sure things are correct size on machines with
		 * 8 byte longs */
		DES_LONG pad[2];
		} ks;
	} des_key_schedule[16];

#define des_ecb2_encrypt(i,o,k1,k2,e) \
	des_ecb3_encrypt((i),(o),(k1),(k2),(k1),(e))

#define des_ede2_cbc_encrypt(i,o,l,k1,k2,iv,e) \
	des_ede3_cbc_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(e))

#define des_ede2_cfb64_encrypt(i,o,l,k1,k2,iv,n,e) \
	des_ede3_cfb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n),(e))

#define des_ede2_ofb64_encrypt(i,o,l,k1,k2,iv,n) \
	des_ede3_ofb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n))

#define des_check_key DES_check_key
#define des_rw_mode DES_rw_mode

const char *des_options(void);
void des_ecb3_encrypt(des_cblock *input,des_cblock *output,
	des_key_schedule ks1,des_key_schedule ks2,
	des_key_schedule ks3, int enc);
DES_LONG des_cbc_cksum(des_cblock *input,des_cblock *output,
	long length,des_key_schedule schedule,des_cblock *ivec);
void des_cbc_encrypt(des_cblock *input,des_cblock *output,long length,
	des_key_schedule schedule,des_cblock *ivec,int enc);
void des_ncbc_encrypt(des_cblock *input,des_cblock *output,long length,
	des_key_schedule schedule,des_cblock *ivec,int enc);
void des_xcbc_encrypt(des_cblock *input,des_cblock *output,long length,
	des_key_schedule schedule,des_cblock *ivec,
	des_cblock *inw,des_cblock *outw,int enc);
void des_cfb_encrypt(unsigned char *in,unsigned char *out,int numbits,
	long length,des_key_schedule schedule,des_cblock *ivec,int enc);
void des_ecb_encrypt(des_cblock *input,des_cblock *output,
	des_key_schedule ks,int enc);
void des_encrypt(DES_LONG *data,des_key_schedule ks, int enc);
void des_encrypt2(DES_LONG *data,des_key_schedule ks, int enc);
void des_encrypt3(DES_LONG *data, des_key_schedule ks1,
	des_key_schedule ks2, des_key_schedule ks3);
void des_decrypt3(DES_LONG *data, des_key_schedule ks1,
	des_key_schedule ks2, des_key_schedule ks3);
void des_ede3_cbc_encrypt(des_cblock *input, des_cblock *output, 
	long length, des_key_schedule ks1, des_key_schedule ks2, 
	des_key_schedule ks3, des_cblock *ivec, int enc);
void des_ede3_cfb64_encrypt(unsigned char *in, unsigned char *out,
	long length, des_key_schedule ks1, des_key_schedule ks2,
	des_key_schedule ks3, des_cblock *ivec, int *num, int enc);
void des_ede3_ofb64_encrypt(unsigned char *in, unsigned char *out,
	long length, des_key_schedule ks1, des_key_schedule ks2,
	des_key_schedule ks3, des_cblock *ivec, int *num);

void des_xwhite_in2out(des_cblock (*des_key), des_cblock (*in_white),
	des_cblock (*out_white));

int des_enc_read(int fd,char *buf,int len,des_key_schedule sched,
	des_cblock *iv);
int des_enc_write(int fd,char *buf,int len,des_key_schedule sched,
	des_cblock *iv);
char *des_fcrypt(const char *buf,const char *salt, char *ret);
char *des_crypt(const char *buf,const char *salt);
#if !defined(PERL5) && !defined(__FreeBSD__) && !defined(NeXT)
char *crypt(const char *buf,const char *salt);
#endif
void des_ofb_encrypt(unsigned char *in,unsigned char *out,
	int numbits,long length,des_key_schedule schedule,des_cblock *ivec);
void des_pcbc_encrypt(des_cblock *input,des_cblock *output,long length,
	des_key_schedule schedule,des_cblock *ivec,int enc);
DES_LONG des_quad_cksum(des_cblock *input,des_cblock *output,
	long length,int out_count,des_cblock *seed);
void des_random_seed(des_cblock key);
void des_random_key(des_cblock ret);
void des_set_odd_parity(des_cblock *key);
int des_is_weak_key(des_cblock *key);
int des_set_key(des_cblock *key,des_key_schedule schedule);
int des_key_sched(des_cblock *key,des_key_schedule schedule);
void des_string_to_key(char *str,des_cblock *key);
void des_string_to_2keys(char *str,des_cblock *key1,des_cblock *key2);
void des_cfb64_encrypt(unsigned char *in, unsigned char *out, long length,
	des_key_schedule schedule, des_cblock *ivec, int *num, int enc);
void des_ofb64_encrypt(unsigned char *in, unsigned char *out, long length,
	des_key_schedule schedule, des_cblock *ivec, int *num);

/* The following definitions provide compatibility with the MIT Kerberos
 * library. The des_key_schedule structure is not binary compatible. */

#define _KERBEROS_DES_H

#define KRBDES_ENCRYPT DES_ENCRYPT
#define KRBDES_DECRYPT DES_DECRYPT

#ifdef KERBEROS
#  define ENCRYPT DES_ENCRYPT
#  define DECRYPT DES_DECRYPT
#endif

#ifndef NCOMPAT
#  define C_Block des_cblock
#  define Key_schedule des_key_schedule
#  define KEY_SZ DES_KEY_SZ
#  define string_to_key des_string_to_key
#  define read_pw_string des_read_pw_string
#  define random_key des_random_key
#  define pcbc_encrypt des_pcbc_encrypt
#  define set_key des_set_key
#  define key_sched des_key_sched
#  define ecb_encrypt des_ecb_encrypt
#  define cbc_encrypt des_cbc_encrypt
#  define ncbc_encrypt des_ncbc_encrypt
#  define xcbc_encrypt des_xcbc_encrypt
#  define cbc_cksum des_cbc_cksum
#  define quad_cksum des_quad_cksum
#  define check_parity des_check_key_parity
#endif

#define des_fixup_key_parity DES_fixup_key_parity

#ifdef  __cplusplus
}
#endif

#endif
