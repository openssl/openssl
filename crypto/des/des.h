/* crypto/des/des.h */
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

#ifndef HEADER_DES_H
#define HEADER_DES_H

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef NO_DES
#error DES is disabled.
#endif

#ifdef _KERBEROS_DES_H
#error <openssl/des.h> replaces <kerberos/des.h>.
#endif

#include <stdio.h>
#include <openssl/opensslconf.h> /* DES_LONG */
#include <openssl/e_os2.h>	/* OPENSSL_EXTERN */

typedef unsigned char des_cblock[8];
typedef /* const */ unsigned char const_des_cblock[8];
/* With "const", gcc 2.8.1 on Solaris thinks that des_cblock *
 * and const_des_cblock * are incompatible pointer types.
 * I haven't seen that warning on other systems ... I'll look
 * what the standard says. */


typedef struct des_ks_struct
	{
	union	{
		des_cblock cblock;
		/* make sure things are correct size on machines with
		 * 8 byte longs */
		DES_LONG deslong[2];
		} ks;
	int weak_key;
	} des_key_schedule[16];

#define DES_KEY_SZ 	(sizeof(des_cblock))
#define DES_SCHEDULE_SZ (sizeof(des_key_schedule))

#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#define DES_CBC_MODE	0
#define DES_PCBC_MODE	1

#define des_ecb2_encrypt(i,o,k1,k2,e) \
	des_ecb3_encrypt((i),(o),(k1),(k2),(k1),(e))

#define des_ede2_cbc_encrypt(i,o,l,k1,k2,iv,e) \
	des_ede3_cbc_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(e))

#define des_ede2_cfb64_encrypt(i,o,l,k1,k2,iv,n,e) \
	des_ede3_cfb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n),(e))

#define des_ede2_ofb64_encrypt(i,o,l,k1,k2,iv,n) \
	des_ede3_ofb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n))

OPENSSL_EXTERN int des_check_key;	/* defaults to false */
OPENSSL_EXTERN int des_rw_mode;		/* defaults to DES_PCBC_MODE */
OPENSSL_EXTERN int des_set_weak_key_flag; /* set the weak key flag */

const char *des_options(void);
void des_ecb3_encrypt(const_des_cblock *input, des_cblock *output,
		      des_key_schedule ks1,des_key_schedule ks2,
		      des_key_schedule ks3, int enc);
DES_LONG des_cbc_cksum(const unsigned char *input,des_cblock *output,
		       long length,des_key_schedule schedule,
		       const_des_cblock *ivec);
/* des_cbc_encrypt does not update the IV!  Use des_ncbc_encrypt instead. */
void des_cbc_encrypt(const unsigned char *input,unsigned char *output,
		     long length,des_key_schedule schedule,des_cblock *ivec,
		     int enc);
void des_ncbc_encrypt(const unsigned char *input,unsigned char *output,
		      long length,des_key_schedule schedule,des_cblock *ivec,
		      int enc);
void des_xcbc_encrypt(const unsigned char *input,unsigned char *output,
		      long length,des_key_schedule schedule,des_cblock *ivec,
		      const_des_cblock *inw,const_des_cblock *outw,int enc);
void des_cfb_encrypt(const unsigned char *in,unsigned char *out,int numbits,
		     long length,des_key_schedule schedule,des_cblock *ivec,
		     int enc);
void des_ecb_encrypt(const_des_cblock *input,des_cblock *output,
		     des_key_schedule ks,int enc);
void des_encrypt(DES_LONG *data,des_key_schedule ks, int enc);
void des_encrypt2(DES_LONG *data,des_key_schedule ks, int enc);
void des_encrypt3(DES_LONG *data, des_key_schedule ks1,
	des_key_schedule ks2, des_key_schedule ks3);
void des_decrypt3(DES_LONG *data, des_key_schedule ks1,
	des_key_schedule ks2, des_key_schedule ks3);
void des_ede3_cbc_encrypt(const unsigned char *input,unsigned char *output, 
			  long length,
			  des_key_schedule ks1,des_key_schedule ks2,
			  des_key_schedule ks3,des_cblock *ivec,int enc);
void des_ede3_cbcm_encrypt(const unsigned char *in,unsigned char *out,
			   long length,
			   des_key_schedule ks1,des_key_schedule ks2,
			   des_key_schedule ks3,
			   des_cblock *ivec1,des_cblock *ivec2,
			   int enc);
void des_ede3_cfb64_encrypt(const unsigned char *in,unsigned char *out,
			    long length,des_key_schedule ks1,
			    des_key_schedule ks2,des_key_schedule ks3,
			    des_cblock *ivec,int *num,int enc);
void des_ede3_ofb64_encrypt(const unsigned char *in,unsigned char *out,
			    long length,des_key_schedule ks1,
			    des_key_schedule ks2,des_key_schedule ks3,
			    des_cblock *ivec,int *num);

void des_xwhite_in2out(const_des_cblock *des_key,const_des_cblock *in_white,
		       des_cblock *out_white);

int des_enc_read(int fd,void *buf,int len,des_key_schedule sched,
		 des_cblock *iv);
int des_enc_write(int fd,const void *buf,int len,des_key_schedule sched,
		  des_cblock *iv);
char *des_fcrypt(const char *buf,const char *salt, char *ret);
char *des_crypt(const char *buf,const char *salt);
#if !defined(PERL5) && !defined(__FreeBSD__) && !defined(NeXT)
char *crypt(const char *buf,const char *salt);
#endif
void des_ofb_encrypt(const unsigned char *in,unsigned char *out,int numbits,
		     long length,des_key_schedule schedule,des_cblock *ivec);
void des_pcbc_encrypt(const unsigned char *input,unsigned char *output,
		      long length,des_key_schedule schedule,des_cblock *ivec,
		      int enc);
DES_LONG des_quad_cksum(const unsigned char *input,des_cblock output[],
			long length,int out_count,des_cblock *seed);
void des_random_seed(des_cblock *key);
int des_random_key(des_cblock *ret);
int des_read_password(des_cblock *key,const char *prompt,int verify);
int des_read_2passwords(des_cblock *key1,des_cblock *key2,
			const char *prompt,int verify);
int des_read_pw_string(char *buf,int length,const char *prompt,int verify);
void des_set_odd_parity(des_cblock *key);
int des_is_weak_key(const_des_cblock *key);
/* des_set_key (= set_key = des_key_sched = key_sched) calls
 * des_set_key_checked if global variable des_check_key is set,
 * des_set_key_unchecked otherwise. */
int des_set_key(const_des_cblock *key,des_key_schedule schedule);
int des_key_sched(const_des_cblock *key,des_key_schedule schedule);
int des_set_key_checked(const_des_cblock *key,des_key_schedule schedule);
void des_set_key_unchecked(const_des_cblock *key,des_key_schedule schedule);
void des_string_to_key(const char *str,des_cblock *key);
void des_string_to_2keys(const char *str,des_cblock *key1,des_cblock *key2);
void des_cfb64_encrypt(const unsigned char *in,unsigned char *out,long length,
		       des_key_schedule schedule,des_cblock *ivec,int *num,
		       int enc);
void des_ofb64_encrypt(const unsigned char *in,unsigned char *out,long length,
		       des_key_schedule schedule,des_cblock *ivec,int *num);
int des_read_pw(char *buf,char *buff,int size,const char *prompt,int verify);

/* Extra functions from Mark Murray <mark@grondar.za> */
void des_cblock_print_file(const_des_cblock *cb, FILE *fp);

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
#endif

typedef des_key_schedule bit_64;
#define des_fixup_key_parity des_set_odd_parity
#define des_check_key_parity check_parity

#ifdef  __cplusplus
}
#endif

#endif
