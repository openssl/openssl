/* crypto/des/des.org */
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

/* WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING 
 *
 * Always modify des.org since des.h is automatically generated from
 * it during SSLeay configuration.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 */

#ifndef HEADER_DES_H
#define HEADER_DES_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdio.h>

/* If this is set to 'unsigned int' on a DEC Alpha, this gives about a
 * %20 speed up (longs are 8 bytes, int's are 4). */
#ifndef DES_LONG
#define DES_LONG unsigned long
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
#undef _
#define _	ks._
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

#define C_Block des_cblock
#define Key_schedule des_key_schedule
#ifdef KERBEROS
#define ENCRYPT DES_ENCRYPT
#define DECRYPT DES_DECRYPT
#endif
#define KEY_SZ DES_KEY_SZ
#define string_to_key des_string_to_key
#define read_pw_string des_read_pw_string
#define random_key des_random_key
#define pcbc_encrypt des_pcbc_encrypt
#define set_key des_set_key
#define key_sched des_key_sched
#define ecb_encrypt des_ecb_encrypt
#define cbc_encrypt des_cbc_encrypt
#define ncbc_encrypt des_ncbc_encrypt
#define xcbc_encrypt des_xcbc_encrypt
#define cbc_cksum des_cbc_cksum
#define quad_cksum des_quad_cksum

/* For compatibility with the MIT lib - eay 20/05/92 */
typedef des_key_schedule bit_64;
#define des_fixup_key_parity des_set_odd_parity
#define des_check_key_parity check_parity

extern int des_check_key;	/* defaults to false */
extern int des_rw_mode;		/* defaults to DES_PCBC_MODE */

/* The next line is used to disable full ANSI prototypes, if your
 * compiler has problems with the prototypes, make sure this line always
 * evaluates to true :-) */
#if defined(MSDOS) || defined(__STDC__)
#undef NOPROTO
#endif
#ifndef NOPROTO
char *des_options(void);
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
#ifdef PERL5
char *des_crypt(const char *buf,const char *salt);
#else
/* some stupid compilers complain because I have declared char instead
 * of const char */
#ifdef HEADER_DES_LOCL_H
char *crypt(const char *buf,const char *salt);
#else
char *crypt();
#endif
#endif
void des_ofb_encrypt(unsigned char *in,unsigned char *out,
	int numbits,long length,des_key_schedule schedule,des_cblock *ivec);
void des_pcbc_encrypt(des_cblock *input,des_cblock *output,long length,
	des_key_schedule schedule,des_cblock *ivec,int enc);
DES_LONG des_quad_cksum(des_cblock *input,des_cblock *output,
	long length,int out_count,des_cblock *seed);
void des_random_seed(des_cblock key);
void des_random_key(des_cblock ret);
int des_read_password(des_cblock *key,char *prompt,int verify);
int des_read_2passwords(des_cblock *key1,des_cblock *key2,
	char *prompt,int verify);
int des_read_pw_string(char *buf,int length,char *prompt,int verify);
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
int des_read_pw(char *buf, char *buff, int size, char *prompt, int verify);

/* Extra functions from Mark Murray <mark@grondar.za> */
void des_cblock_print_file(des_cblock *cb, FILE *fp);
/* The following functions are not in the normal unix build or the
 * SSLeay build.  When using the SSLeay build, use RAND_seed()
 * and RAND_bytes() instead. */
int des_new_random_key(des_cblock *key);
void des_init_random_number_generator(des_cblock *key);
void des_set_random_generator_seed(des_cblock *key);
void des_set_sequence_number(des_cblock new_sequence_number);
void des_generate_random_block(des_cblock *block);

#else

char *des_options();
void des_ecb3_encrypt();
DES_LONG des_cbc_cksum();
void des_cbc_encrypt();
void des_ncbc_encrypt();
void des_xcbc_encrypt();
void des_cfb_encrypt();
void des_ede3_cfb64_encrypt();
void des_ede3_ofb64_encrypt();
void des_ecb_encrypt();
void des_encrypt();
void des_encrypt2();
void des_encrypt3();
void des_decrypt3();
void des_ede3_cbc_encrypt();
int des_enc_read();
int des_enc_write();
char *des_fcrypt();
#ifdef PERL5
char *des_crypt();
#else
char *crypt();
#endif
void des_ofb_encrypt();
void des_pcbc_encrypt();
DES_LONG des_quad_cksum();
void des_random_seed();
void des_random_key();
int des_read_password();
int des_read_2passwords();
int des_read_pw_string();
void des_set_odd_parity();
int des_is_weak_key();
int des_set_key();
int des_key_sched();
void des_string_to_key();
void des_string_to_2keys();
void des_cfb64_encrypt();
void des_ofb64_encrypt();
int des_read_pw();
void des_xwhite_in2out();

/* Extra functions from Mark Murray <mark@grondar.za> */
void des_cblock_print_file();
/* The following functions are not in the normal unix build or the
 * SSLeay build.  When using the SSLeay build, use RAND_seed()
 * and RAND_bytes() instead. */
#ifdef FreeBSD
int des_new_random_key();
void des_init_random_number_generator();
void des_set_random_generator_seed();
void des_set_sequence_number();
void des_generate_random_block();
#endif

#endif

#ifdef  __cplusplus
}
#endif

#endif
