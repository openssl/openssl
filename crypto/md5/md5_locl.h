/* crypto/md5/md5_locl.h */
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

#include <stdlib.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/md5.h>

#ifndef MD5_LONG_LOG2
#define MD5_LONG_LOG2 2 /* default to 32 bits */
#endif

#ifdef MD5_ASM
# if defined(__i386) || defined(__i386__) || defined(_M_IX86) || defined(__INTEL__)
#  define md5_block_host_order md5_block_asm_host_order
# elif defined(__sparc) && defined(OPENSSL_SYS_ULTRASPARC)
   void md5_block_asm_data_order_aligned (MD5_CTX *c, const MD5_LONG *p,int num);
#  define HASH_BLOCK_DATA_ORDER_ALIGNED md5_block_asm_data_order_aligned
# endif
#endif

void md5_block_host_order (MD5_CTX *c, const void *p,int num);
void md5_block_data_order (MD5_CTX *c, const void *p,int num);

#if defined(__i386) || defined(__i386__) || defined(_M_IX86) || defined(__INTEL__)
/*
 * *_block_host_order is expected to handle aligned data while
 * *_block_data_order - unaligned. As algorithm and host (x86)
 * are in this case of the same "endianness" these two are
 * otherwise indistinguishable. But normally you don't want to
 * call the same function because unaligned access in places
 * where alignment is expected is usually a "Bad Thing". Indeed,
 * on RISCs you get punished with BUS ERROR signal or *severe*
 * performance degradation. Intel CPUs are in turn perfectly
 * capable of loading unaligned data without such drastic side
 * effect. Yes, they say it's slower than aligned load, but no
 * exception is generated and therefore performance degradation
 * is *incomparable* with RISCs. What we should weight here is
 * costs of unaligned access against costs of aligning data.
 * According to my measurements allowing unaligned access results
 * in ~9% performance improvement on Pentium II operating at
 * 266MHz. I won't be surprised if the difference will be higher
 * on faster systems:-)
 *
 *				<appro@fy.chalmers.se>
 */
#define md5_block_data_order md5_block_host_order
#endif

#define DATA_ORDER_IS_LITTLE_ENDIAN

#define HASH_LONG		MD5_LONG
#define HASH_LONG_LOG2		MD5_LONG_LOG2
#define HASH_CTX		MD5_CTX
#define HASH_CBLOCK		MD5_CBLOCK
#define HASH_LBLOCK		MD5_LBLOCK
#define HASH_UPDATE		MD5_Update
#define HASH_TRANSFORM		MD5_Transform
#define HASH_FINAL		MD5_Final
#define	HASH_MAKE_STRING(c,s)	do {	\
	unsigned long ll;		\
	ll=(c)->A; HOST_l2c(ll,(s));	\
	ll=(c)->B; HOST_l2c(ll,(s));	\
	ll=(c)->C; HOST_l2c(ll,(s));	\
	ll=(c)->D; HOST_l2c(ll,(s));	\
	} while (0)
#define HASH_BLOCK_HOST_ORDER	md5_block_host_order
#if !defined(L_ENDIAN) || defined(md5_block_data_order)
#define	HASH_BLOCK_DATA_ORDER	md5_block_data_order
/*
 * Little-endians (Intel and Alpha) feel better without this.
 * It looks like memcpy does better job than generic
 * md5_block_data_order on copying-n-aligning input data.
 * But frankly speaking I didn't expect such result on Alpha.
 * On the other hand I've got this with egcs-1.0.2 and if
 * program is compiled with another (better?) compiler it
 * might turn out other way around.
 *
 *				<appro@fy.chalmers.se>
 */
#endif

#include "md32_common.h"

/*
#define	F(x,y,z)	(((x) & (y))  |  ((~(x)) & (z)))
#define	G(x,y,z)	(((x) & (z))  |  ((y) & (~(z))))
*/

/* As pointed out by Wei Dai <weidai@eskimo.com>, the above can be
 * simplified to the code below.  Wei attributes these optimizations
 * to Peter Gutmann's SHS code, and he attributes it to Rich Schroeppel.
 */
#define	F(b,c,d)	((((c) ^ (d)) & (b)) ^ (d))
#define	G(b,c,d)	((((b) ^ (c)) & (d)) ^ (c))
#define	H(b,c,d)	((b) ^ (c) ^ (d))
#define	I(b,c,d)	(((~(d)) | (b)) ^ (c))

#define R0(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+F((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };\

#define R1(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+G((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };

#define R2(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+H((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };

#define R3(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+I((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };
