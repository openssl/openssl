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

/* On sparc, this actually slows things down :-( */
#if defined(sun)
#undef B_ENDIAN
#endif

#include <stdlib.h>
#include <string.h>
#include "md5.h"

#define ULONG	unsigned long
#define UCHAR	unsigned char
#define UINT	unsigned int

#if defined(NOCONST)
#define const
#endif

#undef c2l
#define c2l(c,l)	(l = ((unsigned long)(*((c)++)))     , \
			 l|=(((unsigned long)(*((c)++)))<< 8), \
			 l|=(((unsigned long)(*((c)++)))<<16), \
			 l|=(((unsigned long)(*((c)++)))<<24))

#undef p_c2l
#define p_c2l(c,l,n)	{ \
			switch (n) { \
			case 0: l =((unsigned long)(*((c)++))); \
			case 1: l|=((unsigned long)(*((c)++)))<< 8; \
			case 2: l|=((unsigned long)(*((c)++)))<<16; \
			case 3: l|=((unsigned long)(*((c)++)))<<24; \
				} \
			}

/* NOTE the pointer is not incremented at the end of this */
#undef c2l_p
#define c2l_p(c,l,n)	{ \
			l=0; \
			(c)+=n; \
			switch (n) { \
			case 3: l =((unsigned long)(*(--(c))))<<16; \
			case 2: l|=((unsigned long)(*(--(c))))<< 8; \
			case 1: l|=((unsigned long)(*(--(c))))    ; \
				} \
			}

#undef p_c2l_p
#define p_c2l_p(c,l,sc,len) { \
			switch (sc) \
				{ \
			case 0: l =((unsigned long)(*((c)++))); \
				if (--len == 0) break; \
			case 1: l|=((unsigned long)(*((c)++)))<< 8; \
				if (--len == 0) break; \
			case 2: l|=((unsigned long)(*((c)++)))<<16; \
				} \
			}

#undef l2c
#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)    )&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24)&0xff))

/* NOTE - c is not incremented as per l2c */
#undef l2cn
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

/* A nice byte order reversal from Wei Dai <weidai@eskimo.com> */
#if defined(WIN32)
/* 5 instructions with rotate instruction, else 9 */
#define Endian_Reverse32(a) \
	{ \
	unsigned long l=(a); \
	(a)=((ROTATE(l,8)&0x00FF00FF)|(ROTATE(l,24)&0xFF00FF00)); \
	}
#else
/* 6 instructions with rotate instruction, else 8 */
#define Endian_Reverse32(a) \
	{ \
	unsigned long l=(a); \
	l=(((l&0xFF00FF00)>>8L)|((l&0x00FF00FF)<<8L)); \
	(a)=ROTATE(l,16L); \
	}
#endif
/*
#define	F(x,y,z)	(((x) & (y))  |  ((~(x)) & (z)))
#define	G(x,y,z)	(((x) & (z))  |  ((y) & (~(z))))
*/

/* As pointed out by Wei Dai <weidai@eskimo.com>, the above can be
 * simplified to the code below.  Wei attributes these optimisations
 * to Peter Gutmann's SHS code, and he attributes it to Rich Schroeppel.
 */
#define	F(b,c,d)	((((c) ^ (d)) & (b)) ^ (d))
#define	G(b,c,d)	((((b) ^ (c)) & (d)) ^ (c))
#define	H(b,c,d)	((b) ^ (c) ^ (d))
#define	I(b,c,d)	(((~(d)) | (b)) ^ (c))

#undef ROTATE
#if defined(WIN32)
#define ROTATE(a,n)     _lrotl(a,n)
#else
#define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#endif


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
