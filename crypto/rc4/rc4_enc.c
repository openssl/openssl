/* crypto/rc4/rc4_enc.c */
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

#include <openssl/rc4.h>
#include "rc4_locl.h"

/* RC4 as implemented from a posting from
 * Newsgroups: sci.crypt
 * From: sterndark@netcom.com (David Sterndark)
 * Subject: RC4 Algorithm revealed.
 * Message-ID: <sternCvKL4B.Hyy@netcom.com>
 * Date: Wed, 14 Sep 1994 06:35:31 GMT
 */

void RC4(RC4_KEY *key, unsigned long len, unsigned char *indata,
	     unsigned char *outdata)
	{
        register RC4_INT *d;
        register RC4_INT x,y,tx,ty;
	int i;
        
        x=key->x;     
        y=key->y;     
        d=key->data; 

#if defined(RC4_CHUNK) && (defined(L_ENDIAN) || defined(B_ENDIAN))
	/*
	 * The original reason for implementing this(*) was the fact that
	 * pre-21164a Alpha CPUs don't have byte load/store instructions
	 * and e.g. a byte store has to be done with 64-bit load, shift,
	 * and, or and finally 64-bit store. Peaking data and operating
	 * at natural word size made it possible to reduce amount of
	 * instructions as well as to perform early read-ahead without
	 * suffering from RAW (read-after-write) hazard. This resulted
	 * in >40%(**) performance improvement (on 21064 box with gcc).
	 * But it's not only Alpha users who win here:-) Thanks to the
	 * early-n-wide read-ahead this implementation also exhibits
	 * >40% speed-up on SPARC and almost 20% on MIPS.
	 *
	 * (*)	"this" means code which recognizes the case when input
	 *	and output pointers appear to be aligned at natural CPU
	 *	word boundary.
	 * (**)	i.e. according to 'apps/openssl speed rc4' benchmark,
	 *	crypto/rc4/rc4speed.c exhibits almost 70% speed-up.
	 *
	 *					<appro@fy.chalmers.se>
	 */

#define RC4_STEP	( \
			x=(x+1) &0xff,	\
			tx=d[x],	\
			y=(tx+y)&0xff,	\
			ty=d[y],	\
			d[y]=tx,	\
			d[x]=ty,	\
			(RC4_CHUNK)d[(tx+ty)&0xff]\
			)

#if defined(L_ENDIAN)
#  define SHFT(c)	((c)*8)
#  define MASK(i)	(((RC4_CHUNK)-1)>>((sizeof(RC4_CHUNK)-(i))<<3))
#  define SHINC		8
#elif defined(B_ENDIAN)
#  define SHFT(c)	((sizeof(RC4_CHUNK)-(c)-1)*8)
#  define MASK(i)	(((RC4_CHUNK)-1)<<((sizeof(RC4_CHUNK)-(i))<<3))
#  define SHINC		-8
#else
#  error "L_ENDIAN or B_ENDIAN *must* be defined!"
#endif

	if ( ( ((unsigned long)indata  & (sizeof(RC4_CHUNK)-1)) | 
	       ((unsigned long)outdata & (sizeof(RC4_CHUNK)-1)) ) == 0
	   ) {
		RC4_CHUNK ichunk,cipher;

		for (;len&-sizeof(RC4_CHUNK);len-=sizeof(RC4_CHUNK)) {
			ichunk  = *(RC4_CHUNK *)indata;
			cipher  = RC4_STEP<<SHFT(0);
			cipher |= RC4_STEP<<SHFT(1);
			cipher |= RC4_STEP<<SHFT(2);
			cipher |= RC4_STEP<<SHFT(3);
#ifdef RC4_CHUNK_IS_64_BIT
			cipher |= RC4_STEP<<SHFT(4);
			cipher |= RC4_STEP<<SHFT(5);
			cipher |= RC4_STEP<<SHFT(6);
			cipher |= RC4_STEP<<SHFT(7);
#endif
			*(RC4_CHUNK *)outdata = cipher^ichunk;
			indata  += sizeof(RC4_CHUNK);
			outdata += sizeof(RC4_CHUNK);
		}
		if (len) {
			RC4_CHUNK mask,ochunk;

			ichunk = *(RC4_CHUNK *)indata;
			ochunk = *(RC4_CHUNK *)outdata;
			cipher = 0;
			i = SHFT(0);
			mask = MASK(len);
			switch (len) {
#ifdef RC4_CHUNK_IS_64_BIT
				case 7:	cipher  = RC4_STEP<<SHFT(0), i+=SHINC;
				case 6:	cipher |= RC4_STEP<<i,	i+=SHINC;
				case 5:	cipher |= RC4_STEP<<i,	i+=SHINC;
				case 4:	cipher |= RC4_STEP<<i,	i+=SHINC;
				case 3:	cipher |= RC4_STEP<<i,	i+=SHINC;
#else
				case 3:	cipher  = RC4_STEP<<SHFT(0), i+=SHINC;
#endif
				case 2:	cipher |= RC4_STEP<<i,	i+=SHINC;
				case 1:	cipher |= RC4_STEP<<i,	i+=SHINC;
				case 0: ; /* it's never the case, but it
					     has to be here for ultrix? */
			}
			ochunk &= ~mask;
			ochunk |= (cipher^ichunk) & mask;
			*(RC4_CHUNK *)outdata = ochunk;
		}
	}
	else
#endif
	{
#define LOOP(in,out) \
		x=((x+1)&0xff); \
		tx=d[x]; \
		y=(tx+y)&0xff; \
		d[x]=ty=d[y]; \
		d[y]=tx; \
		(out) = d[(tx+ty)&0xff]^ (in);

#ifndef RC4_INDEX
#define RC4_LOOP(a,b,i)	LOOP(*((a)++),*((b)++))
#else
#define RC4_LOOP(a,b,i)	LOOP(a[i],b[i])
#endif

	i=(int)(len>>3L);
	if (i)
		{
		for (;;)
			{
			RC4_LOOP(indata,outdata,0);
			RC4_LOOP(indata,outdata,1);
			RC4_LOOP(indata,outdata,2);
			RC4_LOOP(indata,outdata,3);
			RC4_LOOP(indata,outdata,4);
			RC4_LOOP(indata,outdata,5);
			RC4_LOOP(indata,outdata,6);
			RC4_LOOP(indata,outdata,7);
#ifdef RC4_INDEX
			indata+=8;
			outdata+=8;
#endif
			if (--i == 0) break;
			}
		}
	i=(int)len&0x07;
	if (i)
		{
		for (;;)
			{
			RC4_LOOP(indata,outdata,0); if (--i == 0) break;
			RC4_LOOP(indata,outdata,1); if (--i == 0) break;
			RC4_LOOP(indata,outdata,2); if (--i == 0) break;
			RC4_LOOP(indata,outdata,3); if (--i == 0) break;
			RC4_LOOP(indata,outdata,4); if (--i == 0) break;
			RC4_LOOP(indata,outdata,5); if (--i == 0) break;
			RC4_LOOP(indata,outdata,6); if (--i == 0) break;
			}
		}               
	}
	key->x=x;     
	key->y=y;
	}
