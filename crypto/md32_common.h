/* crypto/md32_common.h */
/* ====================================================================
 * Copyright (c) 1999-2002 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

/*
 * This is a generic 32 bit "collector" for message digest algorithms.
 * Whenever needed it collects input character stream into chunks of
 * 32 bit values and invokes a block function that performs actual hash
 * calculations.
 *
 * Porting guide.
 *
 * Obligatory macros:
 *
 * DATA_ORDER_IS_BIG_ENDIAN or DATA_ORDER_IS_LITTLE_ENDIAN
 *	this macro defines byte order of input stream.
 * HASH_CBLOCK
 *	size of a unit chunk HASH_BLOCK operates on.
 * HASH_LONG
 *	has to be at lest 32 bit wide, if it's wider, then
 *	HASH_LONG_LOG2 *has to* be defined along
 * HASH_CTX
 *	context structure that at least contains following
 *	members:
 *		typedef struct {
 *			...
 *			HASH_LONG	Nl,Nh;
 *			HASH_LONG	data[HASH_LBLOCK];
 *			unsigned int	num;
 *			...
 *			} HASH_CTX;
 * HASH_UPDATE
 *	name of "Update" function, implemented here.
 * HASH_TRANSFORM
 *	name of "Transform" function, implemented here.
 * HASH_FINAL
 *	name of "Final" function, implemented here.
 * HASH_BLOCK_HOST_ORDER
 *	name of "block" function treating *aligned* input message
 *	in host byte order, implemented externally.
 * HASH_BLOCK_DATA_ORDER
 *	name of "block" function treating *unaligned* input message
 *	in original (data) byte order, implemented externally (it
 *	actually is optional if data and host are of the same
 *	"endianess").
 * HASH_MAKE_STRING
 *	macro convering context variables to an ASCII hash string.
 *
 * Optional macros:
 *
 * B_ENDIAN or L_ENDIAN
 *	defines host byte-order.
 * HASH_LONG_LOG2
 *	defaults to 2 if not states otherwise.
 * HASH_LBLOCK
 *	assumed to be HASH_CBLOCK/4 if not stated otherwise.
 * HASH_BLOCK_DATA_ORDER_ALIGNED
 *	alternative "block" function capable of treating
 *	aligned input message in original (data) order,
 *	implemented externally.
 *
 * MD5 example:
 *
 *	#define DATA_ORDER_IS_LITTLE_ENDIAN
 *
 *	#define HASH_LONG		MD5_LONG
 *	#define HASH_LONG_LOG2		MD5_LONG_LOG2
 *	#define HASH_CTX		MD5_CTX
 *	#define HASH_CBLOCK		MD5_CBLOCK
 *	#define HASH_LBLOCK		MD5_LBLOCK
 *	#define HASH_UPDATE		MD5_Update
 *	#define HASH_TRANSFORM		MD5_Transform
 *	#define HASH_FINAL		MD5_Final
 *	#define HASH_BLOCK_HOST_ORDER	md5_block_host_order
 *	#define HASH_BLOCK_DATA_ORDER	md5_block_data_order
 *
 *					<appro@fy.chalmers.se>
 */

#if !defined(DATA_ORDER_IS_BIG_ENDIAN) && !defined(DATA_ORDER_IS_LITTLE_ENDIAN)
#error "DATA_ORDER must be defined!"
#endif

#ifndef HASH_CBLOCK
#error "HASH_CBLOCK must be defined!"
#endif
#ifndef HASH_LONG
#error "HASH_LONG must be defined!"
#endif
#ifndef HASH_CTX
#error "HASH_CTX must be defined!"
#endif

#ifndef HASH_UPDATE
#error "HASH_UPDATE must be defined!"
#endif
#ifndef HASH_TRANSFORM
#error "HASH_TRANSFORM must be defined!"
#endif
#ifndef HASH_FINAL
#error "HASH_FINAL must be defined!"
#endif

#ifndef HASH_BLOCK_HOST_ORDER
#error "HASH_BLOCK_HOST_ORDER must be defined!"
#endif

#if 0
/*
 * Moved below as it's required only if HASH_BLOCK_DATA_ORDER_ALIGNED
 * isn't defined.
 */
#ifndef HASH_BLOCK_DATA_ORDER
#error "HASH_BLOCK_DATA_ORDER must be defined!"
#endif
#endif

#ifndef HASH_LBLOCK
#define HASH_LBLOCK	(HASH_CBLOCK/4)
#endif

#ifndef HASH_LONG_LOG2
#define HASH_LONG_LOG2	2
#endif

/*
 * Engage compiler specific rotate intrinsic function if available.
 */
#undef ROTATE
#ifndef PEDANTIC
# if defined(_MSC_VER) || defined(__ICC)
#  define ROTATE(a,n)	_lrotl(a,n)
# elif defined(__MWERKS__)
#  if defined(__POWERPC__)
#   define ROTATE(a,n)	__rlwinm(a,n,0,31)
#  elif defined(__MC68K__)
    /* Motorola specific tweak. <appro@fy.chalmers.se> */
#   define ROTATE(a,n)	( n<24 ? __rol(a,n) : __ror(a,32-n) )
#  else
#   define ROTATE(a,n)	__rol(a,n)
#  endif
# elif defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
  /*
   * Some GNU C inline assembler templates. Note that these are
   * rotates by *constant* number of bits! But that's exactly
   * what we need here...
   * 					<appro@fy.chalmers.se>
   */
#  if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
#   define ROTATE(a,n)	({ register unsigned int ret;	\
				asm (			\
				"roll %1,%0"		\
				: "=r"(ret)		\
				: "I"(n), "0"(a)	\
				: "cc");		\
			   ret;				\
			})
#  elif defined(__powerpc) || defined(__ppc__) || defined(__powerpc64__)
#   define ROTATE(a,n)	({ register unsigned int ret;	\
				asm (			\
				"rlwinm %0,%1,%2,0,31"	\
				: "=r"(ret)		\
				: "r"(a), "I"(n));	\
			   ret;				\
			})
#  endif
# endif
#endif /* PEDANTIC */

#if HASH_LONG_LOG2==2	/* Engage only if sizeof(HASH_LONG)== 4 */
/* A nice byte order reversal from Wei Dai <weidai@eskimo.com> */
#ifdef ROTATE
/* 5 instructions with rotate instruction, else 9 */
#define REVERSE_FETCH32(a,l)	(					\
		l=*(const HASH_LONG *)(a),				\
		((ROTATE(l,8)&0x00FF00FF)|(ROTATE((l&0x00FF00FF),24)))	\
				)
#else
/* 6 instructions with rotate instruction, else 8 */
#define REVERSE_FETCH32(a,l)	(				\
		l=*(const HASH_LONG *)(a),			\
		l=(((l>>8)&0x00FF00FF)|((l&0x00FF00FF)<<8)),	\
		ROTATE(l,16)					\
				)
/*
 * Originally the middle line started with l=(((l&0xFF00FF00)>>8)|...
 * It's rewritten as above for two reasons:
 *	- RISCs aren't good at long constants and have to explicitely
 *	  compose 'em with several (well, usually 2) instructions in a
 *	  register before performing the actual operation and (as you
 *	  already realized:-) having same constant should inspire the
 *	  compiler to permanently allocate the only register for it;
 *	- most modern CPUs have two ALUs, but usually only one has
 *	  circuitry for shifts:-( this minor tweak inspires compiler
 *	  to schedule shift instructions in a better way...
 *
 *				<appro@fy.chalmers.se>
 */
#endif
#endif

#ifndef ROTATE
#define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#endif

/*
 * Make some obvious choices. E.g., HASH_BLOCK_DATA_ORDER_ALIGNED
 * and HASH_BLOCK_HOST_ORDER ought to be the same if input data
 * and host are of the same "endianess". It's possible to mask
 * this with blank #define HASH_BLOCK_DATA_ORDER though...
 *
 *				<appro@fy.chalmers.se>
 */
#if defined(B_ENDIAN)
#  if defined(DATA_ORDER_IS_BIG_ENDIAN)
#    if !defined(HASH_BLOCK_DATA_ORDER_ALIGNED) && HASH_LONG_LOG2==2
#      define HASH_BLOCK_DATA_ORDER_ALIGNED	HASH_BLOCK_HOST_ORDER
#    endif
#  endif
#elif defined(L_ENDIAN)
#  if defined(DATA_ORDER_IS_LITTLE_ENDIAN)
#    if !defined(HASH_BLOCK_DATA_ORDER_ALIGNED) && HASH_LONG_LOG2==2
#      define HASH_BLOCK_DATA_ORDER_ALIGNED	HASH_BLOCK_HOST_ORDER
#    endif
#  endif
#endif

#if !defined(HASH_BLOCK_DATA_ORDER_ALIGNED)
#ifndef HASH_BLOCK_DATA_ORDER
#error "HASH_BLOCK_DATA_ORDER must be defined!"
#endif
#endif

#if defined(DATA_ORDER_IS_BIG_ENDIAN)

#ifndef PEDANTIC
# if defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
#  if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
    /*
     * This gives ~30-40% performance improvement in SHA-256 compiled
     * with gcc [on P4]. Well, first macro to be frank. We can pull
     * this trick on x86* platforms only, because these CPUs can fetch
     * unaligned data without raising an exception.
     */
#   define HOST_c2l(c,l)	({ unsigned int r=*((const unsigned int *)(c));	\
				   asm ("bswapl %0":"=r"(r):"0"(r));	\
				   (c)+=4; (l)=r;			})
#   define HOST_l2c(l,c)	({ unsigned int r=(l);			\
				   asm ("bswapl %0":"=r"(r):"0"(r));	\
				   *((unsigned int *)(c))=r; (c)+=4; r;	})
#  endif
# endif
#endif

#ifndef HOST_c2l
#define HOST_c2l(c,l)	(l =(((unsigned long)(*((c)++)))<<24),		\
			 l|=(((unsigned long)(*((c)++)))<<16),		\
			 l|=(((unsigned long)(*((c)++)))<< 8),		\
			 l|=(((unsigned long)(*((c)++)))    ),		\
			 l)
#endif
#define HOST_p_c2l(c,l,n)	{					\
			switch (n) {					\
			case 0: l =((unsigned long)(*((c)++)))<<24;	\
			case 1: l|=((unsigned long)(*((c)++)))<<16;	\
			case 2: l|=((unsigned long)(*((c)++)))<< 8;	\
			case 3: l|=((unsigned long)(*((c)++)));		\
				} }
#define HOST_p_c2l_p(c,l,sc,len) {					\
			switch (sc) {					\
			case 0: l =((unsigned long)(*((c)++)))<<24;	\
				if (--len == 0) break;			\
			case 1: l|=((unsigned long)(*((c)++)))<<16;	\
				if (--len == 0) break;			\
			case 2: l|=((unsigned long)(*((c)++)))<< 8;	\
				} }
/* NOTE the pointer is not incremented at the end of this */
#define HOST_c2l_p(c,l,n)	{					\
			l=0; (c)+=n;					\
			switch (n) {					\
			case 3: l =((unsigned long)(*(--(c))))<< 8;	\
			case 2: l|=((unsigned long)(*(--(c))))<<16;	\
			case 1: l|=((unsigned long)(*(--(c))))<<24;	\
				} }
#ifndef HOST_l2c
#define HOST_l2c(l,c)	(*((c)++)=(unsigned char)(((l)>>24)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>16)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff),	\
			 *((c)++)=(unsigned char)(((l)    )&0xff),	\
			 l)
#endif

#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)

#if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
  /* See comment in DATA_ORDER_IS_BIG_ENDIAN section. */
# define HOST_c2l(c,l)	((l)=*((const unsigned int *)(c)), (c)+=4, l)
# define HOST_l2c(l,c)	(*((unsigned int *)(c))=(l), (c)+=4, l)
#endif

#ifndef HOST_c2l
#define HOST_c2l(c,l)	(l =(((unsigned long)(*((c)++)))    ),		\
			 l|=(((unsigned long)(*((c)++)))<< 8),		\
			 l|=(((unsigned long)(*((c)++)))<<16),		\
			 l|=(((unsigned long)(*((c)++)))<<24),		\
			 l)
#endif
#define HOST_p_c2l(c,l,n)	{					\
			switch (n) {					\
			case 0: l =((unsigned long)(*((c)++)));		\
			case 1: l|=((unsigned long)(*((c)++)))<< 8;	\
			case 2: l|=((unsigned long)(*((c)++)))<<16;	\
			case 3: l|=((unsigned long)(*((c)++)))<<24;	\
				} }
#define HOST_p_c2l_p(c,l,sc,len) {					\
			switch (sc) {					\
			case 0: l =((unsigned long)(*((c)++)));		\
				if (--len == 0) break;			\
			case 1: l|=((unsigned long)(*((c)++)))<< 8;	\
				if (--len == 0) break;			\
			case 2: l|=((unsigned long)(*((c)++)))<<16;	\
				} }
/* NOTE the pointer is not incremented at the end of this */
#define HOST_c2l_p(c,l,n)	{					\
			l=0; (c)+=n;					\
			switch (n) {					\
			case 3: l =((unsigned long)(*(--(c))))<<16;	\
			case 2: l|=((unsigned long)(*(--(c))))<< 8;	\
			case 1: l|=((unsigned long)(*(--(c))));		\
				} }
#ifndef HOST_l2c
#define HOST_l2c(l,c)	(*((c)++)=(unsigned char)(((l)    )&0xff),	\
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>16)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>24)&0xff),	\
			 l)
#endif

#endif

/*
 * Time for some action:-)
 */

int HASH_UPDATE (HASH_CTX *c, const void *data_, size_t len)
	{
	const unsigned char *data=data_;
	register HASH_LONG * p;
	register HASH_LONG l;
	size_t sw,sc,ew,ec;

	if (len==0) return 1;

	l=(c->Nl+(((HASH_LONG)len)<<3))&0xffffffffUL;
	/* 95-05-24 eay Fixed a bug with the overflow handling, thanks to
	 * Wei Dai <weidai@eskimo.com> for pointing it out. */
	if (l < c->Nl) /* overflow */
		c->Nh++;
	c->Nh+=(len>>29);	/* might cause compiler warning on 16-bit */
	c->Nl=l;

	if (c->num != 0)
		{
		p=c->data;
		sw=c->num>>2;
		sc=c->num&0x03;

		if ((c->num+len) >= HASH_CBLOCK)
			{
			l=p[sw]; HOST_p_c2l(data,l,sc); p[sw++]=l;
			for (; sw<HASH_LBLOCK; sw++)
				{
				HOST_c2l(data,l); p[sw]=l;
				}
			HASH_BLOCK_HOST_ORDER (c,p,1);
			len-=(HASH_CBLOCK-c->num);
			c->num=0;
			/* drop through and do the rest */
			}
		else
			{
			c->num+=(unsigned int)len;
			if ((sc+len) < 4) /* ugly, add char's to a word */
				{
				l=p[sw]; HOST_p_c2l_p(data,l,sc,len); p[sw]=l;
				}
			else
				{
				ew=(c->num>>2);
				ec=(c->num&0x03);
				if (sc)
					l=p[sw];
				HOST_p_c2l(data,l,sc);
				p[sw++]=l;
				for (; sw < ew; sw++)
					{
					HOST_c2l(data,l); p[sw]=l;
					}
				if (ec)
					{
					HOST_c2l_p(data,l,ec); p[sw]=l;
					}
				}
			return 1;
			}
		}

	sw=len/HASH_CBLOCK;
	if (sw > 0)
		{
#if defined(HASH_BLOCK_DATA_ORDER_ALIGNED)
		/*
		 * Note that HASH_BLOCK_DATA_ORDER_ALIGNED gets defined
		 * only if sizeof(HASH_LONG)==4.
		 */
		if ((((size_t)data)%4) == 0)
			{
			/* data is properly aligned so that we can cast it: */
			HASH_BLOCK_DATA_ORDER_ALIGNED (c,(const HASH_LONG *)data,sw);
			sw*=HASH_CBLOCK;
			data+=sw;
			len-=sw;
			}
		else
#if !defined(HASH_BLOCK_DATA_ORDER)
			while (sw--)
				{
				memcpy (p=c->data,data,HASH_CBLOCK);
				HASH_BLOCK_DATA_ORDER_ALIGNED(c,p,1);
				data+=HASH_CBLOCK;
				len-=HASH_CBLOCK;
				}
#endif
#endif
#if defined(HASH_BLOCK_DATA_ORDER)
			{
			HASH_BLOCK_DATA_ORDER(c,data,sw);
			sw*=HASH_CBLOCK;
			data+=sw;
			len-=sw;
			}
#endif
		}

	if (len!=0)
		{
		p = c->data;
		c->num = len;
		ew=len>>2;	/* words to copy */
		ec=len&0x03;
		for (; ew; ew--,p++)
			{
			HOST_c2l(data,l); *p=l;
			}
		HOST_c2l_p(data,l,ec);
		*p=l;
		}
	return 1;
	}


void HASH_TRANSFORM (HASH_CTX *c, const unsigned char *data)
	{
#if defined(HASH_BLOCK_DATA_ORDER_ALIGNED)
	if ((((size_t)data)%4) == 0)
		/* data is properly aligned so that we can cast it: */
		HASH_BLOCK_DATA_ORDER_ALIGNED (c,(const HASH_LONG *)data,1);
	else
#if !defined(HASH_BLOCK_DATA_ORDER)
		{
		memcpy (c->data,data,HASH_CBLOCK);
		HASH_BLOCK_DATA_ORDER_ALIGNED (c,c->data,1);
		}
#endif
#endif
#if defined(HASH_BLOCK_DATA_ORDER)
	HASH_BLOCK_DATA_ORDER (c,data,1);
#endif
	}


int HASH_FINAL (unsigned char *md, HASH_CTX *c)
	{
	register HASH_LONG *p;
	register unsigned long l;
	register int i,j;
	static const unsigned char end[4]={0x80,0x00,0x00,0x00};
	const unsigned char *cp=end;

	/* c->num should definitly have room for at least one more byte. */
	p=c->data;
	i=c->num>>2;
	j=c->num&0x03;

#if 0
	/* purify often complains about the following line as an
	 * Uninitialized Memory Read.  While this can be true, the
	 * following p_c2l macro will reset l when that case is true.
	 * This is because j&0x03 contains the number of 'valid' bytes
	 * already in p[i].  If and only if j&0x03 == 0, the UMR will
	 * occur but this is also the only time p_c2l will do
	 * l= *(cp++) instead of l|= *(cp++)
	 * Many thanks to Alex Tang <altitude@cic.net> for pickup this
	 * 'potential bug' */
#ifdef PURIFY
	if (j==0) p[i]=0; /* Yeah, but that's not the way to fix it:-) */
#endif
	l=p[i];
#else
	l = (j==0) ? 0 : p[i];
#endif
	HOST_p_c2l(cp,l,j); p[i++]=l; /* i is the next 'undefined word' */

	if (i>(HASH_LBLOCK-2)) /* save room for Nl and Nh */
		{
		if (i<HASH_LBLOCK) p[i]=0;
		HASH_BLOCK_HOST_ORDER (c,p,1);
		i=0;
		}
	for (; i<(HASH_LBLOCK-2); i++)
		p[i]=0;

#if   defined(DATA_ORDER_IS_BIG_ENDIAN)
	p[HASH_LBLOCK-2]=c->Nh;
	p[HASH_LBLOCK-1]=c->Nl;
#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)
	p[HASH_LBLOCK-2]=c->Nl;
	p[HASH_LBLOCK-1]=c->Nh;
#endif
	HASH_BLOCK_HOST_ORDER (c,p,1);

#ifndef HASH_MAKE_STRING
#error "HASH_MAKE_STRING must be defined!"
#else
	HASH_MAKE_STRING(c,md);
#endif

	c->num=0;
	/* clear stuff, HASH_BLOCK may be leaving some stuff on the stack
	 * but I'm not worried :-)
	OPENSSL_cleanse((void *)c,sizeof(HASH_CTX));
	 */
	return 1;
	}

#ifndef MD32_REG_T
#define MD32_REG_T long
/*
 * This comment was originaly written for MD5, which is why it
 * discusses A-D. But it basically applies to all 32-bit digests,
 * which is why it was moved to common header file.
 *
 * In case you wonder why A-D are declared as long and not
 * as MD5_LONG. Doing so results in slight performance
 * boost on LP64 architectures. The catch is we don't
 * really care if 32 MSBs of a 64-bit register get polluted
 * with eventual overflows as we *save* only 32 LSBs in
 * *either* case. Now declaring 'em long excuses the compiler
 * from keeping 32 MSBs zeroed resulting in 13% performance
 * improvement under SPARC Solaris7/64 and 5% under AlphaLinux.
 * Well, to be honest it should say that this *prevents* 
 * performance degradation.
 *				<appro@fy.chalmers.se>
 * Apparently there're LP64 compilers that generate better
 * code if A-D are declared int. Most notably GCC-x86_64
 * generates better code.
 *				<appro@fy.chalmers.se>
 */
#endif
