/* ====================================================================
 * Copyright (c) 2010 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use is governed by OpenSSL license.
 * ====================================================================
 */

#include <openssl/modes.h>


#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
typedef __int64 i64;
typedef unsigned __int64 u64;
#define U64(C) C##UI64
#elif defined(__arch64__)
typedef long i64;
typedef unsigned long u64;
#define U64(C) C##UL
#else
typedef long long i64;
typedef unsigned long long u64;
#define U64(C) C##ULL
#endif

typedef unsigned int u32;
typedef unsigned char u8;

#define STRICT_ALIGNMENT 1
#if defined(__i386)	|| defined(__i386__)	|| \
    defined(__x86_64)	|| defined(__x86_64__)	|| \
    defined(_M_IX86)	|| defined(_M_AMD64)	|| defined(_M_X64) || \
    defined(__s390__)	|| defined(__s390x__)
# undef STRICT_ALIGNMENT
#endif

#if !defined(PEDANTIC) && !defined(OPENSSL_NO_ASM) && !defined(OPNESSL_NO_INLINE_ASM)
#if defined(__GNUC__) && __GNUC__>=2
# if defined(__x86_64) || defined(__x86_64__)
#  define BSWAP8(x) ({	u64 ret=(x);			\
			asm volatile ("bswapq %0"	\
			: "+r"(ret));	ret;		})
#  define BSWAP4(x) ({	u32 ret=(x);			\
			asm volatile ("bswapl %0"	\
			: "+r"(ret));	ret;		})
# elif (defined(__i386) || defined(__i386__))
#  define BSWAP8(x) ({	u32 lo=(u64)(x)>>32,hi=(x);	\
			asm volatile ("bswapl %0; bswapl %1"	\
			: "+r"(hi),"+r"(lo));		\
			(u64)hi<<32|lo;			})
#  define BSWAP4(x) ({	u32 ret=(x);			\
			asm volatile ("bswapl %0"	\
			: "+r"(ret));	ret;		})
# endif
#elif defined(_MSC_VER)
# if _MSC_VER>=1300
#  pragma intrinsic(_byteswap_uint64,_byteswap_ulong)
#  define BSWAP8(x)	_byteswap_uint64((u64)(x))
#  define BSWAP4(x)	_byteswap_ulong((u32)(x))
# elif defined(_M_IX86)
   __inline u32 _bswap4(u32 val) {
	_asm mov eax,val
	_asm bswap eax
   }
#  define BSWAP4(x)	_bswap4(x)
# endif
#endif
#endif

#if defined(BSWAP4) && !defined(STRICT_ALIGNMENT)
#define GETU32(p)	BSWAP4(*(const u32 *)(p))
#define PUTU32(p,v)	*(u32 *)(p) = BSWAP4(v)
#else
#define GETU32(p)	((u32)(p)[0]<<24|(u32)(p)[1]<<16|(u32)(p)[2]<<8|(u32)(p)[3])
#define PUTU32(p,v)	((p)[0]=(u8)((v)>>24),(p)[1]=(u8)((v)>>16),(p)[2]=(u8)((v)>>8),(p)[3]=(u8)(v))
#endif

/* GCM definitions */

typedef struct { u64 hi,lo; } u128;

#ifdef	TABLE_BITS
#undef	TABLE_BITS
#endif
/*
 * Even though permitted values for TABLE_BITS are 8, 4 and 1, it should
 * never be set to 8. 8 is effectively reserved for testing purposes.
 * TABLE_BITS>1 are lookup-table-driven implementations referred to as
 * "Shoup's" in GCM specification. In other words OpenSSL does not cover
 * whole spectrum of possible table driven implementations. Why? In
 * non-"Shoup's" case memory access pattern is segmented in such manner,
 * that it's trivial to see that cache timing information can reveal
 * fair portion of intermediate hash value. Given that ciphertext is
 * always available to attacker, it's possible for him to attempt to
 * deduce secret parameter H and if successful, tamper with messages
 * [which is nothing but trivial in CTR mode]. In "Shoup's" case it's
 * not as trivial, but there is no reason to believe that it's resistant
 * to cache-timing attack. And the thing about "8-bit" implementation is
 * that it consumes 16 (sixteen) times more memory, 4KB per individual
 * key + 1KB shared. Well, on pros side it should be twice as fast as
 * "4-bit" version. And for gcc-generated x86[_64] code, "8-bit" version
 * was observed to run ~75% faster, closer to 100% for commercial
 * compilers... Yet "4-bit" procedure is preferred, because it's
 * believed to provide better security-performance balance and adequate
 * all-round performance. "All-round" refers to things like:
 *
 * - shorter setup time effectively improves overall timing for
 *   handling short messages;
 * - larger table allocation can become unbearable because of VM
 *   subsystem penalties (for example on Windows large enough free
 *   results in VM working set trimming, meaning that consequent
 *   malloc would immediately incur working set expansion);
 * - larger table has larger cache footprint, which can affect
 *   performance of other code paths (not necessarily even from same
 *   thread in Hyper-Threading world);
 */
#define	TABLE_BITS 4

struct gcm128_context {
	/* Following 6 names follow names in GCM specification */
	union { u64 u[2]; u32 d[4]; u8 c[16]; }	Yi,EKi,EK0,
						Xi,H,len;
	/* Pre-computed table used by gcm_gmult_* */
#if TABLE_BITS==8
	u128 Htable[256];
#else
	u128 Htable[16];
	void (*gmult)(u64 Xi[2],const u128 Htable[16]);
	void (*ghash)(u64 Xi[2],const u128 Htable[16],const u8 *inp,size_t len);
#endif
	unsigned int mres, ares;
	block128_f block;
	void *key;
};
