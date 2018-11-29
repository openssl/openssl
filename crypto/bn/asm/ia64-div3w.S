// Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
//
// Licensed under the OpenSSL license (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
// ====================================================================
// Written by Andy Polyakov, @dot-asm, initially for use in the OpenSSL
// project. The module is dual licensed under OpenSSL and CRYPTOGAMS
// licenses depending on where you obtain it. For further details see
// https://github.com/dot-asm/cryptogams/.
// ====================================================================

.explicit
.text

#if defined(_HPUX_SOURCE) && !defined(_LP64)
#define ADDP    addp4
#else
#define ADDP    add
#endif

.global	bn_div_3_words#
.proc	bn_div_3_words#
.align	64
bn_div_3_words:
	.prologue	
	.save		ar.pfs,r2
{ .mib;	alloc		r2=ar.pfs,3,0,0,0
	.save		ar.lc,r3
	mov		r3=ar.lc		}
	.body
{ .mib;	ADDP		r30=-8,r32
	ADDP		r31=0,r32
	brp.loop.imp	.Lctop,.Lcend-16	};;
{ .mmi;	ld8		r30=[r30]			// load R.lo
	ld8		r31=[r31]			// load R.hi
	mov		ar.lc=63		}
{ .mib	mov		r8=0				// Q = 0
	mov		ar.ec=1			};;
.Lctop:
{ .mfi;	(p0)	sub		r28=r30,r33		// R - D
	(p0)	cmp.ltu		p6,p7=r30,r33	}
{ .mfi;	(p0)	sub		r29=r31,r34
	(p0)	cmp.ltu		p8,p9=r31,r34	};;
{ .mmi;	(p6)	cmp.eq.or.andcm	p8,p9=r29,r0
	(p6)	sub		r29=r29,r0,1
	(p0)	shrp		r33=r34,r33,1	};;	// D >>= 1
{ .mmi;	(p9)	mov		r30=r28			// R or R - D?
	(p9)	mov		r31=r29
	(p0)	shr.u		r34=r34,1	}
{ .mib;	(p8)	add		r8=r8,r8		// Q <<= 1
	(p9)	add		r8=r8,r8,1
	br.ctop.sptk	.Lctop			};;
.Lcend:
{ .mmi;	cmp.ltu		p6,p7=r30,r33
	cmp.ltu		p8,p9=r31,r34
	sub		r29=r31,r34		};;
{ .mmi;
(p6)	cmp.eq.or.andcm	p8,p9=r29,r0
	shr		r9=r8,63		};;	// top bit -> mask
{ .mmi;
(p8)	add		r8=r8,r8			// Q <<= 1
(p9)	add		r8=r8,r8,1		};;
{ .mib;	or		r8=r8,r9			// all ones if overflow
	mov		ar.lc=r3
	br.ret.sptk.many	b0		};;
.endp	bn_div_3_words#
