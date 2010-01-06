#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# January 2010
#
# "Teaser" Montgomery multiplication module for IA-64. There are
# several possibilities for improvement:
#
# - modulo-scheduling outer loop would eliminate quite a number of
#   stalls after ldf8, xma and getf.sig outside inner loop and
#   improve shorter key performance;
# - shorter vector support [with input vectors being fetched only
#   once] should be added;
# - 2x unroll with help of n0[1] would make the code scalable on
#   "wider" IA-64, "wider" than Itanium 2 that is, which is not of
#   acute interest, because upcoming Tukwila's individual cores are
#   reportedly based on Itanium 2 design;
# - dedicated squaring procedure(?);
#
# So far 'openssl speed rsa dsa' output on 900MHz Itanium 2 *with*
# this module is:
#                   sign    verify    sign/s verify/s
# rsa  512 bits 0.000634s 0.000030s   1577.6  32877.3
# rsa 1024 bits 0.001246s 0.000058s    802.8  17181.5
# rsa 2048 bits 0.005908s 0.000148s    169.3   6754.0
# rsa 4096 bits 0.033456s 0.000469s     29.9   2133.6
# dsa  512 bits 0.000322s 0.000286s   3106.0   3499.0
# dsa 1024 bits 0.000585s 0.000607s   1708.4   1647.4
# dsa 2048 bits 0.001453s 0.001703s    688.1    587.4
#
# ... and *without*:
#
# rsa  512 bits 0.000670s 0.000041s   1491.8  24145.5
# rsa 1024 bits 0.001988s 0.000080s    502.9  12499.3
# rsa 2048 bits 0.008702s 0.000189s    114.9   5293.9
# rsa 4096 bits 0.043860s 0.000533s     22.8   1875.9
# dsa  512 bits 0.000441s 0.000427s   2265.3   2340.6
# dsa 1024 bits 0.000823s 0.000867s   1215.6   1153.2
# dsa 2048 bits 0.001894s 0.002179s    528.1    458.9
#
# 512-bit RSA sign performance does not improve, because this module
# doesn't handle short enough vectors (yet). Otherwise RSA sign
# improves by 60-30%, less for longer keys, while verify - by 35-13%.
# DSA performance improves by 40-30%.

if ($^O eq "hpux") {
    $ADDP="addp4";
    for (@ARGV) { $ADDP="add" if (/[\+DD|\-mlp]64/); }
} else { $ADDP="add"; }

$code=<<___;
.explicit
.text

// int bn_mul_mont (BN_ULONG *rp,const BN_ULONG *ap,
//		    const BN_ULONG *bp,const BN_ULONG *np,
//		    const BN_ULONG *n0p,int num);			
.global	bn_mul_mont#
.proc	bn_mul_mont#
prevsp=r2;
prevfs=r3;
prevlc=r10;
prevpr=r11;

rptr=r14;
aptr=r15;
bptr=r16;
nptr=r17;
tptr=r18;	// &tp[0]
tp_1=r19;	// &tp[-1]
num=r20;
len=r21;
topbit=r22;
lc=r23;

bi=f6;
n0=f7;
m0=f8;

.align	64
bn_mul_mont:
	.prologue
{ .mmi;	.save	ar.pfs,prevfs
	alloc	prevfs=ar.pfs,6,2,0,8
	$ADDP	aptr=0,in1
	.save	ar.lc,prevlc
	mov	prevlc=ar.lc		}
{ .mmi;	.vframe	prevsp
	mov	prevsp=sp
	$ADDP	bptr=0,in2
	cmp4.gt	p6,p0=5,in5		};;	// is num large enough?
{ .mfi;	nop.m	0				// align loop bodies
	nop.f	0
	nop.i	0			}
{ .mib;	mov	ret0=r0				// signal "unhandled"
	.save	pr,prevpr
	mov	prevpr=pr
(p6)	br.ret.dpnt.many	b0	};;

	.body
	.rotf		alo[6],nlo[4],ahi[8],nhi[6]
	.rotr		a[3],n[3],t[2]

{ .mmi;	ldf8		bi=[bptr],8		// (*bp++)
	ldf8		alo[4]=[aptr],16	// ap[0]
	$ADDP		r30=8,in1	};;
{ .mmi;	ldf8		alo[3]=[r30],16		// ap[1]
	ldf8		alo[2]=[aptr],16	// ap[2]
	$ADDP		in4=0,in4	};;
{ .mmi;	ldf8		alo[1]=[r30]		// ap[3]
	ldf8		n0=[in4]		// n0
	$ADDP		rptr=0,in0		}
{ .mmi;	$ADDP		nptr=0,in3
	mov		r31=16
	zxt4		num=in5		};;
{ .mmi;	ldf8		nlo[2]=[nptr],8		// np[0]
	shladd		len=num,3,r0
	shladd		r31=num,3,r31	};;
{ .mmi;	ldf8		nlo[1]=[nptr],8		// np[1]
	add		lc=-5,num
	sub		r31=sp,r31	};;
{ .mfb;	and		sp=-16,r31		// alloca
	xmpy.hu		ahi[2]=alo[4],bi	// ap[0]*bp[0]
	nop.b		0		}
{ .mfb;	nop.m		0
	xmpy.lu		alo[4]=alo[4],bi
	brp.loop.imp	.L1st_ctop,.L1st_cend-16
					};;
{ .mfi;	nop.m		0
	xma.hu		ahi[1]=alo[3],bi,ahi[2]	// ap[1]*bp[0]
	$ADDP		tp_1=8,sp	}
{ .mfi;	nop.m		0
	xma.lu		alo[3]=alo[3],bi,ahi[2]
	mov		pr.rot=0x20001f<<16
			// ------^----- (p40) at first (p23)
			// ----------^^ p[16:20]=1
					};;
{ .mfi;	nop.m		0
	xmpy.lu		m0=alo[4],n0		// (ap[0]*bp[0])*n0
	mov		ar.lc=lc	}
{ .mfi;	nop.m		0
	fcvt.fxu.s1	nhi[1]=f0
	mov		ar.ec=8		};;

.align	32
.L1st_ctop:
.pred.rel	"mutex",p40,p42
{ .mfi;	(p16)	ldf8		alo[0]=[aptr],8		    // *(aptr++)
	(p18)	xma.hu		ahi[0]=alo[2],bi,ahi[1]
	(p40)	add		n[2]=n[2],a[2]		}   // (p23)					}
{ .mfi;	(p18)	ldf8		nlo[0]=[nptr],8		    // *(nptr++)(p16)
	(p18)	xma.lu		alo[2]=alo[2],bi,ahi[1]
	(p42)	add		n[2]=n[2],a[2],1	};; // (p23)
{ .mfi;	(p21)	getf.sig	a[0]=alo[5]
	(p20)	xma.hu		nhi[0]=nlo[2],m0,nhi[1]
	(p42)	cmp.leu		p41,p39=n[2],a[2]   	}   // (p23)
{ .mfi;	(p23)	st8		[tp_1]=n[2],8
	(p20)	xma.lu		nlo[2]=nlo[2],m0,nhi[1]
	(p40)	cmp.ltu		p41,p39=n[2],a[2]	}   // (p23)
{ .mmb;	(p21)	getf.sig	n[0]=nlo[3]
	(p16)	nop.m		0
	br.ctop.sptk	.L1st_ctop			};;
.L1st_cend:

{ .mmi;	getf.sig	a[0]=ahi[6]		// (p24)
	getf.sig	n[0]=nhi[4]
	add		num=-1,num	};;	// num--
{ .mmi;	.pred.rel	"mutex",p40,p42
(p40)	add		n[0]=n[0],a[0]
(p42)	add		n[0]=n[0],a[0],1
	sub		aptr=aptr,len	};;	// rewind
{ .mmi;	.pred.rel	"mutex",p40,p42
(p40)	cmp.ltu		p41,p39=n[0],a[0]
(p42)	cmp.leu		p41,p39=n[0],a[0]
	sub		nptr=nptr,len	};;
{ .mmi;	.pred.rel	"mutex",p39,p41
(p39)	add		topbit=r0,r0
(p41)	add		topbit=r0,r0,1
	nop.i		0		}	
{ .mmi;	st8		[tp_1]=n[0]
	$ADDP		tptr=16,sp
	$ADDP		tp_1=8,sp	};;
___

$code.=<<___;
.Louter:
{ .mmi;	ldf8		bi=[bptr],8		// (*bp++)
	ldf8		ahi[3]=[tptr]		// tp[0]
	add		r30=8,aptr	};;
{ .mmi;	ldf8		alo[4]=[aptr],16	// ap[0]
	ldf8		alo[3]=[r30],16		// ap[1]
	add		r31=8,nptr	};;
{ .mfb;	ldf8		alo[2]=[aptr],16	// ap[2]
	xma.hu		ahi[2]=alo[4],bi,ahi[3]	// ap[0]*bp[i]+tp[0]
	brp.loop.imp	.Linner_ctop,.Linner_cend-16
					}
{ .mfb;	ldf8		alo[1]=[r30]		// ap[3]
	xma.lu		alo[4]=alo[4],bi,ahi[3]
	clrrrb.pr			};;
{ .mfi;	ldf8		nlo[2]=[nptr],16	// np[0]
	xma.hu		ahi[1]=alo[3],bi,ahi[2]	// ap[1]*bp[i]
	nop.i		0		}
{ .mfi;	ldf8		nlo[1]=[r31]		// np[1]
	xma.lu		alo[3]=alo[3],bi,ahi[2]
	mov		pr.rot=0x20101f<<16
			// ------^----- (p40) at first (p23)
			// --------^--- (p30) at first (p22)
			// ----------^^ p[16:20]=1
					};;
{ .mfi;	st8		[tptr]=r0		// tp[0] is already accounted
	xmpy.lu		m0=alo[4],n0		// (ap[0]*bp[i]+tp[0])*n0
	mov		ar.lc=lc	}
{ .mfi;
	fcvt.fxu.s1	nhi[1]=f0
	mov		ar.ec=8		};;

// This loop spins in 4*(n+7) ticks on Itanium 2 and should spin in
// 7*(n+7) ticks on Itanium (the one codenamed Merced). Factor of 7
// in latter case accounts for two-tick pipeline stall, which means
// that its performance would be ~20% lower than optimal one. No
// attempt was made to address this, because original Itanium is
// hardly represented out in the wild...
.align	32
.Linner_ctop:
.pred.rel	"mutex",p40,p42
.pred.rel	"mutex",p30,p32
{ .mfi;	(p16)	ldf8		alo[0]=[aptr],8		    // *(aptr++)
	(p18)	xma.hu		ahi[0]=alo[2],bi,ahi[1]
	(p40)	add		n[2]=n[2],a[2]		}   // (p23)
{ .mfi;	(p16)	nop.m		0
	(p18)	xma.lu		alo[2]=alo[2],bi,ahi[1]
	(p42)	add		n[2]=n[2],a[2],1	};; // (p23)
{ .mfi;	(p21)	getf.sig	a[0]=alo[5]
	(p16)	nop.f		0
	(p40)	cmp.ltu		p41,p39=n[2],a[2]	}   // (p23)
{ .mfi;	(p21)	ld8		t[0]=[tptr],8
	(p16)	nop.f		0
	(p42)	cmp.leu		p41,p39=n[2],a[2]	};; // (p23)
{ .mfi;	(p18)	ldf8		nlo[0]=[nptr],8		    // *(nptr++)
	(p20)	xma.hu		nhi[0]=nlo[2],m0,nhi[1]
	(p30)	add		a[1]=a[1],t[1]		}   // (p22)
{ .mfi;	(p16)	nop.m		0
	(p20)	xma.lu		nlo[2]=nlo[2],m0,nhi[1]
	(p32)	add		a[1]=a[1],t[1],1	};; // (p22)
{ .mmi;	(p21)	getf.sig	n[0]=nlo[3]
	(p16)	nop.m		0
	(p30)	cmp.ltu		p31,p29=a[1],t[1]	}   // (p22)
{ .mmb;	(p23)	st8		[tp_1]=n[2],8
	(p32)	cmp.leu		p31,p29=a[1],t[1]	    // (p22)
	br.ctop.sptk	.Linner_ctop			};;
.Linner_cend:

{ .mmi;	getf.sig	a[0]=ahi[6]		// (p24)
	getf.sig	n[0]=nhi[4]
	nop.i		0		};;

{ .mmi;	.pred.rel	"mutex",p31,p33
(p31)	add		a[0]=a[0],topbit
(p33)	add		a[0]=a[0],topbit,1
	mov		topbit=r0	};;
{ .mfi; .pred.rel	"mutex",p31,p33
(p31)	cmp.ltu		p32,p30=a[0],topbit
(p33)	cmp.leu		p32,p30=a[0],topbit
					}
{ .mfi;	.pred.rel	"mutex",p40,p42
(p40)	add		n[0]=n[0],a[0]
(p42)	add		n[0]=n[0],a[0],1
					};;
{ .mmi;	.pred.rel	"mutex",p44,p46
(p40)	cmp.ltu		p41,p39=n[0],a[0]
(p42)	cmp.leu		p41,p39=n[0],a[0]
(p32)	add		topbit=r0,r0,1	}

{ .mmi;	st8		[tp_1]=n[0],8
	cmp4.ne		p6,p0=1,num
	sub		aptr=aptr,len	};;	// rewind
{ .mmi;	sub		nptr=nptr,len
(p41)	add		topbit=r0,r0,1
	$ADDP		tptr=16,sp	}
{ .mmb;	$ADDP		tp_1=8,sp
	add		num=-1,num		// num--
(p6)	br.cond.sptk.many	.Louter	};;

{ .mbb;	add		lc=4,lc
	brp.loop.imp	.Lsub_ctop,.Lsub_cend-16
	clrrrb.pr			};;
{ .mii;	nop.m		0
	mov		pr.rot=0x10001<<16
			// ------^---- (p33) at first (p17)
	mov		ar.lc=lc	}
{ .mii;	nop.m		0
	mov		ar.ec=3
	nop.i		0		};;

.Lsub_ctop:
.pred.rel	"mutex",p33,p35
{ .mfi;	(p16)	ld8		t[0]=[tptr],8		    // t=*(tp++)
	(p16)	nop.f		0
	(p33)	sub		n[1]=t[1],n[1]		}   // (p17)
{ .mfi;	(p16)	ld8		n[0]=[nptr],8		    // n=*(np++)
	(p16)	nop.f		0
	(p35)	sub		n[1]=t[1],n[1],1	};; // (p17)
{ .mib;	(p18)	st8		[rptr]=n[2],8		    // *(rp++)=r
	(p33)	cmp.gtu		p34,p32=n[1],t[1]	    // (p17)
	(p18)	nop.b		0			}
{ .mib;	(p18)	nop.m		0
	(p35)	cmp.geu		p34,p32=n[1],t[1]	    // (p17)
	br.ctop.sptk	.Lsub_ctop			};;
.Lsub_cend:

{ .mmb;	.pred.rel	"mutex",p34,p36
(p34)	sub	topbit=topbit,r0	// (p19)
(p36)	sub	topbit=topbit,r0,1
	brp.loop.imp	.Lcopy_ctop,.Lcopy_cend-16
					}
{ .mmb;	sub	rptr=rptr,len		// rewind
	sub	tptr=tptr,len
	clrrrb.pr			};;
{ .mmi;	and	aptr=tptr,topbit
	andcm	bptr=rptr,topbit
	mov	pr.rot=1<<16		};;
{ .mii;	or	nptr=aptr,bptr
	mov	ar.lc=lc
	mov	ar.ec=3			};;

.Lcopy_ctop:
{ .mmb;	(p16)	ld8	n[0]=[nptr],8
	(p18)	st8	[tptr]=r0,8
	(p16)	nop.b	0		}
{ .mmb;	(p16)	nop.m	0
	(p18)	st8	[rptr]=n[2],8
	br.ctop.sptk	.Lcopy_ctop	};;
.Lcopy_cend:

{ .mmi;	mov		ret0=1			// signal "handled"
	rum		1<<5			// clear um.mfh
	mov		ar.lc=prevlc	}
{ .mib;	.restore	sp
	mov		sp=prevsp
	mov		pr=prevpr,-2
	br.ret.sptk.many	b0	};;
.endp	bn_mul_mont
.type	copyright#,\@object
copyright:
stringz	"Montgomery multiplication for IA-64, CRYPTOGAMS by <appro\@openssl.org>"
___

$output=shift and open STDOUT,">$output";
print $code;
close STDOUT;
