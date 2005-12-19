#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. Rights for redistribution and usage in source and binary
# forms are granted according to the OpenSSL license.
# ====================================================================

# October 2005
#
# "Teaser" Montgomery multiplication module for UltraSPARC. Why FPU?
# Because unlike integer multiplier, which simply stalls whole CPU,
# FPU is fully pipelined and can effectively emit 48 bit partial
# product every cycle. Why not blended SPARC v9? One can argue that
# making this module dependent on UltraSPARC VIS extension limits its
# binary compatibility. Well yes, it does exclude SPARC64 prior-V(!)
# implementations from compatibility matrix. But the rest, whole Sun
# UltraSPARC family and brand new Fujitsu's SPARC64 V, all support
# VIS extension instructions used in this module. This is considered
# good enough to recommend HAL SPARC64 users [if any] to simply fall
# down to no-asm configuration.

# USI&II cores currently exhibit uniform 2x improvement [over pre-
# bn_mul_mont codebase] for all key lengths and benchmarks. On USIII
# performance improves few percents for shorter keys and worsens few
# percents for longer keys. This is because USIII integer multiplier
# is >3x faster than USI&II one, which is harder to match [but see
# TODO list below]. It should also be noted that SPARC64 V features
# out-of-order execution, which *might* mean that integer multiplier
# is pipelined, which in turn *might* be impossible to match... On
# additional note, SPARC64 V implements FP Multiply-Add instruction,
# which is perfectly usable in this context... In other words, as far
# as HAL/Fujitsu SPARC64 family goes, talk to the author:-)

# The implementation implies following "non-natural" limitations on
# input arguments:
# - num may not be less than 4;
# - num has to be even;
# - ap, bp, rp, np has to be 64-bit aligned [which is not a problem
#   as long as BIGNUM.d are malloc-ated];
# Failure to meet either condition has no fatal effects, simply
# doesn't give any performance gain.

# TODO:
# - modulo-schedule inner loop for better performance (on in-order
#   execution core such as UltraSPARC this shall result in further
#   noticeable(!) improvement);
# - dedicated squaring procedure[?];

$fname="bn_mul_mont_fpu";
$bits=32;
for (@ARGV) { $bits=64 if (/\-m64/ || /\-xarch\=v9/); }

if ($bits==64) {
	$bias=2047;
	$frame=192;
} else {
	$bias=0;
	$frame=128;	# 96 rounded up to largest known cache-line
}
$locals=64;

# In order to provide for 32-/64-bit ABI duality, I keep integers wider
# than 32 bit in %g1-%g4 and %o0-%o5. %l0-%l7 and %i0-%i5 are used
# exclusively for pointers, indexes and other small values...
# int bn_mul_mont(
$rp="%i0";	# BN_ULONG *rp,
$ap="%i1";	# const BN_ULONG *ap,
$bp="%i2";	# const BN_ULONG *bp,
$np="%i3";	# const BN_ULONG *np,
$n0="%i4";	# const BN_ULONG *n0,
$num="%i5";	# int num);

$tp="%l0";	# t[num]
$ap_l="%l1";	# a[num],n[num] are smashed to 32-bit words and saved
$ap_h="%l2";	# to these four vectors as double-precision FP values.
$np_l="%l3";	# This way a bunch of fxtods are eliminated in second
$np_h="%l4";	# loop and L1-cache aliasing is minimized...
$i="%l5";
$j="%l6";
$mask="%l7";	# 16-bit mask, 0xffff

$n0="%g4";	# reassigned(!) to "64-bit" register
$carry="%i4";	# %i4 reused(!) for a carry bit

# FP register naming chart
#
#     ..HILO
#       dcba
#   --------
#        LOa
#       LOb
#      LOc
#     LOd
#      HIa
#     HIb
#    HIc
#   HId
#    ..a
#   ..b
$ba="%f0";    $bb="%f2";    $bc="%f4";    $bd="%f6";
$na="%f8";    $nb="%f10";   $nc="%f12";   $nd="%f14";
$alo="%f16";  $alo_="%f17"; $ahi="%f18";  $ahi_="%f19";
$nlo="%f20";  $nlo_="%f21"; $nhi="%f22";  $nhi_="%f23";

$dota="%f24"; $dotb="%f26";

$aloa="%f32"; $alob="%f34"; $aloc="%f36"; $alod="%f38";
$ahia="%f40"; $ahib="%f42"; $ahic="%f44"; $ahid="%f46";
$nloa="%f48"; $nlob="%f50"; $nloc="%f52"; $nlod="%f54";
$nhia="%f56"; $nhib="%f58"; $nhic="%f60"; $nhid="%f62";

$ASI_FL16_P=0xD2;	# magic ASI value to engage 16-bit FP load

$code=<<___;
.ident		"UltraSPARC Montgomery multiply by <appro\@fy.chalmers.se>"
.section	".text",#alloc,#execinstr

.global $fname
.align  32
$fname:
	save	%sp,-$frame-$locals,%sp
	sethi	%hi(0xffff),$mask
	or	$mask,%lo(0xffff),$mask

	cmp	$num,4
	bl,a,pn %icc,.Lret
	clr	%i0
	andcc	$num,1,%g0		! $num has to be even...
	bnz,a,pn %icc,.Lret
	clr	%i0			! signal "unsupported input value"
	or	$bp,$ap,%l0
	srl	$num,1,$num
	or	$rp,$np,%l1
	or	%l0,%l1,%l0
	andcc	%l0,7,%g0		! ...and pointers has to be 8-byte aligned
	bnz,a,pn %icc,.Lret
	clr	%i0			! signal "unsupported input value"
	ld	[%i4+0],$n0		! $n0 reassigned, remember?
	ld	[%i4+4],%o0
	sllx	%o0,32,%o0
	or	%o0,$n0,$n0		! $n0=n0[1].n0[0]

	sll	$num,3,$num		! num*=8

	add	%sp,$bias,%o0		! real top of stack
	sll	$num,2,%o1
	add	%o1,$num,%o1		! %o1=num*5
	sub	%o0,%o1,%o0
	and	%o0,-2048,%o0		! optimize TLB utilization
	sub	%o0,$bias,%sp		! alloca(5*num*8)

	rd	%asi,%o7		! save %asi
	add	%sp,$bias+$frame+$locals,$tp
	add	$tp,$num,$ap_l
	add	$ap_l,$num,$ap_l	! [an]p_[lh] point at the vectors' ends !
	add	$ap_l,$num,$ap_h
	add	$ap_h,$num,$np_l
	add	$np_l,$num,$np_h

	wr	%g0,$ASI_FL16_P,%asi	! setup %asi for 16-bit FP loads

	add	$rp,$num,$rp		! readjust input pointers to point
	add	$ap,$num,$ap		! at the ends too...
	add	$bp,$num,$bp
	add	$np,$num,$np

	stx	%o7,[%sp+$bias+$frame+48]	! save %asi

	sub	%g0,$num,$i		! i=-num
	sub	%g0,$num,$j		! j=-num

	add	$ap,$j,%o3
	add	$bp,$i,%o4

	ldx	[$bp+$i],%o0		! bp[0]
	ldx	[$ap+$j],%o1		! ap[0]
	sllx	%o0,32,%g1
	sllx	%o1,32,%g5
	srlx	%o0,32,%o0
	srlx	%o1,32,%o1
	or	%g1,%o0,%o0
	or	%g5,%o1,%o1

	add	$np,$j,%o5

	mulx	%o1,%o0,%o0		! ap[0]*bp[0]
	mulx	$n0,%o0,%o0		! ap[0]*bp[0]*n0
	stx	%o0,[%sp+$bias+$frame+0]

	ld	[%o3+0],$alo_	! load a[j] as pair of 32-bit words
	fzeros	$alo
	ld	[%o3+4],$ahi_
	fzeros	$ahi
	ld	[%o5+0],$nlo_	! load n[j] as pair of 32-bit words
	fzeros	$nlo
	ld	[%o5+4],$nhi_
	fzeros	$nhi

	! transfer b[i] to FPU as 4x16-bit values
	ldda	[%o4+2]%asi,$ba
	fxtod	$alo,$alo
	ldda	[%o4+0]%asi,$bb
	fxtod	$ahi,$ahi
	ldda	[%o4+6]%asi,$bc
	fxtod	$nlo,$nlo
	ldda	[%o4+4]%asi,$bd
	fxtod	$nhi,$nhi

	! transfer ap[0]*b[0]*n0 to FPU as 4x16-bit values
	ldda	[%sp+$bias+$frame+6]%asi,$na
	fxtod	$ba,$ba
	ldda	[%sp+$bias+$frame+4]%asi,$nb
	fxtod	$bb,$bb
	ldda	[%sp+$bias+$frame+2]%asi,$nc
	fxtod	$bc,$bc
	ldda	[%sp+$bias+$frame+0]%asi,$nd
	fxtod	$bd,$bd

	std	$alo,[$ap_l+$j]		! save smashed ap[j] in double format
	fxtod	$na,$na
	std	$ahi,[$ap_h+$j]
	fxtod	$nb,$nb
	std	$nlo,[$np_l+$j]		! save smashed np[j] in double format
	fxtod	$nc,$nc
	std	$nhi,[$np_h+$j]
	fxtod	$nd,$nd

		fmuld	$alo,$ba,$aloa
		fmuld	$nlo,$na,$nloa
		fmuld	$alo,$bb,$alob
		fmuld	$nlo,$nb,$nlob
		fmuld	$alo,$bc,$aloc
	faddd	$aloa,$nloa,$nloa
		fmuld	$nlo,$nc,$nloc
		fmuld	$alo,$bd,$alod
	faddd	$alob,$nlob,$nlob
		fmuld	$nlo,$nd,$nlod
		fmuld	$ahi,$ba,$ahia
	faddd	$aloc,$nloc,$nloc
		fmuld	$nhi,$na,$nhia
		fmuld	$ahi,$bb,$ahib
	faddd	$alod,$nlod,$nlod
		fmuld	$nhi,$nb,$nhib
		fmuld	$ahi,$bc,$ahic
	faddd	$ahia,$nhia,$nhia
		fmuld	$nhi,$nc,$nhic
		fmuld	$ahi,$bd,$ahid
	faddd	$ahib,$nhib,$nhib
		fmuld	$nhi,$nd,$nhid

	faddd	$ahic,$nhic,$dota	! $nhic
	faddd	$ahid,$nhid,$dotb	! $nhid

	faddd	$nloc,$nhia,$nloc
	faddd	$nlod,$nhib,$nlod

	fdtox	$nloa,$nloa
	fdtox	$nlob,$nlob
	fdtox	$nloc,$nloc
	fdtox	$nlod,$nlod

	std	$nloa,[%sp+$bias+$frame+0]
	std	$nlob,[%sp+$bias+$frame+8]
	std	$nloc,[%sp+$bias+$frame+16]
	std	$nlod,[%sp+$bias+$frame+24]
	ldx	[%sp+$bias+$frame+0],%o0
	ldx	[%sp+$bias+$frame+8],%o1
	ldx	[%sp+$bias+$frame+16],%o2
	ldx	[%sp+$bias+$frame+24],%o3

	srlx	%o0,16,%o7
	add	%o7,%o1,%o1
	srlx	%o1,16,%o7
	add	%o7,%o2,%o2
	srlx	%o2,16,%o7
	add	%o7,%o3,%o3		! %o3.%o2[0..15].%o1[0..15].%o0[0..15]
	!and	%o0,$mask,%o0
	!and	%o1,$mask,%o1
	!and	%o2,$mask,%o2
	!sllx	%o1,16,%o1
	!sllx	%o2,32,%o2
	!sllx	%o3,48,%o7
	!or	%o1,%o0,%o0
	!or	%o2,%o0,%o0
	!or	%o7,%o0,%o0		! 64-bit result
	srlx	%o3,16,%g1		! 34-bit carry

	ba	.L1st
	add	$j,8,$j
.align	32
.L1st:
	add	$ap,$j,%o3
	add	$np,$j,%o4
	ld	[%o3+0],$alo_	! load a[j] as pair of 32-bit words
	fzeros	$alo
	ld	[%o3+4],$ahi_
	fzeros	$ahi
	ld	[%o4+0],$nlo_	! load n[j] as pair of 32-bit words
	fzeros	$nlo
	ld	[%o4+4],$nhi_
	fzeros	$nhi

	fxtod	$alo,$alo
	fxtod	$ahi,$ahi
	fxtod	$nlo,$nlo
	fxtod	$nhi,$nhi

	std	$alo,[$ap_l+$j]		! save smashed ap[j] in double format
		fmuld	$alo,$ba,$aloa
	std	$ahi,[$ap_h+$j]
		fmuld	$nlo,$na,$nloa
	std	$nlo,[$np_l+$j]		! save smashed np[j] in double format
		fmuld	$alo,$bb,$alob
	std	$nhi,[$np_h+$j]
		fmuld	$nlo,$nb,$nlob
		fmuld	$alo,$bc,$aloc
	faddd	$aloa,$nloa,$nloa
		fmuld	$nlo,$nc,$nloc
		fmuld	$alo,$bd,$alod
	faddd	$alob,$nlob,$nlob
		fmuld	$nlo,$nd,$nlod
		fmuld	$ahi,$ba,$ahia
	faddd	$aloc,$nloc,$nloc
		fmuld	$nhi,$na,$nhia
		fmuld	$ahi,$bb,$ahib
	faddd	$alod,$nlod,$nlod
		fmuld	$nhi,$nb,$nhib
		fmuld	$ahi,$bc,$ahic
	faddd	$ahia,$nhia,$nhia
		fmuld	$nhi,$nc,$nhic
		fmuld	$ahi,$bd,$ahid
	faddd	$ahib,$nhib,$nhib
		fmuld	$nhi,$nd,$nhid

	faddd	$dota,$nloa,$nloa
	faddd	$dotb,$nlob,$nlob
	faddd	$ahic,$nhic,$dota	! $nhic
	faddd	$ahid,$nhid,$dotb	! $nhid

	faddd	$nloc,$nhia,$nloc
	faddd	$nlod,$nhib,$nlod

	fdtox	$nloa,$nloa
	fdtox	$nlob,$nlob
	fdtox	$nloc,$nloc
	fdtox	$nlod,$nlod

	std	$nloa,[%sp+$bias+$frame+0]
	std	$nlob,[%sp+$bias+$frame+8]
	std	$nloc,[%sp+$bias+$frame+16]
	std	$nlod,[%sp+$bias+$frame+24]
	ldx	[%sp+$bias+$frame+0],%o0
	ldx	[%sp+$bias+$frame+8],%o1
	ldx	[%sp+$bias+$frame+16],%o2
	ldx	[%sp+$bias+$frame+24],%o3

	srlx	%o0,16,%o7
	add	%o7,%o1,%o1
	srlx	%o1,16,%o7
	add	%o7,%o2,%o2
	srlx	%o2,16,%o7
	add	%o7,%o3,%o3		! %o3.%o2[0..15].%o1[0..15].%o0[0..15]
	and	%o0,$mask,%o0
	and	%o1,$mask,%o1
	and	%o2,$mask,%o2
	sllx	%o1,16,%o1
	sllx	%o2,32,%o2
	sllx	%o3,48,%o7
	or	%o1,%o0,%o0
	or	%o2,%o0,%o0
	or	%o7,%o0,%o0		! 64-bit result
	addcc	%g1,%o0,%o0
	srlx	%o3,16,%g1		! 34-bit carry
	bcs,a	%xcc,.+8
	add	%g1,1,%g1

	stx	%o0,[$tp]		! tp[j-1]=
	addcc	$j,8,$j
	bnz,pt	%icc,.L1st
	add	$tp,8,$tp

	fdtox	$dota,$dota
	fdtox	$dotb,$dotb
	std	$dota,[%sp+$bias+$frame+32]
	std	$dotb,[%sp+$bias+$frame+40]
	ldx	[%sp+$bias+$frame+32],%o0
	ldx	[%sp+$bias+$frame+40],%o1

	srlx	%o0,16,%o7
	add	%o7,%o1,%o1
	and	%o0,$mask,%o0
	sllx	%o1,16,%o7
	or	%o7,%o0,%o0
	addcc	%g1,%o0,%o0
	srlx	%o1,48,%g1
	bcs,a	%xcc,.+8
	add	%g1,1,%g1

	mov	%g1,$carry
	stx	%o0,[$tp]		! tp[num-1]=

	ba	.Louter
	add	$i,8,$i
.align	32
.Louter:
	sub	%g0,$num,$j		! j=-num
	add	%sp,$bias+$frame+$locals,$tp

	add	$bp,$i,%o4

	ldx	[$bp+$i],%o0		! bp[i]
	ldx	[$ap+$j],%o1		! ap[0]
	sllx	%o0,32,%g1
	sllx	%o1,32,%g5
	srlx	%o0,32,%o0
	srlx	%o1,32,%o1
	or	%g1,%o0,%o0
	or	%g5,%o1,%o1

	ldx	[$tp],%o2		! tp[0]
	mulx	%o1,%o0,%o0
	addcc	%o2,%o0,%o0
	mulx	$n0,%o0,%o0		! (ap[0]*bp[i]+t[0])*n0
	stx	%o0,[%sp+$bias+$frame+0]

	! transfer b[i] to FPU as 4x16-bit values
	ldda	[%o4+2]%asi,$ba
	ldda	[%o4+0]%asi,$bb
	ldda	[%o4+6]%asi,$bc
	ldda	[%o4+4]%asi,$bd

	! transfer (ap[0]*b[i]+t[0])*n0 to FPU as 4x16-bit values
	ldda	[%sp+$bias+$frame+6]%asi,$na
	fxtod	$ba,$ba
	ldda	[%sp+$bias+$frame+4]%asi,$nb
	fxtod	$bb,$bb
	ldda	[%sp+$bias+$frame+2]%asi,$nc
	fxtod	$bc,$bc
	ldda	[%sp+$bias+$frame+0]%asi,$nd
	fxtod	$bd,$bd
	ldd	[$ap_l+$j],$alo		! load a[j] in double format
	fxtod	$na,$na
	ldd	[$ap_h+$j],$ahi
	fxtod	$nb,$nb
	ldd	[$np_l+$j],$nlo		! load n[j] in double format
	fxtod	$nc,$nc
	ldd	[$np_h+$j],$nhi
	fxtod	$nd,$nd

		fmuld	$alo,$ba,$aloa
		fmuld	$nlo,$na,$nloa
		fmuld	$alo,$bb,$alob
		fmuld	$nlo,$nb,$nlob
		fmuld	$alo,$bc,$aloc
	faddd	$aloa,$nloa,$nloa
		fmuld	$nlo,$nc,$nloc
		fmuld	$alo,$bd,$alod
	faddd	$alob,$nlob,$nlob
		fmuld	$nlo,$nd,$nlod
		fmuld	$ahi,$ba,$ahia
	faddd	$aloc,$nloc,$nloc
		fmuld	$nhi,$na,$nhia
		fmuld	$ahi,$bb,$ahib
	faddd	$alod,$nlod,$nlod
		fmuld	$nhi,$nb,$nhib
		fmuld	$ahi,$bc,$ahic
	faddd	$ahia,$nhia,$nhia
		fmuld	$nhi,$nc,$nhic
		fmuld	$ahi,$bd,$ahid
	faddd	$ahib,$nhib,$nhib
		fmuld	$nhi,$nd,$nhid

	faddd	$ahic,$nhic,$dota	! $nhic
	faddd	$ahid,$nhid,$dotb	! $nhid

	faddd	$nloc,$nhia,$nloc
	faddd	$nlod,$nhib,$nlod

	fdtox	$nloa,$nloa
	fdtox	$nlob,$nlob
	fdtox	$nloc,$nloc
	fdtox	$nlod,$nlod

	std	$nloa,[%sp+$bias+$frame+0]
	std	$nlob,[%sp+$bias+$frame+8]
	std	$nloc,[%sp+$bias+$frame+16]
	std	$nlod,[%sp+$bias+$frame+24]
	ldx	[%sp+$bias+$frame+0],%o0
	ldx	[%sp+$bias+$frame+8],%o1
	ldx	[%sp+$bias+$frame+16],%o2
	ldx	[%sp+$bias+$frame+24],%o3

	srlx	%o0,16,%o7
	add	%o7,%o1,%o1
	srlx	%o1,16,%o7
	add	%o7,%o2,%o2
	srlx	%o2,16,%o7
	add	%o7,%o3,%o3		! %o3.%o2[0..15].%o1[0..15].%o0[0..15]
	! why?
	and	%o0,$mask,%o0
	and	%o1,$mask,%o1
	and	%o2,$mask,%o2
	sllx	%o1,16,%o1
	sllx	%o2,32,%o2
	sllx	%o3,48,%o7
	or	%o1,%o0,%o0
	or	%o2,%o0,%o0
	or	%o7,%o0,%o0		! 64-bit result
	ldx	[$tp],%o7
	addcc	%o7,%o0,%o0
	! end-of-why?
	srlx	%o3,16,%g1		! 34-bit carry
	bcs,a	%xcc,.+8
	add	%g1,1,%g1

	ba	.Linner
	add	$j,8,$j
.align	32
.Linner:
	ldd	[$ap_l+$j],$alo		! load a[j] in double format
	ldd	[$ap_h+$j],$ahi
	ldd	[$np_l+$j],$nlo		! load n[j] in double format
	ldd	[$np_h+$j],$nhi

		fmuld	$alo,$ba,$aloa
		fmuld	$nlo,$na,$nloa
		fmuld	$alo,$bb,$alob
		fmuld	$nlo,$nb,$nlob
		fmuld	$alo,$bc,$aloc
	faddd	$aloa,$nloa,$nloa
		fmuld	$nlo,$nc,$nloc
		fmuld	$alo,$bd,$alod
	faddd	$alob,$nlob,$nlob
		fmuld	$nlo,$nd,$nlod
		fmuld	$ahi,$ba,$ahia
	faddd	$aloc,$nloc,$nloc
		fmuld	$nhi,$na,$nhia
		fmuld	$ahi,$bb,$ahib
	faddd	$alod,$nlod,$nlod
		fmuld	$nhi,$nb,$nhib
		fmuld	$ahi,$bc,$ahic
	faddd	$ahia,$nhia,$nhia
		fmuld	$nhi,$nc,$nhic
		fmuld	$ahi,$bd,$ahid
	faddd	$ahib,$nhib,$nhib
		fmuld	$nhi,$nd,$nhid

	faddd	$dota,$nloa,$nloa
	faddd	$dotb,$nlob,$nlob
	faddd	$ahic,$nhic,$dota	! $nhic
	faddd	$ahid,$nhid,$dotb	! $nhid

	faddd	$nloc,$nhia,$nloc
	faddd	$nlod,$nhib,$nlod

	fdtox	$nloa,$nloa
	fdtox	$nlob,$nlob
	fdtox	$nloc,$nloc
	fdtox	$nlod,$nlod

	std	$nloa,[%sp+$bias+$frame+0]
	std	$nlob,[%sp+$bias+$frame+8]
	std	$nloc,[%sp+$bias+$frame+16]
	std	$nlod,[%sp+$bias+$frame+24]
	ldx	[%sp+$bias+$frame+0],%o0
	ldx	[%sp+$bias+$frame+8],%o1
	ldx	[%sp+$bias+$frame+16],%o2
	ldx	[%sp+$bias+$frame+24],%o3

	srlx	%o0,16,%o7
	add	%o7,%o1,%o1
	srlx	%o1,16,%o7
	add	%o7,%o2,%o2
	srlx	%o2,16,%o7
	add	%o7,%o3,%o3		! %o3.%o2[0..15].%o1[0..15].%o0[0..15]
	and	%o0,$mask,%o0
	and	%o1,$mask,%o1
	and	%o2,$mask,%o2
	sllx	%o1,16,%o1
	sllx	%o2,32,%o2
	sllx	%o3,48,%o7
	or	%o1,%o0,%o0
	or	%o2,%o0,%o0
	or	%o7,%o0,%o0		! 64-bit result
	addcc	%g1,%o0,%o0
	srlx	%o3,16,%g1		! 34-bit carry
	bcs,a	%xcc,.+8
	add	%g1,1,%g1

	ldx	[$tp+8],%o7		! tp[j]
	addcc	%o7,%o0,%o0
	bcs,a	%xcc,.+8
	add	%g1,1,%g1

	stx	%o0,[$tp]		! tp[j-1]
	addcc	$j,8,$j
	bnz,pt	%icc,.Linner
	add	$tp,8,$tp

	fdtox	$dota,$dota
	fdtox	$dotb,$dotb
	std	$dota,[%sp+$bias+$frame+32]
	std	$dotb,[%sp+$bias+$frame+40]
	ldx	[%sp+$bias+$frame+32],%o0
	ldx	[%sp+$bias+$frame+40],%o1

	srlx	%o0,16,%o7
	add	%o7,%o1,%o1
	and	%o0,$mask,%o0
	sllx	%o1,16,%o7
	or	%o7,%o0,%o0
	addcc	%g1,%o0,%o0
	srlx	%o1,48,%g1
	bcs,a	%xcc,.+8
	add	%g1,1,%g1

	addcc	$carry,%o0,%o0
	stx	%o0,[$tp]		! tp[num-1]
	mov	%g1,$carry
	bcs,a	%xcc,.+8
	add	$carry,1,$carry

	addcc	$i,8,$i
	bnz	%icc,.Louter
	nop

	sub	%g0,$num,%o7		! n=-num
	cmp	$carry,0		! clears %icc.c
	bne,pn	%icc,.Lsub
	add	$tp,8,$tp		! adjust tp to point at the end

	ld	[$tp-8],%o0
	ld	[$np-4],%o1
	cmp	%o0,%o1			! compare topmost words
	bcs,pt	%icc,.Lcopy		! %icc.c is clean if not taken
	nop

.align	32,0x1000000
.Lsub:
	ldd	[$tp+%o7],%o0
	ldd	[$np+%o7],%o2
	subccc	%o1,%o2,%o2
	subccc	%o0,%o3,%o3
	std	%o2,[$rp+%o7]
	add	%o7,8,%o7
	brnz,pt	%o7,.Lsub
	nop
	subccc	$carry,0,$carry
	bcc,pt	%icc,.Lzap
	sub	%g0,$num,%o7		! n=-num

.align	16,0x1000000
.Lcopy:
	ldx	[$tp+%o7],%o0
	srlx	%o0,32,%o1
	std	%o0,[$rp+%o7]
	add	%o7,8,%o7
	brnz,pt	%o7,.Lcopy
	nop
	ba	.Lzap
	sub	%g0,$num,%o7		! n=-num

.align	32
.Lzap:
	stx	%g0,[$tp+%o7]
	stx	%g0,[$ap_l+%o7]
	stx	%g0,[$ap_h+%o7]
	stx	%g0,[$np_l+%o7]
	stx	%g0,[$np_h+%o7]
	add	%o7,8,%o7
	brnz,pt	%o7,.Lzap
	nop

	ldx	[%sp+$bias+$frame+48],%o7
	wr	%g0,%o7,%asi		! restore %asi

	mov	1,%i0
.Lret:
	ret
	restore
.type   $fname,#function
.size	$fname,(.-$fname)
___

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

# Below substitution makes it possible to compile without demanding
# VIS extentions on command line, e.g. -xarch=v9 vs. -xarch=v9a. I
# dare to do this, because VIS capability is detected at run-time now
# and this routine is not called on CPU not capable to execute it. Do
# note that fzeros is not the only VIS dependency! Another dependency
# is implicit and is just _a_ numerical value loaded to %asi register,
# which assembler can't recognize as VIS specific...
$code =~ s/fzeros\s+%f([0-9]+)/
	   sprintf(".word\t0x%x\t! fzeros %%f%d",0x81b00c20|($1<<25),$1)
	  /gem;

print $code;
# flush
close STDOUT;
