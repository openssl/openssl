#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. Rights for redistribution and usage in source and binary
# forms are granted according to the OpenSSL license.
# ====================================================================

# "Teaser" Montgomery multiplication module for UltraSPARC. Why FPU?
# Because unlike integer multiplier, which simply stalls whole CPU,
# FPU is fully pipelined and can effectively emit 48 bit partial
# product every cycle. Why not blended SPARC v9? One can argue that
# making this module dependent on UltraSPARC VIS extension limits its
# binary compatibility. Very well may be, but the simple fact is that
# there is no known SPARC v9 implementation, which does not implement
# VIS. Even brand new Fujitsu's SPARC64 V is equipped with VIS unit.

# USI&II cores currently exhibit uniform 2x improvement [over pre-
# bn_mul_mont codebase] for all key lengths and benchmarks. On USIII
# performance improves few percents for shorter keys and worsens few
# percents for longer keys. This's because USIII integer multiplier
# is >3x faster than USI&II one, which is harder to match [but see
# TODO list below]. It should also be noted that SPARC64 V features
# out-of-order execution, which *might* mean that integer multiplier
# is pipelined, which in turn *might* be impossible to match...
#
# TODO:
# - complete 32-bit adaptation (requires universal changes to
#   BN_MONT_CTX and bn_mul_mont prototype, but nothing really
#   unmanagable:-);
# - modulo-schedule inner loop for better performance (on in-order
#   execution core such as UltraSPARC this shall result in further
#   noticeable(!) improvement);
# - dedicated squaring procedure[?];

$fname="bn_mul_mont";
$bits=32;
for (@ARGV) {
	$bits=64    if (/\-m64/        || /\-xarch\=v9/);
	$vis=1      if (/\-mcpu=ultra/ || /\-xarch\=v[9|8plus]\S/);
}

if (!$vis || $bits==32) {	# 32-bit is not supported just yet...
print<<___;
.section	".text",#alloc,#execinstr
.global $fname
$fname:
	retl
	xor	%o0,%o0,%o0	! just signal "not implemented"
.type   $fname,#function
.size	$fname,(.-$fname)
___
exit;
}

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
$n0="%i4";	# BN_ULONG n0,
$num="%i5";	# int num);

$tp="%l0";
$ap_l="%l1";	# a[num],n[num] are smashed to 32-bit words and saved
$ap_h="%l2";	# to these four vectors as double-precision FP values.
$np_l="%l3";	# This way a bunch of fxtods are eliminated in second
$np_h="%l4";	# loop and L1-cache aliasing is minimized...
$i="%l5";
$j="%l6";
$mask="%l7";	# 16-bit mask, 0xffff

$n0="%g4";	# reassigned!!!
$carry="%i4";	# reassigned!!! [only 1 bit is used]

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
	save	%sp,-$frame,%sp
	sethi	%hi(0xffff),$mask
	sll	$num,3,$num		! num*=8
	or	$mask,%lo(0xffff),$mask
	mov	%i4,$n0			! reassigned, remember?

	add	%sp,$bias,%o0		! real top of stack
	sll	$num,2,%o1
	add	%o1,$num,%o1		! %o1=num*5
	sub	%o0,%o1,%o0
	sub	%o0,$locals,%o0
	and	%o0,-2048,%o0		! optimize TLB utilization
	sub	%o0,$bias,%sp		! alloca

	rd	%asi,%o7
	add	%sp,$bias+$frame+$locals,$tp
	add	$tp,$num,$ap_l
	add	$ap_l,$num,$ap_l	! [an]p_[lh] point at the vector ends !
	add	$ap_l,$num,$ap_h
	add	$ap_h,$num,$np_l
	add	$np_l,$num,$np_h

	wr	%g0,$ASI_FL16_P,%asi	! setup %asi for 16-bit FP loads

	add	$rp,$num,$rp		! readjust input pointers to point
	add	$ap,$num,$ap		! at the ends too...
	add	$bp,$num,$bp
	add	$np,$num,$np

	stx	%o7,[%sp+$bias+$frame+48]

	sub	%g0,$num,$i
	sub	%g0,$num,$j

	add	$ap,$j,%o3
	add	$bp,$i,%o4
	ldx	[$bp+$i],%o0		! bp[0]
	add	$np,$j,%o5
	add	%sp,$bias+$frame+0,%o7
	ldx	[$ap+$j],%o1		! ap[0]

	mulx	%o1,%o0,%o0		! ap[0]*bp[0]
	mulx	$n0,%o0,%o0		! ap[0]*bp[0]*n0
	stx	%o0,[%o7]

	ld	[%o3+4],$alo_		! load a[j] as pair of 32-bit words
	fxors	$alo,$alo,$alo
	ld	[%o3+0],$ahi_
	fxors	$ahi,$ahi,$ahi
	ld	[%o5+4],$nlo_		! load n[j] as pair of 32-bit words
	fxors	$nlo,$nlo,$nlo
	ld	[%o5+0],$nhi_
	fxors	$nhi,$nhi,$nhi

	! transfer b[i] to FPU as 4x16-bit values
	ldda	[%o4+6]%asi,$ba
	fxtod	$alo,$alo
	ldda	[%o4+4]%asi,$bb
	fxtod	$ahi,$ahi
	ldda	[%o4+2]%asi,$bc
	fxtod	$nlo,$nlo
	ldda	[%o4+0]%asi,$bd
	fxtod	$nhi,$nhi

	! transfer ap[0]*b[0]*n0 to FPU as 4x16-bit values
	ldda	[%o7+6]%asi,$na
	fxtod	$ba,$ba
	ldda	[%o7+4]%asi,$nb
	fxtod	$bb,$bb
	ldda	[%o7+2]%asi,$nc
	fxtod	$bc,$bc
	ldda	[%o7+0]%asi,$nd
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
	fmuld	$nlo,$nc,$nloc
		faddd	$aloa,$nloa,$nloa
	fmuld	$alo,$bd,$alod
	fmuld	$nlo,$nd,$nlod
		faddd	$alob,$nlob,$nlob
	fmuld	$ahi,$ba,$ahia
	fmuld	$nhi,$na,$nhia
		faddd	$aloc,$nloc,$nloc
	fmuld	$ahi,$bb,$ahib
	fmuld	$nhi,$nb,$nhib
		faddd	$alod,$nlod,$nlod
	fmuld	$ahi,$bc,$ahic
	fmuld	$nhi,$nc,$nhic
		faddd	$ahia,$nhia,$nhia
	fmuld	$ahi,$bd,$ahid
	fmuld	$nhi,$nd,$nhid

	faddd	$ahib,$nhib,$nhib
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
	ld	[%o3+4],$alo_		! load a[j] as pair of 32-bit words
	fxors	$alo,$alo,$alo
	ld	[%o3+0],$ahi_
	fxors	$ahi,$ahi,$ahi
	ld	[%o4+4],$nlo_		! load n[j] as pair of 32-bit words
	fxors	$nlo,$nlo,$nlo
	ld	[%o4+0],$nhi_
	fxors	$nhi,$nhi,$nhi

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
	fmuld	$nlo,$nc,$nloc
		faddd	$aloa,$nloa,$nloa
	fmuld	$alo,$bd,$alod
	fmuld	$nlo,$nd,$nlod
		faddd	$alob,$nlob,$nlob
	fmuld	$ahi,$ba,$ahia
	fmuld	$nhi,$na,$nhia
		faddd	$aloc,$nloc,$nloc
	fmuld	$ahi,$bb,$ahib
	fmuld	$nhi,$nb,$nhib
		faddd	$alod,$nlod,$nlod
	fmuld	$ahi,$bc,$ahic
	fmuld	$nhi,$nc,$nhic
		faddd	$ahia,$nhia,$nhia
	fmuld	$ahi,$bd,$ahid
	fmuld	$nhi,$nd,$nhid
		faddd	$ahib,$nhib,$nhib

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
	add	$j,8,$j
	brnz	$j,.L1st
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
	sub	%g0,$num,$j
	add	%sp,$bias+$frame+$locals,$tp

	add	$bp,$i,%o4
	ldx	[$bp+$i],%o0		! bp[i]
	add	%sp,$bias+$frame+0,%o7
	ldx	[$ap+$j],%o1		! ap[0]

	ldx	[$tp],%o2		! tp[0]
	mulx	%o1,%o0,%o0
	addcc	%o2,%o0,%o0
	mulx	$n0,%o0,%o0		! (ap[0]*bp[i]+t[0])*n0
	stx	%o0,[%o7]


	! transfer b[i] to FPU as 4x16-bit values
	ldda	[%o4+6]%asi,$ba
	ldda	[%o4+4]%asi,$bb
	ldda	[%o4+2]%asi,$bc
	ldda	[%o4+0]%asi,$bd

	! transfer (ap[0]*b[i]+t[0])*n0 to FPU as 4x16-bit values
	ldda	[%o7+6]%asi,$na
	fxtod	$ba,$ba
	ldda	[%o7+4]%asi,$nb
	fxtod	$bb,$bb
	ldda	[%o7+2]%asi,$nc
	fxtod	$bc,$bc
	ldda	[%o7+0]%asi,$nd
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
	fmuld	$nlo,$nc,$nloc
		faddd	$aloa,$nloa,$nloa
	fmuld	$alo,$bd,$alod
	fmuld	$nlo,$nd,$nlod
		faddd	$alob,$nlob,$nlob
	fmuld	$ahi,$ba,$ahia
	fmuld	$nhi,$na,$nhia
		faddd	$aloc,$nloc,$nloc
	fmuld	$ahi,$bb,$ahib
	fmuld	$nhi,$nb,$nhib
		faddd	$alod,$nlod,$nlod
	fmuld	$ahi,$bc,$ahic
	fmuld	$nhi,$nc,$nhic
		faddd	$ahia,$nhia,$nhia
	fmuld	$ahi,$bd,$ahid
	fmuld	$nhi,$nd,$nhid

	faddd	$ahib,$nhib,$nhib
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
	fmuld	$nlo,$nc,$nloc
		faddd	$aloa,$nloa,$nloa
	fmuld	$alo,$bd,$alod
	fmuld	$nlo,$nd,$nlod
		faddd	$alob,$nlob,$nlob
	fmuld	$ahi,$ba,$ahia
	fmuld	$nhi,$na,$nhia
		faddd	$aloc,$nloc,$nloc
	fmuld	$ahi,$bb,$ahib
	fmuld	$nhi,$nb,$nhib
		faddd	$alod,$nlod,$nlod
	fmuld	$ahi,$bc,$ahic
	fmuld	$nhi,$nc,$nhic
		faddd	$ahia,$nhia,$nhia
	fmuld	$ahi,$bd,$ahid
	fmuld	$nhi,$nd,$nhid

	faddd	$ahib,$nhib,$nhib
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
	add	$j,8,$j
	brnz	$j,.Linner
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

	add	$i,8,$i
	brnz	$i,.Louter
	nop

	sub	%g0,$num,$j		! j=-num
	add	$tp,8,$tp		! adjust tp to point at the end

	cmp	$carry,0		! clears %icc.c
	bne,pn	%icc,.Lsub
	nop

	ld	[$tp-8],%o0
	ld	[$np-8],%o1
	cmp	%o0,%o1
	bcs,pt	%icc,.Lcopy		! %icc.c is clean if not taken
	nop

.align	32,0x1000000
.Lsub:
	ldd	[$tp+$j],%o0
	ldd	[$np+$j],%o2
	subccc	%o1,%o3,%o1
	subccc	%o0,%o2,%o0
	std	%o0,[$rp+$j]
	add	$j,8,$j
	brnz	$j,.Lsub
	nop
	subccc	$carry,0,$carry
	bcc	%icc,.Lzap
	sub	%g0,$num,$j

.align	16,0x1000000
.Lcopy:
	ldx	[$tp+$j],%o0
	stx	%o0,[$rp+$j]
	add	$j,8,$j
	brnz	$j,.Lcopy
	nop
	ba	.Lzap
	sub	%g0,$num,$j

.align	32
.Lzap:
	stx	%g0,[$tp+$j]
	stx	%g0,[$ap_l+$j]
	stx	%g0,[$ap_h+$j]
	stx	%g0,[$np_l+$j]
	stx	%g0,[$np_h+$j]
	add	$j,8,$j
	brnz	$j,.Lzap
	nop

	ldx	[%sp+$bias+$frame+48],%o7
	wr	%g0,%o7,%asi		! restore %asi

	mov	1,%i0
	ret
	restore
.type   $fname,#function
.size	$fname,(.-$fname)
___

$code =~ s/\`([^\`]*)\`/eval($1)/gem;
print $code;
close STDOUT;
