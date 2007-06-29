#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# April 2007.
#
# Performance improvement over vanilla C code varies from 85% to 45%
# depending on key length and benchmark. Unfortunately in this context
# these are not very impressive results [for code that utilizes "wide"
# 64x64=128-bit multiplication, which is not commonly available to C
# programmers], at least hand-coded bn_asm.c replacement is known to
# provide 30-40% better results for longest keys. Well, on a second
# thought it's not very surprising, because z-CPUs are single-issue
# and _strictly_ in-order execution, while bn_mul_mont is more or less
# dependent on CPU ability to pipe-line instructions and have several
# of them "in-flight" at the same time. I mean while other methods,
# for example Karatsuba, aim to minimize amount of multiplications at
# the cost of other operations increase, bn_mul_mont aim to neatly
# "overlap" multiplications and the other operations [and on most
# platforms even minimize the amount of the other operations, in
# particular references to memory]. But it's possible to improve this
# module performance by implementing dedicated squaring code-path and
# possibly by unrolling loops...

$mn0="%r0";
$num="%r1";

# int bn_mul_mont(
$rp="%r2";		# BN_ULONG *rp,
$ap="%r3";		# const BN_ULONG *ap,
$bp="%r4";		# const BN_ULONG *bp,
$np="%r5";		# const BN_ULONG *np,
$n0="%r6";		# const BN_ULONG *n0,
#$num="160(%r15)"	# int num);

$bi="%r2";	# zaps rp
$j="%r7";

$ahi="%r8";
$alo="%r9";
$nhi="%r10";
$nlo="%r11";
$AHI="%r12";
$NHI="%r13";
$fp="%r14";
$sp="%r15";

$code.=<<___;
.text
.globl	bn_mul_mont
.type	bn_mul_mont,\@function
bn_mul_mont:
	lgf	$num,164($sp)	# pull $num
	sla	$num,3		# $num to enumerate bytes
	la	$rp,0($num,$rp)	# pointers to point at the vectors' ends
	la	$ap,0($num,$ap)
	la	$bp,0($num,$bp)
	la	$np,0($num,$np)

	stmg	%r2,%r15,16($sp)

	cghi	$num,16		#
	lghi	%r2,0		#
	blr	%r14		# if($num<16) return 0;

	lcgr	$num,$num	# -$num
	lgr	%r0,$sp
	lgr	$fp,$sp
	aghi	$fp,-160-8	# leave room for carry bit
	la	$sp,0($num,$fp)	# alloca
	stg	%r0,0($sp)
	aghi	$fp,160-8	# $fp to point at tp[$num-1]

	la	$bp,0($num,$bp)	# restore $bp
	lg	$n0,0($n0)	# pull n0

	lg	$bi,0($bp)
	lg	$alo,0($num,$ap)
	mlgr	$ahi,$bi	# ap[0]*bp[0]
	lgr	$AHI,$ahi

	lgr	$mn0,$alo	# "tp[0]"*n0
	msgr	$mn0,$n0

	lg	$nlo,0($num,$np)#
	mlgr	$nhi,$mn0	# np[0]*m1
	algr	$nlo,$alo	# +="tp[0]"
	lghi	$NHI,0
	alcgr	$NHI,$nhi

	lgr	$j,$num
	aghi	$j,8		# j=1
.L1st:
	lg	$alo,0($j,$ap)
	mlgr	$ahi,$bi	# ap[j]*bp[0]
	algr	$alo,$AHI
	lghi	$AHI,0
	alcgr	$AHI,$ahi

	lg	$nlo,0($j,$np)
	mlgr	$nhi,$mn0	# np[j]*m1
	algr	$nlo,$NHI
	lghi	$NHI,0
	alcgr	$nhi,$NHI	# +="tp[j]"
	algr	$nlo,$alo
	alcgr	$NHI,$nhi

	stg	$nlo,0($j,$fp)	# tp[j-1]=
	aghi	$j,8		# j++
	jnz	.L1st

	algr	$NHI,$AHI
	lghi	$AHI,0
	alcgr	$AHI,$AHI	# upmost overflow bit
	stg	$NHI,0($fp)
	stg	$AHI,8($fp)
	la	$bp,8($bp)	# bp++

.Louter:
	lg	$bi,0($bp)	# bp[i]
	lg	$alo,0($num,$ap)
	mlgr	$ahi,$bi	# ap[0]*bp[i]
	alg	$alo,8($num,$fp)# +=tp[0]
	lghi	$AHI,0
	alcgr	$AHI,$ahi

	lgr	$mn0,$alo
	msgr	$mn0,$n0		# tp[0]*n0

	lg	$nlo,0($num,$np)# np[0]
	mlgr	$nhi,$mn0	# np[0]*m1
	algr	$nlo,$alo	# +="tp[0]"
	lghi	$NHI,0
	alcgr	$NHI,$nhi

	lgr	$j,$num
	aghi	$j,8		# j=1
.Linner:
	lg	$alo,0($j,$ap)
	mlgr	$ahi,$bi	# ap[j]*bp[i]
	algr	$alo,$AHI
	lghi	$AHI,0
	alcgr	$ahi,$AHI
	alg	$alo,8($j,$fp)	# +=tp[j]
	alcgr	$AHI,$ahi

	lg	$nlo,0($j,$np)
	mlgr	$nhi,$mn0	# np[j]*m1
	algr	$nlo,$NHI
	lghi	$NHI,0
	alcgr	$nhi,$NHI
	algr	$nlo,$alo	# +="tp[j]"
	alcgr	$NHI,$nhi

	stg	$nlo,0($j,$fp)	# tp[j-1]=
	aghi	$j,8		# j++
	jnz	.Linner

	algr	$NHI,$AHI
	lghi	$AHI,0
	alcgr	$AHI,$AHI
	alg	$NHI,8($fp)	# accumulate previous upmost overflow bit
	lghi	$ahi,0
	alcgr	$AHI,$ahi	# new upmost overflow bit
	stg	$NHI,0($fp)
	stg	$AHI,8($fp)

	la	$bp,8($bp)	# bp++
	clg	$bp,16+32($fp)	# compare to &bp[num]
	jne	.Louter
___

undef $bi;
$count=$bp; undef $bp;

$code.=<<___;
	lg	$rp,16+16($fp)	# reincarnate rp
	la	$ap,8($fp)
	lgr	$j,$num

	lcgr	$count,$num
	sra	$count,3	# incidentally clears "borrow"
.Lsub:	lg	$alo,0($j,$ap)
	slbg	$alo,0($j,$np)
	stg	$alo,0($j,$rp)
	la	$j,8($j)
	brct	$count,.Lsub
	lghi	$ahi,0
	slbgr	$AHI,$ahi	# handle upmost carry

	ngr	$ap,$AHI
	lghi	$np,-1
	xgr	$np,$AHI
	ngr	$np,$rp
	ogr	$ap,$np		# ap=borrow?tp:rp
	lgr	$j,$num

.Lcopy:	lg	$alo,0($j,$ap)	# copy or in-place refresh
	stg	$j,8($j,$fp)	# zap tp
	stg	$alo,0($j,$rp)
	aghi	$j,8
	jnz	.Lcopy

	lmg	%r6,%r15,16+48($fp)
	lghi	%r2,1		# signal "processed"
	br	%r14
.size	bn_mul_mont,.-bn_mul_mont
.string	"Montgomery Multiplication for s390x, CRYPTOGAMS by <appro\@openssl.org>"
___

print $code;
close STDOUT;
