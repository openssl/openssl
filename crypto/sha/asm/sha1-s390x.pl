#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# SHA1 block procedure for s390x.

# April 2007.
#
# Performance is >30% better than gcc 3.3 generated code. But the real
# twist is that SHA1 hardware support is detected and utilized. In
# which case performance can reach further >4.5x for larger chunks.

$kimdfunc=1;	# magic function code for kimd instruction

$output=shift;
open STDOUT,">$output";

$t0="%r0";
$t1="%r1";
$ctx="%r2";
$inp="%r3";
$len="%r4";

$A="%r5";
$B="%r6";
$C="%r7";
$D="%r8";
$E="%r9";	@V=($A,$B,$C,$D,$E);
$K_00_19="%r10";
$K_20_39="%r11";
$K_40_59="%r12";
$K_60_79="%r13";
$Xi="%r14";
$sp="%r15";

$frame=160+16*4;

sub BODY_00_15 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $xi=($i&1)?$Xi:$t1;

$code.=<<___ if ($i<16 && !($i&1));
	lg	$Xi,`$i*4`($inp)
___
$code.=<<___;
	alr	$e,$K_00_19	### $i
	rll	$t0,$a,5
	alr	$e,$t0
	lr	$t0,$d
	xr	$t0,$c
	nr	$t0,$b
	xr	$t0,$d
	alr	$e,$t0
	rll	$b,$b,30
___
$code.=<<___ if ($i<16 && !($i&1));
	srlg	$xi,$Xi,32
	stg	$Xi,`160+$i*4`($sp)
___
$code.=<<___;
	alr	$e,$xi
___
}

sub Xupdate {
my $i=shift;

return if ($i&1);	# Xupdate is vectorized and executed every 2nd cycle
$code.=<<___;
	lg	$Xi,`160+4*($i%16)`($sp)	### Xupdate($i)
	xg	$Xi,`160+4*(($i+2)%16)`($sp)
	xg	$Xi,`160+4*(($i+8)%16)`($sp)
___
if ((($i+13)%16)==15) {
$code.=<<___;
	llgf	$t0,`160+4*15`($sp)
	x	$Xi,`160+0`($sp)
	sllg	$t0,$t0,32
	xgr	$Xi,$t0
___
} else {
$code.=<<___;
	xg	$Xi,`160+4*(($i+13)%16)`($sp)
___
}
$code.=<<___;
	rll	$Xi,$Xi,1
	rllg	$t1,$Xi,32
	rll	$t1,$t1,1
	rllg	$Xi,$t1,32
	stg	$Xi,`160+4*($i%16)`($sp)
___
}

sub BODY_16_19 {
	&Xupdate(@_[0]);
	&BODY_00_15(@_);
}

sub BODY_20_39 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $xi=($i&1)?$Xi:$t1;
my $K_XX_XX=($i<40)?$K_20_39:$K_60_79;

	&Xupdate($i);
$code.=<<___;
	alr	$e,$K_XX_XX	### $i
	rll	$t0,$a,5
	alr	$e,$t0
	lr	$t0,$b
	xr	$t0,$c
	xr	$t0,$d
	alr	$e,$t0
	rll	$b,$b,30
	alr	$e,$xi
___
}

sub BODY_40_59 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $xi=($i&1)?$Xi:$t1;

	&Xupdate($i);
$code.=<<___;
	alr	$e,$K_40_59	### $i
	rll	$t0,$a,5
	alr	$e,$t0
	lr	$t0,$b
	or	$t0,$c
	nr	$t0,$d
	alr	$e,$xi
	lr	$t1,$b
	nr	$t1,$c
	or	$t0,$t1
	alr	$e,$t0
	rll	$b,$b,30
___
}

$code.=<<___;
.text
.globl	sha1_block_data_order
.type	sha1_block_data_order,\@function
sha1_block_data_order:
___
$code.=<<___ if ($kimdfunc);
	lghi	%r0,0
	la	%r1,16($sp)
	.long	0xb93e0002	# kimd %r0,%r2
	lg	%r0,16($sp)
	tmhh	%r0,`0x8000>>$kimdfunc`
	jz	.Lsoftware
	lghi	%r0,$kimdfunc
	lgr	%r1,$ctx
	lgr	%r2,$inp
	sllg	%r3,$len,6
	.long	0xb93e0002	# kimd %r0,%r2
	brc	1,.-4		# pay attention to "partial completion"
	br	%r14
.Lsoftware:
___
$code.=<<___;
	stmg	%r6,%r15,48($sp)
	lgr	%r0,$sp
	aghi	$sp,-$frame
	stg	%r0,0($sp)

	sllg	$len,$len,6
	la	$len,0($inp,$len)

	llgf	$A,0($ctx)
	llgf	$B,4($ctx)
	llgf	$C,8($ctx)
	llgf	$D,12($ctx)
	llgf	$E,16($ctx)

	llilh	$K_00_19,0x5a82
	oill	$K_00_19,0x7999
	llilh	$K_20_39,0x6ed9
	oill	$K_20_39,0xeba1
	llilh	$K_40_59,0x8f1b
	oill	$K_40_59,0xbcdc
	llilh	$K_60_79,0xca62
	oill	$K_60_79,0xc1d6
.Lloop:
___
for ($i=0;$i<16;$i++)	{ &BODY_00_15($i,@V); unshift(@V,pop(@V)); }
for (;$i<20;$i++)	{ &BODY_16_19($i,@V); unshift(@V,pop(@V)); }
for (;$i<40;$i++)	{ &BODY_20_39($i,@V); unshift(@V,pop(@V)); }
for (;$i<60;$i++)	{ &BODY_40_59($i,@V); unshift(@V,pop(@V)); }
for (;$i<80;$i++)	{ &BODY_20_39($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;

	al	$A,0($ctx)
	al	$B,4($ctx)
	al	$C,8($ctx)
	al	$D,12($ctx)
	al	$E,16($ctx)
	st	$A,0($ctx)
	st	$B,4($ctx)
	st	$C,8($ctx)
	st	$D,12($ctx)
	st	$E,16($ctx)
	la	$inp,64($inp)
	clgr	$inp,$len
	jne	.Lloop

	lmg	%r6,%r15,`$frame+48`($sp)
	br	%r14
.size	sha1_block_data_order,.-sha1_block_data_order
.string	"SHA1 block transform for s390x, CRYPTOGAMS by <appro\@openssl.org>"
___

$code =~ s/\`([^\`]*)\`/eval $1/gem;

print $code;
close STDOUT;
