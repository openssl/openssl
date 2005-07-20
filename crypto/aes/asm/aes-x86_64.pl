#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. Rights for redistribution and usage in source and binary
# forms are granted according to the OpenSSL license.
# ====================================================================
#
# Version 1.1.
#
# aes-*-cbc benchmarks are improved by >70% [compared to gcc 3.3.2 on
# Opteron 240 CPU] plus all the bells-n-whistles from 32-bit version
# [you'll notice a lot of resemblance], such as compressed S-boxes
# in little-endian byte order, prefetch of these tables in CBC mode,
# as well as avoiding L1 cache aliasing between stack frame and key
# schedule and already mentioned tables.
#
# Performance in number of cycles per processed byte for 128-bit key:
#
#		ECB		CBC encrypt
# AMD64		13.7		13.0(*)
# EM64T		20.2		18.6(*)
#
# (*)	CBC benchmarks are better than ECB thanks to custom ABI used
#	by the private block encryption function.

$verticalspin=1;	# unlike 32-bit version $verticalspin performs
			# ~15% better on both AMD and Intel cores
$output=shift;
open STDOUT,"| $^X ../perlasm/x86_64-xlate.pl $output";

$code=".text\n";

$s0="%eax";
$s1="%ebx";
$s2="%ecx";
$s3="%edx";
$acc0="%esi";
$acc1="%edi";
$acc2="%ebp";
$inp="%r8";
$out="%r9";
$t0="%r10d";
$t1="%r11d";
$t2="%r12d";
$rnds="%r13d";
$sbox="%r14";
$key="%r15";

sub hi() { my $r=shift;	$r =~ s/%[er]([a-d])x/%\1h/;	$r; }
sub lo() { my $r=shift;	$r =~ s/%[er]([a-d])x/%\1l/;
			$r =~ s/%[er]([sd]i)/%\1l/;
			$r =~ s/%(r[0-9]+)[d]?/%\1b/;	$r; }
sub _data_word()
{ my $i;
    while(defined($i=shift)) { $code.=sprintf".long\t0x%08x,0x%08x\n",$i,$i; }
}
sub data_word()
{ my $i;
  my $last=pop(@_);
    $code.=".long\t";
    while(defined($i=shift)) { $code.=sprintf"0x%08x,",$i; }
    $code.=sprintf"0x%08x\n",$last;
}

sub encvert()
{ my $t3="%r8d";	# zaps $inp!

$code.=<<___;
	# favor 3-way issue Opteron pipeline...
	movzb	`&lo("$s0")`,$acc0
	movzb	`&lo("$s1")`,$acc1
	movzb	`&lo("$s2")`,$acc2
	mov	0($sbox,$acc0,8),$t0
	mov	0($sbox,$acc1,8),$t1
	mov	0($sbox,$acc2,8),$t2

	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	movzb	`&lo("$s3")`,$acc2
	xor	3($sbox,$acc0,8),$t0
	xor	3($sbox,$acc1,8),$t1
	mov	0($sbox,$acc2,8),$t3

	movzb	`&hi("$s3")`,$acc0
	shr	\$16,$s2
	movzb	`&hi("$s0")`,$acc2
	xor	3($sbox,$acc0,8),$t2
	shr	\$16,$s3
	xor	3($sbox,$acc2,8),$t3

	shr	\$16,$s1
	lea	16($key),$key
	shr	\$16,$s0

	movzb	`&lo("$s2")`,$acc0
	movzb	`&lo("$s3")`,$acc1
	movzb	`&lo("$s0")`,$acc2
	xor	2($sbox,$acc0,8),$t0
	xor	2($sbox,$acc1,8),$t1
	xor	2($sbox,$acc2,8),$t2

	movzb	`&hi("$s3")`,$acc0
	movzb	`&hi("$s0")`,$acc1
	movzb	`&lo("$s1")`,$acc2
	xor	1($sbox,$acc0,8),$t0
	xor	1($sbox,$acc1,8),$t1
	xor	2($sbox,$acc2,8),$t3

	mov	12($key),$s3
	movzb	`&hi("$s1")`,$acc1
	movzb	`&hi("$s2")`,$acc2
	mov	0($key),$s0
	xor	1($sbox,$acc1,8),$t2
	xor	1($sbox,$acc2,8),$t3

	mov	4($key),$s1
	mov	8($key),$s2
	xor	$t0,$s0
	xor	$t1,$s1
	xor	$t2,$s2
	xor	$t3,$s3
___
}

sub enclastvert()
{ my $t3="%r8d";	# zaps $inp!

$code.=<<___;
	movzb	`&lo("$s0")`,$acc0
	movzb	`&lo("$s1")`,$acc1
	movzb	`&lo("$s2")`,$acc2
	mov	2($sbox,$acc0,8),$t0
	mov	2($sbox,$acc1,8),$t1
	mov	2($sbox,$acc2,8),$t2

	and	\$0x000000ff,$t0
	and	\$0x000000ff,$t1
	and	\$0x000000ff,$t2

	movzb	`&lo("$s3")`,$acc0
	movzb	`&hi("$s1")`,$acc1
	movzb	`&hi("$s2")`,$acc2
	mov	2($sbox,$acc0,8),$t3
	mov	0($sbox,$acc1,8),$acc1	#$t0
	mov	0($sbox,$acc2,8),$acc2	#$t1

	and	\$0x000000ff,$t3
	and	\$0x0000ff00,$acc1
	and	\$0x0000ff00,$acc2

	xor	$acc1,$t0
	xor	$acc2,$t1
	shr	\$16,$s2

	movzb	`&hi("$s3")`,$acc0
	movzb	`&hi("$s0")`,$acc1
	shr	\$16,$s3
	mov	0($sbox,$acc0,8),$acc0	#$t2
	mov	0($sbox,$acc1,8),$acc1	#$t3

	and	\$0x0000ff00,$acc0
	and	\$0x0000ff00,$acc1
	shr	\$16,$s1
	xor	$acc0,$t2
	xor	$acc1,$t3
	shr	\$16,$s0

	movzb	`&lo("$s2")`,$acc0
	movzb	`&lo("$s3")`,$acc1
	movzb	`&lo("$s0")`,$acc2
	mov	0($sbox,$acc0,8),$acc0	#$t0
	mov	0($sbox,$acc1,8),$acc1	#$t1
	mov	0($sbox,$acc2,8),$acc2	#$t2

	and	\$0x00ff0000,$acc0
	and	\$0x00ff0000,$acc1
	and	\$0x00ff0000,$acc2

	xor	$acc0,$t0
	xor	$acc1,$t1
	xor	$acc2,$t2

	movzb	`&lo("$s1")`,$acc0
	movzb	`&hi("$s3")`,$acc1
	movzb	`&hi("$s0")`,$acc2
	mov	0($sbox,$acc0,8),$acc0	#$t3
	mov	2($sbox,$acc1,8),$acc1	#$t0
	mov	2($sbox,$acc2,8),$acc2	#$t1

	and	\$0x00ff0000,$acc0
	and	\$0xff000000,$acc1
	and	\$0xff000000,$acc2

	xor	$acc0,$t3
	xor	$acc1,$t0
	xor	$acc2,$t1

	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	mov	16+12($key),$s3
	mov	2($sbox,$acc0,8),$acc0	#$t2
	mov	2($sbox,$acc1,8),$acc1	#$t3
	mov	16+0($key),$s0

	and	\$0xff000000,$acc0
	and	\$0xff000000,$acc1

	xor	$acc0,$t2
	xor	$acc1,$t3

	mov	16+4($key),$s1
	mov	16+8($key),$s2
	xor	$t0,$s0
	xor	$t1,$s1
	xor	$t2,$s2
	xor	$t3,$s3
___
}

sub encstep()
{ my ($i,@s) = @_;
  my $tmp0=$acc0;
  my $tmp1=$acc1;
  my $tmp2=$acc2;
  my $out=($t0,$t1,$t2,$s[0])[$i];

	if ($i==3) {
		$tmp0=$s[1];
		$tmp1=$s[2];
		$tmp2=$s[3];
	}
	$code.="	movzb	".&lo($s[0]).",$out\n";
	$code.="	mov	$s[2],$tmp1\n"		if ($i!=3);
	$code.="	lea	16($key),$key\n"	if ($i==0);

	$code.="	movzb	".&hi($s[1]).",$tmp0\n";
	$code.="	mov	0($sbox,$out,8),$out\n";

	$code.="	shr	\$16,$tmp1\n";
	$code.="	mov	$s[3],$tmp2\n"		if ($i!=3);
	$code.="	xor	3($sbox,$tmp0,8),$out\n";

	$code.="	movzb	".&lo($tmp1).",$tmp1\n";
	$code.="	shr	\$24,$tmp2\n";
	$code.="	xor	4*$i($key),$out\n";

	$code.="	xor	2($sbox,$tmp1,8),$out\n";
	$code.="	xor	1($sbox,$tmp2,8),$out\n";

	$code.="	mov	$t0,$s[1]\n"		if ($i==3);
	$code.="	mov	$t1,$s[2]\n"		if ($i==3);
	$code.="	mov	$t2,$s[3]\n"		if ($i==3);
	$code.="\n";
}

sub enclast()
{ my ($i,@s)=@_;
  my $tmp0=$acc0;
  my $tmp1=$acc1;
  my $tmp2=$acc2;
  my $out=($t0,$t1,$t2,$s[0])[$i];

	if ($i==3) {
		$tmp0=$s[1];
		$tmp1=$s[2];
		$tmp2=$s[3];
	}
	$code.="	movzb	".&lo($s[0]).",$out\n";
	$code.="	mov	$s[2],$tmp1\n"		if ($i!=3);

	$code.="	mov	2($sbox,$out,8),$out\n";
	$code.="	shr	\$16,$tmp1\n";
	$code.="	mov	$s[3],$tmp2\n"		if ($i!=3);

	$code.="	and	\$0x000000ff,$out\n";
	$code.="	movzb	".&hi($s[1]).",$tmp0\n";
	$code.="	movzb	".&lo($tmp1).",$tmp1\n";
	$code.="	shr	\$24,$tmp2\n";

	$code.="	mov	0($sbox,$tmp0,8),$tmp0\n";
	$code.="	mov	0($sbox,$tmp1,8),$tmp1\n";
	$code.="	mov	2($sbox,$tmp2,8),$tmp2\n";

	$code.="	and	\$0x0000ff00,$tmp0\n";
	$code.="	and	\$0x00ff0000,$tmp1\n";
	$code.="	and	\$0xff000000,$tmp2\n";

	$code.="	xor	$tmp0,$out\n";
	$code.="	mov	$t0,$s[1]\n"		if ($i==3);
	$code.="	xor	$tmp1,$out\n";
	$code.="	mov	$t1,$s[2]\n"		if ($i==3);
	$code.="	xor	$tmp2,$out\n";
	$code.="	mov	$t2,$s[3]\n"		if ($i==3);
	$code.="\n";
}

$code.=<<___;
.type	_x86_64_AES_encrypt,\@abi-omnipotent
.align	16
_x86_64_AES_encrypt:
	xor	0($key),$s0			# xor with key
	xor	4($key),$s1
	xor	8($key),$s2
	xor	12($key),$s3

	mov	240($key),$rnds			# load key->rounds
	sub	\$1,$rnds
	jmp	.Lenc_loop
.align	16
.Lenc_loop:
___
	if ($verticalspin) { &encvert(); }
	else {	&encstep(0,$s0,$s1,$s2,$s3);
		&encstep(1,$s1,$s2,$s3,$s0);
		&encstep(2,$s2,$s3,$s0,$s1);
		&encstep(3,$s3,$s0,$s1,$s2);
	}
$code.=<<___;
	sub	\$1,$rnds
	jnz	.Lenc_loop
___
	if ($verticalspin) { &enclastvert(); }
	else {	&enclast(0,$s0,$s1,$s2,$s3);
		&enclast(1,$s1,$s2,$s3,$s0);
		&enclast(2,$s2,$s3,$s0,$s1);
		&enclast(3,$s3,$s0,$s1,$s2);
		$code.=<<___;
		xor	16+0($key),$s0		# xor with key
		xor	16+4($key),$s1
		xor	16+8($key),$s2
		xor	16+12($key),$s3
___
	}
$code.=<<___;
	.byte	0xf3,0xc3			# rep ret
.size	_x86_64_AES_encrypt,.-_x86_64_AES_encrypt
___

# void AES_encrypt (const void *inp,void *out,const AES_KEY *key);
$code.=<<___;
.globl	AES_encrypt
.type	AES_encrypt,\@function,3
.align	16
AES_encrypt:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	%rdx,$key
	mov	%rdi,$inp
	mov	%rsi,$out

	.picmeup	$sbox
	lea	AES_Te-.($sbox),$sbox

	mov	0($inp),$s0
	mov	4($inp),$s1
	mov	8($inp),$s2
	mov	12($inp),$s3

	call	_x86_64_AES_encrypt

	mov	$s0,0($out)
	mov	$s1,4($out)
	mov	$s2,8($out)
	mov	$s3,12($out)

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	ret
.size	AES_encrypt,.-AES_encrypt
___

#------------------------------------------------------------------#

sub decvert()
{ my $t3="%r8d";	# zaps $inp!

$code.=<<___;
	# favor 3-way issue Opteron pipeline...
	movzb	`&lo("$s0")`,$acc0
	movzb	`&lo("$s1")`,$acc1
	movzb	`&lo("$s2")`,$acc2
	mov	0($sbox,$acc0,8),$t0
	mov	0($sbox,$acc1,8),$t1
	mov	0($sbox,$acc2,8),$t2

	movzb	`&hi("$s3")`,$acc0
	movzb	`&hi("$s0")`,$acc1
	movzb	`&lo("$s3")`,$acc2
	xor	3($sbox,$acc0,8),$t0
	xor	3($sbox,$acc1,8),$t1
	mov	0($sbox,$acc2,8),$t3

	movzb	`&hi("$s1")`,$acc0
	shr	\$16,$s0
	movzb	`&hi("$s2")`,$acc2
	xor	3($sbox,$acc0,8),$t2
	shr	\$16,$s3
	xor	3($sbox,$acc2,8),$t3

	shr	\$16,$s1
	lea	16($key),$key
	shr	\$16,$s2

	movzb	`&lo("$s2")`,$acc0
	movzb	`&lo("$s3")`,$acc1
	movzb	`&lo("$s0")`,$acc2
	xor	2($sbox,$acc0,8),$t0
	xor	2($sbox,$acc1,8),$t1
	xor	2($sbox,$acc2,8),$t2

	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	movzb	`&lo("$s1")`,$acc2
	xor	1($sbox,$acc0,8),$t0
	xor	1($sbox,$acc1,8),$t1
	xor	2($sbox,$acc2,8),$t3

	movzb	`&hi("$s3")`,$acc0
	mov	12($key),$s3
	movzb	`&hi("$s0")`,$acc2
	xor	1($sbox,$acc0,8),$t2
	mov	0($key),$s0
	xor	1($sbox,$acc2,8),$t3

	xor	$t0,$s0
	mov	4($key),$s1
	mov	8($key),$s2
	xor	$t2,$s2
	xor	$t1,$s1
	xor	$t3,$s3
___
}

sub declastvert()
{ my $t3="%r8d";	# zaps $inp!

$code.=<<___;
	movzb	`&lo("$s0")`,$acc0
	movzb	`&lo("$s1")`,$acc1
	movzb	`&lo("$s2")`,$acc2
	mov	2048($sbox,$acc0,4),$t0
	mov	2048($sbox,$acc1,4),$t1
	mov	2048($sbox,$acc2,4),$t2

	and	\$0x000000ff,$t0
	and	\$0x000000ff,$t1
	and	\$0x000000ff,$t2

	movzb	`&lo("$s3")`,$acc0
	movzb	`&hi("$s3")`,$acc1
	movzb	`&hi("$s0")`,$acc2
	mov	2048($sbox,$acc0,4),$t3
	mov	2048($sbox,$acc1,4),$acc1	#$t0
	mov	2048($sbox,$acc2,4),$acc2	#$t1

	and	\$0x000000ff,$t3
	and	\$0x0000ff00,$acc1
	and	\$0x0000ff00,$acc2

	xor	$acc1,$t0
	xor	$acc2,$t1
	shr	\$16,$s3

	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	shr	\$16,$s0
	mov	2048($sbox,$acc0,4),$acc0	#$t2
	mov	2048($sbox,$acc1,4),$acc1	#$t3

	and	\$0x0000ff00,$acc0
	and	\$0x0000ff00,$acc1
	shr	\$16,$s1
	xor	$acc0,$t2
	xor	$acc1,$t3
	shr	\$16,$s2

	movzb	`&lo("$s2")`,$acc0
	movzb	`&lo("$s3")`,$acc1
	movzb	`&lo("$s0")`,$acc2
	mov	2048($sbox,$acc0,4),$acc0	#$t0
	mov	2048($sbox,$acc1,4),$acc1	#$t1
	mov	2048($sbox,$acc2,4),$acc2	#$t2

	and	\$0x00ff0000,$acc0
	and	\$0x00ff0000,$acc1
	and	\$0x00ff0000,$acc2

	xor	$acc0,$t0
	xor	$acc1,$t1
	xor	$acc2,$t2

	movzb	`&lo("$s1")`,$acc0
	movzb	`&hi("$s1")`,$acc1
	movzb	`&hi("$s2")`,$acc2
	mov	2048($sbox,$acc0,4),$acc0	#$t3
	mov	2048($sbox,$acc1,4),$acc1	#$t0
	mov	2048($sbox,$acc2,4),$acc2	#$t1

	and	\$0x00ff0000,$acc0
	and	\$0xff000000,$acc1
	and	\$0xff000000,$acc2

	xor	$acc0,$t3
	xor	$acc1,$t0
	xor	$acc2,$t1

	movzb	`&hi("$s3")`,$acc0
	movzb	`&hi("$s0")`,$acc1
	mov	16+12($key),$s3
	mov	2048($sbox,$acc0,4),$acc0	#$t2
	mov	2048($sbox,$acc1,4),$acc1	#$t3
	mov	16+0($key),$s0

	and	\$0xff000000,$acc0
	and	\$0xff000000,$acc1

	xor	$acc0,$t2
	xor	$acc1,$t3

	mov	16+4($key),$s1
	mov	16+8($key),$s2
	xor	$t0,$s0
	xor	$t1,$s1
	xor	$t2,$s2
	xor	$t3,$s3
___
}

sub decstep()
{ my ($i,@s) = @_;
  my $tmp0=$acc0;
  my $tmp1=$acc1;
  my $tmp2=$acc2;
  my $out=($t0,$t1,$t2,$s[0])[$i];

	$code.="	mov	$s[0],$out\n"		if ($i!=3);
			$tmp1=$s[2]			if ($i==3);
	$code.="	mov	$s[2],$tmp1\n"		if ($i!=3);
	$code.="	and	\$0xFF,$out\n";

	$code.="	mov	0($sbox,$out,8),$out\n";
	$code.="	shr	\$16,$tmp1\n";
			$tmp2=$s[3]			if ($i==3);
	$code.="	mov	$s[3],$tmp2\n"		if ($i!=3);

			$tmp0=$s[1]			if ($i==3);
	$code.="	movzb	".&hi($s[1]).",$tmp0\n";
	$code.="	and	\$0xFF,$tmp1\n";
	$code.="	shr	\$24,$tmp2\n";

	$code.="	xor	3($sbox,$tmp0,8),$out\n";
	$code.="	xor	2($sbox,$tmp1,8),$out\n";
	$code.="	xor	1($sbox,$tmp2,8),$out\n";

	$code.="	mov	$t2,$s[1]\n"		if ($i==3);
	$code.="	mov	$t1,$s[2]\n"		if ($i==3);
	$code.="	mov	$t0,$s[3]\n"		if ($i==3);
	$code.="\n";
}

sub declast()
{ my ($i,@s)=@_;
  my $tmp0=$acc0;
  my $tmp1=$acc1;
  my $tmp2=$acc2;
  my $out=($t0,$t1,$t2,$s[0])[$i];

	$code.="	mov	$s[0],$out\n"		if ($i!=3);
			$tmp1=$s[2]			if ($i==3);
	$code.="	mov	$s[2],$tmp1\n"		if ($i!=3);
	$code.="	and	\$0xFF,$out\n";

	$code.="	mov	2048($sbox,$out,4),$out\n";
	$code.="	shr	\$16,$tmp1\n";
			$tmp2=$s[3]			if ($i==3);
	$code.="	mov	$s[3],$tmp2\n"		if ($i!=3);

	$code.="	and	\$0x000000ff,$out\n";
			$tmp0=$s[1]			if ($i==3);
	$code.="	movzb	".&hi($s[1]).",$tmp0\n";
	$code.="	and	\$0xFF,$tmp1\n";
	$code.="	shr	\$24,$tmp2\n";

	$code.="	mov	2048($sbox,$tmp0,4),$tmp0\n";
	$code.="	mov	2048($sbox,$tmp1,4),$tmp1\n";
	$code.="	mov	2048($sbox,$tmp2,4),$tmp2\n";

	$code.="	and	\$0x0000ff00,$tmp0\n";
	$code.="	and	\$0x00ff0000,$tmp1\n";
	$code.="	and	\$0xff000000,$tmp2\n";

	$code.="	xor	$tmp0,$out\n";
	$code.="	mov	$t2,$s[1]\n"		if ($i==3);
	$code.="	xor	$tmp1,$out\n";
	$code.="	mov	$t1,$s[2]\n"		if ($i==3);
	$code.="	xor	$tmp2,$out\n";
	$code.="	mov	$t0,$s[3]\n"		if ($i==3);
	$code.="\n";
}

$code.=<<___;
.type	_x86_64_AES_decrypt,\@abi-omnipotent
.align	16
_x86_64_AES_decrypt:
	xor	0($key),$s0			# xor with key
	xor	4($key),$s1
	xor	8($key),$s2
	xor	12($key),$s3

	mov	240($key),$rnds			# load key->rounds
	sub	\$1,$rnds
	jmp	.Ldec_loop
.align	16
.Ldec_loop:
___
	if ($verticalspin) { &decvert(); }
	else {	&decstep(0,$s0,$s3,$s2,$s1);
		&decstep(1,$s1,$s0,$s3,$s2);
		&decstep(2,$s2,$s1,$s0,$s3);
		&decstep(3,$s3,$s2,$s1,$s0);
		$code.=<<___;
		lea	16($key),$key
		xor	0($key),$s0			# xor with key
		xor	4($key),$s1
		xor	8($key),$s2
		xor	12($key),$s3
___
	}
$code.=<<___;
	sub	\$1,$rnds
	jnz	.Ldec_loop
___
	if ($verticalspin) { &declastvert(); }
	else {	&declast(0,$s0,$s3,$s2,$s1);
		&declast(1,$s1,$s0,$s3,$s2);
		&declast(2,$s2,$s1,$s0,$s3);
		&declast(3,$s3,$s2,$s1,$s0);
		$code.=<<___;
		xor	16+0($key),$s0			# xor with key
		xor	4($key),$s1
		xor	8($key),$s2
		xor	12($key),$s3
___
	}
$code.=<<___;
	.byte	0xf3,0xc3			# rep ret
.size	_x86_64_AES_decrypt,.-_x86_64_AES_decrypt
___

# void AES_decrypt (const void *inp,void *out,const AES_KEY *key);
$code.=<<___;
.globl	AES_decrypt
.type	AES_decrypt,\@function,3
.align	16
AES_decrypt:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	%rdx,$key
	mov	%rdi,$inp
	mov	%rsi,$out

	.picmeup	$sbox
	lea	AES_Td-.($sbox),$sbox

	mov	0($inp),$s0
	mov	4($inp),$s1
	mov	8($inp),$s2
	mov	12($inp),$s3

	call	_x86_64_AES_decrypt

	mov	$s0,0($out)
	mov	$s1,4($out)
	mov	$s2,8($out)
	mov	$s3,12($out)

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	ret
.size	AES_decrypt,.-AES_decrypt
___
#------------------------------------------------------------------#

sub enckey()
{
$code.=<<___;
	movz	%dl,%esi		# rk[i]>>0
	mov	2(%rbp,%rsi,8),%ebx
	movz	%dh,%esi		# rk[i]>>8
	and	\$0xFF000000,%ebx
	xor	%ebx,%eax

	mov	2(%rbp,%rsi,8),%ebx
	shr	\$16,%edx
	and	\$0x000000FF,%ebx
	movz	%dl,%esi		# rk[i]>>16
	xor	%ebx,%eax

	mov	0(%rbp,%rsi,8),%ebx
	movz	%dh,%esi		# rk[i]>>24
	and	\$0x0000FF00,%ebx
	xor	%ebx,%eax

	mov	0(%rbp,%rsi,8),%ebx
	and	\$0x00FF0000,%ebx
	xor	%ebx,%eax

	xor	2048(%rbp,%rcx,4),%eax		# rcon
___
}

# int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
#                        AES_KEY *key)
$code.=<<___;
.globl	AES_set_encrypt_key
.type	AES_set_encrypt_key,\@function,3
.align	16
AES_set_encrypt_key:
	push	%rbx
	push	%rbp

	mov	%esi,%ecx			# %ecx=bits
	mov	%rdi,%rsi			# %rsi=userKey
	mov	%rdx,%rdi			# %rdi=key

	test	\$-1,%rsi
	jz	.Lbadpointer
	test	\$-1,%rdi
	jz	.Lbadpointer

	.picmeup %rbp
	lea	AES_Te-.(%rbp),%rbp

	cmp	\$128,%ecx
	je	.L10rounds
	cmp	\$192,%ecx
	je	.L12rounds
	cmp	\$256,%ecx
	je	.L14rounds
	mov	\$-2,%rax			# invalid number of bits
	jmp	.Lexit

.L10rounds:
	mov	0(%rsi),%eax			# copy first 4 dwords
	mov	4(%rsi),%ebx
	mov	8(%rsi),%ecx
	mov	12(%rsi),%edx
	mov	%eax,0(%rdi)
	mov	%ebx,4(%rdi)
	mov	%ecx,8(%rdi)
	mov	%edx,12(%rdi)

	xor	%ecx,%ecx
	jmp	.L10shortcut
.align	4
.L10loop:
		mov	0(%rdi),%eax			# rk[0]
		mov	12(%rdi),%edx			# rk[3]
.L10shortcut:
___
		&enckey	();
$code.=<<___;
		mov	%eax,16(%rdi)			# rk[4]
		xor	4(%rdi),%eax
		mov	%eax,20(%rdi)			# rk[5]
		xor	8(%rdi),%eax
		mov	%eax,24(%rdi)			# rk[6]
		xor	12(%rdi),%eax
		mov	%eax,28(%rdi)			# rk[7]
		add	\$1,%ecx
		lea	16(%rdi),%rdi
		cmp	\$10,%ecx
	jl	.L10loop

	movl	\$10,80(%rdi)			# setup number of rounds
	xor	%rax,%rax
	jmp	.Lexit

.L12rounds:
	mov	0(%rsi),%eax			# copy first 6 dwords
	mov	4(%rsi),%ebx
	mov	8(%rsi),%ecx
	mov	12(%rsi),%edx
	mov	%eax,0(%rdi)
	mov	%ebx,4(%rdi)
	mov	%ecx,8(%rdi)
	mov	%edx,12(%rdi)
	mov	16(%rsi),%ecx
	mov	20(%rsi),%edx
	mov	%ecx,16(%rdi)
	mov	%edx,20(%rdi)

	xor	%ecx,%ecx
	jmp	.L12shortcut
.align	4
.L12loop:
		mov	0(%rdi),%eax			# rk[0]
		mov	20(%rdi),%edx			# rk[5]
.L12shortcut:
___
		&enckey	();
$code.=<<___;
		mov	%eax,24(%rdi)			# rk[6]
		xor	4(%rdi),%eax
		mov	%eax,28(%rdi)			# rk[7]
		xor	8(%rdi),%eax
		mov	%eax,32(%rdi)			# rk[8]
		xor	12(%rdi),%eax
		mov	%eax,36(%rdi)			# rk[9]

		cmp	\$7,%ecx
		je	.L12break
		add	\$1,%ecx

		xor	16(%rdi),%eax
		mov	%eax,40(%rdi)			# rk[10]
		xor	20(%rdi),%eax
		mov	%eax,44(%rdi)			# rk[11]

		lea	24(%rdi),%rdi
	jmp	.L12loop
.L12break:
	movl	\$12,72(%rdi)		# setup number of rounds
	xor	%rax,%rax
	jmp	.Lexit

.L14rounds:		
	mov	0(%rsi),%eax			# copy first 8 dwords
	mov	4(%rsi),%ebx
	mov	8(%rsi),%ecx
	mov	12(%rsi),%edx
	mov	%eax,0(%rdi)
	mov	%ebx,4(%rdi)
	mov	%ecx,8(%rdi)
	mov	%edx,12(%rdi)
	mov	16(%rsi),%eax
	mov	20(%rsi),%ebx
	mov	24(%rsi),%ecx
	mov	28(%rsi),%edx
	mov	%eax,16(%rdi)
	mov	%ebx,20(%rdi)
	mov	%ecx,24(%rdi)
	mov	%edx,28(%rdi)

	xor	%ecx,%ecx
	jmp	.L14shortcut
.align	4
.L14loop:
		mov	28(%rdi),%edx			# rk[4]
.L14shortcut:
		mov	0(%rdi),%eax			# rk[0]
___
		&enckey	();
$code.=<<___;
		mov	%eax,32(%rdi)			# rk[8]
		xor	4(%rdi),%eax
		mov	%eax,36(%rdi)			# rk[9]
		xor	8(%rdi),%eax
		mov	%eax,40(%rdi)			# rk[10]
		xor	12(%rdi),%eax
		mov	%eax,44(%rdi)			# rk[11]

		cmp	\$6,%ecx
		je	.L14break
		add	\$1,%ecx

		mov	%eax,%edx
		mov	16(%rdi),%eax			# rk[4]
		movz	%dl,%esi			# rk[11]>>0
		mov	2(%rbp,%rsi,8),%ebx
		movz	%dh,%esi			# rk[11]>>8
		and	\$0x000000FF,%ebx
		xor	%ebx,%eax

		mov	0(%rbp,%rsi,8),%ebx
		shr	\$16,%edx
		and	\$0x0000FF00,%ebx
		movz	%dl,%esi			# rk[11]>>16
		xor	%ebx,%eax

		mov	0(%rbp,%rsi,8),%ebx
		movz	%dh,%esi			# rk[11]>>24
		and	\$0x00FF0000,%ebx
		xor	%ebx,%eax

		mov	2(%rbp,%rsi,8),%ebx
		and	\$0xFF000000,%ebx
		xor	%ebx,%eax

		mov	%eax,48(%rdi)			# rk[12]
		xor	20(%rdi),%eax
		mov	%eax,52(%rdi)			# rk[13]
		xor	24(%rdi),%eax
		mov	%eax,56(%rdi)			# rk[14]
		xor	28(%rdi),%eax
		mov	%eax,60(%rdi)			# rk[15]

		lea	32(%rdi),%rdi
	jmp	.L14loop
.L14break:
	movl	\$14,48(%rdi)		# setup number of rounds
	xor	%rax,%rax
	jmp	.Lexit

.Lbadpointer:
	mov	\$-1,%rax
.Lexit:
	pop	%rbp
	pop	%rbx
	ret
.size	AES_set_encrypt_key,.-AES_set_encrypt_key
___

sub deckey()
{ my ($i,$ptr,$te,$td) = @_;
$code.=<<___;
	mov	$i($ptr),%eax
	mov	%eax,%edx
	movz	%ah,%ebx
	shr	\$16,%edx
	and	\$0xFF,%eax
	movzb	2($te,%rax,8),%rax
	movzb	2($te,%rbx,8),%rbx
	mov	0($td,%rax,8),%eax
	xor	3($td,%rbx,8),%eax
	movzb	%dh,%ebx
	and	\$0xFF,%edx
	movzb	2($te,%rdx,8),%rdx
	movzb	2($te,%rbx,8),%rbx
	xor	2($td,%rdx,8),%eax
	xor	1($td,%rbx,8),%eax
	mov	%eax,$i($ptr)
___
}

# int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
#                        AES_KEY *key)
$code.=<<___;
.globl	AES_set_decrypt_key
.type	AES_set_decrypt_key,\@function,3
.align	16
AES_set_decrypt_key:
	push	%rdx
	call	AES_set_encrypt_key
	cmp	\$0,%eax
	je	.Lproceed
	lea	24(%rsp),%rsp
	ret
.Lproceed:
	mov	(%rsp),%r8		# restore key schedule
	mov	%rbx,(%rsp)

	mov	240(%r8),%ecx		# pull number of rounds
	xor	%rdi,%rdi
	lea	(%rdi,%rcx,4),%rcx
	mov	%r8,%rsi
	lea	(%r8,%rcx,4),%rdi	# pointer to last chunk
.align	4
.Linvert:
		mov	0(%rsi),%rax
		mov	8(%rsi),%rbx
		mov	0(%rdi),%rcx
		mov	8(%rdi),%rdx
		mov	%rax,0(%rdi)
		mov	%rbx,8(%rdi)
		mov	%rcx,0(%rsi)
		mov	%rdx,8(%rsi)
		lea	16(%rsi),%rsi
		lea	-16(%rdi),%rdi
		cmp	%rsi,%rdi
	jne	.Linvert

	.picmeup %r9
	lea	AES_Td-.(%r9),%rdi
	lea	AES_Te-AES_Td(%rdi),%r9

	mov	%r8,%rsi
	mov	240(%r8),%ecx		# pull number of rounds
	sub	\$1,%ecx
.align	4
.Lpermute:
		lea	16(%rsi),%rsi
___
		&deckey	(0,"%rsi","%r9","%rdi");
		&deckey	(4,"%rsi","%r9","%rdi");
		&deckey	(8,"%rsi","%r9","%rdi");
		&deckey	(12,"%rsi","%r9","%rdi");
$code.=<<___;
		sub	\$1,%ecx
	jnz	.Lpermute

	xor	%rax,%rax
	pop	%rbx
	ret
.size	AES_set_decrypt_key,.-AES_set_decrypt_key
___

# void AES_cbc_encrypt (const void char *inp, unsigned char *out,
#			size_t length, const AES_KEY *key,
#			unsigned char *ivp,const int enc);
{
# stack frame layout
# -8(%rsp)		return address
my $_rsp="0(%rsp)";		# saved %rsp
my $_len="8(%rsp)";		# copy of 3rd parameter, length
my $_key="16(%rsp)";		# copy of 4th parameter, key
my $_ivp="24(%rsp)";		# copy of 5th parameter, ivp
my $keyp="32(%rsp)";		# one to pass as $key
my $ivec="40(%rsp)";		# ivec[16]
my $aes_key="56(%rsp)";		# copy of aes_key
my $mark="56+240(%rsp)";	# copy of aes_key->rounds

$code.=<<___;
.globl	AES_cbc_encrypt
.type	AES_cbc_encrypt,\@function,6
.align	16
AES_cbc_encrypt:
	cmp	\$0,%rdx	# check length
	je	.Lcbc_just_ret
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	cld

	.picmeup $sbox
.Lcbc_pic_point:

	cmp	\$0,%r9
	je	.LDECRYPT

	lea	AES_Te-.Lcbc_pic_point($sbox),$sbox

	# allocate aligned stack frame...
	lea	-64-248(%rsp),$key
	and	\$-64,$key

	# ... and make it doesn't alias with AES_Te modulo 4096
	mov	$sbox,%r10
	lea	2048($sbox),%r11
	mov	$key,%r12
	and	\$0xFFF,%r10	# s = $sbox&0xfff
	and	\$0xFFF,%r11	# e = ($sbox+2048)&0xfff
	and	\$0xFFF,%r12	# p = %rsp&0xfff

	cmp	%r11,%r12	# if (p=>e) %rsp =- (p-e);
	jb	.Lcbc_te_break_out
	sub	%r11,%r12
	sub	%r12,$key
	jmp	.Lcbc_te_ok
.Lcbc_te_break_out:		# else %rsp -= (p-s)&0xfff + framesz
	sub	%r10,%r12
	and	\$0xFFF,%r12
	add	\$320,%r12
	sub	%r12,$key
.align	4
.Lcbc_te_ok:

	xchg	%rsp,$key
	add	\$8,%rsp	# reserve for return address!
	mov	$key,$_rsp	# save %rsp
	mov	%rdx,$_len	# save copy of len
	mov	%rcx,$_key	# save copy of key
	mov	%r8,$_ivp	# save copy of ivp
	movl	\$0,$mark	# copy of aes_key->rounds = 0;
	mov	%r8,%rbp	# rearrange input arguments
	mov	%rsi,$out
	mov	%rdi,$inp
	mov	%rcx,$key

	# do we copy key schedule to stack?
	mov	$key,%r10
	sub	$sbox,%r10
	and	\$0xfff,%r10
	cmp	\$2048,%r10
	jb	.Lcbc_do_ecopy
	cmp	\$4096-248,%r10
	jb	.Lcbc_skip_ecopy
.align	4
.Lcbc_do_ecopy:
		mov	$key,%rsi
		lea	$aes_key,%rdi
		lea	$aes_key,$key
		mov	\$240/8,%ecx
		.long	0x90A548F3	# rep movsq
		mov	(%rsi),%eax	# copy aes_key->rounds
		mov	%eax,(%rdi)
.Lcbc_skip_ecopy:
	mov	$key,$keyp	# save key pointer

	mov	\$16,%ecx
.align	4
.Lcbc_prefetch_te:
		mov	0($sbox),%r10
		mov	32($sbox),%r11
		mov	64($sbox),%r12
		mov	96($sbox),%r13
		lea	128($sbox),$sbox
		sub	\$1,%ecx
	jnz	.Lcbc_prefetch_te
	sub	\$2048,$sbox

	test	\$-16,%rdx		# check upon length
	mov	%rdx,%r10
	mov	0(%rbp),$s0		# load iv
	mov	4(%rbp),$s1
	mov	8(%rbp),$s2
	mov	12(%rbp),$s3
	jz	.Lcbc_enc_tail		# short input...

.align	4
.Lcbc_enc_loop:
		xor	0($inp),$s0
		xor	4($inp),$s1
		xor	8($inp),$s2
		xor	12($inp),$s3
		mov	$inp,$ivec	# if ($verticalspin) save inp

		mov	$keyp,$key	# restore key
		call	_x86_64_AES_encrypt

		mov	$ivec,$inp	# if ($verticalspin) restore inp
		mov	$s0,0($out)
		mov	$s1,4($out)
		mov	$s2,8($out)
		mov	$s3,12($out)

		mov	$_len,%r10
		lea	16($inp),$inp
		lea	16($out),$out
		sub	\$16,%r10
		test	\$-16,%r10
		mov	%r10,$_len
	jnz	.Lcbc_enc_loop
	test	\$15,%r10
	jnz	.Lcbc_enc_tail
	mov	$_ivp,%rbp	# restore ivp
	mov	$s0,0(%rbp)	# save ivec
	mov	$s1,4(%rbp)
	mov	$s2,8(%rbp)
	mov	$s3,12(%rbp)

.align	4
.Lcbc_cleanup:
	cmpl	\$0,$mark	# was the key schedule copied?
	lea	$aes_key,%rdi
	mov	$_rsp,%rsp
	je	.Lcbc_exit
		mov	\$240/8,%ecx
		xor	%rax,%rax
		.long	0x90AB48F3	# rep stosq
.Lcbc_exit:
	popfq
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
.Lcbc_just_ret:
	ret
.align	4
.Lcbc_enc_tail:
	cmp	$inp,$out
	je	.Lcbc_enc_in_place
	mov	%r10,%rcx
	mov	$inp,%rsi
	mov	$out,%rdi
	.long	0xF689A4F3		# rep movsb
.Lcbc_enc_in_place:
	mov	\$16,%rcx		# zero tail
	sub	%r10,%rcx
	xor	%rax,%rax
	.long	0xF689AAF3		# rep stosb
	mov	$out,$inp		# this is not a mistake!
	movq	\$16,$_len		# len=16
	jmp	.Lcbc_enc_loop		# one more spin...
#----------------------------- DECRYPT -----------------------------#
.align	16
.LDECRYPT:
	lea	AES_Td-.Lcbc_pic_point($sbox),$sbox

	# allocate aligned stack frame...
	lea	-64-248(%rsp),$key
	and	\$-64,$key

	# ... and make it doesn't alias with AES_Td modulo 4096
	mov	$sbox,%r10
	lea	3072($sbox),%r11
	mov	$key,%r12
	and	\$0xFFF,%r10	# s = $sbox&0xfff
	and	\$0xFFF,%r11	# e = ($sbox+2048)&0xfff
	and	\$0xFFF,%r12	# p = %rsp&0xfff

	cmp	%r11,%r12	# if (p=>e) %rsp =- (p-e);
	jb	.Lcbc_td_break_out
	sub	%r11,%r12
	sub	%r12,$key
	jmp	.Lcbc_td_ok
.Lcbc_td_break_out:		# else %rsp -= (p-s)&0xfff + framesz
	sub	%r10,%r12
	and	\$0xFFF,%r12
	add	\$320,%r12
	sub	%r12,$key
.align	4
.Lcbc_td_ok:

	xchg	%rsp,$key
	add	\$8,%rsp	# reserve for return address!
	mov	$key,$_rsp	# save %rsp
	mov	%rdx,$_len	# save copy of len
	mov	%rcx,$_key	# save copy of key
	mov	%r8,$_ivp	# save copy of ivp
	movl	\$0,$mark	# copy of aes_key->rounds = 0;
	mov	%r8,%rbp	# rearrange input arguments
	mov	%rsi,$out
	mov	%rdi,$inp
	mov	%rcx,$key

	# do we copy key schedule to stack?
	mov	$key,%r10
	sub	$sbox,%r10
	and	\$0xfff,%r10
	cmp	\$3072,%r10
	jb	.Lcbc_do_dcopy
	cmp	\$4096-248,%r10
	jb	.Lcbc_skip_dcopy
.align	4
.Lcbc_do_dcopy:
		mov	$key,%rsi
		lea	$aes_key,%rdi
		lea	$aes_key,$key
		mov	\$240/8,%ecx
		.long	0x90A548F3	# rep movsq
		mov	(%rsi),%eax	# copy aes_key->rounds
		mov	%eax,(%rdi)
.Lcbc_skip_dcopy:
	mov	$key,$keyp	# save key pointer

	mov	\$24,%ecx
.align	4
.Lcbc_prefetch_td:
		mov	0($sbox),%r10
		mov	32($sbox),%r11
		mov	64($sbox),%r12
		mov	96($sbox),%r13
		lea	128($sbox),$sbox
		sub	\$1,%ecx
	jnz	.Lcbc_prefetch_td
	sub	\$3072,$sbox

	cmp	$inp,$out
	je	.Lcbc_dec_in_place

	mov	%rbp,$ivec
.align	4
.Lcbc_dec_loop:
		mov	0($inp),$s0		# read input
		mov	4($inp),$s1
		mov	8($inp),$s2
		mov	12($inp),$s3
		mov	$inp,8+$ivec	# if ($verticalspin) save inp

		mov	$keyp,$key	# restore key
		call	_x86_64_AES_decrypt

		mov	$ivec,%rbp	# load ivp
		mov	8+$ivec,$inp	# if ($verticalspin) restore inp
		xor	0(%rbp),$s0	# xor iv
		xor	4(%rbp),$s1
		xor	8(%rbp),$s2
		xor	12(%rbp),$s3
		mov	$inp,%rbp	# current input, next iv

		mov	$_len,%r10	# load len
		sub	\$16,%r10
		jc	.Lcbc_dec_partial
		mov	%r10,$_len	# update len
		mov	%rbp,$ivec	# update ivp

		mov	$s0,0($out)	# write output
		mov	$s1,4($out)
		mov	$s2,8($out)
		mov	$s3,12($out)

		lea	16($inp),$inp
		lea	16($out),$out
	jnz	.Lcbc_dec_loop
.Lcbc_dec_end:
	mov	$_ivp,%r12		# load user ivp
	mov	0(%rbp),%r10		# load iv
	mov	8(%rbp),%r11
	mov	%r10,0(%r12)		# copy back to user
	mov	%r11,8(%r12)
	jmp	.Lcbc_cleanup

.align	4
.Lcbc_dec_partial:
	mov	$s0,0+$ivec		# dump output to stack
	mov	$s1,4+$ivec
	mov	$s2,8+$ivec
	mov	$s3,12+$ivec
	mov	$out,%rdi
	lea	$ivec,%rsi
	mov	\$16,%rcx
	add	%r10,%rcx		# number of bytes to copy
	.long	0xF689A4F3		# rep movsb
	jmp	.Lcbc_dec_end

.align	16
.Lcbc_dec_in_place:
		mov	0($inp),$s0	# load input
		mov	4($inp),$s1
		mov	8($inp),$s2
		mov	12($inp),$s3

		mov	$inp,$ivec	# if ($verticalspin) save inp
		mov	$keyp,$key
		call	_x86_64_AES_decrypt

		mov	$ivec,$inp	# if ($verticalspin) restore inp
		mov	$_ivp,%rbp
		xor	0(%rbp),$s0
		xor	4(%rbp),$s1
		xor	8(%rbp),$s2
		xor	12(%rbp),$s3

		mov	0($inp),%r10	# copy input to iv
		mov	8($inp),%r11
		mov	%r10,0(%rbp)
		mov	%r11,8(%rbp)

		mov	$s0,0($out)	# save output [zaps input]
		mov	$s1,4($out)
		mov	$s2,8($out)
		mov	$s3,12($out)

		mov	$_len,%rcx
		lea	16($inp),$inp
		lea	16($out),$out
		sub	\$16,%rcx
		jc	.Lcbc_dec_in_place_partial
		mov	%rcx,$_len
	jnz	.Lcbc_dec_in_place
	jmp	.Lcbc_cleanup

.align	4
.Lcbc_dec_in_place_partial:
	# one can argue if this is actually required
	lea	($out,%rcx),%rdi
	lea	(%rbp,%rcx),%rsi
	neg	%rcx
	.long	0xF689A4F3	# rep movsb	# restore tail
	jmp	.Lcbc_cleanup
.size	AES_cbc_encrypt,.-AES_cbc_encrypt
___
}

$code.=<<___;
.globl	AES_Te
.align	64
AES_Te:
___
	&_data_word(0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6);
	&_data_word(0x0df2f2ff, 0xbd6b6bd6, 0xb16f6fde, 0x54c5c591);
	&_data_word(0x50303060, 0x03010102, 0xa96767ce, 0x7d2b2b56);
	&_data_word(0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec);
	&_data_word(0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa);
	&_data_word(0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb);
	&_data_word(0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45);
	&_data_word(0xbf9c9c23, 0xf7a4a453, 0x967272e4, 0x5bc0c09b);
	&_data_word(0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c);
	&_data_word(0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83);
	&_data_word(0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9);
	&_data_word(0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a);
	&_data_word(0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d);
	&_data_word(0x28181830, 0xa1969637, 0x0f05050a, 0xb59a9a2f);
	&_data_word(0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df);
	&_data_word(0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea);
	&_data_word(0x1b090912, 0x9e83831d, 0x742c2c58, 0x2e1a1a34);
	&_data_word(0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b);
	&_data_word(0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d);
	&_data_word(0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413);
	&_data_word(0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1);
	&_data_word(0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6);
	&_data_word(0xbe6a6ad4, 0x46cbcb8d, 0xd9bebe67, 0x4b393972);
	&_data_word(0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85);
	&_data_word(0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed);
	&_data_word(0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511);
	&_data_word(0xcf45458a, 0x10f9f9e9, 0x06020204, 0x817f7ffe);
	&_data_word(0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b);
	&_data_word(0xf35151a2, 0xfea3a35d, 0xc0404080, 0x8a8f8f05);
	&_data_word(0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1);
	&_data_word(0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142);
	&_data_word(0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf);
	&_data_word(0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3);
	&_data_word(0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e);
	&_data_word(0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a);
	&_data_word(0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6);
	&_data_word(0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3);
	&_data_word(0x66222244, 0x7e2a2a54, 0xab90903b, 0x8388880b);
	&_data_word(0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428);
	&_data_word(0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad);
	&_data_word(0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14);
	&_data_word(0xdb494992, 0x0a06060c, 0x6c242448, 0xe45c5cb8);
	&_data_word(0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4);
	&_data_word(0xa8919139, 0xa4959531, 0x37e4e4d3, 0x8b7979f2);
	&_data_word(0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda);
	&_data_word(0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949);
	&_data_word(0xb46c6cd8, 0xfa5656ac, 0x07f4f4f3, 0x25eaeacf);
	&_data_word(0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810);
	&_data_word(0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c);
	&_data_word(0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697);
	&_data_word(0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e);
	&_data_word(0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f);
	&_data_word(0x907070e0, 0x423e3e7c, 0xc4b5b571, 0xaa6666cc);
	&_data_word(0xd8484890, 0x05030306, 0x01f6f6f7, 0x120e0e1c);
	&_data_word(0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969);
	&_data_word(0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27);
	&_data_word(0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122);
	&_data_word(0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433);
	&_data_word(0xb69b9b2d, 0x221e1e3c, 0x92878715, 0x20e9e9c9);
	&_data_word(0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5);
	&_data_word(0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a);
	&_data_word(0xdabfbf65, 0x31e6e6d7, 0xc6424284, 0xb86868d0);
	&_data_word(0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e);
	&_data_word(0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c);
#rcon:
$code.=<<___;
	.long	0x00000001, 0x00000002, 0x00000004, 0x00000008
	.long	0x00000010, 0x00000020, 0x00000040, 0x00000080
	.long	0x0000001b, 0x00000036, 0, 0, 0, 0, 0, 0
___
$code.=<<___;
.globl	AES_Td
.align	64
AES_Td:
___
	&_data_word(0x50a7f451, 0x5365417e, 0xc3a4171a, 0x965e273a);
	&_data_word(0xcb6bab3b, 0xf1459d1f, 0xab58faac, 0x9303e34b);
	&_data_word(0x55fa3020, 0xf66d76ad, 0x9176cc88, 0x254c02f5);
	&_data_word(0xfcd7e54f, 0xd7cb2ac5, 0x80443526, 0x8fa362b5);
	&_data_word(0x495ab1de, 0x671bba25, 0x980eea45, 0xe1c0fe5d);
	&_data_word(0x02752fc3, 0x12f04c81, 0xa397468d, 0xc6f9d36b);
	&_data_word(0xe75f8f03, 0x959c9215, 0xeb7a6dbf, 0xda595295);
	&_data_word(0x2d83bed4, 0xd3217458, 0x2969e049, 0x44c8c98e);
	&_data_word(0x6a89c275, 0x78798ef4, 0x6b3e5899, 0xdd71b927);
	&_data_word(0xb64fe1be, 0x17ad88f0, 0x66ac20c9, 0xb43ace7d);
	&_data_word(0x184adf63, 0x82311ae5, 0x60335197, 0x457f5362);
	&_data_word(0xe07764b1, 0x84ae6bbb, 0x1ca081fe, 0x942b08f9);
	&_data_word(0x58684870, 0x19fd458f, 0x876cde94, 0xb7f87b52);
	&_data_word(0x23d373ab, 0xe2024b72, 0x578f1fe3, 0x2aab5566);
	&_data_word(0x0728ebb2, 0x03c2b52f, 0x9a7bc586, 0xa50837d3);
	&_data_word(0xf2872830, 0xb2a5bf23, 0xba6a0302, 0x5c8216ed);
	&_data_word(0x2b1ccf8a, 0x92b479a7, 0xf0f207f3, 0xa1e2694e);
	&_data_word(0xcdf4da65, 0xd5be0506, 0x1f6234d1, 0x8afea6c4);
	&_data_word(0x9d532e34, 0xa055f3a2, 0x32e18a05, 0x75ebf6a4);
	&_data_word(0x39ec830b, 0xaaef6040, 0x069f715e, 0x51106ebd);
	&_data_word(0xf98a213e, 0x3d06dd96, 0xae053edd, 0x46bde64d);
	&_data_word(0xb58d5491, 0x055dc471, 0x6fd40604, 0xff155060);
	&_data_word(0x24fb9819, 0x97e9bdd6, 0xcc434089, 0x779ed967);
	&_data_word(0xbd42e8b0, 0x888b8907, 0x385b19e7, 0xdbeec879);
	&_data_word(0x470a7ca1, 0xe90f427c, 0xc91e84f8, 0x00000000);
	&_data_word(0x83868009, 0x48ed2b32, 0xac70111e, 0x4e725a6c);
	&_data_word(0xfbff0efd, 0x5638850f, 0x1ed5ae3d, 0x27392d36);
	&_data_word(0x64d90f0a, 0x21a65c68, 0xd1545b9b, 0x3a2e3624);
	&_data_word(0xb1670a0c, 0x0fe75793, 0xd296eeb4, 0x9e919b1b);
	&_data_word(0x4fc5c080, 0xa220dc61, 0x694b775a, 0x161a121c);
	&_data_word(0x0aba93e2, 0xe52aa0c0, 0x43e0223c, 0x1d171b12);
	&_data_word(0x0b0d090e, 0xadc78bf2, 0xb9a8b62d, 0xc8a91e14);
	&_data_word(0x8519f157, 0x4c0775af, 0xbbdd99ee, 0xfd607fa3);
	&_data_word(0x9f2601f7, 0xbcf5725c, 0xc53b6644, 0x347efb5b);
	&_data_word(0x7629438b, 0xdcc623cb, 0x68fcedb6, 0x63f1e4b8);
	&_data_word(0xcadc31d7, 0x10856342, 0x40229713, 0x2011c684);
	&_data_word(0x7d244a85, 0xf83dbbd2, 0x1132f9ae, 0x6da129c7);
	&_data_word(0x4b2f9e1d, 0xf330b2dc, 0xec52860d, 0xd0e3c177);
	&_data_word(0x6c16b32b, 0x99b970a9, 0xfa489411, 0x2264e947);
	&_data_word(0xc48cfca8, 0x1a3ff0a0, 0xd82c7d56, 0xef903322);
	&_data_word(0xc74e4987, 0xc1d138d9, 0xfea2ca8c, 0x360bd498);
	&_data_word(0xcf81f5a6, 0x28de7aa5, 0x268eb7da, 0xa4bfad3f);
	&_data_word(0xe49d3a2c, 0x0d927850, 0x9bcc5f6a, 0x62467e54);
	&_data_word(0xc2138df6, 0xe8b8d890, 0x5ef7392e, 0xf5afc382);
	&_data_word(0xbe805d9f, 0x7c93d069, 0xa92dd56f, 0xb31225cf);
	&_data_word(0x3b99acc8, 0xa77d1810, 0x6e639ce8, 0x7bbb3bdb);
	&_data_word(0x097826cd, 0xf418596e, 0x01b79aec, 0xa89a4f83);
	&_data_word(0x656e95e6, 0x7ee6ffaa, 0x08cfbc21, 0xe6e815ef);
	&_data_word(0xd99be7ba, 0xce366f4a, 0xd4099fea, 0xd67cb029);
	&_data_word(0xafb2a431, 0x31233f2a, 0x3094a5c6, 0xc066a235);
	&_data_word(0x37bc4e74, 0xa6ca82fc, 0xb0d090e0, 0x15d8a733);
	&_data_word(0x4a9804f1, 0xf7daec41, 0x0e50cd7f, 0x2ff69117);
	&_data_word(0x8dd64d76, 0x4db0ef43, 0x544daacc, 0xdf0496e4);
	&_data_word(0xe3b5d19e, 0x1b886a4c, 0xb81f2cc1, 0x7f516546);
	&_data_word(0x04ea5e9d, 0x5d358c01, 0x737487fa, 0x2e410bfb);
	&_data_word(0x5a1d67b3, 0x52d2db92, 0x335610e9, 0x1347d66d);
	&_data_word(0x8c61d79a, 0x7a0ca137, 0x8e14f859, 0x893c13eb);
	&_data_word(0xee27a9ce, 0x35c961b7, 0xede51ce1, 0x3cb1477a);
	&_data_word(0x59dfd29c, 0x3f73f255, 0x79ce1418, 0xbf37c773);
	&_data_word(0xeacdf753, 0x5baafd5f, 0x146f3ddf, 0x86db4478);
	&_data_word(0x81f3afca, 0x3ec468b9, 0x2c342438, 0x5f40a3c2);
	&_data_word(0x72c31d16, 0x0c25e2bc, 0x8b493c28, 0x41950dff);
	&_data_word(0x7101a839, 0xdeb30c08, 0x9ce4b4d8, 0x90c15664);
	&_data_word(0x6184cb7b, 0x70b632d5, 0x745c6c48, 0x4257b8d0);
#Td4:
	&data_word(0x52525252, 0x09090909, 0x6a6a6a6a, 0xd5d5d5d5);
	&data_word(0x30303030, 0x36363636, 0xa5a5a5a5, 0x38383838);
	&data_word(0xbfbfbfbf, 0x40404040, 0xa3a3a3a3, 0x9e9e9e9e);
	&data_word(0x81818181, 0xf3f3f3f3, 0xd7d7d7d7, 0xfbfbfbfb);
	&data_word(0x7c7c7c7c, 0xe3e3e3e3, 0x39393939, 0x82828282);
	&data_word(0x9b9b9b9b, 0x2f2f2f2f, 0xffffffff, 0x87878787);
	&data_word(0x34343434, 0x8e8e8e8e, 0x43434343, 0x44444444);
	&data_word(0xc4c4c4c4, 0xdededede, 0xe9e9e9e9, 0xcbcbcbcb);
	&data_word(0x54545454, 0x7b7b7b7b, 0x94949494, 0x32323232);
	&data_word(0xa6a6a6a6, 0xc2c2c2c2, 0x23232323, 0x3d3d3d3d);
	&data_word(0xeeeeeeee, 0x4c4c4c4c, 0x95959595, 0x0b0b0b0b);
	&data_word(0x42424242, 0xfafafafa, 0xc3c3c3c3, 0x4e4e4e4e);
	&data_word(0x08080808, 0x2e2e2e2e, 0xa1a1a1a1, 0x66666666);
	&data_word(0x28282828, 0xd9d9d9d9, 0x24242424, 0xb2b2b2b2);
	&data_word(0x76767676, 0x5b5b5b5b, 0xa2a2a2a2, 0x49494949);
	&data_word(0x6d6d6d6d, 0x8b8b8b8b, 0xd1d1d1d1, 0x25252525);
	&data_word(0x72727272, 0xf8f8f8f8, 0xf6f6f6f6, 0x64646464);
	&data_word(0x86868686, 0x68686868, 0x98989898, 0x16161616);
	&data_word(0xd4d4d4d4, 0xa4a4a4a4, 0x5c5c5c5c, 0xcccccccc);
	&data_word(0x5d5d5d5d, 0x65656565, 0xb6b6b6b6, 0x92929292);
	&data_word(0x6c6c6c6c, 0x70707070, 0x48484848, 0x50505050);
	&data_word(0xfdfdfdfd, 0xedededed, 0xb9b9b9b9, 0xdadadada);
	&data_word(0x5e5e5e5e, 0x15151515, 0x46464646, 0x57575757);
	&data_word(0xa7a7a7a7, 0x8d8d8d8d, 0x9d9d9d9d, 0x84848484);
	&data_word(0x90909090, 0xd8d8d8d8, 0xabababab, 0x00000000);
	&data_word(0x8c8c8c8c, 0xbcbcbcbc, 0xd3d3d3d3, 0x0a0a0a0a);
	&data_word(0xf7f7f7f7, 0xe4e4e4e4, 0x58585858, 0x05050505);
	&data_word(0xb8b8b8b8, 0xb3b3b3b3, 0x45454545, 0x06060606);
	&data_word(0xd0d0d0d0, 0x2c2c2c2c, 0x1e1e1e1e, 0x8f8f8f8f);
	&data_word(0xcacacaca, 0x3f3f3f3f, 0x0f0f0f0f, 0x02020202);
	&data_word(0xc1c1c1c1, 0xafafafaf, 0xbdbdbdbd, 0x03030303);
	&data_word(0x01010101, 0x13131313, 0x8a8a8a8a, 0x6b6b6b6b);
	&data_word(0x3a3a3a3a, 0x91919191, 0x11111111, 0x41414141);
	&data_word(0x4f4f4f4f, 0x67676767, 0xdcdcdcdc, 0xeaeaeaea);
	&data_word(0x97979797, 0xf2f2f2f2, 0xcfcfcfcf, 0xcececece);
	&data_word(0xf0f0f0f0, 0xb4b4b4b4, 0xe6e6e6e6, 0x73737373);
	&data_word(0x96969696, 0xacacacac, 0x74747474, 0x22222222);
	&data_word(0xe7e7e7e7, 0xadadadad, 0x35353535, 0x85858585);
	&data_word(0xe2e2e2e2, 0xf9f9f9f9, 0x37373737, 0xe8e8e8e8);
	&data_word(0x1c1c1c1c, 0x75757575, 0xdfdfdfdf, 0x6e6e6e6e);
	&data_word(0x47474747, 0xf1f1f1f1, 0x1a1a1a1a, 0x71717171);
	&data_word(0x1d1d1d1d, 0x29292929, 0xc5c5c5c5, 0x89898989);
	&data_word(0x6f6f6f6f, 0xb7b7b7b7, 0x62626262, 0x0e0e0e0e);
	&data_word(0xaaaaaaaa, 0x18181818, 0xbebebebe, 0x1b1b1b1b);
	&data_word(0xfcfcfcfc, 0x56565656, 0x3e3e3e3e, 0x4b4b4b4b);
	&data_word(0xc6c6c6c6, 0xd2d2d2d2, 0x79797979, 0x20202020);
	&data_word(0x9a9a9a9a, 0xdbdbdbdb, 0xc0c0c0c0, 0xfefefefe);
	&data_word(0x78787878, 0xcdcdcdcd, 0x5a5a5a5a, 0xf4f4f4f4);
	&data_word(0x1f1f1f1f, 0xdddddddd, 0xa8a8a8a8, 0x33333333);
	&data_word(0x88888888, 0x07070707, 0xc7c7c7c7, 0x31313131);
	&data_word(0xb1b1b1b1, 0x12121212, 0x10101010, 0x59595959);
	&data_word(0x27272727, 0x80808080, 0xecececec, 0x5f5f5f5f);
	&data_word(0x60606060, 0x51515151, 0x7f7f7f7f, 0xa9a9a9a9);
	&data_word(0x19191919, 0xb5b5b5b5, 0x4a4a4a4a, 0x0d0d0d0d);
	&data_word(0x2d2d2d2d, 0xe5e5e5e5, 0x7a7a7a7a, 0x9f9f9f9f);
	&data_word(0x93939393, 0xc9c9c9c9, 0x9c9c9c9c, 0xefefefef);
	&data_word(0xa0a0a0a0, 0xe0e0e0e0, 0x3b3b3b3b, 0x4d4d4d4d);
	&data_word(0xaeaeaeae, 0x2a2a2a2a, 0xf5f5f5f5, 0xb0b0b0b0);
	&data_word(0xc8c8c8c8, 0xebebebeb, 0xbbbbbbbb, 0x3c3c3c3c);
	&data_word(0x83838383, 0x53535353, 0x99999999, 0x61616161);
	&data_word(0x17171717, 0x2b2b2b2b, 0x04040404, 0x7e7e7e7e);
	&data_word(0xbabababa, 0x77777777, 0xd6d6d6d6, 0x26262626);
	&data_word(0xe1e1e1e1, 0x69696969, 0x14141414, 0x63636363);
	&data_word(0x55555555, 0x21212121, 0x0c0c0c0c, 0x7d7d7d7d);

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;
