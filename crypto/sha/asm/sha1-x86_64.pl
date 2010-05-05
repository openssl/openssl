#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# sha1_block procedure for x86_64.
#
# It was brought to my attention that on EM64T compiler-generated code
# was far behind 32-bit assembler implementation. This is unlike on
# Opteron where compiler-generated code was only 15% behind 32-bit
# assembler, which originally made it hard to motivate the effort.
# There was suggestion to mechanically translate 32-bit code, but I
# dismissed it, reasoning that x86_64 offers enough register bank
# capacity to fully utilize SHA-1 parallelism. Therefore this fresh
# implementation:-) However! While 64-bit code does perform better
# on Opteron, I failed to beat 32-bit assembler on EM64T core. Well,
# x86_64 does offer larger *addressable* bank, but out-of-order core
# reaches for even more registers through dynamic aliasing, and EM64T
# core must have managed to run-time optimize even 32-bit code just as
# good as 64-bit one. Performance improvement is summarized in the
# following table:
#
#		gcc 3.4		32-bit asm	cycles/byte
# Opteron	+45%		+20%		6.8
# Xeon P4	+65%		+0%		9.9
# Core2		+60%		+10%		7.0

# August 2009.
#
# The code was revised to minimize code size and to maximize
# "distance" between instructions producing input to 'lea'
# instruction and the 'lea' instruction itself, which is essential
# for Intel Atom core.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open STDOUT,"| $^X $xlate $flavour $output";

$ctx="%rdi";	# 1st arg
$inp="%rsi";	# 2nd arg
$num="%rdx";	# 3rd arg

# reassign arguments in order to produce more compact code
$ctx="%r8";
$inp="%r9";
$num="%r10";

$t0="%eax";
$t1="%ebx";
$t2="%ecx";
@xi=("%edx","%ebp");
$A="%esi";
$B="%edi";
$C="%r11d";
$D="%r12d";
$E="%r13d";

@V=($A,$B,$C,$D,$E);

sub BODY_00_19 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;
$code.=<<___ if ($i==0);
	mov	`4*$i`($inp),$xi[0]
	bswap	$xi[0]
	mov	$xi[0],`4*$i`(%rsp)
___
$code.=<<___ if ($i<15);
	mov	$c,$t0
	mov	`4*$j`($inp),$xi[1]
	mov	$a,$t2
	xor	$d,$t0
	bswap	$xi[1]
	rol	\$5,$t2
	lea	0x5a827999($xi[0],$e),$e
	and	$b,$t0
	mov	$xi[1],`4*$j`(%rsp)
	add	$t2,$e
	xor	$d,$t0
	rol	\$30,$b
	add	$t0,$e
___
$code.=<<___ if ($i>=15);
	mov	`4*($j%16)`(%rsp),$xi[1]
	mov	$c,$t0
	mov	$a,$t2
	xor	`4*(($j+2)%16)`(%rsp),$xi[1]
	xor	$d,$t0
	rol	\$5,$t2
	xor	`4*(($j+8)%16)`(%rsp),$xi[1]
	and	$b,$t0
	lea	0x5a827999($xi[0],$e),$e
	xor	`4*(($j+13)%16)`(%rsp),$xi[1]
	xor	$d,$t0
	rol	\$1,$xi[1]
	add	$t2,$e
	rol	\$30,$b
	mov	$xi[1],`4*($j%16)`(%rsp)
	add	$t0,$e
___
unshift(@xi,pop(@xi));
}

sub BODY_20_39 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;
my $K=($i<40)?0x6ed9eba1:0xca62c1d6;
$code.=<<___ if ($i<79);
	mov	`4*($j%16)`(%rsp),$xi[1]
	mov	$c,$t0
	mov	$a,$t2
	xor	`4*(($j+2)%16)`(%rsp),$xi[1]
	xor	$b,$t0
	rol	\$5,$t2
	lea	$K($xi[0],$e),$e
	xor	`4*(($j+8)%16)`(%rsp),$xi[1]
	xor	$d,$t0
	add	$t2,$e
	xor	`4*(($j+13)%16)`(%rsp),$xi[1]
	rol	\$30,$b
	add	$t0,$e
	rol	\$1,$xi[1]
___
$code.=<<___ if ($i<76);
	mov	$xi[1],`4*($j%16)`(%rsp)
___
$code.=<<___ if ($i==79);
	mov	$c,$t0
	mov	$a,$t2
	xor	$b,$t0
	lea	$K($xi[0],$e),$e
	rol	\$5,$t2
	xor	$d,$t0
	add	$t2,$e
	rol	\$30,$b
	add	$t0,$e
___
unshift(@xi,pop(@xi));
}

sub BODY_40_59 {
my ($i,$a,$b,$c,$d,$e)=@_;
my $j=$i+1;
$code.=<<___;
	mov	`4*($j%16)`(%rsp),$xi[1]
	mov	$c,$t0
	mov	$c,$t1
	xor	`4*(($j+2)%16)`(%rsp),$xi[1]
	and	$d,$t0
	mov	$a,$t2
	xor	`4*(($j+8)%16)`(%rsp),$xi[1]
	xor	$d,$t1
	lea	0x8f1bbcdc($xi[0],$e),$e
	rol	\$5,$t2
	xor	`4*(($j+13)%16)`(%rsp),$xi[1]
	add	$t0,$e
	and	$b,$t1
	rol	\$1,$xi[1]
	add	$t1,$e
	rol	\$30,$b
	mov	$xi[1],`4*($j%16)`(%rsp)
	add	$t2,$e
___
unshift(@xi,pop(@xi));
}

$code.=<<___;
.text

.globl	sha1_block_data_order
.type	sha1_block_data_order,\@function,3
.align	16
sha1_block_data_order:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	mov	%rsp,%r11
	mov	%rdi,$ctx	# reassigned argument
	sub	\$`8+16*4`,%rsp
	mov	%rsi,$inp	# reassigned argument
	and	\$-64,%rsp
	mov	%rdx,$num	# reassigned argument
	mov	%r11,`16*4`(%rsp)
.Lprologue:

	mov	0($ctx),$A
	mov	4($ctx),$B
	mov	8($ctx),$C
	mov	12($ctx),$D
	mov	16($ctx),$E

.align	4
.Lloop:
___
for($i=0;$i<20;$i++)	{ &BODY_00_19($i,@V); unshift(@V,pop(@V)); }
for(;$i<40;$i++)	{ &BODY_20_39($i,@V); unshift(@V,pop(@V)); }
for(;$i<60;$i++)	{ &BODY_40_59($i,@V); unshift(@V,pop(@V)); }
for(;$i<80;$i++)	{ &BODY_20_39($i,@V); unshift(@V,pop(@V)); }
$code.=<<___;
	add	0($ctx),$A
	add	4($ctx),$B
	add	8($ctx),$C
	add	12($ctx),$D
	add	16($ctx),$E
	mov	$A,0($ctx)
	mov	$B,4($ctx)
	mov	$C,8($ctx)
	mov	$D,12($ctx)
	mov	$E,16($ctx)

	sub	\$1,$num
	lea	`16*4`($inp),$inp
	jnz	.Lloop

	mov	`16*4`(%rsp),%rsi
	mov	(%rsi),%r13
	mov	8(%rsi),%r12
	mov	16(%rsi),%rbp
	mov	24(%rsi),%rbx
	lea	32(%rsi),%rsp
.Lepilogue:
	ret
.size	sha1_block_data_order,.-sha1_block_data_order

.asciz	"SHA1 block transform for x86_64, CRYPTOGAMS by <appro\@openssl.org>"
.align	16
___

# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
if ($win64) {
$rec="%rcx";
$frame="%rdx";
$context="%r8";
$disp="%r9";

$code.=<<___;
.extern	__imp_RtlVirtualUnwind
.type	se_handler,\@abi-omnipotent
.align	16
se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	lea	.Lprologue(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<.Lprologue
	jb	.Lin_prologue

	mov	152($context),%rax	# pull context->Rsp

	lea	.Lepilogue(%rip),%r10
	cmp	%r10,%rbx		# context->Rip>=.Lepilogue
	jae	.Lin_prologue

	mov	`16*4`(%rax),%rax	# pull saved stack pointer
	lea	32(%rax),%rax

	mov	-8(%rax),%rbx
	mov	-16(%rax),%rbp
	mov	-24(%rax),%r12
	mov	-32(%rax),%r13
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12
	mov	%r13,224($context)	# restore context->R13

.Lin_prologue:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

	mov	40($disp),%rdi		# disp->ContextRecord
	mov	$context,%rsi		# context
	mov	\$154,%ecx		# sizeof(CONTEXT)
	.long	0xa548f3fc		# cld; rep movsq

	mov	$disp,%rsi
	xor	%rcx,%rcx		# arg1, UNW_FLAG_NHANDLER
	mov	8(%rsi),%rdx		# arg2, disp->ImageBase
	mov	0(%rsi),%r8		# arg3, disp->ControlPc
	mov	16(%rsi),%r9		# arg4, disp->FunctionEntry
	mov	40(%rsi),%r10		# disp->ContextRecord
	lea	56(%rsi),%r11		# &disp->HandlerData
	lea	24(%rsi),%r12		# &disp->EstablisherFrame
	mov	%r10,32(%rsp)		# arg5
	mov	%r11,40(%rsp)		# arg6
	mov	%r12,48(%rsp)		# arg7
	mov	%rcx,56(%rsp)		# arg8, (NULL)
	call	*__imp_RtlVirtualUnwind(%rip)

	mov	\$1,%eax		# ExceptionContinueSearch
	add	\$64,%rsp
	popfq
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	pop	%rdi
	pop	%rsi
	ret
.size	se_handler,.-se_handler

.section	.pdata
.align	4
	.rva	.LSEH_begin_sha1_block_data_order
	.rva	.LSEH_end_sha1_block_data_order
	.rva	.LSEH_info_sha1_block_data_order

.section	.xdata
.align	8
.LSEH_info_sha1_block_data_order:
	.byte	9,0,0,0
	.rva	se_handler
___
}

####################################################################

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT;
