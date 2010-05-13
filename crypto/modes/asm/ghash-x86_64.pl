#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# March 2010
#
# The module implements "4-bit" GCM GHASH function and underlying
# single multiplication operation in GF(2^128). "4-bit" means that it
# uses 256 bytes per-key table [+128 bytes shared table]. Performance
# results are for streamed GHASH subroutine and are expressed in
# cycles per processed byte, less is better:
#
#		gcc 3.4.x	assembler
#
# Opteron	18.5		10.2		+80%
# Core2		17.5		11.0		+59%

# May 2010
#
# Add PCLMULQDQ version performing at 2.07 cycles per processed byte.
# See ghash-x86.pl for background information and details about coding
# techniques.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open STDOUT,"| $^X $xlate $flavour $output";

# common register layout
$nlo="%rax";
$nhi="%rbx";
$Zlo="%r8";
$Zhi="%r9";
$tmp="%r10";
$rem_4bit = "%r11";

$Xi="%rdi";
$Htbl="%rsi";

# per-function register layout
$cnt="%rcx";
$rem="%rdx";

sub lo() { my $r=shift; $r =~ s/%[er]([a-d])x/%\1l/;
			$r =~ s/%[er]([sd]i)/%\1l/;
			$r =~ s/%(r[0-9]+)[d]?/%\1b/;   $r; }

{ my $N;
  sub loop() {
  my $inp = shift;

	$N++;
$code.=<<___;
	xor	$nlo,$nlo
	xor	$nhi,$nhi
	mov	`&lo("$Zlo")`,`&lo("$nlo")`
	mov	`&lo("$Zlo")`,`&lo("$nhi")`
	shl	\$4,`&lo("$nlo")`
	mov	\$14,$cnt
	mov	8($Htbl,$nlo),$Zlo
	mov	($Htbl,$nlo),$Zhi
	and	\$0xf0,`&lo("$nhi")`
	mov	$Zlo,$rem
	jmp	.Loop$N

.align	16
.Loop$N:
	shr	\$4,$Zlo
	and	\$0xf,$rem
	mov	$Zhi,$tmp
	mov	($inp,$cnt),`&lo("$nlo")`
	shr	\$4,$Zhi
	xor	8($Htbl,$nhi),$Zlo
	shl	\$60,$tmp
	xor	($Htbl,$nhi),$Zhi
	mov	`&lo("$nlo")`,`&lo("$nhi")`
	xor	($rem_4bit,$rem,8),$Zhi
	mov	$Zlo,$rem
	shl	\$4,`&lo("$nlo")`
	xor	$tmp,$Zlo
	dec	$cnt
	js	.Lbreak$N

	shr	\$4,$Zlo
	and	\$0xf,$rem
	mov	$Zhi,$tmp
	shr	\$4,$Zhi
	xor	8($Htbl,$nlo),$Zlo
	shl	\$60,$tmp
	xor	($Htbl,$nlo),$Zhi
	and	\$0xf0,`&lo("$nhi")`
	xor	($rem_4bit,$rem,8),$Zhi
	mov	$Zlo,$rem
	xor	$tmp,$Zlo
	jmp	.Loop$N

.align	16
.Lbreak$N:
	shr	\$4,$Zlo
	and	\$0xf,$rem
	mov	$Zhi,$tmp
	shr	\$4,$Zhi
	xor	8($Htbl,$nlo),$Zlo
	shl	\$60,$tmp
	xor	($Htbl,$nlo),$Zhi
	and	\$0xf0,`&lo("$nhi")`
	xor	($rem_4bit,$rem,8),$Zhi
	mov	$Zlo,$rem
	xor	$tmp,$Zlo

	shr	\$4,$Zlo
	and	\$0xf,$rem
	mov	$Zhi,$tmp
	shr	\$4,$Zhi
	xor	8($Htbl,$nhi),$Zlo
	shl	\$60,$tmp
	xor	($Htbl,$nhi),$Zhi
	xor	$tmp,$Zlo
	xor	($rem_4bit,$rem,8),$Zhi

	bswap	$Zlo
	bswap	$Zhi
___
}}

$code=<<___;
.text

.globl	gcm_gmult_4bit
.type	gcm_gmult_4bit,\@function,2
.align	16
gcm_gmult_4bit:
	push	%rbx
	push	%rbp		# %rbp and %r12 are pushed exclusively in
	push	%r12		# order to reuse Win64 exception handler...
.Lgmult_prologue:

	movzb	15($Xi),$Zlo
	lea	.Lrem_4bit(%rip),$rem_4bit
___
	&loop	($Xi);
$code.=<<___;
	mov	$Zlo,8($Xi)
	mov	$Zhi,($Xi)

	mov	16(%rsp),%rbx
	lea	24(%rsp),%rsp
.Lgmult_epilogue:
	ret
.size	gcm_gmult_4bit,.-gcm_gmult_4bit
___

# per-function register layout
$inp="%rdx";
$len="%rcx";

$cnt="%rbp";
$rem="%r12";

$code.=<<___;
.globl	gcm_ghash_4bit
.type	gcm_ghash_4bit,\@function,4
.align	16
gcm_ghash_4bit:
	push	%rbx
	push	%rbp
	push	%r12
.Lghash_prologue:

	mov	8($Xi),$Zlo
	mov	($Xi),$Zhi
	add	$inp,$len
	lea	.Lrem_4bit(%rip),$rem_4bit
.align	4
.Louter_loop:
	xor	8($inp),$Zlo
	xor	($inp),$Zhi
	lea	16($inp),$inp
	mov	$Zlo,8($Xi)
	mov	$Zhi,($Xi)
	shr	\$56,$Zlo
___
	&loop	($Xi);
$code.=<<___;
	cmp	$len,$inp
	jb	.Louter_loop

	mov	$Zlo,8($Xi)
	mov	$Zhi,($Xi)

	mov	0(%rsp),%r12
	mov	8(%rsp),%rbp
	mov	16(%rsp),%rbx
	lea	24(%rsp),%rsp
.Lghash_epilogue:
	ret
.size	gcm_ghash_4bit,.-gcm_ghash_4bit
___

######################################################################
# PCLMULQDQ version.

@_4args=$win64?	("%rcx","%rdx","%r8", "%r9") :	# Win64 order
		("%rdi","%rsi","%rdx","%rcx");	# Unix order

($Xi,$Xhi)=("%xmm0","%xmm1");	$Hkey="%xmm2";
($T1,$T2,$T3)=("%xmm3","%xmm4","%xmm5");

sub clmul64x64_T2 {	# minimal register pressure
my ($Xhi,$Xi,$Hkey,$modulo)=@_;

$code.=<<___ if (!defined($modulo));
	movdqa		$Xi,$Xhi		#
	pshufd		\$0b01001110,$Xi,$T1
	pshufd		\$0b01001110,$Hkey,$T2
	pxor		$Xi,$T1			#
	pxor		$Hkey,$T2
___
$code.=<<___;
	pclmulqdq	\$0x00,$Hkey,$Xi	#######
	pclmulqdq	\$0x11,$Hkey,$Xhi	#######
	pclmulqdq	\$0x00,$T2,$T1		#######
	pxor		$Xi,$T1			#
	pxor		$Xhi,$T1		#

	movdqa		$T1,$T2			#
	psrldq		\$8,$T1
	pslldq		\$8,$T2			#
	pxor		$T1,$Xhi
	pxor		$T2,$Xi			#
___
}

sub reduction_alg9 {	# 17/13 times faster than Intel version
my ($Xhi,$Xi) = @_;

$code.=<<___;
	# 1st phase
	movdqa		$Xi,$T1			#
	psllq		\$1,$Xi
	pxor		$T1,$Xi			#
	psllq		\$5,$Xi			#
	pxor		$T1,$Xi			#
	psllq		\$57,$Xi		#
	movdqa		$Xi,$T2			#
	pslldq		\$8,$Xi
	psrldq		\$8,$T2			#	
	pxor		$T1,$Xi
	pxor		$T2,$Xhi		#

	# 2nd phase
	movdqa		$Xi,$T2
	psrlq		\$5,$Xi
	pxor		$T2,$Xi			#
	psrlq		\$1,$Xi			#
	pxor		$T2,$Xi			#
	pxor		$Xhi,$T2
	psrlq		\$1,$Xi			#
	pxor		$T2,$Xi			#
___
}

{ my ($Htbl,$Xip)=@_4args;

$code.=<<___;
.globl	gcm_init_clmul
.type	gcm_init_clmul,\@abi-omnipotent
.align	16
gcm_init_clmul:
	movdqu		($Xip),$Hkey
	pshufd		\$0b01001110,$Hkey,$Hkey	# dword swap

	# <<1 twist
	pshufd		\$0b11111111,$Hkey,$T2	# broadcast uppermost dword
	movdqa		$Hkey,$T1
	psllq		\$1,$Hkey
	pxor		$T3,$T3			#
	psrlq		\$63,$T1
	pcmpgtd		$T2,$T3			# broadcast carry bit
	pslldq		\$8,$T1
	por		$T1,$Hkey		# H<<=1

	# magic reduction
	pand		.L0x1c2_polynomial(%rip),$T3
	pxor		$T3,$Hkey		# if(carry) H^=0x1c2_polynomial

	# calculate H^2
	movdqa		$Hkey,$Xi
___
	&clmul64x64_T2	($Xhi,$Xi,$Hkey);
	&reduction_alg9	($Xhi,$Xi);
$code.=<<___;
	movdqu		$Hkey,($Htbl)		# save H
	movdqu		$Xi,16($Htbl)		# save H^2
	ret
.size	gcm_init_clmul,.-gcm_init_clmul
___
}

{ my ($Xip,$Htbl)=@_4args;

$code.=<<___;
.globl	gcm_gmult_clmul
.type	gcm_gmult_clmul,\@abi-omnipotent
.align	16
gcm_gmult_clmul:
	movdqu		($Xip),$Xi
	movdqa		.Lbswap_mask(%rip),$T3
	movdqu		($Htbl),$Hkey
	pshufb		$T3,$Xi
___
	&clmul64x64_T2	($Xhi,$Xi,$Hkey);
	&reduction_alg9	($Xhi,$Xi);
$code.=<<___;
	pshufb		$T3,$Xi
	movdqu		$Xi,($Xip)
	ret
.size	gcm_gmult_clmul,.-gcm_gmult_clmul
___
}

{ my ($Xip,$Htbl,$inp,$len)=@_4args;
  my $Xn="%xmm6";
  my $Xhn="%xmm7";
  my $Hkey2="%xmm8";
  my $T1n="%xmm9";
  my $T2n="%xmm10";

$code.=<<___;
.globl	gcm_ghash_clmul
.type	gcm_ghash_clmul,\@abi-omnipotent
.align	16
gcm_ghash_clmul:
___
$code.=<<___ if ($win64);
.LSEH_begin_gcm_ghash_clmul:
	# I can't trust assembler to use specific encoding:-(
	.byte	0x48,0x83,0xec,0x58		#sub	\$0x58,%rsp
	.byte	0x0f,0x29,0x34,0x24		#movaps	%xmm6,(%rsp)
	.byte	0x0f,0x29,0x7c,0x24,0x10	#movdqa	%xmm7,0x10(%rsp)
	.byte	0x44,0x0f,0x29,0x44,0x24,0x20	#movaps	%xmm8,0x20(%rsp)
	.byte	0x44,0x0f,0x29,0x4c,0x24,0x30	#movaps	%xmm9,0x30(%rsp)
	.byte	0x44,0x0f,0x29,0x54,0x24,0x40	#movaps	%xmm10,0x40(%rsp)
___
$code.=<<___;
	movdqa		.Lbswap_mask(%rip),$T3

	movdqu		($Xip),$Xi
	movdqu		($Htbl),$Hkey
	pshufb		$T3,$Xi

	sub		\$0x10,$len
	jz		.Lodd_tail

	movdqu		16($Htbl),$Hkey2
	#######
	# Xi+2 =[H*(Ii+1 + Xi+1)] mod P =
	#	[(H*Ii+1) + (H*Xi+1)] mod P =
	#	[(H*Ii+1) + H^2*(Ii+Xi)] mod P
	#
	movdqu		($inp),$T1		# Ii
	movdqu		16($inp),$Xn		# Ii+1
	pshufb		$T3,$T1
	pshufb		$T3,$Xn
	pxor		$T1,$Xi			# Ii+Xi
___
	&clmul64x64_T2	($Xhn,$Xn,$Hkey);	# H*Ii+1
$code.=<<___;
	movdqa		$Xi,$Xhi		#
	pshufd		\$0b01001110,$Xi,$T1
	pshufd		\$0b01001110,$Hkey2,$T2
	pxor		$Xi,$T1			#
	pxor		$Hkey2,$T2

	lea		32($inp),$inp		# i+=2
	sub		\$0x20,$len
	jbe		.Leven_tail

.Lmod_loop:
___
	&clmul64x64_T2	($Xhi,$Xi,$Hkey2,1);	# H^2*(Ii+Xi)
$code.=<<___;
	movdqu		($inp),$T1		# Ii
	pxor		$Xn,$Xi			# (H*Ii+1) + H^2*(Ii+Xi)
	pxor		$Xhn,$Xhi

	movdqu		16($inp),$Xn		# Ii+1
	pshufb		$T3,$T1
	pshufb		$T3,$Xn

	movdqa		$Xn,$Xhn		#
	pshufd		\$0b01001110,$Xn,$T1n
	pshufd		\$0b01001110,$Hkey,$T2n
	pxor		$Xn,$T1n		#
	pxor		$Hkey,$T2n
	 pxor		$T1,$Xhi		# "Ii+Xi", consume early

	  movdqa	$Xi,$T1			# 1st phase
	  psllq		\$1,$Xi
	  pxor		$T1,$Xi			#
	  psllq		\$5,$Xi			#
	  pxor		$T1,$Xi			#
	pclmulqdq	\$0x00,$Hkey,$Xn	#######
	  psllq		\$57,$Xi		#
	  movdqa	$Xi,$T2			#
	  pslldq	\$8,$Xi
	  psrldq	\$8,$T2			#	
	  pxor		$T1,$Xi
	  pxor		$T2,$Xhi		#

	pclmulqdq	\$0x11,$Hkey,$Xhn	#######
	  movdqa	$Xi,$T2			# 2nd phase
	  psrlq		\$5,$Xi
	  pxor		$T2,$Xi			#
	  psrlq		\$1,$Xi			#
	  pxor		$T2,$Xi			#
	  pxor		$Xhi,$T2
	  psrlq		\$1,$Xi			#
	  pxor		$T2,$Xi			#

	pclmulqdq	\$0x00,$T2n,$T1n	#######
	 movdqa		$Xi,$Xhi		#
	 pshufd		\$0b01001110,$Xi,$T1
	 pshufd		\$0b01001110,$Hkey2,$T2
	 pxor		$Xi,$T1			#
	 pxor		$Hkey2,$T2

	pxor		$Xn,$T1n		#
	pxor		$Xhn,$T1n		#
	movdqa		$T1n,$T2n		#
	psrldq		\$8,$T1n
	pslldq		\$8,$T2n		#
	pxor		$T1n,$Xhn
	pxor		$T2n,$Xn		#

	lea		32($inp),$inp
	sub		\$0x20,$len
	ja		.Lmod_loop

.Leven_tail:
___
	&clmul64x64_T2	($Xhi,$Xi,$Hkey2,1);	# H^2*(Ii+Xi)
$code.=<<___;
	pxor		$Xn,$Xi			# (H*Ii+1) + H^2*(Ii+Xi)
	pxor		$Xhn,$Xhi
___
	&reduction_alg9	($Xhi,$Xi);
$code.=<<___;
	test		$len,$len
	jnz		.Ldone

.Lodd_tail:
	movdqu		($inp),$T1		# Ii
	pshufb		$T3,$T1
	pxor		$T1,$Xi			# Ii+Xi
___
	&clmul64x64_T2	($Xhi,$Xi,$Hkey);	# H*(Ii+Xi)
	&reduction_alg9	($Xhi,$Xi);
$code.=<<___;
.Ldone:
	pshufb		$T3,$Xi
	movdqu		$Xi,($Xip)
___
$code.=<<___ if ($win64);
	movaps	(%rsp),%xmm6
	movaps	0x10(%rsp),%xmm7
	movaps	0x20(%rsp),%xmm8
	movaps	0x30(%rsp),%xmm9
	movaps	0x40(%rsp),%xmm10
	add	\$0x58,%rsp
___
$code.=<<___;
	ret
.LSEH_end_gcm_ghash_clmul:
.size	gcm_ghash_clmul,.-gcm_ghash_clmul
___
}

$code.=<<___;
.align	64
.Lbswap_mask:
	.byte	15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
.L0x1c2_polynomial:
	.byte	1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xc2
.align	64
.type	.Lrem_4bit,\@object
.Lrem_4bit:
	.long	0,`0x0000<<16`,0,`0x1C20<<16`,0,`0x3840<<16`,0,`0x2460<<16`
	.long	0,`0x7080<<16`,0,`0x6CA0<<16`,0,`0x48C0<<16`,0,`0x54E0<<16`
	.long	0,`0xE100<<16`,0,`0xFD20<<16`,0,`0xD940<<16`,0,`0xC560<<16`
	.long	0,`0x9180<<16`,0,`0x8DA0<<16`,0,`0xA9C0<<16`,0,`0xB5E0<<16`
.asciz	"GHASH for x86_64, CRYPTOGAMS by <appro\@openssl.org>"
.align	64
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

	mov	8($disp),%rsi		# disp->ImageBase
	mov	56($disp),%r11		# disp->HandlerData

	mov	0(%r11),%r10d		# HandlerData[0]
	lea	(%rsi,%r10),%r10	# prologue label
	cmp	%r10,%rbx		# context->Rip<prologue label
	jb	.Lin_prologue

	mov	152($context),%rax	# pull context->Rsp

	mov	4(%r11),%r10d		# HandlerData[1]
	lea	(%rsi,%r10),%r10	# epilogue label
	cmp	%r10,%rbx		# context->Rip>=epilogue label
	jae	.Lin_prologue

	lea	24(%rax),%rax		# adjust "rsp"

	mov	-8(%rax),%rbx
	mov	-16(%rax),%rbp
	mov	-24(%rax),%r12
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12

.Lin_prologue:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

	mov	40($disp),%rdi		# disp->ContextRecord
	mov	$context,%rsi		# context
	mov	\$`1232/8`,%ecx		# sizeof(CONTEXT)
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
	.rva	.LSEH_begin_gcm_gmult_4bit
	.rva	.LSEH_end_gcm_gmult_4bit
	.rva	.LSEH_info_gcm_gmult_4bit

	.rva	.LSEH_begin_gcm_ghash_4bit
	.rva	.LSEH_end_gcm_ghash_4bit
	.rva	.LSEH_info_gcm_ghash_4bit

	.rva	.LSEH_begin_gcm_ghash_clmul
	.rva	.LSEH_end_gcm_ghash_clmul
	.rva	.LSEH_info_gcm_ghash_clmul

.section	.xdata
.align	8
.LSEH_info_gcm_gmult_4bit:
	.byte	9,0,0,0
	.rva	se_handler
	.rva	.Lgmult_prologue,.Lgmult_epilogue	# HandlerData
.LSEH_info_gcm_ghash_4bit:
	.byte	9,0,0,0
	.rva	se_handler
	.rva	.Lghash_prologue,.Lghash_epilogue	# HandlerData
.LSEH_info_gcm_ghash_clmul:
	.byte	0x01,0x1f,0x0b,0x00
	.byte	0x1f,0xa8,0x04,0x00	#movaps 0x40(rsp),xmm10
	.byte	0x19,0x98,0x03,0x00	#movaps 0x30(rsp),xmm9
	.byte	0x13,0x88,0x02,0x00	#movaps 0x20(rsp),xmm8
	.byte	0x0d,0x78,0x01,0x00	#movaps 0x10(rsp),xmm7
	.byte	0x08,0x68,0x00,0x00	#movaps (rsp),xmm6
	.byte	0x04,0xa2,0x00,0x00	#sub	rsp,0x58
___
}

sub rex {
 local *opcode=shift;
 my ($dst,$src)=@_;

   if ($dst>=8 || $src>=8) {
	$rex=0x40;
	$rex|=0x04 if($dst>=8);
	$rex|=0x01 if($src>=8);
	push @opcode,$rex;
   }
}

sub pclmulqdq {
  my $arg=shift;
  my @opcode=(0x66);

    if ($arg=~/\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/) {
	rex(\@opcode,$3,$2);
	push @opcode,0x0f,0x3a,0x44;
	push @opcode,0xc0|($2&7)|(($3&7)<<3);	# ModR/M
	my $c=$1;
	push @opcode,$c=~/^0/?oct($c):$c;
	return ".byte\t".join(',',@opcode);
    }
    return "pclmulqdq\t".$arg;
}

$code =~ s/\`([^\`]*)\`/eval($1)/gem;
$code =~ s/\bpclmulqdq\s+(\$.*%xmm[0-9]+).*$/pclmulqdq($1)/gem;

print $code;

close STDOUT;
