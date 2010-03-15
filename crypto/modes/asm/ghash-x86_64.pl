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
# The module implements "4-bit" Galois field multiplication and
# streamed GHASH function. "4-bit" means that it uses 256 bytes
# per-key table [+128 bytes shared table]. Performance results are for
# streamed GHASH subroutine and are expressed in cycles per processed
# byte, less is better:
#
#		gcc 3.4.x	assembler
#
# Opteron	18.5		10.2		+80%
# Core2		26.0		16.4		+58%

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

# per-function register layout
$Xi="%rdi";
$Htbl="%rsi";

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
$inp="%rdi";
$len="%rsi";
$Xi="%rdx";
$Htbl="%rcx";

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

.align	64
.type	rem_4bit,\@object
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
___
}
$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;
