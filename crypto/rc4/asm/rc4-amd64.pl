#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. Rights for redistribution and usage in source and binary
# forms are granted according to the OpenSSL license.
# ====================================================================
#
# 2.22x RC4 tune-up:-) It should be noted though that my hand [as in
# "hand-coded assembler"] doesn't stand for the whole improvement
# coefficient. It turned out that eliminating RC4_CHAR from config
# line results in ~40% improvement (yes, even for C implementation).
# Presumably it has everything to do with AMD cache architecture and
# RAW or whatever penalties. Once again! The module *requires* config
# line *without* RC4_CHAR! As for coding "secret," I bet on partial
# register arithmetics. For example instead of 'inc %r8; and $255,%r8'
# I simply 'inc %r8b'. Even though optimization manual discourages
# to operate on partial registers, it turned out to be the best bet.
# At least for AMD... How IA32E would perform remains to be seen...

# As was shown by Marc Bevand reordering of couple of load operations
# results in even higher performance gain of 3.3x:-) At least on
# Opteron... For reference, 1x in this case is RC4_CHAR C-code
# compiled with gcc 3.3.2, which performs at ~54MBps per 1GHz clock.
# Latter means that if you want to *estimate* what to expect from
# *your* CPU, then multiply 54 by 3.3 and clock frequency in GHz.

# Intel P4 EM64T core was found to run the AMD64 code really slow...
# The only way to achieve comparable performance on P4 is to keep
# RC4_CHAR. Kind of ironic, huh? As it's apparently impossible to
# compose blended code, which would perform even within 30% marginal
# on either AMD and Intel platforms, I implement both cases. See
# rc4_skey.c for further details... This applies to 0.9.8 and later.
# In 0.9.7 context RC4_CHAR codepath is never engaged and ~70 bytes
# of code remain redundant.

$output=shift;

$win64a=1 if ($output =~ /win64a.[s|asm]/);

open STDOUT,">$output" || die "can't open $output: $!";

if (defined($win64a)) {
    $dat="%rcx";	# arg1
    $len="%rdx";	# arg2
    $inp="%rsi";	# r8, arg3 moves here
    $out="%rdi";	# r9, arg4 moves here
} else {
    $dat="%rdi";	# arg1
    $len="%rsi";	# arg2
    $inp="%rdx";	# arg3
    $out="%rcx";	# arg4
}

$XX="%r10";
$TX="%r8";
$YY="%r11";
$TY="%r9";

sub PTR() {
    my $ret=shift;
    if (defined($win64a)) {
	$ret =~ s/\[([\S]+)\+([\S]+)\]/[$2+$1]/g;   # [%rN+%rM*4]->[%rM*4+%rN]
	$ret =~ s/:([^\[]+)\[([^\]]+)\]/:[$2+$1]/g; # :off[ea]->:[ea+off]
    } else {
	$ret =~ s/[\+\*]/,/g;		# [%rN+%rM*4]->[%rN,%rM,4]
	$ret =~ s/\[([^\]]+)\]/($1)/g;	# [%rN]->(%rN)
    }
    $ret;
}

$code=<<___ if (!defined($win64a));
.text

.globl	RC4
.type	RC4,\@function
.align	16
RC4:	or	$len,$len
	jne	.Lentry
	repret
.Lentry:
___
$code=<<___ if (defined($win64a));
_TEXT	SEGMENT
PUBLIC	RC4
ALIGN	16
RC4	PROC
	or	$len,$len
	jne	.Lentry
	repret
.Lentry:
	push	%rdi
	push	%rsi
	sub	\$40,%rsp
	mov	%r8,$inp
	mov	%r9,$out
___
$code.=<<___;
	add	\$8,$dat
	movl	`&PTR("DWORD:-8[$dat]")`,$XX#d
	movl	`&PTR("DWORD:-4[$dat]")`,$YY#d
	cmpl	\$-1,`&PTR("DWORD:256[$dat]")`
	je	.LRC4_CHAR
	test	\$-8,$len
	jz	.Lloop1
.align	16
.Lloop8:
	inc	$XX#b
	movl	`&PTR("DWORD:[$dat+$XX*4]")`,$TX#d
	add	$TX#b,$YY#b
	movl	`&PTR("DWORD:[$dat+$YY*4]")`,$TY#d
	movl	$TX#d,`&PTR("DWORD:[$dat+$YY*4]")`
	movl	$TY#d,`&PTR("DWORD:[$dat+$XX*4]")`
	add	$TX#b,$TY#b
	inc	$XX#b
	movl	`&PTR("DWORD:[$dat+$XX*4]")`,$TX#d
	movb	`&PTR("BYTE:[$dat+$TY*4]")`,%al
___
for ($i=1;$i<=6;$i++) {
$code.=<<___;
	add	$TX#b,$YY#b
	ror	\$8,%rax
	movl	`&PTR("DWORD:[$dat+$YY*4]")`,$TY#d
	movl	$TX#d,`&PTR("DWORD:[$dat+$YY*4]")`
	movl	$TY#d,`&PTR("DWORD:[$dat+$XX*4]")`
	add	$TX#b,$TY#b
	inc	$XX#b
	movl	`&PTR("DWORD:[$dat+$XX*4]")`,$TX#d
	movb	`&PTR("BYTE:[$dat+$TY*4]")`,%al
___
}
$code.=<<___;
	add	$TX#b,$YY#b
	ror	\$8,%rax
	movl	`&PTR("DWORD:[$dat+$YY*4]")`,$TY#d
	movl	$TX#d,`&PTR("DWORD:[$dat+$YY*4]")`
	movl	$TY#d,`&PTR("DWORD:[$dat+$XX*4]")`
	sub	\$8,$len
	add	$TY#b,$TX#b
	movb	`&PTR("BYTE:[$dat+$TX*4]")`,%al
	ror	\$8,%rax
	add	\$8,$inp
	add	\$8,$out

	xor	`&PTR("QWORD:-8[$inp]")`,%rax
	mov	%rax,`&PTR("QWORD:-8[$out]")`

	test	\$-8,$len
	jnz	.Lloop8
	cmp	\$0,$len
	jne	.Lloop1
.Lexit:
	movl	$XX#d,`&PTR("DWORD:-8[$dat]")`
	movl	$YY#d,`&PTR("DWORD:-4[$dat]")`
___
$code.=<<___ if (defined($win64a));
	add	\$40,%rsp
	pop	%rsi
	pop	%rdi
___
$code.=<<___;
	repret
.align	16
.Lloop1:
	movzb	`&PTR("BYTE:[$inp]")`,%eax
	inc	$XX#b
	movl	`&PTR("DWORD:[$dat+$XX*4]")`,$TX#d
	add	$TX#b,$YY#b
	movl	`&PTR("DWORD:[$dat+$YY*4]")`,$TY#d
	movl	$TX#d,`&PTR("DWORD:[$dat+$YY*4]")`
	movl	$TY#d,`&PTR("DWORD:[$dat+$XX*4]")`
	add	$TY#b,$TX#b
	movl	`&PTR("DWORD:[$dat+$TX*4]")`,$TY#d
	xor	$TY,%rax
	inc	$inp
	movb	%al,`&PTR("BYTE:[$out]")`
	inc	$out
	dec	$len
	jnz	.Lloop1
	jmp	.Lexit

.align	16
.LRC4_CHAR:
	inc	$XX#b
	movzb	`&PTR("BYTE:[$dat+$XX]")`,$TX#d
	add	$TX#b,$YY#b
	movzb	`&PTR("BYTE:[$dat+$YY]")`,$TY#d
	movb	$TX#b,`&PTR("BYTE:[$dat+$YY]")`
	movb	$TY#b,`&PTR("BYTE:[$dat+$XX]")`
	add	$TX#b,$TY#b
	movzb	`&PTR("BYTE:[$dat+$TY]")`,$TY#d
	xorb	`&PTR("BYTE:[$inp]")`,$TY#b
	movb	$TY#b,`&PTR("BYTE:[$out]")`
	inc	$inp
	inc	$out
	dec	$len
	jnz	.LRC4_CHAR
	jmp	.Lexit
___
$code.=<<___ if (defined($win64a));
RC4	ENDP
_TEXT	ENDS
END
___
$code.=<<___ if (!defined($win64a));
.size	RC4,.-RC4
___

$code =~ s/#([bwd])/$1/gm;
$code =~ s/\`([^\`]*)\`/eval $1/gem;

if (defined($win64a)) {
    $code =~ s/\.align/ALIGN/gm;
    $code =~ s/[\$%]//gm;
    $code =~ s/\.L/\$L/gm;
    $code =~ s/([\w]+)([\s]+)([\S]+),([\S]+)/$1$2$4,$3/gm;
    $code =~ s/([QD]*WORD|BYTE):/$1 PTR/gm;
    $code =~ s/mov[bwlq]/mov/gm;
    $code =~ s/movzb/movzx/gm;
    $code =~ s/repret/DB\t0F3h,0C3h/gm;
    $code =~ s/cmpl/cmp/gm;
    $code =~ s/xorb/xor/gm;
} else {
    $code =~ s/([QD]*WORD|BYTE)://gm;
    $code =~ s/repret/.byte\t0xF3,0xC3/gm;
}
print $code;
