#!/usr/bin/env perl

$output=shift;
$win64a=1 if ($output =~ /win64a\.[s|asm]/);
open STDOUT,">$output" || die "can't open $output: $!";

print<<___ if(defined($win64a));
TEXT	SEGMENT
PUBLIC	OPENSSL_rdtsc
ALIGN	16
OPENSSL_rdtsc	PROC NEAR
	rdtsc
	shl	rdx,32
	or	rax,rdx
	ret
OPENSSL_rdtsc	ENDP
TEXT	ENDS
END
___
print<<___ if(!defined($win64a));
.text
.globl	OPENSSL_rdtsc
.align	16
OPENSSL_rdtsc:
	rdtsc
	shl	\$32,%rdx
	or	%rdx,%rax
	ret
.size	OPENSSL_rdtsc,.-OPENSSL_rdtsc
___
