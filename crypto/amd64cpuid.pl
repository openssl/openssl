#!/usr/bin/env perl

$output=shift;
$win64a=1 if ($output =~ /win64a\.[s|asm]/);
open STDOUT,">$output" || die "can't open $output: $!";

print<<___ if(defined($win64a));
_TEXT	SEGMENT
PUBLIC	OPENSSL_rdtsc
ALIGN	16
OPENSSL_rdtsc	PROC
	rdtsc
	shl	rdx,32
	or	rax,rdx
	ret
OPENSSL_rdtsc	ENDP

PUBLIC	OPENSSL_atomic_add
ALIGN	16
OPENSSL_atomic_add	PROC
	mov	eax,DWORD PTR[rcx]
\$Lspin:	lea	r8,DWORD PTR[rdx+rax]
lock	cmpxchg	DWORD PTR[rcx],r8d
	jne	\$Lspin
	mov	eax,r8d
	cdqe    
	ret
OPENSSL_atomic_add	ENDP

PUBLIC	OPENSSL_wipe_cpu
ALIGN	16
OPENSSL_wipe_cpu	PROC
	pxor	xmm0,xmm0
	pxor	xmm1,xmm1
	pxor	xmm2,xmm2
	pxor	xmm3,xmm3
	pxor	xmm4,xmm4
	pxor	xmm5,xmm5
	xor	rcx,rcx
	xor	rdx,rdx
	xor	r8,r8
	xor	r9,r9
	xor	r10,r10
	xor	r11,r11
	lea	rax,QWORD PTR[rsp+8]
	ret
OPENSSL_wipe_cpu	ENDP

OPENSSL_ia32_cpuid	PROC
	mov	r8,rbx
	mov	eax,1
	cpuid
	shl	rcx,32
	mov	eax,edx
	mov	rbx,r8
	or	rax,rcx
	ret
OPENSSL_ia32_cpuid	ENDP
_TEXT	ENDS

CRT\$XIU	SEGMENT
EXTRN	OPENSSL_cpuid_setup:PROC
DQ	OPENSSL_cpuid_setup
CRT\$XIU	ENDS
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

.globl	OPENSSL_atomic_add
.type	OPENSSL_atomic_add,\@function
.align	16
OPENSSL_atomic_add:
	movl	(%rdi),%eax
.Lspin:	lea	(%rsi,%rax),%r8
lock;	cmpxchg	%r8d,(%rdi)
	jne	.Lspin
	mov	%r8d,%eax
	cdqe
	ret
.size	OPENSSL_atomic_add,.-OPENSSL_atomic_add

.globl	OPENSSL_wipe_cpu
.type	OPENSSL_wipe_cpu,\@function
.align	16
OPENSSL_wipe_cpu:
	pxor	%xmm0,%xmm0
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	pxor	%xmm6,%xmm6
	pxor	%xmm7,%xmm7
	pxor	%xmm8,%xmm8
	pxor	%xmm9,%xmm9
	pxor	%xmm10,%xmm10
	pxor	%xmm11,%xmm11
	pxor	%xmm12,%xmm12
	pxor	%xmm13,%xmm13
	pxor	%xmm14,%xmm14
	pxor	%xmm15,%xmm15
	xor	%rcx,%rcx
	xor	%rdx,%rdx
	xor	%rsi,%rsi
	xor	%rdi,%rdi
	xor	%r8,%r8
	xor	%r9,%r9
	xor	%r10,%r10
	xor	%r11,%r11
	lea	8(%rsp),%rax
	ret
.size	OPENSSL_wipe_cpu,.-OPENSSL_wipe_cpu

.globl	OPENSSL_ia32_cpuid
.align	16
OPENSSL_ia32_cpuid:
	mov	%rbx,%r8
	mov	\$1,%eax
	cpuid
	shl	\$32,%rcx
	mov	%edx,%eax
	mov	%r8,%rbx
	or	%rcx,%rax
	ret
.size	OPENSSL_ia32_cpuid,.-OPENSSL_ia32_cpuid

.section	.init
	call	OPENSSL_cpuid_setup
	.align	16
___
