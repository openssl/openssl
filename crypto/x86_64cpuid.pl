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

	xor	eax,eax
	cpuid
	xor	eax,eax
	cmp	ebx,0756e6547h
	setne	al
	mov	r9d,eax
	cmp	edx,049656e69h
	setne	al
	or	r9d,eax
	cmp	ecx,06c65746eh
	setne	al
	or	r9d,eax

	mov	eax,1
	cpuid
	bt	edx,28
	jnc	\$Ldone
	cmp	r9,0
	jne	\$Lnotintel
	or	edx,000100000h
	and	ah,15
	cmp	ah,15
	je	\$Lnotintel
	or	edx,040000000h
\$Lnotintel:
	shr	ebx,16
	cmp	bl,1
	ja	\$Ldone
	and	edx,0efffffffh
\$Ldone:
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
	shlq	\$32,%rdx
	orq	%rdx,%rax
	ret
.size	OPENSSL_rdtsc,.-OPENSSL_rdtsc

.globl	OPENSSL_atomic_add
.type	OPENSSL_atomic_add,\@function
.align	16
OPENSSL_atomic_add:
	movl	(%rdi),%eax
.Lspin:	leaq	(%rsi,%rax),%r8
lock;	cmpxchgl	%r8d,(%rdi)
	jne	.Lspin
	movl	%r8d,%eax
	.byte	0x48,0x98
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
	xorq	%rcx,%rcx
	xorq	%rdx,%rdx
	xorq	%rsi,%rsi
	xorq	%rdi,%rdi
	xorq	%r8,%r8
	xorq	%r9,%r9
	xorq	%r10,%r10
	xorq	%r11,%r11
	leaq	8(%rsp),%rax
	ret
.size	OPENSSL_wipe_cpu,.-OPENSSL_wipe_cpu

.globl	OPENSSL_ia32_cpuid
.align	16
OPENSSL_ia32_cpuid:
	movq	%rbx,%r8

	xor	%eax,%eax
	cpuid
	xor	%eax,%eax
	cmp	\$0x756e6547,%ebx	# "Genu"
	setne	%al
	mov	%eax,%r9d
	cmp	\$0x49656e69,%edx	# "ineI"
	setne	%al
	or	%eax,%r9d
	cmp	\$0x6c65746e,%ecx	# "ntel"
	setne	%al
	or	%eax,%r9d

	movl	\$1,%eax
	cpuid
	bt	\$28,%edx		# test hyper-threading bit
	jnc	.Ldone
	cmp	\$0,%r9
	jne	.Lnotintel
	or	\$1<<20,%edx		# use reserved bit to engage RC4_CHAR
	and	\$15,%ah
	cmp	\$15,%ah		# examine Family ID
	je	.Lnotintel
	or	\$1<<30,%edx		# use reserved bit to skip unrolled loop
.Lnotintel:
	shr	\$16,%ebx
	cmp	\$1,%bl			# see if cache is shared
	ja	.Ldone
	and	\$~(1<<28),%edx
.Ldone:
	shlq	\$32,%rcx
	movl	%edx,%eax
	movq	%r8,%rbx
	orq	%rcx,%rax
	ret
.size	OPENSSL_ia32_cpuid,.-OPENSSL_ia32_cpuid

.section	.init
	call	OPENSSL_cpuid_setup
___
