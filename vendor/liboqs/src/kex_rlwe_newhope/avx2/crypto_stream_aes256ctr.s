	.file	"crypto_stream_aes256ctr.c"
	.section	.text.unlikely,"ax",@progbits
.LCOLDB11:
	.text
.LHOTB11:
	.p2align 4,,15
	.globl	crypto_stream_aes256ctr
	.type	crypto_stream_aes256ctr, @function
crypto_stream_aes256ctr:
.LFB2248:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	vxorps	%xmm0, %xmm0, %xmm0
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%rbx
	subq	$280, %rsp
	.cfi_offset 3, -24
	movq	8(%rdx), %rax
	vmovups	16(%rcx), %xmm4
	vmovups	(%rcx), %xmm10
	vaeskeygenassist	$1, %xmm4, %xmm2
	vmovaps	%xmm4, -256(%rbp)
	vshufps	$255, %xmm2, %xmm2, %xmm2
	bswap	%rax
	movq	%rax, -280(%rbp)
	movq	(%rdx), %rax
	vshufps	$16, %xmm10, %xmm0, %xmm0
	vmovaps	%xmm10, -272(%rbp)
	vxorps	%xmm0, %xmm10, %xmm1
	vshufps	$140, %xmm1, %xmm0, %xmm0
	vxorps	%xmm0, %xmm1, %xmm1
	vshufps	$16, %xmm4, %xmm0, %xmm0
	vxorps	%xmm2, %xmm1, %xmm2
	vxorps	%xmm0, %xmm4, %xmm4
	vaeskeygenassist	$1, %xmm2, %xmm3
	vshufps	$140, %xmm4, %xmm0, %xmm0
	vshufps	$170, %xmm3, %xmm3, %xmm3
	vxorps	%xmm0, %xmm4, %xmm4
	vmovaps	%xmm2, -240(%rbp)
	vxorps	%xmm3, %xmm4, %xmm3
	vshufps	$16, %xmm2, %xmm0, %xmm0
	bswap	%rax
	vaeskeygenassist	$2, %xmm3, %xmm1
	vxorps	%xmm0, %xmm2, %xmm2
	vshufps	$255, %xmm1, %xmm1, %xmm1
	vshufps	$140, %xmm2, %xmm0, %xmm0
	vmovaps	%xmm3, -224(%rbp)
	vxorps	%xmm0, %xmm2, %xmm2
	movq	%rax, -288(%rbp)
	vxorps	%xmm1, %xmm2, %xmm1
	vshufps	$16, %xmm3, %xmm0, %xmm0
	vaeskeygenassist	$2, %xmm1, %xmm4
	vxorps	%xmm0, %xmm3, %xmm3
	vshufps	$170, %xmm4, %xmm4, %xmm4
	vshufps	$140, %xmm3, %xmm0, %xmm0
	vmovaps	%xmm1, -208(%rbp)
	vxorps	%xmm0, %xmm3, %xmm3
	vxorps	%xmm4, %xmm3, %xmm4
	vshufps	$16, %xmm1, %xmm0, %xmm0
	vaeskeygenassist	$4, %xmm4, %xmm2
	vxorps	%xmm0, %xmm1, %xmm1
	vshufps	$255, %xmm2, %xmm2, %xmm2
	vshufps	$140, %xmm1, %xmm0, %xmm0
	vmovaps	%xmm4, -192(%rbp)
	vxorps	%xmm0, %xmm1, %xmm1
	vxorps	%xmm2, %xmm1, %xmm2
	vshufps	$16, %xmm4, %xmm0, %xmm0
	vaeskeygenassist	$4, %xmm2, %xmm3
	vxorps	%xmm0, %xmm4, %xmm4
	vshufps	$170, %xmm3, %xmm3, %xmm3
	vshufps	$140, %xmm4, %xmm0, %xmm0
	vmovaps	%xmm2, -176(%rbp)
	vxorps	%xmm0, %xmm4, %xmm4
	vxorps	%xmm3, %xmm4, %xmm3
	vshufps	$16, %xmm2, %xmm0, %xmm0
	vaeskeygenassist	$8, %xmm3, %xmm1
	vxorps	%xmm0, %xmm2, %xmm2
	vshufps	$255, %xmm1, %xmm1, %xmm1
	vshufps	$140, %xmm2, %xmm0, %xmm0
	vmovaps	%xmm3, -160(%rbp)
	vxorps	%xmm0, %xmm2, %xmm2
	vxorps	%xmm1, %xmm2, %xmm1
	vshufps	$16, %xmm3, %xmm0, %xmm0
	vaeskeygenassist	$8, %xmm1, %xmm4
	vxorps	%xmm0, %xmm3, %xmm3
	vshufps	$170, %xmm4, %xmm4, %xmm4
	vshufps	$140, %xmm3, %xmm0, %xmm0
	vmovaps	%xmm1, -144(%rbp)
	vxorps	%xmm0, %xmm3, %xmm3
	vxorps	%xmm4, %xmm3, %xmm4
	vshufps	$16, %xmm1, %xmm0, %xmm0
	vaeskeygenassist	$16, %xmm4, %xmm2
	vxorps	%xmm0, %xmm1, %xmm1
	vmovaps	%xmm4, -128(%rbp)
	vshufps	$140, %xmm1, %xmm0, %xmm0
	vshufps	$255, %xmm2, %xmm2, %xmm2
	vxorps	%xmm0, %xmm1, %xmm1
	vshufps	$16, %xmm4, %xmm0, %xmm0
	vxorps	%xmm2, %xmm1, %xmm2
	vxorps	%xmm0, %xmm4, %xmm4
	vaeskeygenassist	$16, %xmm2, %xmm3
	vshufps	$140, %xmm4, %xmm0, %xmm0
	vmovaps	%xmm2, -112(%rbp)
	vxorps	%xmm0, %xmm4, %xmm4
	vshufps	$170, %xmm3, %xmm3, %xmm3
	vshufps	$16, %xmm2, %xmm0, %xmm0
	vxorps	%xmm3, %xmm4, %xmm3
	vxorps	%xmm0, %xmm2, %xmm2
	vaeskeygenassist	$32, %xmm3, %xmm1
	vshufps	$140, %xmm2, %xmm0, %xmm0
	vmovaps	%xmm3, -96(%rbp)
	vxorps	%xmm0, %xmm2, %xmm2
	vshufps	$255, %xmm1, %xmm1, %xmm1
	vshufps	$16, %xmm3, %xmm0, %xmm0
	vxorps	%xmm1, %xmm2, %xmm1
	vxorps	%xmm0, %xmm3, %xmm3
	vaeskeygenassist	$32, %xmm1, %xmm2
	vshufps	$140, %xmm3, %xmm0, %xmm0
	vmovaps	%xmm1, -80(%rbp)
	vxorps	%xmm0, %xmm3, %xmm3
	vshufps	$170, %xmm2, %xmm2, %xmm2
	vshufps	$16, %xmm1, %xmm0, %xmm0
	vxorps	%xmm2, %xmm3, %xmm2
	vxorps	%xmm0, %xmm1, %xmm1
	vaeskeygenassist	$64, %xmm2, %xmm9
	vshufps	$140, %xmm1, %xmm0, %xmm0
	vshufps	$255, %xmm9, %xmm9, %xmm9
	vxorps	%xmm0, %xmm1, %xmm0
	vmovaps	%xmm2, -64(%rbp)
	vxorps	%xmm9, %xmm0, %xmm9
	vmovaps	%xmm9, -48(%rbp)
	testq	%rsi, %rsi
	je	.L14
	vmovdqa	.LC0(%rip), %xmm11
	movq	%rsi, %rdx
	xorl	%r10d, %r10d
	vmovdqa	.LC3(%rip), %xmm15
	vmovdqa	.LC4(%rip), %xmm14
	vmovdqa	.LC5(%rip), %xmm13
	vmovdqa	.LC6(%rip), %xmm12
	.p2align 4,,10
	.p2align 3
.L11:
	movq	-280(%rbp), %r8
	movq	%rsp, %rbx
	subq	$144, %rsp
	leaq	15(%rsp), %rcx
	vmovdqa	-288(%rbp), %xmm8
	andq	$-16, %rcx
	leaq	7(%r8), %rax
	cmpq	$6, %rax
	ja	.L4
	negl	%r8d
	xorl	%eax, %eax
	movl	$1, %r9d
	vpshufb	%xmm11, %xmm8, %xmm7
	cmpl	$1, %r8d
	setle	%al
	vmovq	%rax, %xmm6
	xorl	%eax, %eax
	cmpl	$2, %r8d
	setle	%al
	vpinsrq	$1, %r9, %xmm6, %xmm6
	vpaddq	%xmm6, %xmm8, %xmm6
	vmovq	%rax, %xmm5
	movl	$2, %eax
	vpshufb	%xmm11, %xmm6, %xmm6
	vpinsrq	$1, %rax, %xmm5, %xmm5
	xorl	%eax, %eax
	cmpl	$3, %r8d
	vpaddq	%xmm5, %xmm8, %xmm5
	setle	%al
	vpshufb	%xmm11, %xmm5, %xmm5
	vmovq	%rax, %xmm4
	movl	$3, %eax
	vpinsrq	$1, %rax, %xmm4, %xmm4
	xorl	%eax, %eax
	cmpl	$4, %r8d
	vpaddq	%xmm4, %xmm8, %xmm4
	setle	%al
	vpshufb	%xmm11, %xmm4, %xmm4
	vmovq	%rax, %xmm3
	movl	$4, %eax
	vpinsrq	$1, %rax, %xmm3, %xmm3
	xorl	%eax, %eax
	cmpl	$5, %r8d
	vpaddq	%xmm3, %xmm8, %xmm3
	setle	%al
	vpshufb	%xmm11, %xmm3, %xmm3
	vmovq	%rax, %xmm2
	movl	$5, %eax
	vpinsrq	$1, %rax, %xmm2, %xmm2
	xorl	%eax, %eax
	cmpl	$6, %r8d
	vpaddq	%xmm2, %xmm8, %xmm2
	setle	%al
	vpshufb	%xmm11, %xmm2, %xmm2
	vmovq	%rax, %xmm1
	movl	$6, %eax
	vpinsrq	$1, %rax, %xmm1, %xmm0
	vpaddq	%xmm0, %xmm8, %xmm0
	vpaddq	.LC1(%rip), %xmm8, %xmm1
	vpaddq	.LC2(%rip), %xmm8, %xmm8
	vpshufb	%xmm11, %xmm0, %xmm0
	vpshufb	%xmm11, %xmm1, %xmm1
	vmovups	%xmm8, -288(%rbp)
.L5:
	vpxor	%xmm10, %xmm7, %xmm7
	vpxor	%xmm10, %xmm6, %xmm6
	vpxor	%xmm10, %xmm5, %xmm5
	vpxor	%xmm10, %xmm4, %xmm4
	vpxor	%xmm10, %xmm3, %xmm3
	vpxor	%xmm10, %xmm2, %xmm2
	vpxor	%xmm10, %xmm0, %xmm8
	vpxor	%xmm10, %xmm1, %xmm1
	leaq	-272(%rbp), %rax
	leaq	-272(%rbp), %r11
	addq	$16, %rax
	leaq	224(%r11), %r8
	.p2align 4,,10
	.p2align 3
.L6:
	vmovdqa	(%rax), %xmm0
	addq	$16, %rax
	vaesenc	%xmm0, %xmm7, %xmm7
	vaesenc	%xmm0, %xmm6, %xmm6
	vaesenc	%xmm0, %xmm5, %xmm5
	vaesenc	%xmm0, %xmm4, %xmm4
	vaesenc	%xmm0, %xmm3, %xmm3
	vaesenc	%xmm0, %xmm2, %xmm2
	vaesenc	%xmm0, %xmm8, %xmm8
	vaesenc	%xmm0, %xmm1, %xmm1
	cmpq	%r8, %rax
	jne	.L6
	vaesenclast	%xmm9, %xmm7, %xmm7
	leaq	128(%r10), %r8
	vaesenclast	%xmm9, %xmm6, %xmm6
	vaesenclast	%xmm9, %xmm5, %xmm5
	vaesenclast	%xmm9, %xmm4, %xmm4
	vaesenclast	%xmm9, %xmm3, %xmm3
	vaesenclast	%xmm9, %xmm2, %xmm2
	vaesenclast	%xmm9, %xmm8, %xmm0
	vaesenclast	%xmm9, %xmm1, %xmm1
	vmovaps	%xmm7, (%rcx)
	vmovaps	%xmm6, 16(%rcx)
	vmovaps	%xmm5, 32(%rcx)
	vmovaps	%xmm4, 48(%rcx)
	vmovaps	%xmm3, 64(%rcx)
	vmovaps	%xmm2, 80(%rcx)
	vmovaps	%xmm0, 96(%rcx)
	vmovaps	%xmm1, 112(%rcx)
	cmpq	%r8, %rsi
	jbe	.L18
	movq	(%rcx), %r9
	leaq	(%rdi,%r10), %rax
	addq	$-128, %rdx
	movq	%r8, %r10
	movq	%r9, (%rax)
	movq	8(%rcx), %r9
	movq	%r9, 8(%rax)
	movq	16(%rcx), %r9
	movq	%r9, 16(%rax)
	movq	24(%rcx), %r9
	movq	%r9, 24(%rax)
	movq	32(%rcx), %r9
	movq	%r9, 32(%rax)
	movq	40(%rcx), %r9
	movq	%r9, 40(%rax)
	movq	48(%rcx), %r9
	movq	%r9, 48(%rax)
	movq	56(%rcx), %r9
	movq	%r9, 56(%rax)
	movq	64(%rcx), %r9
	movq	%r9, 64(%rax)
	movq	72(%rcx), %r9
	movq	%r9, 72(%rax)
	movq	80(%rcx), %r9
	movq	%r9, 80(%rax)
	movq	88(%rcx), %r9
	movq	%r9, 88(%rax)
	movq	96(%rcx), %r9
	movq	%r9, 96(%rax)
	movq	104(%rcx), %r9
	movq	%r9, 104(%rax)
	movq	112(%rcx), %r9
	movq	%r9, 112(%rax)
	movq	120(%rcx), %rcx
	movq	%rcx, 120(%rax)
	movq	%rbx, %rsp
	jmp	.L11
	.p2align 4,,10
	.p2align 3
.L4:
	vpaddq	%xmm15, %xmm8, %xmm6
	vpaddq	%xmm14, %xmm8, %xmm5
	vpshufb	%xmm11, %xmm8, %xmm7
	vpaddq	%xmm13, %xmm8, %xmm4
	vpaddq	%xmm12, %xmm8, %xmm3
	vpshufb	%xmm11, %xmm6, %xmm6
	vpshufb	%xmm11, %xmm5, %xmm5
	vpaddq	.LC7(%rip), %xmm8, %xmm2
	vpshufb	%xmm11, %xmm4, %xmm4
	vpshufb	%xmm11, %xmm3, %xmm3
	vpaddq	.LC8(%rip), %xmm8, %xmm0
	vpaddq	.LC9(%rip), %xmm8, %xmm1
	vpaddq	.LC10(%rip), %xmm8, %xmm8
	vpshufb	%xmm11, %xmm2, %xmm2
	vpshufb	%xmm11, %xmm0, %xmm0
	vpshufb	%xmm11, %xmm1, %xmm1
	vmovups	%xmm8, -288(%rbp)
	jmp	.L5
.L18:
	testq	%rdx, %rdx
	je	.L16
	addq	%r10, %rdi
	movq	%rcx, %rsi
	call	memcpy
.L16:
	movq	%rbx, %rsp
.L14:
	xorl	%eax, %eax
	movq	-8(%rbp), %rbx
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2248:
	.size	crypto_stream_aes256ctr, .-crypto_stream_aes256ctr
	.section	.text.unlikely
.LCOLDE11:
	.text
.LHOTE11:
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.LC0:
	.byte	7
	.byte	6
	.byte	5
	.byte	4
	.byte	3
	.byte	2
	.byte	1
	.byte	0
	.byte	15
	.byte	14
	.byte	13
	.byte	12
	.byte	11
	.byte	10
	.byte	9
	.byte	8
	.align 16
.LC1:
	.quad	1
	.quad	7
	.align 16
.LC2:
	.quad	1
	.quad	8
	.align 16
.LC3:
	.quad	0
	.quad	1
	.align 16
.LC4:
	.quad	0
	.quad	2
	.align 16
.LC5:
	.quad	0
	.quad	3
	.align 16
.LC6:
	.quad	0
	.quad	4
	.align 16
.LC7:
	.quad	0
	.quad	5
	.align 16
.LC8:
	.quad	0
	.quad	6
	.align 16
.LC9:
	.quad	0
	.quad	7
	.align 16
.LC10:
	.quad	0
	.quad	8
	.ident	"GCC: (Debian 4.9.2-10) 4.9.2"
	.section	.note.GNU-stack,"",@progbits
