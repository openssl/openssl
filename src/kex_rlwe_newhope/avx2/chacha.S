/* From crypto_stream/chacha20/moon/avx2/64/ 
 * from http://bench.cr.yp.to/supercop.html
 * by Andrew Moon */

#define GLOBAL2(n) .globl n##_avx2; .globl _##n##_avx2
#define GLOBAL(n) GLOBAL2(n)
#define FN2(n) .p2align 4,,15; n##_avx2:; _##n##_avx2:
#define FN(n) FN2(n)

/* linux/elf annotations and NX indicator */
#if defined(__linux__) && defined(__ELF__)
#define ENDFN(n) .size n##_avx2, .-n##_avx2; .type n##_avx2, @function;
#define ENDFILE() .section .note.GNU-stack,"",%progbits
#else
#define ENDFN(n)
#define ENDFILE()
#endif

.text

GLOBAL(chacha)
GLOBAL(xchacha)
GLOBAL(hchacha)
GLOBAL(chacha_blocks)

/* Windows 64 calling convention fixups */
#if defined(_WIN64) || defined(__CYGWIN64__)
FN(chacha)
subq $184, %rsp
vmovdqa %xmm6, 0(%rsp)
vmovdqa %xmm7, 16(%rsp)
vmovdqa %xmm8, 32(%rsp)
vmovdqa %xmm9, 48(%rsp)
vmovdqa %xmm10, 64(%rsp)
vmovdqa %xmm11, 80(%rsp)
vmovdqa %xmm12, 96(%rsp)
vmovdqa %xmm13, 112(%rsp)
vmovdqa %xmm14, 128(%rsp)
vmovdqa %xmm15, 144(%rsp)
movq %rdi, 160(%rsp)
movq %rsi, 168(%rsp)
movq %rcx, %rdi
movq %rdx, %rsi
movq %r8, %rdx
movq %r9, %rcx
movq 224(%rsp), %r8
movq 232(%rsp), %r9
call chacha_thunk_avx2
vmovdqa 0(%rsp), %xmm6
vmovdqa 16(%rsp), %xmm7
vmovdqa 32(%rsp), %xmm8
vmovdqa 48(%rsp), %xmm9
vmovdqa 64(%rsp), %xmm10
vmovdqa 80(%rsp), %xmm11
vmovdqa 96(%rsp), %xmm12
vmovdqa 112(%rsp), %xmm13
vmovdqa 128(%rsp), %xmm14
vmovdqa 144(%rsp), %xmm15
movq 160(%rsp), %rdi
movq 168(%rsp), %rsi
addq $184, %rsp
ret
ENDFN(chacha)

FN(xchacha)
subq $184, %rsp
vmovdqa %xmm6, 0(%rsp)
vmovdqa %xmm7, 16(%rsp)
vmovdqa %xmm8, 32(%rsp)
vmovdqa %xmm9, 48(%rsp)
vmovdqa %xmm10, 64(%rsp)
vmovdqa %xmm11, 80(%rsp)
vmovdqa %xmm12, 96(%rsp)
vmovdqa %xmm13, 112(%rsp)
vmovdqa %xmm14, 128(%rsp)
vmovdqa %xmm15, 144(%rsp)
movq %rdi, 160(%rsp)
movq %rsi, 168(%rsp)
movq %rcx, %rdi
movq %rdx, %rsi
movq %r8, %rdx
movq %r9, %rcx
movq 224(%rsp), %r8
movq 232(%rsp), %r9
call xchacha_thunk_avx2
vmovdqa 0(%rsp), %xmm6
vmovdqa 16(%rsp), %xmm7
vmovdqa 32(%rsp), %xmm8
vmovdqa 48(%rsp), %xmm9
vmovdqa 64(%rsp), %xmm10
vmovdqa 80(%rsp), %xmm11
vmovdqa 96(%rsp), %xmm12
vmovdqa 112(%rsp), %xmm13
vmovdqa 128(%rsp), %xmm14
vmovdqa 144(%rsp), %xmm15
movq 160(%rsp), %rdi
movq 168(%rsp), %rsi
addq $184, %rsp
ret
ENDFN(xchacha)

FN(chacha_blocks)
subq $184, %rsp
movdqa %xmm6, 0(%rsp)
movdqa %xmm7, 16(%rsp)
movdqa %xmm8, 32(%rsp)
movdqa %xmm9, 48(%rsp)
movdqa %xmm10, 64(%rsp)
movdqa %xmm11, 80(%rsp)
movdqa %xmm12, 96(%rsp)
movdqa %xmm13, 112(%rsp)
movdqa %xmm14, 128(%rsp)
movdqa %xmm15, 144(%rsp)
movq %rdi, 160(%rsp)
movq %rsi, 168(%rsp)
movq %rcx, %rdi
movq %rdx, %rsi
movq %r8, %rdx
movq %r9, %rcx
call chacha_blocks_thunk_avx2
movdqa 0(%rsp), %xmm6
movdqa 16(%rsp), %xmm7
movdqa 32(%rsp), %xmm8
movdqa 48(%rsp), %xmm9
movdqa 64(%rsp), %xmm10
movdqa 80(%rsp), %xmm11
movdqa 96(%rsp), %xmm12
movdqa 112(%rsp), %xmm13
movdqa 128(%rsp), %xmm14
movdqa 144(%rsp), %xmm15
movq 160(%rsp), %rdi
movq 168(%rsp), %rsi
addq $184, %rsp
ret
ENDFN(chacha_blocks)

FN(hchacha)
subq $40, %rsp
movdqa %xmm6, 0(%rsp)
movq %rdi, 16(%rsp)
movq %rsi, 24(%rsp)
movq %rcx, %rdi
movq %rdx, %rsi
movq %r8, %rdx
movq %r9, %rcx
call hchacha_thunk_avx2
movdqa 0(%rsp), %xmm6
movq 16(%rsp), %rdi
movq 24(%rsp), %rsi
addq $40, %rsp
ret
ENDFN(hchacha)

#define chacha chacha_thunk
#define xchacha xchacha_thunk
#define hchacha hchacha_thunk
#define chacha_blocks chacha_blocks_thunk
#endif


FN(chacha_blocks)
chacha_blocks_avx2_local:
pushq %rbx
pushq %rbp
pushq %r12
pushq %r13
pushq %r14
movq %rsp, %rbp
andq $~63, %rsp
subq $512, %rsp
leaq C(%rip), %rax
vmovdqa 0(%rax), %xmm8
vmovdqa 16(%rax), %xmm6
vmovdqa 32(%rax), %xmm7
vmovdqa 0(%rdi), %xmm9
vmovdqa 16(%rdi), %xmm10
vmovdqa 32(%rdi), %xmm11
movq 48(%rdi), %rax
movq $1, %r9
vmovdqa %xmm8, 0(%rsp)
vmovdqa %xmm9, 16(%rsp)
vmovdqa %xmm10, 32(%rsp)
vmovdqa %xmm11, 48(%rsp)
movq %rax, 64(%rsp)
vmovdqa %xmm6, 448(%rsp)
vmovdqa %xmm6, 464(%rsp)
vmovdqa %xmm7, 480(%rsp)
vmovdqa %xmm7, 496(%rsp)
cmpq $512, %rcx
jae chacha_blocks_avx2_atleast512
cmp $256, %rcx
jae chacha_blocks_avx2_atleast256
jmp chacha_blocks_avx2_below256
.p2align 6,,63
chacha_blocks_avx2_atleast512:
movq 48(%rsp), %rax
leaq 1(%rax), %r8
leaq 2(%rax), %r9
leaq 3(%rax), %r10
leaq 4(%rax), %rbx
leaq 5(%rax), %r11
leaq 6(%rax), %r12
leaq 7(%rax), %r13
leaq 8(%rax), %r14
movl %eax, 128(%rsp)
movl %r8d, 4+128(%rsp)
movl %r9d, 8+128(%rsp)
movl %r10d, 12+128(%rsp)
movl %ebx, 16+128(%rsp)
movl %r11d, 20+128(%rsp)
movl %r12d, 24+128(%rsp)
movl %r13d, 28+128(%rsp)
shrq $32, %rax
shrq $32, %r8
shrq $32, %r9
shrq $32, %r10
shrq $32, %rbx
shrq $32, %r11
shrq $32, %r12
shrq $32, %r13
movl %eax, 160(%rsp)
movl %r8d, 4+160(%rsp)
movl %r9d, 8+160(%rsp)
movl %r10d, 12+160(%rsp)
movl %ebx, 16+160(%rsp)
movl %r11d, 20+160(%rsp)
movl %r12d, 24+160(%rsp)
movl %r13d, 28+160(%rsp)
movq %r14, 48(%rsp)
movq 64(%rsp), %rax
vpbroadcastd 0(%rsp), %ymm0
vpbroadcastd 4+0(%rsp), %ymm1
vpbroadcastd 8+0(%rsp), %ymm2
vpbroadcastd 12+0(%rsp), %ymm3
vpbroadcastd 16(%rsp), %ymm4
vpbroadcastd 4+16(%rsp), %ymm5
vpbroadcastd 8+16(%rsp), %ymm6
vpbroadcastd 12+16(%rsp), %ymm7
vpbroadcastd 32(%rsp), %ymm8
vpbroadcastd 4+32(%rsp), %ymm9
vpbroadcastd 8+32(%rsp), %ymm10
vpbroadcastd 12+32(%rsp), %ymm11
vpbroadcastd 8+48(%rsp), %ymm14
vpbroadcastd 12+48(%rsp), %ymm15
vmovdqa 128(%rsp), %ymm12
vmovdqa 160(%rsp), %ymm13
chacha_blocks_avx2_mainloop1:
vpaddd %ymm0, %ymm4, %ymm0
vpaddd %ymm1, %ymm5, %ymm1
vpxor %ymm12, %ymm0, %ymm12
vpxor %ymm13, %ymm1, %ymm13
vpaddd %ymm2, %ymm6, %ymm2
vpaddd %ymm3, %ymm7, %ymm3
vpxor %ymm14, %ymm2, %ymm14
vpxor %ymm15, %ymm3, %ymm15
vpshufb 448(%rsp), %ymm12, %ymm12
vpshufb 448(%rsp), %ymm13, %ymm13
vpaddd %ymm8, %ymm12, %ymm8
vpaddd %ymm9, %ymm13, %ymm9
vpshufb 448(%rsp), %ymm14, %ymm14
vpshufb 448(%rsp), %ymm15, %ymm15
vpaddd %ymm10, %ymm14, %ymm10
vpaddd %ymm11, %ymm15, %ymm11
vmovdqa %ymm12, 96(%rsp)
vpxor %ymm4, %ymm8, %ymm4
vpxor %ymm5, %ymm9, %ymm5
vpslld $ 12, %ymm4, %ymm12
vpsrld $20, %ymm4, %ymm4
vpxor %ymm4, %ymm12, %ymm4
vpslld $ 12, %ymm5, %ymm12
vpsrld $20, %ymm5, %ymm5
vpxor %ymm5, %ymm12, %ymm5
vpxor %ymm6, %ymm10, %ymm6
vpxor %ymm7, %ymm11, %ymm7
vpslld $ 12, %ymm6, %ymm12
vpsrld $20, %ymm6, %ymm6
vpxor %ymm6, %ymm12, %ymm6
vpslld $ 12, %ymm7, %ymm12
vpsrld $20, %ymm7, %ymm7
vpxor %ymm7, %ymm12, %ymm7
vpaddd %ymm0, %ymm4, %ymm0
vpaddd %ymm1, %ymm5, %ymm1
vpxor 96(%rsp), %ymm0, %ymm12
vpxor %ymm13, %ymm1, %ymm13
vpaddd %ymm2, %ymm6, %ymm2
vpaddd %ymm3, %ymm7, %ymm3
vpxor %ymm14, %ymm2, %ymm14
vpxor %ymm15, %ymm3, %ymm15
vpshufb 480(%rsp), %ymm12, %ymm12
vpshufb 480(%rsp), %ymm13, %ymm13
vpaddd %ymm8, %ymm12, %ymm8
vpaddd %ymm9, %ymm13, %ymm9
vpshufb 480(%rsp), %ymm14, %ymm14
vpshufb 480(%rsp), %ymm15, %ymm15
vpaddd %ymm10, %ymm14, %ymm10
vpaddd %ymm11, %ymm15, %ymm11
vmovdqa %ymm12, 96(%rsp)
vpxor %ymm4, %ymm8, %ymm4
vpxor %ymm5, %ymm9, %ymm5
vpslld $ 7, %ymm4, %ymm12
vpsrld $25, %ymm4, %ymm4
vpxor %ymm4, %ymm12, %ymm4
vpslld $ 7, %ymm5, %ymm12
vpsrld $25, %ymm5, %ymm5
vpxor %ymm5, %ymm12, %ymm5
vpxor %ymm6, %ymm10, %ymm6
vpxor %ymm7, %ymm11, %ymm7
vpslld $ 7, %ymm6, %ymm12
vpsrld $25, %ymm6, %ymm6
vpxor %ymm6, %ymm12, %ymm6
vpslld $ 7, %ymm7, %ymm12
vpsrld $25, %ymm7, %ymm7
vpxor %ymm7, %ymm12, %ymm7
vpaddd %ymm0, %ymm5, %ymm0
vpaddd %ymm1, %ymm6, %ymm1
vpxor %ymm15, %ymm0, %ymm15
vpxor 96(%rsp), %ymm1, %ymm12
vpaddd %ymm2, %ymm7, %ymm2
vpaddd %ymm3, %ymm4, %ymm3
vpxor %ymm13, %ymm2, %ymm13
vpxor %ymm14, %ymm3, %ymm14
vpshufb 448(%rsp), %ymm15, %ymm15
vpshufb 448(%rsp), %ymm12, %ymm12
vpaddd %ymm10, %ymm15, %ymm10
vpaddd %ymm11, %ymm12, %ymm11
vpshufb 448(%rsp), %ymm13, %ymm13
vpshufb 448(%rsp), %ymm14, %ymm14
vpaddd %ymm8, %ymm13, %ymm8
vpaddd %ymm9, %ymm14, %ymm9
vmovdqa %ymm15, 96(%rsp)
vpxor %ymm5, %ymm10, %ymm5
vpxor %ymm6, %ymm11, %ymm6
vpslld $ 12, %ymm5, %ymm15
vpsrld $20, %ymm5, %ymm5
vpxor %ymm5, %ymm15, %ymm5
vpslld $ 12, %ymm6, %ymm15
vpsrld $20, %ymm6, %ymm6
vpxor %ymm6, %ymm15, %ymm6
vpxor %ymm7, %ymm8, %ymm7
vpxor %ymm4, %ymm9, %ymm4
vpslld $ 12, %ymm7, %ymm15
vpsrld $20, %ymm7, %ymm7
vpxor %ymm7, %ymm15, %ymm7
vpslld $ 12, %ymm4, %ymm15
vpsrld $20, %ymm4, %ymm4
vpxor %ymm4, %ymm15, %ymm4
vpaddd %ymm0, %ymm5, %ymm0
vpaddd %ymm1, %ymm6, %ymm1
vpxor 96(%rsp), %ymm0, %ymm15
vpxor %ymm12, %ymm1, %ymm12
vpaddd %ymm2, %ymm7, %ymm2
vpaddd %ymm3, %ymm4, %ymm3
vpxor %ymm13, %ymm2, %ymm13
vpxor %ymm14, %ymm3, %ymm14
vpshufb 480(%rsp), %ymm15, %ymm15
vpshufb 480(%rsp), %ymm12, %ymm12
vpaddd %ymm10, %ymm15, %ymm10
vpaddd %ymm11, %ymm12, %ymm11
vpshufb 480(%rsp), %ymm13, %ymm13
vpshufb 480(%rsp), %ymm14, %ymm14
vpaddd %ymm8, %ymm13, %ymm8
vpaddd %ymm9, %ymm14, %ymm9
vmovdqa %ymm15, 96(%rsp)
vpxor %ymm5, %ymm10, %ymm5
vpxor %ymm6, %ymm11, %ymm6
vpslld $ 7, %ymm5, %ymm15
vpsrld $25, %ymm5, %ymm5
vpxor %ymm5, %ymm15, %ymm5
vpslld $ 7, %ymm6, %ymm15
vpsrld $25, %ymm6, %ymm6
vpxor %ymm6, %ymm15, %ymm6
vpxor %ymm7, %ymm8, %ymm7
vpxor %ymm4, %ymm9, %ymm4
vpslld $ 7, %ymm7, %ymm15
vpsrld $25, %ymm7, %ymm7
vpxor %ymm7, %ymm15, %ymm7
vpslld $ 7, %ymm4, %ymm15
vpsrld $25, %ymm4, %ymm4
vpxor %ymm4, %ymm15, %ymm4
vmovdqa 96(%rsp), %ymm15
subq $2, %rax
jnz chacha_blocks_avx2_mainloop1
vmovdqa %ymm8, 192(%rsp)
vmovdqa %ymm9, 224(%rsp)
vmovdqa %ymm10, 256(%rsp)
vmovdqa %ymm11, 288(%rsp)
vmovdqa %ymm12, 320(%rsp)
vmovdqa %ymm13, 352(%rsp)
vmovdqa %ymm14, 384(%rsp)
vmovdqa %ymm15, 416(%rsp)
vpbroadcastd 0(%rsp), %ymm8
vpbroadcastd 4+0(%rsp), %ymm9
vpbroadcastd 8+0(%rsp), %ymm10
vpbroadcastd 12+0(%rsp), %ymm11
vpbroadcastd 16(%rsp), %ymm12
vpbroadcastd 4+16(%rsp), %ymm13
vpbroadcastd 8+16(%rsp), %ymm14
vpbroadcastd 12+16(%rsp), %ymm15
vpaddd %ymm8, %ymm0, %ymm0
vpaddd %ymm9, %ymm1, %ymm1
vpaddd %ymm10, %ymm2, %ymm2
vpaddd %ymm11, %ymm3, %ymm3
vpaddd %ymm12, %ymm4, %ymm4
vpaddd %ymm13, %ymm5, %ymm5
vpaddd %ymm14, %ymm6, %ymm6
vpaddd %ymm15, %ymm7, %ymm7
vpunpckldq %ymm1, %ymm0, %ymm8
vpunpckldq %ymm3, %ymm2, %ymm9
vpunpckhdq %ymm1, %ymm0, %ymm12
vpunpckhdq %ymm3, %ymm2, %ymm13
vpunpckldq %ymm5, %ymm4, %ymm10
vpunpckldq %ymm7, %ymm6, %ymm11
vpunpckhdq %ymm5, %ymm4, %ymm14
vpunpckhdq %ymm7, %ymm6, %ymm15
vpunpcklqdq %ymm9, %ymm8, %ymm0
vpunpcklqdq %ymm11, %ymm10, %ymm1
vpunpckhqdq %ymm9, %ymm8, %ymm2
vpunpckhqdq %ymm11, %ymm10, %ymm3
vpunpcklqdq %ymm13, %ymm12, %ymm4
vpunpcklqdq %ymm15, %ymm14, %ymm5
vpunpckhqdq %ymm13, %ymm12, %ymm6
vpunpckhqdq %ymm15, %ymm14, %ymm7
vperm2i128 $0x20, %ymm1, %ymm0, %ymm8
vperm2i128 $0x20, %ymm3, %ymm2, %ymm9
vperm2i128 $0x31, %ymm1, %ymm0, %ymm12
vperm2i128 $0x31, %ymm3, %ymm2, %ymm13
vperm2i128 $0x20, %ymm5, %ymm4, %ymm10
vperm2i128 $0x20, %ymm7, %ymm6, %ymm11
vperm2i128 $0x31, %ymm5, %ymm4, %ymm14
vperm2i128 $0x31, %ymm7, %ymm6, %ymm15
andq %rsi, %rsi
jz chacha_blocks_avx2_noinput1
vpxor 0(%rsi), %ymm8, %ymm8
vpxor 64(%rsi), %ymm9, %ymm9
vpxor 128(%rsi), %ymm10, %ymm10
vpxor 192(%rsi), %ymm11, %ymm11
vpxor 256(%rsi), %ymm12, %ymm12
vpxor 320(%rsi), %ymm13, %ymm13
vpxor 384(%rsi), %ymm14, %ymm14
vpxor 448(%rsi), %ymm15, %ymm15
vmovdqu %ymm8, 0(%rdx)
vmovdqu %ymm9, 64(%rdx)
vmovdqu %ymm10, 128(%rdx)
vmovdqu %ymm11, 192(%rdx)
vmovdqu %ymm12, 256(%rdx)
vmovdqu %ymm13, 320(%rdx)
vmovdqu %ymm14, 384(%rdx)
vmovdqu %ymm15, 448(%rdx)
vmovdqa 192(%rsp), %ymm0
vmovdqa 224(%rsp), %ymm1
vmovdqa 256(%rsp), %ymm2
vmovdqa 288(%rsp), %ymm3
vmovdqa 320(%rsp), %ymm4
vmovdqa 352(%rsp), %ymm5
vmovdqa 384(%rsp), %ymm6
vmovdqa 416(%rsp), %ymm7
vpbroadcastd 32(%rsp), %ymm8
vpbroadcastd 4+32(%rsp), %ymm9
vpbroadcastd 8+32(%rsp), %ymm10
vpbroadcastd 12+32(%rsp), %ymm11
vmovdqa 128(%rsp), %ymm12
vmovdqa 160(%rsp), %ymm13
vpbroadcastd 8+48(%rsp), %ymm14
vpbroadcastd 12+48(%rsp), %ymm15
vpaddd %ymm8, %ymm0, %ymm0
vpaddd %ymm9, %ymm1, %ymm1
vpaddd %ymm10, %ymm2, %ymm2
vpaddd %ymm11, %ymm3, %ymm3
vpaddd %ymm12, %ymm4, %ymm4
vpaddd %ymm13, %ymm5, %ymm5
vpaddd %ymm14, %ymm6, %ymm6
vpaddd %ymm15, %ymm7, %ymm7
vpunpckldq %ymm1, %ymm0, %ymm8
vpunpckldq %ymm3, %ymm2, %ymm9
vpunpckhdq %ymm1, %ymm0, %ymm12
vpunpckhdq %ymm3, %ymm2, %ymm13
vpunpckldq %ymm5, %ymm4, %ymm10
vpunpckldq %ymm7, %ymm6, %ymm11
vpunpckhdq %ymm5, %ymm4, %ymm14
vpunpckhdq %ymm7, %ymm6, %ymm15
vpunpcklqdq %ymm9, %ymm8, %ymm0
vpunpcklqdq %ymm11, %ymm10, %ymm1
vpunpckhqdq %ymm9, %ymm8, %ymm2
vpunpckhqdq %ymm11, %ymm10, %ymm3
vpunpcklqdq %ymm13, %ymm12, %ymm4
vpunpcklqdq %ymm15, %ymm14, %ymm5
vpunpckhqdq %ymm13, %ymm12, %ymm6
vpunpckhqdq %ymm15, %ymm14, %ymm7
vperm2i128 $0x20, %ymm1, %ymm0, %ymm8
vperm2i128 $0x20, %ymm3, %ymm2, %ymm9
vperm2i128 $0x31, %ymm1, %ymm0, %ymm12
vperm2i128 $0x31, %ymm3, %ymm2, %ymm13
vperm2i128 $0x20, %ymm5, %ymm4, %ymm10
vperm2i128 $0x20, %ymm7, %ymm6, %ymm11
vperm2i128 $0x31, %ymm5, %ymm4, %ymm14
vperm2i128 $0x31, %ymm7, %ymm6, %ymm15
vpxor 32(%rsi), %ymm8, %ymm8
vpxor 96(%rsi), %ymm9, %ymm9
vpxor 160(%rsi), %ymm10, %ymm10
vpxor 224(%rsi), %ymm11, %ymm11
vpxor 288(%rsi), %ymm12, %ymm12
vpxor 352(%rsi), %ymm13, %ymm13
vpxor 416(%rsi), %ymm14, %ymm14
vpxor 480(%rsi), %ymm15, %ymm15
vmovdqu %ymm8, 32(%rdx)
vmovdqu %ymm9, 96(%rdx)
vmovdqu %ymm10, 160(%rdx)
vmovdqu %ymm11, 224(%rdx)
vmovdqu %ymm12, 288(%rdx)
vmovdqu %ymm13, 352(%rdx)
vmovdqu %ymm14, 416(%rdx)
vmovdqu %ymm15, 480(%rdx)
addq $512, %rsi
jmp chacha_blocks_avx2_mainloop1_cont
chacha_blocks_avx2_noinput1:
vmovdqu %ymm8, 0(%rdx)
vmovdqu %ymm9, 64(%rdx)
vmovdqu %ymm10, 128(%rdx)
vmovdqu %ymm11, 192(%rdx)
vmovdqu %ymm12, 256(%rdx)
vmovdqu %ymm13, 320(%rdx)
vmovdqu %ymm14, 384(%rdx)
vmovdqu %ymm15, 448(%rdx)
vmovdqa 192(%rsp), %ymm0
vmovdqa 224(%rsp), %ymm1
vmovdqa 256(%rsp), %ymm2
vmovdqa 288(%rsp), %ymm3
vmovdqa 320(%rsp), %ymm4
vmovdqa 352(%rsp), %ymm5
vmovdqa 384(%rsp), %ymm6
vmovdqa 416(%rsp), %ymm7
vpbroadcastd 32(%rsp), %ymm8
vpbroadcastd 4+32(%rsp), %ymm9
vpbroadcastd 8+32(%rsp), %ymm10
vpbroadcastd 12+32(%rsp), %ymm11
vmovdqa 128(%rsp), %ymm12
vmovdqa 160(%rsp), %ymm13
vpbroadcastd 8+48(%rsp), %ymm14
vpbroadcastd 12+48(%rsp), %ymm15
vpaddd %ymm8, %ymm0, %ymm0
vpaddd %ymm9, %ymm1, %ymm1
vpaddd %ymm10, %ymm2, %ymm2
vpaddd %ymm11, %ymm3, %ymm3
vpaddd %ymm12, %ymm4, %ymm4
vpaddd %ymm13, %ymm5, %ymm5
vpaddd %ymm14, %ymm6, %ymm6
vpaddd %ymm15, %ymm7, %ymm7
vpunpckldq %ymm1, %ymm0, %ymm8
vpunpckldq %ymm3, %ymm2, %ymm9
vpunpckhdq %ymm1, %ymm0, %ymm12
vpunpckhdq %ymm3, %ymm2, %ymm13
vpunpckldq %ymm5, %ymm4, %ymm10
vpunpckldq %ymm7, %ymm6, %ymm11
vpunpckhdq %ymm5, %ymm4, %ymm14
vpunpckhdq %ymm7, %ymm6, %ymm15
vpunpcklqdq %ymm9, %ymm8, %ymm0
vpunpcklqdq %ymm11, %ymm10, %ymm1
vpunpckhqdq %ymm9, %ymm8, %ymm2
vpunpckhqdq %ymm11, %ymm10, %ymm3
vpunpcklqdq %ymm13, %ymm12, %ymm4
vpunpcklqdq %ymm15, %ymm14, %ymm5
vpunpckhqdq %ymm13, %ymm12, %ymm6
vpunpckhqdq %ymm15, %ymm14, %ymm7
vperm2i128 $0x20, %ymm1, %ymm0, %ymm8
vperm2i128 $0x20, %ymm3, %ymm2, %ymm9
vperm2i128 $0x31, %ymm1, %ymm0, %ymm12
vperm2i128 $0x31, %ymm3, %ymm2, %ymm13
vperm2i128 $0x20, %ymm5, %ymm4, %ymm10
vperm2i128 $0x20, %ymm7, %ymm6, %ymm11
vperm2i128 $0x31, %ymm5, %ymm4, %ymm14
vperm2i128 $0x31, %ymm7, %ymm6, %ymm15
vmovdqu %ymm8, 32(%rdx)
vmovdqu %ymm9, 96(%rdx)
vmovdqu %ymm10, 160(%rdx)
vmovdqu %ymm11, 224(%rdx)
vmovdqu %ymm12, 288(%rdx)
vmovdqu %ymm13, 352(%rdx)
vmovdqu %ymm14, 416(%rdx)
vmovdqu %ymm15, 480(%rdx)
chacha_blocks_avx2_mainloop1_cont:
addq $512, %rdx
subq $512, %rcx
cmp $512, %rcx
jae chacha_blocks_avx2_atleast512
cmp $256, %rcx
jb chacha_blocks_avx2_below256_fixup
chacha_blocks_avx2_atleast256:
movq 48(%rsp), %rax
leaq 1(%rax), %r8
leaq 2(%rax), %r9
leaq 3(%rax), %r10
leaq 4(%rax), %rbx
movl %eax, 128(%rsp)
movl %r8d, 4+128(%rsp)
movl %r9d, 8+128(%rsp)
movl %r10d, 12+128(%rsp)
shrq $32, %rax
shrq $32, %r8
shrq $32, %r9
shrq $32, %r10
movl %eax, 160(%rsp)
movl %r8d, 4+160(%rsp)
movl %r9d, 8+160(%rsp)
movl %r10d, 12+160(%rsp)
movq %rbx, 48(%rsp)
movq 64(%rsp), %rax
vpbroadcastd 0(%rsp), %xmm0
vpbroadcastd 4+0(%rsp), %xmm1
vpbroadcastd 8+0(%rsp), %xmm2
vpbroadcastd 12+0(%rsp), %xmm3
vpbroadcastd 16(%rsp), %xmm4
vpbroadcastd 4+16(%rsp), %xmm5
vpbroadcastd 8+16(%rsp), %xmm6
vpbroadcastd 12+16(%rsp), %xmm7
vpbroadcastd 32(%rsp), %xmm8
vpbroadcastd 4+32(%rsp), %xmm9
vpbroadcastd 8+32(%rsp), %xmm10
vpbroadcastd 12+32(%rsp), %xmm11
vmovdqa 128(%rsp), %xmm12
vmovdqa 160(%rsp), %xmm13
vpbroadcastd 8+48(%rsp), %xmm14
vpbroadcastd 12+48(%rsp), %xmm15
chacha_blocks_avx2_mainloop2:
vpaddd %xmm0, %xmm4, %xmm0
vpaddd %xmm1, %xmm5, %xmm1
vpxor %xmm12, %xmm0, %xmm12
vpxor %xmm13, %xmm1, %xmm13
vpaddd %xmm2, %xmm6, %xmm2
vpaddd %xmm3, %xmm7, %xmm3
vpxor %xmm14, %xmm2, %xmm14
vpxor %xmm15, %xmm3, %xmm15
vpshufb 448(%rsp), %xmm12, %xmm12
vpshufb 448(%rsp), %xmm13, %xmm13
vpaddd %xmm8, %xmm12, %xmm8
vpaddd %xmm9, %xmm13, %xmm9
vpshufb 448(%rsp), %xmm14, %xmm14
vpshufb 448(%rsp), %xmm15, %xmm15
vpaddd %xmm10, %xmm14, %xmm10
vpaddd %xmm11, %xmm15, %xmm11
vmovdqa %xmm12, 96(%rsp)
vpxor %xmm4, %xmm8, %xmm4
vpxor %xmm5, %xmm9, %xmm5
vpslld $ 12, %xmm4, %xmm12
vpsrld $20, %xmm4, %xmm4
vpxor %xmm4, %xmm12, %xmm4
vpslld $ 12, %xmm5, %xmm12
vpsrld $20, %xmm5, %xmm5
vpxor %xmm5, %xmm12, %xmm5
vpxor %xmm6, %xmm10, %xmm6
vpxor %xmm7, %xmm11, %xmm7
vpslld $ 12, %xmm6, %xmm12
vpsrld $20, %xmm6, %xmm6
vpxor %xmm6, %xmm12, %xmm6
vpslld $ 12, %xmm7, %xmm12
vpsrld $20, %xmm7, %xmm7
vpxor %xmm7, %xmm12, %xmm7
vpaddd %xmm0, %xmm4, %xmm0
vpaddd %xmm1, %xmm5, %xmm1
vpxor 96(%rsp), %xmm0, %xmm12
vpxor %xmm13, %xmm1, %xmm13
vpaddd %xmm2, %xmm6, %xmm2
vpaddd %xmm3, %xmm7, %xmm3
vpxor %xmm14, %xmm2, %xmm14
vpxor %xmm15, %xmm3, %xmm15
vpshufb 480(%rsp), %xmm12, %xmm12
vpshufb 480(%rsp), %xmm13, %xmm13
vpaddd %xmm8, %xmm12, %xmm8
vpaddd %xmm9, %xmm13, %xmm9
vpshufb 480(%rsp), %xmm14, %xmm14
vpshufb 480(%rsp), %xmm15, %xmm15
vpaddd %xmm10, %xmm14, %xmm10
vpaddd %xmm11, %xmm15, %xmm11
vmovdqa %xmm12, 96(%rsp)
vpxor %xmm4, %xmm8, %xmm4
vpxor %xmm5, %xmm9, %xmm5
vpslld $ 7, %xmm4, %xmm12
vpsrld $25, %xmm4, %xmm4
vpxor %xmm4, %xmm12, %xmm4
vpslld $ 7, %xmm5, %xmm12
vpsrld $25, %xmm5, %xmm5
vpxor %xmm5, %xmm12, %xmm5
vpxor %xmm6, %xmm10, %xmm6
vpxor %xmm7, %xmm11, %xmm7
vpslld $ 7, %xmm6, %xmm12
vpsrld $25, %xmm6, %xmm6
vpxor %xmm6, %xmm12, %xmm6
vpslld $ 7, %xmm7, %xmm12
vpsrld $25, %xmm7, %xmm7
vpxor %xmm7, %xmm12, %xmm7
vpaddd %xmm0, %xmm5, %xmm0
vpaddd %xmm1, %xmm6, %xmm1
vpxor %xmm15, %xmm0, %xmm15
vpxor 96(%rsp), %xmm1, %xmm12
vpaddd %xmm2, %xmm7, %xmm2
vpaddd %xmm3, %xmm4, %xmm3
vpxor %xmm13, %xmm2, %xmm13
vpxor %xmm14, %xmm3, %xmm14
vpshufb 448(%rsp), %xmm15, %xmm15
vpshufb 448(%rsp), %xmm12, %xmm12
vpaddd %xmm10, %xmm15, %xmm10
vpaddd %xmm11, %xmm12, %xmm11
vpshufb 448(%rsp), %xmm13, %xmm13
vpshufb 448(%rsp), %xmm14, %xmm14
vpaddd %xmm8, %xmm13, %xmm8
vpaddd %xmm9, %xmm14, %xmm9
vmovdqa %xmm15, 96(%rsp)
vpxor %xmm5, %xmm10, %xmm5
vpxor %xmm6, %xmm11, %xmm6
vpslld $ 12, %xmm5, %xmm15
vpsrld $20, %xmm5, %xmm5
vpxor %xmm5, %xmm15, %xmm5
vpslld $ 12, %xmm6, %xmm15
vpsrld $20, %xmm6, %xmm6
vpxor %xmm6, %xmm15, %xmm6
vpxor %xmm7, %xmm8, %xmm7
vpxor %xmm4, %xmm9, %xmm4
vpslld $ 12, %xmm7, %xmm15
vpsrld $20, %xmm7, %xmm7
vpxor %xmm7, %xmm15, %xmm7
vpslld $ 12, %xmm4, %xmm15
vpsrld $20, %xmm4, %xmm4
vpxor %xmm4, %xmm15, %xmm4
vpaddd %xmm0, %xmm5, %xmm0
vpaddd %xmm1, %xmm6, %xmm1
vpxor 96(%rsp), %xmm0, %xmm15
vpxor %xmm12, %xmm1, %xmm12
vpaddd %xmm2, %xmm7, %xmm2
vpaddd %xmm3, %xmm4, %xmm3
vpxor %xmm13, %xmm2, %xmm13
vpxor %xmm14, %xmm3, %xmm14
vpshufb 480(%rsp), %xmm15, %xmm15
vpshufb 480(%rsp), %xmm12, %xmm12
vpaddd %xmm10, %xmm15, %xmm10
vpaddd %xmm11, %xmm12, %xmm11
vpshufb 480(%rsp), %xmm13, %xmm13
vpshufb 480(%rsp), %xmm14, %xmm14
vpaddd %xmm8, %xmm13, %xmm8
vpaddd %xmm9, %xmm14, %xmm9
vmovdqa %xmm15, 96(%rsp)
vpxor %xmm5, %xmm10, %xmm5
vpxor %xmm6, %xmm11, %xmm6
vpslld $ 7, %xmm5, %xmm15
vpsrld $25, %xmm5, %xmm5
vpxor %xmm5, %xmm15, %xmm5
vpslld $ 7, %xmm6, %xmm15
vpsrld $25, %xmm6, %xmm6
vpxor %xmm6, %xmm15, %xmm6
vpxor %xmm7, %xmm8, %xmm7
vpxor %xmm4, %xmm9, %xmm4
vpslld $ 7, %xmm7, %xmm15
vpsrld $25, %xmm7, %xmm7
vpxor %xmm7, %xmm15, %xmm7
vpslld $ 7, %xmm4, %xmm15
vpsrld $25, %xmm4, %xmm4
vpxor %xmm4, %xmm15, %xmm4
vmovdqa 96(%rsp), %xmm15
subq $2, %rax
jnz chacha_blocks_avx2_mainloop2
vmovdqa %xmm8, 192(%rsp)
vmovdqa %xmm9, 208(%rsp)
vmovdqa %xmm10, 224(%rsp)
vmovdqa %xmm11, 240(%rsp)
vmovdqa %xmm12, 256(%rsp)
vmovdqa %xmm13, 272(%rsp)
vmovdqa %xmm14, 288(%rsp)
vmovdqa %xmm15, 304(%rsp)
vpbroadcastd 0(%rsp), %xmm8
vpbroadcastd 4+0(%rsp), %xmm9
vpbroadcastd 8+0(%rsp), %xmm10
vpbroadcastd 12+0(%rsp), %xmm11
vpbroadcastd 16(%rsp), %xmm12
vpbroadcastd 4+16(%rsp), %xmm13
vpbroadcastd 8+16(%rsp), %xmm14
vpbroadcastd 12+16(%rsp), %xmm15
vpaddd %xmm8, %xmm0, %xmm0
vpaddd %xmm9, %xmm1, %xmm1
vpaddd %xmm10, %xmm2, %xmm2
vpaddd %xmm11, %xmm3, %xmm3
vpaddd %xmm12, %xmm4, %xmm4
vpaddd %xmm13, %xmm5, %xmm5
vpaddd %xmm14, %xmm6, %xmm6
vpaddd %xmm15, %xmm7, %xmm7
vpunpckldq %xmm1, %xmm0, %xmm8
vpunpckldq %xmm3, %xmm2, %xmm9
vpunpckhdq %xmm1, %xmm0, %xmm12
vpunpckhdq %xmm3, %xmm2, %xmm13
vpunpckldq %xmm5, %xmm4, %xmm10
vpunpckldq %xmm7, %xmm6, %xmm11
vpunpckhdq %xmm5, %xmm4, %xmm14
vpunpckhdq %xmm7, %xmm6, %xmm15
vpunpcklqdq %xmm9, %xmm8, %xmm0
vpunpcklqdq %xmm11, %xmm10, %xmm1
vpunpckhqdq %xmm9, %xmm8, %xmm2
vpunpckhqdq %xmm11, %xmm10, %xmm3
vpunpcklqdq %xmm13, %xmm12, %xmm4
vpunpcklqdq %xmm15, %xmm14, %xmm5
vpunpckhqdq %xmm13, %xmm12, %xmm6
vpunpckhqdq %xmm15, %xmm14, %xmm7
andq %rsi, %rsi
jz chacha_blocks_avx2_noinput2
vpxor 0(%rsi), %xmm0, %xmm0
vpxor 16(%rsi), %xmm1, %xmm1
vpxor 64(%rsi), %xmm2, %xmm2
vpxor 80(%rsi), %xmm3, %xmm3
vpxor 128(%rsi), %xmm4, %xmm4
vpxor 144(%rsi), %xmm5, %xmm5
vpxor 192(%rsi), %xmm6, %xmm6
vpxor 208(%rsi), %xmm7, %xmm7
vmovdqu %xmm0, 0(%rdx)
vmovdqu %xmm1, 16(%rdx)
vmovdqu %xmm2, 64(%rdx)
vmovdqu %xmm3, 80(%rdx)
vmovdqu %xmm4, 128(%rdx)
vmovdqu %xmm5, 144(%rdx)
vmovdqu %xmm6, 192(%rdx)
vmovdqu %xmm7, 208(%rdx)
vmovdqa 192(%rsp), %xmm0
vmovdqa 208(%rsp), %xmm1
vmovdqa 224(%rsp), %xmm2
vmovdqa 240(%rsp), %xmm3
vmovdqa 256(%rsp), %xmm4
vmovdqa 272(%rsp), %xmm5
vmovdqa 288(%rsp), %xmm6
vmovdqa 304(%rsp), %xmm7
vpbroadcastd 32(%rsp), %xmm8
vpbroadcastd 4+32(%rsp), %xmm9
vpbroadcastd 8+32(%rsp), %xmm10
vpbroadcastd 12+32(%rsp), %xmm11
vmovdqa 128(%rsp), %xmm12
vmovdqa 160(%rsp), %xmm13
vpbroadcastd 8+48(%rsp), %xmm14
vpbroadcastd 12+48(%rsp), %xmm15
vpaddd %xmm8, %xmm0, %xmm0
vpaddd %xmm9, %xmm1, %xmm1
vpaddd %xmm10, %xmm2, %xmm2
vpaddd %xmm11, %xmm3, %xmm3
vpaddd %xmm12, %xmm4, %xmm4
vpaddd %xmm13, %xmm5, %xmm5
vpaddd %xmm14, %xmm6, %xmm6
vpaddd %xmm15, %xmm7, %xmm7
vpunpckldq %xmm1, %xmm0, %xmm8
vpunpckldq %xmm3, %xmm2, %xmm9
vpunpckhdq %xmm1, %xmm0, %xmm12
vpunpckhdq %xmm3, %xmm2, %xmm13
vpunpckldq %xmm5, %xmm4, %xmm10
vpunpckldq %xmm7, %xmm6, %xmm11
vpunpckhdq %xmm5, %xmm4, %xmm14
vpunpckhdq %xmm7, %xmm6, %xmm15
vpunpcklqdq %xmm9, %xmm8, %xmm0
vpunpcklqdq %xmm11, %xmm10, %xmm1
vpunpckhqdq %xmm9, %xmm8, %xmm2
vpunpckhqdq %xmm11, %xmm10, %xmm3
vpunpcklqdq %xmm13, %xmm12, %xmm4
vpunpcklqdq %xmm15, %xmm14, %xmm5
vpunpckhqdq %xmm13, %xmm12, %xmm6
vpunpckhqdq %xmm15, %xmm14, %xmm7
vpxor 32(%rsi), %xmm0, %xmm0
vpxor 48(%rsi), %xmm1, %xmm1
vpxor 96(%rsi), %xmm2, %xmm2
vpxor 112(%rsi), %xmm3, %xmm3
vpxor 160(%rsi), %xmm4, %xmm4
vpxor 176(%rsi), %xmm5, %xmm5
vpxor 224(%rsi), %xmm6, %xmm6
vpxor 240(%rsi), %xmm7, %xmm7
vmovdqu %xmm0, 32(%rdx)
vmovdqu %xmm1, 48(%rdx)
vmovdqu %xmm2, 96(%rdx)
vmovdqu %xmm3, 112(%rdx)
vmovdqu %xmm4, 160(%rdx)
vmovdqu %xmm5, 176(%rdx)
vmovdqu %xmm6, 224(%rdx)
vmovdqu %xmm7, 240(%rdx)
addq $256, %rsi
jmp chacha_blocks_avx2_mainloop2_cont
chacha_blocks_avx2_noinput2:
vmovdqu %xmm0, 0(%rdx)
vmovdqu %xmm1, 16(%rdx)
vmovdqu %xmm2, 64(%rdx)
vmovdqu %xmm3, 80(%rdx)
vmovdqu %xmm4, 128(%rdx)
vmovdqu %xmm5, 144(%rdx)
vmovdqu %xmm6, 192(%rdx)
vmovdqu %xmm7, 208(%rdx)
vmovdqa 192(%rsp), %xmm0
vmovdqa 208(%rsp), %xmm1
vmovdqa 224(%rsp), %xmm2
vmovdqa 240(%rsp), %xmm3
vmovdqa 256(%rsp), %xmm4
vmovdqa 272(%rsp), %xmm5
vmovdqa 288(%rsp), %xmm6
vmovdqa 304(%rsp), %xmm7
vpbroadcastd 32(%rsp), %xmm8
vpbroadcastd 4+32(%rsp), %xmm9
vpbroadcastd 8+32(%rsp), %xmm10
vpbroadcastd 12+32(%rsp), %xmm11
vmovdqa 128(%rsp), %xmm12
vmovdqa 160(%rsp), %xmm13
vpbroadcastd 8+48(%rsp), %xmm14
vpbroadcastd 12+48(%rsp), %xmm15
vpaddd %xmm8, %xmm0, %xmm0
vpaddd %xmm9, %xmm1, %xmm1
vpaddd %xmm10, %xmm2, %xmm2
vpaddd %xmm11, %xmm3, %xmm3
vpaddd %xmm12, %xmm4, %xmm4
vpaddd %xmm13, %xmm5, %xmm5
vpaddd %xmm14, %xmm6, %xmm6
vpaddd %xmm15, %xmm7, %xmm7
vpunpckldq %xmm1, %xmm0, %xmm8
vpunpckldq %xmm3, %xmm2, %xmm9
vpunpckhdq %xmm1, %xmm0, %xmm12
vpunpckhdq %xmm3, %xmm2, %xmm13
vpunpckldq %xmm5, %xmm4, %xmm10
vpunpckldq %xmm7, %xmm6, %xmm11
vpunpckhdq %xmm5, %xmm4, %xmm14
vpunpckhdq %xmm7, %xmm6, %xmm15
vpunpcklqdq %xmm9, %xmm8, %xmm0
vpunpcklqdq %xmm11, %xmm10, %xmm1
vpunpckhqdq %xmm9, %xmm8, %xmm2
vpunpckhqdq %xmm11, %xmm10, %xmm3
vpunpcklqdq %xmm13, %xmm12, %xmm4
vpunpcklqdq %xmm15, %xmm14, %xmm5
vpunpckhqdq %xmm13, %xmm12, %xmm6
vpunpckhqdq %xmm15, %xmm14, %xmm7
vmovdqu %xmm0, 32(%rdx)
vmovdqu %xmm1, 48(%rdx)
vmovdqu %xmm2, 96(%rdx)
vmovdqu %xmm3, 112(%rdx)
vmovdqu %xmm4, 160(%rdx)
vmovdqu %xmm5, 176(%rdx)
vmovdqu %xmm6, 224(%rdx)
vmovdqu %xmm7, 240(%rdx)
chacha_blocks_avx2_mainloop2_cont:
addq $256, %rdx
subq $256, %rcx
cmp $256, %rcx
jae chacha_blocks_avx2_atleast256
chacha_blocks_avx2_below256_fixup:
vmovdqa 448(%rsp), %xmm6
vmovdqa 480(%rsp), %xmm7
vmovdqa 0(%rsp), %xmm8
vmovdqa 16(%rsp), %xmm9
vmovdqa 32(%rsp), %xmm10
vmovdqa 48(%rsp), %xmm11
movq $1, %r9
chacha_blocks_avx2_below256:
vmovq %r9, %xmm5
andq %rcx, %rcx
jz chacha_blocks_avx2_done
cmpq $64, %rcx
jae chacha_blocks_avx2_above63
movq %rdx, %r9
andq %rsi, %rsi
jz chacha_blocks_avx2_noinput3
movq %rcx, %r10
movq %rsp, %rdx
addq %r10, %rsi
addq %r10, %rdx
negq %r10
chacha_blocks_avx2_copyinput:
movb (%rsi, %r10), %al
movb %al, (%rdx, %r10)
incq %r10
jnz chacha_blocks_avx2_copyinput
movq %rsp, %rsi
chacha_blocks_avx2_noinput3:
movq %rsp, %rdx
chacha_blocks_avx2_above63:
vmovdqa %xmm8, %xmm0
vmovdqa %xmm9, %xmm1
vmovdqa %xmm10, %xmm2
vmovdqa %xmm11, %xmm3
movq 64(%rsp), %rax
chacha_blocks_avx2_mainloop3:
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm6, %xmm3, %xmm3
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpslld $12, %xmm1, %xmm4
vpsrld $20, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm7, %xmm3, %xmm3
vpshufd $0x93, %xmm0, %xmm0
vpaddd %xmm2, %xmm3, %xmm2
vpshufd $0x4e, %xmm3, %xmm3
vpxor %xmm1, %xmm2, %xmm1
vpshufd $0x39, %xmm2, %xmm2
vpslld $7, %xmm1, %xmm4
vpsrld $25, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm6, %xmm3, %xmm3
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpslld $12, %xmm1, %xmm4
vpsrld $20, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm7, %xmm3, %xmm3
vpshufd $0x39, %xmm0, %xmm0
vpaddd %xmm2, %xmm3, %xmm2
vpshufd $0x4e, %xmm3, %xmm3
vpxor %xmm1, %xmm2, %xmm1
vpshufd $0x93, %xmm2, %xmm2
vpslld $7, %xmm1, %xmm4
vpsrld $25, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
subq $2, %rax
jnz chacha_blocks_avx2_mainloop3
vpaddd %xmm0, %xmm8, %xmm0
vpaddd %xmm1, %xmm9, %xmm1
vpaddd %xmm2, %xmm10, %xmm2
vpaddd %xmm3, %xmm11, %xmm3
andq %rsi, %rsi
jz chacha_blocks_avx2_noinput4
vpxor 0(%rsi), %xmm0, %xmm0
vpxor 16(%rsi), %xmm1, %xmm1
vpxor 32(%rsi), %xmm2, %xmm2
vpxor 48(%rsi), %xmm3, %xmm3
addq $64, %rsi
chacha_blocks_avx2_noinput4:
vmovdqu %xmm0, 0(%rdx)
vmovdqu %xmm1, 16(%rdx)
vmovdqu %xmm2, 32(%rdx)
vmovdqu %xmm3, 48(%rdx)
vpaddq %xmm11, %xmm5, %xmm11
cmpq $64, %rcx
jbe chacha_blocks_avx2_mainloop3_finishup
addq $64, %rdx
subq $64, %rcx
jmp chacha_blocks_avx2_below256
chacha_blocks_avx2_mainloop3_finishup:
cmpq $64, %rcx
je chacha_blocks_avx2_done
addq %rcx, %r9
addq %rcx, %rdx
negq %rcx
chacha_blocks_avx2_copyoutput:
movb (%rdx, %rcx), %al
movb %al, (%r9, %rcx)
incq %rcx
jnz chacha_blocks_avx2_copyoutput
chacha_blocks_avx2_done:
vmovdqa %xmm11, 32(%rdi)
movq %rbp, %rsp
popq %r14
popq %r13
popq %r12
popq %rbp
popq %rbx
vzeroupper
ret
ENDFN(chacha_blocks)


FN(hchacha)
hchacha_avx2_local:
leaq C(%rip), %rax
vmovdqa 0(%rax), %xmm0
vmovdqa 16(%rax), %xmm6
vmovdqa 32(%rax), %xmm5
vmovdqu 0(%rdi), %xmm1
vmovdqu 16(%rdi), %xmm2
vmovdqu 0(%rsi), %xmm3
hhacha_mainloop_avx2:
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm6, %xmm3, %xmm3
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpslld $12, %xmm1, %xmm4
vpsrld $20, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm5, %xmm3, %xmm3
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpslld $7, %xmm1, %xmm4
vpsrld $25, %xmm1, %xmm1
vpshufd $0x93, %xmm0, %xmm0
vpxor %xmm1, %xmm4, %xmm1
vpshufd $0x4e, %xmm3, %xmm3
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm6, %xmm3, %xmm3
vpshufd $0x39, %xmm2, %xmm2
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpslld $12, %xmm1, %xmm4
vpsrld $20, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm5, %xmm3, %xmm3
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpshufd $0x39, %xmm0, %xmm0
vpslld $7, %xmm1, %xmm4
vpshufd $0x4e, %xmm3, %xmm3
vpsrld $25, %xmm1, %xmm1
vpshufd $0x93, %xmm2, %xmm2
vpxor %xmm1, %xmm4, %xmm1
subl $2, %ecx
jne hhacha_mainloop_avx2
vmovdqu %xmm0, (%rdx)
vmovdqu %xmm3, 16(%rdx)
ret
ENDFN(hchacha)

FN(chacha)
pushq %rbp
movq %rsp, %rbp
subq $64, %rsp
andq $~63, %rsp
vmovdqu 0(%rdi), %xmm0
vmovdqu 16(%rdi), %xmm1
vmovdqa %xmm0, 0(%rsp)
vmovdqa %xmm1, 16(%rsp)
xorq %rdi, %rdi
movq %rdi, 32(%rsp)
movq 0(%rsi), %rsi
movq %rsi, 40(%rsp)
movq %r9, 48(%rsp)
movq %rsp, %rdi
movq %rdx, %rsi
movq %rcx, %rdx
movq %r8, %rcx
call chacha_blocks_avx2_local
vpxor %xmm0, %xmm0, %xmm0
vmovdqa %xmm0, 0(%rsp)
vmovdqa %xmm0, 16(%rsp)
vmovdqa %xmm0, 32(%rsp)
movq %rbp, %rsp
popq %rbp
ret
ENDFN(chacha)

FN(xchacha)
pushq %rbp
pushq %rbx
movq %rsp, %rbp
subq $64, %rsp
andq $~63, %rsp
movq %rsp, %rbx
xorq %rax, %rax
movq %rax, 32(%rbx)
movq 16(%rsi), %rax
movq %rax, 40(%rbx)
movq %r9, 48(%rbx)
pushq %rdx
pushq %rcx
pushq %r8
movq %rbx, %rdx
movq %r9, %rcx
call hchacha_avx2_local
movq %rbx, %rdi
popq %rcx
popq %rdx
popq %rsi
call chacha_blocks_avx2_local
vpxor %xmm0, %xmm0, %xmm0
vmovdqa %xmm0, 0(%rbx)
vmovdqa %xmm0, 16(%rbx)
vmovdqa %xmm0, 32(%rbx)
movq %rbp, %rsp
popq %rbx
popq %rbp
ret
ENDFN(xchacha)


.section .rodata, "a"
.p2align 4,,15
C:
.long 0x61707865,0x3320646e,0x79622d32,0x6b206574 /* "expand 32-byte k" */
.byte 2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13       /* pshufb rotate by 16 */
.byte 3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14       /* pshufb rotate by 8 */

ENDFILE()
