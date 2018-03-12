
# qhasm: int64 input_0

# qhasm: int64 input_1

# qhasm: int64 input_2

# qhasm: int64 input_3

# qhasm: int64 input_4

# qhasm: int64 input_5

# qhasm: stack64 input_6

# qhasm: stack64 input_7

# qhasm: int64 caller_r11

# qhasm: int64 caller_r12

# qhasm: int64 caller_r13

# qhasm: int64 caller_r14

# qhasm: int64 caller_r15

# qhasm: int64 caller_rbx

# qhasm: int64 caller_rbp

# qhasm: reg256 tmp0

# qhasm: reg256 tmp1

# qhasm: reg256 tmp2

# qhasm: reg256 tmp3

# qhasm: reg256 c0

# qhasm: reg256 c1

# qhasm: reg256 c2

# qhasm: reg256 c3

# qhasm: reg256 b

# qhasm: reg256 t

# qhasm: reg256 d

# qhasm: reg256 c

# qhasm: reg256 qx8

# qhasm: reg256 _1x8

# qhasm: reg256 k

# qhasm: stack256 pg

# qhasm: int64 pgp

# qhasm: int64 byte

# qhasm: int64 key

# qhasm: int64 ctr

# qhasm: enter rec
.p2align 5
.global _rec
.global rec
_rec:
rec:
mov %rsp,%r11
and $31,%r11
add $32,%r11
sub %r11,%rsp

# qhasm: ctr = 0
# asm 1: mov  $0,>ctr=int64#4
# asm 2: mov  $0,>ctr=%rcx
mov  $0,%rcx

# qhasm: _1x8    = mem256[v1x8]
# asm 1: vmovdqu v1x8,>_1x8=reg256#1
# asm 2: vmovdqu v1x8,>_1x8=%ymm0
vmovdqu v1x8,%ymm0

# qhasm: qx8     = mem256[q8x]
# asm 1: vmovdqu q8x,>qx8=reg256#2
# asm 2: vmovdqu q8x,>qx8=%ymm1
vmovdqu q8x,%ymm1

# qhasm: pgp = &pg
# asm 1: leaq <pg=stack256#1,>pgp=int64#5
# asm 2: leaq <pg=0(%rsp),>pgp=%r8
leaq 0(%rsp),%r8

# qhasm: looptop:
._looptop:

# qhasm: ctr <<= 5
# asm 1: shl  $5,<ctr=int64#4
# asm 2: shl  $5,<ctr=%rcx
shl  $5,%rcx

# qhasm: c0 = mem256[input_2 + ctr + 0]
# asm 1: vmovupd   0(<input_2=int64#3,<ctr=int64#4),>c0=reg256#3
# asm 2: vmovupd   0(<input_2=%rdx,<ctr=%rcx),>c0=%ymm2
vmovupd   0(%rdx,%rcx),%ymm2

# qhasm: 8x c0 <<= 1
# asm 1: vpslld $1,<c0=reg256#3,>c0=reg256#3
# asm 2: vpslld $1,<c0=%ymm2,>c0=%ymm2
vpslld $1,%ymm2,%ymm2

# qhasm: c1 = mem256[input_2 + ctr + 1024]
# asm 1: vmovupd   1024(<input_2=int64#3,<ctr=int64#4),>c1=reg256#4
# asm 2: vmovupd   1024(<input_2=%rdx,<ctr=%rcx),>c1=%ymm3
vmovupd   1024(%rdx,%rcx),%ymm3

# qhasm: 8x c1 <<= 1
# asm 1: vpslld $1,<c1=reg256#4,>c1=reg256#4
# asm 2: vpslld $1,<c1=%ymm3,>c1=%ymm3
vpslld $1,%ymm3,%ymm3

# qhasm: c2 = mem256[input_2 + ctr + 2048]
# asm 1: vmovupd   2048(<input_2=int64#3,<ctr=int64#4),>c2=reg256#5
# asm 2: vmovupd   2048(<input_2=%rdx,<ctr=%rcx),>c2=%ymm4
vmovupd   2048(%rdx,%rcx),%ymm4

# qhasm: 8x c2 <<= 1
# asm 1: vpslld $1,<c2=reg256#5,>c2=reg256#5
# asm 2: vpslld $1,<c2=%ymm4,>c2=%ymm4
vpslld $1,%ymm4,%ymm4

# qhasm: c3 = mem256[input_2 + ctr + 3072]
# asm 1: vmovupd   3072(<input_2=int64#3,<ctr=int64#4),>c3=reg256#6
# asm 2: vmovupd   3072(<input_2=%rdx,<ctr=%rcx),>c3=%ymm5
vmovupd   3072(%rdx,%rcx),%ymm5

# qhasm: 8x c0 += c3
# asm 1: vpaddd <c3=reg256#6,<c0=reg256#3,>c0=reg256#3
# asm 2: vpaddd <c3=%ymm5,<c0=%ymm2,>c0=%ymm2
vpaddd %ymm5,%ymm2,%ymm2

# qhasm: 8x c1 += c3
# asm 1: vpaddd <c3=reg256#6,<c1=reg256#4,>c1=reg256#4
# asm 2: vpaddd <c3=%ymm5,<c1=%ymm3,>c1=%ymm3
vpaddd %ymm5,%ymm3,%ymm3

# qhasm: 8x c2 += c3
# asm 1: vpaddd <c3=reg256#6,<c2=reg256#5,>c2=reg256#5
# asm 2: vpaddd <c3=%ymm5,<c2=%ymm4,>c2=%ymm4
vpaddd %ymm5,%ymm4,%ymm4

# qhasm: 8x c0 *= qx8
# asm 1: vpmulld <qx8=reg256#2,<c0=reg256#3,>c0=reg256#3
# asm 2: vpmulld <qx8=%ymm1,<c0=%ymm2,>c0=%ymm2
vpmulld %ymm1,%ymm2,%ymm2

# qhasm: 8x c1 *= qx8
# asm 1: vpmulld <qx8=reg256#2,<c1=reg256#4,>c1=reg256#4
# asm 2: vpmulld <qx8=%ymm1,<c1=%ymm3,>c1=%ymm3
vpmulld %ymm1,%ymm3,%ymm3

# qhasm: 8x c2 *= qx8
# asm 1: vpmulld <qx8=reg256#2,<c2=reg256#5,>c2=reg256#5
# asm 2: vpmulld <qx8=%ymm1,<c2=%ymm4,>c2=%ymm4
vpmulld %ymm1,%ymm4,%ymm4

# qhasm: 8x c3 *= qx8
# asm 1: vpmulld <qx8=reg256#2,<c3=reg256#6,>c3=reg256#6
# asm 2: vpmulld <qx8=%ymm1,<c3=%ymm5,>c3=%ymm5
vpmulld %ymm1,%ymm5,%ymm5

# qhasm: tmp0 = mem256[input_1 + ctr + 0]
# asm 1: vmovupd   0(<input_1=int64#2,<ctr=int64#4),>tmp0=reg256#7
# asm 2: vmovupd   0(<input_1=%rsi,<ctr=%rcx),>tmp0=%ymm6
vmovupd   0(%rsi,%rcx),%ymm6

# qhasm: tmp1 = mem256[input_1 + ctr + 1024]
# asm 1: vmovupd   1024(<input_1=int64#2,<ctr=int64#4),>tmp1=reg256#8
# asm 2: vmovupd   1024(<input_1=%rsi,<ctr=%rcx),>tmp1=%ymm7
vmovupd   1024(%rsi,%rcx),%ymm7

# qhasm: tmp2 = mem256[input_1 + ctr + 2048]
# asm 1: vmovupd   2048(<input_1=int64#2,<ctr=int64#4),>tmp2=reg256#9
# asm 2: vmovupd   2048(<input_1=%rsi,<ctr=%rcx),>tmp2=%ymm8
vmovupd   2048(%rsi,%rcx),%ymm8

# qhasm: tmp3 = mem256[input_1 + ctr + 3072]
# asm 1: vmovupd   3072(<input_1=int64#2,<ctr=int64#4),>tmp3=reg256#10
# asm 2: vmovupd   3072(<input_1=%rsi,<ctr=%rcx),>tmp3=%ymm9
vmovupd   3072(%rsi,%rcx),%ymm9

# qhasm: (uint64) ctr >>= 5
# asm 1: shr  $5,<ctr=int64#4
# asm 2: shr  $5,<ctr=%rcx
shr  $5,%rcx

# qhasm: 8x tmp0 <<= 3
# asm 1: vpslld $3,<tmp0=reg256#7,>tmp0=reg256#7
# asm 2: vpslld $3,<tmp0=%ymm6,>tmp0=%ymm6
vpslld $3,%ymm6,%ymm6

# qhasm: 8x tmp1 <<= 3
# asm 1: vpslld $3,<tmp1=reg256#8,>tmp1=reg256#8
# asm 2: vpslld $3,<tmp1=%ymm7,>tmp1=%ymm7
vpslld $3,%ymm7,%ymm7

# qhasm: 8x tmp2 <<= 3
# asm 1: vpslld $3,<tmp2=reg256#9,>tmp2=reg256#9
# asm 2: vpslld $3,<tmp2=%ymm8,>tmp2=%ymm8
vpslld $3,%ymm8,%ymm8

# qhasm: 8x tmp3 <<= 3
# asm 1: vpslld $3,<tmp3=reg256#10,>tmp3=reg256#10
# asm 2: vpslld $3,<tmp3=%ymm9,>tmp3=%ymm9
vpslld $3,%ymm9,%ymm9

# qhasm: 8x qx8 <<= 4 
# asm 1: vpslld $4,<qx8=reg256#2,>qx8=reg256#2
# asm 2: vpslld $4,<qx8=%ymm1,>qx8=%ymm1
vpslld $4,%ymm1,%ymm1

# qhasm: 8x tmp0 += qx8
# asm 1: vpaddd <qx8=reg256#2,<tmp0=reg256#7,>tmp0=reg256#7
# asm 2: vpaddd <qx8=%ymm1,<tmp0=%ymm6,>tmp0=%ymm6
vpaddd %ymm1,%ymm6,%ymm6

# qhasm: 8x tmp1 += qx8
# asm 1: vpaddd <qx8=reg256#2,<tmp1=reg256#8,>tmp1=reg256#8
# asm 2: vpaddd <qx8=%ymm1,<tmp1=%ymm7,>tmp1=%ymm7
vpaddd %ymm1,%ymm7,%ymm7

# qhasm: 8x tmp2 += qx8
# asm 1: vpaddd <qx8=reg256#2,<tmp2=reg256#9,>tmp2=reg256#9
# asm 2: vpaddd <qx8=%ymm1,<tmp2=%ymm8,>tmp2=%ymm8
vpaddd %ymm1,%ymm8,%ymm8

# qhasm: 8x tmp3 += qx8
# asm 1: vpaddd <qx8=reg256#2,<tmp3=reg256#10,>tmp3=reg256#10
# asm 2: vpaddd <qx8=%ymm1,<tmp3=%ymm9,>tmp3=%ymm9
vpaddd %ymm1,%ymm9,%ymm9

# qhasm: 8x qx8 >>= 2 
# asm 1: vpsrad $2,<qx8=reg256#2,>qx8=reg256#2
# asm 2: vpsrad $2,<qx8=%ymm1,>qx8=%ymm1
vpsrad $2,%ymm1,%ymm1

# qhasm: 8x tmp0 -= c0
# asm 1: vpsubd <c0=reg256#3,<tmp0=reg256#7,>tmp0=reg256#3
# asm 2: vpsubd <c0=%ymm2,<tmp0=%ymm6,>tmp0=%ymm2
vpsubd %ymm2,%ymm6,%ymm2

# qhasm: 8x tmp1 -= c1
# asm 1: vpsubd <c1=reg256#4,<tmp1=reg256#8,>tmp1=reg256#4
# asm 2: vpsubd <c1=%ymm3,<tmp1=%ymm7,>tmp1=%ymm3
vpsubd %ymm3,%ymm7,%ymm3

# qhasm: 8x tmp2 -= c2
# asm 1: vpsubd <c2=reg256#5,<tmp2=reg256#9,>tmp2=reg256#5
# asm 2: vpsubd <c2=%ymm4,<tmp2=%ymm8,>tmp2=%ymm4
vpsubd %ymm4,%ymm8,%ymm4

# qhasm: 8x tmp3 -= c3
# asm 1: vpsubd <c3=reg256#6,<tmp3=reg256#10,>tmp3=reg256#6
# asm 2: vpsubd <c3=%ymm5,<tmp3=%ymm9,>tmp3=%ymm5
vpsubd %ymm5,%ymm9,%ymm5

# qhasm: 8x b = tmp0 * mem256[v2730x8]
# asm 1: vpmulld v2730x8,<tmp0=reg256#3,>b=reg256#7
# asm 2: vpmulld v2730x8,<tmp0=%ymm2,>b=%ymm6
vpmulld v2730x8,%ymm2,%ymm6

# qhasm: 8x t = b >> 27
# asm 1: vpsrad $27,<b=reg256#7,>t=reg256#7
# asm 2: vpsrad $27,<b=%ymm6,>t=%ymm6
vpsrad $27,%ymm6,%ymm6

# qhasm: 8x d = t * qx8
# asm 1: vpmulld <t=reg256#7,<qx8=reg256#2,>d=reg256#8
# asm 2: vpmulld <t=%ymm6,<qx8=%ymm1,>d=%ymm7
vpmulld %ymm6,%ymm1,%ymm7

# qhasm: 8x b = tmp0 - d
# asm 1: vpsubd <d=reg256#8,<tmp0=reg256#3,>b=reg256#8
# asm 2: vpsubd <d=%ymm7,<tmp0=%ymm2,>b=%ymm7
vpsubd %ymm7,%ymm2,%ymm7

# qhasm: 8x b += _1x8
# asm 1: vpaddd <_1x8=reg256#1,<b=reg256#8,>b=reg256#8
# asm 2: vpaddd <_1x8=%ymm0,<b=%ymm7,>b=%ymm7
vpaddd %ymm0,%ymm7,%ymm7

# qhasm: 8x b = qx8 - b
# asm 1: vpsubd <b=reg256#8,<qx8=reg256#2,>b=reg256#8
# asm 2: vpsubd <b=%ymm7,<qx8=%ymm1,>b=%ymm7
vpsubd %ymm7,%ymm1,%ymm7

# qhasm: 8x b >>= 31
# asm 1: vpsrad $31,<b=reg256#8,>b=reg256#8
# asm 2: vpsrad $31,<b=%ymm7,>b=%ymm7
vpsrad $31,%ymm7,%ymm7

# qhasm: 8x t -= b
# asm 1: vpsubd <b=reg256#8,<t=reg256#7,>t=reg256#7
# asm 2: vpsubd <b=%ymm7,<t=%ymm6,>t=%ymm6
vpsubd %ymm7,%ymm6,%ymm6

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#7,<_1x8=reg256#1,>d=reg256#8
# asm 2: vpand <t=%ymm6,<_1x8=%ymm0,>d=%ymm7
vpand %ymm6,%ymm0,%ymm7

# qhasm: 8x t = t >> 1 
# asm 1: vpsrad $1,<t=reg256#7,>t=reg256#7
# asm 2: vpsrad $1,<t=%ymm6,>t=%ymm6
vpsrad $1,%ymm6,%ymm6

# qhasm: 8x t += d
# asm 1: vpaddd <d=reg256#8,<t=reg256#7,>t=reg256#7
# asm 2: vpaddd <d=%ymm7,<t=%ymm6,>t=%ymm6
vpaddd %ymm7,%ymm6,%ymm6

# qhasm: 8x t *= qx8
# asm 1: vpmulld <qx8=reg256#2,<t=reg256#7,>t=reg256#7
# asm 2: vpmulld <qx8=%ymm1,<t=%ymm6,>t=%ymm6
vpmulld %ymm1,%ymm6,%ymm6

# qhasm: 8x t <<= 1 
# asm 1: vpslld $1,<t=reg256#7,>t=reg256#7
# asm 2: vpslld $1,<t=%ymm6,>t=%ymm6
vpslld $1,%ymm6,%ymm6

# qhasm: 8x t -= tmp0
# asm 1: vpsubd <tmp0=reg256#3,<t=reg256#7,>t=reg256#3
# asm 2: vpsubd <tmp0=%ymm2,<t=%ymm6,>t=%ymm2
vpsubd %ymm2,%ymm6,%ymm2

# qhasm: 8x k = abs(t)
# asm 1: vpabsd <t=reg256#3,>k=reg256#3
# asm 2: vpabsd <t=%ymm2,>k=%ymm2
vpabsd %ymm2,%ymm2

# qhasm: 8x b = tmp1 * mem256[v2730x8]
# asm 1: vpmulld v2730x8,<tmp1=reg256#4,>b=reg256#7
# asm 2: vpmulld v2730x8,<tmp1=%ymm3,>b=%ymm6
vpmulld v2730x8,%ymm3,%ymm6

# qhasm: 8x t = b >> 27
# asm 1: vpsrad $27,<b=reg256#7,>t=reg256#7
# asm 2: vpsrad $27,<b=%ymm6,>t=%ymm6
vpsrad $27,%ymm6,%ymm6

# qhasm: 8x d = t * qx8
# asm 1: vpmulld <t=reg256#7,<qx8=reg256#2,>d=reg256#8
# asm 2: vpmulld <t=%ymm6,<qx8=%ymm1,>d=%ymm7
vpmulld %ymm6,%ymm1,%ymm7

# qhasm: 8x b = tmp1 - d
# asm 1: vpsubd <d=reg256#8,<tmp1=reg256#4,>b=reg256#8
# asm 2: vpsubd <d=%ymm7,<tmp1=%ymm3,>b=%ymm7
vpsubd %ymm7,%ymm3,%ymm7

# qhasm: 8x b += _1x8
# asm 1: vpaddd <_1x8=reg256#1,<b=reg256#8,>b=reg256#8
# asm 2: vpaddd <_1x8=%ymm0,<b=%ymm7,>b=%ymm7
vpaddd %ymm0,%ymm7,%ymm7

# qhasm: 8x b = qx8 - b
# asm 1: vpsubd <b=reg256#8,<qx8=reg256#2,>b=reg256#8
# asm 2: vpsubd <b=%ymm7,<qx8=%ymm1,>b=%ymm7
vpsubd %ymm7,%ymm1,%ymm7

# qhasm: 8x b >>= 31
# asm 1: vpsrad $31,<b=reg256#8,>b=reg256#8
# asm 2: vpsrad $31,<b=%ymm7,>b=%ymm7
vpsrad $31,%ymm7,%ymm7

# qhasm: 8x t -= b
# asm 1: vpsubd <b=reg256#8,<t=reg256#7,>t=reg256#7
# asm 2: vpsubd <b=%ymm7,<t=%ymm6,>t=%ymm6
vpsubd %ymm7,%ymm6,%ymm6

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#7,<_1x8=reg256#1,>d=reg256#8
# asm 2: vpand <t=%ymm6,<_1x8=%ymm0,>d=%ymm7
vpand %ymm6,%ymm0,%ymm7

# qhasm: 8x t = t >> 1 
# asm 1: vpsrad $1,<t=reg256#7,>t=reg256#7
# asm 2: vpsrad $1,<t=%ymm6,>t=%ymm6
vpsrad $1,%ymm6,%ymm6

# qhasm: 8x t += d
# asm 1: vpaddd <d=reg256#8,<t=reg256#7,>t=reg256#7
# asm 2: vpaddd <d=%ymm7,<t=%ymm6,>t=%ymm6
vpaddd %ymm7,%ymm6,%ymm6

# qhasm: 8x t *= qx8
# asm 1: vpmulld <qx8=reg256#2,<t=reg256#7,>t=reg256#7
# asm 2: vpmulld <qx8=%ymm1,<t=%ymm6,>t=%ymm6
vpmulld %ymm1,%ymm6,%ymm6

# qhasm: 8x t <<= 1 
# asm 1: vpslld $1,<t=reg256#7,>t=reg256#7
# asm 2: vpslld $1,<t=%ymm6,>t=%ymm6
vpslld $1,%ymm6,%ymm6

# qhasm: 8x t -= tmp1
# asm 1: vpsubd <tmp1=reg256#4,<t=reg256#7,>t=reg256#4
# asm 2: vpsubd <tmp1=%ymm3,<t=%ymm6,>t=%ymm3
vpsubd %ymm3,%ymm6,%ymm3

# qhasm: 8x t = abs(t)
# asm 1: vpabsd <t=reg256#4,>t=reg256#4
# asm 2: vpabsd <t=%ymm3,>t=%ymm3
vpabsd %ymm3,%ymm3

# qhasm: 8x k += t
# asm 1: vpaddd <t=reg256#4,<k=reg256#3,>k=reg256#3
# asm 2: vpaddd <t=%ymm3,<k=%ymm2,>k=%ymm2
vpaddd %ymm3,%ymm2,%ymm2

# qhasm: 8x b = tmp2 * mem256[v2730x8]
# asm 1: vpmulld v2730x8,<tmp2=reg256#5,>b=reg256#4
# asm 2: vpmulld v2730x8,<tmp2=%ymm4,>b=%ymm3
vpmulld v2730x8,%ymm4,%ymm3

# qhasm: 8x t = b >> 27
# asm 1: vpsrad $27,<b=reg256#4,>t=reg256#4
# asm 2: vpsrad $27,<b=%ymm3,>t=%ymm3
vpsrad $27,%ymm3,%ymm3

# qhasm: 8x d = t * qx8
# asm 1: vpmulld <t=reg256#4,<qx8=reg256#2,>d=reg256#7
# asm 2: vpmulld <t=%ymm3,<qx8=%ymm1,>d=%ymm6
vpmulld %ymm3,%ymm1,%ymm6

# qhasm: 8x b = tmp2 - d
# asm 1: vpsubd <d=reg256#7,<tmp2=reg256#5,>b=reg256#7
# asm 2: vpsubd <d=%ymm6,<tmp2=%ymm4,>b=%ymm6
vpsubd %ymm6,%ymm4,%ymm6

# qhasm: 8x b += _1x8
# asm 1: vpaddd <_1x8=reg256#1,<b=reg256#7,>b=reg256#7
# asm 2: vpaddd <_1x8=%ymm0,<b=%ymm6,>b=%ymm6
vpaddd %ymm0,%ymm6,%ymm6

# qhasm: 8x b = qx8 - b
# asm 1: vpsubd <b=reg256#7,<qx8=reg256#2,>b=reg256#7
# asm 2: vpsubd <b=%ymm6,<qx8=%ymm1,>b=%ymm6
vpsubd %ymm6,%ymm1,%ymm6

# qhasm: 8x b >>= 31
# asm 1: vpsrad $31,<b=reg256#7,>b=reg256#7
# asm 2: vpsrad $31,<b=%ymm6,>b=%ymm6
vpsrad $31,%ymm6,%ymm6

# qhasm: 8x t -= b
# asm 1: vpsubd <b=reg256#7,<t=reg256#4,>t=reg256#4
# asm 2: vpsubd <b=%ymm6,<t=%ymm3,>t=%ymm3
vpsubd %ymm6,%ymm3,%ymm3

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#4,<_1x8=reg256#1,>d=reg256#7
# asm 2: vpand <t=%ymm3,<_1x8=%ymm0,>d=%ymm6
vpand %ymm3,%ymm0,%ymm6

# qhasm: 8x t = t >> 1 
# asm 1: vpsrad $1,<t=reg256#4,>t=reg256#4
# asm 2: vpsrad $1,<t=%ymm3,>t=%ymm3
vpsrad $1,%ymm3,%ymm3

# qhasm: 8x t += d
# asm 1: vpaddd <d=reg256#7,<t=reg256#4,>t=reg256#4
# asm 2: vpaddd <d=%ymm6,<t=%ymm3,>t=%ymm3
vpaddd %ymm6,%ymm3,%ymm3

# qhasm: 8x t *= qx8
# asm 1: vpmulld <qx8=reg256#2,<t=reg256#4,>t=reg256#4
# asm 2: vpmulld <qx8=%ymm1,<t=%ymm3,>t=%ymm3
vpmulld %ymm1,%ymm3,%ymm3

# qhasm: 8x t <<= 1 
# asm 1: vpslld $1,<t=reg256#4,>t=reg256#4
# asm 2: vpslld $1,<t=%ymm3,>t=%ymm3
vpslld $1,%ymm3,%ymm3

# qhasm: 8x t -= tmp2
# asm 1: vpsubd <tmp2=reg256#5,<t=reg256#4,>t=reg256#4
# asm 2: vpsubd <tmp2=%ymm4,<t=%ymm3,>t=%ymm3
vpsubd %ymm4,%ymm3,%ymm3

# qhasm: 8x t = abs(t)
# asm 1: vpabsd <t=reg256#4,>t=reg256#4
# asm 2: vpabsd <t=%ymm3,>t=%ymm3
vpabsd %ymm3,%ymm3

# qhasm: 8x k += t
# asm 1: vpaddd <t=reg256#4,<k=reg256#3,>k=reg256#3
# asm 2: vpaddd <t=%ymm3,<k=%ymm2,>k=%ymm2
vpaddd %ymm3,%ymm2,%ymm2

# qhasm: 8x b = tmp3 * mem256[v2730x8]
# asm 1: vpmulld v2730x8,<tmp3=reg256#6,>b=reg256#4
# asm 2: vpmulld v2730x8,<tmp3=%ymm5,>b=%ymm3
vpmulld v2730x8,%ymm5,%ymm3

# qhasm: 8x t = b >> 27
# asm 1: vpsrad $27,<b=reg256#4,>t=reg256#4
# asm 2: vpsrad $27,<b=%ymm3,>t=%ymm3
vpsrad $27,%ymm3,%ymm3

# qhasm: 8x d = t * qx8
# asm 1: vpmulld <t=reg256#4,<qx8=reg256#2,>d=reg256#5
# asm 2: vpmulld <t=%ymm3,<qx8=%ymm1,>d=%ymm4
vpmulld %ymm3,%ymm1,%ymm4

# qhasm: 8x b = tmp3 - d
# asm 1: vpsubd <d=reg256#5,<tmp3=reg256#6,>b=reg256#5
# asm 2: vpsubd <d=%ymm4,<tmp3=%ymm5,>b=%ymm4
vpsubd %ymm4,%ymm5,%ymm4

# qhasm: 8x b += _1x8
# asm 1: vpaddd <_1x8=reg256#1,<b=reg256#5,>b=reg256#5
# asm 2: vpaddd <_1x8=%ymm0,<b=%ymm4,>b=%ymm4
vpaddd %ymm0,%ymm4,%ymm4

# qhasm: 8x b = qx8 - b
# asm 1: vpsubd <b=reg256#5,<qx8=reg256#2,>b=reg256#5
# asm 2: vpsubd <b=%ymm4,<qx8=%ymm1,>b=%ymm4
vpsubd %ymm4,%ymm1,%ymm4

# qhasm: 8x b >>= 31
# asm 1: vpsrad $31,<b=reg256#5,>b=reg256#5
# asm 2: vpsrad $31,<b=%ymm4,>b=%ymm4
vpsrad $31,%ymm4,%ymm4

# qhasm: 8x t -= b
# asm 1: vpsubd <b=reg256#5,<t=reg256#4,>t=reg256#4
# asm 2: vpsubd <b=%ymm4,<t=%ymm3,>t=%ymm3
vpsubd %ymm4,%ymm3,%ymm3

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#4,<_1x8=reg256#1,>d=reg256#5
# asm 2: vpand <t=%ymm3,<_1x8=%ymm0,>d=%ymm4
vpand %ymm3,%ymm0,%ymm4

# qhasm: 8x t = t >> 1 
# asm 1: vpsrad $1,<t=reg256#4,>t=reg256#4
# asm 2: vpsrad $1,<t=%ymm3,>t=%ymm3
vpsrad $1,%ymm3,%ymm3

# qhasm: 8x t += d
# asm 1: vpaddd <d=reg256#5,<t=reg256#4,>t=reg256#4
# asm 2: vpaddd <d=%ymm4,<t=%ymm3,>t=%ymm3
vpaddd %ymm4,%ymm3,%ymm3

# qhasm: 8x t *= qx8
# asm 1: vpmulld <qx8=reg256#2,<t=reg256#4,>t=reg256#4
# asm 2: vpmulld <qx8=%ymm1,<t=%ymm3,>t=%ymm3
vpmulld %ymm1,%ymm3,%ymm3

# qhasm: 8x t <<= 1 
# asm 1: vpslld $1,<t=reg256#4,>t=reg256#4
# asm 2: vpslld $1,<t=%ymm3,>t=%ymm3
vpslld $1,%ymm3,%ymm3

# qhasm: 8x t -= tmp3
# asm 1: vpsubd <tmp3=reg256#6,<t=reg256#4,>t=reg256#4
# asm 2: vpsubd <tmp3=%ymm5,<t=%ymm3,>t=%ymm3
vpsubd %ymm5,%ymm3,%ymm3

# qhasm: 8x t = abs(t)
# asm 1: vpabsd <t=reg256#4,>t=reg256#4
# asm 2: vpabsd <t=%ymm3,>t=%ymm3
vpabsd %ymm3,%ymm3

# qhasm: 8x k += t
# asm 1: vpaddd <t=reg256#4,<k=reg256#3,>k=reg256#3
# asm 2: vpaddd <t=%ymm3,<k=%ymm2,>k=%ymm2
vpaddd %ymm3,%ymm2,%ymm2

# qhasm: 8x qx8 <<= 1 
# asm 1: vpslld $1,<qx8=reg256#2,>qx8=reg256#2
# asm 2: vpslld $1,<qx8=%ymm1,>qx8=%ymm1
vpslld $1,%ymm1,%ymm1

# qhasm: 8x k -= qx8
# asm 1: vpsubd <qx8=reg256#2,<k=reg256#3,>k=reg256#3
# asm 2: vpsubd <qx8=%ymm1,<k=%ymm2,>k=%ymm2
vpsubd %ymm1,%ymm2,%ymm2

# qhasm: 8x k >>= 31
# asm 1: vpsrad $31,<k=reg256#3,>k=reg256#3
# asm 2: vpsrad $31,<k=%ymm2,>k=%ymm2
vpsrad $31,%ymm2,%ymm2

# qhasm:    k &= _1x8
# asm 1: vpand <_1x8=reg256#1,<k=reg256#3,<k=reg256#3
# asm 2: vpand <_1x8=%ymm0,<k=%ymm2,<k=%ymm2
vpand %ymm0,%ymm2,%ymm2

# qhasm: pg = k
# asm 1: vmovapd <k=reg256#3,>pg=stack256#1
# asm 2: vmovapd <k=%ymm2,>pg=0(%rsp)
vmovapd %ymm2,0(%rsp)

# qhasm: key = *(uint32 *)(pgp + 28)
# asm 1: movl   28(<pgp=int64#5),>key=int64#6d
# asm 2: movl   28(<pgp=%r8),>key=%r9d
movl   28(%r8),%r9d

# qhasm: key <<= 1
# asm 1: shl  $1,<key=int64#6
# asm 2: shl  $1,<key=%r9
shl  $1,%r9

# qhasm: byte = *(uint32 *)(pgp + 24)
# asm 1: movl   24(<pgp=int64#5),>byte=int64#7d
# asm 2: movl   24(<pgp=%r8),>byte=%eax
movl   24(%r8),%eax

# qhasm: key |= byte
# asm 1: or   <byte=int64#7,<key=int64#6
# asm 2: or   <byte=%rax,<key=%r9
or   %rax,%r9

# qhasm: key <<= 1
# asm 1: shl  $1,<key=int64#6
# asm 2: shl  $1,<key=%r9
shl  $1,%r9

# qhasm: byte = *(uint32 *)(pgp + 20)
# asm 1: movl   20(<pgp=int64#5),>byte=int64#7d
# asm 2: movl   20(<pgp=%r8),>byte=%eax
movl   20(%r8),%eax

# qhasm: key |= byte
# asm 1: or   <byte=int64#7,<key=int64#6
# asm 2: or   <byte=%rax,<key=%r9
or   %rax,%r9

# qhasm: key <<= 1
# asm 1: shl  $1,<key=int64#6
# asm 2: shl  $1,<key=%r9
shl  $1,%r9

# qhasm: byte = *(uint32 *)(pgp + 16)
# asm 1: movl   16(<pgp=int64#5),>byte=int64#7d
# asm 2: movl   16(<pgp=%r8),>byte=%eax
movl   16(%r8),%eax

# qhasm: key |= byte
# asm 1: or   <byte=int64#7,<key=int64#6
# asm 2: or   <byte=%rax,<key=%r9
or   %rax,%r9

# qhasm: key <<= 1
# asm 1: shl  $1,<key=int64#6
# asm 2: shl  $1,<key=%r9
shl  $1,%r9

# qhasm: byte = *(uint32 *)(pgp + 12)
# asm 1: movl   12(<pgp=int64#5),>byte=int64#7d
# asm 2: movl   12(<pgp=%r8),>byte=%eax
movl   12(%r8),%eax

# qhasm: key |= byte
# asm 1: or   <byte=int64#7,<key=int64#6
# asm 2: or   <byte=%rax,<key=%r9
or   %rax,%r9

# qhasm: key <<= 1
# asm 1: shl  $1,<key=int64#6
# asm 2: shl  $1,<key=%r9
shl  $1,%r9

# qhasm: byte = *(uint32 *)(pgp +  8)
# asm 1: movl   8(<pgp=int64#5),>byte=int64#7d
# asm 2: movl   8(<pgp=%r8),>byte=%eax
movl   8(%r8),%eax

# qhasm: key |= byte
# asm 1: or   <byte=int64#7,<key=int64#6
# asm 2: or   <byte=%rax,<key=%r9
or   %rax,%r9

# qhasm: key <<= 1
# asm 1: shl  $1,<key=int64#6
# asm 2: shl  $1,<key=%r9
shl  $1,%r9

# qhasm: byte = *(uint32 *)(pgp +  4)
# asm 1: movl   4(<pgp=int64#5),>byte=int64#7d
# asm 2: movl   4(<pgp=%r8),>byte=%eax
movl   4(%r8),%eax

# qhasm: key |= byte
# asm 1: or   <byte=int64#7,<key=int64#6
# asm 2: or   <byte=%rax,<key=%r9
or   %rax,%r9

# qhasm: key <<= 1
# asm 1: shl  $1,<key=int64#6
# asm 2: shl  $1,<key=%r9
shl  $1,%r9

# qhasm: byte = *(uint32 *)(pgp +  0)
# asm 1: movl   0(<pgp=int64#5),>byte=int64#7d
# asm 2: movl   0(<pgp=%r8),>byte=%eax
movl   0(%r8),%eax

# qhasm: key |= byte
# asm 1: or   <byte=int64#7,<key=int64#6
# asm 2: or   <byte=%rax,<key=%r9
or   %rax,%r9

# qhasm: mem8[input_0 + ctr + 0] = key
# asm 1: movb   <key=int64#6b,0(<input_0=int64#1,<ctr=int64#4)
# asm 2: movb   <key=%r9b,0(<input_0=%rdi,<ctr=%rcx)
movb   %r9b,0(%rdi,%rcx)

# qhasm: 8x qx8 >>= 3 
# asm 1: vpsrad $3,<qx8=reg256#2,>qx8=reg256#2
# asm 2: vpsrad $3,<qx8=%ymm1,>qx8=%ymm1
vpsrad $3,%ymm1,%ymm1

# qhasm: ctr += 1
# asm 1: add  $1,<ctr=int64#4
# asm 2: add  $1,<ctr=%rcx
add  $1,%rcx

# qhasm: unsigned<? ctr - 32
# asm 1: cmp  $32,<ctr=int64#4
# asm 2: cmp  $32,<ctr=%rcx
cmp  $32,%rcx
# comment:fp stack unchanged by jump

# qhasm: goto looptop if unsigned<
jb ._looptop

# qhasm: return
add %r11,%rsp
ret
