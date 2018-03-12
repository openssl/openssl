
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

# qhasm: reg256 v

# qhasm: reg256 v0a

# qhasm: reg256 v0b

# qhasm: reg256 v0c

# qhasm: reg256 v0d

# qhasm: reg256 v1a

# qhasm: reg256 v1b

# qhasm: reg256 v1c

# qhasm: reg256 v1d

# qhasm: reg256 vtmp0

# qhasm: reg256 vtmp1

# qhasm: reg256 vtmp2

# qhasm: reg256 vtmp3

# qhasm: reg256 k

# qhasm: reg256 b

# qhasm: reg256 t

# qhasm: reg256 d

# qhasm: reg256 c

# qhasm: reg256 rbit

# qhasm: reg256 qx8

# qhasm: reg256 _1x8

# qhasm: reg256 _3x8

# qhasm: reg256 rshifts

# qhasm: reg256 _2730

# qhasm: int64 ctr

# qhasm: enter hr
.p2align 5
.global _hr
.global hr
_hr:
hr:
mov %rsp,%r11
and $31,%r11
add $0,%r11
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

# qhasm: looptop:
._looptop:

# qhasm: rshifts = mem256[vrshiftsx8]
# asm 1: vmovdqu vrshiftsx8,>rshifts=reg256#3
# asm 2: vmovdqu vrshiftsx8,>rshifts=%ymm2
vmovdqu vrshiftsx8,%ymm2

# qhasm: 32x rbit = mem8[input_2 + ctr + 0]
# asm 1: vpbroadcastb 0(<input_2=int64#3,<ctr=int64#4),>rbit=reg256#4
# asm 2: vpbroadcastb 0(<input_2=%rdx,<ctr=%rcx),>rbit=%ymm3
vpbroadcastb 0(%rdx,%rcx),%ymm3

# qhasm: 8x rbit unsigned>>= rshifts
# asm 1: vpsrlvd <rshifts=reg256#3,<rbit=reg256#4,>rbit=reg256#3
# asm 2: vpsrlvd <rshifts=%ymm2,<rbit=%ymm3,>rbit=%ymm2
vpsrlvd %ymm2,%ymm3,%ymm2

# qhasm: rbit &= _1x8
# asm 1: vpand <_1x8=reg256#1,<rbit=reg256#3,<rbit=reg256#3
# asm 2: vpand <_1x8=%ymm0,<rbit=%ymm2,<rbit=%ymm2
vpand %ymm0,%ymm2,%ymm2

# qhasm: 8x rbit <<= 2
# asm 1: vpslld $2,<rbit=reg256#3,>rbit=reg256#3
# asm 2: vpslld $2,<rbit=%ymm2,>rbit=%ymm2
vpslld $2,%ymm2,%ymm2

# qhasm: ctr <<= 5
# asm 1: shl  $5,<ctr=int64#4
# asm 2: shl  $5,<ctr=%rcx
shl  $5,%rcx

# qhasm: v = mem256[input_1 + ctr + 0]
# asm 1: vmovupd   0(<input_1=int64#2,<ctr=int64#4),>v=reg256#4
# asm 2: vmovupd   0(<input_1=%rsi,<ctr=%rcx),>v=%ymm3
vmovupd   0(%rsi,%rcx),%ymm3

# qhasm: 8x v <<= 3
# asm 1: vpslld $3,<v=reg256#4,>v=reg256#4
# asm 2: vpslld $3,<v=%ymm3,>v=%ymm3
vpslld $3,%ymm3,%ymm3

# qhasm: 8x v += rbit
# asm 1: vpaddd <rbit=reg256#3,<v=reg256#4,>v=reg256#4
# asm 2: vpaddd <rbit=%ymm2,<v=%ymm3,>v=%ymm3
vpaddd %ymm2,%ymm3,%ymm3

# qhasm: 8x b = v * mem256[v2730x8]
# asm 1: vpmulld v2730x8,<v=reg256#4,>b=reg256#5
# asm 2: vpmulld v2730x8,<v=%ymm3,>b=%ymm4
vpmulld v2730x8,%ymm3,%ymm4

# qhasm: 8x t = b >> 25
# asm 1: vpsrad $25,<b=reg256#5,>t=reg256#5
# asm 2: vpsrad $25,<b=%ymm4,>t=%ymm4
vpsrad $25,%ymm4,%ymm4

# qhasm: 8x d = t * qx8
# asm 1: vpmulld <t=reg256#5,<qx8=reg256#2,>d=reg256#6
# asm 2: vpmulld <t=%ymm4,<qx8=%ymm1,>d=%ymm5
vpmulld %ymm4,%ymm1,%ymm5

# qhasm: 8x b = v - d
# asm 1: vpsubd <d=reg256#6,<v=reg256#4,>b=reg256#6
# asm 2: vpsubd <d=%ymm5,<v=%ymm3,>b=%ymm5
vpsubd %ymm5,%ymm3,%ymm5

# qhasm: 8x b += _1x8
# asm 1: vpaddd <_1x8=reg256#1,<b=reg256#6,>b=reg256#6
# asm 2: vpaddd <_1x8=%ymm0,<b=%ymm5,>b=%ymm5
vpaddd %ymm0,%ymm5,%ymm5

# qhasm: 8x b = qx8 - b
# asm 1: vpsubd <b=reg256#6,<qx8=reg256#2,>b=reg256#6
# asm 2: vpsubd <b=%ymm5,<qx8=%ymm1,>b=%ymm5
vpsubd %ymm5,%ymm1,%ymm5

# qhasm: 8x b >>= 31
# asm 1: vpsrad $31,<b=reg256#6,>b=reg256#6
# asm 2: vpsrad $31,<b=%ymm5,>b=%ymm5
vpsrad $31,%ymm5,%ymm5

# qhasm: 8x t -= b
# asm 1: vpsubd <b=reg256#6,<t=reg256#5,>t=reg256#5
# asm 2: vpsubd <b=%ymm5,<t=%ymm4,>t=%ymm4
vpsubd %ymm5,%ymm4,%ymm4

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#5,<_1x8=reg256#1,>d=reg256#6
# asm 2: vpand <t=%ymm4,<_1x8=%ymm0,>d=%ymm5
vpand %ymm4,%ymm0,%ymm5

# qhasm: 8x v0a = t >> 1 
# asm 1: vpsrad $1,<t=reg256#5,>v0a=reg256#7
# asm 2: vpsrad $1,<t=%ymm4,>v0a=%ymm6
vpsrad $1,%ymm4,%ymm6

# qhasm: 8x v0a += d
# asm 1: vpaddd <d=reg256#6,<v0a=reg256#7,>v0a=reg256#6
# asm 2: vpaddd <d=%ymm5,<v0a=%ymm6,>v0a=%ymm5
vpaddd %ymm5,%ymm6,%ymm5

# qhasm: 8x t -= _1x8
# asm 1: vpsubd <_1x8=reg256#1,<t=reg256#5,>t=reg256#5
# asm 2: vpsubd <_1x8=%ymm0,<t=%ymm4,>t=%ymm4
vpsubd %ymm0,%ymm4,%ymm4

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#5,<_1x8=reg256#1,>d=reg256#7
# asm 2: vpand <t=%ymm4,<_1x8=%ymm0,>d=%ymm6
vpand %ymm4,%ymm0,%ymm6

# qhasm: 8x v1a = t >> 1 
# asm 1: vpsrad $1,<t=reg256#5,>v1a=reg256#5
# asm 2: vpsrad $1,<t=%ymm4,>v1a=%ymm4
vpsrad $1,%ymm4,%ymm4

# qhasm: 8x v1a += d
# asm 1: vpaddd <d=reg256#7,<v1a=reg256#5,>v1a=reg256#5
# asm 2: vpaddd <d=%ymm6,<v1a=%ymm4,>v1a=%ymm4
vpaddd %ymm6,%ymm4,%ymm4

# qhasm: 8x d = v0a * qx8
# asm 1: vpmulld <v0a=reg256#6,<qx8=reg256#2,>d=reg256#7
# asm 2: vpmulld <v0a=%ymm5,<qx8=%ymm1,>d=%ymm6
vpmulld %ymm5,%ymm1,%ymm6

# qhasm: 8x d <<= 1
# asm 1: vpslld $1,<d=reg256#7,>d=reg256#7
# asm 2: vpslld $1,<d=%ymm6,>d=%ymm6
vpslld $1,%ymm6,%ymm6

# qhasm: 8x d = v - d
# asm 1: vpsubd <d=reg256#7,<v=reg256#4,>d=reg256#4
# asm 2: vpsubd <d=%ymm6,<v=%ymm3,>d=%ymm3
vpsubd %ymm6,%ymm3,%ymm3

# qhasm: 8x k = abs(d)
# asm 1: vpabsd <d=reg256#4,>k=reg256#4
# asm 2: vpabsd <d=%ymm3,>k=%ymm3
vpabsd %ymm3,%ymm3

# qhasm: v = mem256[input_1 + ctr + 1024]
# asm 1: vmovupd   1024(<input_1=int64#2,<ctr=int64#4),>v=reg256#7
# asm 2: vmovupd   1024(<input_1=%rsi,<ctr=%rcx),>v=%ymm6
vmovupd   1024(%rsi,%rcx),%ymm6

# qhasm: 8x v <<= 3
# asm 1: vpslld $3,<v=reg256#7,>v=reg256#7
# asm 2: vpslld $3,<v=%ymm6,>v=%ymm6
vpslld $3,%ymm6,%ymm6

# qhasm: 8x v += rbit
# asm 1: vpaddd <rbit=reg256#3,<v=reg256#7,>v=reg256#7
# asm 2: vpaddd <rbit=%ymm2,<v=%ymm6,>v=%ymm6
vpaddd %ymm2,%ymm6,%ymm6

# qhasm: 8x b = v * mem256[v2730x8]
# asm 1: vpmulld v2730x8,<v=reg256#7,>b=reg256#8
# asm 2: vpmulld v2730x8,<v=%ymm6,>b=%ymm7
vpmulld v2730x8,%ymm6,%ymm7

# qhasm: 8x t = b >> 25
# asm 1: vpsrad $25,<b=reg256#8,>t=reg256#8
# asm 2: vpsrad $25,<b=%ymm7,>t=%ymm7
vpsrad $25,%ymm7,%ymm7

# qhasm: 8x d = t * qx8
# asm 1: vpmulld <t=reg256#8,<qx8=reg256#2,>d=reg256#9
# asm 2: vpmulld <t=%ymm7,<qx8=%ymm1,>d=%ymm8
vpmulld %ymm7,%ymm1,%ymm8

# qhasm: 8x b = v - d
# asm 1: vpsubd <d=reg256#9,<v=reg256#7,>b=reg256#9
# asm 2: vpsubd <d=%ymm8,<v=%ymm6,>b=%ymm8
vpsubd %ymm8,%ymm6,%ymm8

# qhasm: 8x b += _1x8
# asm 1: vpaddd <_1x8=reg256#1,<b=reg256#9,>b=reg256#9
# asm 2: vpaddd <_1x8=%ymm0,<b=%ymm8,>b=%ymm8
vpaddd %ymm0,%ymm8,%ymm8

# qhasm: 8x b = qx8 - b
# asm 1: vpsubd <b=reg256#9,<qx8=reg256#2,>b=reg256#9
# asm 2: vpsubd <b=%ymm8,<qx8=%ymm1,>b=%ymm8
vpsubd %ymm8,%ymm1,%ymm8

# qhasm: 8x b >>= 31
# asm 1: vpsrad $31,<b=reg256#9,>b=reg256#9
# asm 2: vpsrad $31,<b=%ymm8,>b=%ymm8
vpsrad $31,%ymm8,%ymm8

# qhasm: 8x t -= b
# asm 1: vpsubd <b=reg256#9,<t=reg256#8,>t=reg256#8
# asm 2: vpsubd <b=%ymm8,<t=%ymm7,>t=%ymm7
vpsubd %ymm8,%ymm7,%ymm7

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#8,<_1x8=reg256#1,>d=reg256#9
# asm 2: vpand <t=%ymm7,<_1x8=%ymm0,>d=%ymm8
vpand %ymm7,%ymm0,%ymm8

# qhasm: 8x v0b = t >> 1 
# asm 1: vpsrad $1,<t=reg256#8,>v0b=reg256#10
# asm 2: vpsrad $1,<t=%ymm7,>v0b=%ymm9
vpsrad $1,%ymm7,%ymm9

# qhasm: 8x v0b += d
# asm 1: vpaddd <d=reg256#9,<v0b=reg256#10,>v0b=reg256#9
# asm 2: vpaddd <d=%ymm8,<v0b=%ymm9,>v0b=%ymm8
vpaddd %ymm8,%ymm9,%ymm8

# qhasm: 8x t -= _1x8
# asm 1: vpsubd <_1x8=reg256#1,<t=reg256#8,>t=reg256#8
# asm 2: vpsubd <_1x8=%ymm0,<t=%ymm7,>t=%ymm7
vpsubd %ymm0,%ymm7,%ymm7

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#8,<_1x8=reg256#1,>d=reg256#10
# asm 2: vpand <t=%ymm7,<_1x8=%ymm0,>d=%ymm9
vpand %ymm7,%ymm0,%ymm9

# qhasm: 8x v1b = t >> 1 
# asm 1: vpsrad $1,<t=reg256#8,>v1b=reg256#8
# asm 2: vpsrad $1,<t=%ymm7,>v1b=%ymm7
vpsrad $1,%ymm7,%ymm7

# qhasm: 8x v1b += d
# asm 1: vpaddd <d=reg256#10,<v1b=reg256#8,>v1b=reg256#8
# asm 2: vpaddd <d=%ymm9,<v1b=%ymm7,>v1b=%ymm7
vpaddd %ymm9,%ymm7,%ymm7

# qhasm: 8x d = v0b * qx8
# asm 1: vpmulld <v0b=reg256#9,<qx8=reg256#2,>d=reg256#10
# asm 2: vpmulld <v0b=%ymm8,<qx8=%ymm1,>d=%ymm9
vpmulld %ymm8,%ymm1,%ymm9

# qhasm: 8x d <<= 1
# asm 1: vpslld $1,<d=reg256#10,>d=reg256#10
# asm 2: vpslld $1,<d=%ymm9,>d=%ymm9
vpslld $1,%ymm9,%ymm9

# qhasm: 8x d = v - d
# asm 1: vpsubd <d=reg256#10,<v=reg256#7,>d=reg256#7
# asm 2: vpsubd <d=%ymm9,<v=%ymm6,>d=%ymm6
vpsubd %ymm9,%ymm6,%ymm6

# qhasm: 8x v = abs(d)
# asm 1: vpabsd <d=reg256#7,>v=reg256#7
# asm 2: vpabsd <d=%ymm6,>v=%ymm6
vpabsd %ymm6,%ymm6

# qhasm: 8x k += v
# asm 1: vpaddd <v=reg256#7,<k=reg256#4,>k=reg256#4
# asm 2: vpaddd <v=%ymm6,<k=%ymm3,>k=%ymm3
vpaddd %ymm6,%ymm3,%ymm3

# qhasm: v = mem256[input_1 + ctr + 2048]
# asm 1: vmovupd   2048(<input_1=int64#2,<ctr=int64#4),>v=reg256#7
# asm 2: vmovupd   2048(<input_1=%rsi,<ctr=%rcx),>v=%ymm6
vmovupd   2048(%rsi,%rcx),%ymm6

# qhasm: 8x v <<= 3
# asm 1: vpslld $3,<v=reg256#7,>v=reg256#7
# asm 2: vpslld $3,<v=%ymm6,>v=%ymm6
vpslld $3,%ymm6,%ymm6

# qhasm: 8x v += rbit
# asm 1: vpaddd <rbit=reg256#3,<v=reg256#7,>v=reg256#7
# asm 2: vpaddd <rbit=%ymm2,<v=%ymm6,>v=%ymm6
vpaddd %ymm2,%ymm6,%ymm6

# qhasm: 8x b = v * mem256[v2730x8]
# asm 1: vpmulld v2730x8,<v=reg256#7,>b=reg256#10
# asm 2: vpmulld v2730x8,<v=%ymm6,>b=%ymm9
vpmulld v2730x8,%ymm6,%ymm9

# qhasm: 8x t = b >> 25
# asm 1: vpsrad $25,<b=reg256#10,>t=reg256#10
# asm 2: vpsrad $25,<b=%ymm9,>t=%ymm9
vpsrad $25,%ymm9,%ymm9

# qhasm: 8x d = t * qx8
# asm 1: vpmulld <t=reg256#10,<qx8=reg256#2,>d=reg256#11
# asm 2: vpmulld <t=%ymm9,<qx8=%ymm1,>d=%ymm10
vpmulld %ymm9,%ymm1,%ymm10

# qhasm: 8x b = v - d
# asm 1: vpsubd <d=reg256#11,<v=reg256#7,>b=reg256#11
# asm 2: vpsubd <d=%ymm10,<v=%ymm6,>b=%ymm10
vpsubd %ymm10,%ymm6,%ymm10

# qhasm: 8x b += _1x8
# asm 1: vpaddd <_1x8=reg256#1,<b=reg256#11,>b=reg256#11
# asm 2: vpaddd <_1x8=%ymm0,<b=%ymm10,>b=%ymm10
vpaddd %ymm0,%ymm10,%ymm10

# qhasm: 8x b = qx8 - b
# asm 1: vpsubd <b=reg256#11,<qx8=reg256#2,>b=reg256#11
# asm 2: vpsubd <b=%ymm10,<qx8=%ymm1,>b=%ymm10
vpsubd %ymm10,%ymm1,%ymm10

# qhasm: 8x b >>= 31
# asm 1: vpsrad $31,<b=reg256#11,>b=reg256#11
# asm 2: vpsrad $31,<b=%ymm10,>b=%ymm10
vpsrad $31,%ymm10,%ymm10

# qhasm: 8x t -= b
# asm 1: vpsubd <b=reg256#11,<t=reg256#10,>t=reg256#10
# asm 2: vpsubd <b=%ymm10,<t=%ymm9,>t=%ymm9
vpsubd %ymm10,%ymm9,%ymm9

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#10,<_1x8=reg256#1,>d=reg256#11
# asm 2: vpand <t=%ymm9,<_1x8=%ymm0,>d=%ymm10
vpand %ymm9,%ymm0,%ymm10

# qhasm: 8x v0c = t >> 1 
# asm 1: vpsrad $1,<t=reg256#10,>v0c=reg256#12
# asm 2: vpsrad $1,<t=%ymm9,>v0c=%ymm11
vpsrad $1,%ymm9,%ymm11

# qhasm: 8x v0c += d
# asm 1: vpaddd <d=reg256#11,<v0c=reg256#12,>v0c=reg256#11
# asm 2: vpaddd <d=%ymm10,<v0c=%ymm11,>v0c=%ymm10
vpaddd %ymm10,%ymm11,%ymm10

# qhasm: 8x t -= _1x8
# asm 1: vpsubd <_1x8=reg256#1,<t=reg256#10,>t=reg256#10
# asm 2: vpsubd <_1x8=%ymm0,<t=%ymm9,>t=%ymm9
vpsubd %ymm0,%ymm9,%ymm9

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#10,<_1x8=reg256#1,>d=reg256#12
# asm 2: vpand <t=%ymm9,<_1x8=%ymm0,>d=%ymm11
vpand %ymm9,%ymm0,%ymm11

# qhasm: 8x v1c = t >> 1 
# asm 1: vpsrad $1,<t=reg256#10,>v1c=reg256#10
# asm 2: vpsrad $1,<t=%ymm9,>v1c=%ymm9
vpsrad $1,%ymm9,%ymm9

# qhasm: 8x v1c += d
# asm 1: vpaddd <d=reg256#12,<v1c=reg256#10,>v1c=reg256#10
# asm 2: vpaddd <d=%ymm11,<v1c=%ymm9,>v1c=%ymm9
vpaddd %ymm11,%ymm9,%ymm9

# qhasm: 8x d = v0c * qx8
# asm 1: vpmulld <v0c=reg256#11,<qx8=reg256#2,>d=reg256#12
# asm 2: vpmulld <v0c=%ymm10,<qx8=%ymm1,>d=%ymm11
vpmulld %ymm10,%ymm1,%ymm11

# qhasm: 8x d <<= 1
# asm 1: vpslld $1,<d=reg256#12,>d=reg256#12
# asm 2: vpslld $1,<d=%ymm11,>d=%ymm11
vpslld $1,%ymm11,%ymm11

# qhasm: 8x d = v - d
# asm 1: vpsubd <d=reg256#12,<v=reg256#7,>d=reg256#7
# asm 2: vpsubd <d=%ymm11,<v=%ymm6,>d=%ymm6
vpsubd %ymm11,%ymm6,%ymm6

# qhasm: 8x v = abs(d)
# asm 1: vpabsd <d=reg256#7,>v=reg256#7
# asm 2: vpabsd <d=%ymm6,>v=%ymm6
vpabsd %ymm6,%ymm6

# qhasm: 8x k += v
# asm 1: vpaddd <v=reg256#7,<k=reg256#4,>k=reg256#4
# asm 2: vpaddd <v=%ymm6,<k=%ymm3,>k=%ymm3
vpaddd %ymm6,%ymm3,%ymm3

# qhasm: v = mem256[input_1 + ctr + 3072]
# asm 1: vmovupd   3072(<input_1=int64#2,<ctr=int64#4),>v=reg256#7
# asm 2: vmovupd   3072(<input_1=%rsi,<ctr=%rcx),>v=%ymm6
vmovupd   3072(%rsi,%rcx),%ymm6

# qhasm: 8x v <<= 3
# asm 1: vpslld $3,<v=reg256#7,>v=reg256#7
# asm 2: vpslld $3,<v=%ymm6,>v=%ymm6
vpslld $3,%ymm6,%ymm6

# qhasm: 8x v += rbit
# asm 1: vpaddd <rbit=reg256#3,<v=reg256#7,>v=reg256#3
# asm 2: vpaddd <rbit=%ymm2,<v=%ymm6,>v=%ymm2
vpaddd %ymm2,%ymm6,%ymm2

# qhasm: 8x b = v * mem256[v2730x8]
# asm 1: vpmulld v2730x8,<v=reg256#3,>b=reg256#7
# asm 2: vpmulld v2730x8,<v=%ymm2,>b=%ymm6
vpmulld v2730x8,%ymm2,%ymm6

# qhasm: 8x t = b >> 25
# asm 1: vpsrad $25,<b=reg256#7,>t=reg256#7
# asm 2: vpsrad $25,<b=%ymm6,>t=%ymm6
vpsrad $25,%ymm6,%ymm6

# qhasm: 8x d = t * qx8
# asm 1: vpmulld <t=reg256#7,<qx8=reg256#2,>d=reg256#12
# asm 2: vpmulld <t=%ymm6,<qx8=%ymm1,>d=%ymm11
vpmulld %ymm6,%ymm1,%ymm11

# qhasm: 8x b = v - d
# asm 1: vpsubd <d=reg256#12,<v=reg256#3,>b=reg256#12
# asm 2: vpsubd <d=%ymm11,<v=%ymm2,>b=%ymm11
vpsubd %ymm11,%ymm2,%ymm11

# qhasm: 8x b += _1x8
# asm 1: vpaddd <_1x8=reg256#1,<b=reg256#12,>b=reg256#12
# asm 2: vpaddd <_1x8=%ymm0,<b=%ymm11,>b=%ymm11
vpaddd %ymm0,%ymm11,%ymm11

# qhasm: 8x b = qx8 - b
# asm 1: vpsubd <b=reg256#12,<qx8=reg256#2,>b=reg256#12
# asm 2: vpsubd <b=%ymm11,<qx8=%ymm1,>b=%ymm11
vpsubd %ymm11,%ymm1,%ymm11

# qhasm: 8x b >>= 31
# asm 1: vpsrad $31,<b=reg256#12,>b=reg256#12
# asm 2: vpsrad $31,<b=%ymm11,>b=%ymm11
vpsrad $31,%ymm11,%ymm11

# qhasm: 8x t -= b
# asm 1: vpsubd <b=reg256#12,<t=reg256#7,>t=reg256#7
# asm 2: vpsubd <b=%ymm11,<t=%ymm6,>t=%ymm6
vpsubd %ymm11,%ymm6,%ymm6

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#7,<_1x8=reg256#1,>d=reg256#12
# asm 2: vpand <t=%ymm6,<_1x8=%ymm0,>d=%ymm11
vpand %ymm6,%ymm0,%ymm11

# qhasm: 8x v0d = t >> 1 
# asm 1: vpsrad $1,<t=reg256#7,>v0d=reg256#13
# asm 2: vpsrad $1,<t=%ymm6,>v0d=%ymm12
vpsrad $1,%ymm6,%ymm12

# qhasm: 8x v0d += d
# asm 1: vpaddd <d=reg256#12,<v0d=reg256#13,>v0d=reg256#12
# asm 2: vpaddd <d=%ymm11,<v0d=%ymm12,>v0d=%ymm11
vpaddd %ymm11,%ymm12,%ymm11

# qhasm: 8x t -= _1x8
# asm 1: vpsubd <_1x8=reg256#1,<t=reg256#7,>t=reg256#7
# asm 2: vpsubd <_1x8=%ymm0,<t=%ymm6,>t=%ymm6
vpsubd %ymm0,%ymm6,%ymm6

# qhasm:    d = t & _1x8
# asm 1: vpand <t=reg256#7,<_1x8=reg256#1,>d=reg256#13
# asm 2: vpand <t=%ymm6,<_1x8=%ymm0,>d=%ymm12
vpand %ymm6,%ymm0,%ymm12

# qhasm: 8x v1d = t >> 1 
# asm 1: vpsrad $1,<t=reg256#7,>v1d=reg256#7
# asm 2: vpsrad $1,<t=%ymm6,>v1d=%ymm6
vpsrad $1,%ymm6,%ymm6

# qhasm: 8x v1d += d
# asm 1: vpaddd <d=reg256#13,<v1d=reg256#7,>v1d=reg256#7
# asm 2: vpaddd <d=%ymm12,<v1d=%ymm6,>v1d=%ymm6
vpaddd %ymm12,%ymm6,%ymm6

# qhasm: 8x d = v0d * qx8
# asm 1: vpmulld <v0d=reg256#12,<qx8=reg256#2,>d=reg256#13
# asm 2: vpmulld <v0d=%ymm11,<qx8=%ymm1,>d=%ymm12
vpmulld %ymm11,%ymm1,%ymm12

# qhasm: 8x d <<= 1
# asm 1: vpslld $1,<d=reg256#13,>d=reg256#13
# asm 2: vpslld $1,<d=%ymm12,>d=%ymm12
vpslld $1,%ymm12,%ymm12

# qhasm: 8x d = v - d
# asm 1: vpsubd <d=reg256#13,<v=reg256#3,>d=reg256#3
# asm 2: vpsubd <d=%ymm12,<v=%ymm2,>d=%ymm2
vpsubd %ymm12,%ymm2,%ymm2

# qhasm: 8x v = abs(d)
# asm 1: vpabsd <d=reg256#3,>v=reg256#3
# asm 2: vpabsd <d=%ymm2,>v=%ymm2
vpabsd %ymm2,%ymm2

# qhasm: 8x k += v
# asm 1: vpaddd <v=reg256#3,<k=reg256#4,>k=reg256#3
# asm 2: vpaddd <v=%ymm2,<k=%ymm3,>k=%ymm2
vpaddd %ymm2,%ymm3,%ymm2

# qhasm: 8x d = qx8 << 1
# asm 1: vpslld $1,<qx8=reg256#2,>d=reg256#4
# asm 2: vpslld $1,<qx8=%ymm1,>d=%ymm3
vpslld $1,%ymm1,%ymm3

# qhasm: 8x d -= _1x8
# asm 1: vpsubd <_1x8=reg256#1,<d=reg256#4,>d=reg256#4
# asm 2: vpsubd <_1x8=%ymm0,<d=%ymm3,>d=%ymm3
vpsubd %ymm0,%ymm3,%ymm3

# qhasm: 8x k = d - k 
# asm 1: vpsubd <k=reg256#3,<d=reg256#4,>k=reg256#3
# asm 2: vpsubd <k=%ymm2,<d=%ymm3,>k=%ymm2
vpsubd %ymm2,%ymm3,%ymm2

# qhasm: 8x k >>= 31
# asm 1: vpsrad $31,<k=reg256#3,>k=reg256#3
# asm 2: vpsrad $31,<k=%ymm2,>k=%ymm2
vpsrad $31,%ymm2,%ymm2

# qhasm: vtmp0 = v0a ^ v1a
# asm 1: vpxor <v0a=reg256#6,<v1a=reg256#5,>vtmp0=reg256#4
# asm 2: vpxor <v0a=%ymm5,<v1a=%ymm4,>vtmp0=%ymm3
vpxor %ymm5,%ymm4,%ymm3

# qhasm: vtmp0 &= k
# asm 1: vpand <k=reg256#3,<vtmp0=reg256#4,<vtmp0=reg256#4
# asm 2: vpand <k=%ymm2,<vtmp0=%ymm3,<vtmp0=%ymm3
vpand %ymm2,%ymm3,%ymm3

# qhasm: vtmp0 ^= v0a
# asm 1: vpxor <v0a=reg256#6,<vtmp0=reg256#4,<vtmp0=reg256#4
# asm 2: vpxor <v0a=%ymm5,<vtmp0=%ymm3,<vtmp0=%ymm3
vpxor %ymm5,%ymm3,%ymm3

# qhasm: vtmp1 = v0b ^ v1b
# asm 1: vpxor <v0b=reg256#9,<v1b=reg256#8,>vtmp1=reg256#5
# asm 2: vpxor <v0b=%ymm8,<v1b=%ymm7,>vtmp1=%ymm4
vpxor %ymm8,%ymm7,%ymm4

# qhasm: vtmp1 &= k
# asm 1: vpand <k=reg256#3,<vtmp1=reg256#5,<vtmp1=reg256#5
# asm 2: vpand <k=%ymm2,<vtmp1=%ymm4,<vtmp1=%ymm4
vpand %ymm2,%ymm4,%ymm4

# qhasm: vtmp1 ^= v0b
# asm 1: vpxor <v0b=reg256#9,<vtmp1=reg256#5,<vtmp1=reg256#5
# asm 2: vpxor <v0b=%ymm8,<vtmp1=%ymm4,<vtmp1=%ymm4
vpxor %ymm8,%ymm4,%ymm4

# qhasm: vtmp2 = v0c ^ v1c
# asm 1: vpxor <v0c=reg256#11,<v1c=reg256#10,>vtmp2=reg256#6
# asm 2: vpxor <v0c=%ymm10,<v1c=%ymm9,>vtmp2=%ymm5
vpxor %ymm10,%ymm9,%ymm5

# qhasm: vtmp2 &= k
# asm 1: vpand <k=reg256#3,<vtmp2=reg256#6,<vtmp2=reg256#6
# asm 2: vpand <k=%ymm2,<vtmp2=%ymm5,<vtmp2=%ymm5
vpand %ymm2,%ymm5,%ymm5

# qhasm: vtmp2 ^= v0c
# asm 1: vpxor <v0c=reg256#11,<vtmp2=reg256#6,<vtmp2=reg256#6
# asm 2: vpxor <v0c=%ymm10,<vtmp2=%ymm5,<vtmp2=%ymm5
vpxor %ymm10,%ymm5,%ymm5

# qhasm: vtmp3 = v0d ^ v1d
# asm 1: vpxor <v0d=reg256#12,<v1d=reg256#7,>vtmp3=reg256#7
# asm 2: vpxor <v0d=%ymm11,<v1d=%ymm6,>vtmp3=%ymm6
vpxor %ymm11,%ymm6,%ymm6

# qhasm: vtmp3 &= k
# asm 1: vpand <k=reg256#3,<vtmp3=reg256#7,<vtmp3=reg256#7
# asm 2: vpand <k=%ymm2,<vtmp3=%ymm6,<vtmp3=%ymm6
vpand %ymm2,%ymm6,%ymm6

# qhasm: vtmp3 ^= v0d
# asm 1: vpxor <v0d=reg256#12,<vtmp3=reg256#7,<vtmp3=reg256#7
# asm 2: vpxor <v0d=%ymm11,<vtmp3=%ymm6,<vtmp3=%ymm6
vpxor %ymm11,%ymm6,%ymm6

# qhasm: _3x8 = mem256[v3x8]
# asm 1: vmovdqu v3x8,>_3x8=reg256#8
# asm 2: vmovdqu v3x8,>_3x8=%ymm7
vmovdqu v3x8,%ymm7

# qhasm: 8x c = vtmp0 - vtmp3
# asm 1: vpsubd <vtmp3=reg256#7,<vtmp0=reg256#4,>c=reg256#4
# asm 2: vpsubd <vtmp3=%ymm6,<vtmp0=%ymm3,>c=%ymm3
vpsubd %ymm6,%ymm3,%ymm3

# qhasm:    c &= _3x8
# asm 1: vpand <_3x8=reg256#8,<c=reg256#4,<c=reg256#4
# asm 2: vpand <_3x8=%ymm7,<c=%ymm3,<c=%ymm3
vpand %ymm7,%ymm3,%ymm3

# qhasm: mem256[input_0 + ctr + 0] = c
# asm 1: vmovupd   <c=reg256#4,0(<input_0=int64#1,<ctr=int64#4)
# asm 2: vmovupd   <c=%ymm3,0(<input_0=%rdi,<ctr=%rcx)
vmovupd   %ymm3,0(%rdi,%rcx)

# qhasm: 8x c = vtmp1 - vtmp3
# asm 1: vpsubd <vtmp3=reg256#7,<vtmp1=reg256#5,>c=reg256#4
# asm 2: vpsubd <vtmp3=%ymm6,<vtmp1=%ymm4,>c=%ymm3
vpsubd %ymm6,%ymm4,%ymm3

# qhasm:    c &= _3x8
# asm 1: vpand <_3x8=reg256#8,<c=reg256#4,<c=reg256#4
# asm 2: vpand <_3x8=%ymm7,<c=%ymm3,<c=%ymm3
vpand %ymm7,%ymm3,%ymm3

# qhasm: mem256[input_0 + ctr + 1024] = c
# asm 1: vmovupd   <c=reg256#4,1024(<input_0=int64#1,<ctr=int64#4)
# asm 2: vmovupd   <c=%ymm3,1024(<input_0=%rdi,<ctr=%rcx)
vmovupd   %ymm3,1024(%rdi,%rcx)

# qhasm: 8x c = vtmp2 - vtmp3
# asm 1: vpsubd <vtmp3=reg256#7,<vtmp2=reg256#6,>c=reg256#4
# asm 2: vpsubd <vtmp3=%ymm6,<vtmp2=%ymm5,>c=%ymm3
vpsubd %ymm6,%ymm5,%ymm3

# qhasm:    c &= _3x8
# asm 1: vpand <_3x8=reg256#8,<c=reg256#4,<c=reg256#4
# asm 2: vpand <_3x8=%ymm7,<c=%ymm3,<c=%ymm3
vpand %ymm7,%ymm3,%ymm3

# qhasm: mem256[input_0 + ctr + 2048] = c
# asm 1: vmovupd   <c=reg256#4,2048(<input_0=int64#1,<ctr=int64#4)
# asm 2: vmovupd   <c=%ymm3,2048(<input_0=%rdi,<ctr=%rcx)
vmovupd   %ymm3,2048(%rdi,%rcx)

# qhasm: 8x c = vtmp3 << 1
# asm 1: vpslld $1,<vtmp3=reg256#7,>c=reg256#4
# asm 2: vpslld $1,<vtmp3=%ymm6,>c=%ymm3
vpslld $1,%ymm6,%ymm3

# qhasm: 8x c -= k
# asm 1: vpsubd <k=reg256#3,<c=reg256#4,>c=reg256#3
# asm 2: vpsubd <k=%ymm2,<c=%ymm3,>c=%ymm2
vpsubd %ymm2,%ymm3,%ymm2

# qhasm:    c &= _3x8
# asm 1: vpand <_3x8=reg256#8,<c=reg256#3,<c=reg256#3
# asm 2: vpand <_3x8=%ymm7,<c=%ymm2,<c=%ymm2
vpand %ymm7,%ymm2,%ymm2

# qhasm: mem256[input_0 + ctr + 3072] = c
# asm 1: vmovupd   <c=reg256#3,3072(<input_0=int64#1,<ctr=int64#4)
# asm 2: vmovupd   <c=%ymm2,3072(<input_0=%rdi,<ctr=%rcx)
vmovupd   %ymm2,3072(%rdi,%rcx)

# qhasm: (uint64) ctr >>= 5
# asm 1: shr  $5,<ctr=int64#4
# asm 2: shr  $5,<ctr=%rcx
shr  $5,%rcx

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
