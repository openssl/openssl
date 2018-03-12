
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

# qhasm: int64 ctri

# qhasm: int64 rp

# qhasm: int64 ap

# qhasm: int64 bp

# qhasm: reg256 r

# qhasm: reg256 a

# qhasm: reg256 b

# qhasm: reg256 q

# qhasm: reg256 qinv

# qhasm: reg256 c

# qhasm: enter poly_pointwise
.p2align 5
.global _poly_pointwise
.global poly_pointwise
_poly_pointwise:
poly_pointwise:
mov %rsp,%r11
and $31,%r11
add $0,%r11
sub %r11,%rsp

# qhasm: rp = input_0
# asm 1: mov  <input_0=int64#1,>rp=int64#1
# asm 2: mov  <input_0=%rdi,>rp=%rdi
mov  %rdi,%rdi

# qhasm: ap = input_1
# asm 1: mov  <input_1=int64#2,>ap=int64#2
# asm 2: mov  <input_1=%rsi,>ap=%rsi
mov  %rsi,%rsi

# qhasm: bp = input_2
# asm 1: mov  <input_2=int64#3,>bp=int64#3
# asm 2: mov  <input_2=%rdx,>bp=%rdx
mov  %rdx,%rdx

# qhasm: q = mem256[q8]
# asm 1: vmovdqu q8,>q=reg256#1
# asm 2: vmovdqu q8,>q=%ymm0
vmovdqu q8,%ymm0

# qhasm: qinv = mem256[qinv16]
# asm 1: vmovdqu qinv16,>qinv=reg256#2
# asm 2: vmovdqu qinv16,>qinv=%ymm1
vmovdqu qinv16,%ymm1

# qhasm: ctri = 256
# asm 1: mov  $256,>ctri=int64#4
# asm 2: mov  $256,>ctri=%rcx
mov  $256,%rcx

# qhasm: loopi:
._loopi:

# qhasm: a = (4x double)(4x int32)mem128[ap + 0]
# asm 1: vcvtdq2pd 0(<ap=int64#2),>a=reg256#3
# asm 2: vcvtdq2pd 0(<ap=%rsi),>a=%ymm2
vcvtdq2pd 0(%rsi),%ymm2

# qhasm: b = (4x double)(4x int32)mem128[bp + 0]
# asm 1: vcvtdq2pd 0(<bp=int64#3),>b=reg256#4
# asm 2: vcvtdq2pd 0(<bp=%rdx),>b=%ymm3
vcvtdq2pd 0(%rdx),%ymm3

# qhasm: 4x a approx*= b
# asm 1: vmulpd <b=reg256#4,<a=reg256#3,>a=reg256#3
# asm 2: vmulpd <b=%ymm3,<a=%ymm2,>a=%ymm2
vmulpd %ymm3,%ymm2,%ymm2

# qhasm: 4x c = approx a * qinv
# asm 1: vmulpd <a=reg256#3,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <a=%ymm2,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm2,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x a approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<a=reg256#3
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<a=%ymm2
vfnmadd231pd %ymm3,%ymm0,%ymm2

# qhasm: a = (4x int32)(4x double)a,0,0,0,0
# asm 1: vcvtpd2dq <a=reg256#3,>a=reg256#3dq
# asm 2: vcvtpd2dq <a=%ymm2,>a=%xmm2
vcvtpd2dq %ymm2,%xmm2

# qhasm: mem128[rp + 0] = a
# asm 1: vmovupd <a=reg256#3dq,0(<rp=int64#1)
# asm 2: vmovupd <a=%xmm2,0(<rp=%rdi)
vmovupd %xmm2,0(%rdi)

# qhasm: a = (4x double)(4x int32)mem128[ap + 16]
# asm 1: vcvtdq2pd 16(<ap=int64#2),>a=reg256#3
# asm 2: vcvtdq2pd 16(<ap=%rsi),>a=%ymm2
vcvtdq2pd 16(%rsi),%ymm2

# qhasm: b = (4x double)(4x int32)mem128[bp + 16]
# asm 1: vcvtdq2pd 16(<bp=int64#3),>b=reg256#4
# asm 2: vcvtdq2pd 16(<bp=%rdx),>b=%ymm3
vcvtdq2pd 16(%rdx),%ymm3

# qhasm: 4x a approx*= b
# asm 1: vmulpd <b=reg256#4,<a=reg256#3,>a=reg256#3
# asm 2: vmulpd <b=%ymm3,<a=%ymm2,>a=%ymm2
vmulpd %ymm3,%ymm2,%ymm2

# qhasm: 4x c = approx a * qinv
# asm 1: vmulpd <a=reg256#3,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <a=%ymm2,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm2,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x a approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<a=reg256#3
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<a=%ymm2
vfnmadd231pd %ymm3,%ymm0,%ymm2

# qhasm: a = (4x int32)(4x double)a,0,0,0,0
# asm 1: vcvtpd2dq <a=reg256#3,>a=reg256#3dq
# asm 2: vcvtpd2dq <a=%ymm2,>a=%xmm2
vcvtpd2dq %ymm2,%xmm2

# qhasm: mem128[rp + 16] = a
# asm 1: vmovupd <a=reg256#3dq,16(<rp=int64#1)
# asm 2: vmovupd <a=%xmm2,16(<rp=%rdi)
vmovupd %xmm2,16(%rdi)

# qhasm: a = (4x double)(4x int32)mem128[ap + 32]
# asm 1: vcvtdq2pd 32(<ap=int64#2),>a=reg256#3
# asm 2: vcvtdq2pd 32(<ap=%rsi),>a=%ymm2
vcvtdq2pd 32(%rsi),%ymm2

# qhasm: b = (4x double)(4x int32)mem128[bp + 32]
# asm 1: vcvtdq2pd 32(<bp=int64#3),>b=reg256#4
# asm 2: vcvtdq2pd 32(<bp=%rdx),>b=%ymm3
vcvtdq2pd 32(%rdx),%ymm3

# qhasm: 4x a approx*= b
# asm 1: vmulpd <b=reg256#4,<a=reg256#3,>a=reg256#3
# asm 2: vmulpd <b=%ymm3,<a=%ymm2,>a=%ymm2
vmulpd %ymm3,%ymm2,%ymm2

# qhasm: 4x c = approx a * qinv
# asm 1: vmulpd <a=reg256#3,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <a=%ymm2,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm2,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x a approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<a=reg256#3
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<a=%ymm2
vfnmadd231pd %ymm3,%ymm0,%ymm2

# qhasm: a = (4x int32)(4x double)a,0,0,0,0
# asm 1: vcvtpd2dq <a=reg256#3,>a=reg256#3dq
# asm 2: vcvtpd2dq <a=%ymm2,>a=%xmm2
vcvtpd2dq %ymm2,%xmm2

# qhasm: mem128[rp + 32] = a
# asm 1: vmovupd <a=reg256#3dq,32(<rp=int64#1)
# asm 2: vmovupd <a=%xmm2,32(<rp=%rdi)
vmovupd %xmm2,32(%rdi)

# qhasm: a = (4x double)(4x int32)mem128[ap + 48]
# asm 1: vcvtdq2pd 48(<ap=int64#2),>a=reg256#3
# asm 2: vcvtdq2pd 48(<ap=%rsi),>a=%ymm2
vcvtdq2pd 48(%rsi),%ymm2

# qhasm: b = (4x double)(4x int32)mem128[bp + 48]
# asm 1: vcvtdq2pd 48(<bp=int64#3),>b=reg256#4
# asm 2: vcvtdq2pd 48(<bp=%rdx),>b=%ymm3
vcvtdq2pd 48(%rdx),%ymm3

# qhasm: 4x a approx*= b
# asm 1: vmulpd <b=reg256#4,<a=reg256#3,>a=reg256#3
# asm 2: vmulpd <b=%ymm3,<a=%ymm2,>a=%ymm2
vmulpd %ymm3,%ymm2,%ymm2

# qhasm: 4x c = approx a * qinv
# asm 1: vmulpd <a=reg256#3,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <a=%ymm2,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm2,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x a approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<a=reg256#3
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<a=%ymm2
vfnmadd231pd %ymm3,%ymm0,%ymm2

# qhasm: a = (4x int32)(4x double)a,0,0,0,0
# asm 1: vcvtpd2dq <a=reg256#3,>a=reg256#3dq
# asm 2: vcvtpd2dq <a=%ymm2,>a=%xmm2
vcvtpd2dq %ymm2,%xmm2

# qhasm: mem128[rp + 48] = a
# asm 1: vmovupd <a=reg256#3dq,48(<rp=int64#1)
# asm 2: vmovupd <a=%xmm2,48(<rp=%rdi)
vmovupd %xmm2,48(%rdi)

# qhasm: rp += 64
# asm 1: add  $64,<rp=int64#1
# asm 2: add  $64,<rp=%rdi
add  $64,%rdi

# qhasm: ap += 64
# asm 1: add  $64,<ap=int64#2
# asm 2: add  $64,<ap=%rsi
add  $64,%rsi

# qhasm: bp += 64
# asm 1: add  $64,<bp=int64#3
# asm 2: add  $64,<bp=%rdx
add  $64,%rdx

# qhasm: unsigned>? ctri -= 4
# asm 1: sub  $4,<ctri=int64#4
# asm 2: sub  $4,<ctri=%rcx
sub  $4,%rcx
# comment:fp stack unchanged by jump

# qhasm: goto loopi if unsigned>
ja ._loopi

# qhasm: return
add %r11,%rsp
ret
