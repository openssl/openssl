
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

# qhasm: reg256 r

# qhasm: reg256 r2

# qhasm: reg256 a0

# qhasm: reg256 b0

# qhasm: reg256 a1

# qhasm: reg256 b1

# qhasm: reg256 t

# qhasm: reg256 l

# qhasm: reg256 h

# qhasm: reg256 _mask1

# qhasm: reg256 _maskffff

# qhasm: reg256 _maskff

# qhasm: reg256 _q8x

# qhasm: int64 ctr

# qhasm: enter cbd
.p2align 5
.global _cbd
.global cbd
_cbd:
cbd:
mov %rsp,%r11
and $31,%r11
add $0,%r11
sub %r11,%rsp

# qhasm: _mask1 = mem256[mask1]
# asm 1: vmovdqu mask1,>_mask1=reg256#1
# asm 2: vmovdqu mask1,>_mask1=%ymm0
vmovdqu mask1,%ymm0

# qhasm: _maskffff = mem256[maskffff]
# asm 1: vmovdqu maskffff,>_maskffff=reg256#2
# asm 2: vmovdqu maskffff,>_maskffff=%ymm1
vmovdqu maskffff,%ymm1

# qhasm: _maskff = mem256[maskff]
# asm 1: vmovdqu maskff,>_maskff=reg256#3
# asm 2: vmovdqu maskff,>_maskff=%ymm2
vmovdqu maskff,%ymm2

# qhasm: _q8x  = mem256[q8x]
# asm 1: vmovdqu q8x,>_q8x=reg256#4
# asm 2: vmovdqu q8x,>_q8x=%ymm3
vmovdqu q8x,%ymm3

# qhasm: ctr = 128
# asm 1: mov  $128,>ctr=int64#3
# asm 2: mov  $128,>ctr=%rdx
mov  $128,%rdx

# qhasm: looptop:
._looptop:

# qhasm:   r  = mem256[input_1 + 0]
# asm 1: vmovupd   0(<input_1=int64#2),>r=reg256#5
# asm 2: vmovupd   0(<input_1=%rsi),>r=%ymm4
vmovupd   0(%rsi),%ymm4

# qhasm:   a0 = r & _mask1
# asm 1: vpand <r=reg256#5,<_mask1=reg256#1,>a0=reg256#6
# asm 2: vpand <r=%ymm4,<_mask1=%ymm0,>a0=%ymm5
vpand %ymm4,%ymm0,%ymm5

# qhasm:   16x r unsigned>>= 1
# asm 1: vpsrlw $1,<r=reg256#5,>r=reg256#5
# asm 2: vpsrlw $1,<r=%ymm4,>r=%ymm4
vpsrlw $1,%ymm4,%ymm4

# qhasm:   t = r & _mask1
# asm 1: vpand <r=reg256#5,<_mask1=reg256#1,>t=reg256#7
# asm 2: vpand <r=%ymm4,<_mask1=%ymm0,>t=%ymm6
vpand %ymm4,%ymm0,%ymm6

# qhasm:   16x a0 += t
# asm 1: vpaddw <t=reg256#7,<a0=reg256#6,>a0=reg256#6
# asm 2: vpaddw <t=%ymm6,<a0=%ymm5,>a0=%ymm5
vpaddw %ymm6,%ymm5,%ymm5

# qhasm:   16x r unsigned>>= 1
# asm 1: vpsrlw $1,<r=reg256#5,>r=reg256#5
# asm 2: vpsrlw $1,<r=%ymm4,>r=%ymm4
vpsrlw $1,%ymm4,%ymm4

# qhasm:   t = r & _mask1
# asm 1: vpand <r=reg256#5,<_mask1=reg256#1,>t=reg256#7
# asm 2: vpand <r=%ymm4,<_mask1=%ymm0,>t=%ymm6
vpand %ymm4,%ymm0,%ymm6

# qhasm:   16x a0 += t
# asm 1: vpaddw <t=reg256#7,<a0=reg256#6,>a0=reg256#6
# asm 2: vpaddw <t=%ymm6,<a0=%ymm5,>a0=%ymm5
vpaddw %ymm6,%ymm5,%ymm5

# qhasm:   16x r unsigned>>= 1
# asm 1: vpsrlw $1,<r=reg256#5,>r=reg256#5
# asm 2: vpsrlw $1,<r=%ymm4,>r=%ymm4
vpsrlw $1,%ymm4,%ymm4

# qhasm:   t = r & _mask1
# asm 1: vpand <r=reg256#5,<_mask1=reg256#1,>t=reg256#7
# asm 2: vpand <r=%ymm4,<_mask1=%ymm0,>t=%ymm6
vpand %ymm4,%ymm0,%ymm6

# qhasm:   16x a0 += t
# asm 1: vpaddw <t=reg256#7,<a0=reg256#6,>a0=reg256#6
# asm 2: vpaddw <t=%ymm6,<a0=%ymm5,>a0=%ymm5
vpaddw %ymm6,%ymm5,%ymm5

# qhasm:   16x r unsigned>>= 1
# asm 1: vpsrlw $1,<r=reg256#5,>r=reg256#5
# asm 2: vpsrlw $1,<r=%ymm4,>r=%ymm4
vpsrlw $1,%ymm4,%ymm4

# qhasm:   t = r & _mask1
# asm 1: vpand <r=reg256#5,<_mask1=reg256#1,>t=reg256#7
# asm 2: vpand <r=%ymm4,<_mask1=%ymm0,>t=%ymm6
vpand %ymm4,%ymm0,%ymm6

# qhasm:   16x a0 += t
# asm 1: vpaddw <t=reg256#7,<a0=reg256#6,>a0=reg256#6
# asm 2: vpaddw <t=%ymm6,<a0=%ymm5,>a0=%ymm5
vpaddw %ymm6,%ymm5,%ymm5

# qhasm:   16x r unsigned>>= 1
# asm 1: vpsrlw $1,<r=reg256#5,>r=reg256#5
# asm 2: vpsrlw $1,<r=%ymm4,>r=%ymm4
vpsrlw $1,%ymm4,%ymm4

# qhasm:   t = r & _mask1
# asm 1: vpand <r=reg256#5,<_mask1=reg256#1,>t=reg256#7
# asm 2: vpand <r=%ymm4,<_mask1=%ymm0,>t=%ymm6
vpand %ymm4,%ymm0,%ymm6

# qhasm:   16x a0 += t
# asm 1: vpaddw <t=reg256#7,<a0=reg256#6,>a0=reg256#6
# asm 2: vpaddw <t=%ymm6,<a0=%ymm5,>a0=%ymm5
vpaddw %ymm6,%ymm5,%ymm5

# qhasm:   16x r unsigned>>= 1
# asm 1: vpsrlw $1,<r=reg256#5,>r=reg256#5
# asm 2: vpsrlw $1,<r=%ymm4,>r=%ymm4
vpsrlw $1,%ymm4,%ymm4

# qhasm:   t = r & _mask1
# asm 1: vpand <r=reg256#5,<_mask1=reg256#1,>t=reg256#7
# asm 2: vpand <r=%ymm4,<_mask1=%ymm0,>t=%ymm6
vpand %ymm4,%ymm0,%ymm6

# qhasm:   16x a0 += t
# asm 1: vpaddw <t=reg256#7,<a0=reg256#6,>a0=reg256#6
# asm 2: vpaddw <t=%ymm6,<a0=%ymm5,>a0=%ymm5
vpaddw %ymm6,%ymm5,%ymm5

# qhasm:   16x r unsigned>>= 1
# asm 1: vpsrlw $1,<r=reg256#5,>r=reg256#5
# asm 2: vpsrlw $1,<r=%ymm4,>r=%ymm4
vpsrlw $1,%ymm4,%ymm4

# qhasm:   t = r & _mask1
# asm 1: vpand <r=reg256#5,<_mask1=reg256#1,>t=reg256#5
# asm 2: vpand <r=%ymm4,<_mask1=%ymm0,>t=%ymm4
vpand %ymm4,%ymm0,%ymm4

# qhasm:   16x a0 += t
# asm 1: vpaddw <t=reg256#5,<a0=reg256#6,>a0=reg256#5
# asm 2: vpaddw <t=%ymm4,<a0=%ymm5,>a0=%ymm4
vpaddw %ymm4,%ymm5,%ymm4

# qhasm:   16x t = a0 unsigned>> 8
# asm 1: vpsrlw $8,<a0=reg256#5,>t=reg256#6
# asm 2: vpsrlw $8,<a0=%ymm4,>t=%ymm5
vpsrlw $8,%ymm4,%ymm5

# qhasm:   a0 &= _maskff
# asm 1: vpand <_maskff=reg256#3,<a0=reg256#5,<a0=reg256#5
# asm 2: vpand <_maskff=%ymm2,<a0=%ymm4,<a0=%ymm4
vpand %ymm2,%ymm4,%ymm4

# qhasm:   16x a0 += t
# asm 1: vpaddw <t=reg256#6,<a0=reg256#5,>a0=reg256#5
# asm 2: vpaddw <t=%ymm5,<a0=%ymm4,>a0=%ymm4
vpaddw %ymm5,%ymm4,%ymm4

# qhasm:   8x b0 = a0 unsigned>> 16
# asm 1: vpsrld $16,<a0=reg256#5,>b0=reg256#6
# asm 2: vpsrld $16,<a0=%ymm4,>b0=%ymm5
vpsrld $16,%ymm4,%ymm5

# qhasm:   a0 &= _maskffff
# asm 1: vpand <_maskffff=reg256#2,<a0=reg256#5,<a0=reg256#5
# asm 2: vpand <_maskffff=%ymm1,<a0=%ymm4,<a0=%ymm4
vpand %ymm1,%ymm4,%ymm4

# qhasm:   16x a0 += _q8x
# asm 1: vpaddw <_q8x=reg256#4,<a0=reg256#5,>a0=reg256#5
# asm 2: vpaddw <_q8x=%ymm3,<a0=%ymm4,>a0=%ymm4
vpaddw %ymm3,%ymm4,%ymm4

# qhasm:   16x a0 -= b0
# asm 1: vpsubw <b0=reg256#6,<a0=reg256#5,>a0=reg256#5
# asm 2: vpsubw <b0=%ymm5,<a0=%ymm4,>a0=%ymm4
vpsubw %ymm5,%ymm4,%ymm4

# qhasm:   mem256[input_0 + 0] = a0
# asm 1: vmovupd   <a0=reg256#5,0(<input_0=int64#1)
# asm 2: vmovupd   <a0=%ymm4,0(<input_0=%rdi)
vmovupd   %ymm4,0(%rdi)

# qhasm:   input_0 += 32
# asm 1: add  $32,<input_0=int64#1
# asm 2: add  $32,<input_0=%rdi
add  $32,%rdi

# qhasm:   input_1 += 32
# asm 1: add  $32,<input_1=int64#2
# asm 2: add  $32,<input_1=%rsi
add  $32,%rsi

# qhasm:   unsigned>? ctr -= 1
# asm 1: sub  $1,<ctr=int64#3
# asm 2: sub  $1,<ctr=%rdx
sub  $1,%rdx
# comment:fp stack unchanged by jump

# qhasm: goto looptop if unsigned>
ja ._looptop

# qhasm: return
add %r11,%rsp
ret
