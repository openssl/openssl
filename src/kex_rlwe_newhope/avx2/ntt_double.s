
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

# qhasm: int64 ctrj

# qhasm: int64 ap

# qhasm: int64 tp

# qhasm: int64 wp

# qhasm: int64 pp

# qhasm: reg256 c

# qhasm: reg256 qinv

# qhasm: reg256 q

# qhasm: reg256 t0

# qhasm: reg256 t1

# qhasm: reg256 t2

# qhasm: reg256 t3

# qhasm: reg256 w

# qhasm: reg256 a0

# qhasm: reg256 a1

# qhasm: reg256 a2

# qhasm: reg256 a3

# qhasm: reg256 r0

# qhasm: reg256 r1

# qhasm: reg256 r2

# qhasm: reg256 r3

# qhasm: enter ntt_double
.p2align 5
.global _ntt_double
.global ntt_double
_ntt_double:
ntt_double:
mov %rsp,%r11
and $31,%r11
add $0,%r11
sub %r11,%rsp

# qhasm: q = mem256[q8]
# asm 1: vmovdqu q8,>q=reg256#1
# asm 2: vmovdqu q8,>q=%ymm0
vmovdqu q8,%ymm0

# qhasm: qinv = mem256[qinv16]
# asm 1: vmovdqu qinv16,>qinv=reg256#2
# asm 2: vmovdqu qinv16,>qinv=%ymm1
vmovdqu qinv16,%ymm1

# qhasm: ctrj = 64
# asm 1: mov  $64,>ctrj=int64#4
# asm 2: mov  $64,>ctrj=%rcx
mov  $64,%rcx

# qhasm: ap = input_0
# asm 1: mov  <input_0=int64#1,>ap=int64#5
# asm 2: mov  <input_0=%rdi,>ap=%r8
mov  %rdi,%r8

# qhasm: tp = input_2
# asm 1: mov  <input_2=int64#3,>tp=int64#6
# asm 2: mov  <input_2=%rdx,>tp=%r9
mov  %rdx,%r9

# qhasm: wp = input_1 + 8192
# asm 1: lea  8192(<input_1=int64#2),>wp=int64#7
# asm 2: lea  8192(<input_1=%rsi),>wp=%rax
lea  8192(%rsi),%rax

# qhasm: pp = input_1
# asm 1: mov  <input_1=int64#2,>pp=int64#2
# asm 2: mov  <input_1=%rsi,>pp=%rsi
mov  %rsi,%rsi

# qhasm: a0 = (4x double)(4x int32)mem128[ap + 0]
# asm 1: vcvtdq2pd 0(<ap=int64#5),>a0=reg256#3
# asm 2: vcvtdq2pd 0(<ap=%r8),>a0=%ymm2
vcvtdq2pd 0(%r8),%ymm2

# qhasm: a1 = (4x double)(4x int32)mem128[ap + 16]
# asm 1: vcvtdq2pd 16(<ap=int64#5),>a1=reg256#4
# asm 2: vcvtdq2pd 16(<ap=%r8),>a1=%ymm3
vcvtdq2pd 16(%r8),%ymm3

# qhasm: a2 = (4x double)(4x int32)mem128[ap + 32]
# asm 1: vcvtdq2pd 32(<ap=int64#5),>a2=reg256#5
# asm 2: vcvtdq2pd 32(<ap=%r8),>a2=%ymm4
vcvtdq2pd 32(%r8),%ymm4

# qhasm: a3 = (4x double)(4x int32)mem128[ap + 48]
# asm 1: vcvtdq2pd 48(<ap=int64#5),>a3=reg256#6
# asm 2: vcvtdq2pd 48(<ap=%r8),>a3=%ymm5
vcvtdq2pd 48(%r8),%ymm5

# qhasm: r3 = mem256[neg2]
# asm 1: vmovdqu neg2,>r3=reg256#7
# asm 2: vmovdqu neg2,>r3=%ymm6
vmovdqu neg2,%ymm6

# qhasm: 4x r0 = approx a0 * r3
# asm 1: vmulpd <a0=reg256#3,<r3=reg256#7,>r0=reg256#8
# asm 2: vmulpd <a0=%ymm2,<r3=%ymm6,>r0=%ymm7
vmulpd %ymm2,%ymm6,%ymm7

# qhasm: 4x r1 = approx a1 * r3
# asm 1: vmulpd <a1=reg256#4,<r3=reg256#7,>r1=reg256#9
# asm 2: vmulpd <a1=%ymm3,<r3=%ymm6,>r1=%ymm8
vmulpd %ymm3,%ymm6,%ymm8

# qhasm: 4x r2 = approx a2 * r3
# asm 1: vmulpd <a2=reg256#5,<r3=reg256#7,>r2=reg256#10
# asm 2: vmulpd <a2=%ymm4,<r3=%ymm6,>r2=%ymm9
vmulpd %ymm4,%ymm6,%ymm9

# qhasm: 4x r3 approx*= a3
# asm 1: vmulpd <a3=reg256#6,<r3=reg256#7,>r3=reg256#7
# asm 2: vmulpd <a3=%ymm5,<r3=%ymm6,>r3=%ymm6
vmulpd %ymm5,%ymm6,%ymm6

# qhasm: r0[0,1,2,3] = a0[0]approx+a0[1],r0[0]approx+r0[1],a0[2]approx+a0[3],r0[2]approx+r0[3]
# asm 1: vhaddpd <r0=reg256#8,<a0=reg256#3,>r0=reg256#3
# asm 2: vhaddpd <r0=%ymm7,<a0=%ymm2,>r0=%ymm2
vhaddpd %ymm7,%ymm2,%ymm2

# qhasm: w = mem256[pp + 0]
# asm 1: vmovupd   0(<pp=int64#2),>w=reg256#8
# asm 2: vmovupd   0(<pp=%rsi),>w=%ymm7
vmovupd   0(%rsi),%ymm7

# qhasm: 4x r0 approx*= w
# asm 1: vmulpd <w=reg256#8,<r0=reg256#3,>r0=reg256#3
# asm 2: vmulpd <w=%ymm7,<r0=%ymm2,>r0=%ymm2
vmulpd %ymm7,%ymm2,%ymm2

# qhasm: a0[0,1,2,3] = r0[2,3],r0[0,1]
# asm 1: vperm2f128 $0x21,<r0=reg256#3,<r0=reg256#3,>a0=reg256#8
# asm 2: vperm2f128 $0x21,<r0=%ymm2,<r0=%ymm2,>a0=%ymm7
vperm2f128 $0x21,%ymm2,%ymm2,%ymm7

# qhasm: r1[0,1,2,3] = a1[0]approx+a1[1],r1[0]approx+r1[1],a1[2]approx+a1[3],r1[2]approx+r1[3]
# asm 1: vhaddpd <r1=reg256#9,<a1=reg256#4,>r1=reg256#4
# asm 2: vhaddpd <r1=%ymm8,<a1=%ymm3,>r1=%ymm3
vhaddpd %ymm8,%ymm3,%ymm3

# qhasm: w = mem256[pp + 32]
# asm 1: vmovupd   32(<pp=int64#2),>w=reg256#9
# asm 2: vmovupd   32(<pp=%rsi),>w=%ymm8
vmovupd   32(%rsi),%ymm8

# qhasm: 4x r1 approx*= w
# asm 1: vmulpd <w=reg256#9,<r1=reg256#4,>r1=reg256#4
# asm 2: vmulpd <w=%ymm8,<r1=%ymm3,>r1=%ymm3
vmulpd %ymm8,%ymm3,%ymm3

# qhasm: a1[0,1,2,3] = r1[2,3],r1[0,1]
# asm 1: vperm2f128 $0x21,<r1=reg256#4,<r1=reg256#4,>a1=reg256#9
# asm 2: vperm2f128 $0x21,<r1=%ymm3,<r1=%ymm3,>a1=%ymm8
vperm2f128 $0x21,%ymm3,%ymm3,%ymm8

# qhasm: r2[0,1,2,3] = a2[0]approx+a2[1],r2[0]approx+r2[1],a2[2]approx+a2[3],r2[2]approx+r2[3]
# asm 1: vhaddpd <r2=reg256#10,<a2=reg256#5,>r2=reg256#5
# asm 2: vhaddpd <r2=%ymm9,<a2=%ymm4,>r2=%ymm4
vhaddpd %ymm9,%ymm4,%ymm4

# qhasm: w = mem256[pp + 64]
# asm 1: vmovupd   64(<pp=int64#2),>w=reg256#10
# asm 2: vmovupd   64(<pp=%rsi),>w=%ymm9
vmovupd   64(%rsi),%ymm9

# qhasm: 4x r2 approx*= w
# asm 1: vmulpd <w=reg256#10,<r2=reg256#5,>r2=reg256#5
# asm 2: vmulpd <w=%ymm9,<r2=%ymm4,>r2=%ymm4
vmulpd %ymm9,%ymm4,%ymm4

# qhasm: a2[0,1,2,3] = r2[2,3],r2[0,1]
# asm 1: vperm2f128 $0x21,<r2=reg256#5,<r2=reg256#5,>a2=reg256#10
# asm 2: vperm2f128 $0x21,<r2=%ymm4,<r2=%ymm4,>a2=%ymm9
vperm2f128 $0x21,%ymm4,%ymm4,%ymm9

# qhasm: r3[0,1,2,3] = a3[0]approx+a3[1],r3[0]approx+r3[1],a3[2]approx+a3[3],r3[2]approx+r3[3]
# asm 1: vhaddpd <r3=reg256#7,<a3=reg256#6,>r3=reg256#6
# asm 2: vhaddpd <r3=%ymm6,<a3=%ymm5,>r3=%ymm5
vhaddpd %ymm6,%ymm5,%ymm5

# qhasm: w = mem256[pp + 96]
# asm 1: vmovupd   96(<pp=int64#2),>w=reg256#7
# asm 2: vmovupd   96(<pp=%rsi),>w=%ymm6
vmovupd   96(%rsi),%ymm6

# qhasm: 4x r3 approx*= w
# asm 1: vmulpd <w=reg256#7,<r3=reg256#6,>r3=reg256#6
# asm 2: vmulpd <w=%ymm6,<r3=%ymm5,>r3=%ymm5
vmulpd %ymm6,%ymm5,%ymm5

# qhasm: a3[0,1,2,3] = r3[2,3],r3[0,1]
# asm 1: vperm2f128 $0x21,<r3=reg256#6,<r3=reg256#6,>a3=reg256#7
# asm 2: vperm2f128 $0x21,<r3=%ymm5,<r3=%ymm5,>a3=%ymm6
vperm2f128 $0x21,%ymm5,%ymm5,%ymm6

# qhasm: c = mem256[neg4]
# asm 1: vmovdqu neg4,>c=reg256#11
# asm 2: vmovdqu neg4,>c=%ymm10
vmovdqu neg4,%ymm10

# qhasm: 4x a0 approx+= r0 * c
# asm 1: vfmadd231pd <r0=reg256#3,<c=reg256#11,<a0=reg256#8
# asm 2: vfmadd231pd <r0=%ymm2,<c=%ymm10,<a0=%ymm7
vfmadd231pd %ymm2,%ymm10,%ymm7

# qhasm: 4x a1 approx+= r1 * c
# asm 1: vfmadd231pd <r1=reg256#4,<c=reg256#11,<a1=reg256#9
# asm 2: vfmadd231pd <r1=%ymm3,<c=%ymm10,<a1=%ymm8
vfmadd231pd %ymm3,%ymm10,%ymm8

# qhasm: w = mem256[wp + 32]
# asm 1: vmovupd   32(<wp=int64#7),>w=reg256#3
# asm 2: vmovupd   32(<wp=%rax),>w=%ymm2
vmovupd   32(%rax),%ymm2

# qhasm: 4x a1 approx*= w
# asm 1: vmulpd <w=reg256#3,<a1=reg256#9,>a1=reg256#3
# asm 2: vmulpd <w=%ymm2,<a1=%ymm8,>a1=%ymm2
vmulpd %ymm2,%ymm8,%ymm2

# qhasm: w = mem256[wp + 64]
# asm 1: vmovupd   64(<wp=int64#7),>w=reg256#4
# asm 2: vmovupd   64(<wp=%rax),>w=%ymm3
vmovupd   64(%rax),%ymm3

# qhasm: 4x a2 approx+= r2 * c
# asm 1: vfmadd231pd <r2=reg256#5,<c=reg256#11,<a2=reg256#10
# asm 2: vfmadd231pd <r2=%ymm4,<c=%ymm10,<a2=%ymm9
vfmadd231pd %ymm4,%ymm10,%ymm9

# qhasm: 4x a2 approx*= w
# asm 1: vmulpd <w=reg256#4,<a2=reg256#10,>a2=reg256#4
# asm 2: vmulpd <w=%ymm3,<a2=%ymm9,>a2=%ymm3
vmulpd %ymm3,%ymm9,%ymm3

# qhasm: w = mem256[wp + 96]
# asm 1: vmovupd   96(<wp=int64#7),>w=reg256#5
# asm 2: vmovupd   96(<wp=%rax),>w=%ymm4
vmovupd   96(%rax),%ymm4

# qhasm: 4x a3 approx+= r3 * c
# asm 1: vfmadd231pd <r3=reg256#6,<c=reg256#11,<a3=reg256#7
# asm 2: vfmadd231pd <r3=%ymm5,<c=%ymm10,<a3=%ymm6
vfmadd231pd %ymm5,%ymm10,%ymm6

# qhasm: 4x a3 approx*= w
# asm 1: vmulpd <w=reg256#5,<a3=reg256#7,>a3=reg256#5
# asm 2: vmulpd <w=%ymm4,<a3=%ymm6,>a3=%ymm4
vmulpd %ymm4,%ymm6,%ymm4

# qhasm: 4x c = approx a1 * qinv
# asm 1: vmulpd <a1=reg256#3,<qinv=reg256#2,>c=reg256#6
# asm 2: vmulpd <a1=%ymm2,<qinv=%ymm1,>c=%ymm5
vmulpd %ymm2,%ymm1,%ymm5

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#6,>c=reg256#6
# asm 2: vroundpd $9,<c=%ymm5,>c=%ymm5
vroundpd $9,%ymm5,%ymm5

# qhasm: 4x a1 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#6,<q=reg256#1,<a1=reg256#3
# asm 2: vfnmadd231pd <c=%ymm5,<q=%ymm0,<a1=%ymm2
vfnmadd231pd %ymm5,%ymm0,%ymm2

# qhasm: 4x c = approx a2 * qinv
# asm 1: vmulpd <a2=reg256#4,<qinv=reg256#2,>c=reg256#6
# asm 2: vmulpd <a2=%ymm3,<qinv=%ymm1,>c=%ymm5
vmulpd %ymm3,%ymm1,%ymm5

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#6,>c=reg256#6
# asm 2: vroundpd $9,<c=%ymm5,>c=%ymm5
vroundpd $9,%ymm5,%ymm5

# qhasm: 4x a2 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#6,<q=reg256#1,<a2=reg256#4
# asm 2: vfnmadd231pd <c=%ymm5,<q=%ymm0,<a2=%ymm3
vfnmadd231pd %ymm5,%ymm0,%ymm3

# qhasm: 4x c = approx a3 * qinv
# asm 1: vmulpd <a3=reg256#5,<qinv=reg256#2,>c=reg256#6
# asm 2: vmulpd <a3=%ymm4,<qinv=%ymm1,>c=%ymm5
vmulpd %ymm4,%ymm1,%ymm5

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#6,>c=reg256#6
# asm 2: vroundpd $9,<c=%ymm5,>c=%ymm5
vroundpd $9,%ymm5,%ymm5

# qhasm: 4x a3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#6,<q=reg256#1,<a3=reg256#5
# asm 2: vfnmadd231pd <c=%ymm5,<q=%ymm0,<a3=%ymm4
vfnmadd231pd %ymm5,%ymm0,%ymm4

# qhasm: 4x r0 = approx a0 + a1
# asm 1: vaddpd <a0=reg256#8,<a1=reg256#3,>r0=reg256#6
# asm 2: vaddpd <a0=%ymm7,<a1=%ymm2,>r0=%ymm5
vaddpd %ymm7,%ymm2,%ymm5

# qhasm: 4x r2 = approx a2 + a3
# asm 1: vaddpd <a2=reg256#4,<a3=reg256#5,>r2=reg256#7
# asm 2: vaddpd <a2=%ymm3,<a3=%ymm4,>r2=%ymm6
vaddpd %ymm3,%ymm4,%ymm6

# qhasm: 4x r1 = approx a0 - a1
# asm 1: vsubpd <a1=reg256#3,<a0=reg256#8,>r1=reg256#3
# asm 2: vsubpd <a1=%ymm2,<a0=%ymm7,>r1=%ymm2
vsubpd %ymm2,%ymm7,%ymm2

# qhasm: w = mem64[wp + 136],mem64[wp + 136],mem64[wp + 136],mem64[wp + 136]
# asm 1: vbroadcastsd 136(<wp=int64#7),>w=reg256#8
# asm 2: vbroadcastsd 136(<wp=%rax),>w=%ymm7
vbroadcastsd 136(%rax),%ymm7

# qhasm: 4x r3 = approx a2 - a3
# asm 1: vsubpd <a3=reg256#5,<a2=reg256#4,>r3=reg256#4
# asm 2: vsubpd <a3=%ymm4,<a2=%ymm3,>r3=%ymm3
vsubpd %ymm4,%ymm3,%ymm3

# qhasm: 4x r3 approx*= w
# asm 1: vmulpd <w=reg256#8,<r3=reg256#4,>r3=reg256#4
# asm 2: vmulpd <w=%ymm7,<r3=%ymm3,>r3=%ymm3
vmulpd %ymm7,%ymm3,%ymm3

# qhasm: 4x a0 = approx r0 + r2
# asm 1: vaddpd <r0=reg256#6,<r2=reg256#7,>a0=reg256#5
# asm 2: vaddpd <r0=%ymm5,<r2=%ymm6,>a0=%ymm4
vaddpd %ymm5,%ymm6,%ymm4

# qhasm: 4x a1 = approx r1 + r3
# asm 1: vaddpd <r1=reg256#3,<r3=reg256#4,>a1=reg256#8
# asm 2: vaddpd <r1=%ymm2,<r3=%ymm3,>a1=%ymm7
vaddpd %ymm2,%ymm3,%ymm7

# qhasm: 4x a2 = approx r0 - r2
# asm 1: vsubpd <r2=reg256#7,<r0=reg256#6,>a2=reg256#6
# asm 2: vsubpd <r2=%ymm6,<r0=%ymm5,>a2=%ymm5
vsubpd %ymm6,%ymm5,%ymm5

# qhasm: 4x a3 = approx r1 - r3
# asm 1: vsubpd <r3=reg256#4,<r1=reg256#3,>a3=reg256#3
# asm 2: vsubpd <r3=%ymm3,<r1=%ymm2,>a3=%ymm2
vsubpd %ymm3,%ymm2,%ymm2

# qhasm: mem256[tp +  0] = a0
# asm 1: vmovupd   <a0=reg256#5,0(<tp=int64#6)
# asm 2: vmovupd   <a0=%ymm4,0(<tp=%r9)
vmovupd   %ymm4,0(%r9)

# qhasm: mem256[tp + 32] = a1
# asm 1: vmovupd   <a1=reg256#8,32(<tp=int64#6)
# asm 2: vmovupd   <a1=%ymm7,32(<tp=%r9)
vmovupd   %ymm7,32(%r9)

# qhasm: mem256[tp + 64] = a2
# asm 1: vmovupd   <a2=reg256#6,64(<tp=int64#6)
# asm 2: vmovupd   <a2=%ymm5,64(<tp=%r9)
vmovupd   %ymm5,64(%r9)

# qhasm: mem256[tp + 96] = a3
# asm 1: vmovupd   <a3=reg256#3,96(<tp=int64#6)
# asm 2: vmovupd   <a3=%ymm2,96(<tp=%r9)
vmovupd   %ymm2,96(%r9)

# qhasm: ap+= 64
# asm 1: add  $64,<ap=int64#5
# asm 2: add  $64,<ap=%r8
add  $64,%r8

# qhasm: tp+= 128
# asm 1: add  $128,<tp=int64#6
# asm 2: add  $128,<tp=%r9
add  $128,%r9

# qhasm: wp+= 152
# asm 1: add  $152,<wp=int64#7
# asm 2: add  $152,<wp=%rax
add  $152,%rax

# qhasm: pp+= 128
# asm 1: add  $128,<pp=int64#2
# asm 2: add  $128,<pp=%rsi
add  $128,%rsi

# qhasm: ctrj-=1
# asm 1: sub  $1,<ctrj=int64#4
# asm 2: sub  $1,<ctrj=%rcx
sub  $1,%rcx

# qhasm: loopinreg:
._loopinreg:

# qhasm: a0 = (4x double)(4x int32)mem128[ap + 0]
# asm 1: vcvtdq2pd 0(<ap=int64#5),>a0=reg256#3
# asm 2: vcvtdq2pd 0(<ap=%r8),>a0=%ymm2
vcvtdq2pd 0(%r8),%ymm2

# qhasm: a1 = (4x double)(4x int32)mem128[ap + 16]
# asm 1: vcvtdq2pd 16(<ap=int64#5),>a1=reg256#4
# asm 2: vcvtdq2pd 16(<ap=%r8),>a1=%ymm3
vcvtdq2pd 16(%r8),%ymm3

# qhasm: a2 = (4x double)(4x int32)mem128[ap + 32]
# asm 1: vcvtdq2pd 32(<ap=int64#5),>a2=reg256#5
# asm 2: vcvtdq2pd 32(<ap=%r8),>a2=%ymm4
vcvtdq2pd 32(%r8),%ymm4

# qhasm: a3 = (4x double)(4x int32)mem128[ap + 48]
# asm 1: vcvtdq2pd 48(<ap=int64#5),>a3=reg256#6
# asm 2: vcvtdq2pd 48(<ap=%r8),>a3=%ymm5
vcvtdq2pd 48(%r8),%ymm5

# qhasm: r3 = mem256[neg2]
# asm 1: vmovdqu neg2,>r3=reg256#7
# asm 2: vmovdqu neg2,>r3=%ymm6
vmovdqu neg2,%ymm6

# qhasm: 4x r0 = approx a0 * r3
# asm 1: vmulpd <a0=reg256#3,<r3=reg256#7,>r0=reg256#8
# asm 2: vmulpd <a0=%ymm2,<r3=%ymm6,>r0=%ymm7
vmulpd %ymm2,%ymm6,%ymm7

# qhasm: 4x r1 = approx a1 * r3
# asm 1: vmulpd <a1=reg256#4,<r3=reg256#7,>r1=reg256#9
# asm 2: vmulpd <a1=%ymm3,<r3=%ymm6,>r1=%ymm8
vmulpd %ymm3,%ymm6,%ymm8

# qhasm: 4x r2 = approx a2 * r3
# asm 1: vmulpd <a2=reg256#5,<r3=reg256#7,>r2=reg256#10
# asm 2: vmulpd <a2=%ymm4,<r3=%ymm6,>r2=%ymm9
vmulpd %ymm4,%ymm6,%ymm9

# qhasm: 4x r3 approx*= a3
# asm 1: vmulpd <a3=reg256#6,<r3=reg256#7,>r3=reg256#7
# asm 2: vmulpd <a3=%ymm5,<r3=%ymm6,>r3=%ymm6
vmulpd %ymm5,%ymm6,%ymm6

# qhasm: r0[0,1,2,3] = a0[0]approx+a0[1],r0[0]approx+r0[1],a0[2]approx+a0[3],r0[2]approx+r0[3]
# asm 1: vhaddpd <r0=reg256#8,<a0=reg256#3,>r0=reg256#3
# asm 2: vhaddpd <r0=%ymm7,<a0=%ymm2,>r0=%ymm2
vhaddpd %ymm7,%ymm2,%ymm2

# qhasm: w = mem256[pp + 0]
# asm 1: vmovupd   0(<pp=int64#2),>w=reg256#8
# asm 2: vmovupd   0(<pp=%rsi),>w=%ymm7
vmovupd   0(%rsi),%ymm7

# qhasm: 4x r0 approx*= w
# asm 1: vmulpd <w=reg256#8,<r0=reg256#3,>r0=reg256#3
# asm 2: vmulpd <w=%ymm7,<r0=%ymm2,>r0=%ymm2
vmulpd %ymm7,%ymm2,%ymm2

# qhasm: a0[0,1,2,3] = r0[2,3],r0[0,1]
# asm 1: vperm2f128 $0x21,<r0=reg256#3,<r0=reg256#3,>a0=reg256#8
# asm 2: vperm2f128 $0x21,<r0=%ymm2,<r0=%ymm2,>a0=%ymm7
vperm2f128 $0x21,%ymm2,%ymm2,%ymm7

# qhasm: r1[0,1,2,3] = a1[0]approx+a1[1],r1[0]approx+r1[1],a1[2]approx+a1[3],r1[2]approx+r1[3]
# asm 1: vhaddpd <r1=reg256#9,<a1=reg256#4,>r1=reg256#4
# asm 2: vhaddpd <r1=%ymm8,<a1=%ymm3,>r1=%ymm3
vhaddpd %ymm8,%ymm3,%ymm3

# qhasm: w = mem256[pp + 32]
# asm 1: vmovupd   32(<pp=int64#2),>w=reg256#9
# asm 2: vmovupd   32(<pp=%rsi),>w=%ymm8
vmovupd   32(%rsi),%ymm8

# qhasm: 4x r1 approx*= w
# asm 1: vmulpd <w=reg256#9,<r1=reg256#4,>r1=reg256#4
# asm 2: vmulpd <w=%ymm8,<r1=%ymm3,>r1=%ymm3
vmulpd %ymm8,%ymm3,%ymm3

# qhasm: a1[0,1,2,3] = r1[2,3],r1[0,1]
# asm 1: vperm2f128 $0x21,<r1=reg256#4,<r1=reg256#4,>a1=reg256#9
# asm 2: vperm2f128 $0x21,<r1=%ymm3,<r1=%ymm3,>a1=%ymm8
vperm2f128 $0x21,%ymm3,%ymm3,%ymm8

# qhasm: r2[0,1,2,3] = a2[0]approx+a2[1],r2[0]approx+r2[1],a2[2]approx+a2[3],r2[2]approx+r2[3]
# asm 1: vhaddpd <r2=reg256#10,<a2=reg256#5,>r2=reg256#5
# asm 2: vhaddpd <r2=%ymm9,<a2=%ymm4,>r2=%ymm4
vhaddpd %ymm9,%ymm4,%ymm4

# qhasm: w = mem256[pp + 64]
# asm 1: vmovupd   64(<pp=int64#2),>w=reg256#10
# asm 2: vmovupd   64(<pp=%rsi),>w=%ymm9
vmovupd   64(%rsi),%ymm9

# qhasm: 4x r2 approx*= w
# asm 1: vmulpd <w=reg256#10,<r2=reg256#5,>r2=reg256#5
# asm 2: vmulpd <w=%ymm9,<r2=%ymm4,>r2=%ymm4
vmulpd %ymm9,%ymm4,%ymm4

# qhasm: a2[0,1,2,3] = r2[2,3],r2[0,1]
# asm 1: vperm2f128 $0x21,<r2=reg256#5,<r2=reg256#5,>a2=reg256#10
# asm 2: vperm2f128 $0x21,<r2=%ymm4,<r2=%ymm4,>a2=%ymm9
vperm2f128 $0x21,%ymm4,%ymm4,%ymm9

# qhasm: r3[0,1,2,3] = a3[0]approx+a3[1],r3[0]approx+r3[1],a3[2]approx+a3[3],r3[2]approx+r3[3]
# asm 1: vhaddpd <r3=reg256#7,<a3=reg256#6,>r3=reg256#6
# asm 2: vhaddpd <r3=%ymm6,<a3=%ymm5,>r3=%ymm5
vhaddpd %ymm6,%ymm5,%ymm5

# qhasm: w = mem256[pp + 96]
# asm 1: vmovupd   96(<pp=int64#2),>w=reg256#7
# asm 2: vmovupd   96(<pp=%rsi),>w=%ymm6
vmovupd   96(%rsi),%ymm6

# qhasm: 4x r3 approx*= w
# asm 1: vmulpd <w=reg256#7,<r3=reg256#6,>r3=reg256#6
# asm 2: vmulpd <w=%ymm6,<r3=%ymm5,>r3=%ymm5
vmulpd %ymm6,%ymm5,%ymm5

# qhasm: a3[0,1,2,3] = r3[2,3],r3[0,1]
# asm 1: vperm2f128 $0x21,<r3=reg256#6,<r3=reg256#6,>a3=reg256#7
# asm 2: vperm2f128 $0x21,<r3=%ymm5,<r3=%ymm5,>a3=%ymm6
vperm2f128 $0x21,%ymm5,%ymm5,%ymm6

# qhasm: c = mem256[neg4]
# asm 1: vmovdqu neg4,>c=reg256#11
# asm 2: vmovdqu neg4,>c=%ymm10
vmovdqu neg4,%ymm10

# qhasm: 4x a0 approx+= r0 * c
# asm 1: vfmadd231pd <r0=reg256#3,<c=reg256#11,<a0=reg256#8
# asm 2: vfmadd231pd <r0=%ymm2,<c=%ymm10,<a0=%ymm7
vfmadd231pd %ymm2,%ymm10,%ymm7

# qhasm: w = mem256[wp + 0]
# asm 1: vmovupd   0(<wp=int64#7),>w=reg256#3
# asm 2: vmovupd   0(<wp=%rax),>w=%ymm2
vmovupd   0(%rax),%ymm2

# qhasm: 4x a0 approx*= w
# asm 1: vmulpd <w=reg256#3,<a0=reg256#8,>a0=reg256#3
# asm 2: vmulpd <w=%ymm2,<a0=%ymm7,>a0=%ymm2
vmulpd %ymm2,%ymm7,%ymm2

# qhasm: 4x a1 approx+= r1 * c
# asm 1: vfmadd231pd <r1=reg256#4,<c=reg256#11,<a1=reg256#9
# asm 2: vfmadd231pd <r1=%ymm3,<c=%ymm10,<a1=%ymm8
vfmadd231pd %ymm3,%ymm10,%ymm8

# qhasm: w = mem256[wp + 32]
# asm 1: vmovupd   32(<wp=int64#7),>w=reg256#4
# asm 2: vmovupd   32(<wp=%rax),>w=%ymm3
vmovupd   32(%rax),%ymm3

# qhasm: 4x a1 approx*= w
# asm 1: vmulpd <w=reg256#4,<a1=reg256#9,>a1=reg256#4
# asm 2: vmulpd <w=%ymm3,<a1=%ymm8,>a1=%ymm3
vmulpd %ymm3,%ymm8,%ymm3

# qhasm: w = mem256[wp + 64]
# asm 1: vmovupd   64(<wp=int64#7),>w=reg256#8
# asm 2: vmovupd   64(<wp=%rax),>w=%ymm7
vmovupd   64(%rax),%ymm7

# qhasm: 4x a2 approx+= r2 * c
# asm 1: vfmadd231pd <r2=reg256#5,<c=reg256#11,<a2=reg256#10
# asm 2: vfmadd231pd <r2=%ymm4,<c=%ymm10,<a2=%ymm9
vfmadd231pd %ymm4,%ymm10,%ymm9

# qhasm: 4x a2 approx*= w
# asm 1: vmulpd <w=reg256#8,<a2=reg256#10,>a2=reg256#5
# asm 2: vmulpd <w=%ymm7,<a2=%ymm9,>a2=%ymm4
vmulpd %ymm7,%ymm9,%ymm4

# qhasm: w = mem256[wp + 96]
# asm 1: vmovupd   96(<wp=int64#7),>w=reg256#8
# asm 2: vmovupd   96(<wp=%rax),>w=%ymm7
vmovupd   96(%rax),%ymm7

# qhasm: 4x a3 approx+= r3 * c
# asm 1: vfmadd231pd <r3=reg256#6,<c=reg256#11,<a3=reg256#7
# asm 2: vfmadd231pd <r3=%ymm5,<c=%ymm10,<a3=%ymm6
vfmadd231pd %ymm5,%ymm10,%ymm6

# qhasm: 4x a3 approx*= w
# asm 1: vmulpd <w=reg256#8,<a3=reg256#7,>a3=reg256#6
# asm 2: vmulpd <w=%ymm7,<a3=%ymm6,>a3=%ymm5
vmulpd %ymm7,%ymm6,%ymm5

# qhasm: 4x c = approx a0 * qinv
# asm 1: vmulpd <a0=reg256#3,<qinv=reg256#2,>c=reg256#7
# asm 2: vmulpd <a0=%ymm2,<qinv=%ymm1,>c=%ymm6
vmulpd %ymm2,%ymm1,%ymm6

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#7,>c=reg256#7
# asm 2: vroundpd $9,<c=%ymm6,>c=%ymm6
vroundpd $9,%ymm6,%ymm6

# qhasm: 4x a0 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#7,<q=reg256#1,<a0=reg256#3
# asm 2: vfnmadd231pd <c=%ymm6,<q=%ymm0,<a0=%ymm2
vfnmadd231pd %ymm6,%ymm0,%ymm2

# qhasm: 4x c = approx a1 * qinv
# asm 1: vmulpd <a1=reg256#4,<qinv=reg256#2,>c=reg256#7
# asm 2: vmulpd <a1=%ymm3,<qinv=%ymm1,>c=%ymm6
vmulpd %ymm3,%ymm1,%ymm6

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#7,>c=reg256#7
# asm 2: vroundpd $9,<c=%ymm6,>c=%ymm6
vroundpd $9,%ymm6,%ymm6

# qhasm: 4x a1 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#7,<q=reg256#1,<a1=reg256#4
# asm 2: vfnmadd231pd <c=%ymm6,<q=%ymm0,<a1=%ymm3
vfnmadd231pd %ymm6,%ymm0,%ymm3

# qhasm: 4x c = approx a2 * qinv
# asm 1: vmulpd <a2=reg256#5,<qinv=reg256#2,>c=reg256#7
# asm 2: vmulpd <a2=%ymm4,<qinv=%ymm1,>c=%ymm6
vmulpd %ymm4,%ymm1,%ymm6

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#7,>c=reg256#7
# asm 2: vroundpd $9,<c=%ymm6,>c=%ymm6
vroundpd $9,%ymm6,%ymm6

# qhasm: 4x a2 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#7,<q=reg256#1,<a2=reg256#5
# asm 2: vfnmadd231pd <c=%ymm6,<q=%ymm0,<a2=%ymm4
vfnmadd231pd %ymm6,%ymm0,%ymm4

# qhasm: 4x c = approx a3 * qinv
# asm 1: vmulpd <a3=reg256#6,<qinv=reg256#2,>c=reg256#7
# asm 2: vmulpd <a3=%ymm5,<qinv=%ymm1,>c=%ymm6
vmulpd %ymm5,%ymm1,%ymm6

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#7,>c=reg256#7
# asm 2: vroundpd $9,<c=%ymm6,>c=%ymm6
vroundpd $9,%ymm6,%ymm6

# qhasm: 4x a3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#7,<q=reg256#1,<a3=reg256#6
# asm 2: vfnmadd231pd <c=%ymm6,<q=%ymm0,<a3=%ymm5
vfnmadd231pd %ymm6,%ymm0,%ymm5

# qhasm: 4x r0 = approx a0 + a1
# asm 1: vaddpd <a0=reg256#3,<a1=reg256#4,>r0=reg256#7
# asm 2: vaddpd <a0=%ymm2,<a1=%ymm3,>r0=%ymm6
vaddpd %ymm2,%ymm3,%ymm6

# qhasm: 4x r2 = approx a2 + a3
# asm 1: vaddpd <a2=reg256#5,<a3=reg256#6,>r2=reg256#8
# asm 2: vaddpd <a2=%ymm4,<a3=%ymm5,>r2=%ymm7
vaddpd %ymm4,%ymm5,%ymm7

# qhasm: w = mem64[wp + 128],mem64[wp + 128],mem64[wp + 128],mem64[wp + 128]
# asm 1: vbroadcastsd 128(<wp=int64#7),>w=reg256#9
# asm 2: vbroadcastsd 128(<wp=%rax),>w=%ymm8
vbroadcastsd 128(%rax),%ymm8

# qhasm: 4x r1 = approx a0 - a1
# asm 1: vsubpd <a1=reg256#4,<a0=reg256#3,>r1=reg256#3
# asm 2: vsubpd <a1=%ymm3,<a0=%ymm2,>r1=%ymm2
vsubpd %ymm3,%ymm2,%ymm2

# qhasm: 4x r1 approx*= w
# asm 1: vmulpd <w=reg256#9,<r1=reg256#3,>r1=reg256#3
# asm 2: vmulpd <w=%ymm8,<r1=%ymm2,>r1=%ymm2
vmulpd %ymm8,%ymm2,%ymm2

# qhasm: w = mem64[wp + 136],mem64[wp + 136],mem64[wp + 136],mem64[wp + 136]
# asm 1: vbroadcastsd 136(<wp=int64#7),>w=reg256#4
# asm 2: vbroadcastsd 136(<wp=%rax),>w=%ymm3
vbroadcastsd 136(%rax),%ymm3

# qhasm: 4x r3 = approx a2 - a3
# asm 1: vsubpd <a3=reg256#6,<a2=reg256#5,>r3=reg256#5
# asm 2: vsubpd <a3=%ymm5,<a2=%ymm4,>r3=%ymm4
vsubpd %ymm5,%ymm4,%ymm4

# qhasm: 4x r3 approx*= w
# asm 1: vmulpd <w=reg256#4,<r3=reg256#5,>r3=reg256#4
# asm 2: vmulpd <w=%ymm3,<r3=%ymm4,>r3=%ymm3
vmulpd %ymm3,%ymm4,%ymm3

# qhasm: 4x a0 = approx r0 + r2
# asm 1: vaddpd <r0=reg256#7,<r2=reg256#8,>a0=reg256#5
# asm 2: vaddpd <r0=%ymm6,<r2=%ymm7,>a0=%ymm4
vaddpd %ymm6,%ymm7,%ymm4

# qhasm: 4x a1 = approx r1 + r3
# asm 1: vaddpd <r1=reg256#3,<r3=reg256#4,>a1=reg256#6
# asm 2: vaddpd <r1=%ymm2,<r3=%ymm3,>a1=%ymm5
vaddpd %ymm2,%ymm3,%ymm5

# qhasm: w = mem64[wp + 144],mem64[wp + 144],mem64[wp + 144],mem64[wp + 144]
# asm 1: vbroadcastsd 144(<wp=int64#7),>w=reg256#9
# asm 2: vbroadcastsd 144(<wp=%rax),>w=%ymm8
vbroadcastsd 144(%rax),%ymm8

# qhasm: 4x a2 = approx r0 - r2
# asm 1: vsubpd <r2=reg256#8,<r0=reg256#7,>a2=reg256#7
# asm 2: vsubpd <r2=%ymm7,<r0=%ymm6,>a2=%ymm6
vsubpd %ymm7,%ymm6,%ymm6

# qhasm: 4x a3 = approx r1 - r3
# asm 1: vsubpd <r3=reg256#4,<r1=reg256#3,>a3=reg256#3
# asm 2: vsubpd <r3=%ymm3,<r1=%ymm2,>a3=%ymm2
vsubpd %ymm3,%ymm2,%ymm2

# qhasm: 4x a2 approx*= w
# asm 1: vmulpd <w=reg256#9,<a2=reg256#7,>a2=reg256#4
# asm 2: vmulpd <w=%ymm8,<a2=%ymm6,>a2=%ymm3
vmulpd %ymm8,%ymm6,%ymm3

# qhasm: 4x c = approx a2 * qinv
# asm 1: vmulpd <a2=reg256#4,<qinv=reg256#2,>c=reg256#7
# asm 2: vmulpd <a2=%ymm3,<qinv=%ymm1,>c=%ymm6
vmulpd %ymm3,%ymm1,%ymm6

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#7,>c=reg256#7
# asm 2: vroundpd $9,<c=%ymm6,>c=%ymm6
vroundpd $9,%ymm6,%ymm6

# qhasm: 4x a2 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#7,<q=reg256#1,<a2=reg256#4
# asm 2: vfnmadd231pd <c=%ymm6,<q=%ymm0,<a2=%ymm3
vfnmadd231pd %ymm6,%ymm0,%ymm3

# qhasm: 4x a3 approx*= w
# asm 1: vmulpd <w=reg256#9,<a3=reg256#3,>a3=reg256#3
# asm 2: vmulpd <w=%ymm8,<a3=%ymm2,>a3=%ymm2
vmulpd %ymm8,%ymm2,%ymm2

# qhasm: 4x c = approx a3 * qinv
# asm 1: vmulpd <a3=reg256#3,<qinv=reg256#2,>c=reg256#7
# asm 2: vmulpd <a3=%ymm2,<qinv=%ymm1,>c=%ymm6
vmulpd %ymm2,%ymm1,%ymm6

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#7,>c=reg256#7
# asm 2: vroundpd $9,<c=%ymm6,>c=%ymm6
vroundpd $9,%ymm6,%ymm6

# qhasm: 4x a3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#7,<q=reg256#1,<a3=reg256#3
# asm 2: vfnmadd231pd <c=%ymm6,<q=%ymm0,<a3=%ymm2
vfnmadd231pd %ymm6,%ymm0,%ymm2

# qhasm: mem256[tp +  0] = a0
# asm 1: vmovupd   <a0=reg256#5,0(<tp=int64#6)
# asm 2: vmovupd   <a0=%ymm4,0(<tp=%r9)
vmovupd   %ymm4,0(%r9)

# qhasm: mem256[tp + 32] = a1
# asm 1: vmovupd   <a1=reg256#6,32(<tp=int64#6)
# asm 2: vmovupd   <a1=%ymm5,32(<tp=%r9)
vmovupd   %ymm5,32(%r9)

# qhasm: mem256[tp + 64] = a2
# asm 1: vmovupd   <a2=reg256#4,64(<tp=int64#6)
# asm 2: vmovupd   <a2=%ymm3,64(<tp=%r9)
vmovupd   %ymm3,64(%r9)

# qhasm: mem256[tp + 96] = a3
# asm 1: vmovupd   <a3=reg256#3,96(<tp=int64#6)
# asm 2: vmovupd   <a3=%ymm2,96(<tp=%r9)
vmovupd   %ymm2,96(%r9)

# qhasm: ap+= 64
# asm 1: add  $64,<ap=int64#5
# asm 2: add  $64,<ap=%r8
add  $64,%r8

# qhasm: tp+= 128
# asm 1: add  $128,<tp=int64#6
# asm 2: add  $128,<tp=%r9
add  $128,%r9

# qhasm: wp+= 152
# asm 1: add  $152,<wp=int64#7
# asm 2: add  $152,<wp=%rax
add  $152,%rax

# qhasm: pp+= 128
# asm 1: add  $128,<pp=int64#2
# asm 2: add  $128,<pp=%rsi
add  $128,%rsi

# qhasm: unsigned>? ctrj-=1
# asm 1: sub  $1,<ctrj=int64#4
# asm 2: sub  $1,<ctrj=%rcx
sub  $1,%rcx
# comment:fp stack unchanged by jump

# qhasm: goto loopinreg if unsigned>
ja ._loopinreg

# qhasm: ctri = 8
# asm 1: mov  $8,>ctri=int64#2
# asm 2: mov  $8,>ctri=%rsi
mov  $8,%rsi

# qhasm: tp = input_2
# asm 1: mov  <input_2=int64#3,>tp=int64#4
# asm 2: mov  <input_2=%rdx,>tp=%rcx
mov  %rdx,%rcx

# qhasm: ctrj = 4
# asm 1: mov  $4,>ctrj=int64#5
# asm 2: mov  $4,>ctrj=%r8
mov  $4,%r8

# qhasm: loop567jfirst:
._loop567jfirst:

# qhasm: a0 = mem256[tp + 0]
# asm 1: vmovupd   0(<tp=int64#4),>a0=reg256#3
# asm 2: vmovupd   0(<tp=%rcx),>a0=%ymm2
vmovupd   0(%rcx),%ymm2

# qhasm: a1 = mem256[tp + 128]
# asm 1: vmovupd   128(<tp=int64#4),>a1=reg256#4
# asm 2: vmovupd   128(<tp=%rcx),>a1=%ymm3
vmovupd   128(%rcx),%ymm3

# qhasm: a2 = mem256[tp + 256]
# asm 1: vmovupd   256(<tp=int64#4),>a2=reg256#5
# asm 2: vmovupd   256(<tp=%rcx),>a2=%ymm4
vmovupd   256(%rcx),%ymm4

# qhasm: a3 = mem256[tp + 384]
# asm 1: vmovupd   384(<tp=int64#4),>a3=reg256#6
# asm 2: vmovupd   384(<tp=%rcx),>a3=%ymm5
vmovupd   384(%rcx),%ymm5

# qhasm: 4x r0 = approx a0 + a1
# asm 1: vaddpd <a0=reg256#3,<a1=reg256#4,>r0=reg256#7
# asm 2: vaddpd <a0=%ymm2,<a1=%ymm3,>r0=%ymm6
vaddpd %ymm2,%ymm3,%ymm6

# qhasm: 4x r2 = approx a2 + a3
# asm 1: vaddpd <a2=reg256#5,<a3=reg256#6,>r2=reg256#8
# asm 2: vaddpd <a2=%ymm4,<a3=%ymm5,>r2=%ymm7
vaddpd %ymm4,%ymm5,%ymm7

# qhasm: 4x r1 = approx a0 - a1
# asm 1: vsubpd <a1=reg256#4,<a0=reg256#3,>r1=reg256#3
# asm 2: vsubpd <a1=%ymm3,<a0=%ymm2,>r1=%ymm2
vsubpd %ymm3,%ymm2,%ymm2

# qhasm: 4x r3 = approx a2 - a3
# asm 1: vsubpd <a3=reg256#6,<a2=reg256#5,>r3=reg256#4
# asm 2: vsubpd <a3=%ymm5,<a2=%ymm4,>r3=%ymm3
vsubpd %ymm5,%ymm4,%ymm3

# qhasm: 4x a0 = approx r0 + r2
# asm 1: vaddpd <r0=reg256#7,<r2=reg256#8,>a0=reg256#5
# asm 2: vaddpd <r0=%ymm6,<r2=%ymm7,>a0=%ymm4
vaddpd %ymm6,%ymm7,%ymm4

# qhasm: 4x a2 = approx r0 - r2
# asm 1: vsubpd <r2=reg256#8,<r0=reg256#7,>a2=reg256#6
# asm 2: vsubpd <r2=%ymm7,<r0=%ymm6,>a2=%ymm5
vsubpd %ymm7,%ymm6,%ymm5

# qhasm: w = mem64[wp + 8],mem64[wp + 8],mem64[wp + 8],mem64[wp + 8]
# asm 1: vbroadcastsd 8(<wp=int64#7),>w=reg256#7
# asm 2: vbroadcastsd 8(<wp=%rax),>w=%ymm6
vbroadcastsd 8(%rax),%ymm6

# qhasm: 4x r3 approx*= w
# asm 1: vmulpd <w=reg256#7,<r3=reg256#4,>r3=reg256#4
# asm 2: vmulpd <w=%ymm6,<r3=%ymm3,>r3=%ymm3
vmulpd %ymm6,%ymm3,%ymm3

# qhasm: 4x c = approx r3 * qinv
# asm 1: vmulpd <r3=reg256#4,<qinv=reg256#2,>c=reg256#7
# asm 2: vmulpd <r3=%ymm3,<qinv=%ymm1,>c=%ymm6
vmulpd %ymm3,%ymm1,%ymm6

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#7,>c=reg256#7
# asm 2: vroundpd $9,<c=%ymm6,>c=%ymm6
vroundpd $9,%ymm6,%ymm6

# qhasm: 4x r3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#7,<q=reg256#1,<r3=reg256#4
# asm 2: vfnmadd231pd <c=%ymm6,<q=%ymm0,<r3=%ymm3
vfnmadd231pd %ymm6,%ymm0,%ymm3

# qhasm: 4x a1 = approx r1 + r3
# asm 1: vaddpd <r1=reg256#3,<r3=reg256#4,>a1=reg256#7
# asm 2: vaddpd <r1=%ymm2,<r3=%ymm3,>a1=%ymm6
vaddpd %ymm2,%ymm3,%ymm6

# qhasm: 4x a3 = approx r1 - r3
# asm 1: vsubpd <r3=reg256#4,<r1=reg256#3,>a3=reg256#3
# asm 2: vsubpd <r3=%ymm3,<r1=%ymm2,>a3=%ymm2
vsubpd %ymm3,%ymm2,%ymm2

# qhasm: t0 = mem256[tp + 512]
# asm 1: vmovupd   512(<tp=int64#4),>t0=reg256#4
# asm 2: vmovupd   512(<tp=%rcx),>t0=%ymm3
vmovupd   512(%rcx),%ymm3

# qhasm: t1 = mem256[tp + 640]
# asm 1: vmovupd   640(<tp=int64#4),>t1=reg256#8
# asm 2: vmovupd   640(<tp=%rcx),>t1=%ymm7
vmovupd   640(%rcx),%ymm7

# qhasm: t2 = mem256[tp + 768]
# asm 1: vmovupd   768(<tp=int64#4),>t2=reg256#9
# asm 2: vmovupd   768(<tp=%rcx),>t2=%ymm8
vmovupd   768(%rcx),%ymm8

# qhasm: t3 = mem256[tp + 896]
# asm 1: vmovupd   896(<tp=int64#4),>t3=reg256#10
# asm 2: vmovupd   896(<tp=%rcx),>t3=%ymm9
vmovupd   896(%rcx),%ymm9

# qhasm: 4x r0 = approx t0 + t1
# asm 1: vaddpd <t0=reg256#4,<t1=reg256#8,>r0=reg256#11
# asm 2: vaddpd <t0=%ymm3,<t1=%ymm7,>r0=%ymm10
vaddpd %ymm3,%ymm7,%ymm10

# qhasm: 4x r2 = approx t2 + t3
# asm 1: vaddpd <t2=reg256#9,<t3=reg256#10,>r2=reg256#12
# asm 2: vaddpd <t2=%ymm8,<t3=%ymm9,>r2=%ymm11
vaddpd %ymm8,%ymm9,%ymm11

# qhasm: 4x r1 = approx t0 - t1
# asm 1: vsubpd <t1=reg256#8,<t0=reg256#4,>r1=reg256#4
# asm 2: vsubpd <t1=%ymm7,<t0=%ymm3,>r1=%ymm3
vsubpd %ymm7,%ymm3,%ymm3

# qhasm: 4x r3 = approx t2 - t3
# asm 1: vsubpd <t3=reg256#10,<t2=reg256#9,>r3=reg256#8
# asm 2: vsubpd <t3=%ymm9,<t2=%ymm8,>r3=%ymm7
vsubpd %ymm9,%ymm8,%ymm7

# qhasm: 4x t0 = approx r0 + r2
# asm 1: vaddpd <r0=reg256#11,<r2=reg256#12,>t0=reg256#9
# asm 2: vaddpd <r0=%ymm10,<r2=%ymm11,>t0=%ymm8
vaddpd %ymm10,%ymm11,%ymm8

# qhasm: 4x t2 = approx r0 - r2
# asm 1: vsubpd <r2=reg256#12,<r0=reg256#11,>t2=reg256#10
# asm 2: vsubpd <r2=%ymm11,<r0=%ymm10,>t2=%ymm9
vsubpd %ymm11,%ymm10,%ymm9

# qhasm: w = mem64[wp + 24],mem64[wp + 24],mem64[wp + 24],mem64[wp + 24]
# asm 1: vbroadcastsd 24(<wp=int64#7),>w=reg256#11
# asm 2: vbroadcastsd 24(<wp=%rax),>w=%ymm10
vbroadcastsd 24(%rax),%ymm10

# qhasm: 4x r1 approx*= w
# asm 1: vmulpd <w=reg256#11,<r1=reg256#4,>r1=reg256#4
# asm 2: vmulpd <w=%ymm10,<r1=%ymm3,>r1=%ymm3
vmulpd %ymm10,%ymm3,%ymm3

# qhasm: 4x c = approx r1 * qinv
# asm 1: vmulpd <r1=reg256#4,<qinv=reg256#2,>c=reg256#11
# asm 2: vmulpd <r1=%ymm3,<qinv=%ymm1,>c=%ymm10
vmulpd %ymm3,%ymm1,%ymm10

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#11,>c=reg256#11
# asm 2: vroundpd $9,<c=%ymm10,>c=%ymm10
vroundpd $9,%ymm10,%ymm10

# qhasm: 4x r1 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#11,<q=reg256#1,<r1=reg256#4
# asm 2: vfnmadd231pd <c=%ymm10,<q=%ymm0,<r1=%ymm3
vfnmadd231pd %ymm10,%ymm0,%ymm3

# qhasm: w = mem64[wp + 32],mem64[wp + 32],mem64[wp + 32],mem64[wp + 32]
# asm 1: vbroadcastsd 32(<wp=int64#7),>w=reg256#11
# asm 2: vbroadcastsd 32(<wp=%rax),>w=%ymm10
vbroadcastsd 32(%rax),%ymm10

# qhasm: 4x r3 approx*= w
# asm 1: vmulpd <w=reg256#11,<r3=reg256#8,>r3=reg256#8
# asm 2: vmulpd <w=%ymm10,<r3=%ymm7,>r3=%ymm7
vmulpd %ymm10,%ymm7,%ymm7

# qhasm: 4x c = approx r3 * qinv
# asm 1: vmulpd <r3=reg256#8,<qinv=reg256#2,>c=reg256#11
# asm 2: vmulpd <r3=%ymm7,<qinv=%ymm1,>c=%ymm10
vmulpd %ymm7,%ymm1,%ymm10

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#11,>c=reg256#11
# asm 2: vroundpd $9,<c=%ymm10,>c=%ymm10
vroundpd $9,%ymm10,%ymm10

# qhasm: 4x r3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#11,<q=reg256#1,<r3=reg256#8
# asm 2: vfnmadd231pd <c=%ymm10,<q=%ymm0,<r3=%ymm7
vfnmadd231pd %ymm10,%ymm0,%ymm7

# qhasm: 4x t1 = approx r1 + r3
# asm 1: vaddpd <r1=reg256#4,<r3=reg256#8,>t1=reg256#11
# asm 2: vaddpd <r1=%ymm3,<r3=%ymm7,>t1=%ymm10
vaddpd %ymm3,%ymm7,%ymm10

# qhasm: w = mem64[wp + 40],mem64[wp + 40],mem64[wp + 40],mem64[wp + 40]
# asm 1: vbroadcastsd 40(<wp=int64#7),>w=reg256#12
# asm 2: vbroadcastsd 40(<wp=%rax),>w=%ymm11
vbroadcastsd 40(%rax),%ymm11

# qhasm: 4x t3 = approx r1 - r3
# asm 1: vsubpd <r3=reg256#8,<r1=reg256#4,>t3=reg256#4
# asm 2: vsubpd <r3=%ymm7,<r1=%ymm3,>t3=%ymm3
vsubpd %ymm7,%ymm3,%ymm3

# qhasm: 4x t3 approx*= w
# asm 1: vmulpd <w=reg256#12,<t3=reg256#4,>t3=reg256#4
# asm 2: vmulpd <w=%ymm11,<t3=%ymm3,>t3=%ymm3
vmulpd %ymm11,%ymm3,%ymm3

# qhasm: 4x c = approx t3 * qinv
# asm 1: vmulpd <t3=reg256#4,<qinv=reg256#2,>c=reg256#8
# asm 2: vmulpd <t3=%ymm3,<qinv=%ymm1,>c=%ymm7
vmulpd %ymm3,%ymm1,%ymm7

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#8,>c=reg256#8
# asm 2: vroundpd $9,<c=%ymm7,>c=%ymm7
vroundpd $9,%ymm7,%ymm7

# qhasm: 4x t3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#8,<q=reg256#1,<t3=reg256#4
# asm 2: vfnmadd231pd <c=%ymm7,<q=%ymm0,<t3=%ymm3
vfnmadd231pd %ymm7,%ymm0,%ymm3

# qhasm: 4x t2 approx*= w
# asm 1: vmulpd <w=reg256#12,<t2=reg256#10,>t2=reg256#8
# asm 2: vmulpd <w=%ymm11,<t2=%ymm9,>t2=%ymm7
vmulpd %ymm11,%ymm9,%ymm7

# qhasm: 4x c = approx t2 * qinv
# asm 1: vmulpd <t2=reg256#8,<qinv=reg256#2,>c=reg256#10
# asm 2: vmulpd <t2=%ymm7,<qinv=%ymm1,>c=%ymm9
vmulpd %ymm7,%ymm1,%ymm9

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#10,>c=reg256#10
# asm 2: vroundpd $9,<c=%ymm9,>c=%ymm9
vroundpd $9,%ymm9,%ymm9

# qhasm: 4x t2 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#10,<q=reg256#1,<t2=reg256#8
# asm 2: vfnmadd231pd <c=%ymm9,<q=%ymm0,<t2=%ymm7
vfnmadd231pd %ymm9,%ymm0,%ymm7

# qhasm: 4x r0 = approx a0 + t0
# asm 1: vaddpd <a0=reg256#5,<t0=reg256#9,>r0=reg256#10
# asm 2: vaddpd <a0=%ymm4,<t0=%ymm8,>r0=%ymm9
vaddpd %ymm4,%ymm8,%ymm9

# qhasm: 4x r1 = approx a1 + t1
# asm 1: vaddpd <a1=reg256#7,<t1=reg256#11,>r1=reg256#12
# asm 2: vaddpd <a1=%ymm6,<t1=%ymm10,>r1=%ymm11
vaddpd %ymm6,%ymm10,%ymm11

# qhasm: 4x r2 = approx a2 + t2
# asm 1: vaddpd <a2=reg256#6,<t2=reg256#8,>r2=reg256#13
# asm 2: vaddpd <a2=%ymm5,<t2=%ymm7,>r2=%ymm12
vaddpd %ymm5,%ymm7,%ymm12

# qhasm: 4x r3 = approx a3 + t3
# asm 1: vaddpd <a3=reg256#3,<t3=reg256#4,>r3=reg256#14
# asm 2: vaddpd <a3=%ymm2,<t3=%ymm3,>r3=%ymm13
vaddpd %ymm2,%ymm3,%ymm13

# qhasm: 4x a0 approx-= t0
# asm 1: vsubpd <t0=reg256#9,<a0=reg256#5,>a0=reg256#5
# asm 2: vsubpd <t0=%ymm8,<a0=%ymm4,>a0=%ymm4
vsubpd %ymm8,%ymm4,%ymm4

# qhasm: 4x a1 approx-= t1
# asm 1: vsubpd <t1=reg256#11,<a1=reg256#7,>a1=reg256#7
# asm 2: vsubpd <t1=%ymm10,<a1=%ymm6,>a1=%ymm6
vsubpd %ymm10,%ymm6,%ymm6

# qhasm: 4x a2 approx-= t2
# asm 1: vsubpd <t2=reg256#8,<a2=reg256#6,>a2=reg256#6
# asm 2: vsubpd <t2=%ymm7,<a2=%ymm5,>a2=%ymm5
vsubpd %ymm7,%ymm5,%ymm5

# qhasm: 4x a3 approx-= t3
# asm 1: vsubpd <t3=reg256#4,<a3=reg256#3,>a3=reg256#3
# asm 2: vsubpd <t3=%ymm3,<a3=%ymm2,>a3=%ymm2
vsubpd %ymm3,%ymm2,%ymm2

# qhasm: mem256[tp +   0] = r0
# asm 1: vmovupd   <r0=reg256#10,0(<tp=int64#4)
# asm 2: vmovupd   <r0=%ymm9,0(<tp=%rcx)
vmovupd   %ymm9,0(%rcx)

# qhasm: mem256[tp + 128] = r1
# asm 1: vmovupd   <r1=reg256#12,128(<tp=int64#4)
# asm 2: vmovupd   <r1=%ymm11,128(<tp=%rcx)
vmovupd   %ymm11,128(%rcx)

# qhasm: mem256[tp + 256] = r2
# asm 1: vmovupd   <r2=reg256#13,256(<tp=int64#4)
# asm 2: vmovupd   <r2=%ymm12,256(<tp=%rcx)
vmovupd   %ymm12,256(%rcx)

# qhasm: mem256[tp + 384] = r3
# asm 1: vmovupd   <r3=reg256#14,384(<tp=int64#4)
# asm 2: vmovupd   <r3=%ymm13,384(<tp=%rcx)
vmovupd   %ymm13,384(%rcx)

# qhasm: mem256[tp + 512] = a0
# asm 1: vmovupd   <a0=reg256#5,512(<tp=int64#4)
# asm 2: vmovupd   <a0=%ymm4,512(<tp=%rcx)
vmovupd   %ymm4,512(%rcx)

# qhasm: mem256[tp + 640] = a1
# asm 1: vmovupd   <a1=reg256#7,640(<tp=int64#4)
# asm 2: vmovupd   <a1=%ymm6,640(<tp=%rcx)
vmovupd   %ymm6,640(%rcx)

# qhasm: mem256[tp + 768] = a2
# asm 1: vmovupd   <a2=reg256#6,768(<tp=int64#4)
# asm 2: vmovupd   <a2=%ymm5,768(<tp=%rcx)
vmovupd   %ymm5,768(%rcx)

# qhasm: mem256[tp + 896] = a3
# asm 1: vmovupd   <a3=reg256#3,896(<tp=int64#4)
# asm 2: vmovupd   <a3=%ymm2,896(<tp=%rcx)
vmovupd   %ymm2,896(%rcx)

# qhasm: tp+=32
# asm 1: add  $32,<tp=int64#4
# asm 2: add  $32,<tp=%rcx
add  $32,%rcx

# qhasm: unsigned>? ctrj-=1
# asm 1: sub  $1,<ctrj=int64#5
# asm 2: sub  $1,<ctrj=%r8
sub  $1,%r8
# comment:fp stack unchanged by jump

# qhasm: goto loop567jfirst if unsigned>
ja ._loop567jfirst

# qhasm: tp+= 896
# asm 1: add  $896,<tp=int64#4
# asm 2: add  $896,<tp=%rcx
add  $896,%rcx

# qhasm: wp+= 56
# asm 1: add  $56,<wp=int64#7
# asm 2: add  $56,<wp=%rax
add  $56,%rax

# qhasm: ctri-=1
# asm 1: sub  $1,<ctri=int64#2
# asm 2: sub  $1,<ctri=%rsi
sub  $1,%rsi

# qhasm: loop567i:
._loop567i:

# qhasm: ctrj = 4
# asm 1: mov  $4,>ctrj=int64#5
# asm 2: mov  $4,>ctrj=%r8
mov  $4,%r8

# qhasm: loop567j:
._loop567j:

# qhasm: a0 = mem256[tp + 0]
# asm 1: vmovupd   0(<tp=int64#4),>a0=reg256#3
# asm 2: vmovupd   0(<tp=%rcx),>a0=%ymm2
vmovupd   0(%rcx),%ymm2

# qhasm: a1 = mem256[tp + 128]
# asm 1: vmovupd   128(<tp=int64#4),>a1=reg256#4
# asm 2: vmovupd   128(<tp=%rcx),>a1=%ymm3
vmovupd   128(%rcx),%ymm3

# qhasm: a2 = mem256[tp + 256]
# asm 1: vmovupd   256(<tp=int64#4),>a2=reg256#5
# asm 2: vmovupd   256(<tp=%rcx),>a2=%ymm4
vmovupd   256(%rcx),%ymm4

# qhasm: a3 = mem256[tp + 384]
# asm 1: vmovupd   384(<tp=int64#4),>a3=reg256#6
# asm 2: vmovupd   384(<tp=%rcx),>a3=%ymm5
vmovupd   384(%rcx),%ymm5

# qhasm: 4x r0 = approx a0 + a1
# asm 1: vaddpd <a0=reg256#3,<a1=reg256#4,>r0=reg256#7
# asm 2: vaddpd <a0=%ymm2,<a1=%ymm3,>r0=%ymm6
vaddpd %ymm2,%ymm3,%ymm6

# qhasm: 4x r2 = approx a2 + a3
# asm 1: vaddpd <a2=reg256#5,<a3=reg256#6,>r2=reg256#8
# asm 2: vaddpd <a2=%ymm4,<a3=%ymm5,>r2=%ymm7
vaddpd %ymm4,%ymm5,%ymm7

# qhasm: 4x r1 = approx a0 - a1
# asm 1: vsubpd <a1=reg256#4,<a0=reg256#3,>r1=reg256#3
# asm 2: vsubpd <a1=%ymm3,<a0=%ymm2,>r1=%ymm2
vsubpd %ymm3,%ymm2,%ymm2

# qhasm: 4x r3 = approx a2 - a3
# asm 1: vsubpd <a3=reg256#6,<a2=reg256#5,>r3=reg256#4
# asm 2: vsubpd <a3=%ymm5,<a2=%ymm4,>r3=%ymm3
vsubpd %ymm5,%ymm4,%ymm3

# qhasm: 4x a0 = approx r0 + r2
# asm 1: vaddpd <r0=reg256#7,<r2=reg256#8,>a0=reg256#5
# asm 2: vaddpd <r0=%ymm6,<r2=%ymm7,>a0=%ymm4
vaddpd %ymm6,%ymm7,%ymm4

# qhasm: 4x a2 = approx r0 - r2
# asm 1: vsubpd <r2=reg256#8,<r0=reg256#7,>a2=reg256#6
# asm 2: vsubpd <r2=%ymm7,<r0=%ymm6,>a2=%ymm5
vsubpd %ymm7,%ymm6,%ymm5

# qhasm: w = mem64[wp + 0],mem64[wp + 0],mem64[wp + 0],mem64[wp + 0]
# asm 1: vbroadcastsd 0(<wp=int64#7),>w=reg256#7
# asm 2: vbroadcastsd 0(<wp=%rax),>w=%ymm6
vbroadcastsd 0(%rax),%ymm6

# qhasm: 4x r1 approx*= w
# asm 1: vmulpd <w=reg256#7,<r1=reg256#3,>r1=reg256#3
# asm 2: vmulpd <w=%ymm6,<r1=%ymm2,>r1=%ymm2
vmulpd %ymm6,%ymm2,%ymm2

# qhasm: 4x c = approx r1 * qinv
# asm 1: vmulpd <r1=reg256#3,<qinv=reg256#2,>c=reg256#7
# asm 2: vmulpd <r1=%ymm2,<qinv=%ymm1,>c=%ymm6
vmulpd %ymm2,%ymm1,%ymm6

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#7,>c=reg256#7
# asm 2: vroundpd $9,<c=%ymm6,>c=%ymm6
vroundpd $9,%ymm6,%ymm6

# qhasm: 4x r1 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#7,<q=reg256#1,<r1=reg256#3
# asm 2: vfnmadd231pd <c=%ymm6,<q=%ymm0,<r1=%ymm2
vfnmadd231pd %ymm6,%ymm0,%ymm2

# qhasm: w = mem64[wp + 8],mem64[wp + 8],mem64[wp + 8],mem64[wp + 8]
# asm 1: vbroadcastsd 8(<wp=int64#7),>w=reg256#7
# asm 2: vbroadcastsd 8(<wp=%rax),>w=%ymm6
vbroadcastsd 8(%rax),%ymm6

# qhasm: 4x r3 approx*= w
# asm 1: vmulpd <w=reg256#7,<r3=reg256#4,>r3=reg256#4
# asm 2: vmulpd <w=%ymm6,<r3=%ymm3,>r3=%ymm3
vmulpd %ymm6,%ymm3,%ymm3

# qhasm: 4x c = approx r3 * qinv
# asm 1: vmulpd <r3=reg256#4,<qinv=reg256#2,>c=reg256#7
# asm 2: vmulpd <r3=%ymm3,<qinv=%ymm1,>c=%ymm6
vmulpd %ymm3,%ymm1,%ymm6

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#7,>c=reg256#7
# asm 2: vroundpd $9,<c=%ymm6,>c=%ymm6
vroundpd $9,%ymm6,%ymm6

# qhasm: 4x r3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#7,<q=reg256#1,<r3=reg256#4
# asm 2: vfnmadd231pd <c=%ymm6,<q=%ymm0,<r3=%ymm3
vfnmadd231pd %ymm6,%ymm0,%ymm3

# qhasm: 4x a1 = approx r1 + r3
# asm 1: vaddpd <r1=reg256#3,<r3=reg256#4,>a1=reg256#7
# asm 2: vaddpd <r1=%ymm2,<r3=%ymm3,>a1=%ymm6
vaddpd %ymm2,%ymm3,%ymm6

# qhasm: 4x a3 = approx r1 - r3
# asm 1: vsubpd <r3=reg256#4,<r1=reg256#3,>a3=reg256#3
# asm 2: vsubpd <r3=%ymm3,<r1=%ymm2,>a3=%ymm2
vsubpd %ymm3,%ymm2,%ymm2

# qhasm: w = mem64[wp + 16],mem64[wp + 16],mem64[wp + 16],mem64[wp + 16]
# asm 1: vbroadcastsd 16(<wp=int64#7),>w=reg256#4
# asm 2: vbroadcastsd 16(<wp=%rax),>w=%ymm3
vbroadcastsd 16(%rax),%ymm3

# qhasm: 4x a3 approx*= w
# asm 1: vmulpd <w=reg256#4,<a3=reg256#3,>a3=reg256#3
# asm 2: vmulpd <w=%ymm3,<a3=%ymm2,>a3=%ymm2
vmulpd %ymm3,%ymm2,%ymm2

# qhasm: 4x c = approx a3 * qinv
# asm 1: vmulpd <a3=reg256#3,<qinv=reg256#2,>c=reg256#8
# asm 2: vmulpd <a3=%ymm2,<qinv=%ymm1,>c=%ymm7
vmulpd %ymm2,%ymm1,%ymm7

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#8,>c=reg256#8
# asm 2: vroundpd $9,<c=%ymm7,>c=%ymm7
vroundpd $9,%ymm7,%ymm7

# qhasm: 4x a3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#8,<q=reg256#1,<a3=reg256#3
# asm 2: vfnmadd231pd <c=%ymm7,<q=%ymm0,<a3=%ymm2
vfnmadd231pd %ymm7,%ymm0,%ymm2

# qhasm: 4x a2 approx*= w
# asm 1: vmulpd <w=reg256#4,<a2=reg256#6,>a2=reg256#4
# asm 2: vmulpd <w=%ymm3,<a2=%ymm5,>a2=%ymm3
vmulpd %ymm3,%ymm5,%ymm3

# qhasm: 4x c = approx a2 * qinv
# asm 1: vmulpd <a2=reg256#4,<qinv=reg256#2,>c=reg256#6
# asm 2: vmulpd <a2=%ymm3,<qinv=%ymm1,>c=%ymm5
vmulpd %ymm3,%ymm1,%ymm5

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#6,>c=reg256#6
# asm 2: vroundpd $9,<c=%ymm5,>c=%ymm5
vroundpd $9,%ymm5,%ymm5

# qhasm: 4x a2 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#6,<q=reg256#1,<a2=reg256#4
# asm 2: vfnmadd231pd <c=%ymm5,<q=%ymm0,<a2=%ymm3
vfnmadd231pd %ymm5,%ymm0,%ymm3

# qhasm: t0 = mem256[tp + 512]
# asm 1: vmovupd   512(<tp=int64#4),>t0=reg256#6
# asm 2: vmovupd   512(<tp=%rcx),>t0=%ymm5
vmovupd   512(%rcx),%ymm5

# qhasm: t1 = mem256[tp + 640]
# asm 1: vmovupd   640(<tp=int64#4),>t1=reg256#8
# asm 2: vmovupd   640(<tp=%rcx),>t1=%ymm7
vmovupd   640(%rcx),%ymm7

# qhasm: t2 = mem256[tp + 768]
# asm 1: vmovupd   768(<tp=int64#4),>t2=reg256#9
# asm 2: vmovupd   768(<tp=%rcx),>t2=%ymm8
vmovupd   768(%rcx),%ymm8

# qhasm: t3 = mem256[tp + 896]
# asm 1: vmovupd   896(<tp=int64#4),>t3=reg256#10
# asm 2: vmovupd   896(<tp=%rcx),>t3=%ymm9
vmovupd   896(%rcx),%ymm9

# qhasm: 4x r0 = approx t0 + t1
# asm 1: vaddpd <t0=reg256#6,<t1=reg256#8,>r0=reg256#11
# asm 2: vaddpd <t0=%ymm5,<t1=%ymm7,>r0=%ymm10
vaddpd %ymm5,%ymm7,%ymm10

# qhasm: 4x r2 = approx t2 + t3
# asm 1: vaddpd <t2=reg256#9,<t3=reg256#10,>r2=reg256#12
# asm 2: vaddpd <t2=%ymm8,<t3=%ymm9,>r2=%ymm11
vaddpd %ymm8,%ymm9,%ymm11

# qhasm: 4x r1 = approx t0 - t1
# asm 1: vsubpd <t1=reg256#8,<t0=reg256#6,>r1=reg256#6
# asm 2: vsubpd <t1=%ymm7,<t0=%ymm5,>r1=%ymm5
vsubpd %ymm7,%ymm5,%ymm5

# qhasm: 4x r3 = approx t2 - t3
# asm 1: vsubpd <t3=reg256#10,<t2=reg256#9,>r3=reg256#8
# asm 2: vsubpd <t3=%ymm9,<t2=%ymm8,>r3=%ymm7
vsubpd %ymm9,%ymm8,%ymm7

# qhasm: 4x t0 = approx r0 + r2
# asm 1: vaddpd <r0=reg256#11,<r2=reg256#12,>t0=reg256#9
# asm 2: vaddpd <r0=%ymm10,<r2=%ymm11,>t0=%ymm8
vaddpd %ymm10,%ymm11,%ymm8

# qhasm: 4x t2 = approx r0 - r2
# asm 1: vsubpd <r2=reg256#12,<r0=reg256#11,>t2=reg256#10
# asm 2: vsubpd <r2=%ymm11,<r0=%ymm10,>t2=%ymm9
vsubpd %ymm11,%ymm10,%ymm9

# qhasm: w = mem64[wp + 24],mem64[wp + 24],mem64[wp + 24],mem64[wp + 24]
# asm 1: vbroadcastsd 24(<wp=int64#7),>w=reg256#11
# asm 2: vbroadcastsd 24(<wp=%rax),>w=%ymm10
vbroadcastsd 24(%rax),%ymm10

# qhasm: 4x r1 approx*= w
# asm 1: vmulpd <w=reg256#11,<r1=reg256#6,>r1=reg256#6
# asm 2: vmulpd <w=%ymm10,<r1=%ymm5,>r1=%ymm5
vmulpd %ymm10,%ymm5,%ymm5

# qhasm: 4x c = approx r1 * qinv
# asm 1: vmulpd <r1=reg256#6,<qinv=reg256#2,>c=reg256#11
# asm 2: vmulpd <r1=%ymm5,<qinv=%ymm1,>c=%ymm10
vmulpd %ymm5,%ymm1,%ymm10

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#11,>c=reg256#11
# asm 2: vroundpd $9,<c=%ymm10,>c=%ymm10
vroundpd $9,%ymm10,%ymm10

# qhasm: 4x r1 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#11,<q=reg256#1,<r1=reg256#6
# asm 2: vfnmadd231pd <c=%ymm10,<q=%ymm0,<r1=%ymm5
vfnmadd231pd %ymm10,%ymm0,%ymm5

# qhasm: w = mem64[wp + 32],mem64[wp + 32],mem64[wp + 32],mem64[wp + 32]
# asm 1: vbroadcastsd 32(<wp=int64#7),>w=reg256#11
# asm 2: vbroadcastsd 32(<wp=%rax),>w=%ymm10
vbroadcastsd 32(%rax),%ymm10

# qhasm: 4x r3 approx*= w
# asm 1: vmulpd <w=reg256#11,<r3=reg256#8,>r3=reg256#8
# asm 2: vmulpd <w=%ymm10,<r3=%ymm7,>r3=%ymm7
vmulpd %ymm10,%ymm7,%ymm7

# qhasm: 4x c = approx r3 * qinv
# asm 1: vmulpd <r3=reg256#8,<qinv=reg256#2,>c=reg256#11
# asm 2: vmulpd <r3=%ymm7,<qinv=%ymm1,>c=%ymm10
vmulpd %ymm7,%ymm1,%ymm10

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#11,>c=reg256#11
# asm 2: vroundpd $9,<c=%ymm10,>c=%ymm10
vroundpd $9,%ymm10,%ymm10

# qhasm: 4x r3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#11,<q=reg256#1,<r3=reg256#8
# asm 2: vfnmadd231pd <c=%ymm10,<q=%ymm0,<r3=%ymm7
vfnmadd231pd %ymm10,%ymm0,%ymm7

# qhasm: 4x t1 = approx r1 + r3
# asm 1: vaddpd <r1=reg256#6,<r3=reg256#8,>t1=reg256#11
# asm 2: vaddpd <r1=%ymm5,<r3=%ymm7,>t1=%ymm10
vaddpd %ymm5,%ymm7,%ymm10

# qhasm: w = mem64[wp + 40],mem64[wp + 40],mem64[wp + 40],mem64[wp + 40]
# asm 1: vbroadcastsd 40(<wp=int64#7),>w=reg256#12
# asm 2: vbroadcastsd 40(<wp=%rax),>w=%ymm11
vbroadcastsd 40(%rax),%ymm11

# qhasm: 4x t3 = approx r1 - r3
# asm 1: vsubpd <r3=reg256#8,<r1=reg256#6,>t3=reg256#6
# asm 2: vsubpd <r3=%ymm7,<r1=%ymm5,>t3=%ymm5
vsubpd %ymm7,%ymm5,%ymm5

# qhasm: 4x t3 approx*= w
# asm 1: vmulpd <w=reg256#12,<t3=reg256#6,>t3=reg256#6
# asm 2: vmulpd <w=%ymm11,<t3=%ymm5,>t3=%ymm5
vmulpd %ymm11,%ymm5,%ymm5

# qhasm: 4x c = approx t3 * qinv
# asm 1: vmulpd <t3=reg256#6,<qinv=reg256#2,>c=reg256#8
# asm 2: vmulpd <t3=%ymm5,<qinv=%ymm1,>c=%ymm7
vmulpd %ymm5,%ymm1,%ymm7

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#8,>c=reg256#8
# asm 2: vroundpd $9,<c=%ymm7,>c=%ymm7
vroundpd $9,%ymm7,%ymm7

# qhasm: 4x t3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#8,<q=reg256#1,<t3=reg256#6
# asm 2: vfnmadd231pd <c=%ymm7,<q=%ymm0,<t3=%ymm5
vfnmadd231pd %ymm7,%ymm0,%ymm5

# qhasm: 4x t2 approx*= w
# asm 1: vmulpd <w=reg256#12,<t2=reg256#10,>t2=reg256#8
# asm 2: vmulpd <w=%ymm11,<t2=%ymm9,>t2=%ymm7
vmulpd %ymm11,%ymm9,%ymm7

# qhasm: 4x c = approx t2 * qinv
# asm 1: vmulpd <t2=reg256#8,<qinv=reg256#2,>c=reg256#10
# asm 2: vmulpd <t2=%ymm7,<qinv=%ymm1,>c=%ymm9
vmulpd %ymm7,%ymm1,%ymm9

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#10,>c=reg256#10
# asm 2: vroundpd $9,<c=%ymm9,>c=%ymm9
vroundpd $9,%ymm9,%ymm9

# qhasm: 4x t2 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#10,<q=reg256#1,<t2=reg256#8
# asm 2: vfnmadd231pd <c=%ymm9,<q=%ymm0,<t2=%ymm7
vfnmadd231pd %ymm9,%ymm0,%ymm7

# qhasm: 4x r0 = approx a0 + t0
# asm 1: vaddpd <a0=reg256#5,<t0=reg256#9,>r0=reg256#10
# asm 2: vaddpd <a0=%ymm4,<t0=%ymm8,>r0=%ymm9
vaddpd %ymm4,%ymm8,%ymm9

# qhasm: 4x r1 = approx a1 + t1
# asm 1: vaddpd <a1=reg256#7,<t1=reg256#11,>r1=reg256#12
# asm 2: vaddpd <a1=%ymm6,<t1=%ymm10,>r1=%ymm11
vaddpd %ymm6,%ymm10,%ymm11

# qhasm: 4x r2 = approx a2 + t2
# asm 1: vaddpd <a2=reg256#4,<t2=reg256#8,>r2=reg256#13
# asm 2: vaddpd <a2=%ymm3,<t2=%ymm7,>r2=%ymm12
vaddpd %ymm3,%ymm7,%ymm12

# qhasm: 4x r3 = approx a3 + t3
# asm 1: vaddpd <a3=reg256#3,<t3=reg256#6,>r3=reg256#14
# asm 2: vaddpd <a3=%ymm2,<t3=%ymm5,>r3=%ymm13
vaddpd %ymm2,%ymm5,%ymm13

# qhasm: 4x a0 approx-= t0
# asm 1: vsubpd <t0=reg256#9,<a0=reg256#5,>a0=reg256#5
# asm 2: vsubpd <t0=%ymm8,<a0=%ymm4,>a0=%ymm4
vsubpd %ymm8,%ymm4,%ymm4

# qhasm: 4x a1 approx-= t1
# asm 1: vsubpd <t1=reg256#11,<a1=reg256#7,>a1=reg256#7
# asm 2: vsubpd <t1=%ymm10,<a1=%ymm6,>a1=%ymm6
vsubpd %ymm10,%ymm6,%ymm6

# qhasm: 4x a2 approx-= t2
# asm 1: vsubpd <t2=reg256#8,<a2=reg256#4,>a2=reg256#4
# asm 2: vsubpd <t2=%ymm7,<a2=%ymm3,>a2=%ymm3
vsubpd %ymm7,%ymm3,%ymm3

# qhasm: 4x a3 approx-= t3
# asm 1: vsubpd <t3=reg256#6,<a3=reg256#3,>a3=reg256#3
# asm 2: vsubpd <t3=%ymm5,<a3=%ymm2,>a3=%ymm2
vsubpd %ymm5,%ymm2,%ymm2

# qhasm: w = mem64[wp + 48],mem64[wp + 48],mem64[wp + 48],mem64[wp + 48]
# asm 1: vbroadcastsd 48(<wp=int64#7),>w=reg256#6
# asm 2: vbroadcastsd 48(<wp=%rax),>w=%ymm5
vbroadcastsd 48(%rax),%ymm5

# qhasm: 4x a0 approx*= w
# asm 1: vmulpd <w=reg256#6,<a0=reg256#5,>a0=reg256#5
# asm 2: vmulpd <w=%ymm5,<a0=%ymm4,>a0=%ymm4
vmulpd %ymm5,%ymm4,%ymm4

# qhasm: 4x a1 approx*= w
# asm 1: vmulpd <w=reg256#6,<a1=reg256#7,>a1=reg256#7
# asm 2: vmulpd <w=%ymm5,<a1=%ymm6,>a1=%ymm6
vmulpd %ymm5,%ymm6,%ymm6

# qhasm: 4x a2 approx*= w
# asm 1: vmulpd <w=reg256#6,<a2=reg256#4,>a2=reg256#4
# asm 2: vmulpd <w=%ymm5,<a2=%ymm3,>a2=%ymm3
vmulpd %ymm5,%ymm3,%ymm3

# qhasm: 4x a3 approx*= w
# asm 1: vmulpd <w=reg256#6,<a3=reg256#3,>a3=reg256#3
# asm 2: vmulpd <w=%ymm5,<a3=%ymm2,>a3=%ymm2
vmulpd %ymm5,%ymm2,%ymm2

# qhasm: 4x c = approx a0 * qinv
# asm 1: vmulpd <a0=reg256#5,<qinv=reg256#2,>c=reg256#6
# asm 2: vmulpd <a0=%ymm4,<qinv=%ymm1,>c=%ymm5
vmulpd %ymm4,%ymm1,%ymm5

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#6,>c=reg256#6
# asm 2: vroundpd $9,<c=%ymm5,>c=%ymm5
vroundpd $9,%ymm5,%ymm5

# qhasm: 4x a0 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#6,<q=reg256#1,<a0=reg256#5
# asm 2: vfnmadd231pd <c=%ymm5,<q=%ymm0,<a0=%ymm4
vfnmadd231pd %ymm5,%ymm0,%ymm4

# qhasm: 4x c = approx a1 * qinv
# asm 1: vmulpd <a1=reg256#7,<qinv=reg256#2,>c=reg256#6
# asm 2: vmulpd <a1=%ymm6,<qinv=%ymm1,>c=%ymm5
vmulpd %ymm6,%ymm1,%ymm5

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#6,>c=reg256#6
# asm 2: vroundpd $9,<c=%ymm5,>c=%ymm5
vroundpd $9,%ymm5,%ymm5

# qhasm: 4x a1 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#6,<q=reg256#1,<a1=reg256#7
# asm 2: vfnmadd231pd <c=%ymm5,<q=%ymm0,<a1=%ymm6
vfnmadd231pd %ymm5,%ymm0,%ymm6

# qhasm: 4x c = approx a2 * qinv
# asm 1: vmulpd <a2=reg256#4,<qinv=reg256#2,>c=reg256#6
# asm 2: vmulpd <a2=%ymm3,<qinv=%ymm1,>c=%ymm5
vmulpd %ymm3,%ymm1,%ymm5

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#6,>c=reg256#6
# asm 2: vroundpd $9,<c=%ymm5,>c=%ymm5
vroundpd $9,%ymm5,%ymm5

# qhasm: 4x a2 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#6,<q=reg256#1,<a2=reg256#4
# asm 2: vfnmadd231pd <c=%ymm5,<q=%ymm0,<a2=%ymm3
vfnmadd231pd %ymm5,%ymm0,%ymm3

# qhasm: 4x c = approx a3 * qinv
# asm 1: vmulpd <a3=reg256#3,<qinv=reg256#2,>c=reg256#6
# asm 2: vmulpd <a3=%ymm2,<qinv=%ymm1,>c=%ymm5
vmulpd %ymm2,%ymm1,%ymm5

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#6,>c=reg256#6
# asm 2: vroundpd $9,<c=%ymm5,>c=%ymm5
vroundpd $9,%ymm5,%ymm5

# qhasm: 4x a3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#6,<q=reg256#1,<a3=reg256#3
# asm 2: vfnmadd231pd <c=%ymm5,<q=%ymm0,<a3=%ymm2
vfnmadd231pd %ymm5,%ymm0,%ymm2

# qhasm: mem256[tp +   0] = r0
# asm 1: vmovupd   <r0=reg256#10,0(<tp=int64#4)
# asm 2: vmovupd   <r0=%ymm9,0(<tp=%rcx)
vmovupd   %ymm9,0(%rcx)

# qhasm: mem256[tp + 128] = r1
# asm 1: vmovupd   <r1=reg256#12,128(<tp=int64#4)
# asm 2: vmovupd   <r1=%ymm11,128(<tp=%rcx)
vmovupd   %ymm11,128(%rcx)

# qhasm: mem256[tp + 256] = r2
# asm 1: vmovupd   <r2=reg256#13,256(<tp=int64#4)
# asm 2: vmovupd   <r2=%ymm12,256(<tp=%rcx)
vmovupd   %ymm12,256(%rcx)

# qhasm: mem256[tp + 384] = r3
# asm 1: vmovupd   <r3=reg256#14,384(<tp=int64#4)
# asm 2: vmovupd   <r3=%ymm13,384(<tp=%rcx)
vmovupd   %ymm13,384(%rcx)

# qhasm: mem256[tp + 512] = a0
# asm 1: vmovupd   <a0=reg256#5,512(<tp=int64#4)
# asm 2: vmovupd   <a0=%ymm4,512(<tp=%rcx)
vmovupd   %ymm4,512(%rcx)

# qhasm: mem256[tp + 640] = a1
# asm 1: vmovupd   <a1=reg256#7,640(<tp=int64#4)
# asm 2: vmovupd   <a1=%ymm6,640(<tp=%rcx)
vmovupd   %ymm6,640(%rcx)

# qhasm: mem256[tp + 768] = a2
# asm 1: vmovupd   <a2=reg256#4,768(<tp=int64#4)
# asm 2: vmovupd   <a2=%ymm3,768(<tp=%rcx)
vmovupd   %ymm3,768(%rcx)

# qhasm: mem256[tp + 896] = a3
# asm 1: vmovupd   <a3=reg256#3,896(<tp=int64#4)
# asm 2: vmovupd   <a3=%ymm2,896(<tp=%rcx)
vmovupd   %ymm2,896(%rcx)

# qhasm: tp+=32
# asm 1: add  $32,<tp=int64#4
# asm 2: add  $32,<tp=%rcx
add  $32,%rcx

# qhasm: unsigned>? ctrj-=1
# asm 1: sub  $1,<ctrj=int64#5
# asm 2: sub  $1,<ctrj=%r8
sub  $1,%r8
# comment:fp stack unchanged by jump

# qhasm: goto loop567j if unsigned>
ja ._loop567j

# qhasm: tp+= 896
# asm 1: add  $896,<tp=int64#4
# asm 2: add  $896,<tp=%rcx
add  $896,%rcx

# qhasm: wp+= 56
# asm 1: add  $56,<wp=int64#7
# asm 2: add  $56,<wp=%rax
add  $56,%rax

# qhasm: unsigned>? ctri-=1
# asm 1: sub  $1,<ctri=int64#2
# asm 2: sub  $1,<ctri=%rsi
sub  $1,%rsi
# comment:fp stack unchanged by jump

# qhasm: goto loop567i if unsigned>
ja ._loop567i

# qhasm: ctrj = 32
# asm 1: mov  $32,>ctrj=int64#2
# asm 2: mov  $32,>ctrj=%rsi
mov  $32,%rsi

# qhasm: tp = input_2
# asm 1: mov  <input_2=int64#3,>tp=int64#3
# asm 2: mov  <input_2=%rdx,>tp=%rdx
mov  %rdx,%rdx

# qhasm: ap = input_0
# asm 1: mov  <input_0=int64#1,>ap=int64#1
# asm 2: mov  <input_0=%rdi,>ap=%rdi
mov  %rdi,%rdi

# qhasm: loop8910j:
._loop8910j:

# qhasm: a0 = mem256[tp + 0]
# asm 1: vmovupd   0(<tp=int64#3),>a0=reg256#3
# asm 2: vmovupd   0(<tp=%rdx),>a0=%ymm2
vmovupd   0(%rdx),%ymm2

# qhasm: a1 = mem256[tp + 1024]
# asm 1: vmovupd   1024(<tp=int64#3),>a1=reg256#4
# asm 2: vmovupd   1024(<tp=%rdx),>a1=%ymm3
vmovupd   1024(%rdx),%ymm3

# qhasm: a2 = mem256[tp + 2048]
# asm 1: vmovupd   2048(<tp=int64#3),>a2=reg256#5
# asm 2: vmovupd   2048(<tp=%rdx),>a2=%ymm4
vmovupd   2048(%rdx),%ymm4

# qhasm: a3 = mem256[tp + 3072]
# asm 1: vmovupd   3072(<tp=int64#3),>a3=reg256#6
# asm 2: vmovupd   3072(<tp=%rdx),>a3=%ymm5
vmovupd   3072(%rdx),%ymm5

# qhasm: 4x r0 = approx a0 + a1
# asm 1: vaddpd <a0=reg256#3,<a1=reg256#4,>r0=reg256#7
# asm 2: vaddpd <a0=%ymm2,<a1=%ymm3,>r0=%ymm6
vaddpd %ymm2,%ymm3,%ymm6

# qhasm: 4x r2 = approx a2 + a3
# asm 1: vaddpd <a2=reg256#5,<a3=reg256#6,>r2=reg256#8
# asm 2: vaddpd <a2=%ymm4,<a3=%ymm5,>r2=%ymm7
vaddpd %ymm4,%ymm5,%ymm7

# qhasm: 4x r1 = approx a0 - a1
# asm 1: vsubpd <a1=reg256#4,<a0=reg256#3,>r1=reg256#3
# asm 2: vsubpd <a1=%ymm3,<a0=%ymm2,>r1=%ymm2
vsubpd %ymm3,%ymm2,%ymm2

# qhasm: 4x r3 = approx a2 - a3
# asm 1: vsubpd <a3=reg256#6,<a2=reg256#5,>r3=reg256#4
# asm 2: vsubpd <a3=%ymm5,<a2=%ymm4,>r3=%ymm3
vsubpd %ymm5,%ymm4,%ymm3

# qhasm: 4x a0 = approx r0 + r2
# asm 1: vaddpd <r0=reg256#7,<r2=reg256#8,>a0=reg256#5
# asm 2: vaddpd <r0=%ymm6,<r2=%ymm7,>a0=%ymm4
vaddpd %ymm6,%ymm7,%ymm4

# qhasm: 4x a2 = approx r0 - r2
# asm 1: vsubpd <r2=reg256#8,<r0=reg256#7,>a2=reg256#6
# asm 2: vsubpd <r2=%ymm7,<r0=%ymm6,>a2=%ymm5
vsubpd %ymm7,%ymm6,%ymm5

# qhasm: w = mem64[wp + 0],mem64[wp + 0],mem64[wp + 0],mem64[wp + 0]
# asm 1: vbroadcastsd 0(<wp=int64#7),>w=reg256#7
# asm 2: vbroadcastsd 0(<wp=%rax),>w=%ymm6
vbroadcastsd 0(%rax),%ymm6

# qhasm: 4x r3 approx*= w
# asm 1: vmulpd <w=reg256#7,<r3=reg256#4,>r3=reg256#4
# asm 2: vmulpd <w=%ymm6,<r3=%ymm3,>r3=%ymm3
vmulpd %ymm6,%ymm3,%ymm3

# qhasm: 4x a1 = approx r1 + r3
# asm 1: vaddpd <r1=reg256#3,<r3=reg256#4,>a1=reg256#7
# asm 2: vaddpd <r1=%ymm2,<r3=%ymm3,>a1=%ymm6
vaddpd %ymm2,%ymm3,%ymm6

# qhasm: 4x a3 = approx r1 - r3
# asm 1: vsubpd <r3=reg256#4,<r1=reg256#3,>a3=reg256#3
# asm 2: vsubpd <r3=%ymm3,<r1=%ymm2,>a3=%ymm2
vsubpd %ymm3,%ymm2,%ymm2

# qhasm: t0 = mem256[tp + 4096]
# asm 1: vmovupd   4096(<tp=int64#3),>t0=reg256#4
# asm 2: vmovupd   4096(<tp=%rdx),>t0=%ymm3
vmovupd   4096(%rdx),%ymm3

# qhasm: t1 = mem256[tp + 5120]
# asm 1: vmovupd   5120(<tp=int64#3),>t1=reg256#8
# asm 2: vmovupd   5120(<tp=%rdx),>t1=%ymm7
vmovupd   5120(%rdx),%ymm7

# qhasm: t2 = mem256[tp + 6144]
# asm 1: vmovupd   6144(<tp=int64#3),>t2=reg256#9
# asm 2: vmovupd   6144(<tp=%rdx),>t2=%ymm8
vmovupd   6144(%rdx),%ymm8

# qhasm: t3 = mem256[tp + 7168]
# asm 1: vmovupd   7168(<tp=int64#3),>t3=reg256#10
# asm 2: vmovupd   7168(<tp=%rdx),>t3=%ymm9
vmovupd   7168(%rdx),%ymm9

# qhasm: 4x r0 = approx t0 + t1
# asm 1: vaddpd <t0=reg256#4,<t1=reg256#8,>r0=reg256#11
# asm 2: vaddpd <t0=%ymm3,<t1=%ymm7,>r0=%ymm10
vaddpd %ymm3,%ymm7,%ymm10

# qhasm: 4x r2 = approx t2 + t3
# asm 1: vaddpd <t2=reg256#9,<t3=reg256#10,>r2=reg256#12
# asm 2: vaddpd <t2=%ymm8,<t3=%ymm9,>r2=%ymm11
vaddpd %ymm8,%ymm9,%ymm11

# qhasm: 4x r1 = approx t0 - t1
# asm 1: vsubpd <t1=reg256#8,<t0=reg256#4,>r1=reg256#4
# asm 2: vsubpd <t1=%ymm7,<t0=%ymm3,>r1=%ymm3
vsubpd %ymm7,%ymm3,%ymm3

# qhasm: 4x r3 = approx t2 - t3
# asm 1: vsubpd <t3=reg256#10,<t2=reg256#9,>r3=reg256#8
# asm 2: vsubpd <t3=%ymm9,<t2=%ymm8,>r3=%ymm7
vsubpd %ymm9,%ymm8,%ymm7

# qhasm: 4x t0 = approx r0 + r2
# asm 1: vaddpd <r0=reg256#11,<r2=reg256#12,>t0=reg256#9
# asm 2: vaddpd <r0=%ymm10,<r2=%ymm11,>t0=%ymm8
vaddpd %ymm10,%ymm11,%ymm8

# qhasm: 4x t2 = approx r0 - r2
# asm 1: vsubpd <r2=reg256#12,<r0=reg256#11,>t2=reg256#10
# asm 2: vsubpd <r2=%ymm11,<r0=%ymm10,>t2=%ymm9
vsubpd %ymm11,%ymm10,%ymm9

# qhasm: w = mem64[wp + 8],mem64[wp + 8],mem64[wp + 8],mem64[wp + 8]
# asm 1: vbroadcastsd 8(<wp=int64#7),>w=reg256#11
# asm 2: vbroadcastsd 8(<wp=%rax),>w=%ymm10
vbroadcastsd 8(%rax),%ymm10

# qhasm: 4x r1 approx*= w
# asm 1: vmulpd <w=reg256#11,<r1=reg256#4,>r1=reg256#4
# asm 2: vmulpd <w=%ymm10,<r1=%ymm3,>r1=%ymm3
vmulpd %ymm10,%ymm3,%ymm3

# qhasm: 4x c = approx r1 * qinv
# asm 1: vmulpd <r1=reg256#4,<qinv=reg256#2,>c=reg256#11
# asm 2: vmulpd <r1=%ymm3,<qinv=%ymm1,>c=%ymm10
vmulpd %ymm3,%ymm1,%ymm10

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#11,>c=reg256#11
# asm 2: vroundpd $9,<c=%ymm10,>c=%ymm10
vroundpd $9,%ymm10,%ymm10

# qhasm: 4x r1 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#11,<q=reg256#1,<r1=reg256#4
# asm 2: vfnmadd231pd <c=%ymm10,<q=%ymm0,<r1=%ymm3
vfnmadd231pd %ymm10,%ymm0,%ymm3

# qhasm: w = mem64[wp + 16],mem64[wp + 16],mem64[wp + 16],mem64[wp + 16]
# asm 1: vbroadcastsd 16(<wp=int64#7),>w=reg256#11
# asm 2: vbroadcastsd 16(<wp=%rax),>w=%ymm10
vbroadcastsd 16(%rax),%ymm10

# qhasm: 4x r3 approx*= w
# asm 1: vmulpd <w=reg256#11,<r3=reg256#8,>r3=reg256#8
# asm 2: vmulpd <w=%ymm10,<r3=%ymm7,>r3=%ymm7
vmulpd %ymm10,%ymm7,%ymm7

# qhasm: 4x c = approx r3 * qinv
# asm 1: vmulpd <r3=reg256#8,<qinv=reg256#2,>c=reg256#11
# asm 2: vmulpd <r3=%ymm7,<qinv=%ymm1,>c=%ymm10
vmulpd %ymm7,%ymm1,%ymm10

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#11,>c=reg256#11
# asm 2: vroundpd $9,<c=%ymm10,>c=%ymm10
vroundpd $9,%ymm10,%ymm10

# qhasm: 4x r3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#11,<q=reg256#1,<r3=reg256#8
# asm 2: vfnmadd231pd <c=%ymm10,<q=%ymm0,<r3=%ymm7
vfnmadd231pd %ymm10,%ymm0,%ymm7

# qhasm: 4x t1 = approx r1 + r3
# asm 1: vaddpd <r1=reg256#4,<r3=reg256#8,>t1=reg256#11
# asm 2: vaddpd <r1=%ymm3,<r3=%ymm7,>t1=%ymm10
vaddpd %ymm3,%ymm7,%ymm10

# qhasm: w = mem64[wp + 24],mem64[wp + 24],mem64[wp + 24],mem64[wp + 24]
# asm 1: vbroadcastsd 24(<wp=int64#7),>w=reg256#12
# asm 2: vbroadcastsd 24(<wp=%rax),>w=%ymm11
vbroadcastsd 24(%rax),%ymm11

# qhasm: 4x t3 = approx r1 - r3
# asm 1: vsubpd <r3=reg256#8,<r1=reg256#4,>t3=reg256#4
# asm 2: vsubpd <r3=%ymm7,<r1=%ymm3,>t3=%ymm3
vsubpd %ymm7,%ymm3,%ymm3

# qhasm: 4x t3 approx*= w
# asm 1: vmulpd <w=reg256#12,<t3=reg256#4,>t3=reg256#4
# asm 2: vmulpd <w=%ymm11,<t3=%ymm3,>t3=%ymm3
vmulpd %ymm11,%ymm3,%ymm3

# qhasm: 4x t2 approx*= w
# asm 1: vmulpd <w=reg256#12,<t2=reg256#10,>t2=reg256#8
# asm 2: vmulpd <w=%ymm11,<t2=%ymm9,>t2=%ymm7
vmulpd %ymm11,%ymm9,%ymm7

# qhasm: 4x r0 = approx a0 + t0
# asm 1: vaddpd <a0=reg256#5,<t0=reg256#9,>r0=reg256#10
# asm 2: vaddpd <a0=%ymm4,<t0=%ymm8,>r0=%ymm9
vaddpd %ymm4,%ymm8,%ymm9

# qhasm: 4x r1 = approx a1 + t1
# asm 1: vaddpd <a1=reg256#7,<t1=reg256#11,>r1=reg256#12
# asm 2: vaddpd <a1=%ymm6,<t1=%ymm10,>r1=%ymm11
vaddpd %ymm6,%ymm10,%ymm11

# qhasm: 4x r2 = approx a2 + t2
# asm 1: vaddpd <a2=reg256#6,<t2=reg256#8,>r2=reg256#13
# asm 2: vaddpd <a2=%ymm5,<t2=%ymm7,>r2=%ymm12
vaddpd %ymm5,%ymm7,%ymm12

# qhasm: 4x r3 = approx a3 + t3
# asm 1: vaddpd <a3=reg256#3,<t3=reg256#4,>r3=reg256#14
# asm 2: vaddpd <a3=%ymm2,<t3=%ymm3,>r3=%ymm13
vaddpd %ymm2,%ymm3,%ymm13

# qhasm: 4x a0 = approx a0 - t0
# asm 1: vsubpd <t0=reg256#9,<a0=reg256#5,>a0=reg256#5
# asm 2: vsubpd <t0=%ymm8,<a0=%ymm4,>a0=%ymm4
vsubpd %ymm8,%ymm4,%ymm4

# qhasm: 4x a1 = approx a1 - t1
# asm 1: vsubpd <t1=reg256#11,<a1=reg256#7,>a1=reg256#7
# asm 2: vsubpd <t1=%ymm10,<a1=%ymm6,>a1=%ymm6
vsubpd %ymm10,%ymm6,%ymm6

# qhasm: 4x a2 = approx a2 - t2
# asm 1: vsubpd <t2=reg256#8,<a2=reg256#6,>a2=reg256#6
# asm 2: vsubpd <t2=%ymm7,<a2=%ymm5,>a2=%ymm5
vsubpd %ymm7,%ymm5,%ymm5

# qhasm: 4x a3 = approx a3 - t3
# asm 1: vsubpd <t3=reg256#4,<a3=reg256#3,>a3=reg256#3
# asm 2: vsubpd <t3=%ymm3,<a3=%ymm2,>a3=%ymm2
vsubpd %ymm3,%ymm2,%ymm2

# qhasm: 4x c = approx r0 * qinv
# asm 1: vmulpd <r0=reg256#10,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <r0=%ymm9,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm9,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x r0 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<r0=reg256#10
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<r0=%ymm9
vfnmadd231pd %ymm3,%ymm0,%ymm9

# qhasm: 4x c = approx r1 * qinv
# asm 1: vmulpd <r1=reg256#12,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <r1=%ymm11,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm11,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x r1 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<r1=reg256#12
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<r1=%ymm11
vfnmadd231pd %ymm3,%ymm0,%ymm11

# qhasm: 4x c = approx r2 * qinv
# asm 1: vmulpd <r2=reg256#13,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <r2=%ymm12,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm12,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x r2 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<r2=reg256#13
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<r2=%ymm12
vfnmadd231pd %ymm3,%ymm0,%ymm12

# qhasm: 4x c = approx r3 * qinv
# asm 1: vmulpd <r3=reg256#14,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <r3=%ymm13,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm13,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x r3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<r3=reg256#14
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<r3=%ymm13
vfnmadd231pd %ymm3,%ymm0,%ymm13

# qhasm: 4x c = approx a0 * qinv
# asm 1: vmulpd <a0=reg256#5,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <a0=%ymm4,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm4,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x a0 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<a0=reg256#5
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<a0=%ymm4
vfnmadd231pd %ymm3,%ymm0,%ymm4

# qhasm: 4x c = approx a1 * qinv
# asm 1: vmulpd <a1=reg256#7,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <a1=%ymm6,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm6,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x a1 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<a1=reg256#7
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<a1=%ymm6
vfnmadd231pd %ymm3,%ymm0,%ymm6

# qhasm: 4x c = approx a2 * qinv
# asm 1: vmulpd <a2=reg256#6,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <a2=%ymm5,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm5,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x a2 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<a2=reg256#6
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<a2=%ymm5
vfnmadd231pd %ymm3,%ymm0,%ymm5

# qhasm: 4x c = approx a3 * qinv
# asm 1: vmulpd <a3=reg256#3,<qinv=reg256#2,>c=reg256#4
# asm 2: vmulpd <a3=%ymm2,<qinv=%ymm1,>c=%ymm3
vmulpd %ymm2,%ymm1,%ymm3

# qhasm: 4x c = floor(c)
# asm 1: vroundpd $9,<c=reg256#4,>c=reg256#4
# asm 2: vroundpd $9,<c=%ymm3,>c=%ymm3
vroundpd $9,%ymm3,%ymm3

# qhasm: 4x a3 approx-= c * q
# asm 1: vfnmadd231pd <c=reg256#4,<q=reg256#1,<a3=reg256#3
# asm 2: vfnmadd231pd <c=%ymm3,<q=%ymm0,<a3=%ymm2
vfnmadd231pd %ymm3,%ymm0,%ymm2

# qhasm: t0 = (4x int32)(4x double)r0,0,0,0,0
# asm 1: vcvtpd2dq <r0=reg256#10,>t0=reg256#4dq
# asm 2: vcvtpd2dq <r0=%ymm9,>t0=%xmm3
vcvtpd2dq %ymm9,%xmm3

# qhasm: t1 = (4x int32)(4x double)r1,0,0,0,0
# asm 1: vcvtpd2dq <r1=reg256#12,>t1=reg256#8dq
# asm 2: vcvtpd2dq <r1=%ymm11,>t1=%xmm7
vcvtpd2dq %ymm11,%xmm7

# qhasm: t2 = (4x int32)(4x double)r2,0,0,0,0
# asm 1: vcvtpd2dq <r2=reg256#13,>t2=reg256#9dq
# asm 2: vcvtpd2dq <r2=%ymm12,>t2=%xmm8
vcvtpd2dq %ymm12,%xmm8

# qhasm: t3 = (4x int32)(4x double)r3,0,0,0,0
# asm 1: vcvtpd2dq <r3=reg256#14,>t3=reg256#10dq
# asm 2: vcvtpd2dq <r3=%ymm13,>t3=%xmm9
vcvtpd2dq %ymm13,%xmm9

# qhasm: mem128[ap +   0] = t0
# asm 1: vmovupd <t0=reg256#4dq,0(<ap=int64#1)
# asm 2: vmovupd <t0=%xmm3,0(<ap=%rdi)
vmovupd %xmm3,0(%rdi)

# qhasm: mem128[ap + 512] = t1
# asm 1: vmovupd <t1=reg256#8dq,512(<ap=int64#1)
# asm 2: vmovupd <t1=%xmm7,512(<ap=%rdi)
vmovupd %xmm7,512(%rdi)

# qhasm: mem128[ap + 1024] = t2
# asm 1: vmovupd <t2=reg256#9dq,1024(<ap=int64#1)
# asm 2: vmovupd <t2=%xmm8,1024(<ap=%rdi)
vmovupd %xmm8,1024(%rdi)

# qhasm: mem128[ap + 1536] = t3
# asm 1: vmovupd <t3=reg256#10dq,1536(<ap=int64#1)
# asm 2: vmovupd <t3=%xmm9,1536(<ap=%rdi)
vmovupd %xmm9,1536(%rdi)

# qhasm: t0 = (4x int32)(4x double)a0,0,0,0,0
# asm 1: vcvtpd2dq <a0=reg256#5,>t0=reg256#4dq
# asm 2: vcvtpd2dq <a0=%ymm4,>t0=%xmm3
vcvtpd2dq %ymm4,%xmm3

# qhasm: t1 = (4x int32)(4x double)a1,0,0,0,0
# asm 1: vcvtpd2dq <a1=reg256#7,>t1=reg256#5dq
# asm 2: vcvtpd2dq <a1=%ymm6,>t1=%xmm4
vcvtpd2dq %ymm6,%xmm4

# qhasm: t2 = (4x int32)(4x double)a2,0,0,0,0
# asm 1: vcvtpd2dq <a2=reg256#6,>t2=reg256#6dq
# asm 2: vcvtpd2dq <a2=%ymm5,>t2=%xmm5
vcvtpd2dq %ymm5,%xmm5

# qhasm: t3 = (4x int32)(4x double)a3,0,0,0,0
# asm 1: vcvtpd2dq <a3=reg256#3,>t3=reg256#3dq
# asm 2: vcvtpd2dq <a3=%ymm2,>t3=%xmm2
vcvtpd2dq %ymm2,%xmm2

# qhasm: mem128[ap + 2048] = t0
# asm 1: vmovupd <t0=reg256#4dq,2048(<ap=int64#1)
# asm 2: vmovupd <t0=%xmm3,2048(<ap=%rdi)
vmovupd %xmm3,2048(%rdi)

# qhasm: mem128[ap + 2560] = t1
# asm 1: vmovupd <t1=reg256#5dq,2560(<ap=int64#1)
# asm 2: vmovupd <t1=%xmm4,2560(<ap=%rdi)
vmovupd %xmm4,2560(%rdi)

# qhasm: mem128[ap + 3072] = t2
# asm 1: vmovupd <t2=reg256#6dq,3072(<ap=int64#1)
# asm 2: vmovupd <t2=%xmm5,3072(<ap=%rdi)
vmovupd %xmm5,3072(%rdi)

# qhasm: mem128[ap + 3584] = t3
# asm 1: vmovupd <t3=reg256#3dq,3584(<ap=int64#1)
# asm 2: vmovupd <t3=%xmm2,3584(<ap=%rdi)
vmovupd %xmm2,3584(%rdi)

# qhasm: ap+=16
# asm 1: add  $16,<ap=int64#1
# asm 2: add  $16,<ap=%rdi
add  $16,%rdi

# qhasm: tp+=32
# asm 1: add  $32,<tp=int64#3
# asm 2: add  $32,<tp=%rdx
add  $32,%rdx

# qhasm: unsigned>? ctrj-=1
# asm 1: sub  $1,<ctrj=int64#2
# asm 2: sub  $1,<ctrj=%rsi
sub  $1,%rsi
# comment:fp stack unchanged by jump

# qhasm: goto loop8910j if unsigned>
ja ._loop8910j

# qhasm: return
add %r11,%rsp
ret
