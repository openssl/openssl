
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

# qhasm: int64 temp1

# qhasm: int64 temp2

# qhasm: int64 ap

# qhasm: enter bitrev_vector
.p2align 5
.global _bitrev_vector
.global bitrev_vector
_bitrev_vector:
bitrev_vector:
movq %rsp,%r11
and $31,%r11
add $0,%r11
sub %r11,%rsp

# qhasm: ap = input_0
# asm 1: mov  <input_0=int64#1,>ap=int64#1
# asm 2: mov  <input_0=%rdi,>ap=%rdi
mov  %rdi,%rdi

# qhasm: temp1 = mem64[ap + 4]
# asm 1: mov   4(<ap=int64#1),>temp1=int64#2
# asm 2: mov   4(<ap=%rdi),>temp1=%esi
mov   4(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2048]
# asm 1: mov   2048(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2048(<ap=%rdi),>temp2=%edx
mov   2048(%rdi),%edx

# qhasm: mem64[ap + 2048] = temp1
# asm 1: mov   <temp1=int64#2,2048(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2048(<ap=%rdi)
mov   %esi,2048(%rdi)

# qhasm: mem64[ap + 4] = temp2
# asm 1: mov   <temp2=int64#3,4(<ap=int64#1)
# asm 2: mov   <temp2=%edx,4(<ap=%rdi)
mov   %edx,4(%rdi)

# qhasm: temp1 = mem64[ap + 8]
# asm 1: mov   8(<ap=int64#1),>temp1=int64#2
# asm 2: mov   8(<ap=%rdi),>temp1=%esi
mov   8(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1024]
# asm 1: mov   1024(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1024(<ap=%rdi),>temp2=%edx
mov   1024(%rdi),%edx

# qhasm: mem64[ap + 1024] = temp1
# asm 1: mov   <temp1=int64#2,1024(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1024(<ap=%rdi)
mov   %esi,1024(%rdi)

# qhasm: mem64[ap + 8] = temp2
# asm 1: mov   <temp2=int64#3,8(<ap=int64#1)
# asm 2: mov   <temp2=%edx,8(<ap=%rdi)
mov   %edx,8(%rdi)

# qhasm: temp1 = mem64[ap + 12]
# asm 1: mov   12(<ap=int64#1),>temp1=int64#2
# asm 2: mov   12(<ap=%rdi),>temp1=%esi
mov   12(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3072]
# asm 1: mov   3072(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3072(<ap=%rdi),>temp2=%edx
mov   3072(%rdi),%edx

# qhasm: mem64[ap + 3072] = temp1
# asm 1: mov   <temp1=int64#2,3072(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3072(<ap=%rdi)
mov   %esi,3072(%rdi)

# qhasm: mem64[ap + 12] = temp2
# asm 1: mov   <temp2=int64#3,12(<ap=int64#1)
# asm 2: mov   <temp2=%edx,12(<ap=%rdi)
mov   %edx,12(%rdi)

# qhasm: temp1 = mem64[ap + 16]
# asm 1: mov   16(<ap=int64#1),>temp1=int64#2
# asm 2: mov   16(<ap=%rdi),>temp1=%esi
mov   16(%rdi),%esi

# qhasm: temp2 = mem64[ap + 512]
# asm 1: mov   512(<ap=int64#1),>temp2=int64#3
# asm 2: mov   512(<ap=%rdi),>temp2=%edx
mov   512(%rdi),%edx

# qhasm: mem64[ap + 512] = temp1
# asm 1: mov   <temp1=int64#2,512(<ap=int64#1)
# asm 2: mov   <temp1=%esi,512(<ap=%rdi)
mov   %esi,512(%rdi)

# qhasm: mem64[ap + 16] = temp2
# asm 1: mov   <temp2=int64#3,16(<ap=int64#1)
# asm 2: mov   <temp2=%edx,16(<ap=%rdi)
mov   %edx,16(%rdi)

# qhasm: temp1 = mem64[ap + 20]
# asm 1: mov   20(<ap=int64#1),>temp1=int64#2
# asm 2: mov   20(<ap=%rdi),>temp1=%esi
mov   20(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2560]
# asm 1: mov   2560(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2560(<ap=%rdi),>temp2=%edx
mov   2560(%rdi),%edx

# qhasm: mem64[ap + 2560] = temp1
# asm 1: mov   <temp1=int64#2,2560(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2560(<ap=%rdi)
mov   %esi,2560(%rdi)

# qhasm: mem64[ap + 20] = temp2
# asm 1: mov   <temp2=int64#3,20(<ap=int64#1)
# asm 2: mov   <temp2=%edx,20(<ap=%rdi)
mov   %edx,20(%rdi)

# qhasm: temp1 = mem64[ap + 24]
# asm 1: mov   24(<ap=int64#1),>temp1=int64#2
# asm 2: mov   24(<ap=%rdi),>temp1=%esi
mov   24(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1536]
# asm 1: mov   1536(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1536(<ap=%rdi),>temp2=%edx
mov   1536(%rdi),%edx

# qhasm: mem64[ap + 1536] = temp1
# asm 1: mov   <temp1=int64#2,1536(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1536(<ap=%rdi)
mov   %esi,1536(%rdi)

# qhasm: mem64[ap + 24] = temp2
# asm 1: mov   <temp2=int64#3,24(<ap=int64#1)
# asm 2: mov   <temp2=%edx,24(<ap=%rdi)
mov   %edx,24(%rdi)

# qhasm: temp1 = mem64[ap + 28]
# asm 1: mov   28(<ap=int64#1),>temp1=int64#2
# asm 2: mov   28(<ap=%rdi),>temp1=%esi
mov   28(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3584]
# asm 1: mov   3584(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3584(<ap=%rdi),>temp2=%edx
mov   3584(%rdi),%edx

# qhasm: mem64[ap + 3584] = temp1
# asm 1: mov   <temp1=int64#2,3584(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3584(<ap=%rdi)
mov   %esi,3584(%rdi)

# qhasm: mem64[ap + 28] = temp2
# asm 1: mov   <temp2=int64#3,28(<ap=int64#1)
# asm 2: mov   <temp2=%edx,28(<ap=%rdi)
mov   %edx,28(%rdi)

# qhasm: temp1 = mem64[ap + 32]
# asm 1: mov   32(<ap=int64#1),>temp1=int64#2
# asm 2: mov   32(<ap=%rdi),>temp1=%esi
mov   32(%rdi),%esi

# qhasm: temp2 = mem64[ap + 256]
# asm 1: mov   256(<ap=int64#1),>temp2=int64#3
# asm 2: mov   256(<ap=%rdi),>temp2=%edx
mov   256(%rdi),%edx

# qhasm: mem64[ap + 256] = temp1
# asm 1: mov   <temp1=int64#2,256(<ap=int64#1)
# asm 2: mov   <temp1=%esi,256(<ap=%rdi)
mov   %esi,256(%rdi)

# qhasm: mem64[ap + 32] = temp2
# asm 1: mov   <temp2=int64#3,32(<ap=int64#1)
# asm 2: mov   <temp2=%edx,32(<ap=%rdi)
mov   %edx,32(%rdi)

# qhasm: temp1 = mem64[ap + 36]
# asm 1: mov   36(<ap=int64#1),>temp1=int64#2
# asm 2: mov   36(<ap=%rdi),>temp1=%esi
mov   36(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2304]
# asm 1: mov   2304(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2304(<ap=%rdi),>temp2=%edx
mov   2304(%rdi),%edx

# qhasm: mem64[ap + 2304] = temp1
# asm 1: mov   <temp1=int64#2,2304(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2304(<ap=%rdi)
mov   %esi,2304(%rdi)

# qhasm: mem64[ap + 36] = temp2
# asm 1: mov   <temp2=int64#3,36(<ap=int64#1)
# asm 2: mov   <temp2=%edx,36(<ap=%rdi)
mov   %edx,36(%rdi)

# qhasm: temp1 = mem64[ap + 40]
# asm 1: mov   40(<ap=int64#1),>temp1=int64#2
# asm 2: mov   40(<ap=%rdi),>temp1=%esi
mov   40(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1280]
# asm 1: mov   1280(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1280(<ap=%rdi),>temp2=%edx
mov   1280(%rdi),%edx

# qhasm: mem64[ap + 1280] = temp1
# asm 1: mov   <temp1=int64#2,1280(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1280(<ap=%rdi)
mov   %esi,1280(%rdi)

# qhasm: mem64[ap + 40] = temp2
# asm 1: mov   <temp2=int64#3,40(<ap=int64#1)
# asm 2: mov   <temp2=%edx,40(<ap=%rdi)
mov   %edx,40(%rdi)

# qhasm: temp1 = mem64[ap + 44]
# asm 1: mov   44(<ap=int64#1),>temp1=int64#2
# asm 2: mov   44(<ap=%rdi),>temp1=%esi
mov   44(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3328]
# asm 1: mov   3328(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3328(<ap=%rdi),>temp2=%edx
mov   3328(%rdi),%edx

# qhasm: mem64[ap + 3328] = temp1
# asm 1: mov   <temp1=int64#2,3328(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3328(<ap=%rdi)
mov   %esi,3328(%rdi)

# qhasm: mem64[ap + 44] = temp2
# asm 1: mov   <temp2=int64#3,44(<ap=int64#1)
# asm 2: mov   <temp2=%edx,44(<ap=%rdi)
mov   %edx,44(%rdi)

# qhasm: temp1 = mem64[ap + 48]
# asm 1: mov   48(<ap=int64#1),>temp1=int64#2
# asm 2: mov   48(<ap=%rdi),>temp1=%esi
mov   48(%rdi),%esi

# qhasm: temp2 = mem64[ap + 768]
# asm 1: mov   768(<ap=int64#1),>temp2=int64#3
# asm 2: mov   768(<ap=%rdi),>temp2=%edx
mov   768(%rdi),%edx

# qhasm: mem64[ap + 768] = temp1
# asm 1: mov   <temp1=int64#2,768(<ap=int64#1)
# asm 2: mov   <temp1=%esi,768(<ap=%rdi)
mov   %esi,768(%rdi)

# qhasm: mem64[ap + 48] = temp2
# asm 1: mov   <temp2=int64#3,48(<ap=int64#1)
# asm 2: mov   <temp2=%edx,48(<ap=%rdi)
mov   %edx,48(%rdi)

# qhasm: temp1 = mem64[ap + 52]
# asm 1: mov   52(<ap=int64#1),>temp1=int64#2
# asm 2: mov   52(<ap=%rdi),>temp1=%esi
mov   52(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2816]
# asm 1: mov   2816(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2816(<ap=%rdi),>temp2=%edx
mov   2816(%rdi),%edx

# qhasm: mem64[ap + 2816] = temp1
# asm 1: mov   <temp1=int64#2,2816(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2816(<ap=%rdi)
mov   %esi,2816(%rdi)

# qhasm: mem64[ap + 52] = temp2
# asm 1: mov   <temp2=int64#3,52(<ap=int64#1)
# asm 2: mov   <temp2=%edx,52(<ap=%rdi)
mov   %edx,52(%rdi)

# qhasm: temp1 = mem64[ap + 56]
# asm 1: mov   56(<ap=int64#1),>temp1=int64#2
# asm 2: mov   56(<ap=%rdi),>temp1=%esi
mov   56(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1792]
# asm 1: mov   1792(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1792(<ap=%rdi),>temp2=%edx
mov   1792(%rdi),%edx

# qhasm: mem64[ap + 1792] = temp1
# asm 1: mov   <temp1=int64#2,1792(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1792(<ap=%rdi)
mov   %esi,1792(%rdi)

# qhasm: mem64[ap + 56] = temp2
# asm 1: mov   <temp2=int64#3,56(<ap=int64#1)
# asm 2: mov   <temp2=%edx,56(<ap=%rdi)
mov   %edx,56(%rdi)

# qhasm: temp1 = mem64[ap + 60]
# asm 1: mov   60(<ap=int64#1),>temp1=int64#2
# asm 2: mov   60(<ap=%rdi),>temp1=%esi
mov   60(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3840]
# asm 1: mov   3840(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3840(<ap=%rdi),>temp2=%edx
mov   3840(%rdi),%edx

# qhasm: mem64[ap + 3840] = temp1
# asm 1: mov   <temp1=int64#2,3840(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3840(<ap=%rdi)
mov   %esi,3840(%rdi)

# qhasm: mem64[ap + 60] = temp2
# asm 1: mov   <temp2=int64#3,60(<ap=int64#1)
# asm 2: mov   <temp2=%edx,60(<ap=%rdi)
mov   %edx,60(%rdi)

# qhasm: temp1 = mem64[ap + 64]
# asm 1: mov   64(<ap=int64#1),>temp1=int64#2
# asm 2: mov   64(<ap=%rdi),>temp1=%esi
mov   64(%rdi),%esi

# qhasm: temp2 = mem64[ap + 128]
# asm 1: mov   128(<ap=int64#1),>temp2=int64#3
# asm 2: mov   128(<ap=%rdi),>temp2=%edx
mov   128(%rdi),%edx

# qhasm: mem64[ap + 128] = temp1
# asm 1: mov   <temp1=int64#2,128(<ap=int64#1)
# asm 2: mov   <temp1=%esi,128(<ap=%rdi)
mov   %esi,128(%rdi)

# qhasm: mem64[ap + 64] = temp2
# asm 1: mov   <temp2=int64#3,64(<ap=int64#1)
# asm 2: mov   <temp2=%edx,64(<ap=%rdi)
mov   %edx,64(%rdi)

# qhasm: temp1 = mem64[ap + 68]
# asm 1: mov   68(<ap=int64#1),>temp1=int64#2
# asm 2: mov   68(<ap=%rdi),>temp1=%esi
mov   68(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2176]
# asm 1: mov   2176(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2176(<ap=%rdi),>temp2=%edx
mov   2176(%rdi),%edx

# qhasm: mem64[ap + 2176] = temp1
# asm 1: mov   <temp1=int64#2,2176(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2176(<ap=%rdi)
mov   %esi,2176(%rdi)

# qhasm: mem64[ap + 68] = temp2
# asm 1: mov   <temp2=int64#3,68(<ap=int64#1)
# asm 2: mov   <temp2=%edx,68(<ap=%rdi)
mov   %edx,68(%rdi)

# qhasm: temp1 = mem64[ap + 72]
# asm 1: mov   72(<ap=int64#1),>temp1=int64#2
# asm 2: mov   72(<ap=%rdi),>temp1=%esi
mov   72(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1152]
# asm 1: mov   1152(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1152(<ap=%rdi),>temp2=%edx
mov   1152(%rdi),%edx

# qhasm: mem64[ap + 1152] = temp1
# asm 1: mov   <temp1=int64#2,1152(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1152(<ap=%rdi)
mov   %esi,1152(%rdi)

# qhasm: mem64[ap + 72] = temp2
# asm 1: mov   <temp2=int64#3,72(<ap=int64#1)
# asm 2: mov   <temp2=%edx,72(<ap=%rdi)
mov   %edx,72(%rdi)

# qhasm: temp1 = mem64[ap + 76]
# asm 1: mov   76(<ap=int64#1),>temp1=int64#2
# asm 2: mov   76(<ap=%rdi),>temp1=%esi
mov   76(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3200]
# asm 1: mov   3200(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3200(<ap=%rdi),>temp2=%edx
mov   3200(%rdi),%edx

# qhasm: mem64[ap + 3200] = temp1
# asm 1: mov   <temp1=int64#2,3200(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3200(<ap=%rdi)
mov   %esi,3200(%rdi)

# qhasm: mem64[ap + 76] = temp2
# asm 1: mov   <temp2=int64#3,76(<ap=int64#1)
# asm 2: mov   <temp2=%edx,76(<ap=%rdi)
mov   %edx,76(%rdi)

# qhasm: temp1 = mem64[ap + 80]
# asm 1: mov   80(<ap=int64#1),>temp1=int64#2
# asm 2: mov   80(<ap=%rdi),>temp1=%esi
mov   80(%rdi),%esi

# qhasm: temp2 = mem64[ap + 640]
# asm 1: mov   640(<ap=int64#1),>temp2=int64#3
# asm 2: mov   640(<ap=%rdi),>temp2=%edx
mov   640(%rdi),%edx

# qhasm: mem64[ap + 640] = temp1
# asm 1: mov   <temp1=int64#2,640(<ap=int64#1)
# asm 2: mov   <temp1=%esi,640(<ap=%rdi)
mov   %esi,640(%rdi)

# qhasm: mem64[ap + 80] = temp2
# asm 1: mov   <temp2=int64#3,80(<ap=int64#1)
# asm 2: mov   <temp2=%edx,80(<ap=%rdi)
mov   %edx,80(%rdi)

# qhasm: temp1 = mem64[ap + 84]
# asm 1: mov   84(<ap=int64#1),>temp1=int64#2
# asm 2: mov   84(<ap=%rdi),>temp1=%esi
mov   84(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2688]
# asm 1: mov   2688(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2688(<ap=%rdi),>temp2=%edx
mov   2688(%rdi),%edx

# qhasm: mem64[ap + 2688] = temp1
# asm 1: mov   <temp1=int64#2,2688(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2688(<ap=%rdi)
mov   %esi,2688(%rdi)

# qhasm: mem64[ap + 84] = temp2
# asm 1: mov   <temp2=int64#3,84(<ap=int64#1)
# asm 2: mov   <temp2=%edx,84(<ap=%rdi)
mov   %edx,84(%rdi)

# qhasm: temp1 = mem64[ap + 88]
# asm 1: mov   88(<ap=int64#1),>temp1=int64#2
# asm 2: mov   88(<ap=%rdi),>temp1=%esi
mov   88(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1664]
# asm 1: mov   1664(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1664(<ap=%rdi),>temp2=%edx
mov   1664(%rdi),%edx

# qhasm: mem64[ap + 1664] = temp1
# asm 1: mov   <temp1=int64#2,1664(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1664(<ap=%rdi)
mov   %esi,1664(%rdi)

# qhasm: mem64[ap + 88] = temp2
# asm 1: mov   <temp2=int64#3,88(<ap=int64#1)
# asm 2: mov   <temp2=%edx,88(<ap=%rdi)
mov   %edx,88(%rdi)

# qhasm: temp1 = mem64[ap + 92]
# asm 1: mov   92(<ap=int64#1),>temp1=int64#2
# asm 2: mov   92(<ap=%rdi),>temp1=%esi
mov   92(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3712]
# asm 1: mov   3712(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3712(<ap=%rdi),>temp2=%edx
mov   3712(%rdi),%edx

# qhasm: mem64[ap + 3712] = temp1
# asm 1: mov   <temp1=int64#2,3712(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3712(<ap=%rdi)
mov   %esi,3712(%rdi)

# qhasm: mem64[ap + 92] = temp2
# asm 1: mov   <temp2=int64#3,92(<ap=int64#1)
# asm 2: mov   <temp2=%edx,92(<ap=%rdi)
mov   %edx,92(%rdi)

# qhasm: temp1 = mem64[ap + 96]
# asm 1: mov   96(<ap=int64#1),>temp1=int64#2
# asm 2: mov   96(<ap=%rdi),>temp1=%esi
mov   96(%rdi),%esi

# qhasm: temp2 = mem64[ap + 384]
# asm 1: mov   384(<ap=int64#1),>temp2=int64#3
# asm 2: mov   384(<ap=%rdi),>temp2=%edx
mov   384(%rdi),%edx

# qhasm: mem64[ap + 384] = temp1
# asm 1: mov   <temp1=int64#2,384(<ap=int64#1)
# asm 2: mov   <temp1=%esi,384(<ap=%rdi)
mov   %esi,384(%rdi)

# qhasm: mem64[ap + 96] = temp2
# asm 1: mov   <temp2=int64#3,96(<ap=int64#1)
# asm 2: mov   <temp2=%edx,96(<ap=%rdi)
mov   %edx,96(%rdi)

# qhasm: temp1 = mem64[ap + 100]
# asm 1: mov   100(<ap=int64#1),>temp1=int64#2
# asm 2: mov   100(<ap=%rdi),>temp1=%esi
mov   100(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2432]
# asm 1: mov   2432(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2432(<ap=%rdi),>temp2=%edx
mov   2432(%rdi),%edx

# qhasm: mem64[ap + 2432] = temp1
# asm 1: mov   <temp1=int64#2,2432(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2432(<ap=%rdi)
mov   %esi,2432(%rdi)

# qhasm: mem64[ap + 100] = temp2
# asm 1: mov   <temp2=int64#3,100(<ap=int64#1)
# asm 2: mov   <temp2=%edx,100(<ap=%rdi)
mov   %edx,100(%rdi)

# qhasm: temp1 = mem64[ap + 104]
# asm 1: mov   104(<ap=int64#1),>temp1=int64#2
# asm 2: mov   104(<ap=%rdi),>temp1=%esi
mov   104(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1408]
# asm 1: mov   1408(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1408(<ap=%rdi),>temp2=%edx
mov   1408(%rdi),%edx

# qhasm: mem64[ap + 1408] = temp1
# asm 1: mov   <temp1=int64#2,1408(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1408(<ap=%rdi)
mov   %esi,1408(%rdi)

# qhasm: mem64[ap + 104] = temp2
# asm 1: mov   <temp2=int64#3,104(<ap=int64#1)
# asm 2: mov   <temp2=%edx,104(<ap=%rdi)
mov   %edx,104(%rdi)

# qhasm: temp1 = mem64[ap + 108]
# asm 1: mov   108(<ap=int64#1),>temp1=int64#2
# asm 2: mov   108(<ap=%rdi),>temp1=%esi
mov   108(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3456]
# asm 1: mov   3456(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3456(<ap=%rdi),>temp2=%edx
mov   3456(%rdi),%edx

# qhasm: mem64[ap + 3456] = temp1
# asm 1: mov   <temp1=int64#2,3456(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3456(<ap=%rdi)
mov   %esi,3456(%rdi)

# qhasm: mem64[ap + 108] = temp2
# asm 1: mov   <temp2=int64#3,108(<ap=int64#1)
# asm 2: mov   <temp2=%edx,108(<ap=%rdi)
mov   %edx,108(%rdi)

# qhasm: temp1 = mem64[ap + 112]
# asm 1: mov   112(<ap=int64#1),>temp1=int64#2
# asm 2: mov   112(<ap=%rdi),>temp1=%esi
mov   112(%rdi),%esi

# qhasm: temp2 = mem64[ap + 896]
# asm 1: mov   896(<ap=int64#1),>temp2=int64#3
# asm 2: mov   896(<ap=%rdi),>temp2=%edx
mov   896(%rdi),%edx

# qhasm: mem64[ap + 896] = temp1
# asm 1: mov   <temp1=int64#2,896(<ap=int64#1)
# asm 2: mov   <temp1=%esi,896(<ap=%rdi)
mov   %esi,896(%rdi)

# qhasm: mem64[ap + 112] = temp2
# asm 1: mov   <temp2=int64#3,112(<ap=int64#1)
# asm 2: mov   <temp2=%edx,112(<ap=%rdi)
mov   %edx,112(%rdi)

# qhasm: temp1 = mem64[ap + 116]
# asm 1: mov   116(<ap=int64#1),>temp1=int64#2
# asm 2: mov   116(<ap=%rdi),>temp1=%esi
mov   116(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2944]
# asm 1: mov   2944(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2944(<ap=%rdi),>temp2=%edx
mov   2944(%rdi),%edx

# qhasm: mem64[ap + 2944] = temp1
# asm 1: mov   <temp1=int64#2,2944(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2944(<ap=%rdi)
mov   %esi,2944(%rdi)

# qhasm: mem64[ap + 116] = temp2
# asm 1: mov   <temp2=int64#3,116(<ap=int64#1)
# asm 2: mov   <temp2=%edx,116(<ap=%rdi)
mov   %edx,116(%rdi)

# qhasm: temp1 = mem64[ap + 120]
# asm 1: mov   120(<ap=int64#1),>temp1=int64#2
# asm 2: mov   120(<ap=%rdi),>temp1=%esi
mov   120(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1920]
# asm 1: mov   1920(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1920(<ap=%rdi),>temp2=%edx
mov   1920(%rdi),%edx

# qhasm: mem64[ap + 1920] = temp1
# asm 1: mov   <temp1=int64#2,1920(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1920(<ap=%rdi)
mov   %esi,1920(%rdi)

# qhasm: mem64[ap + 120] = temp2
# asm 1: mov   <temp2=int64#3,120(<ap=int64#1)
# asm 2: mov   <temp2=%edx,120(<ap=%rdi)
mov   %edx,120(%rdi)

# qhasm: temp1 = mem64[ap + 124]
# asm 1: mov   124(<ap=int64#1),>temp1=int64#2
# asm 2: mov   124(<ap=%rdi),>temp1=%esi
mov   124(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3968]
# asm 1: mov   3968(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3968(<ap=%rdi),>temp2=%edx
mov   3968(%rdi),%edx

# qhasm: mem64[ap + 3968] = temp1
# asm 1: mov   <temp1=int64#2,3968(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3968(<ap=%rdi)
mov   %esi,3968(%rdi)

# qhasm: mem64[ap + 124] = temp2
# asm 1: mov   <temp2=int64#3,124(<ap=int64#1)
# asm 2: mov   <temp2=%edx,124(<ap=%rdi)
mov   %edx,124(%rdi)

# qhasm: temp1 = mem64[ap + 132]
# asm 1: mov   132(<ap=int64#1),>temp1=int64#2
# asm 2: mov   132(<ap=%rdi),>temp1=%esi
mov   132(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2112]
# asm 1: mov   2112(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2112(<ap=%rdi),>temp2=%edx
mov   2112(%rdi),%edx

# qhasm: mem64[ap + 2112] = temp1
# asm 1: mov   <temp1=int64#2,2112(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2112(<ap=%rdi)
mov   %esi,2112(%rdi)

# qhasm: mem64[ap + 132] = temp2
# asm 1: mov   <temp2=int64#3,132(<ap=int64#1)
# asm 2: mov   <temp2=%edx,132(<ap=%rdi)
mov   %edx,132(%rdi)

# qhasm: temp1 = mem64[ap + 136]
# asm 1: mov   136(<ap=int64#1),>temp1=int64#2
# asm 2: mov   136(<ap=%rdi),>temp1=%esi
mov   136(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1088]
# asm 1: mov   1088(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1088(<ap=%rdi),>temp2=%edx
mov   1088(%rdi),%edx

# qhasm: mem64[ap + 1088] = temp1
# asm 1: mov   <temp1=int64#2,1088(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1088(<ap=%rdi)
mov   %esi,1088(%rdi)

# qhasm: mem64[ap + 136] = temp2
# asm 1: mov   <temp2=int64#3,136(<ap=int64#1)
# asm 2: mov   <temp2=%edx,136(<ap=%rdi)
mov   %edx,136(%rdi)

# qhasm: temp1 = mem64[ap + 140]
# asm 1: mov   140(<ap=int64#1),>temp1=int64#2
# asm 2: mov   140(<ap=%rdi),>temp1=%esi
mov   140(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3136]
# asm 1: mov   3136(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3136(<ap=%rdi),>temp2=%edx
mov   3136(%rdi),%edx

# qhasm: mem64[ap + 3136] = temp1
# asm 1: mov   <temp1=int64#2,3136(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3136(<ap=%rdi)
mov   %esi,3136(%rdi)

# qhasm: mem64[ap + 140] = temp2
# asm 1: mov   <temp2=int64#3,140(<ap=int64#1)
# asm 2: mov   <temp2=%edx,140(<ap=%rdi)
mov   %edx,140(%rdi)

# qhasm: temp1 = mem64[ap + 144]
# asm 1: mov   144(<ap=int64#1),>temp1=int64#2
# asm 2: mov   144(<ap=%rdi),>temp1=%esi
mov   144(%rdi),%esi

# qhasm: temp2 = mem64[ap + 576]
# asm 1: mov   576(<ap=int64#1),>temp2=int64#3
# asm 2: mov   576(<ap=%rdi),>temp2=%edx
mov   576(%rdi),%edx

# qhasm: mem64[ap + 576] = temp1
# asm 1: mov   <temp1=int64#2,576(<ap=int64#1)
# asm 2: mov   <temp1=%esi,576(<ap=%rdi)
mov   %esi,576(%rdi)

# qhasm: mem64[ap + 144] = temp2
# asm 1: mov   <temp2=int64#3,144(<ap=int64#1)
# asm 2: mov   <temp2=%edx,144(<ap=%rdi)
mov   %edx,144(%rdi)

# qhasm: temp1 = mem64[ap + 148]
# asm 1: mov   148(<ap=int64#1),>temp1=int64#2
# asm 2: mov   148(<ap=%rdi),>temp1=%esi
mov   148(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2624]
# asm 1: mov   2624(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2624(<ap=%rdi),>temp2=%edx
mov   2624(%rdi),%edx

# qhasm: mem64[ap + 2624] = temp1
# asm 1: mov   <temp1=int64#2,2624(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2624(<ap=%rdi)
mov   %esi,2624(%rdi)

# qhasm: mem64[ap + 148] = temp2
# asm 1: mov   <temp2=int64#3,148(<ap=int64#1)
# asm 2: mov   <temp2=%edx,148(<ap=%rdi)
mov   %edx,148(%rdi)

# qhasm: temp1 = mem64[ap + 152]
# asm 1: mov   152(<ap=int64#1),>temp1=int64#2
# asm 2: mov   152(<ap=%rdi),>temp1=%esi
mov   152(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1600]
# asm 1: mov   1600(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1600(<ap=%rdi),>temp2=%edx
mov   1600(%rdi),%edx

# qhasm: mem64[ap + 1600] = temp1
# asm 1: mov   <temp1=int64#2,1600(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1600(<ap=%rdi)
mov   %esi,1600(%rdi)

# qhasm: mem64[ap + 152] = temp2
# asm 1: mov   <temp2=int64#3,152(<ap=int64#1)
# asm 2: mov   <temp2=%edx,152(<ap=%rdi)
mov   %edx,152(%rdi)

# qhasm: temp1 = mem64[ap + 156]
# asm 1: mov   156(<ap=int64#1),>temp1=int64#2
# asm 2: mov   156(<ap=%rdi),>temp1=%esi
mov   156(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3648]
# asm 1: mov   3648(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3648(<ap=%rdi),>temp2=%edx
mov   3648(%rdi),%edx

# qhasm: mem64[ap + 3648] = temp1
# asm 1: mov   <temp1=int64#2,3648(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3648(<ap=%rdi)
mov   %esi,3648(%rdi)

# qhasm: mem64[ap + 156] = temp2
# asm 1: mov   <temp2=int64#3,156(<ap=int64#1)
# asm 2: mov   <temp2=%edx,156(<ap=%rdi)
mov   %edx,156(%rdi)

# qhasm: temp1 = mem64[ap + 160]
# asm 1: mov   160(<ap=int64#1),>temp1=int64#2
# asm 2: mov   160(<ap=%rdi),>temp1=%esi
mov   160(%rdi),%esi

# qhasm: temp2 = mem64[ap + 320]
# asm 1: mov   320(<ap=int64#1),>temp2=int64#3
# asm 2: mov   320(<ap=%rdi),>temp2=%edx
mov   320(%rdi),%edx

# qhasm: mem64[ap + 320] = temp1
# asm 1: mov   <temp1=int64#2,320(<ap=int64#1)
# asm 2: mov   <temp1=%esi,320(<ap=%rdi)
mov   %esi,320(%rdi)

# qhasm: mem64[ap + 160] = temp2
# asm 1: mov   <temp2=int64#3,160(<ap=int64#1)
# asm 2: mov   <temp2=%edx,160(<ap=%rdi)
mov   %edx,160(%rdi)

# qhasm: temp1 = mem64[ap + 164]
# asm 1: mov   164(<ap=int64#1),>temp1=int64#2
# asm 2: mov   164(<ap=%rdi),>temp1=%esi
mov   164(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2368]
# asm 1: mov   2368(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2368(<ap=%rdi),>temp2=%edx
mov   2368(%rdi),%edx

# qhasm: mem64[ap + 2368] = temp1
# asm 1: mov   <temp1=int64#2,2368(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2368(<ap=%rdi)
mov   %esi,2368(%rdi)

# qhasm: mem64[ap + 164] = temp2
# asm 1: mov   <temp2=int64#3,164(<ap=int64#1)
# asm 2: mov   <temp2=%edx,164(<ap=%rdi)
mov   %edx,164(%rdi)

# qhasm: temp1 = mem64[ap + 168]
# asm 1: mov   168(<ap=int64#1),>temp1=int64#2
# asm 2: mov   168(<ap=%rdi),>temp1=%esi
mov   168(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1344]
# asm 1: mov   1344(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1344(<ap=%rdi),>temp2=%edx
mov   1344(%rdi),%edx

# qhasm: mem64[ap + 1344] = temp1
# asm 1: mov   <temp1=int64#2,1344(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1344(<ap=%rdi)
mov   %esi,1344(%rdi)

# qhasm: mem64[ap + 168] = temp2
# asm 1: mov   <temp2=int64#3,168(<ap=int64#1)
# asm 2: mov   <temp2=%edx,168(<ap=%rdi)
mov   %edx,168(%rdi)

# qhasm: temp1 = mem64[ap + 172]
# asm 1: mov   172(<ap=int64#1),>temp1=int64#2
# asm 2: mov   172(<ap=%rdi),>temp1=%esi
mov   172(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3392]
# asm 1: mov   3392(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3392(<ap=%rdi),>temp2=%edx
mov   3392(%rdi),%edx

# qhasm: mem64[ap + 3392] = temp1
# asm 1: mov   <temp1=int64#2,3392(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3392(<ap=%rdi)
mov   %esi,3392(%rdi)

# qhasm: mem64[ap + 172] = temp2
# asm 1: mov   <temp2=int64#3,172(<ap=int64#1)
# asm 2: mov   <temp2=%edx,172(<ap=%rdi)
mov   %edx,172(%rdi)

# qhasm: temp1 = mem64[ap + 176]
# asm 1: mov   176(<ap=int64#1),>temp1=int64#2
# asm 2: mov   176(<ap=%rdi),>temp1=%esi
mov   176(%rdi),%esi

# qhasm: temp2 = mem64[ap + 832]
# asm 1: mov   832(<ap=int64#1),>temp2=int64#3
# asm 2: mov   832(<ap=%rdi),>temp2=%edx
mov   832(%rdi),%edx

# qhasm: mem64[ap + 832] = temp1
# asm 1: mov   <temp1=int64#2,832(<ap=int64#1)
# asm 2: mov   <temp1=%esi,832(<ap=%rdi)
mov   %esi,832(%rdi)

# qhasm: mem64[ap + 176] = temp2
# asm 1: mov   <temp2=int64#3,176(<ap=int64#1)
# asm 2: mov   <temp2=%edx,176(<ap=%rdi)
mov   %edx,176(%rdi)

# qhasm: temp1 = mem64[ap + 180]
# asm 1: mov   180(<ap=int64#1),>temp1=int64#2
# asm 2: mov   180(<ap=%rdi),>temp1=%esi
mov   180(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2880]
# asm 1: mov   2880(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2880(<ap=%rdi),>temp2=%edx
mov   2880(%rdi),%edx

# qhasm: mem64[ap + 2880] = temp1
# asm 1: mov   <temp1=int64#2,2880(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2880(<ap=%rdi)
mov   %esi,2880(%rdi)

# qhasm: mem64[ap + 180] = temp2
# asm 1: mov   <temp2=int64#3,180(<ap=int64#1)
# asm 2: mov   <temp2=%edx,180(<ap=%rdi)
mov   %edx,180(%rdi)

# qhasm: temp1 = mem64[ap + 184]
# asm 1: mov   184(<ap=int64#1),>temp1=int64#2
# asm 2: mov   184(<ap=%rdi),>temp1=%esi
mov   184(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1856]
# asm 1: mov   1856(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1856(<ap=%rdi),>temp2=%edx
mov   1856(%rdi),%edx

# qhasm: mem64[ap + 1856] = temp1
# asm 1: mov   <temp1=int64#2,1856(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1856(<ap=%rdi)
mov   %esi,1856(%rdi)

# qhasm: mem64[ap + 184] = temp2
# asm 1: mov   <temp2=int64#3,184(<ap=int64#1)
# asm 2: mov   <temp2=%edx,184(<ap=%rdi)
mov   %edx,184(%rdi)

# qhasm: temp1 = mem64[ap + 188]
# asm 1: mov   188(<ap=int64#1),>temp1=int64#2
# asm 2: mov   188(<ap=%rdi),>temp1=%esi
mov   188(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3904]
# asm 1: mov   3904(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3904(<ap=%rdi),>temp2=%edx
mov   3904(%rdi),%edx

# qhasm: mem64[ap + 3904] = temp1
# asm 1: mov   <temp1=int64#2,3904(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3904(<ap=%rdi)
mov   %esi,3904(%rdi)

# qhasm: mem64[ap + 188] = temp2
# asm 1: mov   <temp2=int64#3,188(<ap=int64#1)
# asm 2: mov   <temp2=%edx,188(<ap=%rdi)
mov   %edx,188(%rdi)

# qhasm: temp1 = mem64[ap + 196]
# asm 1: mov   196(<ap=int64#1),>temp1=int64#2
# asm 2: mov   196(<ap=%rdi),>temp1=%esi
mov   196(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2240]
# asm 1: mov   2240(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2240(<ap=%rdi),>temp2=%edx
mov   2240(%rdi),%edx

# qhasm: mem64[ap + 2240] = temp1
# asm 1: mov   <temp1=int64#2,2240(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2240(<ap=%rdi)
mov   %esi,2240(%rdi)

# qhasm: mem64[ap + 196] = temp2
# asm 1: mov   <temp2=int64#3,196(<ap=int64#1)
# asm 2: mov   <temp2=%edx,196(<ap=%rdi)
mov   %edx,196(%rdi)

# qhasm: temp1 = mem64[ap + 200]
# asm 1: mov   200(<ap=int64#1),>temp1=int64#2
# asm 2: mov   200(<ap=%rdi),>temp1=%esi
mov   200(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1216]
# asm 1: mov   1216(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1216(<ap=%rdi),>temp2=%edx
mov   1216(%rdi),%edx

# qhasm: mem64[ap + 1216] = temp1
# asm 1: mov   <temp1=int64#2,1216(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1216(<ap=%rdi)
mov   %esi,1216(%rdi)

# qhasm: mem64[ap + 200] = temp2
# asm 1: mov   <temp2=int64#3,200(<ap=int64#1)
# asm 2: mov   <temp2=%edx,200(<ap=%rdi)
mov   %edx,200(%rdi)

# qhasm: temp1 = mem64[ap + 204]
# asm 1: mov   204(<ap=int64#1),>temp1=int64#2
# asm 2: mov   204(<ap=%rdi),>temp1=%esi
mov   204(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3264]
# asm 1: mov   3264(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3264(<ap=%rdi),>temp2=%edx
mov   3264(%rdi),%edx

# qhasm: mem64[ap + 3264] = temp1
# asm 1: mov   <temp1=int64#2,3264(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3264(<ap=%rdi)
mov   %esi,3264(%rdi)

# qhasm: mem64[ap + 204] = temp2
# asm 1: mov   <temp2=int64#3,204(<ap=int64#1)
# asm 2: mov   <temp2=%edx,204(<ap=%rdi)
mov   %edx,204(%rdi)

# qhasm: temp1 = mem64[ap + 208]
# asm 1: mov   208(<ap=int64#1),>temp1=int64#2
# asm 2: mov   208(<ap=%rdi),>temp1=%esi
mov   208(%rdi),%esi

# qhasm: temp2 = mem64[ap + 704]
# asm 1: mov   704(<ap=int64#1),>temp2=int64#3
# asm 2: mov   704(<ap=%rdi),>temp2=%edx
mov   704(%rdi),%edx

# qhasm: mem64[ap + 704] = temp1
# asm 1: mov   <temp1=int64#2,704(<ap=int64#1)
# asm 2: mov   <temp1=%esi,704(<ap=%rdi)
mov   %esi,704(%rdi)

# qhasm: mem64[ap + 208] = temp2
# asm 1: mov   <temp2=int64#3,208(<ap=int64#1)
# asm 2: mov   <temp2=%edx,208(<ap=%rdi)
mov   %edx,208(%rdi)

# qhasm: temp1 = mem64[ap + 212]
# asm 1: mov   212(<ap=int64#1),>temp1=int64#2
# asm 2: mov   212(<ap=%rdi),>temp1=%esi
mov   212(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2752]
# asm 1: mov   2752(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2752(<ap=%rdi),>temp2=%edx
mov   2752(%rdi),%edx

# qhasm: mem64[ap + 2752] = temp1
# asm 1: mov   <temp1=int64#2,2752(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2752(<ap=%rdi)
mov   %esi,2752(%rdi)

# qhasm: mem64[ap + 212] = temp2
# asm 1: mov   <temp2=int64#3,212(<ap=int64#1)
# asm 2: mov   <temp2=%edx,212(<ap=%rdi)
mov   %edx,212(%rdi)

# qhasm: temp1 = mem64[ap + 216]
# asm 1: mov   216(<ap=int64#1),>temp1=int64#2
# asm 2: mov   216(<ap=%rdi),>temp1=%esi
mov   216(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1728]
# asm 1: mov   1728(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1728(<ap=%rdi),>temp2=%edx
mov   1728(%rdi),%edx

# qhasm: mem64[ap + 1728] = temp1
# asm 1: mov   <temp1=int64#2,1728(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1728(<ap=%rdi)
mov   %esi,1728(%rdi)

# qhasm: mem64[ap + 216] = temp2
# asm 1: mov   <temp2=int64#3,216(<ap=int64#1)
# asm 2: mov   <temp2=%edx,216(<ap=%rdi)
mov   %edx,216(%rdi)

# qhasm: temp1 = mem64[ap + 220]
# asm 1: mov   220(<ap=int64#1),>temp1=int64#2
# asm 2: mov   220(<ap=%rdi),>temp1=%esi
mov   220(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3776]
# asm 1: mov   3776(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3776(<ap=%rdi),>temp2=%edx
mov   3776(%rdi),%edx

# qhasm: mem64[ap + 3776] = temp1
# asm 1: mov   <temp1=int64#2,3776(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3776(<ap=%rdi)
mov   %esi,3776(%rdi)

# qhasm: mem64[ap + 220] = temp2
# asm 1: mov   <temp2=int64#3,220(<ap=int64#1)
# asm 2: mov   <temp2=%edx,220(<ap=%rdi)
mov   %edx,220(%rdi)

# qhasm: temp1 = mem64[ap + 224]
# asm 1: mov   224(<ap=int64#1),>temp1=int64#2
# asm 2: mov   224(<ap=%rdi),>temp1=%esi
mov   224(%rdi),%esi

# qhasm: temp2 = mem64[ap + 448]
# asm 1: mov   448(<ap=int64#1),>temp2=int64#3
# asm 2: mov   448(<ap=%rdi),>temp2=%edx
mov   448(%rdi),%edx

# qhasm: mem64[ap + 448] = temp1
# asm 1: mov   <temp1=int64#2,448(<ap=int64#1)
# asm 2: mov   <temp1=%esi,448(<ap=%rdi)
mov   %esi,448(%rdi)

# qhasm: mem64[ap + 224] = temp2
# asm 1: mov   <temp2=int64#3,224(<ap=int64#1)
# asm 2: mov   <temp2=%edx,224(<ap=%rdi)
mov   %edx,224(%rdi)

# qhasm: temp1 = mem64[ap + 228]
# asm 1: mov   228(<ap=int64#1),>temp1=int64#2
# asm 2: mov   228(<ap=%rdi),>temp1=%esi
mov   228(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2496]
# asm 1: mov   2496(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2496(<ap=%rdi),>temp2=%edx
mov   2496(%rdi),%edx

# qhasm: mem64[ap + 2496] = temp1
# asm 1: mov   <temp1=int64#2,2496(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2496(<ap=%rdi)
mov   %esi,2496(%rdi)

# qhasm: mem64[ap + 228] = temp2
# asm 1: mov   <temp2=int64#3,228(<ap=int64#1)
# asm 2: mov   <temp2=%edx,228(<ap=%rdi)
mov   %edx,228(%rdi)

# qhasm: temp1 = mem64[ap + 232]
# asm 1: mov   232(<ap=int64#1),>temp1=int64#2
# asm 2: mov   232(<ap=%rdi),>temp1=%esi
mov   232(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1472]
# asm 1: mov   1472(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1472(<ap=%rdi),>temp2=%edx
mov   1472(%rdi),%edx

# qhasm: mem64[ap + 1472] = temp1
# asm 1: mov   <temp1=int64#2,1472(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1472(<ap=%rdi)
mov   %esi,1472(%rdi)

# qhasm: mem64[ap + 232] = temp2
# asm 1: mov   <temp2=int64#3,232(<ap=int64#1)
# asm 2: mov   <temp2=%edx,232(<ap=%rdi)
mov   %edx,232(%rdi)

# qhasm: temp1 = mem64[ap + 236]
# asm 1: mov   236(<ap=int64#1),>temp1=int64#2
# asm 2: mov   236(<ap=%rdi),>temp1=%esi
mov   236(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3520]
# asm 1: mov   3520(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3520(<ap=%rdi),>temp2=%edx
mov   3520(%rdi),%edx

# qhasm: mem64[ap + 3520] = temp1
# asm 1: mov   <temp1=int64#2,3520(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3520(<ap=%rdi)
mov   %esi,3520(%rdi)

# qhasm: mem64[ap + 236] = temp2
# asm 1: mov   <temp2=int64#3,236(<ap=int64#1)
# asm 2: mov   <temp2=%edx,236(<ap=%rdi)
mov   %edx,236(%rdi)

# qhasm: temp1 = mem64[ap + 240]
# asm 1: mov   240(<ap=int64#1),>temp1=int64#2
# asm 2: mov   240(<ap=%rdi),>temp1=%esi
mov   240(%rdi),%esi

# qhasm: temp2 = mem64[ap + 960]
# asm 1: mov   960(<ap=int64#1),>temp2=int64#3
# asm 2: mov   960(<ap=%rdi),>temp2=%edx
mov   960(%rdi),%edx

# qhasm: mem64[ap + 960] = temp1
# asm 1: mov   <temp1=int64#2,960(<ap=int64#1)
# asm 2: mov   <temp1=%esi,960(<ap=%rdi)
mov   %esi,960(%rdi)

# qhasm: mem64[ap + 240] = temp2
# asm 1: mov   <temp2=int64#3,240(<ap=int64#1)
# asm 2: mov   <temp2=%edx,240(<ap=%rdi)
mov   %edx,240(%rdi)

# qhasm: temp1 = mem64[ap + 244]
# asm 1: mov   244(<ap=int64#1),>temp1=int64#2
# asm 2: mov   244(<ap=%rdi),>temp1=%esi
mov   244(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3008]
# asm 1: mov   3008(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3008(<ap=%rdi),>temp2=%edx
mov   3008(%rdi),%edx

# qhasm: mem64[ap + 3008] = temp1
# asm 1: mov   <temp1=int64#2,3008(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3008(<ap=%rdi)
mov   %esi,3008(%rdi)

# qhasm: mem64[ap + 244] = temp2
# asm 1: mov   <temp2=int64#3,244(<ap=int64#1)
# asm 2: mov   <temp2=%edx,244(<ap=%rdi)
mov   %edx,244(%rdi)

# qhasm: temp1 = mem64[ap + 248]
# asm 1: mov   248(<ap=int64#1),>temp1=int64#2
# asm 2: mov   248(<ap=%rdi),>temp1=%esi
mov   248(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1984]
# asm 1: mov   1984(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1984(<ap=%rdi),>temp2=%edx
mov   1984(%rdi),%edx

# qhasm: mem64[ap + 1984] = temp1
# asm 1: mov   <temp1=int64#2,1984(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1984(<ap=%rdi)
mov   %esi,1984(%rdi)

# qhasm: mem64[ap + 248] = temp2
# asm 1: mov   <temp2=int64#3,248(<ap=int64#1)
# asm 2: mov   <temp2=%edx,248(<ap=%rdi)
mov   %edx,248(%rdi)

# qhasm: temp1 = mem64[ap + 252]
# asm 1: mov   252(<ap=int64#1),>temp1=int64#2
# asm 2: mov   252(<ap=%rdi),>temp1=%esi
mov   252(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4032]
# asm 1: mov   4032(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4032(<ap=%rdi),>temp2=%edx
mov   4032(%rdi),%edx

# qhasm: mem64[ap + 4032] = temp1
# asm 1: mov   <temp1=int64#2,4032(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4032(<ap=%rdi)
mov   %esi,4032(%rdi)

# qhasm: mem64[ap + 252] = temp2
# asm 1: mov   <temp2=int64#3,252(<ap=int64#1)
# asm 2: mov   <temp2=%edx,252(<ap=%rdi)
mov   %edx,252(%rdi)

# qhasm: temp1 = mem64[ap + 260]
# asm 1: mov   260(<ap=int64#1),>temp1=int64#2
# asm 2: mov   260(<ap=%rdi),>temp1=%esi
mov   260(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2080]
# asm 1: mov   2080(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2080(<ap=%rdi),>temp2=%edx
mov   2080(%rdi),%edx

# qhasm: mem64[ap + 2080] = temp1
# asm 1: mov   <temp1=int64#2,2080(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2080(<ap=%rdi)
mov   %esi,2080(%rdi)

# qhasm: mem64[ap + 260] = temp2
# asm 1: mov   <temp2=int64#3,260(<ap=int64#1)
# asm 2: mov   <temp2=%edx,260(<ap=%rdi)
mov   %edx,260(%rdi)

# qhasm: temp1 = mem64[ap + 264]
# asm 1: mov   264(<ap=int64#1),>temp1=int64#2
# asm 2: mov   264(<ap=%rdi),>temp1=%esi
mov   264(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1056]
# asm 1: mov   1056(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1056(<ap=%rdi),>temp2=%edx
mov   1056(%rdi),%edx

# qhasm: mem64[ap + 1056] = temp1
# asm 1: mov   <temp1=int64#2,1056(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1056(<ap=%rdi)
mov   %esi,1056(%rdi)

# qhasm: mem64[ap + 264] = temp2
# asm 1: mov   <temp2=int64#3,264(<ap=int64#1)
# asm 2: mov   <temp2=%edx,264(<ap=%rdi)
mov   %edx,264(%rdi)

# qhasm: temp1 = mem64[ap + 268]
# asm 1: mov   268(<ap=int64#1),>temp1=int64#2
# asm 2: mov   268(<ap=%rdi),>temp1=%esi
mov   268(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3104]
# asm 1: mov   3104(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3104(<ap=%rdi),>temp2=%edx
mov   3104(%rdi),%edx

# qhasm: mem64[ap + 3104] = temp1
# asm 1: mov   <temp1=int64#2,3104(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3104(<ap=%rdi)
mov   %esi,3104(%rdi)

# qhasm: mem64[ap + 268] = temp2
# asm 1: mov   <temp2=int64#3,268(<ap=int64#1)
# asm 2: mov   <temp2=%edx,268(<ap=%rdi)
mov   %edx,268(%rdi)

# qhasm: temp1 = mem64[ap + 272]
# asm 1: mov   272(<ap=int64#1),>temp1=int64#2
# asm 2: mov   272(<ap=%rdi),>temp1=%esi
mov   272(%rdi),%esi

# qhasm: temp2 = mem64[ap + 544]
# asm 1: mov   544(<ap=int64#1),>temp2=int64#3
# asm 2: mov   544(<ap=%rdi),>temp2=%edx
mov   544(%rdi),%edx

# qhasm: mem64[ap + 544] = temp1
# asm 1: mov   <temp1=int64#2,544(<ap=int64#1)
# asm 2: mov   <temp1=%esi,544(<ap=%rdi)
mov   %esi,544(%rdi)

# qhasm: mem64[ap + 272] = temp2
# asm 1: mov   <temp2=int64#3,272(<ap=int64#1)
# asm 2: mov   <temp2=%edx,272(<ap=%rdi)
mov   %edx,272(%rdi)

# qhasm: temp1 = mem64[ap + 276]
# asm 1: mov   276(<ap=int64#1),>temp1=int64#2
# asm 2: mov   276(<ap=%rdi),>temp1=%esi
mov   276(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2592]
# asm 1: mov   2592(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2592(<ap=%rdi),>temp2=%edx
mov   2592(%rdi),%edx

# qhasm: mem64[ap + 2592] = temp1
# asm 1: mov   <temp1=int64#2,2592(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2592(<ap=%rdi)
mov   %esi,2592(%rdi)

# qhasm: mem64[ap + 276] = temp2
# asm 1: mov   <temp2=int64#3,276(<ap=int64#1)
# asm 2: mov   <temp2=%edx,276(<ap=%rdi)
mov   %edx,276(%rdi)

# qhasm: temp1 = mem64[ap + 280]
# asm 1: mov   280(<ap=int64#1),>temp1=int64#2
# asm 2: mov   280(<ap=%rdi),>temp1=%esi
mov   280(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1568]
# asm 1: mov   1568(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1568(<ap=%rdi),>temp2=%edx
mov   1568(%rdi),%edx

# qhasm: mem64[ap + 1568] = temp1
# asm 1: mov   <temp1=int64#2,1568(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1568(<ap=%rdi)
mov   %esi,1568(%rdi)

# qhasm: mem64[ap + 280] = temp2
# asm 1: mov   <temp2=int64#3,280(<ap=int64#1)
# asm 2: mov   <temp2=%edx,280(<ap=%rdi)
mov   %edx,280(%rdi)

# qhasm: temp1 = mem64[ap + 284]
# asm 1: mov   284(<ap=int64#1),>temp1=int64#2
# asm 2: mov   284(<ap=%rdi),>temp1=%esi
mov   284(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3616]
# asm 1: mov   3616(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3616(<ap=%rdi),>temp2=%edx
mov   3616(%rdi),%edx

# qhasm: mem64[ap + 3616] = temp1
# asm 1: mov   <temp1=int64#2,3616(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3616(<ap=%rdi)
mov   %esi,3616(%rdi)

# qhasm: mem64[ap + 284] = temp2
# asm 1: mov   <temp2=int64#3,284(<ap=int64#1)
# asm 2: mov   <temp2=%edx,284(<ap=%rdi)
mov   %edx,284(%rdi)

# qhasm: temp1 = mem64[ap + 292]
# asm 1: mov   292(<ap=int64#1),>temp1=int64#2
# asm 2: mov   292(<ap=%rdi),>temp1=%esi
mov   292(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2336]
# asm 1: mov   2336(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2336(<ap=%rdi),>temp2=%edx
mov   2336(%rdi),%edx

# qhasm: mem64[ap + 2336] = temp1
# asm 1: mov   <temp1=int64#2,2336(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2336(<ap=%rdi)
mov   %esi,2336(%rdi)

# qhasm: mem64[ap + 292] = temp2
# asm 1: mov   <temp2=int64#3,292(<ap=int64#1)
# asm 2: mov   <temp2=%edx,292(<ap=%rdi)
mov   %edx,292(%rdi)

# qhasm: temp1 = mem64[ap + 296]
# asm 1: mov   296(<ap=int64#1),>temp1=int64#2
# asm 2: mov   296(<ap=%rdi),>temp1=%esi
mov   296(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1312]
# asm 1: mov   1312(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1312(<ap=%rdi),>temp2=%edx
mov   1312(%rdi),%edx

# qhasm: mem64[ap + 1312] = temp1
# asm 1: mov   <temp1=int64#2,1312(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1312(<ap=%rdi)
mov   %esi,1312(%rdi)

# qhasm: mem64[ap + 296] = temp2
# asm 1: mov   <temp2=int64#3,296(<ap=int64#1)
# asm 2: mov   <temp2=%edx,296(<ap=%rdi)
mov   %edx,296(%rdi)

# qhasm: temp1 = mem64[ap + 300]
# asm 1: mov   300(<ap=int64#1),>temp1=int64#2
# asm 2: mov   300(<ap=%rdi),>temp1=%esi
mov   300(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3360]
# asm 1: mov   3360(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3360(<ap=%rdi),>temp2=%edx
mov   3360(%rdi),%edx

# qhasm: mem64[ap + 3360] = temp1
# asm 1: mov   <temp1=int64#2,3360(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3360(<ap=%rdi)
mov   %esi,3360(%rdi)

# qhasm: mem64[ap + 300] = temp2
# asm 1: mov   <temp2=int64#3,300(<ap=int64#1)
# asm 2: mov   <temp2=%edx,300(<ap=%rdi)
mov   %edx,300(%rdi)

# qhasm: temp1 = mem64[ap + 304]
# asm 1: mov   304(<ap=int64#1),>temp1=int64#2
# asm 2: mov   304(<ap=%rdi),>temp1=%esi
mov   304(%rdi),%esi

# qhasm: temp2 = mem64[ap + 800]
# asm 1: mov   800(<ap=int64#1),>temp2=int64#3
# asm 2: mov   800(<ap=%rdi),>temp2=%edx
mov   800(%rdi),%edx

# qhasm: mem64[ap + 800] = temp1
# asm 1: mov   <temp1=int64#2,800(<ap=int64#1)
# asm 2: mov   <temp1=%esi,800(<ap=%rdi)
mov   %esi,800(%rdi)

# qhasm: mem64[ap + 304] = temp2
# asm 1: mov   <temp2=int64#3,304(<ap=int64#1)
# asm 2: mov   <temp2=%edx,304(<ap=%rdi)
mov   %edx,304(%rdi)

# qhasm: temp1 = mem64[ap + 308]
# asm 1: mov   308(<ap=int64#1),>temp1=int64#2
# asm 2: mov   308(<ap=%rdi),>temp1=%esi
mov   308(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2848]
# asm 1: mov   2848(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2848(<ap=%rdi),>temp2=%edx
mov   2848(%rdi),%edx

# qhasm: mem64[ap + 2848] = temp1
# asm 1: mov   <temp1=int64#2,2848(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2848(<ap=%rdi)
mov   %esi,2848(%rdi)

# qhasm: mem64[ap + 308] = temp2
# asm 1: mov   <temp2=int64#3,308(<ap=int64#1)
# asm 2: mov   <temp2=%edx,308(<ap=%rdi)
mov   %edx,308(%rdi)

# qhasm: temp1 = mem64[ap + 312]
# asm 1: mov   312(<ap=int64#1),>temp1=int64#2
# asm 2: mov   312(<ap=%rdi),>temp1=%esi
mov   312(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1824]
# asm 1: mov   1824(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1824(<ap=%rdi),>temp2=%edx
mov   1824(%rdi),%edx

# qhasm: mem64[ap + 1824] = temp1
# asm 1: mov   <temp1=int64#2,1824(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1824(<ap=%rdi)
mov   %esi,1824(%rdi)

# qhasm: mem64[ap + 312] = temp2
# asm 1: mov   <temp2=int64#3,312(<ap=int64#1)
# asm 2: mov   <temp2=%edx,312(<ap=%rdi)
mov   %edx,312(%rdi)

# qhasm: temp1 = mem64[ap + 316]
# asm 1: mov   316(<ap=int64#1),>temp1=int64#2
# asm 2: mov   316(<ap=%rdi),>temp1=%esi
mov   316(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3872]
# asm 1: mov   3872(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3872(<ap=%rdi),>temp2=%edx
mov   3872(%rdi),%edx

# qhasm: mem64[ap + 3872] = temp1
# asm 1: mov   <temp1=int64#2,3872(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3872(<ap=%rdi)
mov   %esi,3872(%rdi)

# qhasm: mem64[ap + 316] = temp2
# asm 1: mov   <temp2=int64#3,316(<ap=int64#1)
# asm 2: mov   <temp2=%edx,316(<ap=%rdi)
mov   %edx,316(%rdi)

# qhasm: temp1 = mem64[ap + 324]
# asm 1: mov   324(<ap=int64#1),>temp1=int64#2
# asm 2: mov   324(<ap=%rdi),>temp1=%esi
mov   324(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2208]
# asm 1: mov   2208(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2208(<ap=%rdi),>temp2=%edx
mov   2208(%rdi),%edx

# qhasm: mem64[ap + 2208] = temp1
# asm 1: mov   <temp1=int64#2,2208(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2208(<ap=%rdi)
mov   %esi,2208(%rdi)

# qhasm: mem64[ap + 324] = temp2
# asm 1: mov   <temp2=int64#3,324(<ap=int64#1)
# asm 2: mov   <temp2=%edx,324(<ap=%rdi)
mov   %edx,324(%rdi)

# qhasm: temp1 = mem64[ap + 328]
# asm 1: mov   328(<ap=int64#1),>temp1=int64#2
# asm 2: mov   328(<ap=%rdi),>temp1=%esi
mov   328(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1184]
# asm 1: mov   1184(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1184(<ap=%rdi),>temp2=%edx
mov   1184(%rdi),%edx

# qhasm: mem64[ap + 1184] = temp1
# asm 1: mov   <temp1=int64#2,1184(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1184(<ap=%rdi)
mov   %esi,1184(%rdi)

# qhasm: mem64[ap + 328] = temp2
# asm 1: mov   <temp2=int64#3,328(<ap=int64#1)
# asm 2: mov   <temp2=%edx,328(<ap=%rdi)
mov   %edx,328(%rdi)

# qhasm: temp1 = mem64[ap + 332]
# asm 1: mov   332(<ap=int64#1),>temp1=int64#2
# asm 2: mov   332(<ap=%rdi),>temp1=%esi
mov   332(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3232]
# asm 1: mov   3232(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3232(<ap=%rdi),>temp2=%edx
mov   3232(%rdi),%edx

# qhasm: mem64[ap + 3232] = temp1
# asm 1: mov   <temp1=int64#2,3232(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3232(<ap=%rdi)
mov   %esi,3232(%rdi)

# qhasm: mem64[ap + 332] = temp2
# asm 1: mov   <temp2=int64#3,332(<ap=int64#1)
# asm 2: mov   <temp2=%edx,332(<ap=%rdi)
mov   %edx,332(%rdi)

# qhasm: temp1 = mem64[ap + 336]
# asm 1: mov   336(<ap=int64#1),>temp1=int64#2
# asm 2: mov   336(<ap=%rdi),>temp1=%esi
mov   336(%rdi),%esi

# qhasm: temp2 = mem64[ap + 672]
# asm 1: mov   672(<ap=int64#1),>temp2=int64#3
# asm 2: mov   672(<ap=%rdi),>temp2=%edx
mov   672(%rdi),%edx

# qhasm: mem64[ap + 672] = temp1
# asm 1: mov   <temp1=int64#2,672(<ap=int64#1)
# asm 2: mov   <temp1=%esi,672(<ap=%rdi)
mov   %esi,672(%rdi)

# qhasm: mem64[ap + 336] = temp2
# asm 1: mov   <temp2=int64#3,336(<ap=int64#1)
# asm 2: mov   <temp2=%edx,336(<ap=%rdi)
mov   %edx,336(%rdi)

# qhasm: temp1 = mem64[ap + 340]
# asm 1: mov   340(<ap=int64#1),>temp1=int64#2
# asm 2: mov   340(<ap=%rdi),>temp1=%esi
mov   340(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2720]
# asm 1: mov   2720(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2720(<ap=%rdi),>temp2=%edx
mov   2720(%rdi),%edx

# qhasm: mem64[ap + 2720] = temp1
# asm 1: mov   <temp1=int64#2,2720(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2720(<ap=%rdi)
mov   %esi,2720(%rdi)

# qhasm: mem64[ap + 340] = temp2
# asm 1: mov   <temp2=int64#3,340(<ap=int64#1)
# asm 2: mov   <temp2=%edx,340(<ap=%rdi)
mov   %edx,340(%rdi)

# qhasm: temp1 = mem64[ap + 344]
# asm 1: mov   344(<ap=int64#1),>temp1=int64#2
# asm 2: mov   344(<ap=%rdi),>temp1=%esi
mov   344(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1696]
# asm 1: mov   1696(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1696(<ap=%rdi),>temp2=%edx
mov   1696(%rdi),%edx

# qhasm: mem64[ap + 1696] = temp1
# asm 1: mov   <temp1=int64#2,1696(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1696(<ap=%rdi)
mov   %esi,1696(%rdi)

# qhasm: mem64[ap + 344] = temp2
# asm 1: mov   <temp2=int64#3,344(<ap=int64#1)
# asm 2: mov   <temp2=%edx,344(<ap=%rdi)
mov   %edx,344(%rdi)

# qhasm: temp1 = mem64[ap + 348]
# asm 1: mov   348(<ap=int64#1),>temp1=int64#2
# asm 2: mov   348(<ap=%rdi),>temp1=%esi
mov   348(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3744]
# asm 1: mov   3744(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3744(<ap=%rdi),>temp2=%edx
mov   3744(%rdi),%edx

# qhasm: mem64[ap + 3744] = temp1
# asm 1: mov   <temp1=int64#2,3744(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3744(<ap=%rdi)
mov   %esi,3744(%rdi)

# qhasm: mem64[ap + 348] = temp2
# asm 1: mov   <temp2=int64#3,348(<ap=int64#1)
# asm 2: mov   <temp2=%edx,348(<ap=%rdi)
mov   %edx,348(%rdi)

# qhasm: temp1 = mem64[ap + 352]
# asm 1: mov   352(<ap=int64#1),>temp1=int64#2
# asm 2: mov   352(<ap=%rdi),>temp1=%esi
mov   352(%rdi),%esi

# qhasm: temp2 = mem64[ap + 416]
# asm 1: mov   416(<ap=int64#1),>temp2=int64#3
# asm 2: mov   416(<ap=%rdi),>temp2=%edx
mov   416(%rdi),%edx

# qhasm: mem64[ap + 416] = temp1
# asm 1: mov   <temp1=int64#2,416(<ap=int64#1)
# asm 2: mov   <temp1=%esi,416(<ap=%rdi)
mov   %esi,416(%rdi)

# qhasm: mem64[ap + 352] = temp2
# asm 1: mov   <temp2=int64#3,352(<ap=int64#1)
# asm 2: mov   <temp2=%edx,352(<ap=%rdi)
mov   %edx,352(%rdi)

# qhasm: temp1 = mem64[ap + 356]
# asm 1: mov   356(<ap=int64#1),>temp1=int64#2
# asm 2: mov   356(<ap=%rdi),>temp1=%esi
mov   356(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2464]
# asm 1: mov   2464(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2464(<ap=%rdi),>temp2=%edx
mov   2464(%rdi),%edx

# qhasm: mem64[ap + 2464] = temp1
# asm 1: mov   <temp1=int64#2,2464(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2464(<ap=%rdi)
mov   %esi,2464(%rdi)

# qhasm: mem64[ap + 356] = temp2
# asm 1: mov   <temp2=int64#3,356(<ap=int64#1)
# asm 2: mov   <temp2=%edx,356(<ap=%rdi)
mov   %edx,356(%rdi)

# qhasm: temp1 = mem64[ap + 360]
# asm 1: mov   360(<ap=int64#1),>temp1=int64#2
# asm 2: mov   360(<ap=%rdi),>temp1=%esi
mov   360(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1440]
# asm 1: mov   1440(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1440(<ap=%rdi),>temp2=%edx
mov   1440(%rdi),%edx

# qhasm: mem64[ap + 1440] = temp1
# asm 1: mov   <temp1=int64#2,1440(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1440(<ap=%rdi)
mov   %esi,1440(%rdi)

# qhasm: mem64[ap + 360] = temp2
# asm 1: mov   <temp2=int64#3,360(<ap=int64#1)
# asm 2: mov   <temp2=%edx,360(<ap=%rdi)
mov   %edx,360(%rdi)

# qhasm: temp1 = mem64[ap + 364]
# asm 1: mov   364(<ap=int64#1),>temp1=int64#2
# asm 2: mov   364(<ap=%rdi),>temp1=%esi
mov   364(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3488]
# asm 1: mov   3488(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3488(<ap=%rdi),>temp2=%edx
mov   3488(%rdi),%edx

# qhasm: mem64[ap + 3488] = temp1
# asm 1: mov   <temp1=int64#2,3488(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3488(<ap=%rdi)
mov   %esi,3488(%rdi)

# qhasm: mem64[ap + 364] = temp2
# asm 1: mov   <temp2=int64#3,364(<ap=int64#1)
# asm 2: mov   <temp2=%edx,364(<ap=%rdi)
mov   %edx,364(%rdi)

# qhasm: temp1 = mem64[ap + 368]
# asm 1: mov   368(<ap=int64#1),>temp1=int64#2
# asm 2: mov   368(<ap=%rdi),>temp1=%esi
mov   368(%rdi),%esi

# qhasm: temp2 = mem64[ap + 928]
# asm 1: mov   928(<ap=int64#1),>temp2=int64#3
# asm 2: mov   928(<ap=%rdi),>temp2=%edx
mov   928(%rdi),%edx

# qhasm: mem64[ap + 928] = temp1
# asm 1: mov   <temp1=int64#2,928(<ap=int64#1)
# asm 2: mov   <temp1=%esi,928(<ap=%rdi)
mov   %esi,928(%rdi)

# qhasm: mem64[ap + 368] = temp2
# asm 1: mov   <temp2=int64#3,368(<ap=int64#1)
# asm 2: mov   <temp2=%edx,368(<ap=%rdi)
mov   %edx,368(%rdi)

# qhasm: temp1 = mem64[ap + 372]
# asm 1: mov   372(<ap=int64#1),>temp1=int64#2
# asm 2: mov   372(<ap=%rdi),>temp1=%esi
mov   372(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2976]
# asm 1: mov   2976(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2976(<ap=%rdi),>temp2=%edx
mov   2976(%rdi),%edx

# qhasm: mem64[ap + 2976] = temp1
# asm 1: mov   <temp1=int64#2,2976(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2976(<ap=%rdi)
mov   %esi,2976(%rdi)

# qhasm: mem64[ap + 372] = temp2
# asm 1: mov   <temp2=int64#3,372(<ap=int64#1)
# asm 2: mov   <temp2=%edx,372(<ap=%rdi)
mov   %edx,372(%rdi)

# qhasm: temp1 = mem64[ap + 376]
# asm 1: mov   376(<ap=int64#1),>temp1=int64#2
# asm 2: mov   376(<ap=%rdi),>temp1=%esi
mov   376(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1952]
# asm 1: mov   1952(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1952(<ap=%rdi),>temp2=%edx
mov   1952(%rdi),%edx

# qhasm: mem64[ap + 1952] = temp1
# asm 1: mov   <temp1=int64#2,1952(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1952(<ap=%rdi)
mov   %esi,1952(%rdi)

# qhasm: mem64[ap + 376] = temp2
# asm 1: mov   <temp2=int64#3,376(<ap=int64#1)
# asm 2: mov   <temp2=%edx,376(<ap=%rdi)
mov   %edx,376(%rdi)

# qhasm: temp1 = mem64[ap + 380]
# asm 1: mov   380(<ap=int64#1),>temp1=int64#2
# asm 2: mov   380(<ap=%rdi),>temp1=%esi
mov   380(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4000]
# asm 1: mov   4000(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4000(<ap=%rdi),>temp2=%edx
mov   4000(%rdi),%edx

# qhasm: mem64[ap + 4000] = temp1
# asm 1: mov   <temp1=int64#2,4000(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4000(<ap=%rdi)
mov   %esi,4000(%rdi)

# qhasm: mem64[ap + 380] = temp2
# asm 1: mov   <temp2=int64#3,380(<ap=int64#1)
# asm 2: mov   <temp2=%edx,380(<ap=%rdi)
mov   %edx,380(%rdi)

# qhasm: temp1 = mem64[ap + 388]
# asm 1: mov   388(<ap=int64#1),>temp1=int64#2
# asm 2: mov   388(<ap=%rdi),>temp1=%esi
mov   388(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2144]
# asm 1: mov   2144(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2144(<ap=%rdi),>temp2=%edx
mov   2144(%rdi),%edx

# qhasm: mem64[ap + 2144] = temp1
# asm 1: mov   <temp1=int64#2,2144(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2144(<ap=%rdi)
mov   %esi,2144(%rdi)

# qhasm: mem64[ap + 388] = temp2
# asm 1: mov   <temp2=int64#3,388(<ap=int64#1)
# asm 2: mov   <temp2=%edx,388(<ap=%rdi)
mov   %edx,388(%rdi)

# qhasm: temp1 = mem64[ap + 392]
# asm 1: mov   392(<ap=int64#1),>temp1=int64#2
# asm 2: mov   392(<ap=%rdi),>temp1=%esi
mov   392(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1120]
# asm 1: mov   1120(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1120(<ap=%rdi),>temp2=%edx
mov   1120(%rdi),%edx

# qhasm: mem64[ap + 1120] = temp1
# asm 1: mov   <temp1=int64#2,1120(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1120(<ap=%rdi)
mov   %esi,1120(%rdi)

# qhasm: mem64[ap + 392] = temp2
# asm 1: mov   <temp2=int64#3,392(<ap=int64#1)
# asm 2: mov   <temp2=%edx,392(<ap=%rdi)
mov   %edx,392(%rdi)

# qhasm: temp1 = mem64[ap + 396]
# asm 1: mov   396(<ap=int64#1),>temp1=int64#2
# asm 2: mov   396(<ap=%rdi),>temp1=%esi
mov   396(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3168]
# asm 1: mov   3168(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3168(<ap=%rdi),>temp2=%edx
mov   3168(%rdi),%edx

# qhasm: mem64[ap + 3168] = temp1
# asm 1: mov   <temp1=int64#2,3168(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3168(<ap=%rdi)
mov   %esi,3168(%rdi)

# qhasm: mem64[ap + 396] = temp2
# asm 1: mov   <temp2=int64#3,396(<ap=int64#1)
# asm 2: mov   <temp2=%edx,396(<ap=%rdi)
mov   %edx,396(%rdi)

# qhasm: temp1 = mem64[ap + 400]
# asm 1: mov   400(<ap=int64#1),>temp1=int64#2
# asm 2: mov   400(<ap=%rdi),>temp1=%esi
mov   400(%rdi),%esi

# qhasm: temp2 = mem64[ap + 608]
# asm 1: mov   608(<ap=int64#1),>temp2=int64#3
# asm 2: mov   608(<ap=%rdi),>temp2=%edx
mov   608(%rdi),%edx

# qhasm: mem64[ap + 608] = temp1
# asm 1: mov   <temp1=int64#2,608(<ap=int64#1)
# asm 2: mov   <temp1=%esi,608(<ap=%rdi)
mov   %esi,608(%rdi)

# qhasm: mem64[ap + 400] = temp2
# asm 1: mov   <temp2=int64#3,400(<ap=int64#1)
# asm 2: mov   <temp2=%edx,400(<ap=%rdi)
mov   %edx,400(%rdi)

# qhasm: temp1 = mem64[ap + 404]
# asm 1: mov   404(<ap=int64#1),>temp1=int64#2
# asm 2: mov   404(<ap=%rdi),>temp1=%esi
mov   404(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2656]
# asm 1: mov   2656(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2656(<ap=%rdi),>temp2=%edx
mov   2656(%rdi),%edx

# qhasm: mem64[ap + 2656] = temp1
# asm 1: mov   <temp1=int64#2,2656(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2656(<ap=%rdi)
mov   %esi,2656(%rdi)

# qhasm: mem64[ap + 404] = temp2
# asm 1: mov   <temp2=int64#3,404(<ap=int64#1)
# asm 2: mov   <temp2=%edx,404(<ap=%rdi)
mov   %edx,404(%rdi)

# qhasm: temp1 = mem64[ap + 408]
# asm 1: mov   408(<ap=int64#1),>temp1=int64#2
# asm 2: mov   408(<ap=%rdi),>temp1=%esi
mov   408(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1632]
# asm 1: mov   1632(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1632(<ap=%rdi),>temp2=%edx
mov   1632(%rdi),%edx

# qhasm: mem64[ap + 1632] = temp1
# asm 1: mov   <temp1=int64#2,1632(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1632(<ap=%rdi)
mov   %esi,1632(%rdi)

# qhasm: mem64[ap + 408] = temp2
# asm 1: mov   <temp2=int64#3,408(<ap=int64#1)
# asm 2: mov   <temp2=%edx,408(<ap=%rdi)
mov   %edx,408(%rdi)

# qhasm: temp1 = mem64[ap + 412]
# asm 1: mov   412(<ap=int64#1),>temp1=int64#2
# asm 2: mov   412(<ap=%rdi),>temp1=%esi
mov   412(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3680]
# asm 1: mov   3680(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3680(<ap=%rdi),>temp2=%edx
mov   3680(%rdi),%edx

# qhasm: mem64[ap + 3680] = temp1
# asm 1: mov   <temp1=int64#2,3680(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3680(<ap=%rdi)
mov   %esi,3680(%rdi)

# qhasm: mem64[ap + 412] = temp2
# asm 1: mov   <temp2=int64#3,412(<ap=int64#1)
# asm 2: mov   <temp2=%edx,412(<ap=%rdi)
mov   %edx,412(%rdi)

# qhasm: temp1 = mem64[ap + 420]
# asm 1: mov   420(<ap=int64#1),>temp1=int64#2
# asm 2: mov   420(<ap=%rdi),>temp1=%esi
mov   420(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2400]
# asm 1: mov   2400(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2400(<ap=%rdi),>temp2=%edx
mov   2400(%rdi),%edx

# qhasm: mem64[ap + 2400] = temp1
# asm 1: mov   <temp1=int64#2,2400(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2400(<ap=%rdi)
mov   %esi,2400(%rdi)

# qhasm: mem64[ap + 420] = temp2
# asm 1: mov   <temp2=int64#3,420(<ap=int64#1)
# asm 2: mov   <temp2=%edx,420(<ap=%rdi)
mov   %edx,420(%rdi)

# qhasm: temp1 = mem64[ap + 424]
# asm 1: mov   424(<ap=int64#1),>temp1=int64#2
# asm 2: mov   424(<ap=%rdi),>temp1=%esi
mov   424(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1376]
# asm 1: mov   1376(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1376(<ap=%rdi),>temp2=%edx
mov   1376(%rdi),%edx

# qhasm: mem64[ap + 1376] = temp1
# asm 1: mov   <temp1=int64#2,1376(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1376(<ap=%rdi)
mov   %esi,1376(%rdi)

# qhasm: mem64[ap + 424] = temp2
# asm 1: mov   <temp2=int64#3,424(<ap=int64#1)
# asm 2: mov   <temp2=%edx,424(<ap=%rdi)
mov   %edx,424(%rdi)

# qhasm: temp1 = mem64[ap + 428]
# asm 1: mov   428(<ap=int64#1),>temp1=int64#2
# asm 2: mov   428(<ap=%rdi),>temp1=%esi
mov   428(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3424]
# asm 1: mov   3424(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3424(<ap=%rdi),>temp2=%edx
mov   3424(%rdi),%edx

# qhasm: mem64[ap + 3424] = temp1
# asm 1: mov   <temp1=int64#2,3424(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3424(<ap=%rdi)
mov   %esi,3424(%rdi)

# qhasm: mem64[ap + 428] = temp2
# asm 1: mov   <temp2=int64#3,428(<ap=int64#1)
# asm 2: mov   <temp2=%edx,428(<ap=%rdi)
mov   %edx,428(%rdi)

# qhasm: temp1 = mem64[ap + 432]
# asm 1: mov   432(<ap=int64#1),>temp1=int64#2
# asm 2: mov   432(<ap=%rdi),>temp1=%esi
mov   432(%rdi),%esi

# qhasm: temp2 = mem64[ap + 864]
# asm 1: mov   864(<ap=int64#1),>temp2=int64#3
# asm 2: mov   864(<ap=%rdi),>temp2=%edx
mov   864(%rdi),%edx

# qhasm: mem64[ap + 864] = temp1
# asm 1: mov   <temp1=int64#2,864(<ap=int64#1)
# asm 2: mov   <temp1=%esi,864(<ap=%rdi)
mov   %esi,864(%rdi)

# qhasm: mem64[ap + 432] = temp2
# asm 1: mov   <temp2=int64#3,432(<ap=int64#1)
# asm 2: mov   <temp2=%edx,432(<ap=%rdi)
mov   %edx,432(%rdi)

# qhasm: temp1 = mem64[ap + 436]
# asm 1: mov   436(<ap=int64#1),>temp1=int64#2
# asm 2: mov   436(<ap=%rdi),>temp1=%esi
mov   436(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2912]
# asm 1: mov   2912(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2912(<ap=%rdi),>temp2=%edx
mov   2912(%rdi),%edx

# qhasm: mem64[ap + 2912] = temp1
# asm 1: mov   <temp1=int64#2,2912(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2912(<ap=%rdi)
mov   %esi,2912(%rdi)

# qhasm: mem64[ap + 436] = temp2
# asm 1: mov   <temp2=int64#3,436(<ap=int64#1)
# asm 2: mov   <temp2=%edx,436(<ap=%rdi)
mov   %edx,436(%rdi)

# qhasm: temp1 = mem64[ap + 440]
# asm 1: mov   440(<ap=int64#1),>temp1=int64#2
# asm 2: mov   440(<ap=%rdi),>temp1=%esi
mov   440(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1888]
# asm 1: mov   1888(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1888(<ap=%rdi),>temp2=%edx
mov   1888(%rdi),%edx

# qhasm: mem64[ap + 1888] = temp1
# asm 1: mov   <temp1=int64#2,1888(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1888(<ap=%rdi)
mov   %esi,1888(%rdi)

# qhasm: mem64[ap + 440] = temp2
# asm 1: mov   <temp2=int64#3,440(<ap=int64#1)
# asm 2: mov   <temp2=%edx,440(<ap=%rdi)
mov   %edx,440(%rdi)

# qhasm: temp1 = mem64[ap + 444]
# asm 1: mov   444(<ap=int64#1),>temp1=int64#2
# asm 2: mov   444(<ap=%rdi),>temp1=%esi
mov   444(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3936]
# asm 1: mov   3936(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3936(<ap=%rdi),>temp2=%edx
mov   3936(%rdi),%edx

# qhasm: mem64[ap + 3936] = temp1
# asm 1: mov   <temp1=int64#2,3936(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3936(<ap=%rdi)
mov   %esi,3936(%rdi)

# qhasm: mem64[ap + 444] = temp2
# asm 1: mov   <temp2=int64#3,444(<ap=int64#1)
# asm 2: mov   <temp2=%edx,444(<ap=%rdi)
mov   %edx,444(%rdi)

# qhasm: temp1 = mem64[ap + 452]
# asm 1: mov   452(<ap=int64#1),>temp1=int64#2
# asm 2: mov   452(<ap=%rdi),>temp1=%esi
mov   452(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2272]
# asm 1: mov   2272(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2272(<ap=%rdi),>temp2=%edx
mov   2272(%rdi),%edx

# qhasm: mem64[ap + 2272] = temp1
# asm 1: mov   <temp1=int64#2,2272(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2272(<ap=%rdi)
mov   %esi,2272(%rdi)

# qhasm: mem64[ap + 452] = temp2
# asm 1: mov   <temp2=int64#3,452(<ap=int64#1)
# asm 2: mov   <temp2=%edx,452(<ap=%rdi)
mov   %edx,452(%rdi)

# qhasm: temp1 = mem64[ap + 456]
# asm 1: mov   456(<ap=int64#1),>temp1=int64#2
# asm 2: mov   456(<ap=%rdi),>temp1=%esi
mov   456(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1248]
# asm 1: mov   1248(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1248(<ap=%rdi),>temp2=%edx
mov   1248(%rdi),%edx

# qhasm: mem64[ap + 1248] = temp1
# asm 1: mov   <temp1=int64#2,1248(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1248(<ap=%rdi)
mov   %esi,1248(%rdi)

# qhasm: mem64[ap + 456] = temp2
# asm 1: mov   <temp2=int64#3,456(<ap=int64#1)
# asm 2: mov   <temp2=%edx,456(<ap=%rdi)
mov   %edx,456(%rdi)

# qhasm: temp1 = mem64[ap + 460]
# asm 1: mov   460(<ap=int64#1),>temp1=int64#2
# asm 2: mov   460(<ap=%rdi),>temp1=%esi
mov   460(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3296]
# asm 1: mov   3296(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3296(<ap=%rdi),>temp2=%edx
mov   3296(%rdi),%edx

# qhasm: mem64[ap + 3296] = temp1
# asm 1: mov   <temp1=int64#2,3296(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3296(<ap=%rdi)
mov   %esi,3296(%rdi)

# qhasm: mem64[ap + 460] = temp2
# asm 1: mov   <temp2=int64#3,460(<ap=int64#1)
# asm 2: mov   <temp2=%edx,460(<ap=%rdi)
mov   %edx,460(%rdi)

# qhasm: temp1 = mem64[ap + 464]
# asm 1: mov   464(<ap=int64#1),>temp1=int64#2
# asm 2: mov   464(<ap=%rdi),>temp1=%esi
mov   464(%rdi),%esi

# qhasm: temp2 = mem64[ap + 736]
# asm 1: mov   736(<ap=int64#1),>temp2=int64#3
# asm 2: mov   736(<ap=%rdi),>temp2=%edx
mov   736(%rdi),%edx

# qhasm: mem64[ap + 736] = temp1
# asm 1: mov   <temp1=int64#2,736(<ap=int64#1)
# asm 2: mov   <temp1=%esi,736(<ap=%rdi)
mov   %esi,736(%rdi)

# qhasm: mem64[ap + 464] = temp2
# asm 1: mov   <temp2=int64#3,464(<ap=int64#1)
# asm 2: mov   <temp2=%edx,464(<ap=%rdi)
mov   %edx,464(%rdi)

# qhasm: temp1 = mem64[ap + 468]
# asm 1: mov   468(<ap=int64#1),>temp1=int64#2
# asm 2: mov   468(<ap=%rdi),>temp1=%esi
mov   468(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2784]
# asm 1: mov   2784(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2784(<ap=%rdi),>temp2=%edx
mov   2784(%rdi),%edx

# qhasm: mem64[ap + 2784] = temp1
# asm 1: mov   <temp1=int64#2,2784(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2784(<ap=%rdi)
mov   %esi,2784(%rdi)

# qhasm: mem64[ap + 468] = temp2
# asm 1: mov   <temp2=int64#3,468(<ap=int64#1)
# asm 2: mov   <temp2=%edx,468(<ap=%rdi)
mov   %edx,468(%rdi)

# qhasm: temp1 = mem64[ap + 472]
# asm 1: mov   472(<ap=int64#1),>temp1=int64#2
# asm 2: mov   472(<ap=%rdi),>temp1=%esi
mov   472(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1760]
# asm 1: mov   1760(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1760(<ap=%rdi),>temp2=%edx
mov   1760(%rdi),%edx

# qhasm: mem64[ap + 1760] = temp1
# asm 1: mov   <temp1=int64#2,1760(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1760(<ap=%rdi)
mov   %esi,1760(%rdi)

# qhasm: mem64[ap + 472] = temp2
# asm 1: mov   <temp2=int64#3,472(<ap=int64#1)
# asm 2: mov   <temp2=%edx,472(<ap=%rdi)
mov   %edx,472(%rdi)

# qhasm: temp1 = mem64[ap + 476]
# asm 1: mov   476(<ap=int64#1),>temp1=int64#2
# asm 2: mov   476(<ap=%rdi),>temp1=%esi
mov   476(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3808]
# asm 1: mov   3808(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3808(<ap=%rdi),>temp2=%edx
mov   3808(%rdi),%edx

# qhasm: mem64[ap + 3808] = temp1
# asm 1: mov   <temp1=int64#2,3808(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3808(<ap=%rdi)
mov   %esi,3808(%rdi)

# qhasm: mem64[ap + 476] = temp2
# asm 1: mov   <temp2=int64#3,476(<ap=int64#1)
# asm 2: mov   <temp2=%edx,476(<ap=%rdi)
mov   %edx,476(%rdi)

# qhasm: temp1 = mem64[ap + 484]
# asm 1: mov   484(<ap=int64#1),>temp1=int64#2
# asm 2: mov   484(<ap=%rdi),>temp1=%esi
mov   484(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2528]
# asm 1: mov   2528(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2528(<ap=%rdi),>temp2=%edx
mov   2528(%rdi),%edx

# qhasm: mem64[ap + 2528] = temp1
# asm 1: mov   <temp1=int64#2,2528(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2528(<ap=%rdi)
mov   %esi,2528(%rdi)

# qhasm: mem64[ap + 484] = temp2
# asm 1: mov   <temp2=int64#3,484(<ap=int64#1)
# asm 2: mov   <temp2=%edx,484(<ap=%rdi)
mov   %edx,484(%rdi)

# qhasm: temp1 = mem64[ap + 488]
# asm 1: mov   488(<ap=int64#1),>temp1=int64#2
# asm 2: mov   488(<ap=%rdi),>temp1=%esi
mov   488(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1504]
# asm 1: mov   1504(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1504(<ap=%rdi),>temp2=%edx
mov   1504(%rdi),%edx

# qhasm: mem64[ap + 1504] = temp1
# asm 1: mov   <temp1=int64#2,1504(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1504(<ap=%rdi)
mov   %esi,1504(%rdi)

# qhasm: mem64[ap + 488] = temp2
# asm 1: mov   <temp2=int64#3,488(<ap=int64#1)
# asm 2: mov   <temp2=%edx,488(<ap=%rdi)
mov   %edx,488(%rdi)

# qhasm: temp1 = mem64[ap + 492]
# asm 1: mov   492(<ap=int64#1),>temp1=int64#2
# asm 2: mov   492(<ap=%rdi),>temp1=%esi
mov   492(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3552]
# asm 1: mov   3552(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3552(<ap=%rdi),>temp2=%edx
mov   3552(%rdi),%edx

# qhasm: mem64[ap + 3552] = temp1
# asm 1: mov   <temp1=int64#2,3552(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3552(<ap=%rdi)
mov   %esi,3552(%rdi)

# qhasm: mem64[ap + 492] = temp2
# asm 1: mov   <temp2=int64#3,492(<ap=int64#1)
# asm 2: mov   <temp2=%edx,492(<ap=%rdi)
mov   %edx,492(%rdi)

# qhasm: temp1 = mem64[ap + 496]
# asm 1: mov   496(<ap=int64#1),>temp1=int64#2
# asm 2: mov   496(<ap=%rdi),>temp1=%esi
mov   496(%rdi),%esi

# qhasm: temp2 = mem64[ap + 992]
# asm 1: mov   992(<ap=int64#1),>temp2=int64#3
# asm 2: mov   992(<ap=%rdi),>temp2=%edx
mov   992(%rdi),%edx

# qhasm: mem64[ap + 992] = temp1
# asm 1: mov   <temp1=int64#2,992(<ap=int64#1)
# asm 2: mov   <temp1=%esi,992(<ap=%rdi)
mov   %esi,992(%rdi)

# qhasm: mem64[ap + 496] = temp2
# asm 1: mov   <temp2=int64#3,496(<ap=int64#1)
# asm 2: mov   <temp2=%edx,496(<ap=%rdi)
mov   %edx,496(%rdi)

# qhasm: temp1 = mem64[ap + 500]
# asm 1: mov   500(<ap=int64#1),>temp1=int64#2
# asm 2: mov   500(<ap=%rdi),>temp1=%esi
mov   500(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3040]
# asm 1: mov   3040(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3040(<ap=%rdi),>temp2=%edx
mov   3040(%rdi),%edx

# qhasm: mem64[ap + 3040] = temp1
# asm 1: mov   <temp1=int64#2,3040(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3040(<ap=%rdi)
mov   %esi,3040(%rdi)

# qhasm: mem64[ap + 500] = temp2
# asm 1: mov   <temp2=int64#3,500(<ap=int64#1)
# asm 2: mov   <temp2=%edx,500(<ap=%rdi)
mov   %edx,500(%rdi)

# qhasm: temp1 = mem64[ap + 504]
# asm 1: mov   504(<ap=int64#1),>temp1=int64#2
# asm 2: mov   504(<ap=%rdi),>temp1=%esi
mov   504(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2016]
# asm 1: mov   2016(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2016(<ap=%rdi),>temp2=%edx
mov   2016(%rdi),%edx

# qhasm: mem64[ap + 2016] = temp1
# asm 1: mov   <temp1=int64#2,2016(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2016(<ap=%rdi)
mov   %esi,2016(%rdi)

# qhasm: mem64[ap + 504] = temp2
# asm 1: mov   <temp2=int64#3,504(<ap=int64#1)
# asm 2: mov   <temp2=%edx,504(<ap=%rdi)
mov   %edx,504(%rdi)

# qhasm: temp1 = mem64[ap + 508]
# asm 1: mov   508(<ap=int64#1),>temp1=int64#2
# asm 2: mov   508(<ap=%rdi),>temp1=%esi
mov   508(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4064]
# asm 1: mov   4064(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4064(<ap=%rdi),>temp2=%edx
mov   4064(%rdi),%edx

# qhasm: mem64[ap + 4064] = temp1
# asm 1: mov   <temp1=int64#2,4064(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4064(<ap=%rdi)
mov   %esi,4064(%rdi)

# qhasm: mem64[ap + 508] = temp2
# asm 1: mov   <temp2=int64#3,508(<ap=int64#1)
# asm 2: mov   <temp2=%edx,508(<ap=%rdi)
mov   %edx,508(%rdi)

# qhasm: temp1 = mem64[ap + 516]
# asm 1: mov   516(<ap=int64#1),>temp1=int64#2
# asm 2: mov   516(<ap=%rdi),>temp1=%esi
mov   516(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2064]
# asm 1: mov   2064(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2064(<ap=%rdi),>temp2=%edx
mov   2064(%rdi),%edx

# qhasm: mem64[ap + 2064] = temp1
# asm 1: mov   <temp1=int64#2,2064(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2064(<ap=%rdi)
mov   %esi,2064(%rdi)

# qhasm: mem64[ap + 516] = temp2
# asm 1: mov   <temp2=int64#3,516(<ap=int64#1)
# asm 2: mov   <temp2=%edx,516(<ap=%rdi)
mov   %edx,516(%rdi)

# qhasm: temp1 = mem64[ap + 520]
# asm 1: mov   520(<ap=int64#1),>temp1=int64#2
# asm 2: mov   520(<ap=%rdi),>temp1=%esi
mov   520(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1040]
# asm 1: mov   1040(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1040(<ap=%rdi),>temp2=%edx
mov   1040(%rdi),%edx

# qhasm: mem64[ap + 1040] = temp1
# asm 1: mov   <temp1=int64#2,1040(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1040(<ap=%rdi)
mov   %esi,1040(%rdi)

# qhasm: mem64[ap + 520] = temp2
# asm 1: mov   <temp2=int64#3,520(<ap=int64#1)
# asm 2: mov   <temp2=%edx,520(<ap=%rdi)
mov   %edx,520(%rdi)

# qhasm: temp1 = mem64[ap + 524]
# asm 1: mov   524(<ap=int64#1),>temp1=int64#2
# asm 2: mov   524(<ap=%rdi),>temp1=%esi
mov   524(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3088]
# asm 1: mov   3088(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3088(<ap=%rdi),>temp2=%edx
mov   3088(%rdi),%edx

# qhasm: mem64[ap + 3088] = temp1
# asm 1: mov   <temp1=int64#2,3088(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3088(<ap=%rdi)
mov   %esi,3088(%rdi)

# qhasm: mem64[ap + 524] = temp2
# asm 1: mov   <temp2=int64#3,524(<ap=int64#1)
# asm 2: mov   <temp2=%edx,524(<ap=%rdi)
mov   %edx,524(%rdi)

# qhasm: temp1 = mem64[ap + 532]
# asm 1: mov   532(<ap=int64#1),>temp1=int64#2
# asm 2: mov   532(<ap=%rdi),>temp1=%esi
mov   532(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2576]
# asm 1: mov   2576(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2576(<ap=%rdi),>temp2=%edx
mov   2576(%rdi),%edx

# qhasm: mem64[ap + 2576] = temp1
# asm 1: mov   <temp1=int64#2,2576(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2576(<ap=%rdi)
mov   %esi,2576(%rdi)

# qhasm: mem64[ap + 532] = temp2
# asm 1: mov   <temp2=int64#3,532(<ap=int64#1)
# asm 2: mov   <temp2=%edx,532(<ap=%rdi)
mov   %edx,532(%rdi)

# qhasm: temp1 = mem64[ap + 536]
# asm 1: mov   536(<ap=int64#1),>temp1=int64#2
# asm 2: mov   536(<ap=%rdi),>temp1=%esi
mov   536(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1552]
# asm 1: mov   1552(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1552(<ap=%rdi),>temp2=%edx
mov   1552(%rdi),%edx

# qhasm: mem64[ap + 1552] = temp1
# asm 1: mov   <temp1=int64#2,1552(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1552(<ap=%rdi)
mov   %esi,1552(%rdi)

# qhasm: mem64[ap + 536] = temp2
# asm 1: mov   <temp2=int64#3,536(<ap=int64#1)
# asm 2: mov   <temp2=%edx,536(<ap=%rdi)
mov   %edx,536(%rdi)

# qhasm: temp1 = mem64[ap + 540]
# asm 1: mov   540(<ap=int64#1),>temp1=int64#2
# asm 2: mov   540(<ap=%rdi),>temp1=%esi
mov   540(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3600]
# asm 1: mov   3600(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3600(<ap=%rdi),>temp2=%edx
mov   3600(%rdi),%edx

# qhasm: mem64[ap + 3600] = temp1
# asm 1: mov   <temp1=int64#2,3600(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3600(<ap=%rdi)
mov   %esi,3600(%rdi)

# qhasm: mem64[ap + 540] = temp2
# asm 1: mov   <temp2=int64#3,540(<ap=int64#1)
# asm 2: mov   <temp2=%edx,540(<ap=%rdi)
mov   %edx,540(%rdi)

# qhasm: temp1 = mem64[ap + 548]
# asm 1: mov   548(<ap=int64#1),>temp1=int64#2
# asm 2: mov   548(<ap=%rdi),>temp1=%esi
mov   548(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2320]
# asm 1: mov   2320(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2320(<ap=%rdi),>temp2=%edx
mov   2320(%rdi),%edx

# qhasm: mem64[ap + 2320] = temp1
# asm 1: mov   <temp1=int64#2,2320(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2320(<ap=%rdi)
mov   %esi,2320(%rdi)

# qhasm: mem64[ap + 548] = temp2
# asm 1: mov   <temp2=int64#3,548(<ap=int64#1)
# asm 2: mov   <temp2=%edx,548(<ap=%rdi)
mov   %edx,548(%rdi)

# qhasm: temp1 = mem64[ap + 552]
# asm 1: mov   552(<ap=int64#1),>temp1=int64#2
# asm 2: mov   552(<ap=%rdi),>temp1=%esi
mov   552(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1296]
# asm 1: mov   1296(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1296(<ap=%rdi),>temp2=%edx
mov   1296(%rdi),%edx

# qhasm: mem64[ap + 1296] = temp1
# asm 1: mov   <temp1=int64#2,1296(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1296(<ap=%rdi)
mov   %esi,1296(%rdi)

# qhasm: mem64[ap + 552] = temp2
# asm 1: mov   <temp2=int64#3,552(<ap=int64#1)
# asm 2: mov   <temp2=%edx,552(<ap=%rdi)
mov   %edx,552(%rdi)

# qhasm: temp1 = mem64[ap + 556]
# asm 1: mov   556(<ap=int64#1),>temp1=int64#2
# asm 2: mov   556(<ap=%rdi),>temp1=%esi
mov   556(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3344]
# asm 1: mov   3344(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3344(<ap=%rdi),>temp2=%edx
mov   3344(%rdi),%edx

# qhasm: mem64[ap + 3344] = temp1
# asm 1: mov   <temp1=int64#2,3344(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3344(<ap=%rdi)
mov   %esi,3344(%rdi)

# qhasm: mem64[ap + 556] = temp2
# asm 1: mov   <temp2=int64#3,556(<ap=int64#1)
# asm 2: mov   <temp2=%edx,556(<ap=%rdi)
mov   %edx,556(%rdi)

# qhasm: temp1 = mem64[ap + 560]
# asm 1: mov   560(<ap=int64#1),>temp1=int64#2
# asm 2: mov   560(<ap=%rdi),>temp1=%esi
mov   560(%rdi),%esi

# qhasm: temp2 = mem64[ap + 784]
# asm 1: mov   784(<ap=int64#1),>temp2=int64#3
# asm 2: mov   784(<ap=%rdi),>temp2=%edx
mov   784(%rdi),%edx

# qhasm: mem64[ap + 784] = temp1
# asm 1: mov   <temp1=int64#2,784(<ap=int64#1)
# asm 2: mov   <temp1=%esi,784(<ap=%rdi)
mov   %esi,784(%rdi)

# qhasm: mem64[ap + 560] = temp2
# asm 1: mov   <temp2=int64#3,560(<ap=int64#1)
# asm 2: mov   <temp2=%edx,560(<ap=%rdi)
mov   %edx,560(%rdi)

# qhasm: temp1 = mem64[ap + 564]
# asm 1: mov   564(<ap=int64#1),>temp1=int64#2
# asm 2: mov   564(<ap=%rdi),>temp1=%esi
mov   564(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2832]
# asm 1: mov   2832(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2832(<ap=%rdi),>temp2=%edx
mov   2832(%rdi),%edx

# qhasm: mem64[ap + 2832] = temp1
# asm 1: mov   <temp1=int64#2,2832(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2832(<ap=%rdi)
mov   %esi,2832(%rdi)

# qhasm: mem64[ap + 564] = temp2
# asm 1: mov   <temp2=int64#3,564(<ap=int64#1)
# asm 2: mov   <temp2=%edx,564(<ap=%rdi)
mov   %edx,564(%rdi)

# qhasm: temp1 = mem64[ap + 568]
# asm 1: mov   568(<ap=int64#1),>temp1=int64#2
# asm 2: mov   568(<ap=%rdi),>temp1=%esi
mov   568(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1808]
# asm 1: mov   1808(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1808(<ap=%rdi),>temp2=%edx
mov   1808(%rdi),%edx

# qhasm: mem64[ap + 1808] = temp1
# asm 1: mov   <temp1=int64#2,1808(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1808(<ap=%rdi)
mov   %esi,1808(%rdi)

# qhasm: mem64[ap + 568] = temp2
# asm 1: mov   <temp2=int64#3,568(<ap=int64#1)
# asm 2: mov   <temp2=%edx,568(<ap=%rdi)
mov   %edx,568(%rdi)

# qhasm: temp1 = mem64[ap + 572]
# asm 1: mov   572(<ap=int64#1),>temp1=int64#2
# asm 2: mov   572(<ap=%rdi),>temp1=%esi
mov   572(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3856]
# asm 1: mov   3856(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3856(<ap=%rdi),>temp2=%edx
mov   3856(%rdi),%edx

# qhasm: mem64[ap + 3856] = temp1
# asm 1: mov   <temp1=int64#2,3856(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3856(<ap=%rdi)
mov   %esi,3856(%rdi)

# qhasm: mem64[ap + 572] = temp2
# asm 1: mov   <temp2=int64#3,572(<ap=int64#1)
# asm 2: mov   <temp2=%edx,572(<ap=%rdi)
mov   %edx,572(%rdi)

# qhasm: temp1 = mem64[ap + 580]
# asm 1: mov   580(<ap=int64#1),>temp1=int64#2
# asm 2: mov   580(<ap=%rdi),>temp1=%esi
mov   580(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2192]
# asm 1: mov   2192(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2192(<ap=%rdi),>temp2=%edx
mov   2192(%rdi),%edx

# qhasm: mem64[ap + 2192] = temp1
# asm 1: mov   <temp1=int64#2,2192(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2192(<ap=%rdi)
mov   %esi,2192(%rdi)

# qhasm: mem64[ap + 580] = temp2
# asm 1: mov   <temp2=int64#3,580(<ap=int64#1)
# asm 2: mov   <temp2=%edx,580(<ap=%rdi)
mov   %edx,580(%rdi)

# qhasm: temp1 = mem64[ap + 584]
# asm 1: mov   584(<ap=int64#1),>temp1=int64#2
# asm 2: mov   584(<ap=%rdi),>temp1=%esi
mov   584(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1168]
# asm 1: mov   1168(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1168(<ap=%rdi),>temp2=%edx
mov   1168(%rdi),%edx

# qhasm: mem64[ap + 1168] = temp1
# asm 1: mov   <temp1=int64#2,1168(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1168(<ap=%rdi)
mov   %esi,1168(%rdi)

# qhasm: mem64[ap + 584] = temp2
# asm 1: mov   <temp2=int64#3,584(<ap=int64#1)
# asm 2: mov   <temp2=%edx,584(<ap=%rdi)
mov   %edx,584(%rdi)

# qhasm: temp1 = mem64[ap + 588]
# asm 1: mov   588(<ap=int64#1),>temp1=int64#2
# asm 2: mov   588(<ap=%rdi),>temp1=%esi
mov   588(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3216]
# asm 1: mov   3216(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3216(<ap=%rdi),>temp2=%edx
mov   3216(%rdi),%edx

# qhasm: mem64[ap + 3216] = temp1
# asm 1: mov   <temp1=int64#2,3216(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3216(<ap=%rdi)
mov   %esi,3216(%rdi)

# qhasm: mem64[ap + 588] = temp2
# asm 1: mov   <temp2=int64#3,588(<ap=int64#1)
# asm 2: mov   <temp2=%edx,588(<ap=%rdi)
mov   %edx,588(%rdi)

# qhasm: temp1 = mem64[ap + 592]
# asm 1: mov   592(<ap=int64#1),>temp1=int64#2
# asm 2: mov   592(<ap=%rdi),>temp1=%esi
mov   592(%rdi),%esi

# qhasm: temp2 = mem64[ap + 656]
# asm 1: mov   656(<ap=int64#1),>temp2=int64#3
# asm 2: mov   656(<ap=%rdi),>temp2=%edx
mov   656(%rdi),%edx

# qhasm: mem64[ap + 656] = temp1
# asm 1: mov   <temp1=int64#2,656(<ap=int64#1)
# asm 2: mov   <temp1=%esi,656(<ap=%rdi)
mov   %esi,656(%rdi)

# qhasm: mem64[ap + 592] = temp2
# asm 1: mov   <temp2=int64#3,592(<ap=int64#1)
# asm 2: mov   <temp2=%edx,592(<ap=%rdi)
mov   %edx,592(%rdi)

# qhasm: temp1 = mem64[ap + 596]
# asm 1: mov   596(<ap=int64#1),>temp1=int64#2
# asm 2: mov   596(<ap=%rdi),>temp1=%esi
mov   596(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2704]
# asm 1: mov   2704(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2704(<ap=%rdi),>temp2=%edx
mov   2704(%rdi),%edx

# qhasm: mem64[ap + 2704] = temp1
# asm 1: mov   <temp1=int64#2,2704(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2704(<ap=%rdi)
mov   %esi,2704(%rdi)

# qhasm: mem64[ap + 596] = temp2
# asm 1: mov   <temp2=int64#3,596(<ap=int64#1)
# asm 2: mov   <temp2=%edx,596(<ap=%rdi)
mov   %edx,596(%rdi)

# qhasm: temp1 = mem64[ap + 600]
# asm 1: mov   600(<ap=int64#1),>temp1=int64#2
# asm 2: mov   600(<ap=%rdi),>temp1=%esi
mov   600(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1680]
# asm 1: mov   1680(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1680(<ap=%rdi),>temp2=%edx
mov   1680(%rdi),%edx

# qhasm: mem64[ap + 1680] = temp1
# asm 1: mov   <temp1=int64#2,1680(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1680(<ap=%rdi)
mov   %esi,1680(%rdi)

# qhasm: mem64[ap + 600] = temp2
# asm 1: mov   <temp2=int64#3,600(<ap=int64#1)
# asm 2: mov   <temp2=%edx,600(<ap=%rdi)
mov   %edx,600(%rdi)

# qhasm: temp1 = mem64[ap + 604]
# asm 1: mov   604(<ap=int64#1),>temp1=int64#2
# asm 2: mov   604(<ap=%rdi),>temp1=%esi
mov   604(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3728]
# asm 1: mov   3728(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3728(<ap=%rdi),>temp2=%edx
mov   3728(%rdi),%edx

# qhasm: mem64[ap + 3728] = temp1
# asm 1: mov   <temp1=int64#2,3728(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3728(<ap=%rdi)
mov   %esi,3728(%rdi)

# qhasm: mem64[ap + 604] = temp2
# asm 1: mov   <temp2=int64#3,604(<ap=int64#1)
# asm 2: mov   <temp2=%edx,604(<ap=%rdi)
mov   %edx,604(%rdi)

# qhasm: temp1 = mem64[ap + 612]
# asm 1: mov   612(<ap=int64#1),>temp1=int64#2
# asm 2: mov   612(<ap=%rdi),>temp1=%esi
mov   612(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2448]
# asm 1: mov   2448(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2448(<ap=%rdi),>temp2=%edx
mov   2448(%rdi),%edx

# qhasm: mem64[ap + 2448] = temp1
# asm 1: mov   <temp1=int64#2,2448(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2448(<ap=%rdi)
mov   %esi,2448(%rdi)

# qhasm: mem64[ap + 612] = temp2
# asm 1: mov   <temp2=int64#3,612(<ap=int64#1)
# asm 2: mov   <temp2=%edx,612(<ap=%rdi)
mov   %edx,612(%rdi)

# qhasm: temp1 = mem64[ap + 616]
# asm 1: mov   616(<ap=int64#1),>temp1=int64#2
# asm 2: mov   616(<ap=%rdi),>temp1=%esi
mov   616(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1424]
# asm 1: mov   1424(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1424(<ap=%rdi),>temp2=%edx
mov   1424(%rdi),%edx

# qhasm: mem64[ap + 1424] = temp1
# asm 1: mov   <temp1=int64#2,1424(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1424(<ap=%rdi)
mov   %esi,1424(%rdi)

# qhasm: mem64[ap + 616] = temp2
# asm 1: mov   <temp2=int64#3,616(<ap=int64#1)
# asm 2: mov   <temp2=%edx,616(<ap=%rdi)
mov   %edx,616(%rdi)

# qhasm: temp1 = mem64[ap + 620]
# asm 1: mov   620(<ap=int64#1),>temp1=int64#2
# asm 2: mov   620(<ap=%rdi),>temp1=%esi
mov   620(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3472]
# asm 1: mov   3472(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3472(<ap=%rdi),>temp2=%edx
mov   3472(%rdi),%edx

# qhasm: mem64[ap + 3472] = temp1
# asm 1: mov   <temp1=int64#2,3472(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3472(<ap=%rdi)
mov   %esi,3472(%rdi)

# qhasm: mem64[ap + 620] = temp2
# asm 1: mov   <temp2=int64#3,620(<ap=int64#1)
# asm 2: mov   <temp2=%edx,620(<ap=%rdi)
mov   %edx,620(%rdi)

# qhasm: temp1 = mem64[ap + 624]
# asm 1: mov   624(<ap=int64#1),>temp1=int64#2
# asm 2: mov   624(<ap=%rdi),>temp1=%esi
mov   624(%rdi),%esi

# qhasm: temp2 = mem64[ap + 912]
# asm 1: mov   912(<ap=int64#1),>temp2=int64#3
# asm 2: mov   912(<ap=%rdi),>temp2=%edx
mov   912(%rdi),%edx

# qhasm: mem64[ap + 912] = temp1
# asm 1: mov   <temp1=int64#2,912(<ap=int64#1)
# asm 2: mov   <temp1=%esi,912(<ap=%rdi)
mov   %esi,912(%rdi)

# qhasm: mem64[ap + 624] = temp2
# asm 1: mov   <temp2=int64#3,624(<ap=int64#1)
# asm 2: mov   <temp2=%edx,624(<ap=%rdi)
mov   %edx,624(%rdi)

# qhasm: temp1 = mem64[ap + 628]
# asm 1: mov   628(<ap=int64#1),>temp1=int64#2
# asm 2: mov   628(<ap=%rdi),>temp1=%esi
mov   628(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2960]
# asm 1: mov   2960(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2960(<ap=%rdi),>temp2=%edx
mov   2960(%rdi),%edx

# qhasm: mem64[ap + 2960] = temp1
# asm 1: mov   <temp1=int64#2,2960(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2960(<ap=%rdi)
mov   %esi,2960(%rdi)

# qhasm: mem64[ap + 628] = temp2
# asm 1: mov   <temp2=int64#3,628(<ap=int64#1)
# asm 2: mov   <temp2=%edx,628(<ap=%rdi)
mov   %edx,628(%rdi)

# qhasm: temp1 = mem64[ap + 632]
# asm 1: mov   632(<ap=int64#1),>temp1=int64#2
# asm 2: mov   632(<ap=%rdi),>temp1=%esi
mov   632(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1936]
# asm 1: mov   1936(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1936(<ap=%rdi),>temp2=%edx
mov   1936(%rdi),%edx

# qhasm: mem64[ap + 1936] = temp1
# asm 1: mov   <temp1=int64#2,1936(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1936(<ap=%rdi)
mov   %esi,1936(%rdi)

# qhasm: mem64[ap + 632] = temp2
# asm 1: mov   <temp2=int64#3,632(<ap=int64#1)
# asm 2: mov   <temp2=%edx,632(<ap=%rdi)
mov   %edx,632(%rdi)

# qhasm: temp1 = mem64[ap + 636]
# asm 1: mov   636(<ap=int64#1),>temp1=int64#2
# asm 2: mov   636(<ap=%rdi),>temp1=%esi
mov   636(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3984]
# asm 1: mov   3984(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3984(<ap=%rdi),>temp2=%edx
mov   3984(%rdi),%edx

# qhasm: mem64[ap + 3984] = temp1
# asm 1: mov   <temp1=int64#2,3984(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3984(<ap=%rdi)
mov   %esi,3984(%rdi)

# qhasm: mem64[ap + 636] = temp2
# asm 1: mov   <temp2=int64#3,636(<ap=int64#1)
# asm 2: mov   <temp2=%edx,636(<ap=%rdi)
mov   %edx,636(%rdi)

# qhasm: temp1 = mem64[ap + 644]
# asm 1: mov   644(<ap=int64#1),>temp1=int64#2
# asm 2: mov   644(<ap=%rdi),>temp1=%esi
mov   644(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2128]
# asm 1: mov   2128(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2128(<ap=%rdi),>temp2=%edx
mov   2128(%rdi),%edx

# qhasm: mem64[ap + 2128] = temp1
# asm 1: mov   <temp1=int64#2,2128(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2128(<ap=%rdi)
mov   %esi,2128(%rdi)

# qhasm: mem64[ap + 644] = temp2
# asm 1: mov   <temp2=int64#3,644(<ap=int64#1)
# asm 2: mov   <temp2=%edx,644(<ap=%rdi)
mov   %edx,644(%rdi)

# qhasm: temp1 = mem64[ap + 648]
# asm 1: mov   648(<ap=int64#1),>temp1=int64#2
# asm 2: mov   648(<ap=%rdi),>temp1=%esi
mov   648(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1104]
# asm 1: mov   1104(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1104(<ap=%rdi),>temp2=%edx
mov   1104(%rdi),%edx

# qhasm: mem64[ap + 1104] = temp1
# asm 1: mov   <temp1=int64#2,1104(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1104(<ap=%rdi)
mov   %esi,1104(%rdi)

# qhasm: mem64[ap + 648] = temp2
# asm 1: mov   <temp2=int64#3,648(<ap=int64#1)
# asm 2: mov   <temp2=%edx,648(<ap=%rdi)
mov   %edx,648(%rdi)

# qhasm: temp1 = mem64[ap + 652]
# asm 1: mov   652(<ap=int64#1),>temp1=int64#2
# asm 2: mov   652(<ap=%rdi),>temp1=%esi
mov   652(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3152]
# asm 1: mov   3152(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3152(<ap=%rdi),>temp2=%edx
mov   3152(%rdi),%edx

# qhasm: mem64[ap + 3152] = temp1
# asm 1: mov   <temp1=int64#2,3152(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3152(<ap=%rdi)
mov   %esi,3152(%rdi)

# qhasm: mem64[ap + 652] = temp2
# asm 1: mov   <temp2=int64#3,652(<ap=int64#1)
# asm 2: mov   <temp2=%edx,652(<ap=%rdi)
mov   %edx,652(%rdi)

# qhasm: temp1 = mem64[ap + 660]
# asm 1: mov   660(<ap=int64#1),>temp1=int64#2
# asm 2: mov   660(<ap=%rdi),>temp1=%esi
mov   660(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2640]
# asm 1: mov   2640(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2640(<ap=%rdi),>temp2=%edx
mov   2640(%rdi),%edx

# qhasm: mem64[ap + 2640] = temp1
# asm 1: mov   <temp1=int64#2,2640(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2640(<ap=%rdi)
mov   %esi,2640(%rdi)

# qhasm: mem64[ap + 660] = temp2
# asm 1: mov   <temp2=int64#3,660(<ap=int64#1)
# asm 2: mov   <temp2=%edx,660(<ap=%rdi)
mov   %edx,660(%rdi)

# qhasm: temp1 = mem64[ap + 664]
# asm 1: mov   664(<ap=int64#1),>temp1=int64#2
# asm 2: mov   664(<ap=%rdi),>temp1=%esi
mov   664(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1616]
# asm 1: mov   1616(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1616(<ap=%rdi),>temp2=%edx
mov   1616(%rdi),%edx

# qhasm: mem64[ap + 1616] = temp1
# asm 1: mov   <temp1=int64#2,1616(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1616(<ap=%rdi)
mov   %esi,1616(%rdi)

# qhasm: mem64[ap + 664] = temp2
# asm 1: mov   <temp2=int64#3,664(<ap=int64#1)
# asm 2: mov   <temp2=%edx,664(<ap=%rdi)
mov   %edx,664(%rdi)

# qhasm: temp1 = mem64[ap + 668]
# asm 1: mov   668(<ap=int64#1),>temp1=int64#2
# asm 2: mov   668(<ap=%rdi),>temp1=%esi
mov   668(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3664]
# asm 1: mov   3664(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3664(<ap=%rdi),>temp2=%edx
mov   3664(%rdi),%edx

# qhasm: mem64[ap + 3664] = temp1
# asm 1: mov   <temp1=int64#2,3664(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3664(<ap=%rdi)
mov   %esi,3664(%rdi)

# qhasm: mem64[ap + 668] = temp2
# asm 1: mov   <temp2=int64#3,668(<ap=int64#1)
# asm 2: mov   <temp2=%edx,668(<ap=%rdi)
mov   %edx,668(%rdi)

# qhasm: temp1 = mem64[ap + 676]
# asm 1: mov   676(<ap=int64#1),>temp1=int64#2
# asm 2: mov   676(<ap=%rdi),>temp1=%esi
mov   676(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2384]
# asm 1: mov   2384(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2384(<ap=%rdi),>temp2=%edx
mov   2384(%rdi),%edx

# qhasm: mem64[ap + 2384] = temp1
# asm 1: mov   <temp1=int64#2,2384(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2384(<ap=%rdi)
mov   %esi,2384(%rdi)

# qhasm: mem64[ap + 676] = temp2
# asm 1: mov   <temp2=int64#3,676(<ap=int64#1)
# asm 2: mov   <temp2=%edx,676(<ap=%rdi)
mov   %edx,676(%rdi)

# qhasm: temp1 = mem64[ap + 680]
# asm 1: mov   680(<ap=int64#1),>temp1=int64#2
# asm 2: mov   680(<ap=%rdi),>temp1=%esi
mov   680(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1360]
# asm 1: mov   1360(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1360(<ap=%rdi),>temp2=%edx
mov   1360(%rdi),%edx

# qhasm: mem64[ap + 1360] = temp1
# asm 1: mov   <temp1=int64#2,1360(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1360(<ap=%rdi)
mov   %esi,1360(%rdi)

# qhasm: mem64[ap + 680] = temp2
# asm 1: mov   <temp2=int64#3,680(<ap=int64#1)
# asm 2: mov   <temp2=%edx,680(<ap=%rdi)
mov   %edx,680(%rdi)

# qhasm: temp1 = mem64[ap + 684]
# asm 1: mov   684(<ap=int64#1),>temp1=int64#2
# asm 2: mov   684(<ap=%rdi),>temp1=%esi
mov   684(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3408]
# asm 1: mov   3408(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3408(<ap=%rdi),>temp2=%edx
mov   3408(%rdi),%edx

# qhasm: mem64[ap + 3408] = temp1
# asm 1: mov   <temp1=int64#2,3408(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3408(<ap=%rdi)
mov   %esi,3408(%rdi)

# qhasm: mem64[ap + 684] = temp2
# asm 1: mov   <temp2=int64#3,684(<ap=int64#1)
# asm 2: mov   <temp2=%edx,684(<ap=%rdi)
mov   %edx,684(%rdi)

# qhasm: temp1 = mem64[ap + 688]
# asm 1: mov   688(<ap=int64#1),>temp1=int64#2
# asm 2: mov   688(<ap=%rdi),>temp1=%esi
mov   688(%rdi),%esi

# qhasm: temp2 = mem64[ap + 848]
# asm 1: mov   848(<ap=int64#1),>temp2=int64#3
# asm 2: mov   848(<ap=%rdi),>temp2=%edx
mov   848(%rdi),%edx

# qhasm: mem64[ap + 848] = temp1
# asm 1: mov   <temp1=int64#2,848(<ap=int64#1)
# asm 2: mov   <temp1=%esi,848(<ap=%rdi)
mov   %esi,848(%rdi)

# qhasm: mem64[ap + 688] = temp2
# asm 1: mov   <temp2=int64#3,688(<ap=int64#1)
# asm 2: mov   <temp2=%edx,688(<ap=%rdi)
mov   %edx,688(%rdi)

# qhasm: temp1 = mem64[ap + 692]
# asm 1: mov   692(<ap=int64#1),>temp1=int64#2
# asm 2: mov   692(<ap=%rdi),>temp1=%esi
mov   692(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2896]
# asm 1: mov   2896(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2896(<ap=%rdi),>temp2=%edx
mov   2896(%rdi),%edx

# qhasm: mem64[ap + 2896] = temp1
# asm 1: mov   <temp1=int64#2,2896(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2896(<ap=%rdi)
mov   %esi,2896(%rdi)

# qhasm: mem64[ap + 692] = temp2
# asm 1: mov   <temp2=int64#3,692(<ap=int64#1)
# asm 2: mov   <temp2=%edx,692(<ap=%rdi)
mov   %edx,692(%rdi)

# qhasm: temp1 = mem64[ap + 696]
# asm 1: mov   696(<ap=int64#1),>temp1=int64#2
# asm 2: mov   696(<ap=%rdi),>temp1=%esi
mov   696(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1872]
# asm 1: mov   1872(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1872(<ap=%rdi),>temp2=%edx
mov   1872(%rdi),%edx

# qhasm: mem64[ap + 1872] = temp1
# asm 1: mov   <temp1=int64#2,1872(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1872(<ap=%rdi)
mov   %esi,1872(%rdi)

# qhasm: mem64[ap + 696] = temp2
# asm 1: mov   <temp2=int64#3,696(<ap=int64#1)
# asm 2: mov   <temp2=%edx,696(<ap=%rdi)
mov   %edx,696(%rdi)

# qhasm: temp1 = mem64[ap + 700]
# asm 1: mov   700(<ap=int64#1),>temp1=int64#2
# asm 2: mov   700(<ap=%rdi),>temp1=%esi
mov   700(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3920]
# asm 1: mov   3920(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3920(<ap=%rdi),>temp2=%edx
mov   3920(%rdi),%edx

# qhasm: mem64[ap + 3920] = temp1
# asm 1: mov   <temp1=int64#2,3920(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3920(<ap=%rdi)
mov   %esi,3920(%rdi)

# qhasm: mem64[ap + 700] = temp2
# asm 1: mov   <temp2=int64#3,700(<ap=int64#1)
# asm 2: mov   <temp2=%edx,700(<ap=%rdi)
mov   %edx,700(%rdi)

# qhasm: temp1 = mem64[ap + 708]
# asm 1: mov   708(<ap=int64#1),>temp1=int64#2
# asm 2: mov   708(<ap=%rdi),>temp1=%esi
mov   708(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2256]
# asm 1: mov   2256(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2256(<ap=%rdi),>temp2=%edx
mov   2256(%rdi),%edx

# qhasm: mem64[ap + 2256] = temp1
# asm 1: mov   <temp1=int64#2,2256(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2256(<ap=%rdi)
mov   %esi,2256(%rdi)

# qhasm: mem64[ap + 708] = temp2
# asm 1: mov   <temp2=int64#3,708(<ap=int64#1)
# asm 2: mov   <temp2=%edx,708(<ap=%rdi)
mov   %edx,708(%rdi)

# qhasm: temp1 = mem64[ap + 712]
# asm 1: mov   712(<ap=int64#1),>temp1=int64#2
# asm 2: mov   712(<ap=%rdi),>temp1=%esi
mov   712(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1232]
# asm 1: mov   1232(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1232(<ap=%rdi),>temp2=%edx
mov   1232(%rdi),%edx

# qhasm: mem64[ap + 1232] = temp1
# asm 1: mov   <temp1=int64#2,1232(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1232(<ap=%rdi)
mov   %esi,1232(%rdi)

# qhasm: mem64[ap + 712] = temp2
# asm 1: mov   <temp2=int64#3,712(<ap=int64#1)
# asm 2: mov   <temp2=%edx,712(<ap=%rdi)
mov   %edx,712(%rdi)

# qhasm: temp1 = mem64[ap + 716]
# asm 1: mov   716(<ap=int64#1),>temp1=int64#2
# asm 2: mov   716(<ap=%rdi),>temp1=%esi
mov   716(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3280]
# asm 1: mov   3280(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3280(<ap=%rdi),>temp2=%edx
mov   3280(%rdi),%edx

# qhasm: mem64[ap + 3280] = temp1
# asm 1: mov   <temp1=int64#2,3280(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3280(<ap=%rdi)
mov   %esi,3280(%rdi)

# qhasm: mem64[ap + 716] = temp2
# asm 1: mov   <temp2=int64#3,716(<ap=int64#1)
# asm 2: mov   <temp2=%edx,716(<ap=%rdi)
mov   %edx,716(%rdi)

# qhasm: temp1 = mem64[ap + 724]
# asm 1: mov   724(<ap=int64#1),>temp1=int64#2
# asm 2: mov   724(<ap=%rdi),>temp1=%esi
mov   724(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2768]
# asm 1: mov   2768(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2768(<ap=%rdi),>temp2=%edx
mov   2768(%rdi),%edx

# qhasm: mem64[ap + 2768] = temp1
# asm 1: mov   <temp1=int64#2,2768(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2768(<ap=%rdi)
mov   %esi,2768(%rdi)

# qhasm: mem64[ap + 724] = temp2
# asm 1: mov   <temp2=int64#3,724(<ap=int64#1)
# asm 2: mov   <temp2=%edx,724(<ap=%rdi)
mov   %edx,724(%rdi)

# qhasm: temp1 = mem64[ap + 728]
# asm 1: mov   728(<ap=int64#1),>temp1=int64#2
# asm 2: mov   728(<ap=%rdi),>temp1=%esi
mov   728(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1744]
# asm 1: mov   1744(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1744(<ap=%rdi),>temp2=%edx
mov   1744(%rdi),%edx

# qhasm: mem64[ap + 1744] = temp1
# asm 1: mov   <temp1=int64#2,1744(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1744(<ap=%rdi)
mov   %esi,1744(%rdi)

# qhasm: mem64[ap + 728] = temp2
# asm 1: mov   <temp2=int64#3,728(<ap=int64#1)
# asm 2: mov   <temp2=%edx,728(<ap=%rdi)
mov   %edx,728(%rdi)

# qhasm: temp1 = mem64[ap + 732]
# asm 1: mov   732(<ap=int64#1),>temp1=int64#2
# asm 2: mov   732(<ap=%rdi),>temp1=%esi
mov   732(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3792]
# asm 1: mov   3792(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3792(<ap=%rdi),>temp2=%edx
mov   3792(%rdi),%edx

# qhasm: mem64[ap + 3792] = temp1
# asm 1: mov   <temp1=int64#2,3792(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3792(<ap=%rdi)
mov   %esi,3792(%rdi)

# qhasm: mem64[ap + 732] = temp2
# asm 1: mov   <temp2=int64#3,732(<ap=int64#1)
# asm 2: mov   <temp2=%edx,732(<ap=%rdi)
mov   %edx,732(%rdi)

# qhasm: temp1 = mem64[ap + 740]
# asm 1: mov   740(<ap=int64#1),>temp1=int64#2
# asm 2: mov   740(<ap=%rdi),>temp1=%esi
mov   740(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2512]
# asm 1: mov   2512(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2512(<ap=%rdi),>temp2=%edx
mov   2512(%rdi),%edx

# qhasm: mem64[ap + 2512] = temp1
# asm 1: mov   <temp1=int64#2,2512(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2512(<ap=%rdi)
mov   %esi,2512(%rdi)

# qhasm: mem64[ap + 740] = temp2
# asm 1: mov   <temp2=int64#3,740(<ap=int64#1)
# asm 2: mov   <temp2=%edx,740(<ap=%rdi)
mov   %edx,740(%rdi)

# qhasm: temp1 = mem64[ap + 744]
# asm 1: mov   744(<ap=int64#1),>temp1=int64#2
# asm 2: mov   744(<ap=%rdi),>temp1=%esi
mov   744(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1488]
# asm 1: mov   1488(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1488(<ap=%rdi),>temp2=%edx
mov   1488(%rdi),%edx

# qhasm: mem64[ap + 1488] = temp1
# asm 1: mov   <temp1=int64#2,1488(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1488(<ap=%rdi)
mov   %esi,1488(%rdi)

# qhasm: mem64[ap + 744] = temp2
# asm 1: mov   <temp2=int64#3,744(<ap=int64#1)
# asm 2: mov   <temp2=%edx,744(<ap=%rdi)
mov   %edx,744(%rdi)

# qhasm: temp1 = mem64[ap + 748]
# asm 1: mov   748(<ap=int64#1),>temp1=int64#2
# asm 2: mov   748(<ap=%rdi),>temp1=%esi
mov   748(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3536]
# asm 1: mov   3536(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3536(<ap=%rdi),>temp2=%edx
mov   3536(%rdi),%edx

# qhasm: mem64[ap + 3536] = temp1
# asm 1: mov   <temp1=int64#2,3536(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3536(<ap=%rdi)
mov   %esi,3536(%rdi)

# qhasm: mem64[ap + 748] = temp2
# asm 1: mov   <temp2=int64#3,748(<ap=int64#1)
# asm 2: mov   <temp2=%edx,748(<ap=%rdi)
mov   %edx,748(%rdi)

# qhasm: temp1 = mem64[ap + 752]
# asm 1: mov   752(<ap=int64#1),>temp1=int64#2
# asm 2: mov   752(<ap=%rdi),>temp1=%esi
mov   752(%rdi),%esi

# qhasm: temp2 = mem64[ap + 976]
# asm 1: mov   976(<ap=int64#1),>temp2=int64#3
# asm 2: mov   976(<ap=%rdi),>temp2=%edx
mov   976(%rdi),%edx

# qhasm: mem64[ap + 976] = temp1
# asm 1: mov   <temp1=int64#2,976(<ap=int64#1)
# asm 2: mov   <temp1=%esi,976(<ap=%rdi)
mov   %esi,976(%rdi)

# qhasm: mem64[ap + 752] = temp2
# asm 1: mov   <temp2=int64#3,752(<ap=int64#1)
# asm 2: mov   <temp2=%edx,752(<ap=%rdi)
mov   %edx,752(%rdi)

# qhasm: temp1 = mem64[ap + 756]
# asm 1: mov   756(<ap=int64#1),>temp1=int64#2
# asm 2: mov   756(<ap=%rdi),>temp1=%esi
mov   756(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3024]
# asm 1: mov   3024(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3024(<ap=%rdi),>temp2=%edx
mov   3024(%rdi),%edx

# qhasm: mem64[ap + 3024] = temp1
# asm 1: mov   <temp1=int64#2,3024(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3024(<ap=%rdi)
mov   %esi,3024(%rdi)

# qhasm: mem64[ap + 756] = temp2
# asm 1: mov   <temp2=int64#3,756(<ap=int64#1)
# asm 2: mov   <temp2=%edx,756(<ap=%rdi)
mov   %edx,756(%rdi)

# qhasm: temp1 = mem64[ap + 760]
# asm 1: mov   760(<ap=int64#1),>temp1=int64#2
# asm 2: mov   760(<ap=%rdi),>temp1=%esi
mov   760(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2000]
# asm 1: mov   2000(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2000(<ap=%rdi),>temp2=%edx
mov   2000(%rdi),%edx

# qhasm: mem64[ap + 2000] = temp1
# asm 1: mov   <temp1=int64#2,2000(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2000(<ap=%rdi)
mov   %esi,2000(%rdi)

# qhasm: mem64[ap + 760] = temp2
# asm 1: mov   <temp2=int64#3,760(<ap=int64#1)
# asm 2: mov   <temp2=%edx,760(<ap=%rdi)
mov   %edx,760(%rdi)

# qhasm: temp1 = mem64[ap + 764]
# asm 1: mov   764(<ap=int64#1),>temp1=int64#2
# asm 2: mov   764(<ap=%rdi),>temp1=%esi
mov   764(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4048]
# asm 1: mov   4048(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4048(<ap=%rdi),>temp2=%edx
mov   4048(%rdi),%edx

# qhasm: mem64[ap + 4048] = temp1
# asm 1: mov   <temp1=int64#2,4048(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4048(<ap=%rdi)
mov   %esi,4048(%rdi)

# qhasm: mem64[ap + 764] = temp2
# asm 1: mov   <temp2=int64#3,764(<ap=int64#1)
# asm 2: mov   <temp2=%edx,764(<ap=%rdi)
mov   %edx,764(%rdi)

# qhasm: temp1 = mem64[ap + 772]
# asm 1: mov   772(<ap=int64#1),>temp1=int64#2
# asm 2: mov   772(<ap=%rdi),>temp1=%esi
mov   772(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2096]
# asm 1: mov   2096(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2096(<ap=%rdi),>temp2=%edx
mov   2096(%rdi),%edx

# qhasm: mem64[ap + 2096] = temp1
# asm 1: mov   <temp1=int64#2,2096(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2096(<ap=%rdi)
mov   %esi,2096(%rdi)

# qhasm: mem64[ap + 772] = temp2
# asm 1: mov   <temp2=int64#3,772(<ap=int64#1)
# asm 2: mov   <temp2=%edx,772(<ap=%rdi)
mov   %edx,772(%rdi)

# qhasm: temp1 = mem64[ap + 776]
# asm 1: mov   776(<ap=int64#1),>temp1=int64#2
# asm 2: mov   776(<ap=%rdi),>temp1=%esi
mov   776(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1072]
# asm 1: mov   1072(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1072(<ap=%rdi),>temp2=%edx
mov   1072(%rdi),%edx

# qhasm: mem64[ap + 1072] = temp1
# asm 1: mov   <temp1=int64#2,1072(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1072(<ap=%rdi)
mov   %esi,1072(%rdi)

# qhasm: mem64[ap + 776] = temp2
# asm 1: mov   <temp2=int64#3,776(<ap=int64#1)
# asm 2: mov   <temp2=%edx,776(<ap=%rdi)
mov   %edx,776(%rdi)

# qhasm: temp1 = mem64[ap + 780]
# asm 1: mov   780(<ap=int64#1),>temp1=int64#2
# asm 2: mov   780(<ap=%rdi),>temp1=%esi
mov   780(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3120]
# asm 1: mov   3120(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3120(<ap=%rdi),>temp2=%edx
mov   3120(%rdi),%edx

# qhasm: mem64[ap + 3120] = temp1
# asm 1: mov   <temp1=int64#2,3120(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3120(<ap=%rdi)
mov   %esi,3120(%rdi)

# qhasm: mem64[ap + 780] = temp2
# asm 1: mov   <temp2=int64#3,780(<ap=int64#1)
# asm 2: mov   <temp2=%edx,780(<ap=%rdi)
mov   %edx,780(%rdi)

# qhasm: temp1 = mem64[ap + 788]
# asm 1: mov   788(<ap=int64#1),>temp1=int64#2
# asm 2: mov   788(<ap=%rdi),>temp1=%esi
mov   788(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2608]
# asm 1: mov   2608(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2608(<ap=%rdi),>temp2=%edx
mov   2608(%rdi),%edx

# qhasm: mem64[ap + 2608] = temp1
# asm 1: mov   <temp1=int64#2,2608(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2608(<ap=%rdi)
mov   %esi,2608(%rdi)

# qhasm: mem64[ap + 788] = temp2
# asm 1: mov   <temp2=int64#3,788(<ap=int64#1)
# asm 2: mov   <temp2=%edx,788(<ap=%rdi)
mov   %edx,788(%rdi)

# qhasm: temp1 = mem64[ap + 792]
# asm 1: mov   792(<ap=int64#1),>temp1=int64#2
# asm 2: mov   792(<ap=%rdi),>temp1=%esi
mov   792(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1584]
# asm 1: mov   1584(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1584(<ap=%rdi),>temp2=%edx
mov   1584(%rdi),%edx

# qhasm: mem64[ap + 1584] = temp1
# asm 1: mov   <temp1=int64#2,1584(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1584(<ap=%rdi)
mov   %esi,1584(%rdi)

# qhasm: mem64[ap + 792] = temp2
# asm 1: mov   <temp2=int64#3,792(<ap=int64#1)
# asm 2: mov   <temp2=%edx,792(<ap=%rdi)
mov   %edx,792(%rdi)

# qhasm: temp1 = mem64[ap + 796]
# asm 1: mov   796(<ap=int64#1),>temp1=int64#2
# asm 2: mov   796(<ap=%rdi),>temp1=%esi
mov   796(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3632]
# asm 1: mov   3632(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3632(<ap=%rdi),>temp2=%edx
mov   3632(%rdi),%edx

# qhasm: mem64[ap + 3632] = temp1
# asm 1: mov   <temp1=int64#2,3632(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3632(<ap=%rdi)
mov   %esi,3632(%rdi)

# qhasm: mem64[ap + 796] = temp2
# asm 1: mov   <temp2=int64#3,796(<ap=int64#1)
# asm 2: mov   <temp2=%edx,796(<ap=%rdi)
mov   %edx,796(%rdi)

# qhasm: temp1 = mem64[ap + 804]
# asm 1: mov   804(<ap=int64#1),>temp1=int64#2
# asm 2: mov   804(<ap=%rdi),>temp1=%esi
mov   804(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2352]
# asm 1: mov   2352(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2352(<ap=%rdi),>temp2=%edx
mov   2352(%rdi),%edx

# qhasm: mem64[ap + 2352] = temp1
# asm 1: mov   <temp1=int64#2,2352(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2352(<ap=%rdi)
mov   %esi,2352(%rdi)

# qhasm: mem64[ap + 804] = temp2
# asm 1: mov   <temp2=int64#3,804(<ap=int64#1)
# asm 2: mov   <temp2=%edx,804(<ap=%rdi)
mov   %edx,804(%rdi)

# qhasm: temp1 = mem64[ap + 808]
# asm 1: mov   808(<ap=int64#1),>temp1=int64#2
# asm 2: mov   808(<ap=%rdi),>temp1=%esi
mov   808(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1328]
# asm 1: mov   1328(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1328(<ap=%rdi),>temp2=%edx
mov   1328(%rdi),%edx

# qhasm: mem64[ap + 1328] = temp1
# asm 1: mov   <temp1=int64#2,1328(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1328(<ap=%rdi)
mov   %esi,1328(%rdi)

# qhasm: mem64[ap + 808] = temp2
# asm 1: mov   <temp2=int64#3,808(<ap=int64#1)
# asm 2: mov   <temp2=%edx,808(<ap=%rdi)
mov   %edx,808(%rdi)

# qhasm: temp1 = mem64[ap + 812]
# asm 1: mov   812(<ap=int64#1),>temp1=int64#2
# asm 2: mov   812(<ap=%rdi),>temp1=%esi
mov   812(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3376]
# asm 1: mov   3376(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3376(<ap=%rdi),>temp2=%edx
mov   3376(%rdi),%edx

# qhasm: mem64[ap + 3376] = temp1
# asm 1: mov   <temp1=int64#2,3376(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3376(<ap=%rdi)
mov   %esi,3376(%rdi)

# qhasm: mem64[ap + 812] = temp2
# asm 1: mov   <temp2=int64#3,812(<ap=int64#1)
# asm 2: mov   <temp2=%edx,812(<ap=%rdi)
mov   %edx,812(%rdi)

# qhasm: temp1 = mem64[ap + 820]
# asm 1: mov   820(<ap=int64#1),>temp1=int64#2
# asm 2: mov   820(<ap=%rdi),>temp1=%esi
mov   820(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2864]
# asm 1: mov   2864(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2864(<ap=%rdi),>temp2=%edx
mov   2864(%rdi),%edx

# qhasm: mem64[ap + 2864] = temp1
# asm 1: mov   <temp1=int64#2,2864(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2864(<ap=%rdi)
mov   %esi,2864(%rdi)

# qhasm: mem64[ap + 820] = temp2
# asm 1: mov   <temp2=int64#3,820(<ap=int64#1)
# asm 2: mov   <temp2=%edx,820(<ap=%rdi)
mov   %edx,820(%rdi)

# qhasm: temp1 = mem64[ap + 824]
# asm 1: mov   824(<ap=int64#1),>temp1=int64#2
# asm 2: mov   824(<ap=%rdi),>temp1=%esi
mov   824(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1840]
# asm 1: mov   1840(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1840(<ap=%rdi),>temp2=%edx
mov   1840(%rdi),%edx

# qhasm: mem64[ap + 1840] = temp1
# asm 1: mov   <temp1=int64#2,1840(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1840(<ap=%rdi)
mov   %esi,1840(%rdi)

# qhasm: mem64[ap + 824] = temp2
# asm 1: mov   <temp2=int64#3,824(<ap=int64#1)
# asm 2: mov   <temp2=%edx,824(<ap=%rdi)
mov   %edx,824(%rdi)

# qhasm: temp1 = mem64[ap + 828]
# asm 1: mov   828(<ap=int64#1),>temp1=int64#2
# asm 2: mov   828(<ap=%rdi),>temp1=%esi
mov   828(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3888]
# asm 1: mov   3888(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3888(<ap=%rdi),>temp2=%edx
mov   3888(%rdi),%edx

# qhasm: mem64[ap + 3888] = temp1
# asm 1: mov   <temp1=int64#2,3888(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3888(<ap=%rdi)
mov   %esi,3888(%rdi)

# qhasm: mem64[ap + 828] = temp2
# asm 1: mov   <temp2=int64#3,828(<ap=int64#1)
# asm 2: mov   <temp2=%edx,828(<ap=%rdi)
mov   %edx,828(%rdi)

# qhasm: temp1 = mem64[ap + 836]
# asm 1: mov   836(<ap=int64#1),>temp1=int64#2
# asm 2: mov   836(<ap=%rdi),>temp1=%esi
mov   836(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2224]
# asm 1: mov   2224(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2224(<ap=%rdi),>temp2=%edx
mov   2224(%rdi),%edx

# qhasm: mem64[ap + 2224] = temp1
# asm 1: mov   <temp1=int64#2,2224(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2224(<ap=%rdi)
mov   %esi,2224(%rdi)

# qhasm: mem64[ap + 836] = temp2
# asm 1: mov   <temp2=int64#3,836(<ap=int64#1)
# asm 2: mov   <temp2=%edx,836(<ap=%rdi)
mov   %edx,836(%rdi)

# qhasm: temp1 = mem64[ap + 840]
# asm 1: mov   840(<ap=int64#1),>temp1=int64#2
# asm 2: mov   840(<ap=%rdi),>temp1=%esi
mov   840(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1200]
# asm 1: mov   1200(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1200(<ap=%rdi),>temp2=%edx
mov   1200(%rdi),%edx

# qhasm: mem64[ap + 1200] = temp1
# asm 1: mov   <temp1=int64#2,1200(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1200(<ap=%rdi)
mov   %esi,1200(%rdi)

# qhasm: mem64[ap + 840] = temp2
# asm 1: mov   <temp2=int64#3,840(<ap=int64#1)
# asm 2: mov   <temp2=%edx,840(<ap=%rdi)
mov   %edx,840(%rdi)

# qhasm: temp1 = mem64[ap + 844]
# asm 1: mov   844(<ap=int64#1),>temp1=int64#2
# asm 2: mov   844(<ap=%rdi),>temp1=%esi
mov   844(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3248]
# asm 1: mov   3248(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3248(<ap=%rdi),>temp2=%edx
mov   3248(%rdi),%edx

# qhasm: mem64[ap + 3248] = temp1
# asm 1: mov   <temp1=int64#2,3248(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3248(<ap=%rdi)
mov   %esi,3248(%rdi)

# qhasm: mem64[ap + 844] = temp2
# asm 1: mov   <temp2=int64#3,844(<ap=int64#1)
# asm 2: mov   <temp2=%edx,844(<ap=%rdi)
mov   %edx,844(%rdi)

# qhasm: temp1 = mem64[ap + 852]
# asm 1: mov   852(<ap=int64#1),>temp1=int64#2
# asm 2: mov   852(<ap=%rdi),>temp1=%esi
mov   852(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2736]
# asm 1: mov   2736(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2736(<ap=%rdi),>temp2=%edx
mov   2736(%rdi),%edx

# qhasm: mem64[ap + 2736] = temp1
# asm 1: mov   <temp1=int64#2,2736(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2736(<ap=%rdi)
mov   %esi,2736(%rdi)

# qhasm: mem64[ap + 852] = temp2
# asm 1: mov   <temp2=int64#3,852(<ap=int64#1)
# asm 2: mov   <temp2=%edx,852(<ap=%rdi)
mov   %edx,852(%rdi)

# qhasm: temp1 = mem64[ap + 856]
# asm 1: mov   856(<ap=int64#1),>temp1=int64#2
# asm 2: mov   856(<ap=%rdi),>temp1=%esi
mov   856(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1712]
# asm 1: mov   1712(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1712(<ap=%rdi),>temp2=%edx
mov   1712(%rdi),%edx

# qhasm: mem64[ap + 1712] = temp1
# asm 1: mov   <temp1=int64#2,1712(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1712(<ap=%rdi)
mov   %esi,1712(%rdi)

# qhasm: mem64[ap + 856] = temp2
# asm 1: mov   <temp2=int64#3,856(<ap=int64#1)
# asm 2: mov   <temp2=%edx,856(<ap=%rdi)
mov   %edx,856(%rdi)

# qhasm: temp1 = mem64[ap + 860]
# asm 1: mov   860(<ap=int64#1),>temp1=int64#2
# asm 2: mov   860(<ap=%rdi),>temp1=%esi
mov   860(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3760]
# asm 1: mov   3760(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3760(<ap=%rdi),>temp2=%edx
mov   3760(%rdi),%edx

# qhasm: mem64[ap + 3760] = temp1
# asm 1: mov   <temp1=int64#2,3760(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3760(<ap=%rdi)
mov   %esi,3760(%rdi)

# qhasm: mem64[ap + 860] = temp2
# asm 1: mov   <temp2=int64#3,860(<ap=int64#1)
# asm 2: mov   <temp2=%edx,860(<ap=%rdi)
mov   %edx,860(%rdi)

# qhasm: temp1 = mem64[ap + 868]
# asm 1: mov   868(<ap=int64#1),>temp1=int64#2
# asm 2: mov   868(<ap=%rdi),>temp1=%esi
mov   868(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2480]
# asm 1: mov   2480(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2480(<ap=%rdi),>temp2=%edx
mov   2480(%rdi),%edx

# qhasm: mem64[ap + 2480] = temp1
# asm 1: mov   <temp1=int64#2,2480(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2480(<ap=%rdi)
mov   %esi,2480(%rdi)

# qhasm: mem64[ap + 868] = temp2
# asm 1: mov   <temp2=int64#3,868(<ap=int64#1)
# asm 2: mov   <temp2=%edx,868(<ap=%rdi)
mov   %edx,868(%rdi)

# qhasm: temp1 = mem64[ap + 872]
# asm 1: mov   872(<ap=int64#1),>temp1=int64#2
# asm 2: mov   872(<ap=%rdi),>temp1=%esi
mov   872(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1456]
# asm 1: mov   1456(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1456(<ap=%rdi),>temp2=%edx
mov   1456(%rdi),%edx

# qhasm: mem64[ap + 1456] = temp1
# asm 1: mov   <temp1=int64#2,1456(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1456(<ap=%rdi)
mov   %esi,1456(%rdi)

# qhasm: mem64[ap + 872] = temp2
# asm 1: mov   <temp2=int64#3,872(<ap=int64#1)
# asm 2: mov   <temp2=%edx,872(<ap=%rdi)
mov   %edx,872(%rdi)

# qhasm: temp1 = mem64[ap + 876]
# asm 1: mov   876(<ap=int64#1),>temp1=int64#2
# asm 2: mov   876(<ap=%rdi),>temp1=%esi
mov   876(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3504]
# asm 1: mov   3504(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3504(<ap=%rdi),>temp2=%edx
mov   3504(%rdi),%edx

# qhasm: mem64[ap + 3504] = temp1
# asm 1: mov   <temp1=int64#2,3504(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3504(<ap=%rdi)
mov   %esi,3504(%rdi)

# qhasm: mem64[ap + 876] = temp2
# asm 1: mov   <temp2=int64#3,876(<ap=int64#1)
# asm 2: mov   <temp2=%edx,876(<ap=%rdi)
mov   %edx,876(%rdi)

# qhasm: temp1 = mem64[ap + 880]
# asm 1: mov   880(<ap=int64#1),>temp1=int64#2
# asm 2: mov   880(<ap=%rdi),>temp1=%esi
mov   880(%rdi),%esi

# qhasm: temp2 = mem64[ap + 944]
# asm 1: mov   944(<ap=int64#1),>temp2=int64#3
# asm 2: mov   944(<ap=%rdi),>temp2=%edx
mov   944(%rdi),%edx

# qhasm: mem64[ap + 944] = temp1
# asm 1: mov   <temp1=int64#2,944(<ap=int64#1)
# asm 2: mov   <temp1=%esi,944(<ap=%rdi)
mov   %esi,944(%rdi)

# qhasm: mem64[ap + 880] = temp2
# asm 1: mov   <temp2=int64#3,880(<ap=int64#1)
# asm 2: mov   <temp2=%edx,880(<ap=%rdi)
mov   %edx,880(%rdi)

# qhasm: temp1 = mem64[ap + 884]
# asm 1: mov   884(<ap=int64#1),>temp1=int64#2
# asm 2: mov   884(<ap=%rdi),>temp1=%esi
mov   884(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2992]
# asm 1: mov   2992(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2992(<ap=%rdi),>temp2=%edx
mov   2992(%rdi),%edx

# qhasm: mem64[ap + 2992] = temp1
# asm 1: mov   <temp1=int64#2,2992(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2992(<ap=%rdi)
mov   %esi,2992(%rdi)

# qhasm: mem64[ap + 884] = temp2
# asm 1: mov   <temp2=int64#3,884(<ap=int64#1)
# asm 2: mov   <temp2=%edx,884(<ap=%rdi)
mov   %edx,884(%rdi)

# qhasm: temp1 = mem64[ap + 888]
# asm 1: mov   888(<ap=int64#1),>temp1=int64#2
# asm 2: mov   888(<ap=%rdi),>temp1=%esi
mov   888(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1968]
# asm 1: mov   1968(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1968(<ap=%rdi),>temp2=%edx
mov   1968(%rdi),%edx

# qhasm: mem64[ap + 1968] = temp1
# asm 1: mov   <temp1=int64#2,1968(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1968(<ap=%rdi)
mov   %esi,1968(%rdi)

# qhasm: mem64[ap + 888] = temp2
# asm 1: mov   <temp2=int64#3,888(<ap=int64#1)
# asm 2: mov   <temp2=%edx,888(<ap=%rdi)
mov   %edx,888(%rdi)

# qhasm: temp1 = mem64[ap + 892]
# asm 1: mov   892(<ap=int64#1),>temp1=int64#2
# asm 2: mov   892(<ap=%rdi),>temp1=%esi
mov   892(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4016]
# asm 1: mov   4016(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4016(<ap=%rdi),>temp2=%edx
mov   4016(%rdi),%edx

# qhasm: mem64[ap + 4016] = temp1
# asm 1: mov   <temp1=int64#2,4016(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4016(<ap=%rdi)
mov   %esi,4016(%rdi)

# qhasm: mem64[ap + 892] = temp2
# asm 1: mov   <temp2=int64#3,892(<ap=int64#1)
# asm 2: mov   <temp2=%edx,892(<ap=%rdi)
mov   %edx,892(%rdi)

# qhasm: temp1 = mem64[ap + 900]
# asm 1: mov   900(<ap=int64#1),>temp1=int64#2
# asm 2: mov   900(<ap=%rdi),>temp1=%esi
mov   900(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2160]
# asm 1: mov   2160(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2160(<ap=%rdi),>temp2=%edx
mov   2160(%rdi),%edx

# qhasm: mem64[ap + 2160] = temp1
# asm 1: mov   <temp1=int64#2,2160(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2160(<ap=%rdi)
mov   %esi,2160(%rdi)

# qhasm: mem64[ap + 900] = temp2
# asm 1: mov   <temp2=int64#3,900(<ap=int64#1)
# asm 2: mov   <temp2=%edx,900(<ap=%rdi)
mov   %edx,900(%rdi)

# qhasm: temp1 = mem64[ap + 904]
# asm 1: mov   904(<ap=int64#1),>temp1=int64#2
# asm 2: mov   904(<ap=%rdi),>temp1=%esi
mov   904(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1136]
# asm 1: mov   1136(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1136(<ap=%rdi),>temp2=%edx
mov   1136(%rdi),%edx

# qhasm: mem64[ap + 1136] = temp1
# asm 1: mov   <temp1=int64#2,1136(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1136(<ap=%rdi)
mov   %esi,1136(%rdi)

# qhasm: mem64[ap + 904] = temp2
# asm 1: mov   <temp2=int64#3,904(<ap=int64#1)
# asm 2: mov   <temp2=%edx,904(<ap=%rdi)
mov   %edx,904(%rdi)

# qhasm: temp1 = mem64[ap + 908]
# asm 1: mov   908(<ap=int64#1),>temp1=int64#2
# asm 2: mov   908(<ap=%rdi),>temp1=%esi
mov   908(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3184]
# asm 1: mov   3184(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3184(<ap=%rdi),>temp2=%edx
mov   3184(%rdi),%edx

# qhasm: mem64[ap + 3184] = temp1
# asm 1: mov   <temp1=int64#2,3184(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3184(<ap=%rdi)
mov   %esi,3184(%rdi)

# qhasm: mem64[ap + 908] = temp2
# asm 1: mov   <temp2=int64#3,908(<ap=int64#1)
# asm 2: mov   <temp2=%edx,908(<ap=%rdi)
mov   %edx,908(%rdi)

# qhasm: temp1 = mem64[ap + 916]
# asm 1: mov   916(<ap=int64#1),>temp1=int64#2
# asm 2: mov   916(<ap=%rdi),>temp1=%esi
mov   916(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2672]
# asm 1: mov   2672(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2672(<ap=%rdi),>temp2=%edx
mov   2672(%rdi),%edx

# qhasm: mem64[ap + 2672] = temp1
# asm 1: mov   <temp1=int64#2,2672(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2672(<ap=%rdi)
mov   %esi,2672(%rdi)

# qhasm: mem64[ap + 916] = temp2
# asm 1: mov   <temp2=int64#3,916(<ap=int64#1)
# asm 2: mov   <temp2=%edx,916(<ap=%rdi)
mov   %edx,916(%rdi)

# qhasm: temp1 = mem64[ap + 920]
# asm 1: mov   920(<ap=int64#1),>temp1=int64#2
# asm 2: mov   920(<ap=%rdi),>temp1=%esi
mov   920(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1648]
# asm 1: mov   1648(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1648(<ap=%rdi),>temp2=%edx
mov   1648(%rdi),%edx

# qhasm: mem64[ap + 1648] = temp1
# asm 1: mov   <temp1=int64#2,1648(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1648(<ap=%rdi)
mov   %esi,1648(%rdi)

# qhasm: mem64[ap + 920] = temp2
# asm 1: mov   <temp2=int64#3,920(<ap=int64#1)
# asm 2: mov   <temp2=%edx,920(<ap=%rdi)
mov   %edx,920(%rdi)

# qhasm: temp1 = mem64[ap + 924]
# asm 1: mov   924(<ap=int64#1),>temp1=int64#2
# asm 2: mov   924(<ap=%rdi),>temp1=%esi
mov   924(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3696]
# asm 1: mov   3696(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3696(<ap=%rdi),>temp2=%edx
mov   3696(%rdi),%edx

# qhasm: mem64[ap + 3696] = temp1
# asm 1: mov   <temp1=int64#2,3696(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3696(<ap=%rdi)
mov   %esi,3696(%rdi)

# qhasm: mem64[ap + 924] = temp2
# asm 1: mov   <temp2=int64#3,924(<ap=int64#1)
# asm 2: mov   <temp2=%edx,924(<ap=%rdi)
mov   %edx,924(%rdi)

# qhasm: temp1 = mem64[ap + 932]
# asm 1: mov   932(<ap=int64#1),>temp1=int64#2
# asm 2: mov   932(<ap=%rdi),>temp1=%esi
mov   932(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2416]
# asm 1: mov   2416(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2416(<ap=%rdi),>temp2=%edx
mov   2416(%rdi),%edx

# qhasm: mem64[ap + 2416] = temp1
# asm 1: mov   <temp1=int64#2,2416(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2416(<ap=%rdi)
mov   %esi,2416(%rdi)

# qhasm: mem64[ap + 932] = temp2
# asm 1: mov   <temp2=int64#3,932(<ap=int64#1)
# asm 2: mov   <temp2=%edx,932(<ap=%rdi)
mov   %edx,932(%rdi)

# qhasm: temp1 = mem64[ap + 936]
# asm 1: mov   936(<ap=int64#1),>temp1=int64#2
# asm 2: mov   936(<ap=%rdi),>temp1=%esi
mov   936(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1392]
# asm 1: mov   1392(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1392(<ap=%rdi),>temp2=%edx
mov   1392(%rdi),%edx

# qhasm: mem64[ap + 1392] = temp1
# asm 1: mov   <temp1=int64#2,1392(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1392(<ap=%rdi)
mov   %esi,1392(%rdi)

# qhasm: mem64[ap + 936] = temp2
# asm 1: mov   <temp2=int64#3,936(<ap=int64#1)
# asm 2: mov   <temp2=%edx,936(<ap=%rdi)
mov   %edx,936(%rdi)

# qhasm: temp1 = mem64[ap + 940]
# asm 1: mov   940(<ap=int64#1),>temp1=int64#2
# asm 2: mov   940(<ap=%rdi),>temp1=%esi
mov   940(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3440]
# asm 1: mov   3440(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3440(<ap=%rdi),>temp2=%edx
mov   3440(%rdi),%edx

# qhasm: mem64[ap + 3440] = temp1
# asm 1: mov   <temp1=int64#2,3440(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3440(<ap=%rdi)
mov   %esi,3440(%rdi)

# qhasm: mem64[ap + 940] = temp2
# asm 1: mov   <temp2=int64#3,940(<ap=int64#1)
# asm 2: mov   <temp2=%edx,940(<ap=%rdi)
mov   %edx,940(%rdi)

# qhasm: temp1 = mem64[ap + 948]
# asm 1: mov   948(<ap=int64#1),>temp1=int64#2
# asm 2: mov   948(<ap=%rdi),>temp1=%esi
mov   948(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2928]
# asm 1: mov   2928(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2928(<ap=%rdi),>temp2=%edx
mov   2928(%rdi),%edx

# qhasm: mem64[ap + 2928] = temp1
# asm 1: mov   <temp1=int64#2,2928(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2928(<ap=%rdi)
mov   %esi,2928(%rdi)

# qhasm: mem64[ap + 948] = temp2
# asm 1: mov   <temp2=int64#3,948(<ap=int64#1)
# asm 2: mov   <temp2=%edx,948(<ap=%rdi)
mov   %edx,948(%rdi)

# qhasm: temp1 = mem64[ap + 952]
# asm 1: mov   952(<ap=int64#1),>temp1=int64#2
# asm 2: mov   952(<ap=%rdi),>temp1=%esi
mov   952(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1904]
# asm 1: mov   1904(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1904(<ap=%rdi),>temp2=%edx
mov   1904(%rdi),%edx

# qhasm: mem64[ap + 1904] = temp1
# asm 1: mov   <temp1=int64#2,1904(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1904(<ap=%rdi)
mov   %esi,1904(%rdi)

# qhasm: mem64[ap + 952] = temp2
# asm 1: mov   <temp2=int64#3,952(<ap=int64#1)
# asm 2: mov   <temp2=%edx,952(<ap=%rdi)
mov   %edx,952(%rdi)

# qhasm: temp1 = mem64[ap + 956]
# asm 1: mov   956(<ap=int64#1),>temp1=int64#2
# asm 2: mov   956(<ap=%rdi),>temp1=%esi
mov   956(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3952]
# asm 1: mov   3952(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3952(<ap=%rdi),>temp2=%edx
mov   3952(%rdi),%edx

# qhasm: mem64[ap + 3952] = temp1
# asm 1: mov   <temp1=int64#2,3952(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3952(<ap=%rdi)
mov   %esi,3952(%rdi)

# qhasm: mem64[ap + 956] = temp2
# asm 1: mov   <temp2=int64#3,956(<ap=int64#1)
# asm 2: mov   <temp2=%edx,956(<ap=%rdi)
mov   %edx,956(%rdi)

# qhasm: temp1 = mem64[ap + 964]
# asm 1: mov   964(<ap=int64#1),>temp1=int64#2
# asm 2: mov   964(<ap=%rdi),>temp1=%esi
mov   964(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2288]
# asm 1: mov   2288(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2288(<ap=%rdi),>temp2=%edx
mov   2288(%rdi),%edx

# qhasm: mem64[ap + 2288] = temp1
# asm 1: mov   <temp1=int64#2,2288(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2288(<ap=%rdi)
mov   %esi,2288(%rdi)

# qhasm: mem64[ap + 964] = temp2
# asm 1: mov   <temp2=int64#3,964(<ap=int64#1)
# asm 2: mov   <temp2=%edx,964(<ap=%rdi)
mov   %edx,964(%rdi)

# qhasm: temp1 = mem64[ap + 968]
# asm 1: mov   968(<ap=int64#1),>temp1=int64#2
# asm 2: mov   968(<ap=%rdi),>temp1=%esi
mov   968(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1264]
# asm 1: mov   1264(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1264(<ap=%rdi),>temp2=%edx
mov   1264(%rdi),%edx

# qhasm: mem64[ap + 1264] = temp1
# asm 1: mov   <temp1=int64#2,1264(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1264(<ap=%rdi)
mov   %esi,1264(%rdi)

# qhasm: mem64[ap + 968] = temp2
# asm 1: mov   <temp2=int64#3,968(<ap=int64#1)
# asm 2: mov   <temp2=%edx,968(<ap=%rdi)
mov   %edx,968(%rdi)

# qhasm: temp1 = mem64[ap + 972]
# asm 1: mov   972(<ap=int64#1),>temp1=int64#2
# asm 2: mov   972(<ap=%rdi),>temp1=%esi
mov   972(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3312]
# asm 1: mov   3312(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3312(<ap=%rdi),>temp2=%edx
mov   3312(%rdi),%edx

# qhasm: mem64[ap + 3312] = temp1
# asm 1: mov   <temp1=int64#2,3312(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3312(<ap=%rdi)
mov   %esi,3312(%rdi)

# qhasm: mem64[ap + 972] = temp2
# asm 1: mov   <temp2=int64#3,972(<ap=int64#1)
# asm 2: mov   <temp2=%edx,972(<ap=%rdi)
mov   %edx,972(%rdi)

# qhasm: temp1 = mem64[ap + 980]
# asm 1: mov   980(<ap=int64#1),>temp1=int64#2
# asm 2: mov   980(<ap=%rdi),>temp1=%esi
mov   980(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2800]
# asm 1: mov   2800(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2800(<ap=%rdi),>temp2=%edx
mov   2800(%rdi),%edx

# qhasm: mem64[ap + 2800] = temp1
# asm 1: mov   <temp1=int64#2,2800(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2800(<ap=%rdi)
mov   %esi,2800(%rdi)

# qhasm: mem64[ap + 980] = temp2
# asm 1: mov   <temp2=int64#3,980(<ap=int64#1)
# asm 2: mov   <temp2=%edx,980(<ap=%rdi)
mov   %edx,980(%rdi)

# qhasm: temp1 = mem64[ap + 984]
# asm 1: mov   984(<ap=int64#1),>temp1=int64#2
# asm 2: mov   984(<ap=%rdi),>temp1=%esi
mov   984(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1776]
# asm 1: mov   1776(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1776(<ap=%rdi),>temp2=%edx
mov   1776(%rdi),%edx

# qhasm: mem64[ap + 1776] = temp1
# asm 1: mov   <temp1=int64#2,1776(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1776(<ap=%rdi)
mov   %esi,1776(%rdi)

# qhasm: mem64[ap + 984] = temp2
# asm 1: mov   <temp2=int64#3,984(<ap=int64#1)
# asm 2: mov   <temp2=%edx,984(<ap=%rdi)
mov   %edx,984(%rdi)

# qhasm: temp1 = mem64[ap + 988]
# asm 1: mov   988(<ap=int64#1),>temp1=int64#2
# asm 2: mov   988(<ap=%rdi),>temp1=%esi
mov   988(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3824]
# asm 1: mov   3824(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3824(<ap=%rdi),>temp2=%edx
mov   3824(%rdi),%edx

# qhasm: mem64[ap + 3824] = temp1
# asm 1: mov   <temp1=int64#2,3824(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3824(<ap=%rdi)
mov   %esi,3824(%rdi)

# qhasm: mem64[ap + 988] = temp2
# asm 1: mov   <temp2=int64#3,988(<ap=int64#1)
# asm 2: mov   <temp2=%edx,988(<ap=%rdi)
mov   %edx,988(%rdi)

# qhasm: temp1 = mem64[ap + 996]
# asm 1: mov   996(<ap=int64#1),>temp1=int64#2
# asm 2: mov   996(<ap=%rdi),>temp1=%esi
mov   996(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2544]
# asm 1: mov   2544(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2544(<ap=%rdi),>temp2=%edx
mov   2544(%rdi),%edx

# qhasm: mem64[ap + 2544] = temp1
# asm 1: mov   <temp1=int64#2,2544(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2544(<ap=%rdi)
mov   %esi,2544(%rdi)

# qhasm: mem64[ap + 996] = temp2
# asm 1: mov   <temp2=int64#3,996(<ap=int64#1)
# asm 2: mov   <temp2=%edx,996(<ap=%rdi)
mov   %edx,996(%rdi)

# qhasm: temp1 = mem64[ap + 1000]
# asm 1: mov   1000(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1000(<ap=%rdi),>temp1=%esi
mov   1000(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1520]
# asm 1: mov   1520(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1520(<ap=%rdi),>temp2=%edx
mov   1520(%rdi),%edx

# qhasm: mem64[ap + 1520] = temp1
# asm 1: mov   <temp1=int64#2,1520(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1520(<ap=%rdi)
mov   %esi,1520(%rdi)

# qhasm: mem64[ap + 1000] = temp2
# asm 1: mov   <temp2=int64#3,1000(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1000(<ap=%rdi)
mov   %edx,1000(%rdi)

# qhasm: temp1 = mem64[ap + 1004]
# asm 1: mov   1004(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1004(<ap=%rdi),>temp1=%esi
mov   1004(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3568]
# asm 1: mov   3568(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3568(<ap=%rdi),>temp2=%edx
mov   3568(%rdi),%edx

# qhasm: mem64[ap + 3568] = temp1
# asm 1: mov   <temp1=int64#2,3568(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3568(<ap=%rdi)
mov   %esi,3568(%rdi)

# qhasm: mem64[ap + 1004] = temp2
# asm 1: mov   <temp2=int64#3,1004(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1004(<ap=%rdi)
mov   %edx,1004(%rdi)

# qhasm: temp1 = mem64[ap + 1012]
# asm 1: mov   1012(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1012(<ap=%rdi),>temp1=%esi
mov   1012(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3056]
# asm 1: mov   3056(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3056(<ap=%rdi),>temp2=%edx
mov   3056(%rdi),%edx

# qhasm: mem64[ap + 3056] = temp1
# asm 1: mov   <temp1=int64#2,3056(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3056(<ap=%rdi)
mov   %esi,3056(%rdi)

# qhasm: mem64[ap + 1012] = temp2
# asm 1: mov   <temp2=int64#3,1012(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1012(<ap=%rdi)
mov   %edx,1012(%rdi)

# qhasm: temp1 = mem64[ap + 1016]
# asm 1: mov   1016(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1016(<ap=%rdi),>temp1=%esi
mov   1016(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2032]
# asm 1: mov   2032(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2032(<ap=%rdi),>temp2=%edx
mov   2032(%rdi),%edx

# qhasm: mem64[ap + 2032] = temp1
# asm 1: mov   <temp1=int64#2,2032(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2032(<ap=%rdi)
mov   %esi,2032(%rdi)

# qhasm: mem64[ap + 1016] = temp2
# asm 1: mov   <temp2=int64#3,1016(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1016(<ap=%rdi)
mov   %edx,1016(%rdi)

# qhasm: temp1 = mem64[ap + 1020]
# asm 1: mov   1020(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1020(<ap=%rdi),>temp1=%esi
mov   1020(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4080]
# asm 1: mov   4080(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4080(<ap=%rdi),>temp2=%edx
mov   4080(%rdi),%edx

# qhasm: mem64[ap + 4080] = temp1
# asm 1: mov   <temp1=int64#2,4080(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4080(<ap=%rdi)
mov   %esi,4080(%rdi)

# qhasm: mem64[ap + 1020] = temp2
# asm 1: mov   <temp2=int64#3,1020(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1020(<ap=%rdi)
mov   %edx,1020(%rdi)

# qhasm: temp1 = mem64[ap + 1028]
# asm 1: mov   1028(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1028(<ap=%rdi),>temp1=%esi
mov   1028(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2056]
# asm 1: mov   2056(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2056(<ap=%rdi),>temp2=%edx
mov   2056(%rdi),%edx

# qhasm: mem64[ap + 2056] = temp1
# asm 1: mov   <temp1=int64#2,2056(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2056(<ap=%rdi)
mov   %esi,2056(%rdi)

# qhasm: mem64[ap + 1028] = temp2
# asm 1: mov   <temp2=int64#3,1028(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1028(<ap=%rdi)
mov   %edx,1028(%rdi)

# qhasm: temp1 = mem64[ap + 1036]
# asm 1: mov   1036(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1036(<ap=%rdi),>temp1=%esi
mov   1036(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3080]
# asm 1: mov   3080(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3080(<ap=%rdi),>temp2=%edx
mov   3080(%rdi),%edx

# qhasm: mem64[ap + 3080] = temp1
# asm 1: mov   <temp1=int64#2,3080(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3080(<ap=%rdi)
mov   %esi,3080(%rdi)

# qhasm: mem64[ap + 1036] = temp2
# asm 1: mov   <temp2=int64#3,1036(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1036(<ap=%rdi)
mov   %edx,1036(%rdi)

# qhasm: temp1 = mem64[ap + 1044]
# asm 1: mov   1044(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1044(<ap=%rdi),>temp1=%esi
mov   1044(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2568]
# asm 1: mov   2568(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2568(<ap=%rdi),>temp2=%edx
mov   2568(%rdi),%edx

# qhasm: mem64[ap + 2568] = temp1
# asm 1: mov   <temp1=int64#2,2568(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2568(<ap=%rdi)
mov   %esi,2568(%rdi)

# qhasm: mem64[ap + 1044] = temp2
# asm 1: mov   <temp2=int64#3,1044(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1044(<ap=%rdi)
mov   %edx,1044(%rdi)

# qhasm: temp1 = mem64[ap + 1048]
# asm 1: mov   1048(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1048(<ap=%rdi),>temp1=%esi
mov   1048(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1544]
# asm 1: mov   1544(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1544(<ap=%rdi),>temp2=%edx
mov   1544(%rdi),%edx

# qhasm: mem64[ap + 1544] = temp1
# asm 1: mov   <temp1=int64#2,1544(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1544(<ap=%rdi)
mov   %esi,1544(%rdi)

# qhasm: mem64[ap + 1048] = temp2
# asm 1: mov   <temp2=int64#3,1048(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1048(<ap=%rdi)
mov   %edx,1048(%rdi)

# qhasm: temp1 = mem64[ap + 1052]
# asm 1: mov   1052(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1052(<ap=%rdi),>temp1=%esi
mov   1052(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3592]
# asm 1: mov   3592(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3592(<ap=%rdi),>temp2=%edx
mov   3592(%rdi),%edx

# qhasm: mem64[ap + 3592] = temp1
# asm 1: mov   <temp1=int64#2,3592(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3592(<ap=%rdi)
mov   %esi,3592(%rdi)

# qhasm: mem64[ap + 1052] = temp2
# asm 1: mov   <temp2=int64#3,1052(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1052(<ap=%rdi)
mov   %edx,1052(%rdi)

# qhasm: temp1 = mem64[ap + 1060]
# asm 1: mov   1060(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1060(<ap=%rdi),>temp1=%esi
mov   1060(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2312]
# asm 1: mov   2312(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2312(<ap=%rdi),>temp2=%edx
mov   2312(%rdi),%edx

# qhasm: mem64[ap + 2312] = temp1
# asm 1: mov   <temp1=int64#2,2312(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2312(<ap=%rdi)
mov   %esi,2312(%rdi)

# qhasm: mem64[ap + 1060] = temp2
# asm 1: mov   <temp2=int64#3,1060(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1060(<ap=%rdi)
mov   %edx,1060(%rdi)

# qhasm: temp1 = mem64[ap + 1064]
# asm 1: mov   1064(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1064(<ap=%rdi),>temp1=%esi
mov   1064(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1288]
# asm 1: mov   1288(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1288(<ap=%rdi),>temp2=%edx
mov   1288(%rdi),%edx

# qhasm: mem64[ap + 1288] = temp1
# asm 1: mov   <temp1=int64#2,1288(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1288(<ap=%rdi)
mov   %esi,1288(%rdi)

# qhasm: mem64[ap + 1064] = temp2
# asm 1: mov   <temp2=int64#3,1064(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1064(<ap=%rdi)
mov   %edx,1064(%rdi)

# qhasm: temp1 = mem64[ap + 1068]
# asm 1: mov   1068(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1068(<ap=%rdi),>temp1=%esi
mov   1068(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3336]
# asm 1: mov   3336(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3336(<ap=%rdi),>temp2=%edx
mov   3336(%rdi),%edx

# qhasm: mem64[ap + 3336] = temp1
# asm 1: mov   <temp1=int64#2,3336(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3336(<ap=%rdi)
mov   %esi,3336(%rdi)

# qhasm: mem64[ap + 1068] = temp2
# asm 1: mov   <temp2=int64#3,1068(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1068(<ap=%rdi)
mov   %edx,1068(%rdi)

# qhasm: temp1 = mem64[ap + 1076]
# asm 1: mov   1076(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1076(<ap=%rdi),>temp1=%esi
mov   1076(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2824]
# asm 1: mov   2824(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2824(<ap=%rdi),>temp2=%edx
mov   2824(%rdi),%edx

# qhasm: mem64[ap + 2824] = temp1
# asm 1: mov   <temp1=int64#2,2824(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2824(<ap=%rdi)
mov   %esi,2824(%rdi)

# qhasm: mem64[ap + 1076] = temp2
# asm 1: mov   <temp2=int64#3,1076(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1076(<ap=%rdi)
mov   %edx,1076(%rdi)

# qhasm: temp1 = mem64[ap + 1080]
# asm 1: mov   1080(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1080(<ap=%rdi),>temp1=%esi
mov   1080(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1800]
# asm 1: mov   1800(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1800(<ap=%rdi),>temp2=%edx
mov   1800(%rdi),%edx

# qhasm: mem64[ap + 1800] = temp1
# asm 1: mov   <temp1=int64#2,1800(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1800(<ap=%rdi)
mov   %esi,1800(%rdi)

# qhasm: mem64[ap + 1080] = temp2
# asm 1: mov   <temp2=int64#3,1080(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1080(<ap=%rdi)
mov   %edx,1080(%rdi)

# qhasm: temp1 = mem64[ap + 1084]
# asm 1: mov   1084(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1084(<ap=%rdi),>temp1=%esi
mov   1084(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3848]
# asm 1: mov   3848(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3848(<ap=%rdi),>temp2=%edx
mov   3848(%rdi),%edx

# qhasm: mem64[ap + 3848] = temp1
# asm 1: mov   <temp1=int64#2,3848(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3848(<ap=%rdi)
mov   %esi,3848(%rdi)

# qhasm: mem64[ap + 1084] = temp2
# asm 1: mov   <temp2=int64#3,1084(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1084(<ap=%rdi)
mov   %edx,1084(%rdi)

# qhasm: temp1 = mem64[ap + 1092]
# asm 1: mov   1092(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1092(<ap=%rdi),>temp1=%esi
mov   1092(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2184]
# asm 1: mov   2184(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2184(<ap=%rdi),>temp2=%edx
mov   2184(%rdi),%edx

# qhasm: mem64[ap + 2184] = temp1
# asm 1: mov   <temp1=int64#2,2184(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2184(<ap=%rdi)
mov   %esi,2184(%rdi)

# qhasm: mem64[ap + 1092] = temp2
# asm 1: mov   <temp2=int64#3,1092(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1092(<ap=%rdi)
mov   %edx,1092(%rdi)

# qhasm: temp1 = mem64[ap + 1096]
# asm 1: mov   1096(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1096(<ap=%rdi),>temp1=%esi
mov   1096(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1160]
# asm 1: mov   1160(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1160(<ap=%rdi),>temp2=%edx
mov   1160(%rdi),%edx

# qhasm: mem64[ap + 1160] = temp1
# asm 1: mov   <temp1=int64#2,1160(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1160(<ap=%rdi)
mov   %esi,1160(%rdi)

# qhasm: mem64[ap + 1096] = temp2
# asm 1: mov   <temp2=int64#3,1096(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1096(<ap=%rdi)
mov   %edx,1096(%rdi)

# qhasm: temp1 = mem64[ap + 1100]
# asm 1: mov   1100(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1100(<ap=%rdi),>temp1=%esi
mov   1100(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3208]
# asm 1: mov   3208(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3208(<ap=%rdi),>temp2=%edx
mov   3208(%rdi),%edx

# qhasm: mem64[ap + 3208] = temp1
# asm 1: mov   <temp1=int64#2,3208(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3208(<ap=%rdi)
mov   %esi,3208(%rdi)

# qhasm: mem64[ap + 1100] = temp2
# asm 1: mov   <temp2=int64#3,1100(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1100(<ap=%rdi)
mov   %edx,1100(%rdi)

# qhasm: temp1 = mem64[ap + 1108]
# asm 1: mov   1108(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1108(<ap=%rdi),>temp1=%esi
mov   1108(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2696]
# asm 1: mov   2696(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2696(<ap=%rdi),>temp2=%edx
mov   2696(%rdi),%edx

# qhasm: mem64[ap + 2696] = temp1
# asm 1: mov   <temp1=int64#2,2696(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2696(<ap=%rdi)
mov   %esi,2696(%rdi)

# qhasm: mem64[ap + 1108] = temp2
# asm 1: mov   <temp2=int64#3,1108(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1108(<ap=%rdi)
mov   %edx,1108(%rdi)

# qhasm: temp1 = mem64[ap + 1112]
# asm 1: mov   1112(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1112(<ap=%rdi),>temp1=%esi
mov   1112(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1672]
# asm 1: mov   1672(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1672(<ap=%rdi),>temp2=%edx
mov   1672(%rdi),%edx

# qhasm: mem64[ap + 1672] = temp1
# asm 1: mov   <temp1=int64#2,1672(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1672(<ap=%rdi)
mov   %esi,1672(%rdi)

# qhasm: mem64[ap + 1112] = temp2
# asm 1: mov   <temp2=int64#3,1112(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1112(<ap=%rdi)
mov   %edx,1112(%rdi)

# qhasm: temp1 = mem64[ap + 1116]
# asm 1: mov   1116(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1116(<ap=%rdi),>temp1=%esi
mov   1116(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3720]
# asm 1: mov   3720(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3720(<ap=%rdi),>temp2=%edx
mov   3720(%rdi),%edx

# qhasm: mem64[ap + 3720] = temp1
# asm 1: mov   <temp1=int64#2,3720(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3720(<ap=%rdi)
mov   %esi,3720(%rdi)

# qhasm: mem64[ap + 1116] = temp2
# asm 1: mov   <temp2=int64#3,1116(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1116(<ap=%rdi)
mov   %edx,1116(%rdi)

# qhasm: temp1 = mem64[ap + 1124]
# asm 1: mov   1124(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1124(<ap=%rdi),>temp1=%esi
mov   1124(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2440]
# asm 1: mov   2440(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2440(<ap=%rdi),>temp2=%edx
mov   2440(%rdi),%edx

# qhasm: mem64[ap + 2440] = temp1
# asm 1: mov   <temp1=int64#2,2440(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2440(<ap=%rdi)
mov   %esi,2440(%rdi)

# qhasm: mem64[ap + 1124] = temp2
# asm 1: mov   <temp2=int64#3,1124(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1124(<ap=%rdi)
mov   %edx,1124(%rdi)

# qhasm: temp1 = mem64[ap + 1128]
# asm 1: mov   1128(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1128(<ap=%rdi),>temp1=%esi
mov   1128(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1416]
# asm 1: mov   1416(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1416(<ap=%rdi),>temp2=%edx
mov   1416(%rdi),%edx

# qhasm: mem64[ap + 1416] = temp1
# asm 1: mov   <temp1=int64#2,1416(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1416(<ap=%rdi)
mov   %esi,1416(%rdi)

# qhasm: mem64[ap + 1128] = temp2
# asm 1: mov   <temp2=int64#3,1128(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1128(<ap=%rdi)
mov   %edx,1128(%rdi)

# qhasm: temp1 = mem64[ap + 1132]
# asm 1: mov   1132(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1132(<ap=%rdi),>temp1=%esi
mov   1132(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3464]
# asm 1: mov   3464(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3464(<ap=%rdi),>temp2=%edx
mov   3464(%rdi),%edx

# qhasm: mem64[ap + 3464] = temp1
# asm 1: mov   <temp1=int64#2,3464(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3464(<ap=%rdi)
mov   %esi,3464(%rdi)

# qhasm: mem64[ap + 1132] = temp2
# asm 1: mov   <temp2=int64#3,1132(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1132(<ap=%rdi)
mov   %edx,1132(%rdi)

# qhasm: temp1 = mem64[ap + 1140]
# asm 1: mov   1140(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1140(<ap=%rdi),>temp1=%esi
mov   1140(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2952]
# asm 1: mov   2952(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2952(<ap=%rdi),>temp2=%edx
mov   2952(%rdi),%edx

# qhasm: mem64[ap + 2952] = temp1
# asm 1: mov   <temp1=int64#2,2952(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2952(<ap=%rdi)
mov   %esi,2952(%rdi)

# qhasm: mem64[ap + 1140] = temp2
# asm 1: mov   <temp2=int64#3,1140(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1140(<ap=%rdi)
mov   %edx,1140(%rdi)

# qhasm: temp1 = mem64[ap + 1144]
# asm 1: mov   1144(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1144(<ap=%rdi),>temp1=%esi
mov   1144(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1928]
# asm 1: mov   1928(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1928(<ap=%rdi),>temp2=%edx
mov   1928(%rdi),%edx

# qhasm: mem64[ap + 1928] = temp1
# asm 1: mov   <temp1=int64#2,1928(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1928(<ap=%rdi)
mov   %esi,1928(%rdi)

# qhasm: mem64[ap + 1144] = temp2
# asm 1: mov   <temp2=int64#3,1144(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1144(<ap=%rdi)
mov   %edx,1144(%rdi)

# qhasm: temp1 = mem64[ap + 1148]
# asm 1: mov   1148(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1148(<ap=%rdi),>temp1=%esi
mov   1148(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3976]
# asm 1: mov   3976(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3976(<ap=%rdi),>temp2=%edx
mov   3976(%rdi),%edx

# qhasm: mem64[ap + 3976] = temp1
# asm 1: mov   <temp1=int64#2,3976(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3976(<ap=%rdi)
mov   %esi,3976(%rdi)

# qhasm: mem64[ap + 1148] = temp2
# asm 1: mov   <temp2=int64#3,1148(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1148(<ap=%rdi)
mov   %edx,1148(%rdi)

# qhasm: temp1 = mem64[ap + 1156]
# asm 1: mov   1156(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1156(<ap=%rdi),>temp1=%esi
mov   1156(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2120]
# asm 1: mov   2120(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2120(<ap=%rdi),>temp2=%edx
mov   2120(%rdi),%edx

# qhasm: mem64[ap + 2120] = temp1
# asm 1: mov   <temp1=int64#2,2120(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2120(<ap=%rdi)
mov   %esi,2120(%rdi)

# qhasm: mem64[ap + 1156] = temp2
# asm 1: mov   <temp2=int64#3,1156(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1156(<ap=%rdi)
mov   %edx,1156(%rdi)

# qhasm: temp1 = mem64[ap + 1164]
# asm 1: mov   1164(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1164(<ap=%rdi),>temp1=%esi
mov   1164(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3144]
# asm 1: mov   3144(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3144(<ap=%rdi),>temp2=%edx
mov   3144(%rdi),%edx

# qhasm: mem64[ap + 3144] = temp1
# asm 1: mov   <temp1=int64#2,3144(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3144(<ap=%rdi)
mov   %esi,3144(%rdi)

# qhasm: mem64[ap + 1164] = temp2
# asm 1: mov   <temp2=int64#3,1164(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1164(<ap=%rdi)
mov   %edx,1164(%rdi)

# qhasm: temp1 = mem64[ap + 1172]
# asm 1: mov   1172(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1172(<ap=%rdi),>temp1=%esi
mov   1172(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2632]
# asm 1: mov   2632(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2632(<ap=%rdi),>temp2=%edx
mov   2632(%rdi),%edx

# qhasm: mem64[ap + 2632] = temp1
# asm 1: mov   <temp1=int64#2,2632(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2632(<ap=%rdi)
mov   %esi,2632(%rdi)

# qhasm: mem64[ap + 1172] = temp2
# asm 1: mov   <temp2=int64#3,1172(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1172(<ap=%rdi)
mov   %edx,1172(%rdi)

# qhasm: temp1 = mem64[ap + 1176]
# asm 1: mov   1176(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1176(<ap=%rdi),>temp1=%esi
mov   1176(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1608]
# asm 1: mov   1608(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1608(<ap=%rdi),>temp2=%edx
mov   1608(%rdi),%edx

# qhasm: mem64[ap + 1608] = temp1
# asm 1: mov   <temp1=int64#2,1608(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1608(<ap=%rdi)
mov   %esi,1608(%rdi)

# qhasm: mem64[ap + 1176] = temp2
# asm 1: mov   <temp2=int64#3,1176(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1176(<ap=%rdi)
mov   %edx,1176(%rdi)

# qhasm: temp1 = mem64[ap + 1180]
# asm 1: mov   1180(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1180(<ap=%rdi),>temp1=%esi
mov   1180(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3656]
# asm 1: mov   3656(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3656(<ap=%rdi),>temp2=%edx
mov   3656(%rdi),%edx

# qhasm: mem64[ap + 3656] = temp1
# asm 1: mov   <temp1=int64#2,3656(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3656(<ap=%rdi)
mov   %esi,3656(%rdi)

# qhasm: mem64[ap + 1180] = temp2
# asm 1: mov   <temp2=int64#3,1180(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1180(<ap=%rdi)
mov   %edx,1180(%rdi)

# qhasm: temp1 = mem64[ap + 1188]
# asm 1: mov   1188(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1188(<ap=%rdi),>temp1=%esi
mov   1188(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2376]
# asm 1: mov   2376(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2376(<ap=%rdi),>temp2=%edx
mov   2376(%rdi),%edx

# qhasm: mem64[ap + 2376] = temp1
# asm 1: mov   <temp1=int64#2,2376(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2376(<ap=%rdi)
mov   %esi,2376(%rdi)

# qhasm: mem64[ap + 1188] = temp2
# asm 1: mov   <temp2=int64#3,1188(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1188(<ap=%rdi)
mov   %edx,1188(%rdi)

# qhasm: temp1 = mem64[ap + 1192]
# asm 1: mov   1192(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1192(<ap=%rdi),>temp1=%esi
mov   1192(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1352]
# asm 1: mov   1352(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1352(<ap=%rdi),>temp2=%edx
mov   1352(%rdi),%edx

# qhasm: mem64[ap + 1352] = temp1
# asm 1: mov   <temp1=int64#2,1352(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1352(<ap=%rdi)
mov   %esi,1352(%rdi)

# qhasm: mem64[ap + 1192] = temp2
# asm 1: mov   <temp2=int64#3,1192(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1192(<ap=%rdi)
mov   %edx,1192(%rdi)

# qhasm: temp1 = mem64[ap + 1196]
# asm 1: mov   1196(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1196(<ap=%rdi),>temp1=%esi
mov   1196(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3400]
# asm 1: mov   3400(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3400(<ap=%rdi),>temp2=%edx
mov   3400(%rdi),%edx

# qhasm: mem64[ap + 3400] = temp1
# asm 1: mov   <temp1=int64#2,3400(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3400(<ap=%rdi)
mov   %esi,3400(%rdi)

# qhasm: mem64[ap + 1196] = temp2
# asm 1: mov   <temp2=int64#3,1196(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1196(<ap=%rdi)
mov   %edx,1196(%rdi)

# qhasm: temp1 = mem64[ap + 1204]
# asm 1: mov   1204(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1204(<ap=%rdi),>temp1=%esi
mov   1204(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2888]
# asm 1: mov   2888(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2888(<ap=%rdi),>temp2=%edx
mov   2888(%rdi),%edx

# qhasm: mem64[ap + 2888] = temp1
# asm 1: mov   <temp1=int64#2,2888(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2888(<ap=%rdi)
mov   %esi,2888(%rdi)

# qhasm: mem64[ap + 1204] = temp2
# asm 1: mov   <temp2=int64#3,1204(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1204(<ap=%rdi)
mov   %edx,1204(%rdi)

# qhasm: temp1 = mem64[ap + 1208]
# asm 1: mov   1208(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1208(<ap=%rdi),>temp1=%esi
mov   1208(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1864]
# asm 1: mov   1864(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1864(<ap=%rdi),>temp2=%edx
mov   1864(%rdi),%edx

# qhasm: mem64[ap + 1864] = temp1
# asm 1: mov   <temp1=int64#2,1864(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1864(<ap=%rdi)
mov   %esi,1864(%rdi)

# qhasm: mem64[ap + 1208] = temp2
# asm 1: mov   <temp2=int64#3,1208(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1208(<ap=%rdi)
mov   %edx,1208(%rdi)

# qhasm: temp1 = mem64[ap + 1212]
# asm 1: mov   1212(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1212(<ap=%rdi),>temp1=%esi
mov   1212(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3912]
# asm 1: mov   3912(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3912(<ap=%rdi),>temp2=%edx
mov   3912(%rdi),%edx

# qhasm: mem64[ap + 3912] = temp1
# asm 1: mov   <temp1=int64#2,3912(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3912(<ap=%rdi)
mov   %esi,3912(%rdi)

# qhasm: mem64[ap + 1212] = temp2
# asm 1: mov   <temp2=int64#3,1212(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1212(<ap=%rdi)
mov   %edx,1212(%rdi)

# qhasm: temp1 = mem64[ap + 1220]
# asm 1: mov   1220(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1220(<ap=%rdi),>temp1=%esi
mov   1220(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2248]
# asm 1: mov   2248(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2248(<ap=%rdi),>temp2=%edx
mov   2248(%rdi),%edx

# qhasm: mem64[ap + 2248] = temp1
# asm 1: mov   <temp1=int64#2,2248(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2248(<ap=%rdi)
mov   %esi,2248(%rdi)

# qhasm: mem64[ap + 1220] = temp2
# asm 1: mov   <temp2=int64#3,1220(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1220(<ap=%rdi)
mov   %edx,1220(%rdi)

# qhasm: temp1 = mem64[ap + 1228]
# asm 1: mov   1228(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1228(<ap=%rdi),>temp1=%esi
mov   1228(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3272]
# asm 1: mov   3272(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3272(<ap=%rdi),>temp2=%edx
mov   3272(%rdi),%edx

# qhasm: mem64[ap + 3272] = temp1
# asm 1: mov   <temp1=int64#2,3272(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3272(<ap=%rdi)
mov   %esi,3272(%rdi)

# qhasm: mem64[ap + 1228] = temp2
# asm 1: mov   <temp2=int64#3,1228(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1228(<ap=%rdi)
mov   %edx,1228(%rdi)

# qhasm: temp1 = mem64[ap + 1236]
# asm 1: mov   1236(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1236(<ap=%rdi),>temp1=%esi
mov   1236(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2760]
# asm 1: mov   2760(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2760(<ap=%rdi),>temp2=%edx
mov   2760(%rdi),%edx

# qhasm: mem64[ap + 2760] = temp1
# asm 1: mov   <temp1=int64#2,2760(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2760(<ap=%rdi)
mov   %esi,2760(%rdi)

# qhasm: mem64[ap + 1236] = temp2
# asm 1: mov   <temp2=int64#3,1236(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1236(<ap=%rdi)
mov   %edx,1236(%rdi)

# qhasm: temp1 = mem64[ap + 1240]
# asm 1: mov   1240(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1240(<ap=%rdi),>temp1=%esi
mov   1240(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1736]
# asm 1: mov   1736(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1736(<ap=%rdi),>temp2=%edx
mov   1736(%rdi),%edx

# qhasm: mem64[ap + 1736] = temp1
# asm 1: mov   <temp1=int64#2,1736(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1736(<ap=%rdi)
mov   %esi,1736(%rdi)

# qhasm: mem64[ap + 1240] = temp2
# asm 1: mov   <temp2=int64#3,1240(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1240(<ap=%rdi)
mov   %edx,1240(%rdi)

# qhasm: temp1 = mem64[ap + 1244]
# asm 1: mov   1244(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1244(<ap=%rdi),>temp1=%esi
mov   1244(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3784]
# asm 1: mov   3784(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3784(<ap=%rdi),>temp2=%edx
mov   3784(%rdi),%edx

# qhasm: mem64[ap + 3784] = temp1
# asm 1: mov   <temp1=int64#2,3784(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3784(<ap=%rdi)
mov   %esi,3784(%rdi)

# qhasm: mem64[ap + 1244] = temp2
# asm 1: mov   <temp2=int64#3,1244(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1244(<ap=%rdi)
mov   %edx,1244(%rdi)

# qhasm: temp1 = mem64[ap + 1252]
# asm 1: mov   1252(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1252(<ap=%rdi),>temp1=%esi
mov   1252(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2504]
# asm 1: mov   2504(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2504(<ap=%rdi),>temp2=%edx
mov   2504(%rdi),%edx

# qhasm: mem64[ap + 2504] = temp1
# asm 1: mov   <temp1=int64#2,2504(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2504(<ap=%rdi)
mov   %esi,2504(%rdi)

# qhasm: mem64[ap + 1252] = temp2
# asm 1: mov   <temp2=int64#3,1252(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1252(<ap=%rdi)
mov   %edx,1252(%rdi)

# qhasm: temp1 = mem64[ap + 1256]
# asm 1: mov   1256(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1256(<ap=%rdi),>temp1=%esi
mov   1256(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1480]
# asm 1: mov   1480(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1480(<ap=%rdi),>temp2=%edx
mov   1480(%rdi),%edx

# qhasm: mem64[ap + 1480] = temp1
# asm 1: mov   <temp1=int64#2,1480(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1480(<ap=%rdi)
mov   %esi,1480(%rdi)

# qhasm: mem64[ap + 1256] = temp2
# asm 1: mov   <temp2=int64#3,1256(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1256(<ap=%rdi)
mov   %edx,1256(%rdi)

# qhasm: temp1 = mem64[ap + 1260]
# asm 1: mov   1260(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1260(<ap=%rdi),>temp1=%esi
mov   1260(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3528]
# asm 1: mov   3528(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3528(<ap=%rdi),>temp2=%edx
mov   3528(%rdi),%edx

# qhasm: mem64[ap + 3528] = temp1
# asm 1: mov   <temp1=int64#2,3528(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3528(<ap=%rdi)
mov   %esi,3528(%rdi)

# qhasm: mem64[ap + 1260] = temp2
# asm 1: mov   <temp2=int64#3,1260(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1260(<ap=%rdi)
mov   %edx,1260(%rdi)

# qhasm: temp1 = mem64[ap + 1268]
# asm 1: mov   1268(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1268(<ap=%rdi),>temp1=%esi
mov   1268(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3016]
# asm 1: mov   3016(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3016(<ap=%rdi),>temp2=%edx
mov   3016(%rdi),%edx

# qhasm: mem64[ap + 3016] = temp1
# asm 1: mov   <temp1=int64#2,3016(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3016(<ap=%rdi)
mov   %esi,3016(%rdi)

# qhasm: mem64[ap + 1268] = temp2
# asm 1: mov   <temp2=int64#3,1268(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1268(<ap=%rdi)
mov   %edx,1268(%rdi)

# qhasm: temp1 = mem64[ap + 1272]
# asm 1: mov   1272(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1272(<ap=%rdi),>temp1=%esi
mov   1272(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1992]
# asm 1: mov   1992(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1992(<ap=%rdi),>temp2=%edx
mov   1992(%rdi),%edx

# qhasm: mem64[ap + 1992] = temp1
# asm 1: mov   <temp1=int64#2,1992(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1992(<ap=%rdi)
mov   %esi,1992(%rdi)

# qhasm: mem64[ap + 1272] = temp2
# asm 1: mov   <temp2=int64#3,1272(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1272(<ap=%rdi)
mov   %edx,1272(%rdi)

# qhasm: temp1 = mem64[ap + 1276]
# asm 1: mov   1276(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1276(<ap=%rdi),>temp1=%esi
mov   1276(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4040]
# asm 1: mov   4040(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4040(<ap=%rdi),>temp2=%edx
mov   4040(%rdi),%edx

# qhasm: mem64[ap + 4040] = temp1
# asm 1: mov   <temp1=int64#2,4040(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4040(<ap=%rdi)
mov   %esi,4040(%rdi)

# qhasm: mem64[ap + 1276] = temp2
# asm 1: mov   <temp2=int64#3,1276(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1276(<ap=%rdi)
mov   %edx,1276(%rdi)

# qhasm: temp1 = mem64[ap + 1284]
# asm 1: mov   1284(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1284(<ap=%rdi),>temp1=%esi
mov   1284(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2088]
# asm 1: mov   2088(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2088(<ap=%rdi),>temp2=%edx
mov   2088(%rdi),%edx

# qhasm: mem64[ap + 2088] = temp1
# asm 1: mov   <temp1=int64#2,2088(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2088(<ap=%rdi)
mov   %esi,2088(%rdi)

# qhasm: mem64[ap + 1284] = temp2
# asm 1: mov   <temp2=int64#3,1284(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1284(<ap=%rdi)
mov   %edx,1284(%rdi)

# qhasm: temp1 = mem64[ap + 1292]
# asm 1: mov   1292(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1292(<ap=%rdi),>temp1=%esi
mov   1292(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3112]
# asm 1: mov   3112(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3112(<ap=%rdi),>temp2=%edx
mov   3112(%rdi),%edx

# qhasm: mem64[ap + 3112] = temp1
# asm 1: mov   <temp1=int64#2,3112(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3112(<ap=%rdi)
mov   %esi,3112(%rdi)

# qhasm: mem64[ap + 1292] = temp2
# asm 1: mov   <temp2=int64#3,1292(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1292(<ap=%rdi)
mov   %edx,1292(%rdi)

# qhasm: temp1 = mem64[ap + 1300]
# asm 1: mov   1300(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1300(<ap=%rdi),>temp1=%esi
mov   1300(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2600]
# asm 1: mov   2600(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2600(<ap=%rdi),>temp2=%edx
mov   2600(%rdi),%edx

# qhasm: mem64[ap + 2600] = temp1
# asm 1: mov   <temp1=int64#2,2600(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2600(<ap=%rdi)
mov   %esi,2600(%rdi)

# qhasm: mem64[ap + 1300] = temp2
# asm 1: mov   <temp2=int64#3,1300(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1300(<ap=%rdi)
mov   %edx,1300(%rdi)

# qhasm: temp1 = mem64[ap + 1304]
# asm 1: mov   1304(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1304(<ap=%rdi),>temp1=%esi
mov   1304(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1576]
# asm 1: mov   1576(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1576(<ap=%rdi),>temp2=%edx
mov   1576(%rdi),%edx

# qhasm: mem64[ap + 1576] = temp1
# asm 1: mov   <temp1=int64#2,1576(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1576(<ap=%rdi)
mov   %esi,1576(%rdi)

# qhasm: mem64[ap + 1304] = temp2
# asm 1: mov   <temp2=int64#3,1304(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1304(<ap=%rdi)
mov   %edx,1304(%rdi)

# qhasm: temp1 = mem64[ap + 1308]
# asm 1: mov   1308(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1308(<ap=%rdi),>temp1=%esi
mov   1308(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3624]
# asm 1: mov   3624(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3624(<ap=%rdi),>temp2=%edx
mov   3624(%rdi),%edx

# qhasm: mem64[ap + 3624] = temp1
# asm 1: mov   <temp1=int64#2,3624(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3624(<ap=%rdi)
mov   %esi,3624(%rdi)

# qhasm: mem64[ap + 1308] = temp2
# asm 1: mov   <temp2=int64#3,1308(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1308(<ap=%rdi)
mov   %edx,1308(%rdi)

# qhasm: temp1 = mem64[ap + 1316]
# asm 1: mov   1316(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1316(<ap=%rdi),>temp1=%esi
mov   1316(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2344]
# asm 1: mov   2344(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2344(<ap=%rdi),>temp2=%edx
mov   2344(%rdi),%edx

# qhasm: mem64[ap + 2344] = temp1
# asm 1: mov   <temp1=int64#2,2344(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2344(<ap=%rdi)
mov   %esi,2344(%rdi)

# qhasm: mem64[ap + 1316] = temp2
# asm 1: mov   <temp2=int64#3,1316(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1316(<ap=%rdi)
mov   %edx,1316(%rdi)

# qhasm: temp1 = mem64[ap + 1324]
# asm 1: mov   1324(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1324(<ap=%rdi),>temp1=%esi
mov   1324(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3368]
# asm 1: mov   3368(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3368(<ap=%rdi),>temp2=%edx
mov   3368(%rdi),%edx

# qhasm: mem64[ap + 3368] = temp1
# asm 1: mov   <temp1=int64#2,3368(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3368(<ap=%rdi)
mov   %esi,3368(%rdi)

# qhasm: mem64[ap + 1324] = temp2
# asm 1: mov   <temp2=int64#3,1324(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1324(<ap=%rdi)
mov   %edx,1324(%rdi)

# qhasm: temp1 = mem64[ap + 1332]
# asm 1: mov   1332(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1332(<ap=%rdi),>temp1=%esi
mov   1332(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2856]
# asm 1: mov   2856(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2856(<ap=%rdi),>temp2=%edx
mov   2856(%rdi),%edx

# qhasm: mem64[ap + 2856] = temp1
# asm 1: mov   <temp1=int64#2,2856(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2856(<ap=%rdi)
mov   %esi,2856(%rdi)

# qhasm: mem64[ap + 1332] = temp2
# asm 1: mov   <temp2=int64#3,1332(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1332(<ap=%rdi)
mov   %edx,1332(%rdi)

# qhasm: temp1 = mem64[ap + 1336]
# asm 1: mov   1336(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1336(<ap=%rdi),>temp1=%esi
mov   1336(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1832]
# asm 1: mov   1832(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1832(<ap=%rdi),>temp2=%edx
mov   1832(%rdi),%edx

# qhasm: mem64[ap + 1832] = temp1
# asm 1: mov   <temp1=int64#2,1832(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1832(<ap=%rdi)
mov   %esi,1832(%rdi)

# qhasm: mem64[ap + 1336] = temp2
# asm 1: mov   <temp2=int64#3,1336(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1336(<ap=%rdi)
mov   %edx,1336(%rdi)

# qhasm: temp1 = mem64[ap + 1340]
# asm 1: mov   1340(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1340(<ap=%rdi),>temp1=%esi
mov   1340(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3880]
# asm 1: mov   3880(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3880(<ap=%rdi),>temp2=%edx
mov   3880(%rdi),%edx

# qhasm: mem64[ap + 3880] = temp1
# asm 1: mov   <temp1=int64#2,3880(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3880(<ap=%rdi)
mov   %esi,3880(%rdi)

# qhasm: mem64[ap + 1340] = temp2
# asm 1: mov   <temp2=int64#3,1340(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1340(<ap=%rdi)
mov   %edx,1340(%rdi)

# qhasm: temp1 = mem64[ap + 1348]
# asm 1: mov   1348(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1348(<ap=%rdi),>temp1=%esi
mov   1348(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2216]
# asm 1: mov   2216(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2216(<ap=%rdi),>temp2=%edx
mov   2216(%rdi),%edx

# qhasm: mem64[ap + 2216] = temp1
# asm 1: mov   <temp1=int64#2,2216(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2216(<ap=%rdi)
mov   %esi,2216(%rdi)

# qhasm: mem64[ap + 1348] = temp2
# asm 1: mov   <temp2=int64#3,1348(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1348(<ap=%rdi)
mov   %edx,1348(%rdi)

# qhasm: temp1 = mem64[ap + 1356]
# asm 1: mov   1356(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1356(<ap=%rdi),>temp1=%esi
mov   1356(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3240]
# asm 1: mov   3240(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3240(<ap=%rdi),>temp2=%edx
mov   3240(%rdi),%edx

# qhasm: mem64[ap + 3240] = temp1
# asm 1: mov   <temp1=int64#2,3240(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3240(<ap=%rdi)
mov   %esi,3240(%rdi)

# qhasm: mem64[ap + 1356] = temp2
# asm 1: mov   <temp2=int64#3,1356(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1356(<ap=%rdi)
mov   %edx,1356(%rdi)

# qhasm: temp1 = mem64[ap + 1364]
# asm 1: mov   1364(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1364(<ap=%rdi),>temp1=%esi
mov   1364(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2728]
# asm 1: mov   2728(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2728(<ap=%rdi),>temp2=%edx
mov   2728(%rdi),%edx

# qhasm: mem64[ap + 2728] = temp1
# asm 1: mov   <temp1=int64#2,2728(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2728(<ap=%rdi)
mov   %esi,2728(%rdi)

# qhasm: mem64[ap + 1364] = temp2
# asm 1: mov   <temp2=int64#3,1364(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1364(<ap=%rdi)
mov   %edx,1364(%rdi)

# qhasm: temp1 = mem64[ap + 1368]
# asm 1: mov   1368(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1368(<ap=%rdi),>temp1=%esi
mov   1368(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1704]
# asm 1: mov   1704(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1704(<ap=%rdi),>temp2=%edx
mov   1704(%rdi),%edx

# qhasm: mem64[ap + 1704] = temp1
# asm 1: mov   <temp1=int64#2,1704(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1704(<ap=%rdi)
mov   %esi,1704(%rdi)

# qhasm: mem64[ap + 1368] = temp2
# asm 1: mov   <temp2=int64#3,1368(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1368(<ap=%rdi)
mov   %edx,1368(%rdi)

# qhasm: temp1 = mem64[ap + 1372]
# asm 1: mov   1372(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1372(<ap=%rdi),>temp1=%esi
mov   1372(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3752]
# asm 1: mov   3752(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3752(<ap=%rdi),>temp2=%edx
mov   3752(%rdi),%edx

# qhasm: mem64[ap + 3752] = temp1
# asm 1: mov   <temp1=int64#2,3752(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3752(<ap=%rdi)
mov   %esi,3752(%rdi)

# qhasm: mem64[ap + 1372] = temp2
# asm 1: mov   <temp2=int64#3,1372(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1372(<ap=%rdi)
mov   %edx,1372(%rdi)

# qhasm: temp1 = mem64[ap + 1380]
# asm 1: mov   1380(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1380(<ap=%rdi),>temp1=%esi
mov   1380(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2472]
# asm 1: mov   2472(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2472(<ap=%rdi),>temp2=%edx
mov   2472(%rdi),%edx

# qhasm: mem64[ap + 2472] = temp1
# asm 1: mov   <temp1=int64#2,2472(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2472(<ap=%rdi)
mov   %esi,2472(%rdi)

# qhasm: mem64[ap + 1380] = temp2
# asm 1: mov   <temp2=int64#3,1380(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1380(<ap=%rdi)
mov   %edx,1380(%rdi)

# qhasm: temp1 = mem64[ap + 1384]
# asm 1: mov   1384(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1384(<ap=%rdi),>temp1=%esi
mov   1384(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1448]
# asm 1: mov   1448(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1448(<ap=%rdi),>temp2=%edx
mov   1448(%rdi),%edx

# qhasm: mem64[ap + 1448] = temp1
# asm 1: mov   <temp1=int64#2,1448(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1448(<ap=%rdi)
mov   %esi,1448(%rdi)

# qhasm: mem64[ap + 1384] = temp2
# asm 1: mov   <temp2=int64#3,1384(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1384(<ap=%rdi)
mov   %edx,1384(%rdi)

# qhasm: temp1 = mem64[ap + 1388]
# asm 1: mov   1388(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1388(<ap=%rdi),>temp1=%esi
mov   1388(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3496]
# asm 1: mov   3496(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3496(<ap=%rdi),>temp2=%edx
mov   3496(%rdi),%edx

# qhasm: mem64[ap + 3496] = temp1
# asm 1: mov   <temp1=int64#2,3496(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3496(<ap=%rdi)
mov   %esi,3496(%rdi)

# qhasm: mem64[ap + 1388] = temp2
# asm 1: mov   <temp2=int64#3,1388(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1388(<ap=%rdi)
mov   %edx,1388(%rdi)

# qhasm: temp1 = mem64[ap + 1396]
# asm 1: mov   1396(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1396(<ap=%rdi),>temp1=%esi
mov   1396(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2984]
# asm 1: mov   2984(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2984(<ap=%rdi),>temp2=%edx
mov   2984(%rdi),%edx

# qhasm: mem64[ap + 2984] = temp1
# asm 1: mov   <temp1=int64#2,2984(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2984(<ap=%rdi)
mov   %esi,2984(%rdi)

# qhasm: mem64[ap + 1396] = temp2
# asm 1: mov   <temp2=int64#3,1396(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1396(<ap=%rdi)
mov   %edx,1396(%rdi)

# qhasm: temp1 = mem64[ap + 1400]
# asm 1: mov   1400(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1400(<ap=%rdi),>temp1=%esi
mov   1400(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1960]
# asm 1: mov   1960(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1960(<ap=%rdi),>temp2=%edx
mov   1960(%rdi),%edx

# qhasm: mem64[ap + 1960] = temp1
# asm 1: mov   <temp1=int64#2,1960(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1960(<ap=%rdi)
mov   %esi,1960(%rdi)

# qhasm: mem64[ap + 1400] = temp2
# asm 1: mov   <temp2=int64#3,1400(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1400(<ap=%rdi)
mov   %edx,1400(%rdi)

# qhasm: temp1 = mem64[ap + 1404]
# asm 1: mov   1404(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1404(<ap=%rdi),>temp1=%esi
mov   1404(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4008]
# asm 1: mov   4008(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4008(<ap=%rdi),>temp2=%edx
mov   4008(%rdi),%edx

# qhasm: mem64[ap + 4008] = temp1
# asm 1: mov   <temp1=int64#2,4008(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4008(<ap=%rdi)
mov   %esi,4008(%rdi)

# qhasm: mem64[ap + 1404] = temp2
# asm 1: mov   <temp2=int64#3,1404(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1404(<ap=%rdi)
mov   %edx,1404(%rdi)

# qhasm: temp1 = mem64[ap + 1412]
# asm 1: mov   1412(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1412(<ap=%rdi),>temp1=%esi
mov   1412(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2152]
# asm 1: mov   2152(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2152(<ap=%rdi),>temp2=%edx
mov   2152(%rdi),%edx

# qhasm: mem64[ap + 2152] = temp1
# asm 1: mov   <temp1=int64#2,2152(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2152(<ap=%rdi)
mov   %esi,2152(%rdi)

# qhasm: mem64[ap + 1412] = temp2
# asm 1: mov   <temp2=int64#3,1412(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1412(<ap=%rdi)
mov   %edx,1412(%rdi)

# qhasm: temp1 = mem64[ap + 1420]
# asm 1: mov   1420(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1420(<ap=%rdi),>temp1=%esi
mov   1420(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3176]
# asm 1: mov   3176(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3176(<ap=%rdi),>temp2=%edx
mov   3176(%rdi),%edx

# qhasm: mem64[ap + 3176] = temp1
# asm 1: mov   <temp1=int64#2,3176(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3176(<ap=%rdi)
mov   %esi,3176(%rdi)

# qhasm: mem64[ap + 1420] = temp2
# asm 1: mov   <temp2=int64#3,1420(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1420(<ap=%rdi)
mov   %edx,1420(%rdi)

# qhasm: temp1 = mem64[ap + 1428]
# asm 1: mov   1428(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1428(<ap=%rdi),>temp1=%esi
mov   1428(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2664]
# asm 1: mov   2664(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2664(<ap=%rdi),>temp2=%edx
mov   2664(%rdi),%edx

# qhasm: mem64[ap + 2664] = temp1
# asm 1: mov   <temp1=int64#2,2664(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2664(<ap=%rdi)
mov   %esi,2664(%rdi)

# qhasm: mem64[ap + 1428] = temp2
# asm 1: mov   <temp2=int64#3,1428(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1428(<ap=%rdi)
mov   %edx,1428(%rdi)

# qhasm: temp1 = mem64[ap + 1432]
# asm 1: mov   1432(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1432(<ap=%rdi),>temp1=%esi
mov   1432(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1640]
# asm 1: mov   1640(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1640(<ap=%rdi),>temp2=%edx
mov   1640(%rdi),%edx

# qhasm: mem64[ap + 1640] = temp1
# asm 1: mov   <temp1=int64#2,1640(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1640(<ap=%rdi)
mov   %esi,1640(%rdi)

# qhasm: mem64[ap + 1432] = temp2
# asm 1: mov   <temp2=int64#3,1432(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1432(<ap=%rdi)
mov   %edx,1432(%rdi)

# qhasm: temp1 = mem64[ap + 1436]
# asm 1: mov   1436(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1436(<ap=%rdi),>temp1=%esi
mov   1436(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3688]
# asm 1: mov   3688(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3688(<ap=%rdi),>temp2=%edx
mov   3688(%rdi),%edx

# qhasm: mem64[ap + 3688] = temp1
# asm 1: mov   <temp1=int64#2,3688(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3688(<ap=%rdi)
mov   %esi,3688(%rdi)

# qhasm: mem64[ap + 1436] = temp2
# asm 1: mov   <temp2=int64#3,1436(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1436(<ap=%rdi)
mov   %edx,1436(%rdi)

# qhasm: temp1 = mem64[ap + 1444]
# asm 1: mov   1444(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1444(<ap=%rdi),>temp1=%esi
mov   1444(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2408]
# asm 1: mov   2408(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2408(<ap=%rdi),>temp2=%edx
mov   2408(%rdi),%edx

# qhasm: mem64[ap + 2408] = temp1
# asm 1: mov   <temp1=int64#2,2408(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2408(<ap=%rdi)
mov   %esi,2408(%rdi)

# qhasm: mem64[ap + 1444] = temp2
# asm 1: mov   <temp2=int64#3,1444(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1444(<ap=%rdi)
mov   %edx,1444(%rdi)

# qhasm: temp1 = mem64[ap + 1452]
# asm 1: mov   1452(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1452(<ap=%rdi),>temp1=%esi
mov   1452(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3432]
# asm 1: mov   3432(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3432(<ap=%rdi),>temp2=%edx
mov   3432(%rdi),%edx

# qhasm: mem64[ap + 3432] = temp1
# asm 1: mov   <temp1=int64#2,3432(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3432(<ap=%rdi)
mov   %esi,3432(%rdi)

# qhasm: mem64[ap + 1452] = temp2
# asm 1: mov   <temp2=int64#3,1452(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1452(<ap=%rdi)
mov   %edx,1452(%rdi)

# qhasm: temp1 = mem64[ap + 1460]
# asm 1: mov   1460(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1460(<ap=%rdi),>temp1=%esi
mov   1460(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2920]
# asm 1: mov   2920(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2920(<ap=%rdi),>temp2=%edx
mov   2920(%rdi),%edx

# qhasm: mem64[ap + 2920] = temp1
# asm 1: mov   <temp1=int64#2,2920(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2920(<ap=%rdi)
mov   %esi,2920(%rdi)

# qhasm: mem64[ap + 1460] = temp2
# asm 1: mov   <temp2=int64#3,1460(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1460(<ap=%rdi)
mov   %edx,1460(%rdi)

# qhasm: temp1 = mem64[ap + 1464]
# asm 1: mov   1464(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1464(<ap=%rdi),>temp1=%esi
mov   1464(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1896]
# asm 1: mov   1896(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1896(<ap=%rdi),>temp2=%edx
mov   1896(%rdi),%edx

# qhasm: mem64[ap + 1896] = temp1
# asm 1: mov   <temp1=int64#2,1896(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1896(<ap=%rdi)
mov   %esi,1896(%rdi)

# qhasm: mem64[ap + 1464] = temp2
# asm 1: mov   <temp2=int64#3,1464(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1464(<ap=%rdi)
mov   %edx,1464(%rdi)

# qhasm: temp1 = mem64[ap + 1468]
# asm 1: mov   1468(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1468(<ap=%rdi),>temp1=%esi
mov   1468(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3944]
# asm 1: mov   3944(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3944(<ap=%rdi),>temp2=%edx
mov   3944(%rdi),%edx

# qhasm: mem64[ap + 3944] = temp1
# asm 1: mov   <temp1=int64#2,3944(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3944(<ap=%rdi)
mov   %esi,3944(%rdi)

# qhasm: mem64[ap + 1468] = temp2
# asm 1: mov   <temp2=int64#3,1468(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1468(<ap=%rdi)
mov   %edx,1468(%rdi)

# qhasm: temp1 = mem64[ap + 1476]
# asm 1: mov   1476(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1476(<ap=%rdi),>temp1=%esi
mov   1476(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2280]
# asm 1: mov   2280(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2280(<ap=%rdi),>temp2=%edx
mov   2280(%rdi),%edx

# qhasm: mem64[ap + 2280] = temp1
# asm 1: mov   <temp1=int64#2,2280(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2280(<ap=%rdi)
mov   %esi,2280(%rdi)

# qhasm: mem64[ap + 1476] = temp2
# asm 1: mov   <temp2=int64#3,1476(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1476(<ap=%rdi)
mov   %edx,1476(%rdi)

# qhasm: temp1 = mem64[ap + 1484]
# asm 1: mov   1484(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1484(<ap=%rdi),>temp1=%esi
mov   1484(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3304]
# asm 1: mov   3304(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3304(<ap=%rdi),>temp2=%edx
mov   3304(%rdi),%edx

# qhasm: mem64[ap + 3304] = temp1
# asm 1: mov   <temp1=int64#2,3304(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3304(<ap=%rdi)
mov   %esi,3304(%rdi)

# qhasm: mem64[ap + 1484] = temp2
# asm 1: mov   <temp2=int64#3,1484(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1484(<ap=%rdi)
mov   %edx,1484(%rdi)

# qhasm: temp1 = mem64[ap + 1492]
# asm 1: mov   1492(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1492(<ap=%rdi),>temp1=%esi
mov   1492(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2792]
# asm 1: mov   2792(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2792(<ap=%rdi),>temp2=%edx
mov   2792(%rdi),%edx

# qhasm: mem64[ap + 2792] = temp1
# asm 1: mov   <temp1=int64#2,2792(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2792(<ap=%rdi)
mov   %esi,2792(%rdi)

# qhasm: mem64[ap + 1492] = temp2
# asm 1: mov   <temp2=int64#3,1492(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1492(<ap=%rdi)
mov   %edx,1492(%rdi)

# qhasm: temp1 = mem64[ap + 1496]
# asm 1: mov   1496(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1496(<ap=%rdi),>temp1=%esi
mov   1496(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1768]
# asm 1: mov   1768(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1768(<ap=%rdi),>temp2=%edx
mov   1768(%rdi),%edx

# qhasm: mem64[ap + 1768] = temp1
# asm 1: mov   <temp1=int64#2,1768(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1768(<ap=%rdi)
mov   %esi,1768(%rdi)

# qhasm: mem64[ap + 1496] = temp2
# asm 1: mov   <temp2=int64#3,1496(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1496(<ap=%rdi)
mov   %edx,1496(%rdi)

# qhasm: temp1 = mem64[ap + 1500]
# asm 1: mov   1500(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1500(<ap=%rdi),>temp1=%esi
mov   1500(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3816]
# asm 1: mov   3816(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3816(<ap=%rdi),>temp2=%edx
mov   3816(%rdi),%edx

# qhasm: mem64[ap + 3816] = temp1
# asm 1: mov   <temp1=int64#2,3816(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3816(<ap=%rdi)
mov   %esi,3816(%rdi)

# qhasm: mem64[ap + 1500] = temp2
# asm 1: mov   <temp2=int64#3,1500(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1500(<ap=%rdi)
mov   %edx,1500(%rdi)

# qhasm: temp1 = mem64[ap + 1508]
# asm 1: mov   1508(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1508(<ap=%rdi),>temp1=%esi
mov   1508(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2536]
# asm 1: mov   2536(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2536(<ap=%rdi),>temp2=%edx
mov   2536(%rdi),%edx

# qhasm: mem64[ap + 2536] = temp1
# asm 1: mov   <temp1=int64#2,2536(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2536(<ap=%rdi)
mov   %esi,2536(%rdi)

# qhasm: mem64[ap + 1508] = temp2
# asm 1: mov   <temp2=int64#3,1508(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1508(<ap=%rdi)
mov   %edx,1508(%rdi)

# qhasm: temp1 = mem64[ap + 1516]
# asm 1: mov   1516(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1516(<ap=%rdi),>temp1=%esi
mov   1516(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3560]
# asm 1: mov   3560(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3560(<ap=%rdi),>temp2=%edx
mov   3560(%rdi),%edx

# qhasm: mem64[ap + 3560] = temp1
# asm 1: mov   <temp1=int64#2,3560(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3560(<ap=%rdi)
mov   %esi,3560(%rdi)

# qhasm: mem64[ap + 1516] = temp2
# asm 1: mov   <temp2=int64#3,1516(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1516(<ap=%rdi)
mov   %edx,1516(%rdi)

# qhasm: temp1 = mem64[ap + 1524]
# asm 1: mov   1524(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1524(<ap=%rdi),>temp1=%esi
mov   1524(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3048]
# asm 1: mov   3048(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3048(<ap=%rdi),>temp2=%edx
mov   3048(%rdi),%edx

# qhasm: mem64[ap + 3048] = temp1
# asm 1: mov   <temp1=int64#2,3048(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3048(<ap=%rdi)
mov   %esi,3048(%rdi)

# qhasm: mem64[ap + 1524] = temp2
# asm 1: mov   <temp2=int64#3,1524(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1524(<ap=%rdi)
mov   %edx,1524(%rdi)

# qhasm: temp1 = mem64[ap + 1528]
# asm 1: mov   1528(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1528(<ap=%rdi),>temp1=%esi
mov   1528(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2024]
# asm 1: mov   2024(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2024(<ap=%rdi),>temp2=%edx
mov   2024(%rdi),%edx

# qhasm: mem64[ap + 2024] = temp1
# asm 1: mov   <temp1=int64#2,2024(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2024(<ap=%rdi)
mov   %esi,2024(%rdi)

# qhasm: mem64[ap + 1528] = temp2
# asm 1: mov   <temp2=int64#3,1528(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1528(<ap=%rdi)
mov   %edx,1528(%rdi)

# qhasm: temp1 = mem64[ap + 1532]
# asm 1: mov   1532(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1532(<ap=%rdi),>temp1=%esi
mov   1532(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4072]
# asm 1: mov   4072(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4072(<ap=%rdi),>temp2=%edx
mov   4072(%rdi),%edx

# qhasm: mem64[ap + 4072] = temp1
# asm 1: mov   <temp1=int64#2,4072(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4072(<ap=%rdi)
mov   %esi,4072(%rdi)

# qhasm: mem64[ap + 1532] = temp2
# asm 1: mov   <temp2=int64#3,1532(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1532(<ap=%rdi)
mov   %edx,1532(%rdi)

# qhasm: temp1 = mem64[ap + 1540]
# asm 1: mov   1540(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1540(<ap=%rdi),>temp1=%esi
mov   1540(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2072]
# asm 1: mov   2072(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2072(<ap=%rdi),>temp2=%edx
mov   2072(%rdi),%edx

# qhasm: mem64[ap + 2072] = temp1
# asm 1: mov   <temp1=int64#2,2072(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2072(<ap=%rdi)
mov   %esi,2072(%rdi)

# qhasm: mem64[ap + 1540] = temp2
# asm 1: mov   <temp2=int64#3,1540(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1540(<ap=%rdi)
mov   %edx,1540(%rdi)

# qhasm: temp1 = mem64[ap + 1548]
# asm 1: mov   1548(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1548(<ap=%rdi),>temp1=%esi
mov   1548(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3096]
# asm 1: mov   3096(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3096(<ap=%rdi),>temp2=%edx
mov   3096(%rdi),%edx

# qhasm: mem64[ap + 3096] = temp1
# asm 1: mov   <temp1=int64#2,3096(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3096(<ap=%rdi)
mov   %esi,3096(%rdi)

# qhasm: mem64[ap + 1548] = temp2
# asm 1: mov   <temp2=int64#3,1548(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1548(<ap=%rdi)
mov   %edx,1548(%rdi)

# qhasm: temp1 = mem64[ap + 1556]
# asm 1: mov   1556(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1556(<ap=%rdi),>temp1=%esi
mov   1556(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2584]
# asm 1: mov   2584(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2584(<ap=%rdi),>temp2=%edx
mov   2584(%rdi),%edx

# qhasm: mem64[ap + 2584] = temp1
# asm 1: mov   <temp1=int64#2,2584(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2584(<ap=%rdi)
mov   %esi,2584(%rdi)

# qhasm: mem64[ap + 1556] = temp2
# asm 1: mov   <temp2=int64#3,1556(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1556(<ap=%rdi)
mov   %edx,1556(%rdi)

# qhasm: temp1 = mem64[ap + 1564]
# asm 1: mov   1564(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1564(<ap=%rdi),>temp1=%esi
mov   1564(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3608]
# asm 1: mov   3608(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3608(<ap=%rdi),>temp2=%edx
mov   3608(%rdi),%edx

# qhasm: mem64[ap + 3608] = temp1
# asm 1: mov   <temp1=int64#2,3608(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3608(<ap=%rdi)
mov   %esi,3608(%rdi)

# qhasm: mem64[ap + 1564] = temp2
# asm 1: mov   <temp2=int64#3,1564(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1564(<ap=%rdi)
mov   %edx,1564(%rdi)

# qhasm: temp1 = mem64[ap + 1572]
# asm 1: mov   1572(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1572(<ap=%rdi),>temp1=%esi
mov   1572(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2328]
# asm 1: mov   2328(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2328(<ap=%rdi),>temp2=%edx
mov   2328(%rdi),%edx

# qhasm: mem64[ap + 2328] = temp1
# asm 1: mov   <temp1=int64#2,2328(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2328(<ap=%rdi)
mov   %esi,2328(%rdi)

# qhasm: mem64[ap + 1572] = temp2
# asm 1: mov   <temp2=int64#3,1572(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1572(<ap=%rdi)
mov   %edx,1572(%rdi)

# qhasm: temp1 = mem64[ap + 1580]
# asm 1: mov   1580(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1580(<ap=%rdi),>temp1=%esi
mov   1580(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3352]
# asm 1: mov   3352(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3352(<ap=%rdi),>temp2=%edx
mov   3352(%rdi),%edx

# qhasm: mem64[ap + 3352] = temp1
# asm 1: mov   <temp1=int64#2,3352(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3352(<ap=%rdi)
mov   %esi,3352(%rdi)

# qhasm: mem64[ap + 1580] = temp2
# asm 1: mov   <temp2=int64#3,1580(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1580(<ap=%rdi)
mov   %edx,1580(%rdi)

# qhasm: temp1 = mem64[ap + 1588]
# asm 1: mov   1588(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1588(<ap=%rdi),>temp1=%esi
mov   1588(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2840]
# asm 1: mov   2840(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2840(<ap=%rdi),>temp2=%edx
mov   2840(%rdi),%edx

# qhasm: mem64[ap + 2840] = temp1
# asm 1: mov   <temp1=int64#2,2840(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2840(<ap=%rdi)
mov   %esi,2840(%rdi)

# qhasm: mem64[ap + 1588] = temp2
# asm 1: mov   <temp2=int64#3,1588(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1588(<ap=%rdi)
mov   %edx,1588(%rdi)

# qhasm: temp1 = mem64[ap + 1592]
# asm 1: mov   1592(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1592(<ap=%rdi),>temp1=%esi
mov   1592(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1816]
# asm 1: mov   1816(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1816(<ap=%rdi),>temp2=%edx
mov   1816(%rdi),%edx

# qhasm: mem64[ap + 1816] = temp1
# asm 1: mov   <temp1=int64#2,1816(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1816(<ap=%rdi)
mov   %esi,1816(%rdi)

# qhasm: mem64[ap + 1592] = temp2
# asm 1: mov   <temp2=int64#3,1592(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1592(<ap=%rdi)
mov   %edx,1592(%rdi)

# qhasm: temp1 = mem64[ap + 1596]
# asm 1: mov   1596(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1596(<ap=%rdi),>temp1=%esi
mov   1596(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3864]
# asm 1: mov   3864(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3864(<ap=%rdi),>temp2=%edx
mov   3864(%rdi),%edx

# qhasm: mem64[ap + 3864] = temp1
# asm 1: mov   <temp1=int64#2,3864(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3864(<ap=%rdi)
mov   %esi,3864(%rdi)

# qhasm: mem64[ap + 1596] = temp2
# asm 1: mov   <temp2=int64#3,1596(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1596(<ap=%rdi)
mov   %edx,1596(%rdi)

# qhasm: temp1 = mem64[ap + 1604]
# asm 1: mov   1604(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1604(<ap=%rdi),>temp1=%esi
mov   1604(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2200]
# asm 1: mov   2200(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2200(<ap=%rdi),>temp2=%edx
mov   2200(%rdi),%edx

# qhasm: mem64[ap + 2200] = temp1
# asm 1: mov   <temp1=int64#2,2200(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2200(<ap=%rdi)
mov   %esi,2200(%rdi)

# qhasm: mem64[ap + 1604] = temp2
# asm 1: mov   <temp2=int64#3,1604(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1604(<ap=%rdi)
mov   %edx,1604(%rdi)

# qhasm: temp1 = mem64[ap + 1612]
# asm 1: mov   1612(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1612(<ap=%rdi),>temp1=%esi
mov   1612(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3224]
# asm 1: mov   3224(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3224(<ap=%rdi),>temp2=%edx
mov   3224(%rdi),%edx

# qhasm: mem64[ap + 3224] = temp1
# asm 1: mov   <temp1=int64#2,3224(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3224(<ap=%rdi)
mov   %esi,3224(%rdi)

# qhasm: mem64[ap + 1612] = temp2
# asm 1: mov   <temp2=int64#3,1612(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1612(<ap=%rdi)
mov   %edx,1612(%rdi)

# qhasm: temp1 = mem64[ap + 1620]
# asm 1: mov   1620(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1620(<ap=%rdi),>temp1=%esi
mov   1620(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2712]
# asm 1: mov   2712(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2712(<ap=%rdi),>temp2=%edx
mov   2712(%rdi),%edx

# qhasm: mem64[ap + 2712] = temp1
# asm 1: mov   <temp1=int64#2,2712(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2712(<ap=%rdi)
mov   %esi,2712(%rdi)

# qhasm: mem64[ap + 1620] = temp2
# asm 1: mov   <temp2=int64#3,1620(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1620(<ap=%rdi)
mov   %edx,1620(%rdi)

# qhasm: temp1 = mem64[ap + 1624]
# asm 1: mov   1624(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1624(<ap=%rdi),>temp1=%esi
mov   1624(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1688]
# asm 1: mov   1688(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1688(<ap=%rdi),>temp2=%edx
mov   1688(%rdi),%edx

# qhasm: mem64[ap + 1688] = temp1
# asm 1: mov   <temp1=int64#2,1688(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1688(<ap=%rdi)
mov   %esi,1688(%rdi)

# qhasm: mem64[ap + 1624] = temp2
# asm 1: mov   <temp2=int64#3,1624(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1624(<ap=%rdi)
mov   %edx,1624(%rdi)

# qhasm: temp1 = mem64[ap + 1628]
# asm 1: mov   1628(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1628(<ap=%rdi),>temp1=%esi
mov   1628(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3736]
# asm 1: mov   3736(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3736(<ap=%rdi),>temp2=%edx
mov   3736(%rdi),%edx

# qhasm: mem64[ap + 3736] = temp1
# asm 1: mov   <temp1=int64#2,3736(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3736(<ap=%rdi)
mov   %esi,3736(%rdi)

# qhasm: mem64[ap + 1628] = temp2
# asm 1: mov   <temp2=int64#3,1628(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1628(<ap=%rdi)
mov   %edx,1628(%rdi)

# qhasm: temp1 = mem64[ap + 1636]
# asm 1: mov   1636(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1636(<ap=%rdi),>temp1=%esi
mov   1636(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2456]
# asm 1: mov   2456(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2456(<ap=%rdi),>temp2=%edx
mov   2456(%rdi),%edx

# qhasm: mem64[ap + 2456] = temp1
# asm 1: mov   <temp1=int64#2,2456(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2456(<ap=%rdi)
mov   %esi,2456(%rdi)

# qhasm: mem64[ap + 1636] = temp2
# asm 1: mov   <temp2=int64#3,1636(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1636(<ap=%rdi)
mov   %edx,1636(%rdi)

# qhasm: temp1 = mem64[ap + 1644]
# asm 1: mov   1644(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1644(<ap=%rdi),>temp1=%esi
mov   1644(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3480]
# asm 1: mov   3480(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3480(<ap=%rdi),>temp2=%edx
mov   3480(%rdi),%edx

# qhasm: mem64[ap + 3480] = temp1
# asm 1: mov   <temp1=int64#2,3480(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3480(<ap=%rdi)
mov   %esi,3480(%rdi)

# qhasm: mem64[ap + 1644] = temp2
# asm 1: mov   <temp2=int64#3,1644(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1644(<ap=%rdi)
mov   %edx,1644(%rdi)

# qhasm: temp1 = mem64[ap + 1652]
# asm 1: mov   1652(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1652(<ap=%rdi),>temp1=%esi
mov   1652(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2968]
# asm 1: mov   2968(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2968(<ap=%rdi),>temp2=%edx
mov   2968(%rdi),%edx

# qhasm: mem64[ap + 2968] = temp1
# asm 1: mov   <temp1=int64#2,2968(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2968(<ap=%rdi)
mov   %esi,2968(%rdi)

# qhasm: mem64[ap + 1652] = temp2
# asm 1: mov   <temp2=int64#3,1652(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1652(<ap=%rdi)
mov   %edx,1652(%rdi)

# qhasm: temp1 = mem64[ap + 1656]
# asm 1: mov   1656(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1656(<ap=%rdi),>temp1=%esi
mov   1656(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1944]
# asm 1: mov   1944(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1944(<ap=%rdi),>temp2=%edx
mov   1944(%rdi),%edx

# qhasm: mem64[ap + 1944] = temp1
# asm 1: mov   <temp1=int64#2,1944(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1944(<ap=%rdi)
mov   %esi,1944(%rdi)

# qhasm: mem64[ap + 1656] = temp2
# asm 1: mov   <temp2=int64#3,1656(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1656(<ap=%rdi)
mov   %edx,1656(%rdi)

# qhasm: temp1 = mem64[ap + 1660]
# asm 1: mov   1660(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1660(<ap=%rdi),>temp1=%esi
mov   1660(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3992]
# asm 1: mov   3992(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3992(<ap=%rdi),>temp2=%edx
mov   3992(%rdi),%edx

# qhasm: mem64[ap + 3992] = temp1
# asm 1: mov   <temp1=int64#2,3992(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3992(<ap=%rdi)
mov   %esi,3992(%rdi)

# qhasm: mem64[ap + 1660] = temp2
# asm 1: mov   <temp2=int64#3,1660(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1660(<ap=%rdi)
mov   %edx,1660(%rdi)

# qhasm: temp1 = mem64[ap + 1668]
# asm 1: mov   1668(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1668(<ap=%rdi),>temp1=%esi
mov   1668(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2136]
# asm 1: mov   2136(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2136(<ap=%rdi),>temp2=%edx
mov   2136(%rdi),%edx

# qhasm: mem64[ap + 2136] = temp1
# asm 1: mov   <temp1=int64#2,2136(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2136(<ap=%rdi)
mov   %esi,2136(%rdi)

# qhasm: mem64[ap + 1668] = temp2
# asm 1: mov   <temp2=int64#3,1668(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1668(<ap=%rdi)
mov   %edx,1668(%rdi)

# qhasm: temp1 = mem64[ap + 1676]
# asm 1: mov   1676(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1676(<ap=%rdi),>temp1=%esi
mov   1676(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3160]
# asm 1: mov   3160(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3160(<ap=%rdi),>temp2=%edx
mov   3160(%rdi),%edx

# qhasm: mem64[ap + 3160] = temp1
# asm 1: mov   <temp1=int64#2,3160(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3160(<ap=%rdi)
mov   %esi,3160(%rdi)

# qhasm: mem64[ap + 1676] = temp2
# asm 1: mov   <temp2=int64#3,1676(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1676(<ap=%rdi)
mov   %edx,1676(%rdi)

# qhasm: temp1 = mem64[ap + 1684]
# asm 1: mov   1684(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1684(<ap=%rdi),>temp1=%esi
mov   1684(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2648]
# asm 1: mov   2648(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2648(<ap=%rdi),>temp2=%edx
mov   2648(%rdi),%edx

# qhasm: mem64[ap + 2648] = temp1
# asm 1: mov   <temp1=int64#2,2648(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2648(<ap=%rdi)
mov   %esi,2648(%rdi)

# qhasm: mem64[ap + 1684] = temp2
# asm 1: mov   <temp2=int64#3,1684(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1684(<ap=%rdi)
mov   %edx,1684(%rdi)

# qhasm: temp1 = mem64[ap + 1692]
# asm 1: mov   1692(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1692(<ap=%rdi),>temp1=%esi
mov   1692(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3672]
# asm 1: mov   3672(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3672(<ap=%rdi),>temp2=%edx
mov   3672(%rdi),%edx

# qhasm: mem64[ap + 3672] = temp1
# asm 1: mov   <temp1=int64#2,3672(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3672(<ap=%rdi)
mov   %esi,3672(%rdi)

# qhasm: mem64[ap + 1692] = temp2
# asm 1: mov   <temp2=int64#3,1692(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1692(<ap=%rdi)
mov   %edx,1692(%rdi)

# qhasm: temp1 = mem64[ap + 1700]
# asm 1: mov   1700(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1700(<ap=%rdi),>temp1=%esi
mov   1700(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2392]
# asm 1: mov   2392(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2392(<ap=%rdi),>temp2=%edx
mov   2392(%rdi),%edx

# qhasm: mem64[ap + 2392] = temp1
# asm 1: mov   <temp1=int64#2,2392(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2392(<ap=%rdi)
mov   %esi,2392(%rdi)

# qhasm: mem64[ap + 1700] = temp2
# asm 1: mov   <temp2=int64#3,1700(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1700(<ap=%rdi)
mov   %edx,1700(%rdi)

# qhasm: temp1 = mem64[ap + 1708]
# asm 1: mov   1708(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1708(<ap=%rdi),>temp1=%esi
mov   1708(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3416]
# asm 1: mov   3416(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3416(<ap=%rdi),>temp2=%edx
mov   3416(%rdi),%edx

# qhasm: mem64[ap + 3416] = temp1
# asm 1: mov   <temp1=int64#2,3416(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3416(<ap=%rdi)
mov   %esi,3416(%rdi)

# qhasm: mem64[ap + 1708] = temp2
# asm 1: mov   <temp2=int64#3,1708(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1708(<ap=%rdi)
mov   %edx,1708(%rdi)

# qhasm: temp1 = mem64[ap + 1716]
# asm 1: mov   1716(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1716(<ap=%rdi),>temp1=%esi
mov   1716(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2904]
# asm 1: mov   2904(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2904(<ap=%rdi),>temp2=%edx
mov   2904(%rdi),%edx

# qhasm: mem64[ap + 2904] = temp1
# asm 1: mov   <temp1=int64#2,2904(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2904(<ap=%rdi)
mov   %esi,2904(%rdi)

# qhasm: mem64[ap + 1716] = temp2
# asm 1: mov   <temp2=int64#3,1716(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1716(<ap=%rdi)
mov   %edx,1716(%rdi)

# qhasm: temp1 = mem64[ap + 1720]
# asm 1: mov   1720(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1720(<ap=%rdi),>temp1=%esi
mov   1720(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1880]
# asm 1: mov   1880(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1880(<ap=%rdi),>temp2=%edx
mov   1880(%rdi),%edx

# qhasm: mem64[ap + 1880] = temp1
# asm 1: mov   <temp1=int64#2,1880(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1880(<ap=%rdi)
mov   %esi,1880(%rdi)

# qhasm: mem64[ap + 1720] = temp2
# asm 1: mov   <temp2=int64#3,1720(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1720(<ap=%rdi)
mov   %edx,1720(%rdi)

# qhasm: temp1 = mem64[ap + 1724]
# asm 1: mov   1724(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1724(<ap=%rdi),>temp1=%esi
mov   1724(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3928]
# asm 1: mov   3928(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3928(<ap=%rdi),>temp2=%edx
mov   3928(%rdi),%edx

# qhasm: mem64[ap + 3928] = temp1
# asm 1: mov   <temp1=int64#2,3928(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3928(<ap=%rdi)
mov   %esi,3928(%rdi)

# qhasm: mem64[ap + 1724] = temp2
# asm 1: mov   <temp2=int64#3,1724(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1724(<ap=%rdi)
mov   %edx,1724(%rdi)

# qhasm: temp1 = mem64[ap + 1732]
# asm 1: mov   1732(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1732(<ap=%rdi),>temp1=%esi
mov   1732(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2264]
# asm 1: mov   2264(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2264(<ap=%rdi),>temp2=%edx
mov   2264(%rdi),%edx

# qhasm: mem64[ap + 2264] = temp1
# asm 1: mov   <temp1=int64#2,2264(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2264(<ap=%rdi)
mov   %esi,2264(%rdi)

# qhasm: mem64[ap + 1732] = temp2
# asm 1: mov   <temp2=int64#3,1732(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1732(<ap=%rdi)
mov   %edx,1732(%rdi)

# qhasm: temp1 = mem64[ap + 1740]
# asm 1: mov   1740(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1740(<ap=%rdi),>temp1=%esi
mov   1740(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3288]
# asm 1: mov   3288(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3288(<ap=%rdi),>temp2=%edx
mov   3288(%rdi),%edx

# qhasm: mem64[ap + 3288] = temp1
# asm 1: mov   <temp1=int64#2,3288(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3288(<ap=%rdi)
mov   %esi,3288(%rdi)

# qhasm: mem64[ap + 1740] = temp2
# asm 1: mov   <temp2=int64#3,1740(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1740(<ap=%rdi)
mov   %edx,1740(%rdi)

# qhasm: temp1 = mem64[ap + 1748]
# asm 1: mov   1748(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1748(<ap=%rdi),>temp1=%esi
mov   1748(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2776]
# asm 1: mov   2776(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2776(<ap=%rdi),>temp2=%edx
mov   2776(%rdi),%edx

# qhasm: mem64[ap + 2776] = temp1
# asm 1: mov   <temp1=int64#2,2776(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2776(<ap=%rdi)
mov   %esi,2776(%rdi)

# qhasm: mem64[ap + 1748] = temp2
# asm 1: mov   <temp2=int64#3,1748(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1748(<ap=%rdi)
mov   %edx,1748(%rdi)

# qhasm: temp1 = mem64[ap + 1756]
# asm 1: mov   1756(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1756(<ap=%rdi),>temp1=%esi
mov   1756(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3800]
# asm 1: mov   3800(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3800(<ap=%rdi),>temp2=%edx
mov   3800(%rdi),%edx

# qhasm: mem64[ap + 3800] = temp1
# asm 1: mov   <temp1=int64#2,3800(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3800(<ap=%rdi)
mov   %esi,3800(%rdi)

# qhasm: mem64[ap + 1756] = temp2
# asm 1: mov   <temp2=int64#3,1756(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1756(<ap=%rdi)
mov   %edx,1756(%rdi)

# qhasm: temp1 = mem64[ap + 1764]
# asm 1: mov   1764(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1764(<ap=%rdi),>temp1=%esi
mov   1764(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2520]
# asm 1: mov   2520(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2520(<ap=%rdi),>temp2=%edx
mov   2520(%rdi),%edx

# qhasm: mem64[ap + 2520] = temp1
# asm 1: mov   <temp1=int64#2,2520(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2520(<ap=%rdi)
mov   %esi,2520(%rdi)

# qhasm: mem64[ap + 1764] = temp2
# asm 1: mov   <temp2=int64#3,1764(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1764(<ap=%rdi)
mov   %edx,1764(%rdi)

# qhasm: temp1 = mem64[ap + 1772]
# asm 1: mov   1772(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1772(<ap=%rdi),>temp1=%esi
mov   1772(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3544]
# asm 1: mov   3544(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3544(<ap=%rdi),>temp2=%edx
mov   3544(%rdi),%edx

# qhasm: mem64[ap + 3544] = temp1
# asm 1: mov   <temp1=int64#2,3544(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3544(<ap=%rdi)
mov   %esi,3544(%rdi)

# qhasm: mem64[ap + 1772] = temp2
# asm 1: mov   <temp2=int64#3,1772(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1772(<ap=%rdi)
mov   %edx,1772(%rdi)

# qhasm: temp1 = mem64[ap + 1780]
# asm 1: mov   1780(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1780(<ap=%rdi),>temp1=%esi
mov   1780(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3032]
# asm 1: mov   3032(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3032(<ap=%rdi),>temp2=%edx
mov   3032(%rdi),%edx

# qhasm: mem64[ap + 3032] = temp1
# asm 1: mov   <temp1=int64#2,3032(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3032(<ap=%rdi)
mov   %esi,3032(%rdi)

# qhasm: mem64[ap + 1780] = temp2
# asm 1: mov   <temp2=int64#3,1780(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1780(<ap=%rdi)
mov   %edx,1780(%rdi)

# qhasm: temp1 = mem64[ap + 1784]
# asm 1: mov   1784(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1784(<ap=%rdi),>temp1=%esi
mov   1784(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2008]
# asm 1: mov   2008(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2008(<ap=%rdi),>temp2=%edx
mov   2008(%rdi),%edx

# qhasm: mem64[ap + 2008] = temp1
# asm 1: mov   <temp1=int64#2,2008(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2008(<ap=%rdi)
mov   %esi,2008(%rdi)

# qhasm: mem64[ap + 1784] = temp2
# asm 1: mov   <temp2=int64#3,1784(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1784(<ap=%rdi)
mov   %edx,1784(%rdi)

# qhasm: temp1 = mem64[ap + 1788]
# asm 1: mov   1788(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1788(<ap=%rdi),>temp1=%esi
mov   1788(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4056]
# asm 1: mov   4056(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4056(<ap=%rdi),>temp2=%edx
mov   4056(%rdi),%edx

# qhasm: mem64[ap + 4056] = temp1
# asm 1: mov   <temp1=int64#2,4056(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4056(<ap=%rdi)
mov   %esi,4056(%rdi)

# qhasm: mem64[ap + 1788] = temp2
# asm 1: mov   <temp2=int64#3,1788(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1788(<ap=%rdi)
mov   %edx,1788(%rdi)

# qhasm: temp1 = mem64[ap + 1796]
# asm 1: mov   1796(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1796(<ap=%rdi),>temp1=%esi
mov   1796(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2104]
# asm 1: mov   2104(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2104(<ap=%rdi),>temp2=%edx
mov   2104(%rdi),%edx

# qhasm: mem64[ap + 2104] = temp1
# asm 1: mov   <temp1=int64#2,2104(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2104(<ap=%rdi)
mov   %esi,2104(%rdi)

# qhasm: mem64[ap + 1796] = temp2
# asm 1: mov   <temp2=int64#3,1796(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1796(<ap=%rdi)
mov   %edx,1796(%rdi)

# qhasm: temp1 = mem64[ap + 1804]
# asm 1: mov   1804(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1804(<ap=%rdi),>temp1=%esi
mov   1804(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3128]
# asm 1: mov   3128(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3128(<ap=%rdi),>temp2=%edx
mov   3128(%rdi),%edx

# qhasm: mem64[ap + 3128] = temp1
# asm 1: mov   <temp1=int64#2,3128(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3128(<ap=%rdi)
mov   %esi,3128(%rdi)

# qhasm: mem64[ap + 1804] = temp2
# asm 1: mov   <temp2=int64#3,1804(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1804(<ap=%rdi)
mov   %edx,1804(%rdi)

# qhasm: temp1 = mem64[ap + 1812]
# asm 1: mov   1812(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1812(<ap=%rdi),>temp1=%esi
mov   1812(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2616]
# asm 1: mov   2616(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2616(<ap=%rdi),>temp2=%edx
mov   2616(%rdi),%edx

# qhasm: mem64[ap + 2616] = temp1
# asm 1: mov   <temp1=int64#2,2616(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2616(<ap=%rdi)
mov   %esi,2616(%rdi)

# qhasm: mem64[ap + 1812] = temp2
# asm 1: mov   <temp2=int64#3,1812(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1812(<ap=%rdi)
mov   %edx,1812(%rdi)

# qhasm: temp1 = mem64[ap + 1820]
# asm 1: mov   1820(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1820(<ap=%rdi),>temp1=%esi
mov   1820(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3640]
# asm 1: mov   3640(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3640(<ap=%rdi),>temp2=%edx
mov   3640(%rdi),%edx

# qhasm: mem64[ap + 3640] = temp1
# asm 1: mov   <temp1=int64#2,3640(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3640(<ap=%rdi)
mov   %esi,3640(%rdi)

# qhasm: mem64[ap + 1820] = temp2
# asm 1: mov   <temp2=int64#3,1820(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1820(<ap=%rdi)
mov   %edx,1820(%rdi)

# qhasm: temp1 = mem64[ap + 1828]
# asm 1: mov   1828(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1828(<ap=%rdi),>temp1=%esi
mov   1828(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2360]
# asm 1: mov   2360(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2360(<ap=%rdi),>temp2=%edx
mov   2360(%rdi),%edx

# qhasm: mem64[ap + 2360] = temp1
# asm 1: mov   <temp1=int64#2,2360(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2360(<ap=%rdi)
mov   %esi,2360(%rdi)

# qhasm: mem64[ap + 1828] = temp2
# asm 1: mov   <temp2=int64#3,1828(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1828(<ap=%rdi)
mov   %edx,1828(%rdi)

# qhasm: temp1 = mem64[ap + 1836]
# asm 1: mov   1836(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1836(<ap=%rdi),>temp1=%esi
mov   1836(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3384]
# asm 1: mov   3384(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3384(<ap=%rdi),>temp2=%edx
mov   3384(%rdi),%edx

# qhasm: mem64[ap + 3384] = temp1
# asm 1: mov   <temp1=int64#2,3384(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3384(<ap=%rdi)
mov   %esi,3384(%rdi)

# qhasm: mem64[ap + 1836] = temp2
# asm 1: mov   <temp2=int64#3,1836(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1836(<ap=%rdi)
mov   %edx,1836(%rdi)

# qhasm: temp1 = mem64[ap + 1844]
# asm 1: mov   1844(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1844(<ap=%rdi),>temp1=%esi
mov   1844(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2872]
# asm 1: mov   2872(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2872(<ap=%rdi),>temp2=%edx
mov   2872(%rdi),%edx

# qhasm: mem64[ap + 2872] = temp1
# asm 1: mov   <temp1=int64#2,2872(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2872(<ap=%rdi)
mov   %esi,2872(%rdi)

# qhasm: mem64[ap + 1844] = temp2
# asm 1: mov   <temp2=int64#3,1844(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1844(<ap=%rdi)
mov   %edx,1844(%rdi)

# qhasm: temp1 = mem64[ap + 1852]
# asm 1: mov   1852(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1852(<ap=%rdi),>temp1=%esi
mov   1852(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3896]
# asm 1: mov   3896(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3896(<ap=%rdi),>temp2=%edx
mov   3896(%rdi),%edx

# qhasm: mem64[ap + 3896] = temp1
# asm 1: mov   <temp1=int64#2,3896(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3896(<ap=%rdi)
mov   %esi,3896(%rdi)

# qhasm: mem64[ap + 1852] = temp2
# asm 1: mov   <temp2=int64#3,1852(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1852(<ap=%rdi)
mov   %edx,1852(%rdi)

# qhasm: temp1 = mem64[ap + 1860]
# asm 1: mov   1860(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1860(<ap=%rdi),>temp1=%esi
mov   1860(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2232]
# asm 1: mov   2232(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2232(<ap=%rdi),>temp2=%edx
mov   2232(%rdi),%edx

# qhasm: mem64[ap + 2232] = temp1
# asm 1: mov   <temp1=int64#2,2232(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2232(<ap=%rdi)
mov   %esi,2232(%rdi)

# qhasm: mem64[ap + 1860] = temp2
# asm 1: mov   <temp2=int64#3,1860(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1860(<ap=%rdi)
mov   %edx,1860(%rdi)

# qhasm: temp1 = mem64[ap + 1868]
# asm 1: mov   1868(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1868(<ap=%rdi),>temp1=%esi
mov   1868(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3256]
# asm 1: mov   3256(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3256(<ap=%rdi),>temp2=%edx
mov   3256(%rdi),%edx

# qhasm: mem64[ap + 3256] = temp1
# asm 1: mov   <temp1=int64#2,3256(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3256(<ap=%rdi)
mov   %esi,3256(%rdi)

# qhasm: mem64[ap + 1868] = temp2
# asm 1: mov   <temp2=int64#3,1868(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1868(<ap=%rdi)
mov   %edx,1868(%rdi)

# qhasm: temp1 = mem64[ap + 1876]
# asm 1: mov   1876(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1876(<ap=%rdi),>temp1=%esi
mov   1876(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2744]
# asm 1: mov   2744(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2744(<ap=%rdi),>temp2=%edx
mov   2744(%rdi),%edx

# qhasm: mem64[ap + 2744] = temp1
# asm 1: mov   <temp1=int64#2,2744(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2744(<ap=%rdi)
mov   %esi,2744(%rdi)

# qhasm: mem64[ap + 1876] = temp2
# asm 1: mov   <temp2=int64#3,1876(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1876(<ap=%rdi)
mov   %edx,1876(%rdi)

# qhasm: temp1 = mem64[ap + 1884]
# asm 1: mov   1884(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1884(<ap=%rdi),>temp1=%esi
mov   1884(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3768]
# asm 1: mov   3768(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3768(<ap=%rdi),>temp2=%edx
mov   3768(%rdi),%edx

# qhasm: mem64[ap + 3768] = temp1
# asm 1: mov   <temp1=int64#2,3768(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3768(<ap=%rdi)
mov   %esi,3768(%rdi)

# qhasm: mem64[ap + 1884] = temp2
# asm 1: mov   <temp2=int64#3,1884(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1884(<ap=%rdi)
mov   %edx,1884(%rdi)

# qhasm: temp1 = mem64[ap + 1892]
# asm 1: mov   1892(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1892(<ap=%rdi),>temp1=%esi
mov   1892(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2488]
# asm 1: mov   2488(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2488(<ap=%rdi),>temp2=%edx
mov   2488(%rdi),%edx

# qhasm: mem64[ap + 2488] = temp1
# asm 1: mov   <temp1=int64#2,2488(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2488(<ap=%rdi)
mov   %esi,2488(%rdi)

# qhasm: mem64[ap + 1892] = temp2
# asm 1: mov   <temp2=int64#3,1892(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1892(<ap=%rdi)
mov   %edx,1892(%rdi)

# qhasm: temp1 = mem64[ap + 1900]
# asm 1: mov   1900(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1900(<ap=%rdi),>temp1=%esi
mov   1900(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3512]
# asm 1: mov   3512(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3512(<ap=%rdi),>temp2=%edx
mov   3512(%rdi),%edx

# qhasm: mem64[ap + 3512] = temp1
# asm 1: mov   <temp1=int64#2,3512(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3512(<ap=%rdi)
mov   %esi,3512(%rdi)

# qhasm: mem64[ap + 1900] = temp2
# asm 1: mov   <temp2=int64#3,1900(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1900(<ap=%rdi)
mov   %edx,1900(%rdi)

# qhasm: temp1 = mem64[ap + 1908]
# asm 1: mov   1908(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1908(<ap=%rdi),>temp1=%esi
mov   1908(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3000]
# asm 1: mov   3000(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3000(<ap=%rdi),>temp2=%edx
mov   3000(%rdi),%edx

# qhasm: mem64[ap + 3000] = temp1
# asm 1: mov   <temp1=int64#2,3000(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3000(<ap=%rdi)
mov   %esi,3000(%rdi)

# qhasm: mem64[ap + 1908] = temp2
# asm 1: mov   <temp2=int64#3,1908(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1908(<ap=%rdi)
mov   %edx,1908(%rdi)

# qhasm: temp1 = mem64[ap + 1912]
# asm 1: mov   1912(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1912(<ap=%rdi),>temp1=%esi
mov   1912(%rdi),%esi

# qhasm: temp2 = mem64[ap + 1976]
# asm 1: mov   1976(<ap=int64#1),>temp2=int64#3
# asm 2: mov   1976(<ap=%rdi),>temp2=%edx
mov   1976(%rdi),%edx

# qhasm: mem64[ap + 1976] = temp1
# asm 1: mov   <temp1=int64#2,1976(<ap=int64#1)
# asm 2: mov   <temp1=%esi,1976(<ap=%rdi)
mov   %esi,1976(%rdi)

# qhasm: mem64[ap + 1912] = temp2
# asm 1: mov   <temp2=int64#3,1912(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1912(<ap=%rdi)
mov   %edx,1912(%rdi)

# qhasm: temp1 = mem64[ap + 1916]
# asm 1: mov   1916(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1916(<ap=%rdi),>temp1=%esi
mov   1916(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4024]
# asm 1: mov   4024(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4024(<ap=%rdi),>temp2=%edx
mov   4024(%rdi),%edx

# qhasm: mem64[ap + 4024] = temp1
# asm 1: mov   <temp1=int64#2,4024(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4024(<ap=%rdi)
mov   %esi,4024(%rdi)

# qhasm: mem64[ap + 1916] = temp2
# asm 1: mov   <temp2=int64#3,1916(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1916(<ap=%rdi)
mov   %edx,1916(%rdi)

# qhasm: temp1 = mem64[ap + 1924]
# asm 1: mov   1924(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1924(<ap=%rdi),>temp1=%esi
mov   1924(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2168]
# asm 1: mov   2168(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2168(<ap=%rdi),>temp2=%edx
mov   2168(%rdi),%edx

# qhasm: mem64[ap + 2168] = temp1
# asm 1: mov   <temp1=int64#2,2168(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2168(<ap=%rdi)
mov   %esi,2168(%rdi)

# qhasm: mem64[ap + 1924] = temp2
# asm 1: mov   <temp2=int64#3,1924(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1924(<ap=%rdi)
mov   %edx,1924(%rdi)

# qhasm: temp1 = mem64[ap + 1932]
# asm 1: mov   1932(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1932(<ap=%rdi),>temp1=%esi
mov   1932(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3192]
# asm 1: mov   3192(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3192(<ap=%rdi),>temp2=%edx
mov   3192(%rdi),%edx

# qhasm: mem64[ap + 3192] = temp1
# asm 1: mov   <temp1=int64#2,3192(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3192(<ap=%rdi)
mov   %esi,3192(%rdi)

# qhasm: mem64[ap + 1932] = temp2
# asm 1: mov   <temp2=int64#3,1932(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1932(<ap=%rdi)
mov   %edx,1932(%rdi)

# qhasm: temp1 = mem64[ap + 1940]
# asm 1: mov   1940(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1940(<ap=%rdi),>temp1=%esi
mov   1940(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2680]
# asm 1: mov   2680(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2680(<ap=%rdi),>temp2=%edx
mov   2680(%rdi),%edx

# qhasm: mem64[ap + 2680] = temp1
# asm 1: mov   <temp1=int64#2,2680(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2680(<ap=%rdi)
mov   %esi,2680(%rdi)

# qhasm: mem64[ap + 1940] = temp2
# asm 1: mov   <temp2=int64#3,1940(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1940(<ap=%rdi)
mov   %edx,1940(%rdi)

# qhasm: temp1 = mem64[ap + 1948]
# asm 1: mov   1948(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1948(<ap=%rdi),>temp1=%esi
mov   1948(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3704]
# asm 1: mov   3704(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3704(<ap=%rdi),>temp2=%edx
mov   3704(%rdi),%edx

# qhasm: mem64[ap + 3704] = temp1
# asm 1: mov   <temp1=int64#2,3704(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3704(<ap=%rdi)
mov   %esi,3704(%rdi)

# qhasm: mem64[ap + 1948] = temp2
# asm 1: mov   <temp2=int64#3,1948(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1948(<ap=%rdi)
mov   %edx,1948(%rdi)

# qhasm: temp1 = mem64[ap + 1956]
# asm 1: mov   1956(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1956(<ap=%rdi),>temp1=%esi
mov   1956(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2424]
# asm 1: mov   2424(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2424(<ap=%rdi),>temp2=%edx
mov   2424(%rdi),%edx

# qhasm: mem64[ap + 2424] = temp1
# asm 1: mov   <temp1=int64#2,2424(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2424(<ap=%rdi)
mov   %esi,2424(%rdi)

# qhasm: mem64[ap + 1956] = temp2
# asm 1: mov   <temp2=int64#3,1956(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1956(<ap=%rdi)
mov   %edx,1956(%rdi)

# qhasm: temp1 = mem64[ap + 1964]
# asm 1: mov   1964(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1964(<ap=%rdi),>temp1=%esi
mov   1964(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3448]
# asm 1: mov   3448(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3448(<ap=%rdi),>temp2=%edx
mov   3448(%rdi),%edx

# qhasm: mem64[ap + 3448] = temp1
# asm 1: mov   <temp1=int64#2,3448(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3448(<ap=%rdi)
mov   %esi,3448(%rdi)

# qhasm: mem64[ap + 1964] = temp2
# asm 1: mov   <temp2=int64#3,1964(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1964(<ap=%rdi)
mov   %edx,1964(%rdi)

# qhasm: temp1 = mem64[ap + 1972]
# asm 1: mov   1972(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1972(<ap=%rdi),>temp1=%esi
mov   1972(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2936]
# asm 1: mov   2936(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2936(<ap=%rdi),>temp2=%edx
mov   2936(%rdi),%edx

# qhasm: mem64[ap + 2936] = temp1
# asm 1: mov   <temp1=int64#2,2936(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2936(<ap=%rdi)
mov   %esi,2936(%rdi)

# qhasm: mem64[ap + 1972] = temp2
# asm 1: mov   <temp2=int64#3,1972(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1972(<ap=%rdi)
mov   %edx,1972(%rdi)

# qhasm: temp1 = mem64[ap + 1980]
# asm 1: mov   1980(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1980(<ap=%rdi),>temp1=%esi
mov   1980(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3960]
# asm 1: mov   3960(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3960(<ap=%rdi),>temp2=%edx
mov   3960(%rdi),%edx

# qhasm: mem64[ap + 3960] = temp1
# asm 1: mov   <temp1=int64#2,3960(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3960(<ap=%rdi)
mov   %esi,3960(%rdi)

# qhasm: mem64[ap + 1980] = temp2
# asm 1: mov   <temp2=int64#3,1980(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1980(<ap=%rdi)
mov   %edx,1980(%rdi)

# qhasm: temp1 = mem64[ap + 1988]
# asm 1: mov   1988(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1988(<ap=%rdi),>temp1=%esi
mov   1988(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2296]
# asm 1: mov   2296(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2296(<ap=%rdi),>temp2=%edx
mov   2296(%rdi),%edx

# qhasm: mem64[ap + 2296] = temp1
# asm 1: mov   <temp1=int64#2,2296(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2296(<ap=%rdi)
mov   %esi,2296(%rdi)

# qhasm: mem64[ap + 1988] = temp2
# asm 1: mov   <temp2=int64#3,1988(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1988(<ap=%rdi)
mov   %edx,1988(%rdi)

# qhasm: temp1 = mem64[ap + 1996]
# asm 1: mov   1996(<ap=int64#1),>temp1=int64#2
# asm 2: mov   1996(<ap=%rdi),>temp1=%esi
mov   1996(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3320]
# asm 1: mov   3320(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3320(<ap=%rdi),>temp2=%edx
mov   3320(%rdi),%edx

# qhasm: mem64[ap + 3320] = temp1
# asm 1: mov   <temp1=int64#2,3320(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3320(<ap=%rdi)
mov   %esi,3320(%rdi)

# qhasm: mem64[ap + 1996] = temp2
# asm 1: mov   <temp2=int64#3,1996(<ap=int64#1)
# asm 2: mov   <temp2=%edx,1996(<ap=%rdi)
mov   %edx,1996(%rdi)

# qhasm: temp1 = mem64[ap + 2004]
# asm 1: mov   2004(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2004(<ap=%rdi),>temp1=%esi
mov   2004(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2808]
# asm 1: mov   2808(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2808(<ap=%rdi),>temp2=%edx
mov   2808(%rdi),%edx

# qhasm: mem64[ap + 2808] = temp1
# asm 1: mov   <temp1=int64#2,2808(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2808(<ap=%rdi)
mov   %esi,2808(%rdi)

# qhasm: mem64[ap + 2004] = temp2
# asm 1: mov   <temp2=int64#3,2004(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2004(<ap=%rdi)
mov   %edx,2004(%rdi)

# qhasm: temp1 = mem64[ap + 2012]
# asm 1: mov   2012(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2012(<ap=%rdi),>temp1=%esi
mov   2012(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3832]
# asm 1: mov   3832(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3832(<ap=%rdi),>temp2=%edx
mov   3832(%rdi),%edx

# qhasm: mem64[ap + 3832] = temp1
# asm 1: mov   <temp1=int64#2,3832(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3832(<ap=%rdi)
mov   %esi,3832(%rdi)

# qhasm: mem64[ap + 2012] = temp2
# asm 1: mov   <temp2=int64#3,2012(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2012(<ap=%rdi)
mov   %edx,2012(%rdi)

# qhasm: temp1 = mem64[ap + 2020]
# asm 1: mov   2020(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2020(<ap=%rdi),>temp1=%esi
mov   2020(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2552]
# asm 1: mov   2552(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2552(<ap=%rdi),>temp2=%edx
mov   2552(%rdi),%edx

# qhasm: mem64[ap + 2552] = temp1
# asm 1: mov   <temp1=int64#2,2552(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2552(<ap=%rdi)
mov   %esi,2552(%rdi)

# qhasm: mem64[ap + 2020] = temp2
# asm 1: mov   <temp2=int64#3,2020(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2020(<ap=%rdi)
mov   %edx,2020(%rdi)

# qhasm: temp1 = mem64[ap + 2028]
# asm 1: mov   2028(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2028(<ap=%rdi),>temp1=%esi
mov   2028(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3576]
# asm 1: mov   3576(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3576(<ap=%rdi),>temp2=%edx
mov   3576(%rdi),%edx

# qhasm: mem64[ap + 3576] = temp1
# asm 1: mov   <temp1=int64#2,3576(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3576(<ap=%rdi)
mov   %esi,3576(%rdi)

# qhasm: mem64[ap + 2028] = temp2
# asm 1: mov   <temp2=int64#3,2028(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2028(<ap=%rdi)
mov   %edx,2028(%rdi)

# qhasm: temp1 = mem64[ap + 2036]
# asm 1: mov   2036(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2036(<ap=%rdi),>temp1=%esi
mov   2036(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3064]
# asm 1: mov   3064(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3064(<ap=%rdi),>temp2=%edx
mov   3064(%rdi),%edx

# qhasm: mem64[ap + 3064] = temp1
# asm 1: mov   <temp1=int64#2,3064(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3064(<ap=%rdi)
mov   %esi,3064(%rdi)

# qhasm: mem64[ap + 2036] = temp2
# asm 1: mov   <temp2=int64#3,2036(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2036(<ap=%rdi)
mov   %edx,2036(%rdi)

# qhasm: temp1 = mem64[ap + 2044]
# asm 1: mov   2044(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2044(<ap=%rdi),>temp1=%esi
mov   2044(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4088]
# asm 1: mov   4088(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4088(<ap=%rdi),>temp2=%edx
mov   4088(%rdi),%edx

# qhasm: mem64[ap + 4088] = temp1
# asm 1: mov   <temp1=int64#2,4088(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4088(<ap=%rdi)
mov   %esi,4088(%rdi)

# qhasm: mem64[ap + 2044] = temp2
# asm 1: mov   <temp2=int64#3,2044(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2044(<ap=%rdi)
mov   %edx,2044(%rdi)

# qhasm: temp1 = mem64[ap + 2060]
# asm 1: mov   2060(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2060(<ap=%rdi),>temp1=%esi
mov   2060(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3076]
# asm 1: mov   3076(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3076(<ap=%rdi),>temp2=%edx
mov   3076(%rdi),%edx

# qhasm: mem64[ap + 3076] = temp1
# asm 1: mov   <temp1=int64#2,3076(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3076(<ap=%rdi)
mov   %esi,3076(%rdi)

# qhasm: mem64[ap + 2060] = temp2
# asm 1: mov   <temp2=int64#3,2060(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2060(<ap=%rdi)
mov   %edx,2060(%rdi)

# qhasm: temp1 = mem64[ap + 2068]
# asm 1: mov   2068(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2068(<ap=%rdi),>temp1=%esi
mov   2068(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2564]
# asm 1: mov   2564(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2564(<ap=%rdi),>temp2=%edx
mov   2564(%rdi),%edx

# qhasm: mem64[ap + 2564] = temp1
# asm 1: mov   <temp1=int64#2,2564(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2564(<ap=%rdi)
mov   %esi,2564(%rdi)

# qhasm: mem64[ap + 2068] = temp2
# asm 1: mov   <temp2=int64#3,2068(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2068(<ap=%rdi)
mov   %edx,2068(%rdi)

# qhasm: temp1 = mem64[ap + 2076]
# asm 1: mov   2076(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2076(<ap=%rdi),>temp1=%esi
mov   2076(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3588]
# asm 1: mov   3588(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3588(<ap=%rdi),>temp2=%edx
mov   3588(%rdi),%edx

# qhasm: mem64[ap + 3588] = temp1
# asm 1: mov   <temp1=int64#2,3588(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3588(<ap=%rdi)
mov   %esi,3588(%rdi)

# qhasm: mem64[ap + 2076] = temp2
# asm 1: mov   <temp2=int64#3,2076(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2076(<ap=%rdi)
mov   %edx,2076(%rdi)

# qhasm: temp1 = mem64[ap + 2084]
# asm 1: mov   2084(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2084(<ap=%rdi),>temp1=%esi
mov   2084(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2308]
# asm 1: mov   2308(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2308(<ap=%rdi),>temp2=%edx
mov   2308(%rdi),%edx

# qhasm: mem64[ap + 2308] = temp1
# asm 1: mov   <temp1=int64#2,2308(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2308(<ap=%rdi)
mov   %esi,2308(%rdi)

# qhasm: mem64[ap + 2084] = temp2
# asm 1: mov   <temp2=int64#3,2084(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2084(<ap=%rdi)
mov   %edx,2084(%rdi)

# qhasm: temp1 = mem64[ap + 2092]
# asm 1: mov   2092(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2092(<ap=%rdi),>temp1=%esi
mov   2092(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3332]
# asm 1: mov   3332(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3332(<ap=%rdi),>temp2=%edx
mov   3332(%rdi),%edx

# qhasm: mem64[ap + 3332] = temp1
# asm 1: mov   <temp1=int64#2,3332(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3332(<ap=%rdi)
mov   %esi,3332(%rdi)

# qhasm: mem64[ap + 2092] = temp2
# asm 1: mov   <temp2=int64#3,2092(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2092(<ap=%rdi)
mov   %edx,2092(%rdi)

# qhasm: temp1 = mem64[ap + 2100]
# asm 1: mov   2100(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2100(<ap=%rdi),>temp1=%esi
mov   2100(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2820]
# asm 1: mov   2820(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2820(<ap=%rdi),>temp2=%edx
mov   2820(%rdi),%edx

# qhasm: mem64[ap + 2820] = temp1
# asm 1: mov   <temp1=int64#2,2820(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2820(<ap=%rdi)
mov   %esi,2820(%rdi)

# qhasm: mem64[ap + 2100] = temp2
# asm 1: mov   <temp2=int64#3,2100(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2100(<ap=%rdi)
mov   %edx,2100(%rdi)

# qhasm: temp1 = mem64[ap + 2108]
# asm 1: mov   2108(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2108(<ap=%rdi),>temp1=%esi
mov   2108(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3844]
# asm 1: mov   3844(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3844(<ap=%rdi),>temp2=%edx
mov   3844(%rdi),%edx

# qhasm: mem64[ap + 3844] = temp1
# asm 1: mov   <temp1=int64#2,3844(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3844(<ap=%rdi)
mov   %esi,3844(%rdi)

# qhasm: mem64[ap + 2108] = temp2
# asm 1: mov   <temp2=int64#3,2108(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2108(<ap=%rdi)
mov   %edx,2108(%rdi)

# qhasm: temp1 = mem64[ap + 2116]
# asm 1: mov   2116(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2116(<ap=%rdi),>temp1=%esi
mov   2116(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2180]
# asm 1: mov   2180(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2180(<ap=%rdi),>temp2=%edx
mov   2180(%rdi),%edx

# qhasm: mem64[ap + 2180] = temp1
# asm 1: mov   <temp1=int64#2,2180(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2180(<ap=%rdi)
mov   %esi,2180(%rdi)

# qhasm: mem64[ap + 2116] = temp2
# asm 1: mov   <temp2=int64#3,2116(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2116(<ap=%rdi)
mov   %edx,2116(%rdi)

# qhasm: temp1 = mem64[ap + 2124]
# asm 1: mov   2124(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2124(<ap=%rdi),>temp1=%esi
mov   2124(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3204]
# asm 1: mov   3204(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3204(<ap=%rdi),>temp2=%edx
mov   3204(%rdi),%edx

# qhasm: mem64[ap + 3204] = temp1
# asm 1: mov   <temp1=int64#2,3204(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3204(<ap=%rdi)
mov   %esi,3204(%rdi)

# qhasm: mem64[ap + 2124] = temp2
# asm 1: mov   <temp2=int64#3,2124(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2124(<ap=%rdi)
mov   %edx,2124(%rdi)

# qhasm: temp1 = mem64[ap + 2132]
# asm 1: mov   2132(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2132(<ap=%rdi),>temp1=%esi
mov   2132(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2692]
# asm 1: mov   2692(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2692(<ap=%rdi),>temp2=%edx
mov   2692(%rdi),%edx

# qhasm: mem64[ap + 2692] = temp1
# asm 1: mov   <temp1=int64#2,2692(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2692(<ap=%rdi)
mov   %esi,2692(%rdi)

# qhasm: mem64[ap + 2132] = temp2
# asm 1: mov   <temp2=int64#3,2132(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2132(<ap=%rdi)
mov   %edx,2132(%rdi)

# qhasm: temp1 = mem64[ap + 2140]
# asm 1: mov   2140(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2140(<ap=%rdi),>temp1=%esi
mov   2140(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3716]
# asm 1: mov   3716(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3716(<ap=%rdi),>temp2=%edx
mov   3716(%rdi),%edx

# qhasm: mem64[ap + 3716] = temp1
# asm 1: mov   <temp1=int64#2,3716(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3716(<ap=%rdi)
mov   %esi,3716(%rdi)

# qhasm: mem64[ap + 2140] = temp2
# asm 1: mov   <temp2=int64#3,2140(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2140(<ap=%rdi)
mov   %edx,2140(%rdi)

# qhasm: temp1 = mem64[ap + 2148]
# asm 1: mov   2148(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2148(<ap=%rdi),>temp1=%esi
mov   2148(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2436]
# asm 1: mov   2436(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2436(<ap=%rdi),>temp2=%edx
mov   2436(%rdi),%edx

# qhasm: mem64[ap + 2436] = temp1
# asm 1: mov   <temp1=int64#2,2436(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2436(<ap=%rdi)
mov   %esi,2436(%rdi)

# qhasm: mem64[ap + 2148] = temp2
# asm 1: mov   <temp2=int64#3,2148(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2148(<ap=%rdi)
mov   %edx,2148(%rdi)

# qhasm: temp1 = mem64[ap + 2156]
# asm 1: mov   2156(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2156(<ap=%rdi),>temp1=%esi
mov   2156(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3460]
# asm 1: mov   3460(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3460(<ap=%rdi),>temp2=%edx
mov   3460(%rdi),%edx

# qhasm: mem64[ap + 3460] = temp1
# asm 1: mov   <temp1=int64#2,3460(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3460(<ap=%rdi)
mov   %esi,3460(%rdi)

# qhasm: mem64[ap + 2156] = temp2
# asm 1: mov   <temp2=int64#3,2156(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2156(<ap=%rdi)
mov   %edx,2156(%rdi)

# qhasm: temp1 = mem64[ap + 2164]
# asm 1: mov   2164(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2164(<ap=%rdi),>temp1=%esi
mov   2164(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2948]
# asm 1: mov   2948(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2948(<ap=%rdi),>temp2=%edx
mov   2948(%rdi),%edx

# qhasm: mem64[ap + 2948] = temp1
# asm 1: mov   <temp1=int64#2,2948(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2948(<ap=%rdi)
mov   %esi,2948(%rdi)

# qhasm: mem64[ap + 2164] = temp2
# asm 1: mov   <temp2=int64#3,2164(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2164(<ap=%rdi)
mov   %edx,2164(%rdi)

# qhasm: temp1 = mem64[ap + 2172]
# asm 1: mov   2172(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2172(<ap=%rdi),>temp1=%esi
mov   2172(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3972]
# asm 1: mov   3972(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3972(<ap=%rdi),>temp2=%edx
mov   3972(%rdi),%edx

# qhasm: mem64[ap + 3972] = temp1
# asm 1: mov   <temp1=int64#2,3972(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3972(<ap=%rdi)
mov   %esi,3972(%rdi)

# qhasm: mem64[ap + 2172] = temp2
# asm 1: mov   <temp2=int64#3,2172(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2172(<ap=%rdi)
mov   %edx,2172(%rdi)

# qhasm: temp1 = mem64[ap + 2188]
# asm 1: mov   2188(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2188(<ap=%rdi),>temp1=%esi
mov   2188(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3140]
# asm 1: mov   3140(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3140(<ap=%rdi),>temp2=%edx
mov   3140(%rdi),%edx

# qhasm: mem64[ap + 3140] = temp1
# asm 1: mov   <temp1=int64#2,3140(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3140(<ap=%rdi)
mov   %esi,3140(%rdi)

# qhasm: mem64[ap + 2188] = temp2
# asm 1: mov   <temp2=int64#3,2188(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2188(<ap=%rdi)
mov   %edx,2188(%rdi)

# qhasm: temp1 = mem64[ap + 2196]
# asm 1: mov   2196(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2196(<ap=%rdi),>temp1=%esi
mov   2196(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2628]
# asm 1: mov   2628(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2628(<ap=%rdi),>temp2=%edx
mov   2628(%rdi),%edx

# qhasm: mem64[ap + 2628] = temp1
# asm 1: mov   <temp1=int64#2,2628(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2628(<ap=%rdi)
mov   %esi,2628(%rdi)

# qhasm: mem64[ap + 2196] = temp2
# asm 1: mov   <temp2=int64#3,2196(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2196(<ap=%rdi)
mov   %edx,2196(%rdi)

# qhasm: temp1 = mem64[ap + 2204]
# asm 1: mov   2204(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2204(<ap=%rdi),>temp1=%esi
mov   2204(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3652]
# asm 1: mov   3652(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3652(<ap=%rdi),>temp2=%edx
mov   3652(%rdi),%edx

# qhasm: mem64[ap + 3652] = temp1
# asm 1: mov   <temp1=int64#2,3652(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3652(<ap=%rdi)
mov   %esi,3652(%rdi)

# qhasm: mem64[ap + 2204] = temp2
# asm 1: mov   <temp2=int64#3,2204(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2204(<ap=%rdi)
mov   %edx,2204(%rdi)

# qhasm: temp1 = mem64[ap + 2212]
# asm 1: mov   2212(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2212(<ap=%rdi),>temp1=%esi
mov   2212(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2372]
# asm 1: mov   2372(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2372(<ap=%rdi),>temp2=%edx
mov   2372(%rdi),%edx

# qhasm: mem64[ap + 2372] = temp1
# asm 1: mov   <temp1=int64#2,2372(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2372(<ap=%rdi)
mov   %esi,2372(%rdi)

# qhasm: mem64[ap + 2212] = temp2
# asm 1: mov   <temp2=int64#3,2212(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2212(<ap=%rdi)
mov   %edx,2212(%rdi)

# qhasm: temp1 = mem64[ap + 2220]
# asm 1: mov   2220(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2220(<ap=%rdi),>temp1=%esi
mov   2220(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3396]
# asm 1: mov   3396(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3396(<ap=%rdi),>temp2=%edx
mov   3396(%rdi),%edx

# qhasm: mem64[ap + 3396] = temp1
# asm 1: mov   <temp1=int64#2,3396(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3396(<ap=%rdi)
mov   %esi,3396(%rdi)

# qhasm: mem64[ap + 2220] = temp2
# asm 1: mov   <temp2=int64#3,2220(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2220(<ap=%rdi)
mov   %edx,2220(%rdi)

# qhasm: temp1 = mem64[ap + 2228]
# asm 1: mov   2228(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2228(<ap=%rdi),>temp1=%esi
mov   2228(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2884]
# asm 1: mov   2884(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2884(<ap=%rdi),>temp2=%edx
mov   2884(%rdi),%edx

# qhasm: mem64[ap + 2884] = temp1
# asm 1: mov   <temp1=int64#2,2884(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2884(<ap=%rdi)
mov   %esi,2884(%rdi)

# qhasm: mem64[ap + 2228] = temp2
# asm 1: mov   <temp2=int64#3,2228(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2228(<ap=%rdi)
mov   %edx,2228(%rdi)

# qhasm: temp1 = mem64[ap + 2236]
# asm 1: mov   2236(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2236(<ap=%rdi),>temp1=%esi
mov   2236(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3908]
# asm 1: mov   3908(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3908(<ap=%rdi),>temp2=%edx
mov   3908(%rdi),%edx

# qhasm: mem64[ap + 3908] = temp1
# asm 1: mov   <temp1=int64#2,3908(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3908(<ap=%rdi)
mov   %esi,3908(%rdi)

# qhasm: mem64[ap + 2236] = temp2
# asm 1: mov   <temp2=int64#3,2236(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2236(<ap=%rdi)
mov   %edx,2236(%rdi)

# qhasm: temp1 = mem64[ap + 2252]
# asm 1: mov   2252(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2252(<ap=%rdi),>temp1=%esi
mov   2252(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3268]
# asm 1: mov   3268(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3268(<ap=%rdi),>temp2=%edx
mov   3268(%rdi),%edx

# qhasm: mem64[ap + 3268] = temp1
# asm 1: mov   <temp1=int64#2,3268(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3268(<ap=%rdi)
mov   %esi,3268(%rdi)

# qhasm: mem64[ap + 2252] = temp2
# asm 1: mov   <temp2=int64#3,2252(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2252(<ap=%rdi)
mov   %edx,2252(%rdi)

# qhasm: temp1 = mem64[ap + 2260]
# asm 1: mov   2260(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2260(<ap=%rdi),>temp1=%esi
mov   2260(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2756]
# asm 1: mov   2756(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2756(<ap=%rdi),>temp2=%edx
mov   2756(%rdi),%edx

# qhasm: mem64[ap + 2756] = temp1
# asm 1: mov   <temp1=int64#2,2756(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2756(<ap=%rdi)
mov   %esi,2756(%rdi)

# qhasm: mem64[ap + 2260] = temp2
# asm 1: mov   <temp2=int64#3,2260(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2260(<ap=%rdi)
mov   %edx,2260(%rdi)

# qhasm: temp1 = mem64[ap + 2268]
# asm 1: mov   2268(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2268(<ap=%rdi),>temp1=%esi
mov   2268(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3780]
# asm 1: mov   3780(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3780(<ap=%rdi),>temp2=%edx
mov   3780(%rdi),%edx

# qhasm: mem64[ap + 3780] = temp1
# asm 1: mov   <temp1=int64#2,3780(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3780(<ap=%rdi)
mov   %esi,3780(%rdi)

# qhasm: mem64[ap + 2268] = temp2
# asm 1: mov   <temp2=int64#3,2268(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2268(<ap=%rdi)
mov   %edx,2268(%rdi)

# qhasm: temp1 = mem64[ap + 2276]
# asm 1: mov   2276(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2276(<ap=%rdi),>temp1=%esi
mov   2276(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2500]
# asm 1: mov   2500(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2500(<ap=%rdi),>temp2=%edx
mov   2500(%rdi),%edx

# qhasm: mem64[ap + 2500] = temp1
# asm 1: mov   <temp1=int64#2,2500(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2500(<ap=%rdi)
mov   %esi,2500(%rdi)

# qhasm: mem64[ap + 2276] = temp2
# asm 1: mov   <temp2=int64#3,2276(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2276(<ap=%rdi)
mov   %edx,2276(%rdi)

# qhasm: temp1 = mem64[ap + 2284]
# asm 1: mov   2284(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2284(<ap=%rdi),>temp1=%esi
mov   2284(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3524]
# asm 1: mov   3524(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3524(<ap=%rdi),>temp2=%edx
mov   3524(%rdi),%edx

# qhasm: mem64[ap + 3524] = temp1
# asm 1: mov   <temp1=int64#2,3524(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3524(<ap=%rdi)
mov   %esi,3524(%rdi)

# qhasm: mem64[ap + 2284] = temp2
# asm 1: mov   <temp2=int64#3,2284(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2284(<ap=%rdi)
mov   %edx,2284(%rdi)

# qhasm: temp1 = mem64[ap + 2292]
# asm 1: mov   2292(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2292(<ap=%rdi),>temp1=%esi
mov   2292(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3012]
# asm 1: mov   3012(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3012(<ap=%rdi),>temp2=%edx
mov   3012(%rdi),%edx

# qhasm: mem64[ap + 3012] = temp1
# asm 1: mov   <temp1=int64#2,3012(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3012(<ap=%rdi)
mov   %esi,3012(%rdi)

# qhasm: mem64[ap + 2292] = temp2
# asm 1: mov   <temp2=int64#3,2292(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2292(<ap=%rdi)
mov   %edx,2292(%rdi)

# qhasm: temp1 = mem64[ap + 2300]
# asm 1: mov   2300(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2300(<ap=%rdi),>temp1=%esi
mov   2300(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4036]
# asm 1: mov   4036(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4036(<ap=%rdi),>temp2=%edx
mov   4036(%rdi),%edx

# qhasm: mem64[ap + 4036] = temp1
# asm 1: mov   <temp1=int64#2,4036(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4036(<ap=%rdi)
mov   %esi,4036(%rdi)

# qhasm: mem64[ap + 2300] = temp2
# asm 1: mov   <temp2=int64#3,2300(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2300(<ap=%rdi)
mov   %edx,2300(%rdi)

# qhasm: temp1 = mem64[ap + 2316]
# asm 1: mov   2316(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2316(<ap=%rdi),>temp1=%esi
mov   2316(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3108]
# asm 1: mov   3108(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3108(<ap=%rdi),>temp2=%edx
mov   3108(%rdi),%edx

# qhasm: mem64[ap + 3108] = temp1
# asm 1: mov   <temp1=int64#2,3108(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3108(<ap=%rdi)
mov   %esi,3108(%rdi)

# qhasm: mem64[ap + 2316] = temp2
# asm 1: mov   <temp2=int64#3,2316(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2316(<ap=%rdi)
mov   %edx,2316(%rdi)

# qhasm: temp1 = mem64[ap + 2324]
# asm 1: mov   2324(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2324(<ap=%rdi),>temp1=%esi
mov   2324(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2596]
# asm 1: mov   2596(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2596(<ap=%rdi),>temp2=%edx
mov   2596(%rdi),%edx

# qhasm: mem64[ap + 2596] = temp1
# asm 1: mov   <temp1=int64#2,2596(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2596(<ap=%rdi)
mov   %esi,2596(%rdi)

# qhasm: mem64[ap + 2324] = temp2
# asm 1: mov   <temp2=int64#3,2324(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2324(<ap=%rdi)
mov   %edx,2324(%rdi)

# qhasm: temp1 = mem64[ap + 2332]
# asm 1: mov   2332(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2332(<ap=%rdi),>temp1=%esi
mov   2332(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3620]
# asm 1: mov   3620(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3620(<ap=%rdi),>temp2=%edx
mov   3620(%rdi),%edx

# qhasm: mem64[ap + 3620] = temp1
# asm 1: mov   <temp1=int64#2,3620(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3620(<ap=%rdi)
mov   %esi,3620(%rdi)

# qhasm: mem64[ap + 2332] = temp2
# asm 1: mov   <temp2=int64#3,2332(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2332(<ap=%rdi)
mov   %edx,2332(%rdi)

# qhasm: temp1 = mem64[ap + 2348]
# asm 1: mov   2348(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2348(<ap=%rdi),>temp1=%esi
mov   2348(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3364]
# asm 1: mov   3364(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3364(<ap=%rdi),>temp2=%edx
mov   3364(%rdi),%edx

# qhasm: mem64[ap + 3364] = temp1
# asm 1: mov   <temp1=int64#2,3364(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3364(<ap=%rdi)
mov   %esi,3364(%rdi)

# qhasm: mem64[ap + 2348] = temp2
# asm 1: mov   <temp2=int64#3,2348(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2348(<ap=%rdi)
mov   %edx,2348(%rdi)

# qhasm: temp1 = mem64[ap + 2356]
# asm 1: mov   2356(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2356(<ap=%rdi),>temp1=%esi
mov   2356(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2852]
# asm 1: mov   2852(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2852(<ap=%rdi),>temp2=%edx
mov   2852(%rdi),%edx

# qhasm: mem64[ap + 2852] = temp1
# asm 1: mov   <temp1=int64#2,2852(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2852(<ap=%rdi)
mov   %esi,2852(%rdi)

# qhasm: mem64[ap + 2356] = temp2
# asm 1: mov   <temp2=int64#3,2356(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2356(<ap=%rdi)
mov   %edx,2356(%rdi)

# qhasm: temp1 = mem64[ap + 2364]
# asm 1: mov   2364(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2364(<ap=%rdi),>temp1=%esi
mov   2364(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3876]
# asm 1: mov   3876(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3876(<ap=%rdi),>temp2=%edx
mov   3876(%rdi),%edx

# qhasm: mem64[ap + 3876] = temp1
# asm 1: mov   <temp1=int64#2,3876(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3876(<ap=%rdi)
mov   %esi,3876(%rdi)

# qhasm: mem64[ap + 2364] = temp2
# asm 1: mov   <temp2=int64#3,2364(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2364(<ap=%rdi)
mov   %edx,2364(%rdi)

# qhasm: temp1 = mem64[ap + 2380]
# asm 1: mov   2380(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2380(<ap=%rdi),>temp1=%esi
mov   2380(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3236]
# asm 1: mov   3236(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3236(<ap=%rdi),>temp2=%edx
mov   3236(%rdi),%edx

# qhasm: mem64[ap + 3236] = temp1
# asm 1: mov   <temp1=int64#2,3236(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3236(<ap=%rdi)
mov   %esi,3236(%rdi)

# qhasm: mem64[ap + 2380] = temp2
# asm 1: mov   <temp2=int64#3,2380(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2380(<ap=%rdi)
mov   %edx,2380(%rdi)

# qhasm: temp1 = mem64[ap + 2388]
# asm 1: mov   2388(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2388(<ap=%rdi),>temp1=%esi
mov   2388(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2724]
# asm 1: mov   2724(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2724(<ap=%rdi),>temp2=%edx
mov   2724(%rdi),%edx

# qhasm: mem64[ap + 2724] = temp1
# asm 1: mov   <temp1=int64#2,2724(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2724(<ap=%rdi)
mov   %esi,2724(%rdi)

# qhasm: mem64[ap + 2388] = temp2
# asm 1: mov   <temp2=int64#3,2388(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2388(<ap=%rdi)
mov   %edx,2388(%rdi)

# qhasm: temp1 = mem64[ap + 2396]
# asm 1: mov   2396(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2396(<ap=%rdi),>temp1=%esi
mov   2396(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3748]
# asm 1: mov   3748(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3748(<ap=%rdi),>temp2=%edx
mov   3748(%rdi),%edx

# qhasm: mem64[ap + 3748] = temp1
# asm 1: mov   <temp1=int64#2,3748(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3748(<ap=%rdi)
mov   %esi,3748(%rdi)

# qhasm: mem64[ap + 2396] = temp2
# asm 1: mov   <temp2=int64#3,2396(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2396(<ap=%rdi)
mov   %edx,2396(%rdi)

# qhasm: temp1 = mem64[ap + 2404]
# asm 1: mov   2404(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2404(<ap=%rdi),>temp1=%esi
mov   2404(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2468]
# asm 1: mov   2468(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2468(<ap=%rdi),>temp2=%edx
mov   2468(%rdi),%edx

# qhasm: mem64[ap + 2468] = temp1
# asm 1: mov   <temp1=int64#2,2468(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2468(<ap=%rdi)
mov   %esi,2468(%rdi)

# qhasm: mem64[ap + 2404] = temp2
# asm 1: mov   <temp2=int64#3,2404(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2404(<ap=%rdi)
mov   %edx,2404(%rdi)

# qhasm: temp1 = mem64[ap + 2412]
# asm 1: mov   2412(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2412(<ap=%rdi),>temp1=%esi
mov   2412(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3492]
# asm 1: mov   3492(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3492(<ap=%rdi),>temp2=%edx
mov   3492(%rdi),%edx

# qhasm: mem64[ap + 3492] = temp1
# asm 1: mov   <temp1=int64#2,3492(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3492(<ap=%rdi)
mov   %esi,3492(%rdi)

# qhasm: mem64[ap + 2412] = temp2
# asm 1: mov   <temp2=int64#3,2412(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2412(<ap=%rdi)
mov   %edx,2412(%rdi)

# qhasm: temp1 = mem64[ap + 2420]
# asm 1: mov   2420(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2420(<ap=%rdi),>temp1=%esi
mov   2420(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2980]
# asm 1: mov   2980(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2980(<ap=%rdi),>temp2=%edx
mov   2980(%rdi),%edx

# qhasm: mem64[ap + 2980] = temp1
# asm 1: mov   <temp1=int64#2,2980(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2980(<ap=%rdi)
mov   %esi,2980(%rdi)

# qhasm: mem64[ap + 2420] = temp2
# asm 1: mov   <temp2=int64#3,2420(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2420(<ap=%rdi)
mov   %edx,2420(%rdi)

# qhasm: temp1 = mem64[ap + 2428]
# asm 1: mov   2428(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2428(<ap=%rdi),>temp1=%esi
mov   2428(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4004]
# asm 1: mov   4004(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4004(<ap=%rdi),>temp2=%edx
mov   4004(%rdi),%edx

# qhasm: mem64[ap + 4004] = temp1
# asm 1: mov   <temp1=int64#2,4004(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4004(<ap=%rdi)
mov   %esi,4004(%rdi)

# qhasm: mem64[ap + 2428] = temp2
# asm 1: mov   <temp2=int64#3,2428(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2428(<ap=%rdi)
mov   %edx,2428(%rdi)

# qhasm: temp1 = mem64[ap + 2444]
# asm 1: mov   2444(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2444(<ap=%rdi),>temp1=%esi
mov   2444(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3172]
# asm 1: mov   3172(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3172(<ap=%rdi),>temp2=%edx
mov   3172(%rdi),%edx

# qhasm: mem64[ap + 3172] = temp1
# asm 1: mov   <temp1=int64#2,3172(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3172(<ap=%rdi)
mov   %esi,3172(%rdi)

# qhasm: mem64[ap + 2444] = temp2
# asm 1: mov   <temp2=int64#3,2444(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2444(<ap=%rdi)
mov   %edx,2444(%rdi)

# qhasm: temp1 = mem64[ap + 2452]
# asm 1: mov   2452(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2452(<ap=%rdi),>temp1=%esi
mov   2452(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2660]
# asm 1: mov   2660(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2660(<ap=%rdi),>temp2=%edx
mov   2660(%rdi),%edx

# qhasm: mem64[ap + 2660] = temp1
# asm 1: mov   <temp1=int64#2,2660(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2660(<ap=%rdi)
mov   %esi,2660(%rdi)

# qhasm: mem64[ap + 2452] = temp2
# asm 1: mov   <temp2=int64#3,2452(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2452(<ap=%rdi)
mov   %edx,2452(%rdi)

# qhasm: temp1 = mem64[ap + 2460]
# asm 1: mov   2460(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2460(<ap=%rdi),>temp1=%esi
mov   2460(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3684]
# asm 1: mov   3684(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3684(<ap=%rdi),>temp2=%edx
mov   3684(%rdi),%edx

# qhasm: mem64[ap + 3684] = temp1
# asm 1: mov   <temp1=int64#2,3684(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3684(<ap=%rdi)
mov   %esi,3684(%rdi)

# qhasm: mem64[ap + 2460] = temp2
# asm 1: mov   <temp2=int64#3,2460(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2460(<ap=%rdi)
mov   %edx,2460(%rdi)

# qhasm: temp1 = mem64[ap + 2476]
# asm 1: mov   2476(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2476(<ap=%rdi),>temp1=%esi
mov   2476(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3428]
# asm 1: mov   3428(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3428(<ap=%rdi),>temp2=%edx
mov   3428(%rdi),%edx

# qhasm: mem64[ap + 3428] = temp1
# asm 1: mov   <temp1=int64#2,3428(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3428(<ap=%rdi)
mov   %esi,3428(%rdi)

# qhasm: mem64[ap + 2476] = temp2
# asm 1: mov   <temp2=int64#3,2476(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2476(<ap=%rdi)
mov   %edx,2476(%rdi)

# qhasm: temp1 = mem64[ap + 2484]
# asm 1: mov   2484(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2484(<ap=%rdi),>temp1=%esi
mov   2484(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2916]
# asm 1: mov   2916(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2916(<ap=%rdi),>temp2=%edx
mov   2916(%rdi),%edx

# qhasm: mem64[ap + 2916] = temp1
# asm 1: mov   <temp1=int64#2,2916(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2916(<ap=%rdi)
mov   %esi,2916(%rdi)

# qhasm: mem64[ap + 2484] = temp2
# asm 1: mov   <temp2=int64#3,2484(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2484(<ap=%rdi)
mov   %edx,2484(%rdi)

# qhasm: temp1 = mem64[ap + 2492]
# asm 1: mov   2492(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2492(<ap=%rdi),>temp1=%esi
mov   2492(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3940]
# asm 1: mov   3940(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3940(<ap=%rdi),>temp2=%edx
mov   3940(%rdi),%edx

# qhasm: mem64[ap + 3940] = temp1
# asm 1: mov   <temp1=int64#2,3940(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3940(<ap=%rdi)
mov   %esi,3940(%rdi)

# qhasm: mem64[ap + 2492] = temp2
# asm 1: mov   <temp2=int64#3,2492(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2492(<ap=%rdi)
mov   %edx,2492(%rdi)

# qhasm: temp1 = mem64[ap + 2508]
# asm 1: mov   2508(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2508(<ap=%rdi),>temp1=%esi
mov   2508(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3300]
# asm 1: mov   3300(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3300(<ap=%rdi),>temp2=%edx
mov   3300(%rdi),%edx

# qhasm: mem64[ap + 3300] = temp1
# asm 1: mov   <temp1=int64#2,3300(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3300(<ap=%rdi)
mov   %esi,3300(%rdi)

# qhasm: mem64[ap + 2508] = temp2
# asm 1: mov   <temp2=int64#3,2508(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2508(<ap=%rdi)
mov   %edx,2508(%rdi)

# qhasm: temp1 = mem64[ap + 2516]
# asm 1: mov   2516(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2516(<ap=%rdi),>temp1=%esi
mov   2516(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2788]
# asm 1: mov   2788(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2788(<ap=%rdi),>temp2=%edx
mov   2788(%rdi),%edx

# qhasm: mem64[ap + 2788] = temp1
# asm 1: mov   <temp1=int64#2,2788(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2788(<ap=%rdi)
mov   %esi,2788(%rdi)

# qhasm: mem64[ap + 2516] = temp2
# asm 1: mov   <temp2=int64#3,2516(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2516(<ap=%rdi)
mov   %edx,2516(%rdi)

# qhasm: temp1 = mem64[ap + 2524]
# asm 1: mov   2524(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2524(<ap=%rdi),>temp1=%esi
mov   2524(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3812]
# asm 1: mov   3812(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3812(<ap=%rdi),>temp2=%edx
mov   3812(%rdi),%edx

# qhasm: mem64[ap + 3812] = temp1
# asm 1: mov   <temp1=int64#2,3812(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3812(<ap=%rdi)
mov   %esi,3812(%rdi)

# qhasm: mem64[ap + 2524] = temp2
# asm 1: mov   <temp2=int64#3,2524(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2524(<ap=%rdi)
mov   %edx,2524(%rdi)

# qhasm: temp1 = mem64[ap + 2540]
# asm 1: mov   2540(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2540(<ap=%rdi),>temp1=%esi
mov   2540(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3556]
# asm 1: mov   3556(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3556(<ap=%rdi),>temp2=%edx
mov   3556(%rdi),%edx

# qhasm: mem64[ap + 3556] = temp1
# asm 1: mov   <temp1=int64#2,3556(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3556(<ap=%rdi)
mov   %esi,3556(%rdi)

# qhasm: mem64[ap + 2540] = temp2
# asm 1: mov   <temp2=int64#3,2540(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2540(<ap=%rdi)
mov   %edx,2540(%rdi)

# qhasm: temp1 = mem64[ap + 2548]
# asm 1: mov   2548(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2548(<ap=%rdi),>temp1=%esi
mov   2548(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3044]
# asm 1: mov   3044(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3044(<ap=%rdi),>temp2=%edx
mov   3044(%rdi),%edx

# qhasm: mem64[ap + 3044] = temp1
# asm 1: mov   <temp1=int64#2,3044(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3044(<ap=%rdi)
mov   %esi,3044(%rdi)

# qhasm: mem64[ap + 2548] = temp2
# asm 1: mov   <temp2=int64#3,2548(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2548(<ap=%rdi)
mov   %edx,2548(%rdi)

# qhasm: temp1 = mem64[ap + 2556]
# asm 1: mov   2556(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2556(<ap=%rdi),>temp1=%esi
mov   2556(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4068]
# asm 1: mov   4068(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4068(<ap=%rdi),>temp2=%edx
mov   4068(%rdi),%edx

# qhasm: mem64[ap + 4068] = temp1
# asm 1: mov   <temp1=int64#2,4068(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4068(<ap=%rdi)
mov   %esi,4068(%rdi)

# qhasm: mem64[ap + 2556] = temp2
# asm 1: mov   <temp2=int64#3,2556(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2556(<ap=%rdi)
mov   %edx,2556(%rdi)

# qhasm: temp1 = mem64[ap + 2572]
# asm 1: mov   2572(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2572(<ap=%rdi),>temp1=%esi
mov   2572(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3092]
# asm 1: mov   3092(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3092(<ap=%rdi),>temp2=%edx
mov   3092(%rdi),%edx

# qhasm: mem64[ap + 3092] = temp1
# asm 1: mov   <temp1=int64#2,3092(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3092(<ap=%rdi)
mov   %esi,3092(%rdi)

# qhasm: mem64[ap + 2572] = temp2
# asm 1: mov   <temp2=int64#3,2572(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2572(<ap=%rdi)
mov   %edx,2572(%rdi)

# qhasm: temp1 = mem64[ap + 2588]
# asm 1: mov   2588(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2588(<ap=%rdi),>temp1=%esi
mov   2588(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3604]
# asm 1: mov   3604(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3604(<ap=%rdi),>temp2=%edx
mov   3604(%rdi),%edx

# qhasm: mem64[ap + 3604] = temp1
# asm 1: mov   <temp1=int64#2,3604(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3604(<ap=%rdi)
mov   %esi,3604(%rdi)

# qhasm: mem64[ap + 2588] = temp2
# asm 1: mov   <temp2=int64#3,2588(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2588(<ap=%rdi)
mov   %edx,2588(%rdi)

# qhasm: temp1 = mem64[ap + 2604]
# asm 1: mov   2604(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2604(<ap=%rdi),>temp1=%esi
mov   2604(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3348]
# asm 1: mov   3348(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3348(<ap=%rdi),>temp2=%edx
mov   3348(%rdi),%edx

# qhasm: mem64[ap + 3348] = temp1
# asm 1: mov   <temp1=int64#2,3348(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3348(<ap=%rdi)
mov   %esi,3348(%rdi)

# qhasm: mem64[ap + 2604] = temp2
# asm 1: mov   <temp2=int64#3,2604(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2604(<ap=%rdi)
mov   %edx,2604(%rdi)

# qhasm: temp1 = mem64[ap + 2612]
# asm 1: mov   2612(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2612(<ap=%rdi),>temp1=%esi
mov   2612(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2836]
# asm 1: mov   2836(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2836(<ap=%rdi),>temp2=%edx
mov   2836(%rdi),%edx

# qhasm: mem64[ap + 2836] = temp1
# asm 1: mov   <temp1=int64#2,2836(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2836(<ap=%rdi)
mov   %esi,2836(%rdi)

# qhasm: mem64[ap + 2612] = temp2
# asm 1: mov   <temp2=int64#3,2612(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2612(<ap=%rdi)
mov   %edx,2612(%rdi)

# qhasm: temp1 = mem64[ap + 2620]
# asm 1: mov   2620(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2620(<ap=%rdi),>temp1=%esi
mov   2620(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3860]
# asm 1: mov   3860(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3860(<ap=%rdi),>temp2=%edx
mov   3860(%rdi),%edx

# qhasm: mem64[ap + 3860] = temp1
# asm 1: mov   <temp1=int64#2,3860(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3860(<ap=%rdi)
mov   %esi,3860(%rdi)

# qhasm: mem64[ap + 2620] = temp2
# asm 1: mov   <temp2=int64#3,2620(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2620(<ap=%rdi)
mov   %edx,2620(%rdi)

# qhasm: temp1 = mem64[ap + 2636]
# asm 1: mov   2636(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2636(<ap=%rdi),>temp1=%esi
mov   2636(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3220]
# asm 1: mov   3220(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3220(<ap=%rdi),>temp2=%edx
mov   3220(%rdi),%edx

# qhasm: mem64[ap + 3220] = temp1
# asm 1: mov   <temp1=int64#2,3220(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3220(<ap=%rdi)
mov   %esi,3220(%rdi)

# qhasm: mem64[ap + 2636] = temp2
# asm 1: mov   <temp2=int64#3,2636(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2636(<ap=%rdi)
mov   %edx,2636(%rdi)

# qhasm: temp1 = mem64[ap + 2644]
# asm 1: mov   2644(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2644(<ap=%rdi),>temp1=%esi
mov   2644(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2708]
# asm 1: mov   2708(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2708(<ap=%rdi),>temp2=%edx
mov   2708(%rdi),%edx

# qhasm: mem64[ap + 2708] = temp1
# asm 1: mov   <temp1=int64#2,2708(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2708(<ap=%rdi)
mov   %esi,2708(%rdi)

# qhasm: mem64[ap + 2644] = temp2
# asm 1: mov   <temp2=int64#3,2644(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2644(<ap=%rdi)
mov   %edx,2644(%rdi)

# qhasm: temp1 = mem64[ap + 2652]
# asm 1: mov   2652(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2652(<ap=%rdi),>temp1=%esi
mov   2652(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3732]
# asm 1: mov   3732(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3732(<ap=%rdi),>temp2=%edx
mov   3732(%rdi),%edx

# qhasm: mem64[ap + 3732] = temp1
# asm 1: mov   <temp1=int64#2,3732(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3732(<ap=%rdi)
mov   %esi,3732(%rdi)

# qhasm: mem64[ap + 2652] = temp2
# asm 1: mov   <temp2=int64#3,2652(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2652(<ap=%rdi)
mov   %edx,2652(%rdi)

# qhasm: temp1 = mem64[ap + 2668]
# asm 1: mov   2668(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2668(<ap=%rdi),>temp1=%esi
mov   2668(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3476]
# asm 1: mov   3476(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3476(<ap=%rdi),>temp2=%edx
mov   3476(%rdi),%edx

# qhasm: mem64[ap + 3476] = temp1
# asm 1: mov   <temp1=int64#2,3476(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3476(<ap=%rdi)
mov   %esi,3476(%rdi)

# qhasm: mem64[ap + 2668] = temp2
# asm 1: mov   <temp2=int64#3,2668(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2668(<ap=%rdi)
mov   %edx,2668(%rdi)

# qhasm: temp1 = mem64[ap + 2676]
# asm 1: mov   2676(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2676(<ap=%rdi),>temp1=%esi
mov   2676(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2964]
# asm 1: mov   2964(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2964(<ap=%rdi),>temp2=%edx
mov   2964(%rdi),%edx

# qhasm: mem64[ap + 2964] = temp1
# asm 1: mov   <temp1=int64#2,2964(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2964(<ap=%rdi)
mov   %esi,2964(%rdi)

# qhasm: mem64[ap + 2676] = temp2
# asm 1: mov   <temp2=int64#3,2676(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2676(<ap=%rdi)
mov   %edx,2676(%rdi)

# qhasm: temp1 = mem64[ap + 2684]
# asm 1: mov   2684(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2684(<ap=%rdi),>temp1=%esi
mov   2684(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3988]
# asm 1: mov   3988(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3988(<ap=%rdi),>temp2=%edx
mov   3988(%rdi),%edx

# qhasm: mem64[ap + 3988] = temp1
# asm 1: mov   <temp1=int64#2,3988(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3988(<ap=%rdi)
mov   %esi,3988(%rdi)

# qhasm: mem64[ap + 2684] = temp2
# asm 1: mov   <temp2=int64#3,2684(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2684(<ap=%rdi)
mov   %edx,2684(%rdi)

# qhasm: temp1 = mem64[ap + 2700]
# asm 1: mov   2700(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2700(<ap=%rdi),>temp1=%esi
mov   2700(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3156]
# asm 1: mov   3156(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3156(<ap=%rdi),>temp2=%edx
mov   3156(%rdi),%edx

# qhasm: mem64[ap + 3156] = temp1
# asm 1: mov   <temp1=int64#2,3156(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3156(<ap=%rdi)
mov   %esi,3156(%rdi)

# qhasm: mem64[ap + 2700] = temp2
# asm 1: mov   <temp2=int64#3,2700(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2700(<ap=%rdi)
mov   %edx,2700(%rdi)

# qhasm: temp1 = mem64[ap + 2716]
# asm 1: mov   2716(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2716(<ap=%rdi),>temp1=%esi
mov   2716(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3668]
# asm 1: mov   3668(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3668(<ap=%rdi),>temp2=%edx
mov   3668(%rdi),%edx

# qhasm: mem64[ap + 3668] = temp1
# asm 1: mov   <temp1=int64#2,3668(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3668(<ap=%rdi)
mov   %esi,3668(%rdi)

# qhasm: mem64[ap + 2716] = temp2
# asm 1: mov   <temp2=int64#3,2716(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2716(<ap=%rdi)
mov   %edx,2716(%rdi)

# qhasm: temp1 = mem64[ap + 2732]
# asm 1: mov   2732(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2732(<ap=%rdi),>temp1=%esi
mov   2732(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3412]
# asm 1: mov   3412(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3412(<ap=%rdi),>temp2=%edx
mov   3412(%rdi),%edx

# qhasm: mem64[ap + 3412] = temp1
# asm 1: mov   <temp1=int64#2,3412(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3412(<ap=%rdi)
mov   %esi,3412(%rdi)

# qhasm: mem64[ap + 2732] = temp2
# asm 1: mov   <temp2=int64#3,2732(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2732(<ap=%rdi)
mov   %edx,2732(%rdi)

# qhasm: temp1 = mem64[ap + 2740]
# asm 1: mov   2740(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2740(<ap=%rdi),>temp1=%esi
mov   2740(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2900]
# asm 1: mov   2900(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2900(<ap=%rdi),>temp2=%edx
mov   2900(%rdi),%edx

# qhasm: mem64[ap + 2900] = temp1
# asm 1: mov   <temp1=int64#2,2900(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2900(<ap=%rdi)
mov   %esi,2900(%rdi)

# qhasm: mem64[ap + 2740] = temp2
# asm 1: mov   <temp2=int64#3,2740(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2740(<ap=%rdi)
mov   %edx,2740(%rdi)

# qhasm: temp1 = mem64[ap + 2748]
# asm 1: mov   2748(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2748(<ap=%rdi),>temp1=%esi
mov   2748(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3924]
# asm 1: mov   3924(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3924(<ap=%rdi),>temp2=%edx
mov   3924(%rdi),%edx

# qhasm: mem64[ap + 3924] = temp1
# asm 1: mov   <temp1=int64#2,3924(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3924(<ap=%rdi)
mov   %esi,3924(%rdi)

# qhasm: mem64[ap + 2748] = temp2
# asm 1: mov   <temp2=int64#3,2748(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2748(<ap=%rdi)
mov   %edx,2748(%rdi)

# qhasm: temp1 = mem64[ap + 2764]
# asm 1: mov   2764(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2764(<ap=%rdi),>temp1=%esi
mov   2764(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3284]
# asm 1: mov   3284(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3284(<ap=%rdi),>temp2=%edx
mov   3284(%rdi),%edx

# qhasm: mem64[ap + 3284] = temp1
# asm 1: mov   <temp1=int64#2,3284(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3284(<ap=%rdi)
mov   %esi,3284(%rdi)

# qhasm: mem64[ap + 2764] = temp2
# asm 1: mov   <temp2=int64#3,2764(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2764(<ap=%rdi)
mov   %edx,2764(%rdi)

# qhasm: temp1 = mem64[ap + 2780]
# asm 1: mov   2780(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2780(<ap=%rdi),>temp1=%esi
mov   2780(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3796]
# asm 1: mov   3796(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3796(<ap=%rdi),>temp2=%edx
mov   3796(%rdi),%edx

# qhasm: mem64[ap + 3796] = temp1
# asm 1: mov   <temp1=int64#2,3796(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3796(<ap=%rdi)
mov   %esi,3796(%rdi)

# qhasm: mem64[ap + 2780] = temp2
# asm 1: mov   <temp2=int64#3,2780(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2780(<ap=%rdi)
mov   %edx,2780(%rdi)

# qhasm: temp1 = mem64[ap + 2796]
# asm 1: mov   2796(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2796(<ap=%rdi),>temp1=%esi
mov   2796(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3540]
# asm 1: mov   3540(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3540(<ap=%rdi),>temp2=%edx
mov   3540(%rdi),%edx

# qhasm: mem64[ap + 3540] = temp1
# asm 1: mov   <temp1=int64#2,3540(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3540(<ap=%rdi)
mov   %esi,3540(%rdi)

# qhasm: mem64[ap + 2796] = temp2
# asm 1: mov   <temp2=int64#3,2796(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2796(<ap=%rdi)
mov   %edx,2796(%rdi)

# qhasm: temp1 = mem64[ap + 2804]
# asm 1: mov   2804(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2804(<ap=%rdi),>temp1=%esi
mov   2804(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3028]
# asm 1: mov   3028(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3028(<ap=%rdi),>temp2=%edx
mov   3028(%rdi),%edx

# qhasm: mem64[ap + 3028] = temp1
# asm 1: mov   <temp1=int64#2,3028(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3028(<ap=%rdi)
mov   %esi,3028(%rdi)

# qhasm: mem64[ap + 2804] = temp2
# asm 1: mov   <temp2=int64#3,2804(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2804(<ap=%rdi)
mov   %edx,2804(%rdi)

# qhasm: temp1 = mem64[ap + 2812]
# asm 1: mov   2812(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2812(<ap=%rdi),>temp1=%esi
mov   2812(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4052]
# asm 1: mov   4052(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4052(<ap=%rdi),>temp2=%edx
mov   4052(%rdi),%edx

# qhasm: mem64[ap + 4052] = temp1
# asm 1: mov   <temp1=int64#2,4052(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4052(<ap=%rdi)
mov   %esi,4052(%rdi)

# qhasm: mem64[ap + 2812] = temp2
# asm 1: mov   <temp2=int64#3,2812(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2812(<ap=%rdi)
mov   %edx,2812(%rdi)

# qhasm: temp1 = mem64[ap + 2828]
# asm 1: mov   2828(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2828(<ap=%rdi),>temp1=%esi
mov   2828(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3124]
# asm 1: mov   3124(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3124(<ap=%rdi),>temp2=%edx
mov   3124(%rdi),%edx

# qhasm: mem64[ap + 3124] = temp1
# asm 1: mov   <temp1=int64#2,3124(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3124(<ap=%rdi)
mov   %esi,3124(%rdi)

# qhasm: mem64[ap + 2828] = temp2
# asm 1: mov   <temp2=int64#3,2828(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2828(<ap=%rdi)
mov   %edx,2828(%rdi)

# qhasm: temp1 = mem64[ap + 2844]
# asm 1: mov   2844(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2844(<ap=%rdi),>temp1=%esi
mov   2844(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3636]
# asm 1: mov   3636(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3636(<ap=%rdi),>temp2=%edx
mov   3636(%rdi),%edx

# qhasm: mem64[ap + 3636] = temp1
# asm 1: mov   <temp1=int64#2,3636(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3636(<ap=%rdi)
mov   %esi,3636(%rdi)

# qhasm: mem64[ap + 2844] = temp2
# asm 1: mov   <temp2=int64#3,2844(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2844(<ap=%rdi)
mov   %edx,2844(%rdi)

# qhasm: temp1 = mem64[ap + 2860]
# asm 1: mov   2860(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2860(<ap=%rdi),>temp1=%esi
mov   2860(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3380]
# asm 1: mov   3380(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3380(<ap=%rdi),>temp2=%edx
mov   3380(%rdi),%edx

# qhasm: mem64[ap + 3380] = temp1
# asm 1: mov   <temp1=int64#2,3380(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3380(<ap=%rdi)
mov   %esi,3380(%rdi)

# qhasm: mem64[ap + 2860] = temp2
# asm 1: mov   <temp2=int64#3,2860(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2860(<ap=%rdi)
mov   %edx,2860(%rdi)

# qhasm: temp1 = mem64[ap + 2876]
# asm 1: mov   2876(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2876(<ap=%rdi),>temp1=%esi
mov   2876(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3892]
# asm 1: mov   3892(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3892(<ap=%rdi),>temp2=%edx
mov   3892(%rdi),%edx

# qhasm: mem64[ap + 3892] = temp1
# asm 1: mov   <temp1=int64#2,3892(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3892(<ap=%rdi)
mov   %esi,3892(%rdi)

# qhasm: mem64[ap + 2876] = temp2
# asm 1: mov   <temp2=int64#3,2876(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2876(<ap=%rdi)
mov   %edx,2876(%rdi)

# qhasm: temp1 = mem64[ap + 2892]
# asm 1: mov   2892(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2892(<ap=%rdi),>temp1=%esi
mov   2892(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3252]
# asm 1: mov   3252(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3252(<ap=%rdi),>temp2=%edx
mov   3252(%rdi),%edx

# qhasm: mem64[ap + 3252] = temp1
# asm 1: mov   <temp1=int64#2,3252(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3252(<ap=%rdi)
mov   %esi,3252(%rdi)

# qhasm: mem64[ap + 2892] = temp2
# asm 1: mov   <temp2=int64#3,2892(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2892(<ap=%rdi)
mov   %edx,2892(%rdi)

# qhasm: temp1 = mem64[ap + 2908]
# asm 1: mov   2908(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2908(<ap=%rdi),>temp1=%esi
mov   2908(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3764]
# asm 1: mov   3764(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3764(<ap=%rdi),>temp2=%edx
mov   3764(%rdi),%edx

# qhasm: mem64[ap + 3764] = temp1
# asm 1: mov   <temp1=int64#2,3764(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3764(<ap=%rdi)
mov   %esi,3764(%rdi)

# qhasm: mem64[ap + 2908] = temp2
# asm 1: mov   <temp2=int64#3,2908(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2908(<ap=%rdi)
mov   %edx,2908(%rdi)

# qhasm: temp1 = mem64[ap + 2924]
# asm 1: mov   2924(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2924(<ap=%rdi),>temp1=%esi
mov   2924(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3508]
# asm 1: mov   3508(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3508(<ap=%rdi),>temp2=%edx
mov   3508(%rdi),%edx

# qhasm: mem64[ap + 3508] = temp1
# asm 1: mov   <temp1=int64#2,3508(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3508(<ap=%rdi)
mov   %esi,3508(%rdi)

# qhasm: mem64[ap + 2924] = temp2
# asm 1: mov   <temp2=int64#3,2924(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2924(<ap=%rdi)
mov   %edx,2924(%rdi)

# qhasm: temp1 = mem64[ap + 2932]
# asm 1: mov   2932(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2932(<ap=%rdi),>temp1=%esi
mov   2932(%rdi),%esi

# qhasm: temp2 = mem64[ap + 2996]
# asm 1: mov   2996(<ap=int64#1),>temp2=int64#3
# asm 2: mov   2996(<ap=%rdi),>temp2=%edx
mov   2996(%rdi),%edx

# qhasm: mem64[ap + 2996] = temp1
# asm 1: mov   <temp1=int64#2,2996(<ap=int64#1)
# asm 2: mov   <temp1=%esi,2996(<ap=%rdi)
mov   %esi,2996(%rdi)

# qhasm: mem64[ap + 2932] = temp2
# asm 1: mov   <temp2=int64#3,2932(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2932(<ap=%rdi)
mov   %edx,2932(%rdi)

# qhasm: temp1 = mem64[ap + 2940]
# asm 1: mov   2940(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2940(<ap=%rdi),>temp1=%esi
mov   2940(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4020]
# asm 1: mov   4020(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4020(<ap=%rdi),>temp2=%edx
mov   4020(%rdi),%edx

# qhasm: mem64[ap + 4020] = temp1
# asm 1: mov   <temp1=int64#2,4020(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4020(<ap=%rdi)
mov   %esi,4020(%rdi)

# qhasm: mem64[ap + 2940] = temp2
# asm 1: mov   <temp2=int64#3,2940(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2940(<ap=%rdi)
mov   %edx,2940(%rdi)

# qhasm: temp1 = mem64[ap + 2956]
# asm 1: mov   2956(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2956(<ap=%rdi),>temp1=%esi
mov   2956(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3188]
# asm 1: mov   3188(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3188(<ap=%rdi),>temp2=%edx
mov   3188(%rdi),%edx

# qhasm: mem64[ap + 3188] = temp1
# asm 1: mov   <temp1=int64#2,3188(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3188(<ap=%rdi)
mov   %esi,3188(%rdi)

# qhasm: mem64[ap + 2956] = temp2
# asm 1: mov   <temp2=int64#3,2956(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2956(<ap=%rdi)
mov   %edx,2956(%rdi)

# qhasm: temp1 = mem64[ap + 2972]
# asm 1: mov   2972(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2972(<ap=%rdi),>temp1=%esi
mov   2972(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3700]
# asm 1: mov   3700(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3700(<ap=%rdi),>temp2=%edx
mov   3700(%rdi),%edx

# qhasm: mem64[ap + 3700] = temp1
# asm 1: mov   <temp1=int64#2,3700(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3700(<ap=%rdi)
mov   %esi,3700(%rdi)

# qhasm: mem64[ap + 2972] = temp2
# asm 1: mov   <temp2=int64#3,2972(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2972(<ap=%rdi)
mov   %edx,2972(%rdi)

# qhasm: temp1 = mem64[ap + 2988]
# asm 1: mov   2988(<ap=int64#1),>temp1=int64#2
# asm 2: mov   2988(<ap=%rdi),>temp1=%esi
mov   2988(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3444]
# asm 1: mov   3444(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3444(<ap=%rdi),>temp2=%edx
mov   3444(%rdi),%edx

# qhasm: mem64[ap + 3444] = temp1
# asm 1: mov   <temp1=int64#2,3444(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3444(<ap=%rdi)
mov   %esi,3444(%rdi)

# qhasm: mem64[ap + 2988] = temp2
# asm 1: mov   <temp2=int64#3,2988(<ap=int64#1)
# asm 2: mov   <temp2=%edx,2988(<ap=%rdi)
mov   %edx,2988(%rdi)

# qhasm: temp1 = mem64[ap + 3004]
# asm 1: mov   3004(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3004(<ap=%rdi),>temp1=%esi
mov   3004(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3956]
# asm 1: mov   3956(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3956(<ap=%rdi),>temp2=%edx
mov   3956(%rdi),%edx

# qhasm: mem64[ap + 3956] = temp1
# asm 1: mov   <temp1=int64#2,3956(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3956(<ap=%rdi)
mov   %esi,3956(%rdi)

# qhasm: mem64[ap + 3004] = temp2
# asm 1: mov   <temp2=int64#3,3004(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3004(<ap=%rdi)
mov   %edx,3004(%rdi)

# qhasm: temp1 = mem64[ap + 3020]
# asm 1: mov   3020(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3020(<ap=%rdi),>temp1=%esi
mov   3020(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3316]
# asm 1: mov   3316(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3316(<ap=%rdi),>temp2=%edx
mov   3316(%rdi),%edx

# qhasm: mem64[ap + 3316] = temp1
# asm 1: mov   <temp1=int64#2,3316(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3316(<ap=%rdi)
mov   %esi,3316(%rdi)

# qhasm: mem64[ap + 3020] = temp2
# asm 1: mov   <temp2=int64#3,3020(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3020(<ap=%rdi)
mov   %edx,3020(%rdi)

# qhasm: temp1 = mem64[ap + 3036]
# asm 1: mov   3036(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3036(<ap=%rdi),>temp1=%esi
mov   3036(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3828]
# asm 1: mov   3828(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3828(<ap=%rdi),>temp2=%edx
mov   3828(%rdi),%edx

# qhasm: mem64[ap + 3828] = temp1
# asm 1: mov   <temp1=int64#2,3828(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3828(<ap=%rdi)
mov   %esi,3828(%rdi)

# qhasm: mem64[ap + 3036] = temp2
# asm 1: mov   <temp2=int64#3,3036(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3036(<ap=%rdi)
mov   %edx,3036(%rdi)

# qhasm: temp1 = mem64[ap + 3052]
# asm 1: mov   3052(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3052(<ap=%rdi),>temp1=%esi
mov   3052(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3572]
# asm 1: mov   3572(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3572(<ap=%rdi),>temp2=%edx
mov   3572(%rdi),%edx

# qhasm: mem64[ap + 3572] = temp1
# asm 1: mov   <temp1=int64#2,3572(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3572(<ap=%rdi)
mov   %esi,3572(%rdi)

# qhasm: mem64[ap + 3052] = temp2
# asm 1: mov   <temp2=int64#3,3052(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3052(<ap=%rdi)
mov   %edx,3052(%rdi)

# qhasm: temp1 = mem64[ap + 3068]
# asm 1: mov   3068(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3068(<ap=%rdi),>temp1=%esi
mov   3068(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4084]
# asm 1: mov   4084(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4084(<ap=%rdi),>temp2=%edx
mov   4084(%rdi),%edx

# qhasm: mem64[ap + 4084] = temp1
# asm 1: mov   <temp1=int64#2,4084(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4084(<ap=%rdi)
mov   %esi,4084(%rdi)

# qhasm: mem64[ap + 3068] = temp2
# asm 1: mov   <temp2=int64#3,3068(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3068(<ap=%rdi)
mov   %edx,3068(%rdi)

# qhasm: temp1 = mem64[ap + 3100]
# asm 1: mov   3100(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3100(<ap=%rdi),>temp1=%esi
mov   3100(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3596]
# asm 1: mov   3596(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3596(<ap=%rdi),>temp2=%edx
mov   3596(%rdi),%edx

# qhasm: mem64[ap + 3596] = temp1
# asm 1: mov   <temp1=int64#2,3596(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3596(<ap=%rdi)
mov   %esi,3596(%rdi)

# qhasm: mem64[ap + 3100] = temp2
# asm 1: mov   <temp2=int64#3,3100(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3100(<ap=%rdi)
mov   %edx,3100(%rdi)

# qhasm: temp1 = mem64[ap + 3116]
# asm 1: mov   3116(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3116(<ap=%rdi),>temp1=%esi
mov   3116(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3340]
# asm 1: mov   3340(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3340(<ap=%rdi),>temp2=%edx
mov   3340(%rdi),%edx

# qhasm: mem64[ap + 3340] = temp1
# asm 1: mov   <temp1=int64#2,3340(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3340(<ap=%rdi)
mov   %esi,3340(%rdi)

# qhasm: mem64[ap + 3116] = temp2
# asm 1: mov   <temp2=int64#3,3116(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3116(<ap=%rdi)
mov   %edx,3116(%rdi)

# qhasm: temp1 = mem64[ap + 3132]
# asm 1: mov   3132(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3132(<ap=%rdi),>temp1=%esi
mov   3132(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3852]
# asm 1: mov   3852(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3852(<ap=%rdi),>temp2=%edx
mov   3852(%rdi),%edx

# qhasm: mem64[ap + 3852] = temp1
# asm 1: mov   <temp1=int64#2,3852(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3852(<ap=%rdi)
mov   %esi,3852(%rdi)

# qhasm: mem64[ap + 3132] = temp2
# asm 1: mov   <temp2=int64#3,3132(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3132(<ap=%rdi)
mov   %edx,3132(%rdi)

# qhasm: temp1 = mem64[ap + 3148]
# asm 1: mov   3148(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3148(<ap=%rdi),>temp1=%esi
mov   3148(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3212]
# asm 1: mov   3212(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3212(<ap=%rdi),>temp2=%edx
mov   3212(%rdi),%edx

# qhasm: mem64[ap + 3212] = temp1
# asm 1: mov   <temp1=int64#2,3212(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3212(<ap=%rdi)
mov   %esi,3212(%rdi)

# qhasm: mem64[ap + 3148] = temp2
# asm 1: mov   <temp2=int64#3,3148(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3148(<ap=%rdi)
mov   %edx,3148(%rdi)

# qhasm: temp1 = mem64[ap + 3164]
# asm 1: mov   3164(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3164(<ap=%rdi),>temp1=%esi
mov   3164(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3724]
# asm 1: mov   3724(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3724(<ap=%rdi),>temp2=%edx
mov   3724(%rdi),%edx

# qhasm: mem64[ap + 3724] = temp1
# asm 1: mov   <temp1=int64#2,3724(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3724(<ap=%rdi)
mov   %esi,3724(%rdi)

# qhasm: mem64[ap + 3164] = temp2
# asm 1: mov   <temp2=int64#3,3164(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3164(<ap=%rdi)
mov   %edx,3164(%rdi)

# qhasm: temp1 = mem64[ap + 3180]
# asm 1: mov   3180(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3180(<ap=%rdi),>temp1=%esi
mov   3180(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3468]
# asm 1: mov   3468(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3468(<ap=%rdi),>temp2=%edx
mov   3468(%rdi),%edx

# qhasm: mem64[ap + 3468] = temp1
# asm 1: mov   <temp1=int64#2,3468(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3468(<ap=%rdi)
mov   %esi,3468(%rdi)

# qhasm: mem64[ap + 3180] = temp2
# asm 1: mov   <temp2=int64#3,3180(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3180(<ap=%rdi)
mov   %edx,3180(%rdi)

# qhasm: temp1 = mem64[ap + 3196]
# asm 1: mov   3196(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3196(<ap=%rdi),>temp1=%esi
mov   3196(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3980]
# asm 1: mov   3980(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3980(<ap=%rdi),>temp2=%edx
mov   3980(%rdi),%edx

# qhasm: mem64[ap + 3980] = temp1
# asm 1: mov   <temp1=int64#2,3980(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3980(<ap=%rdi)
mov   %esi,3980(%rdi)

# qhasm: mem64[ap + 3196] = temp2
# asm 1: mov   <temp2=int64#3,3196(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3196(<ap=%rdi)
mov   %edx,3196(%rdi)

# qhasm: temp1 = mem64[ap + 3228]
# asm 1: mov   3228(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3228(<ap=%rdi),>temp1=%esi
mov   3228(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3660]
# asm 1: mov   3660(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3660(<ap=%rdi),>temp2=%edx
mov   3660(%rdi),%edx

# qhasm: mem64[ap + 3660] = temp1
# asm 1: mov   <temp1=int64#2,3660(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3660(<ap=%rdi)
mov   %esi,3660(%rdi)

# qhasm: mem64[ap + 3228] = temp2
# asm 1: mov   <temp2=int64#3,3228(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3228(<ap=%rdi)
mov   %edx,3228(%rdi)

# qhasm: temp1 = mem64[ap + 3244]
# asm 1: mov   3244(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3244(<ap=%rdi),>temp1=%esi
mov   3244(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3404]
# asm 1: mov   3404(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3404(<ap=%rdi),>temp2=%edx
mov   3404(%rdi),%edx

# qhasm: mem64[ap + 3404] = temp1
# asm 1: mov   <temp1=int64#2,3404(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3404(<ap=%rdi)
mov   %esi,3404(%rdi)

# qhasm: mem64[ap + 3244] = temp2
# asm 1: mov   <temp2=int64#3,3244(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3244(<ap=%rdi)
mov   %edx,3244(%rdi)

# qhasm: temp1 = mem64[ap + 3260]
# asm 1: mov   3260(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3260(<ap=%rdi),>temp1=%esi
mov   3260(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3916]
# asm 1: mov   3916(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3916(<ap=%rdi),>temp2=%edx
mov   3916(%rdi),%edx

# qhasm: mem64[ap + 3916] = temp1
# asm 1: mov   <temp1=int64#2,3916(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3916(<ap=%rdi)
mov   %esi,3916(%rdi)

# qhasm: mem64[ap + 3260] = temp2
# asm 1: mov   <temp2=int64#3,3260(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3260(<ap=%rdi)
mov   %edx,3260(%rdi)

# qhasm: temp1 = mem64[ap + 3292]
# asm 1: mov   3292(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3292(<ap=%rdi),>temp1=%esi
mov   3292(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3788]
# asm 1: mov   3788(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3788(<ap=%rdi),>temp2=%edx
mov   3788(%rdi),%edx

# qhasm: mem64[ap + 3788] = temp1
# asm 1: mov   <temp1=int64#2,3788(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3788(<ap=%rdi)
mov   %esi,3788(%rdi)

# qhasm: mem64[ap + 3292] = temp2
# asm 1: mov   <temp2=int64#3,3292(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3292(<ap=%rdi)
mov   %edx,3292(%rdi)

# qhasm: temp1 = mem64[ap + 3308]
# asm 1: mov   3308(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3308(<ap=%rdi),>temp1=%esi
mov   3308(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3532]
# asm 1: mov   3532(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3532(<ap=%rdi),>temp2=%edx
mov   3532(%rdi),%edx

# qhasm: mem64[ap + 3532] = temp1
# asm 1: mov   <temp1=int64#2,3532(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3532(<ap=%rdi)
mov   %esi,3532(%rdi)

# qhasm: mem64[ap + 3308] = temp2
# asm 1: mov   <temp2=int64#3,3308(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3308(<ap=%rdi)
mov   %edx,3308(%rdi)

# qhasm: temp1 = mem64[ap + 3324]
# asm 1: mov   3324(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3324(<ap=%rdi),>temp1=%esi
mov   3324(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4044]
# asm 1: mov   4044(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4044(<ap=%rdi),>temp2=%edx
mov   4044(%rdi),%edx

# qhasm: mem64[ap + 4044] = temp1
# asm 1: mov   <temp1=int64#2,4044(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4044(<ap=%rdi)
mov   %esi,4044(%rdi)

# qhasm: mem64[ap + 3324] = temp2
# asm 1: mov   <temp2=int64#3,3324(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3324(<ap=%rdi)
mov   %edx,3324(%rdi)

# qhasm: temp1 = mem64[ap + 3356]
# asm 1: mov   3356(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3356(<ap=%rdi),>temp1=%esi
mov   3356(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3628]
# asm 1: mov   3628(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3628(<ap=%rdi),>temp2=%edx
mov   3628(%rdi),%edx

# qhasm: mem64[ap + 3628] = temp1
# asm 1: mov   <temp1=int64#2,3628(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3628(<ap=%rdi)
mov   %esi,3628(%rdi)

# qhasm: mem64[ap + 3356] = temp2
# asm 1: mov   <temp2=int64#3,3356(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3356(<ap=%rdi)
mov   %edx,3356(%rdi)

# qhasm: temp1 = mem64[ap + 3388]
# asm 1: mov   3388(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3388(<ap=%rdi),>temp1=%esi
mov   3388(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3884]
# asm 1: mov   3884(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3884(<ap=%rdi),>temp2=%edx
mov   3884(%rdi),%edx

# qhasm: mem64[ap + 3884] = temp1
# asm 1: mov   <temp1=int64#2,3884(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3884(<ap=%rdi)
mov   %esi,3884(%rdi)

# qhasm: mem64[ap + 3388] = temp2
# asm 1: mov   <temp2=int64#3,3388(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3388(<ap=%rdi)
mov   %edx,3388(%rdi)

# qhasm: temp1 = mem64[ap + 3420]
# asm 1: mov   3420(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3420(<ap=%rdi),>temp1=%esi
mov   3420(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3756]
# asm 1: mov   3756(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3756(<ap=%rdi),>temp2=%edx
mov   3756(%rdi),%edx

# qhasm: mem64[ap + 3756] = temp1
# asm 1: mov   <temp1=int64#2,3756(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3756(<ap=%rdi)
mov   %esi,3756(%rdi)

# qhasm: mem64[ap + 3420] = temp2
# asm 1: mov   <temp2=int64#3,3420(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3420(<ap=%rdi)
mov   %edx,3420(%rdi)

# qhasm: temp1 = mem64[ap + 3436]
# asm 1: mov   3436(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3436(<ap=%rdi),>temp1=%esi
mov   3436(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3500]
# asm 1: mov   3500(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3500(<ap=%rdi),>temp2=%edx
mov   3500(%rdi),%edx

# qhasm: mem64[ap + 3500] = temp1
# asm 1: mov   <temp1=int64#2,3500(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3500(<ap=%rdi)
mov   %esi,3500(%rdi)

# qhasm: mem64[ap + 3436] = temp2
# asm 1: mov   <temp2=int64#3,3436(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3436(<ap=%rdi)
mov   %edx,3436(%rdi)

# qhasm: temp1 = mem64[ap + 3452]
# asm 1: mov   3452(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3452(<ap=%rdi),>temp1=%esi
mov   3452(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4012]
# asm 1: mov   4012(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4012(<ap=%rdi),>temp2=%edx
mov   4012(%rdi),%edx

# qhasm: mem64[ap + 4012] = temp1
# asm 1: mov   <temp1=int64#2,4012(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4012(<ap=%rdi)
mov   %esi,4012(%rdi)

# qhasm: mem64[ap + 3452] = temp2
# asm 1: mov   <temp2=int64#3,3452(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3452(<ap=%rdi)
mov   %edx,3452(%rdi)

# qhasm: temp1 = mem64[ap + 3484]
# asm 1: mov   3484(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3484(<ap=%rdi),>temp1=%esi
mov   3484(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3692]
# asm 1: mov   3692(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3692(<ap=%rdi),>temp2=%edx
mov   3692(%rdi),%edx

# qhasm: mem64[ap + 3692] = temp1
# asm 1: mov   <temp1=int64#2,3692(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3692(<ap=%rdi)
mov   %esi,3692(%rdi)

# qhasm: mem64[ap + 3484] = temp2
# asm 1: mov   <temp2=int64#3,3484(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3484(<ap=%rdi)
mov   %edx,3484(%rdi)

# qhasm: temp1 = mem64[ap + 3516]
# asm 1: mov   3516(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3516(<ap=%rdi),>temp1=%esi
mov   3516(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3948]
# asm 1: mov   3948(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3948(<ap=%rdi),>temp2=%edx
mov   3948(%rdi),%edx

# qhasm: mem64[ap + 3948] = temp1
# asm 1: mov   <temp1=int64#2,3948(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3948(<ap=%rdi)
mov   %esi,3948(%rdi)

# qhasm: mem64[ap + 3516] = temp2
# asm 1: mov   <temp2=int64#3,3516(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3516(<ap=%rdi)
mov   %edx,3516(%rdi)

# qhasm: temp1 = mem64[ap + 3548]
# asm 1: mov   3548(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3548(<ap=%rdi),>temp1=%esi
mov   3548(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3820]
# asm 1: mov   3820(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3820(<ap=%rdi),>temp2=%edx
mov   3820(%rdi),%edx

# qhasm: mem64[ap + 3820] = temp1
# asm 1: mov   <temp1=int64#2,3820(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3820(<ap=%rdi)
mov   %esi,3820(%rdi)

# qhasm: mem64[ap + 3548] = temp2
# asm 1: mov   <temp2=int64#3,3548(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3548(<ap=%rdi)
mov   %edx,3548(%rdi)

# qhasm: temp1 = mem64[ap + 3580]
# asm 1: mov   3580(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3580(<ap=%rdi),>temp1=%esi
mov   3580(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4076]
# asm 1: mov   4076(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4076(<ap=%rdi),>temp2=%edx
mov   4076(%rdi),%edx

# qhasm: mem64[ap + 4076] = temp1
# asm 1: mov   <temp1=int64#2,4076(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4076(<ap=%rdi)
mov   %esi,4076(%rdi)

# qhasm: mem64[ap + 3580] = temp2
# asm 1: mov   <temp2=int64#3,3580(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3580(<ap=%rdi)
mov   %edx,3580(%rdi)

# qhasm: temp1 = mem64[ap + 3644]
# asm 1: mov   3644(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3644(<ap=%rdi),>temp1=%esi
mov   3644(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3868]
# asm 1: mov   3868(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3868(<ap=%rdi),>temp2=%edx
mov   3868(%rdi),%edx

# qhasm: mem64[ap + 3868] = temp1
# asm 1: mov   <temp1=int64#2,3868(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3868(<ap=%rdi)
mov   %esi,3868(%rdi)

# qhasm: mem64[ap + 3644] = temp2
# asm 1: mov   <temp2=int64#3,3644(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3644(<ap=%rdi)
mov   %edx,3644(%rdi)

# qhasm: temp1 = mem64[ap + 3676]
# asm 1: mov   3676(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3676(<ap=%rdi),>temp1=%esi
mov   3676(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3740]
# asm 1: mov   3740(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3740(<ap=%rdi),>temp2=%edx
mov   3740(%rdi),%edx

# qhasm: mem64[ap + 3740] = temp1
# asm 1: mov   <temp1=int64#2,3740(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3740(<ap=%rdi)
mov   %esi,3740(%rdi)

# qhasm: mem64[ap + 3676] = temp2
# asm 1: mov   <temp2=int64#3,3676(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3676(<ap=%rdi)
mov   %edx,3676(%rdi)

# qhasm: temp1 = mem64[ap + 3708]
# asm 1: mov   3708(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3708(<ap=%rdi),>temp1=%esi
mov   3708(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3996]
# asm 1: mov   3996(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3996(<ap=%rdi),>temp2=%edx
mov   3996(%rdi),%edx

# qhasm: mem64[ap + 3996] = temp1
# asm 1: mov   <temp1=int64#2,3996(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3996(<ap=%rdi)
mov   %esi,3996(%rdi)

# qhasm: mem64[ap + 3708] = temp2
# asm 1: mov   <temp2=int64#3,3708(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3708(<ap=%rdi)
mov   %edx,3708(%rdi)

# qhasm: temp1 = mem64[ap + 3772]
# asm 1: mov   3772(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3772(<ap=%rdi),>temp1=%esi
mov   3772(%rdi),%esi

# qhasm: temp2 = mem64[ap + 3932]
# asm 1: mov   3932(<ap=int64#1),>temp2=int64#3
# asm 2: mov   3932(<ap=%rdi),>temp2=%edx
mov   3932(%rdi),%edx

# qhasm: mem64[ap + 3932] = temp1
# asm 1: mov   <temp1=int64#2,3932(<ap=int64#1)
# asm 2: mov   <temp1=%esi,3932(<ap=%rdi)
mov   %esi,3932(%rdi)

# qhasm: mem64[ap + 3772] = temp2
# asm 1: mov   <temp2=int64#3,3772(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3772(<ap=%rdi)
mov   %edx,3772(%rdi)

# qhasm: temp1 = mem64[ap + 3836]
# asm 1: mov   3836(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3836(<ap=%rdi),>temp1=%esi
mov   3836(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4060]
# asm 1: mov   4060(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4060(<ap=%rdi),>temp2=%edx
mov   4060(%rdi),%edx

# qhasm: mem64[ap + 4060] = temp1
# asm 1: mov   <temp1=int64#2,4060(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4060(<ap=%rdi)
mov   %esi,4060(%rdi)

# qhasm: mem64[ap + 3836] = temp2
# asm 1: mov   <temp2=int64#3,3836(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3836(<ap=%rdi)
mov   %edx,3836(%rdi)

# qhasm: temp1 = mem64[ap + 3964]
# asm 1: mov   3964(<ap=int64#1),>temp1=int64#2
# asm 2: mov   3964(<ap=%rdi),>temp1=%esi
mov   3964(%rdi),%esi

# qhasm: temp2 = mem64[ap + 4028]
# asm 1: mov   4028(<ap=int64#1),>temp2=int64#3
# asm 2: mov   4028(<ap=%rdi),>temp2=%edx
mov   4028(%rdi),%edx

# qhasm: mem64[ap + 4028] = temp1
# asm 1: mov   <temp1=int64#2,4028(<ap=int64#1)
# asm 2: mov   <temp1=%esi,4028(<ap=%rdi)
mov   %esi,4028(%rdi)

# qhasm: mem64[ap + 3964] = temp2
# asm 1: mov   <temp2=int64#3,3964(<ap=int64#1)
# asm 2: mov   <temp2=%edx,3964(<ap=%rdi)
mov   %edx,3964(%rdi)

# qhasm: return
add %r11,%rsp
ret
