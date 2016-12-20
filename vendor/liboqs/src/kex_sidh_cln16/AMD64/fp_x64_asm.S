//*******************************************************************************************
// SIDH: an efficient supersingular isogeny-based cryptography library for Diffie-Hellman key 
//       exchange providing 128 bits of quantum security and 192 bits of classical security.
//
//    Copyright (c) Microsoft Corporation. All rights reserved.
//
//
// Abstract: field arithmetic in x64 assembly for Linux 
//
//*******************************************************************************************  

.intel_syntax noprefix 

// Registers that are used for parameter passing:
#define reg_p1  rdi
#define reg_p2  rsi
#define reg_p3  rdx

// p751 + 1
#define p751p1_5   0xEEB0000000000000
#define p751p1_6   0xE3EC968549F878A8
#define p751p1_7   0xDA959B1A13F7CC76
#define p751p1_8   0x084E9867D6EBE876
#define p751p1_9   0x8562B5045CB25748
#define p751p1_10  0x0E12909F97BADC66
#define p751p1_11  0x00006FE5D541F71C

#define p751_0     0xFFFFFFFFFFFFFFFF
#define p751_5     0xEEAFFFFFFFFFFFFF
#define p751_6     0xE3EC968549F878A8
#define p751_7     0xDA959B1A13F7CC76
#define p751_8     0x084E9867D6EBE876
#define p751_9     0x8562B5045CB25748
#define p751_10    0x0E12909F97BADC66
#define p751_11    0x00006FE5D541F71C

#define p751x2_0   0xFFFFFFFFFFFFFFFE
#define p751x2_1   0xFFFFFFFFFFFFFFFF
#define p751x2_5   0xDD5FFFFFFFFFFFFF
#define p751x2_6   0xC7D92D0A93F0F151
#define p751x2_7   0xB52B363427EF98ED
#define p751x2_8   0x109D30CFADD7D0ED
#define p751x2_9   0x0AC56A08B964AE90
#define p751x2_10  0x1C25213F2F75B8CD
#define p751x2_11  0x0000DFCBAA83EE38


.text
//***********************************************************************
//  Field addition
//  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
//*********************************************************************** 
.global oqs_sidh_cln16_fpadd751_asm
oqs_sidh_cln16_fpadd751_asm:
  push   r12
  push   r13
  push   r14
  push   r15
  
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rcx, [reg_p1+64]
  add    r8, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 
  adc    r12, [reg_p2+32] 
  adc    r13, [reg_p2+40] 
  adc    r14, [reg_p2+48] 
  adc    r15, [reg_p2+56]
  adc    rcx, [reg_p2+64] 
  mov    rax, [reg_p1+72]
  adc    rax, [reg_p2+72] 
  mov    [reg_p3+72], rax
  mov    rax, [reg_p1+80]
  adc    rax, [reg_p2+80] 
  mov    [reg_p3+80], rax
  mov    rax, [reg_p1+88]
  adc    rax, [reg_p2+88] 
  mov    [reg_p3+88], rax

  movq   rax, p751x2_0
  sub    r8, rax
  movq   rax, p751x2_1
  sbb    r9, rax
  sbb    r10, rax
  sbb    r11, rax
  sbb    r12, rax
  movq   rax, p751x2_5
  sbb    r13, rax
  movq   rax, p751x2_6
  sbb    r14, rax
  movq   rax, p751x2_7
  sbb    r15, rax
  movq   rax, p751x2_8
  sbb    rcx, rax
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rcx
  mov    r8, [reg_p3+72]
  mov    r9, [reg_p3+80]
  mov    r10, [reg_p3+88]
  movq   rax, p751x2_9
  sbb    r8, rax
  movq   rax, p751x2_10
  sbb    r9, rax
  movq   rax, p751x2_11
  sbb    r10, rax
  mov    [reg_p3+72], r8
  mov    [reg_p3+80], r9
  mov    [reg_p3+88], r10
  movq   rax, 0
  sbb    rax, 0
  
  mov    rsi, p751x2_0
  and    rsi, rax
  mov    r8, p751x2_1
  and    r8, rax
  movq   r9, p751x2_5
  and    r9, rax
  movq   r10, p751x2_6
  and    r10, rax
  movq   r11, p751x2_7
  and    r11, rax
  movq   r12, p751x2_8
  and    r12, rax
  movq   r13, p751x2_9
  and    r13, rax
  movq   r14, p751x2_10
  and    r14, rax
  movq   r15, p751x2_11
  and    r15, rax
  
  mov    rax, [reg_p3]
  add    rax, rsi  
  mov    [reg_p3], rax
  mov    rax, [reg_p3+8]
  adc    rax, r8 
  mov    [reg_p3+8], rax  
  mov    rax, [reg_p3+16]
  adc    rax, r8 
  mov    [reg_p3+16], rax  
  mov    rax, [reg_p3+24]  
  adc    rax, r8 
  mov    [reg_p3+24], rax 
  mov    rax, [reg_p3+32]  
  adc    rax, r8 
  mov    [reg_p3+32], rax 
  mov    rax, [reg_p3+40]    
  adc    rax, r9 
  mov    [reg_p3+40], rax 
  mov    rax, [reg_p3+48]   
  adc    rax, r10 
  mov    [reg_p3+48], rax 
  mov    rax, [reg_p3+56]   
  adc    rax, r11  
  mov    [reg_p3+56], rax 
  mov    rax, [reg_p3+64]  
  adc    rax, r12 
  mov    [reg_p3+64], rax 
  mov    rax, [reg_p3+72]   
  adc    rax, r13 
  mov    [reg_p3+72], rax 
  mov    rax, [reg_p3+80]   
  adc    rax, r14 
  mov    [reg_p3+80], rax 
  mov    rax, [reg_p3+88]   
  adc    rax, r15
  mov    [reg_p3+88], rax 
  
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret


//***********************************************************************
//  Field subtraction
//  Operation: c [reg_p3] = a [reg_p1] - b [reg_p2]
//*********************************************************************** 
.global oqs_sidh_cln16_fpsub751_asm
oqs_sidh_cln16_fpsub751_asm:
  push   r12
  push   r13
  push   r14
  push   r15
  
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rcx, [reg_p1+64]
  sub    r8, [reg_p2] 
  sbb    r9, [reg_p2+8] 
  sbb    r10, [reg_p2+16] 
  sbb    r11, [reg_p2+24] 
  sbb    r12, [reg_p2+32] 
  sbb    r13, [reg_p2+40] 
  sbb    r14, [reg_p2+48] 
  sbb    r15, [reg_p2+56]
  sbb    rcx, [reg_p2+64] 
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rcx
  mov    rax, [reg_p1+72]
  sbb    rax, [reg_p2+72] 
  mov    [reg_p3+72], rax
  mov    rax, [reg_p1+80]
  sbb    rax, [reg_p2+80] 
  mov    [reg_p3+80], rax
  mov    rax, [reg_p1+88]
  sbb    rax, [reg_p2+88] 
  mov    [reg_p3+88], rax
  movq   rax, 0
  sbb    rax, 0
  
  mov    rsi, p751x2_0
  and    rsi, rax
  mov    r8, p751x2_1
  and    r8, rax
  movq   r9, p751x2_5
  and    r9, rax
  movq   r10, p751x2_6
  and    r10, rax
  movq   r11, p751x2_7
  and    r11, rax
  movq   r12, p751x2_8
  and    r12, rax
  movq   r13, p751x2_9
  and    r13, rax
  movq   r14, p751x2_10
  and    r14, rax
  movq   r15, p751x2_11
  and    r15, rax
  
  mov    rax, [reg_p3]
  add    rax, rsi  
  mov    [reg_p3], rax
  mov    rax, [reg_p3+8]
  adc    rax, r8 
  mov    [reg_p3+8], rax  
  mov    rax, [reg_p3+16]
  adc    rax, r8 
  mov    [reg_p3+16], rax  
  mov    rax, [reg_p3+24]  
  adc    rax, r8 
  mov    [reg_p3+24], rax 
  mov    rax, [reg_p3+32]  
  adc    rax, r8 
  mov    [reg_p3+32], rax 
  mov    rax, [reg_p3+40]    
  adc    rax, r9 
  mov    [reg_p3+40], rax 
  mov    rax, [reg_p3+48]   
  adc    rax, r10 
  mov    [reg_p3+48], rax 
  mov    rax, [reg_p3+56]   
  adc    rax, r11  
  mov    [reg_p3+56], rax 
  mov    rax, [reg_p3+64]  
  adc    rax, r12 
  mov    [reg_p3+64], rax 
  mov    rax, [reg_p3+72]   
  adc    rax, r13 
  mov    [reg_p3+72], rax 
  mov    rax, [reg_p3+80]   
  adc    rax, r14 
  mov    [reg_p3+80], rax 
  mov    rax, [reg_p3+88]   
  adc    rax, r15
  mov    [reg_p3+88], rax 
  
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret


//***********************************************************************
//  Integer multiplication
//  Based on Karatsuba method
//  Operation: c [reg_p3] = a [reg_p1] * b [reg_p2]
//  NOTE: a=c or b=c are not allowed
//***********************************************************************
.global oqs_sidh_cln16_mul751_asm
oqs_sidh_cln16_mul751_asm:
  push   r12
  push   r13
  push   r14
  mov    rcx, reg_p3
  
  // rcx[0-5] <- AH+AL
  xor    rax, rax
  mov    r8, [reg_p1+48]
  mov    r9, [reg_p1+56]
  mov    r10, [reg_p1+64]
  mov    r11, [reg_p1+72]
  mov    r12, [reg_p1+80]
  mov    r13, [reg_p1+88]
  add    r8, [reg_p1] 
  adc    r9, [reg_p1+8] 
  adc    r10, [reg_p1+16] 
  adc    r11, [reg_p1+24] 
  adc    r12, [reg_p1+32] 
  adc    r13, [reg_p1+40] 
  push   r15  
  mov    [rcx], r8
  mov    [rcx+8], r9
  mov    [rcx+16], r10
  mov    [rcx+24], r11
  mov    [rcx+32], r12
  mov    [rcx+40], r13
  sbb    rax, 0 
  sub    rsp, 96           // Allocating space in stack
       
  // rcx[6-11] <- BH+BL
  xor    rdx, rdx
  mov    r8, [reg_p2+48]
  mov    r9, [reg_p2+56]
  mov    r10, [reg_p2+64]
  mov    r11, [reg_p2+72]
  mov    r12, [reg_p2+80]
  mov    r13, [reg_p2+88]
  add    r8, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 
  adc    r12, [reg_p2+32] 
  adc    r13, [reg_p2+40] 
  mov    [rcx+48], r8
  mov    [rcx+56], r9
  mov    [rcx+64], r10
  mov    [rcx+72], r11
  mov    [rcx+80], r12
  mov    [rcx+88], r13
  sbb    rdx, 0 
  mov    [rsp+80], rax
  mov    [rsp+88], rdx
  
  // (rsp[0-8],r10,r8,r9) <- (AH+AL)*(BH+BL)
  mov    r11, [rcx]
  mov    rax, r8 
  mul    r11
  mov    [rsp], rax        // c0
  mov    r14, rdx
  
  xor    r15, r15
  mov    rax, r9
  mul    r11
  xor    r9, r9
  add    r14, rax
  adc    r9, rdx
  
  mov    r12, [rcx+8] 
  mov    rax, r8 
  mul    r12
  add    r14, rax
  mov    [rsp+8], r14      // c1 
  adc    r9, rdx
  adc    r15, 0
  
  xor    r8, r8
  mov    rax, r10 
  mul    r11
  add    r9, rax
  mov    r13, [rcx+48] 
  adc    r15, rdx 
  adc    r8, 0
  
  mov    rax, [rcx+16] 
  mul    r13
  add    r9, rax
  adc    r15, rdx 
  mov    rax, [rcx+56] 
  adc    r8, 0
  
  mul    r12
  add    r9, rax
  mov    [rsp+16], r9      // c2 
  adc    r15, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [rcx+72] 
  mul    r11
  add    r15, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rcx+24] 
  mul    r13
  add    r15, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, r10 
  mul    r12
  add    r15, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r14, [rcx+16] 
  mov    rax, [rcx+56] 
  mul    r14
  add    r15, rax
  mov    [rsp+24], r15     // c3 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [rcx+80] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rcx+64] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r15, [rcx+48] 
  mov    rax, [rcx+32] 
  mul    r15
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rcx+72] 
  mul    r12
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [rcx+24] 
  mov    rax, [rcx+56] 
  mul    r13
  add    r8, rax
  mov    [rsp+32], r8      // c4 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [rcx+88] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rcx+64] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rcx+72] 
  mul    r14
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rcx+40] 
  mul    r15
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rcx+80] 
  mul    r12
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r15, [rcx+32] 
  mov    rax, [rcx+56] 
  mul    r15
  add    r9, rax
  mov    [rsp+40], r9      // c5 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [rcx+64] 
  mul    r15
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rcx+88] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rcx+80] 
  mul    r14
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r11, [rcx+40] 
  mov    rax, [rcx+56] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [rcx+72] 
  mul    r13
  add    r10, rax
  mov    [rsp+48], r10     // c6 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [rcx+88] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rcx+64] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rcx+80]
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [rcx+72] 
  mul    r15
  add    r8, rax
  mov    [rsp+56], r8      // c7 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [rcx+72] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rcx+80] 
  mul    r15
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [rcx+88] 
  mul    r13
  add    r9, rax
  mov    [rsp+64], r9      // c8 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [rcx+88]
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0

  mov    rax, [rcx+80] 
  mul    r11
  add    r10, rax          // c9 
  adc    r8, rdx
  adc    r9, 0

  mov    rax, [rcx+88] 
  mul    r11
  add    r8, rax           // c10 
  adc    r9, rdx           // c11 
  
  mov    rax, [rsp+88]
  mov    rdx, [rcx]
  and    r12, rax
  and    r14, rax
  and    rdx, rax
  and    r13, rax
  and    r15, rax
  and    r11, rax
  mov    rax, [rsp+48]
  add    rdx, rax
  mov    rax, [rsp+56]
  adc    r12, rax
  mov    rax, [rsp+64]
  adc    r14, rax
  adc    r13, r10
  adc    r15, r8
  adc    r11, r9
  mov    rax, [rsp+80]
  mov    [rsp+48], rdx
  mov    [rsp+56], r12
  mov    [rsp+64], r14
  mov    [rsp+72], r13
  mov    [rsp+80], r15
  mov    [rsp+88], r11
  
  mov    r8, [rcx+48]
  mov    r9, [rcx+56]
  mov    r10, [rcx+64]
  mov    r11, [rcx+72]
  mov    r12, [rcx+80]
  mov    r13, [rcx+88]
  and    r8, rax
  and    r9, rax
  and    r10, rax
  and    r11, rax
  and    r12, rax
  and    r13, rax
  mov    rax, [rsp+48]
  add    r8, rax
  mov    rax, [rsp+56]
  adc    r9, rax
  mov    rax, [rsp+64]
  adc    r10, rax
  mov    rax, [rsp+72]
  adc    r11, rax
  mov    rax, [rsp+80]
  adc    r12, rax
  mov    rax, [rsp+88]
  adc    r13, rax
  mov    [rsp+48], r8
  mov    [rsp+56], r9
  mov    [rsp+72], r11
  
  // rcx[0-11] <- AL*BL
  mov    r11, [reg_p1]
  mov    rax, [reg_p2] 
  mul    r11
  xor    r9, r9
  mov    [rcx], rax        // c0
  mov    [rsp+64], r10
  mov    r8, rdx

  mov    rax, [reg_p2+8]
  mul    r11
  xor    r10, r10
  add    r8, rax
  mov    [rsp+80], r12
  adc    r9, rdx

  mov    r12, [reg_p1+8] 
  mov    rax, [reg_p2] 
  mul    r12
  add    r8, rax
  mov    [rcx+8], r8       // c1 
  adc    r9, rdx
  mov    [rsp+88], r13
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+16] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p2] 
  mov    rax, [reg_p1+16] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+8] 
  mul    r12
  add    r9, rax
  mov    [rcx+16], r9      // c2 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [reg_p2+24] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p1+24] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+16] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r14, [reg_p1+16] 
  mov    rax, [reg_p2+8] 
  mul    r14
  add    r10, rax
  mov    [rcx+24], r10     // c3 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [reg_p2+32] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+16] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p1+32] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+24] 
  mul    r12
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+24] 
  mov    rax, [reg_p2+8] 
  mul    r13
  add    r8, rax
  mov    [rcx+32], r8      // c4 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+40] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+16] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+24] 
  mul    r14
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r11, [reg_p1+40] 
  mov    rax, [reg_p2] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+32] 
  mul    r12
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r15, [reg_p1+32] 
  mov    rax, [reg_p2+8] 
  mul    r15
  add    r9, rax
  mov    [rcx+40], r9      // c5 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [reg_p2+16] 
  mul    r15
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+40] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+32] 
  mul    r14
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+8] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+24] 
  mul    r13
  add    r10, rax
  mov    [rcx+48], r10     // c6 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [reg_p2+40] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+16] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+32]
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+24] 
  mul    r15
  add    r8, rax
  mov    [rcx+56], r8      // c7 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+24] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+32] 
  mul    r15
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r9, rax
  mov    [rcx+64], r9     // c8 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [reg_p2+40]
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0

  mov    rax, [reg_p2+32] 
  mul    r11
  add    r10, rax
  mov    [rcx+72], r10     // c9 
  adc    r8, rdx
  adc    r9, 0

  mov    rax, [reg_p2+40] 
  mul    r11
  add    r8, rax
  mov    [rcx+80], r8      // c10 
  adc    r9, rdx   
  mov    [rcx+88], r9      // c11 

  // rcx[12-23] <- AH*BH
  mov    r11, [reg_p1+48]
  mov    rax, [reg_p2+48] 
  mul    r11
  xor    r9, r9
  mov    [rcx+96], rax       // c0
  mov    r8, rdx

  mov    rax, [reg_p2+56]
  mul    r11
  xor    r10, r10
  add    r8, rax
  adc    r9, rdx

  mov    r12, [reg_p1+56] 
  mov    rax, [reg_p2+48] 
  mul    r12
  add    r8, rax
  mov    [rcx+104], r8      // c1 
  adc    r9, rdx
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+64] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p2+48] 
  mov    rax, [reg_p1+64] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+56] 
  mul    r12
  add    r9, rax
  mov    [rcx+112], r9     // c2 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [reg_p2+72] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p1+72] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+64] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r14, [reg_p1+64] 
  mov    rax, [reg_p2+56] 
  mul    r14
  add    r10, rax
  mov    [rcx+120], r10    // c3 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [reg_p2+80] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+64] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r15, [reg_p1+80] 
  mov    rax, r13 
  mul    r15
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+72] 
  mul    r12
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+72] 
  mov    rax, [reg_p2+56] 
  mul    r13
  add    r8, rax
  mov    [rcx+128], r8     // c4 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+88] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+64] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+72] 
  mul    r14
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r11, [reg_p1+88] 
  mov    rax, [reg_p2+48] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+80] 
  mul    r12
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+56] 
  mul    r15
  add    r9, rax
  mov    [rcx+136], r9     // c5 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [reg_p2+64] 
  mul    r15
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+88] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+80] 
  mul    r14
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+56] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+72] 
  mul    r13
  add    r10, rax
  mov    [rcx+144], r10    // c6 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [reg_p2+88] 
  mul    r14
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+64] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+80]
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+72] 
  mul    r15
  add    r8, rax
  mov    [rcx+152], r8     // c7 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+72] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+80] 
  mul    r15
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+88] 
  mul    r13
  add    r9, rax
  mov    [rcx+160], r9     // c8 
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+88]
  mul    r15
  add    r10, rax
  adc    r8, rdx

  mov    rax, [reg_p2+80] 
  mul    r11
  add    r10, rax
  mov    [rcx+168], r10     // c9 
  adc    r8, rdx

  mov    rax, [reg_p2+88] 
  mul    r11
  add    r8, rax
  mov    [rcx+176], r8      // c10 
  adc    rdx, 0   
  mov    [rcx+184], rdx     // c11  
      
  // [r8-r15,rax,rdx,rdi,[rsp]] <- (AH+AL)*(BH+BL) - AL*BL 
  mov    r8,  [rsp]
  sub    r8,  [rcx] 
  mov    r9,  [rsp+8]
  sbb    r9,  [rcx+8]
  mov    r10, [rsp+16]
  sbb    r10, [rcx+16]
  mov    r11, [rsp+24]
  sbb    r11, [rcx+24] 
  mov    r12, [rsp+32]
  sbb    r12, [rcx+32]
  mov    r13, [rsp+40]
  sbb    r13, [rcx+40] 
  mov    r14, [rsp+48]
  sbb    r14, [rcx+48] 
  mov    r15, [rsp+56]
  sbb    r15, [rcx+56] 
  mov    rax, [rsp+64]
  sbb    rax, [rcx+64]
  mov    rdx, [rsp+72]
  sbb    rdx, [rcx+72] 
  mov    rdi, [rsp+80]
  sbb    rdi, [rcx+80] 
  mov    rsi, [rsp+88]
  sbb    rsi, [rcx+88] 
  mov    [rsp], rsi
      
  // [r8-r15,rax,rdx,rdi,[rsp]] <- (AH+AL)*(BH+BL) - AL*BL - AH*BH
  mov    rsi, [rcx+96]
  sub    r8,  rsi 
  mov    rsi, [rcx+104]
  sbb    r9,  rsi
  mov    rsi, [rcx+112]
  sbb    r10, rsi
  mov    rsi, [rcx+120]
  sbb    r11, rsi 
  mov    rsi, [rcx+128]
  sbb    r12, rsi
  mov    rsi, [rcx+136]
  sbb    r13, rsi
  mov    rsi, [rcx+144]
  sbb    r14, rsi 
  mov    rsi, [rcx+152]
  sbb    r15, rsi 
  mov    rsi, [rcx+160]
  sbb    rax, rsi
  mov    rsi, [rcx+168]
  sbb    rdx, rsi
  mov    rsi, [rcx+176] 
  sbb    rdi, rsi
  mov    rsi, [rsp] 
  sbb    rsi, [rcx+184]
      
  // Final result
  add    r8,  [rcx+48] 
  mov    [rcx+48], r8
  adc    r9,  [rcx+56]
  mov    [rcx+56], r9
  adc    r10, [rcx+64]
  mov    [rcx+64], r10
  adc    r11, [rcx+72]
  mov    [rcx+72], r11
  adc    r12, [rcx+80]
  mov    [rcx+80], r12
  adc    r13, [rcx+88]
  mov    [rcx+88], r13
  adc    r14, [rcx+96] 
  mov    [rcx+96], r14
  adc    r15, [rcx+104] 
  mov    [rcx+104], r15
  adc    rax, [rcx+112]
  mov    [rcx+112], rax
  adc    rdx, [rcx+120]
  mov    [rcx+120], rdx
  adc    rdi, [rcx+128]
  mov    [rcx+128], rdi
  adc    rsi, [rcx+136]
  mov    [rcx+136], rsi  
  mov    rax, [rcx+144]
  adc    rax, 0
  mov    [rcx+144], rax
  mov    rax, [rcx+152]
  adc    rax, 0
  mov    [rcx+152], rax
  mov    rax, [rcx+160]
  adc    rax, 0
  mov    [rcx+160], rax
  mov    rax, [rcx+168]
  adc    rax, 0
  mov    [rcx+168], rax
  mov    rax, [rcx+176]
  adc    rax, 0
  mov    [rcx+176], rax
  mov    rax, [rcx+184]
  adc    rax, 0
  mov    [rcx+184], rax
    
  add    rsp, 96           // Restoring space in stack
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret

  
//***********************************************************************
//  Montgomery reduction
//  Based on comba method
//  Operation: c [reg_p2] = a [reg_p1]
//  NOTE: a=c is not allowed
//*********************************************************************** 
.global oqs_sidh_cln16_rdc751_asm
oqs_sidh_cln16_rdc751_asm:
  push   r12
  push   r13 
  push   r14 
  push   r15 

  mov    r11, [reg_p1]
  movq   rax, p751p1_5 
  mul    r11
  xor    r8, r8
  add    rax, [reg_p1+40]
  mov    [reg_p2+40], rax    // z5
  adc    r8, rdx
  
  xor    r9, r9
  movq   rax, p751p1_6 
  mul    r11
  xor    r10, r10
  add    r8, rax
  adc    r9, rdx

  mov    r12, [reg_p1+8]
  movq   rax, p751p1_5 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+48]
  mov    [reg_p2+48], r8    // z6
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  movq   rax, p751p1_7 
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_6 
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    r13, [reg_p1+16]
  movq   rax, p751p1_5 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+56]
  mov    [reg_p2+56], r9    // z7
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  movq   rax, p751p1_8 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_7 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_6 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    r14, [reg_p1+24]
  movq   rax, p751p1_5 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+64]
  mov    [reg_p2+64], r10   // z8
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  movq   rax, p751p1_9 
  mul    r11
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_8 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_7 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_6 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    r15, [reg_p1+32]
  movq   rax, p751p1_5 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+72]
  mov    [reg_p2+72], r8    // z9
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  movq   rax, p751p1_10 
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_9 
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_8 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_7 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_6 
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rcx, [reg_p2+40]
  movq   rax, p751p1_5 
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+80]
  mov    [reg_p2+80], r9    // z10
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  movq   rax, p751p1_11 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_10 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_9 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_8 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_7 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_6 
  mul    rcx
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    r11, [reg_p2+48]
  movq   rax, p751p1_5 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+88]
  mov    [reg_p2+88], r10    // z11
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  movq   rax, p751p1_11 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_10 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_9 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_8 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_7 
  mul    rcx
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_6 
  mul    r11
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    r12, [reg_p2+56]
  movq   rax, p751p1_5 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+96]
  mov    [reg_p2], r8        // z0
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  movq   rax, p751p1_11 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  movq   rax, p751p1_10 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  movq   rax, p751p1_9
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  movq   rax, p751p1_8
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  movq   rax, p751p1_7
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  movq   rax, p751p1_6
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    r13, [reg_p2+64]
  movq   rax, p751p1_5
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+104]
  mov    [reg_p2+8], r9      // z1
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  movq   rax, p751p1_11 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_10 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_9 
  mul    rcx
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_8 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_7 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_6 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    r14, [reg_p2+72]
  movq   rax, p751p1_5 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+112]
  mov    [reg_p2+16], r10    // z2
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  movq   rax, p751p1_11 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_10 
  mul    rcx
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_9 
  mul    r11
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_8 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_7 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_6 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    r15, [reg_p2+80]
  movq   rax, p751p1_5 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+120]
  mov    [reg_p2+24], r8     // z3
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  movq   rax, p751p1_11 
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_10 
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_9 
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_8 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_7 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_6 
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rcx, [reg_p2+88]
  movq   rax, p751p1_5 
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+128]
  mov    [reg_p2+32], r9     // z4
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  movq   rax, p751p1_11 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_10 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_9 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_8 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_7 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_6 
  mul    rcx
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+136]
  mov    [reg_p2+40], r10    // z5
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  movq   rax, p751p1_11 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_10 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_9 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_8 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_7 
  mul    rcx
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+144]
  mov    [reg_p2+48], r8     // z6
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  movq   rax, p751p1_11 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_10 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_9 
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_8 
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+152]
  mov    [reg_p2+56], r9     // z7
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  movq   rax, p751p1_11 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_10 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_9 
  mul    rcx
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+160]
  mov    [reg_p2+64], r10    // z8
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  movq   rax, p751p1_11 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0

  movq   rax, p751p1_10 
  mul    rcx
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+168]    // z9
  mov    [reg_p2+72], r8     // z9
  adc    r9, 0
  adc    r10, 0
  
  movq   rax, p751p1_11 
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  add    r9, [reg_p1+176]    // z10
  mov    [reg_p2+80], r9     // z10
  adc    r10, 0  
  add    r10, [reg_p1+184]   // z11
  mov    [reg_p2+88], r10    // z11

  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret
