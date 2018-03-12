//****************************************************************************************
// LatticeCrypto: an efficient post-quantum Ring-Learning With Errors cryptography library
//
//    Copyright (c) Microsoft Corporation. All rights reserved.
//
//
// Abstract: functions for error sampling and reconciliation in x64 assembly using AVX2 
//           vector instructions for Linux 
//
//****************************************************************************************  

.intel_syntax noprefix 

// Registers that are used for parameter passing:
#define reg_p1  rdi
#define reg_p2  rsi
#define reg_p3  rdx
#define reg_p4  rcx
#define reg_p5  r8


.text
//***********************************************************************
//  Error sampling from psi_12
//  Operation: c [reg_p2] <- sampling(a) [reg_p1]
//*********************************************************************** 
.globl oqs_rlwe_msrln16_error_sampling_asm
oqs_rlwe_msrln16_error_sampling_asm:  
  vmovdqu    ymm7, ONE32x 
  movq       r11, 384
  movq       r10, 32
  movq       r8, 24
  xor        rax, rax
  xor        rcx, rcx
loop1:
  vmovdqu    ymm0, YMMWORD PTR [reg_p1+4*rax]        // sample
  vmovdqu    ymm2, YMMWORD PTR [reg_p1+4*rax+32]     // sample
  vmovdqu    ymm4, YMMWORD PTR [reg_p1+4*rax+64]     // sample
  movq       r9, 2

loop1b:
  vpand      ymm1, ymm0, ymm7                        // Collecting 8 bits for first sample
  vpsrlw     ymm0, ymm0, 1 
  vpand      ymm3, ymm0, ymm7
  vpaddb     ymm1, ymm1, ymm3
  vpsrlw     ymm0, ymm0, 1 
  vpand      ymm3, ymm0, ymm7
  vpaddb     ymm1, ymm1, ymm3
  vpsrlw     ymm0, ymm0, 1 
  vpand      ymm3, ymm0, ymm7
  vpaddb     ymm1, ymm1, ymm3
  vpsrlw     ymm0, ymm0, 1 
  vpand      ymm3, ymm0, ymm7
  vpaddb     ymm1, ymm1, ymm3
  vpsrlw     ymm0, ymm0, 1 
  vpand      ymm3, ymm0, ymm7
  vpaddb     ymm1, ymm1, ymm3
  vpsrlw     ymm0, ymm0, 1 
  vpand      ymm3, ymm0, ymm7
  vpaddb     ymm1, ymm1, ymm3
  vpsrlw     ymm0, ymm0, 1 
  vpand      ymm3, ymm0, ymm7
  vpaddb     ymm1, ymm1, ymm3
  
  vpand      ymm3, ymm2, ymm7                        // Adding next 4 bits
  vpaddb     ymm1, ymm1, ymm3
  vpsrlw     ymm2, ymm2, 1 
  vpand      ymm3, ymm2, ymm7
  vpaddb     ymm1, ymm1, ymm3
  vpsrlw     ymm2, ymm2, 1 
  vpand      ymm3, ymm2, ymm7
  vpaddb     ymm1, ymm1, ymm3
  vpsrlw     ymm2, ymm2, 1 
  vpand      ymm3, ymm2, ymm7
  vpaddb     ymm1, ymm1, ymm3
  
  vpsrlw     ymm2, ymm2, 1                           // Collecting 4-bits for second sample
  vpand      ymm5, ymm2, ymm7
  vpsrlw     ymm2, ymm2, 1 
  vpand      ymm3, ymm2, ymm7
  vpaddb     ymm5, ymm5, ymm3
  vpsrlw     ymm2, ymm2, 1 
  vpand      ymm3, ymm2, ymm7
  vpaddb     ymm5, ymm5, ymm3
  vpsrlw     ymm2, ymm2, 1 
  vpand      ymm3, ymm2, ymm7
  vpaddb     ymm5, ymm5, ymm3
  
  vpand      ymm3, ymm4, ymm7                        // Adding next 8 bits
  vpaddb     ymm5, ymm5, ymm3
  vpsrlw     ymm4, ymm4, 1 
  vpand      ymm3, ymm4, ymm7
  vpaddb     ymm5, ymm5, ymm3
  vpsrlw     ymm4, ymm4, 1 
  vpand      ymm3, ymm4, ymm7
  vpaddb     ymm5, ymm5, ymm3
  vpsrlw     ymm4, ymm4, 1 
  vpand      ymm3, ymm4, ymm7
  vpaddb     ymm5, ymm5, ymm3
  vpsrlw     ymm4, ymm4, 1 
  vpand      ymm3, ymm4, ymm7
  vpaddb     ymm5, ymm5, ymm3
  vpsrlw     ymm4, ymm4, 1 
  vpand      ymm3, ymm4, ymm7
  vpaddb     ymm5, ymm5, ymm3
  vpsrlw     ymm4, ymm4, 1 
  vpand      ymm3, ymm4, ymm7
  vpaddb     ymm5, ymm5, ymm3
  vpsrlw     ymm4, ymm4, 1 
  vpand      ymm3, ymm4, ymm7
  vpaddb     ymm5, ymm5, ymm3

  vpsubb     ymm5, ymm1, ymm5
  vpermq     ymm3, ymm5, 0x0e 
  vpmovsxbd  ymm6, xmm5
  vpsrldq    ymm5, ymm5, 8 
  vpmovsxbd  ymm7, xmm5 
  vpmovsxbd  ymm8, xmm3
  vpsrldq    ymm3, ymm3, 8 
  vpmovsxbd  ymm9, xmm3
  vmovdqu    YMMWORD PTR [reg_p2+4*rcx], ymm6
  vmovdqu    YMMWORD PTR [reg_p2+4*rcx+32], ymm7
  vmovdqu    YMMWORD PTR [reg_p2+4*rcx+64], ymm8
  vmovdqu    YMMWORD PTR [reg_p2+4*rcx+96], ymm9
  
  add        rcx, r10        // i+32
  vpsrlw     ymm0, ymm0, 1 
  vpsrlw     ymm2, ymm2, 1 
  vpsrlw     ymm4, ymm4, 1 
  dec        r9
  jnz        loop1b
        
  add        rax, r8         // j+24        
  cmp        rax, r11
  jl         loop1
  ret


//***********************************************************************
//  Reconciliation helper function
//  Operation: c [reg_p2] <- function(a) [reg_p1]
//             [reg_p3] points to random bits
//*********************************************************************** 
.globl oqs_rlwe_msrln16_helprec_asm
oqs_rlwe_msrln16_helprec_asm:  
  vmovdqu    ymm8, ONE8x 
  movq       r11, 256
  movq       r10, 8
  xor        rax, rax
  vmovdqu    ymm4, YMMWORD PTR [reg_p3]              // rbits
loop2:
  vmovdqu    ymm0, YMMWORD PTR [reg_p1+4*rax]        // x
  vmovdqu    ymm1, YMMWORD PTR [reg_p1+4*rax+4*256]  // x+256
  vmovdqu    ymm2, YMMWORD PTR [reg_p1+4*rax+4*512]  // x+512
  vmovdqu    ymm3, YMMWORD PTR [reg_p1+4*rax+4*768]  // x+768

  vpand      ymm5, ymm4, ymm8                        // Collecting 8 random bits
  vpslld     ymm0, ymm0, 1                           // 2*x - rbits
  vpslld     ymm1, ymm1, 1 
  vpslld     ymm2, ymm2, 1 
  vpslld     ymm3, ymm3, 1 
  vpsubd     ymm0, ymm0, ymm5
  vpsubd     ymm1, ymm1, ymm5
  vpsubd     ymm2, ymm2, ymm5
  vpsubd     ymm3, ymm3, ymm5
    
  vmovdqu    ymm15, PARAM_Q4x8 
  vmovdqu    ymm7, FOUR8x
  vmovdqu    ymm8, ymm7
  vmovdqu    ymm9, ymm7
  vmovdqu    ymm10, ymm7
  vpsubd     ymm6, ymm0, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm7, ymm7, ymm6
  vpsubd     ymm6, ymm1, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm8, ymm8, ymm6
  vpsubd     ymm6, ymm2, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm9, ymm9, ymm6
  vpsubd     ymm6, ymm3, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm10, ymm10, ymm6
  vmovdqu    ymm15, PARAM_3Q4x8 
  vpsubd     ymm6, ymm0, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm7, ymm7, ymm6
  vpsubd     ymm6, ymm1, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm8, ymm8, ymm6
  vpsubd     ymm6, ymm2, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm9, ymm9, ymm6
  vpsubd     ymm6, ymm3, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm10, ymm10, ymm6
  vmovdqu    ymm15, PARAM_5Q4x8 
  vpsubd     ymm6, ymm0, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm7, ymm7, ymm6
  vpsubd     ymm6, ymm1, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm8, ymm8, ymm6
  vpsubd     ymm6, ymm2, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm9, ymm9, ymm6
  vpsubd     ymm6, ymm3, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm10, ymm10, ymm6
  vmovdqu    ymm15, PARAM_7Q4x8 
  vpsubd     ymm6, ymm0, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm7, ymm7, ymm6                        // v0[0]
  vpsubd     ymm6, ymm1, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm8, ymm8, ymm6                        // v0[1]
  vpsubd     ymm6, ymm2, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm9, ymm9, ymm6                        // v0[2]
  vpsubd     ymm6, ymm3, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm10, ymm10, ymm6                      // v0[3]  
    
  vmovdqu    ymm15, PARAM_Q2x8 
  vmovdqu    ymm11, THREE8x
  vmovdqu    ymm12, ymm11
  vmovdqu    ymm13, ymm11
  vmovdqu    ymm14, ymm11
  vpsubd     ymm6, ymm0, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm11, ymm11, ymm6
  vpsubd     ymm6, ymm1, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm12, ymm12, ymm6
  vpsubd     ymm6, ymm2, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm13, ymm13, ymm6
  vpsubd     ymm6, ymm3, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm14, ymm14, ymm6
  vmovdqu    ymm15, PARAM_3Q2x8 
  vpsubd     ymm6, ymm0, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm11, ymm11, ymm6
  vpsubd     ymm6, ymm1, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm12, ymm12, ymm6
  vpsubd     ymm6, ymm2, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm13, ymm13, ymm6
  vpsubd     ymm6, ymm3, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm14, ymm14, ymm6
  vmovdqu    ymm15, PRIME8x  
  vpsubd     ymm6, ymm0, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm11, ymm11, ymm6                      // v1[0]
  vpsubd     ymm6, ymm1, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm12, ymm12, ymm6                      // v1[1]
  vpsubd     ymm6, ymm2, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm13, ymm13, ymm6                      // v1[2]
  vpsubd     ymm6, ymm3, ymm15
  vpsrld     ymm6, ymm6, 31 
  vpsubd     ymm14, ymm14, ymm6                      // v1[3]

  vpmulld    ymm6, ymm7, ymm15 
  vpslld     ymm0, ymm0, 1 
  vpsubd     ymm0, ymm0, ymm6
  vpabsd     ymm0, ymm0
  vpmulld    ymm6, ymm8, ymm15 
  vpslld     ymm1, ymm1, 1 
  vpsubd     ymm1, ymm1, ymm6
  vpabsd     ymm1, ymm1
  vpaddd     ymm0, ymm0, ymm1
  vpmulld    ymm6, ymm9, ymm15 
  vpslld     ymm2, ymm2, 1 
  vpsubd     ymm2, ymm2, ymm6
  vpabsd     ymm2, ymm2
  vpaddd     ymm0, ymm0, ymm2
  vpmulld    ymm6, ymm10, ymm15 
  vpslld     ymm3, ymm3, 1 
  vpsubd     ymm3, ymm3, ymm6
  vpabsd     ymm3, ymm3
  vpaddd     ymm0, ymm0, ymm3                        // norm
  vpsubd     ymm0, ymm0, ymm15
  vpsrad     ymm0, ymm0, 31                          // If norm < q then norm = 0xff...ff, else norm = 0
  
  vpxor      ymm7, ymm7, ymm11                       // v0[i] = (norm & (v0[i] ^ v1[i])) ^ v1[i]
  vpand      ymm7, ymm7, ymm0
  vpxor      ymm7, ymm7, ymm11
  vpxor      ymm8, ymm8, ymm12
  vpand      ymm8, ymm8, ymm0
  vpxor      ymm8, ymm8, ymm12
  vpxor      ymm9, ymm9, ymm13
  vpand      ymm9, ymm9, ymm0
  vpxor      ymm9, ymm9, ymm13
  vpxor      ymm10, ymm10, ymm14
  vpand      ymm10, ymm10, ymm0
  vpxor      ymm10, ymm10, ymm14
  
  vmovdqu    ymm15, THREE8x
  vmovdqu    ymm14, ONE8x
  vpsubd     ymm7, ymm7, ymm10
  vpand      ymm7, ymm7, ymm15
  vpsubd     ymm8, ymm8, ymm10
  vpand      ymm8, ymm8, ymm15
  vpsubd     ymm9, ymm9, ymm10
  vpand      ymm9, ymm9, ymm15 
  vpslld     ymm10, ymm10, 1 
  vpxor      ymm0, ymm0, ymm14
  vpand      ymm0, ymm0, ymm14
  vpaddd     ymm10, ymm0, ymm10
  vpand      ymm10, ymm10, ymm15 
  
  vpsrld     ymm4, ymm4, 1 
  vmovdqu    YMMWORD PTR [reg_p2+4*rax], ymm7
  vmovdqu    YMMWORD PTR [reg_p2+4*rax+4*256], ymm8
  vmovdqu    YMMWORD PTR [reg_p2+4*rax+4*512], ymm9
  vmovdqu    YMMWORD PTR [reg_p2+4*rax+4*768], ymm10

  add        rax, r10             // j+8 
  add        rcx, r9
  cmp        rax, r11             
  jl         loop2
  ret


//***********************************************************************
//  Reconciliation function
//  Operation: c [reg_p3] <- function(a [reg_p1], b [reg_p2])
//*********************************************************************** 
.globl oqs_rlwe_msrln16_rec_asm
oqs_rlwe_msrln16_rec_asm:  
  vpxor      ymm12, ymm12, ymm12 
  vmovdqu    ymm15, PRIME8x   
  vpslld     ymm14, ymm15, 2                         // 4*Q  
  vpslld     ymm13, ymm15, 3                         // 8*Q
  vpsubd     ymm12, ymm12, ymm13                     // -8*Q
  vpxor      ymm11, ymm12, ymm13                     // 8*Q ^ -8*Q
  vmovdqu    ymm10, ONE8x 
  movq       r11, 256
  movq       r10, 8
  xor        rax, rax
  xor        rcx, rcx
loop3:
  vmovdqu    ymm0, YMMWORD PTR [reg_p1+4*rax]        // x
  vmovdqu    ymm1, YMMWORD PTR [reg_p1+4*rax+4*256]  // x+256
  vmovdqu    ymm2, YMMWORD PTR [reg_p1+4*rax+4*512]  // x+512
  vmovdqu    ymm3, YMMWORD PTR [reg_p1+4*rax+4*768]  // x+768
  vmovdqu    ymm4, YMMWORD PTR [reg_p2+4*rax]        // rvec
  vmovdqu    ymm5, YMMWORD PTR [reg_p2+4*rax+4*256]  // rvec+256
  vmovdqu    ymm6, YMMWORD PTR [reg_p2+4*rax+4*512]  // rvec+512
  vmovdqu    ymm7, YMMWORD PTR [reg_p2+4*rax+4*768]  // rvec+768
  
  vpslld     ymm8, ymm4, 1                           // 2*rvec + rvec
  vpaddd     ymm4, ymm7, ymm8
  vpslld     ymm8, ymm5, 1 
  vpaddd     ymm5, ymm7, ymm8
  vpslld     ymm8, ymm6, 1 
  vpaddd     ymm6, ymm7, ymm8
  vpmulld    ymm4, ymm4, ymm15
  vpmulld    ymm5, ymm5, ymm15
  vpmulld    ymm6, ymm6, ymm15
  vpmulld    ymm7, ymm7, ymm15
  vpslld     ymm0, ymm0, 3                           // 8*x
  vpslld     ymm1, ymm1, 3 
  vpslld     ymm2, ymm2, 3 
  vpslld     ymm3, ymm3, 3 
  vpsubd     ymm0, ymm0, ymm4                        // t[i]
  vpsubd     ymm1, ymm1, ymm5
  vpsubd     ymm2, ymm2, ymm6
  vpsubd     ymm3, ymm3, ymm7
  
  vpsrad     ymm8, ymm0, 31                          // mask1
  vpabsd     ymm4, ymm0
  vpsubd     ymm4, ymm14, ymm4
  vpsrad     ymm4, ymm4, 31                          // mask2                       
  vpand      ymm8, ymm8, ymm11                       // (mask1 & (8*PARAMETER_Q ^ -8*PARAMETER_Q)) ^ -8*PARAMETER_Q
  vpxor      ymm8, ymm8, ymm12
  vpand      ymm4, ymm4, ymm8
  vpaddd     ymm0, ymm0, ymm4
  vpabsd     ymm0, ymm0  
  vpsrad     ymm8, ymm1, 31                          // mask1
  vpabsd     ymm4, ymm1
  vpsubd     ymm4, ymm14, ymm4
  vpsrad     ymm4, ymm4, 31                          // mask2                       
  vpand      ymm8, ymm8, ymm11                       // (mask1 & (8*PARAMETER_Q ^ -8*PARAMETER_Q)) ^ -8*PARAMETER_Q
  vpxor      ymm8, ymm8, ymm12
  vpand      ymm4, ymm4, ymm8
  vpaddd     ymm1, ymm1, ymm4
  vpabsd     ymm1, ymm1
  vpaddd     ymm0, ymm0, ymm1
  vpsrad     ymm8, ymm2, 31                          // mask1
  vpabsd     ymm4, ymm2
  vpsubd     ymm4, ymm14, ymm4
  vpsrad     ymm4, ymm4, 31                          // mask2                       
  vpand      ymm8, ymm8, ymm11                       // (mask1 & (8*PARAMETER_Q ^ -8*PARAMETER_Q)) ^ -8*PARAMETER_Q
  vpxor      ymm8, ymm8, ymm12
  vpand      ymm4, ymm4, ymm8
  vpaddd     ymm2, ymm2, ymm4
  vpabsd     ymm2, ymm2
  vpaddd     ymm0, ymm0, ymm2
  vpsrad     ymm8, ymm3, 31                          // mask1
  vpabsd     ymm4, ymm3
  vpsubd     ymm4, ymm14, ymm4
  vpsrad     ymm4, ymm4, 31                          // mask2                       
  vpand      ymm8, ymm8, ymm11                       // (mask1 & (8*PARAMETER_Q ^ -8*PARAMETER_Q)) ^ -8*PARAMETER_Q
  vpxor      ymm8, ymm8, ymm12
  vpand      ymm4, ymm4, ymm8
  vpaddd     ymm3, ymm3, ymm4
  vpabsd     ymm3, ymm3
  vpaddd     ymm0, ymm0, ymm3                        // norm

  vpsubd     ymm0, ymm13, ymm0                       // If norm < PARAMETER_Q then result = 1, else result = 0
  vpsrld     ymm0, ymm0, 31                            
  vpxor      ymm0, ymm0, ymm10

  vpsrlq     ymm1, ymm0, 31
  vpor       ymm1, ymm0, ymm1 
  vpsllq     ymm2, ymm1, 2
  vpsrldq    ymm2, ymm2, 8
  vpor       ymm1, ymm2, ymm1 
  vpsllq     ymm2, ymm1, 4
  vpermq     ymm2, ymm2, 0x56
  vpor       ymm0, ymm1, ymm2 
  vmovq      r9, xmm0
  
  mov        BYTE PTR [reg_p3+rcx], r9b

  add        rax, r10             // j+8 
  inc        rcx
  cmp        rax, r11             
  jl         loop3
  ret
