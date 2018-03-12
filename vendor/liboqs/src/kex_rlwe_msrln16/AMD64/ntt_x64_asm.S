//****************************************************************************************
// LatticeCrypto: an efficient post-quantum Ring-Learning With Errors cryptography library
//
//    Copyright (c) Microsoft Corporation. All rights reserved.
//
//
// Abstract: NTT functions in x64 assembly using AVX2 vector instructions for Linux 
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
//  Forward NTT
//  Operation: a [reg_p1] <- NTT(a) [reg_p1], 
//             [reg_p2] points to table and 
//             reg_p3 contains parameter n
//*********************************************************************** 
.globl oqs_rlwe_msrln16_NTT_CT_std2rev_12289_asm
oqs_rlwe_msrln16_NTT_CT_std2rev_12289_asm:
  push       r12
  push       r13
  push       r14

// Stages m=1 -> m=32
  mov        r9, 1            // m = 1
  mov        rax, reg_p3 
  mov        r12, reg_p3      
  shr        r12, 4           // n/16
  vmovdqu    ymm14, MASK12x8
  vmovdqu    ymm12, PERM0246
  mov        r14, 16
  mov        rcx, 11
loop1:
  shr        rax, 1           // k = k/2
  dec        rcx 
  xor        rdx, rdx         // i = 0
loop2:
  mov        r10, rdx
  mov        r11, rax
  dec        r11
  shl        r10, cl          // j1
  add        r11, r10         // j2
  mov        r13, r9
  add        r13, rdx         // m+i
  vbroadcastss ymm11, DWORD PTR [reg_p2+4*r13]   // S

loop3:
  mov        r13, r10
  add        r13, rax         // j+k
  vpmovsxdq  ymm1, XMMWORD PTR [reg_p1+4*r13]    // a[j+k]
  vpmovsxdq  ymm3, XMMWORD PTR [reg_p1+4*r13+16] // a[j+k]
  vpmovsxdq  ymm5, XMMWORD PTR [reg_p1+4*r13+32] // a[j+k]
  vpmovsxdq  ymm7, XMMWORD PTR [reg_p1+4*r13+48] // a[j+k]
  
  vpmuldq    ymm1, ymm1, ymm11                   // a[j+k].S
  vpmuldq    ymm3, ymm3, ymm11                   
  vpmuldq    ymm5, ymm5, ymm11                   
  vpmuldq    ymm7, ymm7, ymm11   
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*r10]    // U = a[j]

  vmovdqu    ymm13, ymm1
  vpand      ymm1, ymm14, ymm1                   // c0
  vpsrlq     ymm13, ymm13, 12                    // c1
  vpslld     ymm15, ymm1, 1                      // 2*c0
  vpsubd     ymm13, ymm1, ymm13                  // c0-c1
  vpaddd     ymm13, ymm13, ymm15                 // V = 3*c0-c1    
  vpsubd     ymm1, ymm0, ymm13                   // a[j+k] = U - V
  vpaddd     ymm0, ymm0, ymm13                   // a[j] = U + V   
  vpermd     ymm1, ymm12, ymm1 
  vpermd     ymm0, ymm12, ymm0 
  vpmovsxdq  ymm2, XMMWORD PTR [reg_p1+4*r10+16] // U = a[j]

  vmovdqu    ymm13, ymm3
  vpand      ymm3, ymm14, ymm3                   // c0
  vpsrlq     ymm13, ymm13, 12                    // c1
  vpslld     ymm15, ymm3, 1                      // 2*c0
  vpsubd     ymm13, ymm3, ymm13                  // c0-c1
  vpaddd     ymm13, ymm13, ymm15                 // V = 3*c0-c1    
  vpsubd     ymm3, ymm2, ymm13                   // a[j+k] = U - V
  vpaddd     ymm2, ymm2, ymm13                   // a[j] = U + V  
  vmovdqu    XMMWORD PTR [reg_p1+4*r10], xmm0
  vmovdqu    XMMWORD PTR [reg_p1+4*r13], xmm1 
  vpermd     ymm3, ymm12, ymm3 
  vpermd     ymm2, ymm12, ymm2 
  vpmovsxdq  ymm4, XMMWORD PTR [reg_p1+4*r10+32] // U = a[j]

  vmovdqu    ymm13, ymm5
  vpand      ymm5, ymm14, ymm5                   // c0
  vpsrlq     ymm13, ymm13, 12                    // c1
  vpslld     ymm15, ymm5, 1                      // 2*c0
  vpsubd     ymm13, ymm5, ymm13                  // c0-c1
  vpaddd     ymm13, ymm13, ymm15                 // V = 3*c0-c1    
  vpsubd     ymm5, ymm4, ymm13                   // a[j+k] = U - V
  vpaddd     ymm4, ymm4, ymm13                   // a[j] = U + V  
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+16], xmm2
  vmovdqu    XMMWORD PTR [reg_p1+4*r13+16], xmm3 
  vpermd     ymm5, ymm12, ymm5 
  vpermd     ymm4, ymm12, ymm4 
  vpmovsxdq  ymm6, XMMWORD PTR [reg_p1+4*r10+48] // U = a[j]

  vmovdqu    ymm13, ymm7
  vpand      ymm7, ymm14, ymm7                   // c0
  vpsrlq     ymm13, ymm13, 12                    // c1
  vpslld     ymm15, ymm7, 1                      // 2*c0
  vpsubd     ymm13, ymm7, ymm13                  // c0-c1
  vpaddd     ymm13, ymm13, ymm15                 // V = 3*c0-c1    
  vpsubd     ymm7, ymm6, ymm13                   // a[j+k] = U - V
  vpaddd     ymm6, ymm6, ymm13                   // a[j] = U + V 
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+32], xmm4
  vmovdqu    XMMWORD PTR [reg_p1+4*r13+32], xmm5  
  vpermd     ymm6, ymm12, ymm6   
  vpermd     ymm7, ymm12, ymm7 
  vmovdqu    XMMWORD PTR [reg_p1+4*r13+48], xmm7
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+48], xmm6
  
  add        r10, r14
  cmp        r10, r11
  jl         loop3
  inc        rdx
  cmp        rdx, r9
  jl         loop2
  shl        r9, 1
  cmp        r9, r12
  jl         loop1
   
// Stage m=64
  xor        rdx, rdx         // i = 0
  xor        r10, r10         // j1 = 0
loop4:
  vbroadcastss ymm11, DWORD PTR [reg_p2+4*rdx+4*64] // S
  vpmovsxdq  ymm1, XMMWORD PTR [reg_p1+4*r10+32] // a[j+k]
  vpmovsxdq  ymm3, XMMWORD PTR [reg_p1+4*r10+48] // a[j+k]
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*r10]    // U = a[j]
  vpmovsxdq  ymm2, XMMWORD PTR [reg_p1+4*r10+16] // U = a[j]
  vpmuldq    ymm1, ymm1, ymm11                   // a[j+k].S
  vpmuldq    ymm3, ymm3, ymm11                   // a[j+k].S

  vmovdqu    ymm13, ymm1
  vpand      ymm1, ymm14, ymm1                   // c0
  vpsrlq     ymm13, ymm13, 12                    // c1
  vpslld     ymm15, ymm1, 1                      // 2*c0
  vpsubd     ymm13, ymm1, ymm13                  // c0-c1
  vpaddd     ymm13, ymm13, ymm15                 // V = 3*c0-c1 
  
  vmovdqu    ymm10, ymm3
  vpand      ymm3, ymm14, ymm3                   // c0
  vpsrlq     ymm10, ymm10, 12                    // c1
  vpslld     ymm15, ymm3, 1                      // 2*c0
  vpsubd     ymm10, ymm3, ymm10                  // c0-c1
  vpaddd     ymm10, ymm10, ymm15                 // V = 3*c0-c1    
  
  vpsubd     ymm1, ymm0, ymm13                   // a[j+k] = U - V
  vpaddd     ymm0, ymm0, ymm13                   // a[j] = U + V    
  vpsubd     ymm3, ymm2, ymm10                   // a[j+k] = U - V
  vpaddd     ymm2, ymm2, ymm10                   // a[j] = U + V 
  
  vpermd     ymm0, ymm12, ymm0 
  vpermd     ymm1, ymm12, ymm1 
  vpermd     ymm2, ymm12, ymm2 
  vpermd     ymm3, ymm12, ymm3 
  vmovdqu    XMMWORD PTR [reg_p1+4*r10], xmm0
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+32], xmm1
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+16], xmm2
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+48], xmm3
  
  add        r10, r14        // j+16 
  inc        rdx             // i+1
  cmp        rdx, r9
  jl         loop4
   
// Stage m=128
  shl        r9, 1
  xor        rdx, rdx         // i = 0
  xor        r10, r10         // j1 = 0
  mov        r13, 8 
loop6:
  vbroadcastss ymm2, DWORD PTR [reg_p2+4*rdx+4*128] // S
  vpmovsxdq  ymm1, XMMWORD PTR [reg_p1+4*r10+16] // a[j+k]
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*r10]    // U = a[j]
  vpmuldq    ymm1, ymm1, ymm2                    // a[j+k].S
  
  vmovdqu    ymm3, ymm0
  vpand      ymm0, ymm14, ymm0                   // c0
  vpsrad     ymm3, ymm3, 12                      // c1
  vpslld     ymm4, ymm0, 1                       // 2*c0
  vpsubd     ymm3, ymm0, ymm3                    // c0-c1
  vpaddd     ymm0, ymm3, ymm4                    // U = 3*c0-c1    
  
  vmovdqu    ymm3, ymm1
  vpand      ymm1, ymm14, ymm1                   // c0
  vpsrlq     ymm4, ymm3, 24                      // c2
  vpsrad     ymm3, ymm3, 12                      // xc1
  vpand      ymm3, ymm14, ymm3                   // c1
  vpslld     ymm5, ymm1, 3                       // 8*c0
  vpaddd     ymm4, ymm1, ymm4                    // c0+c2
  vpaddd     ymm4, ymm4, ymm5                    // 9*c0+c2
  vpslld     ymm5, ymm3, 1                       // 2*c1
  vpaddd     ymm1, ymm0, ymm3                    // U+c1
  vpsubd     ymm0, ymm0, ymm3                    // U-c1
  vpsubd     ymm4, ymm4, ymm5                    // 9*c0-2*c1+c2
  vpaddd     ymm0, ymm0, ymm4                    // U+(9*c0-3*c1+c2)
  vpsubd     ymm1, ymm1, ymm4                    // U-(9*c0-3*c1+c2)
  vpermd     ymm0, ymm12, ymm0 
  vpermd     ymm1, ymm12, ymm1 
  vmovdqu    XMMWORD PTR [reg_p1+4*r10], xmm0
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+16], xmm1

  add        r10, r13        // j+8
  inc        rdx             // i+1
  cmp        rdx, r9
  jl         loop6

// Stage m=256 
  vmovdqu    ymm9, PERM02134657  
  shl        r9, 1
  xor        rdx, rdx         // i = 0
  xor        r10, r10         // j1 = 0
  mov        r14, 32
loop7:
  vpmovsxdq  ymm2, XMMWORD PTR [reg_p2+4*rdx+4*256]    // S = psi[m+i]->psi[m+i+3]
  vpermq     ymm8, ymm2, 0x50   
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*r10]    // U = a[j]->a[j+3]
  vpmovsxdq  ymm1, XMMWORD PTR [reg_p1+4*r10+16] // a[j+k]->a[j+k+3]
  vpermq     ymm3, ymm0, 0x4e    
  vinserti128 ymm0, ymm0, xmm1, 1                // U
  vpblendd   ymm1, ymm1, ymm3, 15
  vpmuldq    ymm3, ymm1, ymm8                    // a[j+k].S
  vmovdqu    ymm4, ymm3
  vpand      ymm3, ymm14, ymm3                   // c0
  vpsrlq     ymm4, ymm4, 12                      // c1
  vpslld     ymm5, ymm3, 1                       // 2*c0
  vpsubd     ymm4, ymm3, ymm4                    // c0-c1
  vpaddd     ymm4, ymm4, ymm5                    // V = 3*c0-c1     
  vpsubd     ymm1, ymm0, ymm4                    // a[j+k] = U - V
  vpaddd     ymm0, ymm0, ymm4                    // a[j] = U + V 
  vpslldq    ymm1, ymm1, 4    
  vpblendd   ymm0, ymm0, ymm1, 0xaa
  vpermd     ymm0, ymm9, ymm0 
  vmovdqu    YMMWORD PTR [reg_p1+4*r10], ymm0
  
  vpermq     ymm8, ymm2, 0xfa   
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*r10+32] // U = a[j]->a[j+3]
  vpmovsxdq  ymm1, XMMWORD PTR [reg_p1+4*r10+48] // a[j+k]->a[j+k+3]
  vpermq     ymm3, ymm0, 0x4e    
  vinserti128 ymm0, ymm0, xmm1, 1                // U
  vpblendd   ymm1, ymm1, ymm3, 15
  vpmuldq    ymm3, ymm1, ymm8                    // a[j+k].S
  vmovdqu    ymm4, ymm3
  vpand      ymm3, ymm14, ymm3                   // c0
  vpsrlq     ymm4, ymm4, 12                      // c1
  vpslld     ymm5, ymm3, 1                       // 2*c0
  vpsubd     ymm4, ymm3, ymm4                    // c0-c1
  vpaddd     ymm4, ymm4, ymm5                    // V = 3*c0-c1     
  vpsubd     ymm1, ymm0, ymm4                    // a[j+k] = U - V
  vpaddd     ymm0, ymm0, ymm4                    // a[j] = U + V 
  vpslldq    ymm1, ymm1, 4    
  vpblendd   ymm0, ymm0, ymm1, 0xaa
  vpermd     ymm0, ymm9, ymm0 
  vmovdqu    YMMWORD PTR [reg_p1+4*r10+32], ymm0

  vpmovsxdq  ymm2, XMMWORD PTR [reg_p2+4*rdx+4*256+16]  // S = psi[m+i]->psi[m+i+3] 
  vpermq     ymm8, ymm2, 0x50   
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*r10+64] // U = a[j]->a[j+3]
  vpmovsxdq  ymm1, XMMWORD PTR [reg_p1+4*r10+80] // a[j+k]->a[j+k+3]
  vpermq     ymm3, ymm0, 0x4e    
  vinserti128 ymm0, ymm0, xmm1, 1                // U
  vpblendd   ymm1, ymm1, ymm3, 15
  vpmuldq    ymm3, ymm1, ymm8                    // a[j+k].S
  vmovdqu    ymm4, ymm3
  vpand      ymm3, ymm14, ymm3                   // c0
  vpsrlq     ymm4, ymm4, 12                      // c1
  vpslld     ymm5, ymm3, 1                       // 2*c0
  vpsubd     ymm4, ymm3, ymm4                    // c0-c1
  vpaddd     ymm4, ymm4, ymm5                    // V = 3*c0-c1     
  vpsubd     ymm1, ymm0, ymm4                    // a[j+k] = U - V
  vpaddd     ymm0, ymm0, ymm4                    // a[j] = U + V 
  vpslldq    ymm1, ymm1, 4    
  vpblendd   ymm0, ymm0, ymm1, 0xaa
  vpermd     ymm0, ymm9, ymm0 
  vmovdqu    YMMWORD PTR [reg_p1+4*r10+64], ymm0
          
  vpermq     ymm8, ymm2, 0xfa   
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*r10+96]  // U = a[j]->a[j+3]
  vpmovsxdq  ymm1, XMMWORD PTR [reg_p1+4*r10+112] // a[j+k]->a[j+k+3]
  vpermq     ymm3, ymm0, 0x4e    
  vinserti128 ymm0, ymm0, xmm1, 1                // U
  vpblendd   ymm1, ymm1, ymm3, 15
  vpmuldq    ymm3, ymm1, ymm8                    // a[j+k].S
  vmovdqu    ymm4, ymm3
  vpand      ymm3, ymm14, ymm3                   // c0
  vpsrlq     ymm4, ymm4, 12                      // c1
  vpslld     ymm5, ymm3, 1                       // 2*c0
  vpsubd     ymm4, ymm3, ymm4                    // c0-c1
  vpaddd     ymm4, ymm4, ymm5                    // V = 3*c0-c1     
  vpsubd     ymm1, ymm0, ymm4                    // a[j+k] = U - V
  vpaddd     ymm0, ymm0, ymm4                    // a[j] = U + V 
  vpslldq    ymm1, ymm1, 4    
  vpblendd   ymm0, ymm0, ymm1, 0xaa
  vpermd     ymm0, ymm9, ymm0 
  vmovdqu    YMMWORD PTR [reg_p1+4*r10+96], ymm0
         
  add        r10, r14        // j+32
  add        rdx, r13        // i+8
  cmp        rdx, r9
  jl         loop7

// Stage m=512
  vmovdqu    ymm9, PERM00224466
  shl        r9, 1            // m = n/2 
  xor        rdx, rdx         // i = 0
  xor        r10, r10         // j1 = 0
  mov        r14, 4
loop8:
  vpmovsxdq  ymm2, XMMWORD PTR [reg_p2+4*rdx+4*512] // S
  vmovdqu    ymm0, YMMWORD PTR [reg_p1+4*r10]    // U = a[j]
  vmovdqu    ymm1, YMMWORD PTR [reg_p1+4*r10+4]  // a[j+k]
  vpmuldq    ymm3, ymm1, ymm2                    // a[j+k].S
  vmovdqu    ymm4, ymm3
  vpand      ymm3, ymm14, ymm3                   // c0
  vpsrlq     ymm4, ymm4, 12                      // c1
  vpslld     ymm5, ymm3, 1                       // 2*c0
  vpsubd     ymm4, ymm3, ymm4                    // c0-c1
  vpaddd     ymm4, ymm4, ymm5                    // V = 3*c0-c1     
  vpsubd     ymm1, ymm0, ymm4                    // a[j+k] = U - V
  vpaddd     ymm0, ymm0, ymm4                    // a[j] = U + V 
  vpermd     ymm1, ymm9, ymm1 
  vpblendd   ymm0, ymm0, ymm1, 0xaa
  vmovdqu    YMMWORD PTR [reg_p1+4*r10], ymm0
  
  add        r10, r13        // j+8
  add        rdx, r14        // i+4
  cmp        rdx, r9
  jl         loop8

  pop        r14
  pop        r13
  pop        r12
  ret


//***********************************************************************
//  Inverse NTT
//  Operation: a [reg_p1] <- INTT(a) [reg_p1], 
//             [reg_p2] points to table
//             reg_p3 and reg_p4 point to constants for scaling and
//             reg_p5 contains parameter n
//*********************************************************************** 
.globl oqs_rlwe_msrln16_INTT_GS_rev2std_12289_asm
oqs_rlwe_msrln16_INTT_GS_rev2std_12289_asm:
  push       r12
  push       r13
  push       r14
  push       r15
  push       rbx

// Stage m=1024
  vmovdqu    ymm9, PERM00224466
  vmovdqu    ymm14, MASK12x8  
  mov        r12, reg_p5           
  shr        r12, 1          // n/2 = 512
  xor        r15, r15        // i = 0
  xor        r10, r10        // j1 = 0
  mov        r13, 8
  mov        r14, 4
loop1b:
  vmovdqu    ymm1, YMMWORD PTR [reg_p1+4*r10+4]       // V = a[j+k]    
  vmovdqu    ymm0, YMMWORD PTR [reg_p1+4*r10]         // U = a[j]
  vpmovsxdq  ymm2, XMMWORD PTR [reg_p2+4*r15+4*512]   // S
  vpsubd     ymm3, ymm0, ymm1                         // U - V
  vpaddd     ymm0, ymm0, ymm1                         // U + V 
  vpmuldq    ymm3, ymm3, ymm2                         // (U - V).S
  vmovdqu    ymm4, ymm3
  vpand      ymm3, ymm14, ymm3                        // c0
  vpsrlq     ymm4, ymm4, 12                           // c1
  vpslld     ymm5, ymm3, 1                            // 2*c0
  vpsubd     ymm4, ymm3, ymm4                         // c0-c1
  vpaddd     ymm1, ymm4, ymm5                         // 3*c0-c1 
  vpermd     ymm1, ymm9, ymm1 
  vpblendd   ymm0, ymm0, ymm1, 0xaa
  vmovdqu    YMMWORD PTR [reg_p1+4*r10], ymm0

  add        r10, r13        // j+8
  add        r15, r14        // i+4
  cmp        r15, r12
  jl         loop1b
  
// Stage m=512 
  vmovdqu    ymm9, PERM02134657
  vmovdqu    ymm13, PERM0145
  vmovdqu    ymm15, PERM2367   
  shr        r12, 1          // n/4 = 256
  xor        r15, r15        // i = 0
  xor        r10, r10        // j1 = 0
  mov        r14, 32
loop2b:
  vpmovsxdq  ymm2, XMMWORD PTR [reg_p2+4*r15+4*256]   // S = psi[m+i]->psi[m+i+3]
  vpermq     ymm8, ymm2, 0x50   
  vmovdqu    ymm0, YMMWORD PTR [reg_p1+4*r10]         // U = a[j]->a[j+7]
  vpermd     ymm1, ymm15, ymm0 
  vpermd     ymm0, ymm13, ymm0  
  vpsubd     ymm3, ymm0, ymm1                         // U - V
  vpaddd     ymm0, ymm0, ymm1                         // U + V 
  vpmuldq    ymm3, ymm3, ymm8                         // (U - V).S
  vmovdqu    ymm4, ymm3
  vpand      ymm3, ymm14, ymm3                        // c0
  vpsrlq     ymm4, ymm4, 12                           // c1
  vpslld     ymm5, ymm3, 1                            // 2*c0
  vpsubd     ymm4, ymm3, ymm4                         // c0-c1
  vpaddd     ymm1, ymm4, ymm5                         // 3*c0-c1
  vpslldq    ymm1, ymm1, 4    
  vpblendd   ymm0, ymm0, ymm1, 0xaa
  vpermd     ymm0, ymm9, ymm0 
  vmovdqu    YMMWORD PTR [reg_p1+4*r10], ymm0
  
  vpermq     ymm8, ymm2, 0xfa   
  vmovdqu    ymm0, YMMWORD PTR [reg_p1+4*r10+32]      // U = a[j]->a[j+7]
  vpermd     ymm1, ymm15, ymm0 
  vpermd     ymm0, ymm13, ymm0  
  vpsubd     ymm3, ymm0, ymm1                         // U - V
  vpaddd     ymm0, ymm0, ymm1                         // U + V 
  vpmuldq    ymm3, ymm3, ymm8                         // (U - V).S
  vmovdqu    ymm4, ymm3
  vpand      ymm3, ymm14, ymm3                        // c0
  vpsrlq     ymm4, ymm4, 12                           // c1
  vpslld     ymm5, ymm3, 1                            // 2*c0
  vpsubd     ymm4, ymm3, ymm4                         // c0-c1
  vpaddd     ymm1, ymm4, ymm5                         // 3*c0-c1
  vpslldq    ymm1, ymm1, 4    
  vpblendd   ymm0, ymm0, ymm1, 0xaa
  vpermd     ymm0, ymm9, ymm0
  vmovdqu    YMMWORD PTR [reg_p1+4*r10+32], ymm0

  vpmovsxdq  ymm2, XMMWORD PTR [reg_p2+4*r15+4*256+16]// S = psi[m+i]->psi[m+i+3] 
  vpermq     ymm8, ymm2, 0x50   
  vmovdqu    ymm0, YMMWORD PTR [reg_p1+4*r10+64]      // U = a[j]->a[j+7]
  vpermd     ymm1, ymm15, ymm0 
  vpermd     ymm0, ymm13, ymm0  
  vpsubd     ymm3, ymm0, ymm1                         // U - V
  vpaddd     ymm0, ymm0, ymm1                         // U + V 
  vpmuldq    ymm3, ymm3, ymm8                         // (U - V).S
  vmovdqu    ymm4, ymm3
  vpand      ymm3, ymm14, ymm3                        // c0
  vpsrlq     ymm4, ymm4, 12                           // c1
  vpslld     ymm5, ymm3, 1                            // 2*c0
  vpsubd     ymm4, ymm3, ymm4                         // c0-c1
  vpaddd     ymm1, ymm4, ymm5                         // 3*c0-c1
  vpslldq    ymm1, ymm1, 4    
  vpblendd   ymm0, ymm0, ymm1, 0xaa
  vpermd     ymm0, ymm9, ymm0
  vmovdqu    YMMWORD PTR [reg_p1+4*r10+64], ymm0
         
  vpermq     ymm8, ymm2, 0xfa   
  vmovdqu    ymm0, YMMWORD PTR [reg_p1+4*r10+96]      // U = a[j]->a[j+7]
  vpermd     ymm1, ymm15, ymm0 
  vpermd     ymm0, ymm13, ymm0  
  vpsubd     ymm3, ymm0, ymm1                         // U - V
  vpaddd     ymm0, ymm0, ymm1                         // U + V 
  vpmuldq    ymm3, ymm3, ymm8                         // (U - V).S
  vmovdqu    ymm4, ymm3
  vpand      ymm3, ymm14, ymm3                        // c0
  vpsrlq     ymm4, ymm4, 12                           // c1
  vpslld     ymm5, ymm3, 1                            // 2*c0
  vpsubd     ymm4, ymm3, ymm4                         // c0-c1
  vpaddd     ymm1, ymm4, ymm5                         // 3*c0-c1
  vpslldq    ymm1, ymm1, 4    
  vpblendd   ymm0, ymm0, ymm1, 0xaa
  vpermd     ymm0, ymm9, ymm0
  vmovdqu    YMMWORD PTR [reg_p1+4*r10+96], ymm0
         
  add        r10, r14        // j+32
  add        r15, r13        // i+8
  cmp        r15, r12
  jl         loop2b
     
// Stage m=256 
  vmovdqu    ymm12, PERM0246   
  shr        r12, 1          // n/8 = 128
  xor        r15, r15        // i = 0
  xor        r10, r10        // j1 = 0
loop3b:
  vbroadcastss ymm2, DWORD PTR [reg_p2+4*r15+4*128]   // S
  vpmovsxdq  ymm1, XMMWORD PTR [reg_p1+4*r10+16]      // V = a[j+k]
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*r10]         // U = a[j]
  vpsubd     ymm3, ymm0, ymm1                         // U - V
  vpaddd     ymm0, ymm0, ymm1                         // U + V 
  vpmuldq    ymm3, ymm3, ymm2                         // (U - V).S
  vmovdqu    ymm4, ymm3
  vpand      ymm3, ymm14, ymm3                        // c0
  vpsrlq     ymm4, ymm4, 12                           // c1
  vpslld     ymm5, ymm3, 1                            // 2*c0
  vpsubd     ymm4, ymm3, ymm4                         // c0-c1
  vpaddd     ymm1, ymm4, ymm5                         // 3*c0-c1 
  vpermd     ymm0, ymm12, ymm0 
  vpermd     ymm1, ymm12, ymm1 
  vmovdqu    XMMWORD PTR [reg_p1+4*r10], xmm0
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+16], xmm1
  
  add        r10, r13        // j+8
  inc        r15             // i+1
  cmp        r15, r12
  jl         loop3b
     
// Stage m=128
  shr        r12, 1          // n/16 = 64
  xor        r15, r15        // i = 0
  xor        r10, r10        // j1 = 0
  mov        r14, 16 
loop4b:
  vbroadcastss ymm11, DWORD PTR [reg_p2+4*r15+4*64]   // S
  vpmovsxdq  ymm13, XMMWORD PTR [reg_p1+4*r10+32]     // V = a[j+k]
  vpmovsxdq  ymm15, XMMWORD PTR [reg_p1+4*r10+48]     // V = a[j+k]
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*r10]         // U = a[j]
  vpmovsxdq  ymm2, XMMWORD PTR [reg_p1+4*r10+16]      // U = a[j]
  vpsubd     ymm1, ymm0, ymm13                        // U - V
  vpaddd     ymm0, ymm0, ymm13                        // U + V 
  vpsubd     ymm3, ymm2, ymm15                        // U - V
  vpaddd     ymm2, ymm2, ymm15                        // U + V   
  vpmuldq    ymm1, ymm1, ymm11                        // (U - V).S
  vpmuldq    ymm3, ymm3, ymm11                        // (U - V).S
  
  vmovdqu    ymm13, ymm1
  vpand      ymm1, ymm14, ymm1                        // c0
  vpsrlq     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm1, 1                           // 2*c0
  vpsubd     ymm13, ymm1, ymm13                       // c0-c1
  vpaddd     ymm1, ymm13, ymm15                       // 3*c0-c1    

  vmovdqu    ymm13, ymm3
  vpand      ymm3, ymm14, ymm3                        // c0
  vpsrlq     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm3, 1                           // 2*c0
  vpsubd     ymm13, ymm3, ymm13                       // c0-c1
  vpaddd     ymm3, ymm13, ymm15                       // 3*c0-c1 
  
  vpermd     ymm0, ymm12, ymm0 
  vpermd     ymm1, ymm12, ymm1 
  vpermd     ymm2, ymm12, ymm2 
  vpermd     ymm3, ymm12, ymm3 
  vmovdqu    XMMWORD PTR [reg_p1+4*r10], xmm0
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+32], xmm1
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+16], xmm2
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+48], xmm3
  
  add        r10, r14        // j+16 
  inc        r15             // i+1
  cmp        r15, r12
  jl         loop4b
  
// Stages m=64 -> m=4  
  mov        r9, 5            // 5 iterations
  mov        rax, 8 
loop5b:
  shl        rax, 1          // k = 2*k
  shr        r12, 1          // m/2
  xor        r15, r15        // i = 0
  xor        r8, r8        
loop6b:
  mov        r10, r8         // Load j1
  mov        r11, rax
  dec        r11
  add        r11, r10        // j2
  mov        r13, r12
  add        r13, r15        // m/2+i
  vbroadcastss ymm9, DWORD PTR [reg_p2+4*r13]         // S
  mov        rbx, 4

loop7b:
  mov        r13, r10
  add        r13, rax         // j+k
  vpmovsxdq  ymm10, XMMWORD PTR [reg_p1+4*r13]        // V = a[j+k]
  vpmovsxdq  ymm11, XMMWORD PTR [reg_p1+4*r13+16]     // V = a[j+k]
  vpmovsxdq  ymm13, XMMWORD PTR [reg_p1+4*r13+32]     // V = a[j+k]
  vpmovsxdq  ymm15, XMMWORD PTR [reg_p1+4*r13+48]     // V = a[j+k]
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*r10]         // U = a[j]
  vpmovsxdq  ymm2, XMMWORD PTR [reg_p1+4*r10+16]      // U = a[j]
  vpmovsxdq  ymm4, XMMWORD PTR [reg_p1+4*r10+32]      // U = a[j]
  vpmovsxdq  ymm6, XMMWORD PTR [reg_p1+4*r10+48]      // U = a[j]
  
  vpsubd     ymm1, ymm0, ymm10                        // U - V
  vpaddd     ymm0, ymm0, ymm10                        // U + V 
  vpsubd     ymm3, ymm2, ymm11                        // U - V
  vpaddd     ymm2, ymm2, ymm11                        // U + V 
  vpsubd     ymm5, ymm4, ymm13                        // U - V
  vpaddd     ymm4, ymm4, ymm13                        // U + V 
  vpsubd     ymm7, ymm6, ymm15                        // U - V
  vpaddd     ymm6, ymm6, ymm15                        // U + V 

  vpmuldq    ymm1, ymm1, ymm9                         // (U - V).S
  vpmuldq    ymm3, ymm3, ymm9                   
  vpmuldq    ymm5, ymm5, ymm9                   
  vpmuldq    ymm7, ymm7, ymm9   
  
  vmovdqu    ymm13, ymm1
  vpand      ymm1, ymm14, ymm1                        // c0
  vpsrlq     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm1, 1                           // 2*c0
  vpsubd     ymm13, ymm1, ymm13                       // c0-c1
  vpaddd     ymm1, ymm13, ymm15                       // 3*c0-c1 

  cmp        r9, rbx 
  jne        skip1
  vmovdqu    ymm13, ymm0
  vpand      ymm0, ymm14, ymm0                        // c0
  vpsrad     ymm13, ymm13, 12                         // c1       
  vpslld     ymm15, ymm0, 1                           // 2*c0
  vpsubd     ymm13, ymm0, ymm13                       // c0-c1
  vpaddd     ymm0, ymm13, ymm15                       // 3*c0-c1

  vmovdqu    ymm13, ymm1
  vpand      ymm1, ymm14, ymm1                        // c0
  vpsrad     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm1, 1                           // 2*c0
  vpsubd     ymm13, ymm1, ymm13                       // c0-c1
  vpaddd     ymm1, ymm13, ymm15                       // 3*c0-c1
skip1:
  vpermd     ymm1, ymm12, ymm1 
  vpermd     ymm0, ymm12, ymm0 

  vmovdqu    ymm13, ymm3
  vpand      ymm3, ymm14, ymm3                        // c0
  vpsrlq     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm3, 1                           // 2*c0
  vpsubd     ymm13, ymm3, ymm13                       // c0-c1
  vpaddd     ymm3, ymm13, ymm15                       // 3*c0-c1 
  vmovdqu    XMMWORD PTR [reg_p1+4*r10], xmm0
  vmovdqu    XMMWORD PTR [reg_p1+4*r13], xmm1 

  cmp        r9, rbx 
  jne        skip2
  vmovdqu    ymm13, ymm2
  vpand      ymm2, ymm14, ymm2                        // c0
  vpsrad     ymm13, ymm13, 12                         // c1       
  vpslld     ymm15, ymm2, 1                           // 2*c0
  vpsubd     ymm13, ymm2, ymm13                       // c0-c1
  vpaddd     ymm2, ymm13, ymm15                       // 3*c0-c1

  vmovdqu    ymm13, ymm3
  vpand      ymm3, ymm14, ymm3                        // c0
  vpsrad     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm3, 1                           // 2*c0
  vpsubd     ymm13, ymm3, ymm13                       // c0-c1
  vpaddd     ymm3, ymm13, ymm15                       // 3*c0-c1
skip2:
  vpermd     ymm3, ymm12, ymm3 
  vpermd     ymm2, ymm12, ymm2 

  vmovdqu    ymm13, ymm5
  vpand      ymm5, ymm14, ymm5                        // c0
  vpsrlq     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm5, 1                           // 2*c0
  vpsubd     ymm13, ymm5, ymm13                       // c0-c1
  vpaddd     ymm5, ymm13, ymm15                       // 3*c0-c1 
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+16], xmm2
  vmovdqu    XMMWORD PTR [reg_p1+4*r13+16], xmm3 

  cmp        r9, rbx 
  jne        skip3
  vmovdqu    ymm13, ymm4
  vpand      ymm4, ymm14, ymm4                        // c0
  vpsrad     ymm13, ymm13, 12                         // c1       
  vpslld     ymm15, ymm4, 1                           // 2*c0
  vpsubd     ymm13, ymm4, ymm13                       // c0-c1
  vpaddd     ymm4, ymm13, ymm15                       // 3*c0-c1

  vmovdqu    ymm13, ymm5
  vpand      ymm5, ymm14, ymm5                        // c0
  vpsrad     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm5, 1                           // 2*c0
  vpsubd     ymm13, ymm5, ymm13                       // c0-c1
  vpaddd     ymm5, ymm13, ymm15                       // 3*c0-c1
skip3:
  vpermd     ymm5, ymm12, ymm5 
  vpermd     ymm4, ymm12, ymm4 

  vmovdqu    ymm13, ymm7
  vpand      ymm7, ymm14, ymm7                        // c0
  vpsrlq     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm7, 1                           // 2*c0
  vpsubd     ymm13, ymm7, ymm13                       // c0-c1
  vpaddd     ymm7, ymm13, ymm15                       // 3*c0-c1 
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+32], xmm4
  vmovdqu    XMMWORD PTR [reg_p1+4*r13+32], xmm5  

  cmp        r9, rbx 
  jne        skip4
  vmovdqu    ymm13, ymm6
  vpand      ymm6, ymm14, ymm6                        // c0
  vpsrad     ymm13, ymm13, 12                         // c1       
  vpslld     ymm15, ymm6, 1                           // 2*c0
  vpsubd     ymm13, ymm6, ymm13                       // c0-c1
  vpaddd     ymm6, ymm13, ymm15                       // 3*c0-c1

  vmovdqu    ymm13, ymm7
  vpand      ymm7, ymm14, ymm7                        // c0
  vpsrad     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm7, 1                           // 2*c0
  vpsubd     ymm13, ymm7, ymm13                       // c0-c1
  vpaddd     ymm7, ymm13, ymm15                       // 3*c0-c1
skip4:
  vpermd     ymm7, ymm12, ymm7 
  vpermd     ymm6, ymm12, ymm6   
  vmovdqu    XMMWORD PTR [reg_p1+4*r13+48], xmm7
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+48], xmm6
  
  add        r10, r14
  cmp        r10, r11
  jl         loop7b
  mov        rbx, rax
  shl        rbx, 1          // 2*k
  add        r8, rbx         // j1+2*k
  inc        r15
  cmp        r15, r12
  jl         loop6b
  dec        r9
  jnz        loop5b
       
// Scaling step
  shl        rax, 1          // k = 2*k = 512
  xor        r10, r10        // j = 0
  mov        r14, 4 
  movq       xmm0, reg_p3
  vbroadcastsd ymm10, xmm0                            // S = omegainv1N_rev
  movq       xmm0, reg_p4
  vbroadcastsd ymm11, xmm0                            // T = Ninv
loop8b:
  vpmovsxdq  ymm13, XMMWORD PTR [reg_p1+4*r10+4*512]  // V = a[j+k]
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*r10]         // U = a[j]
  vpsubd     ymm1, ymm0, ymm13                        // U - V
  vpaddd     ymm0, ymm0, ymm13                        // U + V  
  vpmuldq    ymm1, ymm1, ymm10                        // (U - V).S
  vpmuldq    ymm0, ymm0, ymm11                        // (U + V).T
  
  vmovdqu    ymm13, ymm0
  vpand      ymm0, ymm14, ymm0                        // c0
  vpsrlq     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm0, 1                           // 2*c0
  vpsubd     ymm13, ymm0, ymm13                       // c0-c1
  vpaddd     ymm0, ymm13, ymm15                       // 3*c0-c1    

  vmovdqu    ymm13, ymm1
  vpand      ymm1, ymm14, ymm1                        // c0
  vpsrlq     ymm13, ymm13, 12                         // c1
  vpslld     ymm15, ymm1, 1                           // 2*c0
  vpsubd     ymm13, ymm1, ymm13                       // c0-c1
  vpaddd     ymm1, ymm13, ymm15                       // 3*c0-c1 
  
  vpermd     ymm0, ymm12, ymm0 
  vpermd     ymm1, ymm12, ymm1 
  vmovdqu    XMMWORD PTR [reg_p1+4*r10], xmm0
  vmovdqu    XMMWORD PTR [reg_p1+4*r10+4*512], xmm1
  
  add        r10, r14        // j+4 
  cmp        r10, rax
  jl         loop8b  
loop9b:
  pop        rbx
  pop        r15
  pop        r14
  pop        r13
  pop        r12
  ret


//***********************************************************************
//  Component-wise multiplication and addition
//  Operation: d [reg_p4] <- a [reg_p1] * b [reg_p2] + c [reg_p3]
//             reg_p5 contains parameter n
//*********************************************************************** 
.globl oqs_rlwe_msrln16_pmuladd_asm
oqs_rlwe_msrln16_pmuladd_asm:
  vmovdqu    ymm5, PERM0246
  vmovdqu    ymm6, MASK12x8 
  xor        rax, rax
  movq       r11, 4
lazo2:
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*rax]   // a
  vpmovsxdq  ymm1, XMMWORD PTR [reg_p2+4*rax]   // b
  vpmovsxdq  ymm2, XMMWORD PTR [reg_p3+4*rax]   // c
  vpmuldq    ymm0, ymm1, ymm0 
  vpaddq     ymm0, ymm2, ymm0                    

  vmovdqu    ymm3, ymm0
  vpand      ymm0, ymm6, ymm0                   // c0
  vpsrlq     ymm3, ymm3, 12                     // c1
  vpslld     ymm4, ymm0, 1                      // 2*c0
  vpsubd     ymm3, ymm0, ymm3                   // c0-c1
  vpaddd     ymm0, ymm3, ymm4                   // 3*c0-c1 

  vmovdqu    ymm3, ymm0
  vpand      ymm0, ymm6, ymm0                   // c0
  vpsrad     ymm3, ymm3, 12                     // c1       
  vpslld     ymm4, ymm0, 1                      // 2*c0
  vpsubd     ymm3, ymm0, ymm3                   // c0-c1
  vpaddd     ymm0, ymm3, ymm4                   // 3*c0-c1

  vpermd     ymm0, ymm5, ymm0 
  vmovdqu    XMMWORD PTR [reg_p4+4*rax], xmm0

  add        rax, r11                           // j+4
  cmp        rax, reg_p5
  jl         lazo2
  ret


//***********************************************************************
//  Component-wise multiplication
//  Operation: c [reg_p3] <- a [reg_p1] * b [reg_p2]
//             reg_p4 contains parameter n
//*********************************************************************** 
.globl oqs_rlwe_msrln16_pmul_asm
oqs_rlwe_msrln16_pmul_asm: 
  vmovdqu    ymm5, PERM0246
  vmovdqu    ymm6, MASK12x8 
  xor        rax, rax
  movq       r11, 4
lazo3:
  vpmovsxdq  ymm0, XMMWORD PTR [reg_p1+4*rax]   // a
  vpmovsxdq  ymm1, XMMWORD PTR [reg_p2+4*rax]   // b
  vpmuldq    ymm0, ymm1, ymm0                    

  vmovdqu    ymm3, ymm0
  vpand      ymm0, ymm6, ymm0                   // c0
  vpsrlq     ymm3, ymm3, 12                     // c1
  vpslld     ymm4, ymm0, 1                      // 2*c0
  vpsubd     ymm3, ymm0, ymm3                   // c0-c1
  vpaddd     ymm0, ymm3, ymm4                   // 3*c0-c1 

  vmovdqu    ymm3, ymm0
  vpand      ymm0, ymm6, ymm0                   // c0
  vpsrad     ymm3, ymm3, 12                     // c1       
  vpslld     ymm4, ymm0, 1                      // 2*c0
  vpsubd     ymm3, ymm0, ymm3                   // c0-c1
  vpaddd     ymm0, ymm3, ymm4                   // 3*c0-c1

  vpermd     ymm0, ymm5, ymm0 
  vmovdqu    XMMWORD PTR [reg_p3+4*rax], xmm0

  add        rax, r11                           // j+4
  cmp        rax, reg_p4
  jl         lazo3
  ret


//***********************************************************************
//  Two consecutive reductions
//  Operation: c [reg_p1] <- a [reg_p1]
//             reg_p2 contains parameter n
//*********************************************************************** 
.globl oqs_rlwe_msrln16_two_reduce12289_asm
oqs_rlwe_msrln16_two_reduce12289_asm: 
  vmovdqu    ymm6, MASK12x8 
  vmovdqu    ymm7, PRIME8x
  xor        rax, rax
  movq       r11, 8
lazo4:
  vmovdqu    ymm0, YMMWORD PTR [reg_p1+4*rax]   // a

  vmovdqu    ymm3, ymm0
  vpand      ymm0, ymm6, ymm0                   // c0
  vpsrad     ymm3, ymm3, 12                     // c1
  vpslld     ymm4, ymm0, 1                      // 2*c0
  vpsubd     ymm3, ymm0, ymm3                   // c0-c1
  vpaddd     ymm0, ymm3, ymm4                   // 3*c0-c1 

  vmovdqu    ymm3, ymm0
  vpand      ymm0, ymm6, ymm0                   // c0
  vpsrad     ymm3, ymm3, 12                     // c1       
  vpslld     ymm4, ymm0, 1                      // 2*c0
  vpsubd     ymm3, ymm0, ymm3                   // c0-c1
  vpaddd     ymm0, ymm3, ymm4                   // 3*c0-c1

  vpsrad     ymm2, ymm0, 31
  vpand      ymm2, ymm7, ymm2
  vpaddd     ymm2, ymm0, ymm2
  vpsubd     ymm0, ymm2, ymm7

  vpsrad     ymm2, ymm0, 31
  vpand      ymm2, ymm7, ymm2
  vpaddd     ymm0, ymm0, ymm2

  vmovdqu    YMMWORD PTR [reg_p1+4*rax], ymm0

  add        rax, r11                           // j+8
  cmp        rax, reg_p2
  jl         lazo4
  ret


//***********************************************************************
//  Encoding
//  Operation: c [reg_p2] <- a [reg_p1]
//*********************************************************************** 
.globl oqs_rlwe_msrln16_encode_asm
oqs_rlwe_msrln16_encode_asm: 
  vmovdqu    ymm6, MASK32 
  vmovdqu    ymm7, MASK42
  mov        r9, 1024
  xor        rax, rax
  xor        r10, r10
  mov        r11, 14
  mov        rcx, 8
lazo5:
  vmovdqu    ymm0, YMMWORD PTR [reg_p1+4*rax]   // a

  vpsrlq     ymm1, ymm0, 18  
  vpsllq     ymm2, ymm0, 4
  vpand      ymm0, ymm0, ymm6
  vpsrldq    ymm2, ymm2, 5   
  vpsrlq     ymm3, ymm1, 4
  vpand      ymm1, ymm1, ymm6
  vpand      ymm2, ymm2, ymm7
  vpsrldq    ymm3, ymm3, 4 
  vpor       ymm0, ymm0, ymm1
  vpor       ymm0, ymm0, ymm2 
  vpor       ymm0, ymm0, ymm3 
  vpermq     ymm1, ymm0, 0x0e   

  vmovdqu    XMMWORD PTR [reg_p2+r10], xmm0
  vmovdqu    XMMWORD PTR [reg_p2+r10+7], xmm1

  add        r10, r11
  add        rax, rcx        // j+8
  cmp        rax, r9
  jl         lazo5
  ret


//***********************************************************************
//  Decoding
//  Operation: c [reg_p2] <- a [reg_p1]
//*********************************************************************** 
.globl oqs_rlwe_msrln16_decode_asm
oqs_rlwe_msrln16_decode_asm: 
  vmovdqu    ymm6, MASK14_1 
  vmovdqu    ymm7, MASK14_2
  vmovdqu    ymm8, MASK14_3
  vmovdqu    ymm9, MASK14_4
  mov        r9, 1024
  xor        rax, rax
  xor        r10, r10
  mov        r11, 14
  mov        rcx, 8
lazo6:
  vmovdqu    xmm0, XMMWORD PTR [reg_p1+r10]
  vmovdqu    xmm1, XMMWORD PTR [reg_p1+r10+7]
  vinserti128 ymm0, ymm0, xmm1, 1               

  vpand      ymm1, ymm0, ymm6
  vpand      ymm2, ymm0, ymm7
  vpand      ymm3, ymm0, ymm8
  vpand      ymm4, ymm0, ymm9
   
  vpsllq     ymm2, ymm2, 18 
  vpsllq     ymm3, ymm3, 4
  vpslldq    ymm3, ymm3, 4 
  vpsrlq     ymm4, ymm4, 2
  vpslldq    ymm4, ymm4, 7

  vpor       ymm1, ymm1, ymm2 
  vpor       ymm1, ymm1, ymm3 
  vpor       ymm1, ymm1, ymm4 
  
  vmovdqu    YMMWORD PTR [reg_p2+4*rax], ymm1   

  add        r10, r11
  add        rax, rcx            // j+8
  cmp        rax, r9
  jl         lazo6
  ret
