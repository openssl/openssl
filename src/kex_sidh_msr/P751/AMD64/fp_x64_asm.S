//*******************************************************************************************
// SIDH: an efficient supersingular isogeny cryptography library
//
// Abstract: field arithmetic in x64 assembly for P751 on Linux 
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
// p751 x 2
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
.global fpadd751_asm
fpadd751_asm:
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
.global fpsub751_asm
fpsub751_asm:
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


  #ifdef _MULX_	

///////////////////////////////////////////////////////////////// MACRO
// Schoolbook integer multiplication
// Inputs:  memory pointers M0 and M1
// Outputs: memory pointer C
// Temps:   stack pointer for 15 64-bit values, regs T0:T7
/////////////////////////////////////////////////////////////////
#if _ADX_
.macro MUL384_SCHOOL M0, M1, C, S, T0, T1, T2, T3, T4, T5, T6, T7 
    mov    rdx, \M0
    mulx   \T0, \T1, \M1    
    mulx   \T2, \T3, 8\M1
    mov    \C, \T1             // C0_final 
    xor    rax, rax
    mulx   \T4, \T5, 16\M1 
    adox   \T0, \T3               
    adox   \T2, \T5     
    mulx   \T1, \T3, 24\M1
    adox   \T4, \T3         
    mulx   \T5, \T6, 32\M1 
    adox   \T1, \T6        
    mulx   \T3, \T7, 40\M1    
    adox   \T5, \T7       
    adox   \T3, rax        
	
    mov    rdx, 8\M0 
    mulx   \T6, \T7, \M1 
    adcx   \T0, \T7 
    mov    8\C, \T0            // C1_final 
    adcx   \T2, \T6     
    mulx   \T6, \T7, 8\M1
    mov    \S, \T7             // store T7
    adcx   \T4, \T6        
    mulx   \T0, \T6, 16\M1   
    mov    8\S, \T6            // store T6 
    adcx   \T0, \T1     
    mulx   \T1, \T7, 24\M1   
    adcx   \T1, \T5  
    mulx   \T5, \T6, 32\M1     
    adcx   \T3, \T5   
    mulx   \T5, rdx, 40\M1
    adcx   \T5, rax 
		
    xor    rax, rax
    adox   \T2, \S 
    adox   \T4, 8\S  
    adox   \T0, \T7  
    adox   \T1, \T6  
    adox   \T3, rdx  
    adox   \T5, rax         
	
    mov    rdx, 16\M0 
    mulx   \T6, \T7, \M1 
    adcx   \T2, \T7 
    mov    16\C, \T2           // C2_final 
    adcx   \T4, \T6     
    mulx   \T6, \T7, 8\M1
    mov    \S, \T7             // store T7
    adcx   \T0, \T6        
    mulx   \T2, \T6, 16\M1   
    mov    8\S, \T6            // store T6 
    adcx   \T1, \T2     
    mulx   \T2, \T7, 24\M1   
    adcx   \T3, \T2  
    mulx   \T2, \T6, 32\M1     
    adcx   \T5, \T2   
    mulx   \T2, rdx, 40\M1     
    adcx   \T2, rax 
		
    xor    rax, rax
    adox   \T4, \S 
    adox   \T0, 8\S  
    adox   \T1, \T7  
    adox   \T3, \T6  
    adox   \T5, rdx 
    adox   \T2, rax           
	
    mov    rdx, 24\M0 
    mulx   \T6, \T7, \M1 
    adcx   \T4, \T7 
    mov    24\C, \T4           // C3_final 
    adcx   \T0, \T6     
    mulx   \T6, \T7, 8\M1
    mov    \S, \T7             // store T7
    adcx   \T1, \T6        
    mulx   \T4, \T6, 16\M1   
    mov    8\S, \T6            // store T6 
    adcx   \T3, \T4     
    mulx   \T4, \T7, 24\M1   
    adcx   \T5, \T4  
    mulx   \T4, \T6, 32\M1     
    adcx   \T2, \T4   
    mulx   \T4, rdx, 40\M1     
    adcx   \T4, rax
		
    xor    rax, rax
    adox   \T0, \S 
    adox   \T1, 8\S  
    adox   \T3, \T7  
    adox   \T5, \T6  
    adox   \T2, rdx  
    adox   \T4, rax         
	
    mov    rdx, 32\M0 
    mulx   \T6, \T7, \M1 
    adcx   \T0, \T7 
    mov    32\C, \T0           // C4_final 
    adcx   \T1, \T6     
    mulx   \T6, \T7, 8\M1
    mov    \S, \T7             // store T7
    adcx   \T3, \T6        
    mulx   \T0, \T6, 16\M1   
    mov    8\S, \T6            // store T6 
    adcx   \T5, \T0     
    mulx   \T0, \T7, 24\M1   
    adcx   \T2, \T0  
    mulx   \T0, \T6, 32\M1     
    adcx   \T4, \T0   
    mulx   \T0, rdx, 40\M1     
    adcx   \T0, rax 
		
    xor    rax, rax
    adox   \T1, \S 
    adox   \T3, 8\S  
    adox   \T5, \T7  
    adox   \T2, \T6  
    adox   \T4, rdx  
    adox   \T0, rax           
	
    mov    rdx, 40\M0 
    mulx   \T6, \T7, \M1 
    adcx   \T1, \T7 
    mov    40\C, \T1           // C5_final 
    adcx   \T3, \T6     
    mulx   \T6, \T7, 8\M1
    mov    \S, \T7             // store T7
    adcx   \T5, \T6        
    mulx   \T1, \T6, 16\M1   
    mov    8\S, \T6            // store T6 
    adcx   \T2, \T1     
    mulx   \T1, \T7, 24\M1   
    adcx   \T4, \T1  
    mulx   \T1, \T6, 32\M1     
    adcx   \T0, \T1   
    mulx   \T1, rdx, 40\M1     
    adcx   \T1, rax 
		
    add    \T3, \S 
    adc    \T5, 8\S  
    adc    \T2, \T7 
    adc    \T4, \T6 
    adc    \T0, rdx 
    adc    \T1, 0 
    mov    48\C, \T3 
    mov    56\C, \T5 
    mov    64\C, \T2 
    mov    72\C, \T4
    mov    80\C, \T0 
    mov    88\C, \T1 
.endm

#else

.macro MUL384_SCHOOL M0, M1, C, S, T0, T1, T2, T3, T4, T5, T6, T7 
    mov    rdx, \M0
    mulx   \T0, \T1, \M1    
    mulx   \T2, \T3, 8\M1
    mov    \C, \T1             // C0_final 
    mulx   \T4, \T5, 16\M1 
    add    \T0, \T3               
    adc    \T2, \T5     
    mulx   \T1, \T3, 24\M1
    adc    \T4, \T3         
    mulx   \T5, \T6, 32\M1 
    adc    \T1, \T6        
    mulx   \T3, \T7, 40\M1    
    adc    \T5, \T7       
    adc    \T3, 0         
	
    mov    rdx, 8\M0 
    mulx   \T6, \T7, \M1 
    add    \T0, \T7 
    mov    8\C, \T0            // C1_final 
    adc    \T2, \T6     
    mulx   \T6, \T7, 8\M1
    mov    \S, \T7             // store T7
    adc    \T4, \T6        
    mulx   \T0, \T6, 16\M1   
    mov    8\S, \T6            // store T6 
    adc    \T0, \T1     
    mulx   \T1, rax, 24\M1   
    adc    \T1, \T5  
    mulx   \T5, \T7, 32\M1     
    adc    \T3, \T5   
    mulx   \T5, \T6, 40\M1     
    adc    \T5, 0 
		
    add    \T2, \S 
    adc    \T4, 8\S  
    adc    \T0, rax  
    adc    \T1, \T7  
    adc    \T3, \T6  
    adc    \T5, 0          
	
    mov    rdx, 16\M0 
    mulx   \T6, \T7, \M1 
    add    \T2, \T7 
    mov    16\C, \T2           // C2_final 
    adc    \T4, \T6     
    mulx   \T6, \T7, 8\M1
    mov    \S, \T7             // store T7
    adc    \T0, \T6        
    mulx   \T2, \T6, 16\M1   
    mov    8\S, \T6            // store T6 
    adc    \T1, \T2     
    mulx   \T2, rax, 24\M1   
    adc    \T3, \T2  
    mulx   \T2, \T7, 32\M1     
    adc    \T5, \T2   
    mulx   \T2, \T6, 40\M1     
    adc    \T2, 0 
		
    add    \T4, \S 
    adc    \T0, 8\S  
    adc    \T1, rax  
    adc    \T3, \T7  
    adc    \T5, \T6  
    adc    \T2, 0           
	
    mov    rdx, 24\M0 
    mulx   \T6, \T7, \M1 
    add    \T4, \T7 
    mov    24\C, \T4           // C3_final 
    adc    \T0, \T6     
    mulx   \T6, \T7, 8\M1
    mov    \S, \T7             // store T7
    adc    \T1, \T6        
    mulx   \T4, \T6, 16\M1   
    mov    8\S, \T6            // store T6 
    adc    \T3, \T4     
    mulx   \T4, rax, 24\M1   
    adc    \T5, \T4  
    mulx   \T4, \T7, 32\M1     
    adc    \T2, \T4   
    mulx   \T4, \T6, 40\M1     
    adc    \T4, 0 
		
    add    \T0, \S 
    adc    \T1, 8\S  
    adc    \T3, rax  
    adc    \T5, \T7  
    adc    \T2, \T6  
    adc    \T4, 0         
	
    mov    rdx, 32\M0 
    mulx   \T6, \T7, \M1 
    add    \T0, \T7 
    mov    32\C, \T0           // C4_final 
    adc    \T1, \T6     
    mulx   \T6, \T7, 8\M1
    mov    \S, \T7             // store T7
    adc    \T3, \T6        
    mulx   \T0, \T6, 16\M1   
    mov    8\S, \T6            // store T6 
    adc    \T5, \T0     
    mulx   \T0, rax, 24\M1   
    adc    \T2, \T0  
    mulx   \T0, \T7, 32\M1     
    adc    \T4, \T0   
    mulx   \T0, \T6, 40\M1     
    adc    \T0, 0 
		
    add    \T1, \S 
    adc    \T3, 8\S  
    adc    \T5, rax  
    adc    \T2, \T7  
    adc    \T4, \T6  
    adc    \T0, 0           
	
    mov    rdx, 40\M0 
    mulx   \T6, \T7, \M1 
    add    \T1, \T7 
    mov    40\C, \T1           // C5_final 
    adc    \T3, \T6     
    mulx   \T6, \T7, 8\M1
    mov    \S, \T7             // store T7
    adc    \T5, \T6        
    mulx   \T1, \T6, 16\M1   
    mov    8\S, \T6            // store T6 
    adc    \T2, \T1     
    mulx   \T1, rax, 24\M1   
    adc    \T4, \T1  
    mulx   \T1, \T7, 32\M1     
    adc    \T0, \T1   
    mulx   \T1, \T6, 40\M1     
    adc    \T1, 0 
		
    add    \T3, \S 
    mov    48\C, \T3 
    adc    \T5, 8\S 
    mov    56\C, \T5  
    adc    \T2, rax
    mov    64\C, \T2  
    adc    \T4, \T7  
    mov    72\C, \T4
    adc    \T0, \T6 
    mov    80\C, \T0 
    adc    \T1, 0
    mov    88\C, \T1 
.endm
#endif


//*****************************************************************************
//  751-bit multiplication using Karatsuba (one level), schoolbook (two levels)
//***************************************************************************** 
.global mul751_asm
mul751_asm:    
    push   r12
    push   r13 
    push   r14 
    push   r15
    mov    rcx, reg_p3 

    // [rsp] <- AH + AL, rax <- mask
    xor    rax, rax
    mov    r8, [reg_p1]
    mov    r9, [reg_p1+8]
    mov    r10, [reg_p1+16]
    mov    r11, [reg_p1+24] 
    mov    r12, [reg_p1+32] 
    mov    r13, [reg_p1+40] 
    push   rbx 
    push   rbp
    sub    rsp, 152
    add    r8, [reg_p1+48]
    adc    r9, [reg_p1+56]
    adc    r10, [reg_p1+64]
    adc    r11, [reg_p1+72]
    adc    r12, [reg_p1+80]
    adc    r13, [reg_p1+88]
    sbb    rax, 0
    mov    [rsp], r8
    mov    [rsp+8], r9
    mov    [rsp+16], r10
    mov    [rsp+24], r11
    mov    [rsp+32], r12
    mov    [rsp+40], r13

    // [rsp+48] <- BH + BL, rdx <- mask
    xor    rdx, rdx
    mov    r8, [reg_p2]
    mov    r9, [reg_p2+8]
    mov    rbx, [reg_p2+16]
    mov    rbp, [reg_p2+24] 
    mov    r14, [reg_p2+32]     
    mov    r15, [reg_p2+40]     
    add    r8, [reg_p2+48]
    adc    r9, [reg_p2+56]
    adc    rbx, [reg_p2+64]
    adc    rbp, [reg_p2+72]
    adc    r14, [reg_p2+80]
    adc    r15, [reg_p2+88]
    sbb    rdx, 0
    mov    [rsp+48], r8
    mov    [rsp+56], r9
    mov    [rsp+64], rbx
    mov    [rsp+72], rbp
    mov    [rsp+80], r14     
    mov    [rsp+88], r15     
    
    // [rcx] <- masked (BH + BL)
    and    r8, rax
    and    r9, rax
    and    rbx, rax
    and    rbp, rax
    and    r14, rax     
    and    r15, rax     
    mov    [rcx], r8
    mov    [rcx+8], r9
    mov    [rcx+16], rbx    /////
    mov    [rcx+24], rbp    /////

    // r8-r13 <- masked (AH + AL)
    mov    r8, [rsp]
    mov    r9, [rsp+8]
    and    r8, rdx
    and    r9, rdx
    and    r10, rdx
    and    r11, rdx
    and    r12, rdx
    and    r13, rdx

    // [rsp+96] <- masked (AH + AL) + masked (AH + AL)
    mov    rax, [rcx]
    mov    rdx, [rcx+8]
    add    r8, rax
    adc    r9, rdx
    adc    r10, rbx
    adc    r11, rbp
    adc    r12, r14         
    adc    r13, r15         
    mov    [rsp+96], r8
    mov    [rsp+104], r9
    mov    [rsp+112], r10
    mov    [rsp+120], r11

    // [rcx] <- AL x BL
    MUL384_SCHOOL  [reg_p1], [reg_p2], [rcx], [rsp+128], r8, r9, r10, r11, rbx, rbp, r14, r15     // Result C0-C5 

    // [rcx+96] <- (AH+AL) x (BH+BL), low part 
    MUL384_SCHOOL  [rsp], [rsp+48], [rcx+96], [rsp+128], r8, r9, r10, r11, rbx, rbp, r14, r15

    // [rsp] <- AH x BH 
    MUL384_SCHOOL  [reg_p1+48], [reg_p2+48], [rsp], [rsp+128], r8, r9, r10, r11, rbx, rbp, r14, r15
    
    // r8-r13 <- (AH+AL) x (BH+BL), final step
    mov    r8, [rsp+96]
    mov    r9, [rsp+104]
    mov    r10, [rsp+112]
    mov    r11, [rsp+120]
    mov    rax, [rcx+144]
    add    r8, rax
    mov    rax, [rcx+152]
    adc    r9, rax
    mov    rax, [rcx+160]
    adc    r10, rax
    mov    rax, [rcx+168]
    adc    r11, rax
    mov    rax, [rcx+176]
    adc    r12, rax
    mov    rax, [rcx+184]
    adc    r13, rax
    
    // rdi,rdx,rbx,rbp,r14,r15,r8-r13 <- (AH+AL) x (BH+BL) - ALxBL
    mov    rdi, [rcx+96]
    sub    rdi, [rcx]
    mov    rdx, [rcx+104]
    sbb    rdx, [rcx+8]
    mov    rbx, [rcx+112]
    sbb    rbx, [rcx+16]
    mov    rbp, [rcx+120]
    sbb    rbp, [rcx+24]
    mov    r14, [rcx+128]     
    sbb    r14, [rcx+32]   
    mov    r15, [rcx+136]     
    sbb    r15, [rcx+40]     
    sbb    r8, [rcx+48]
    sbb    r9, [rcx+56]
    sbb    r10, [rcx+64]
    sbb    r11, [rcx+72]
    sbb    r12, [rcx+80]
    sbb    r13, [rcx+88]
    
    // rdi,rdx,rbx,rbp,r14,r15,r8-r13 <- (AH+AL) x (BH+BL) - ALxBL - AHxBH
    sub    rdi, [rsp]
    sbb    rdx, [rsp+8]
    sbb    rbx, [rsp+16]
    sbb    rbp, [rsp+24]
    sbb    r14, [rsp+32]     
    sbb    r15, [rsp+40]   
    sbb    r8, [rsp+48]
    sbb    r9, [rsp+56]
    sbb    r10, [rsp+64]
    sbb    r11, [rsp+72]
    sbb    r12, [rsp+80]
    sbb    r13, [rsp+88]
    
    mov    rax, [rcx+48]
    add    rax, rdi
    mov    [rcx+48], rax    // Result C6-C11
    mov    rax, [rcx+56]
    adc    rax, rdx
    mov    [rcx+56], rax 
    mov    rax, [rcx+64]
    adc    rax, rbx
    mov    [rcx+64], rax 
    mov    rax, [rcx+72]
    adc    rax, rbp
    mov    [rcx+72], rax 
    mov    rax, [rcx+80]
    adc    rax, r14           
    mov    [rcx+80], rax 
    mov    rax, [rcx+88]
    adc    rax, r15             
    mov    [rcx+88], rax
    mov    rax, [rsp]
    adc    r8, rax 
    mov    [rcx+96], r8    // Result C8-C15
    mov    rax, [rsp+8]
    adc    r9, rax
    mov    [rcx+104], r9 
    mov    rax, [rsp+16]
    adc    r10, rax
    mov    [rcx+112], r10 
    mov    rax, [rsp+24]
    adc    r11, rax
    mov    [rcx+120], r11 
    mov    rax, [rsp+32]
    adc    r12, rax
    mov    [rcx+128], r12 
    mov    rax, [rsp+40]
    adc    r13, rax
    mov    [rcx+136], r13
    mov    r8, [rsp+48]
    mov    r9, [rsp+56]
    mov    r10, [rsp+64]
    mov    r11, [rsp+72]
    mov    r12, [rsp+80]
    mov    r13, [rsp+88]
    adc    r8, 0
    adc    r9, 0
    adc    r10, 0
    adc    r11, 0
    adc    r12, 0
    adc    r13, 0
    add    rsp, 152   
    mov    [rcx+144], r8 
    mov    [rcx+152], r9 
    mov    [rcx+160], r10 
    mov    [rcx+168], r11 
    mov    [rcx+176], r12 
    mov    [rcx+184], r13 
     
    pop    rbp  
    pop    rbx
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    ret

#else

//***********************************************************************
//  Integer multiplication
//  Based on Karatsuba method
//  Operation: c [reg_p3] = a [reg_p1] * b [reg_p2]
//  NOTE: a=c or b=c are not allowed
//***********************************************************************
.global mul751_asm
mul751_asm:
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

#endif

  
//***********************************************************************
//  Montgomery reduction
//  Based on comba method
//  Operation: c [reg_p2] = a [reg_p1]
//  NOTE: a=c is not allowed
//*********************************************************************** 
.global rdc751_asm
rdc751_asm:
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


//***********************************************************************
//  751-bit multiprecision addition
//  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
//*********************************************************************** 
.global mp_add751_asm
mp_add751_asm:
  push   r12
  push   r13
  push   r14
  push   r15
  push   rbx
  
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rax, [reg_p1+64]
  mov    rbx, [reg_p1+72] 
  mov    rcx, [reg_p1+80]  
  mov    rdi, [reg_p1+88] 

  add    r8, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 
  adc    r12, [reg_p2+32] 
  adc    r13, [reg_p2+40] 
  adc    r14, [reg_p2+48] 
  adc    r15, [reg_p2+56]
  adc    rax, [reg_p2+64] 
  adc    rbx, [reg_p2+72]
  adc    rcx, [reg_p2+80]
  adc    rdi, [reg_p2+88]

  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rax
  mov    [reg_p3+72], rbx
  mov    [reg_p3+80], rcx
  mov    [reg_p3+88], rdi
  
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret


//***********************************************************************
//  2x751-bit multiprecision addition
//  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
//*********************************************************************** 
.global mp_add751x2_asm
mp_add751x2_asm:
  push   r12
  push   r13
  push   r14
  push   r15
  push   rbx
  
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rax, [reg_p1+64]
  mov    rbx, [reg_p1+72] 
  mov    rcx, [reg_p1+80] 

  add    r8, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 
  adc    r12, [reg_p2+32] 
  adc    r13, [reg_p2+40] 
  adc    r14, [reg_p2+48] 
  adc    r15, [reg_p2+56]
  adc    rax, [reg_p2+64] 
  adc    rbx, [reg_p2+72]
  adc    rcx, [reg_p2+80]

  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rax
  mov    [reg_p3+72], rbx
  mov    [reg_p3+80], rcx 
  mov    rax, [reg_p1+88] 
  adc    rax, [reg_p2+88]
  mov    [reg_p3+88], rax
  
  mov    r8, [reg_p1+96]
  mov    r9, [reg_p1+104]
  mov    r10, [reg_p1+112]
  mov    r11, [reg_p1+120]
  mov    r12, [reg_p1+128]
  mov    r13, [reg_p1+136]
  mov    r14, [reg_p1+144]
  mov    r15, [reg_p1+152] 
  mov    rax, [reg_p1+160]
  mov    rbx, [reg_p1+168] 
  mov    rcx, [reg_p1+176]  
  mov    rdi, [reg_p1+184] 

  adc    r8, [reg_p2+96] 
  adc    r9, [reg_p2+104] 
  adc    r10, [reg_p2+112] 
  adc    r11, [reg_p2+120] 
  adc    r12, [reg_p2+128] 
  adc    r13, [reg_p2+136] 
  adc    r14, [reg_p2+144] 
  adc    r15, [reg_p2+152]
  adc    rax, [reg_p2+160] 
  adc    rbx, [reg_p2+168]
  adc    rcx, [reg_p2+176]
  adc    rdi, [reg_p2+184]

  mov    [reg_p3+96], r8
  mov    [reg_p3+104], r9
  mov    [reg_p3+112], r10
  mov    [reg_p3+120], r11
  mov    [reg_p3+128], r12
  mov    [reg_p3+136], r13
  mov    [reg_p3+144], r14
  mov    [reg_p3+152], r15
  mov    [reg_p3+160], rax
  mov    [reg_p3+168], rbx
  mov    [reg_p3+176], rcx
  mov    [reg_p3+184], rdi
  
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret


//***********************************************************************
//  2x751-bit multiprecision subtraction
//  Operation: c [reg_p3] = a [reg_p1] - b [reg_p2]. Returns borrow mask
//*********************************************************************** 
.global mp_sub751x2_asm
mp_sub751x2_asm:
  push   r12
  push   r13
  push   r14
  push   r15
  push   rbx
  
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rax, [reg_p1+64]
  mov    rbx, [reg_p1+72] 
  mov    rcx, [reg_p1+80] 

  sub    r8, [reg_p2] 
  sbb    r9, [reg_p2+8] 
  sbb    r10, [reg_p2+16] 
  sbb    r11, [reg_p2+24] 
  sbb    r12, [reg_p2+32] 
  sbb    r13, [reg_p2+40] 
  sbb    r14, [reg_p2+48] 
  sbb    r15, [reg_p2+56]
  sbb    rax, [reg_p2+64] 
  sbb    rbx, [reg_p2+72]
  sbb    rcx, [reg_p2+80]

  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rax
  mov    [reg_p3+72], rbx
  mov    [reg_p3+80], rcx 
  mov    rax, [reg_p1+88] 
  sbb    rax, [reg_p2+88]
  mov    [reg_p3+88], rax
  
  mov    r8, [reg_p1+96]
  mov    r9, [reg_p1+104]
  mov    r10, [reg_p1+112]
  mov    r11, [reg_p1+120]
  mov    r12, [reg_p1+128]
  mov    r13, [reg_p1+136]
  mov    r14, [reg_p1+144]
  mov    r15, [reg_p1+152] 
  mov    rax, [reg_p1+160]
  mov    rbx, [reg_p1+168] 
  mov    rcx, [reg_p1+176]  
  mov    rdi, [reg_p1+184] 

  sbb    r8, [reg_p2+96] 
  sbb    r9, [reg_p2+104] 
  sbb    r10, [reg_p2+112] 
  sbb    r11, [reg_p2+120] 
  sbb    r12, [reg_p2+128] 
  sbb    r13, [reg_p2+136] 
  sbb    r14, [reg_p2+144] 
  sbb    r15, [reg_p2+152]
  sbb    rax, [reg_p2+160]
  sbb    rbx, [reg_p2+168]
  sbb    rcx, [reg_p2+176]
  sbb    rdi, [reg_p2+184]

  mov    [reg_p3+96], r8
  mov    [reg_p3+104], r9
  mov    [reg_p3+112], r10
  mov    [reg_p3+120], r11
  mov    [reg_p3+128], r12
  mov    [reg_p3+136], r13
  mov    [reg_p3+144], r14
  mov    [reg_p3+152], r15
  mov    [reg_p3+160], rax 
  mov    rax, 0
  sbb    rax, 0
  mov    [reg_p3+168], rbx
  mov    [reg_p3+176], rcx
  mov    [reg_p3+184], rdi
  
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret