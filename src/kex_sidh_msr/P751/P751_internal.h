/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: internal header file for P751
*********************************************************************************************/  

#ifndef __P751_INTERNAL_H__
#define __P751_INTERNAL_H__

#include "../config.h"
 

#if (TARGET == TARGET_AMD64)
    #define NWORDS_FIELD    12              // Number of words of a 751-bit field element
    #define p751_ZERO_WORDS 5               // Number of "0" digits in the least significant part of p751 + 1     
#elif (TARGET == TARGET_x86)
    #define NWORDS_FIELD    24 
    #define p751_ZERO_WORDS 11
#elif (TARGET == TARGET_ARM)
    #define NWORDS_FIELD    24
    #define p751_ZERO_WORDS 11
#elif (TARGET == TARGET_ARM64)
    #define NWORDS_FIELD    12
    #define p751_ZERO_WORDS 5
#endif 
    

// Basic constants

#define NBITS_FIELD             751  
#define MAXBITS_FIELD           768                
#define MAXWORDS_FIELD          ((MAXBITS_FIELD+RADIX-1)/RADIX)     // Max. number of words to represent field elements
#define NWORDS64_FIELD          ((NBITS_FIELD+63)/64)               // Number of 64-bit words of a 751-bit field element 
#define NBITS_ORDER             384
#define NWORDS_ORDER            ((NBITS_ORDER+RADIX-1)/RADIX)       // Number of words of oA and oB, where oA and oB are the subgroup orders of Alice and Bob, resp.
#define NWORDS64_ORDER          ((NBITS_ORDER+63)/64)               // Number of 64-bit words of a 384-bit element 
#define MAXBITS_ORDER           NBITS_ORDER                         
#define MAXWORDS_ORDER          ((MAXBITS_ORDER+RADIX-1)/RADIX)     // Max. number of words to represent elements in [1, oA-1] or [1, oB].
#define ALICE                   0
#define BOB                     1 
#define OALICE_BITS             372  
#define OBOB_BITS               379    
#define OBOB_EXPON              239 
#define MASK_ALICE              0x0F
#define MASK_BOB                0x03  
#define PRIME                   p751  
#define PARAM_A                 0  
#define PARAM_C                 1
// Fixed parameters for isogeny tree computation
#define MAX_INT_POINTS_ALICE    8      
#define MAX_INT_POINTS_BOB      10 
#define MAX_Alice               186
#define MAX_Bob                 239
#define MSG_BYTES               32
#define SECRETKEY_A_BYTES       (OALICE_BITS + 7) / 8
#define SECRETKEY_B_BYTES       (OBOB_BITS + 7) / 8
#define FP2_ENCODED_BYTES       2*((NBITS_FIELD + 7) / 8)

// SIDH's basic element definitions and point representations

typedef digit_t felm_t[NWORDS_FIELD];                                 // Datatype for representing 751-bit field elements (768-bit max.)
typedef digit_t dfelm_t[2*NWORDS_FIELD];                              // Datatype for representing double-precision 2x751-bit field elements (2x768-bit max.) 
typedef felm_t  f2elm_t[2];                                           // Datatype for representing quadratic extension field elements GF(p751^2)
        
typedef struct { f2elm_t X; f2elm_t Z; } point_proj;                  // Point representation in projective XZ Montgomery coordinates.
typedef point_proj point_proj_t[1]; 



/**************** Function prototypes ****************/
/************* Multiprecision functions **************/ 

// Copy wordsize digits, c = a, where lng(a) = nwords
static void copy_words(const digit_t* a, digit_t* c, const unsigned int nwords);

// Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit 
static unsigned int mp_add(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);

// 751-bit multiprecision addition, c = a+b
static void mp_add751(const digit_t* a, const digit_t* b, digit_t* c);
static void mp_add751_asm(const digit_t* a, const digit_t* b, digit_t* c);
//void mp_addmask751_asm(const digit_t* a, const digit_t mask, digit_t* c);

// 2x751-bit multiprecision addition, c = a+b
static void mp_add751x2(const digit_t* a, const digit_t* b, digit_t* c);
static void mp_add751x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit 
static unsigned int mp_sub(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);
static digit_t mp_sub751x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Multiprecision left shift
static void mp_shiftleft(digit_t* x, unsigned int shift, const unsigned int nwords);

// Multiprecision right shift by one
static void mp_shiftr1(digit_t* x, const unsigned int nwords);

// Multiprecision left right shift by one    
static void mp_shiftl1(digit_t* x, const unsigned int nwords);

// Digit multiplication, digit * digit -> 2-digit result
static void digit_x_digit(const digit_t a, const digit_t b, digit_t* c);

// Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.
static void mp_mul(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);

/************ Field arithmetic functions *************/

// Copy of a field element, c = a
static void fpcopy751(const digit_t* a, digit_t* c);

// Zeroing a field element, a = 0
static void fpzero751(digit_t* a);

// Non constant-time comparison of two field elements. If a = b return TRUE, otherwise, return FALSE
static bool fpequal751_non_constant_time(const digit_t* a, const digit_t* b); 

// Modular addition, c = a+b mod p751
static void fpadd751(const digit_t* a, const digit_t* b, digit_t* c);
extern void fpadd751_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Modular subtraction, c = a-b mod p751
static void fpsub751(const digit_t* a, const digit_t* b, digit_t* c);
extern void fpsub751_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Modular negation, a = -a mod p751        
static void fpneg751(digit_t* a);  

// Modular division by two, c = a/2 mod p751.
static void fpdiv2_751(const digit_t* a, digit_t* c);

// Modular correction to reduce field element a in [0, 2*p751-1] to [0, p751-1].
static void fpcorrection751(digit_t* a);

// 751-bit Montgomery reduction, c = a mod p
static void rdc_mont(const digit_t* a, digit_t* c);
            
// Field multiplication using Montgomery arithmetic, c = a*b*R^-1 mod p751, where R=2^768
static void fpmul751_mont(const digit_t* a, const digit_t* b, digit_t* c);
static void mul751_asm(const digit_t* a, const digit_t* b, digit_t* c);
static void rdc751_asm(const digit_t* ma, digit_t* mc);
   
// Field squaring using Montgomery arithmetic, c = a*b*R^-1 mod p751, where R=2^768
static void fpsqr751_mont(const digit_t* ma, digit_t* mc);

// Conversion to Montgomery representation
static void to_mont(const digit_t* a, digit_t* mc);
    
// Conversion from Montgomery representation to standard representation
static void from_mont(const digit_t* ma, digit_t* c);

// Field inversion, a = a^-1 in GF(p751)
static void fpinv751_mont(digit_t* a);

// Field inversion, a = a^-1 in GF(p751) using the binary GCD 
static void fpinv751_mont_bingcd(digit_t* a);

// Chain to compute (p751-3)/4 using Montgomery arithmetic
static void fpinv751_chain_mont(digit_t* a);

/************ GF(p^2) arithmetic functions *************/
    
// Copy of a GF(p751^2) element, c = a
static void fp2copy751(const f2elm_t a, f2elm_t c);

// Zeroing a GF(p751^2) element, a = 0
static void fp2zero751(f2elm_t a);

// GF(p751^2) negation, a = -a in GF(p751^2)
static void fp2neg751(f2elm_t a);

// GF(p751^2) addition, c = a+b in GF(p751^2)
static void fp2add751(const f2elm_t a, const f2elm_t b, f2elm_t c);           

// GF(p751^2) subtraction, c = a-b in GF(p751^2)
static void fp2sub751(const f2elm_t a, const f2elm_t b, f2elm_t c); 

// GF(p751^2) division by two, c = a/2  in GF(p751^2) 
static void fp2div2_751(const f2elm_t a, f2elm_t c);

// Modular correction, a = a in GF(p751^2)
static void fp2correction751(f2elm_t a);
            
// GF(p751^2) squaring using Montgomery arithmetic, c = a^2 in GF(p751^2)
static void fp2sqr751_mont(const f2elm_t a, f2elm_t c);
 
// GF(p751^2) multiplication using Montgomery arithmetic, c = a*b in GF(p751^2)
static void fp2mul751_mont(const f2elm_t a, const f2elm_t b, f2elm_t c);
    
// Conversion of a GF(p751^2) element to Montgomery representation
static void to_fp2mont(const f2elm_t a, f2elm_t mc);

// Conversion of a GF(p751^2) element from Montgomery representation to standard representation
static void from_fp2mont(const f2elm_t ma, f2elm_t c);

// GF(p751^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
static void fp2inv751_mont(f2elm_t a);

// GF(p751^2) inversion, a = (a0-i*a1)/(a0^2+a1^2), GF(p751) inversion done using the binary GCD 
static void fp2inv751_mont_bingcd(f2elm_t a);

// n-way Montgomery inversion
static void mont_n_way_inv(const f2elm_t* vec, const int n, f2elm_t* out);

/************ Elliptic curve and isogeny functions *************/

// Computes the j-invariant of a Montgomery curve with projective constant.
static void j_inv(const f2elm_t A, const f2elm_t C, f2elm_t jinv);

// Simultaneous doubling and differential addition.
static void xDBLADD(point_proj_t P, point_proj_t Q, const f2elm_t xPQ, const f2elm_t A24);

// Doubling of a Montgomery point in projective coordinates (X:Z).
static void xDBL(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus, const f2elm_t C24);

// Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings.
static void xDBLe(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus, const f2elm_t C24, const int e);

// Differential addition.
static void xADD(point_proj_t P, const point_proj_t Q, const f2elm_t xPQ);

// Computes the corresponding 4-isogeny of a projective Montgomery point (X4:Z4) of order 4.
static void get_4_isog(const point_proj_t P, f2elm_t A24plus, f2elm_t C24, f2elm_t* coeff);

// Evaluates the isogeny at the point (X:Z) in the domain of the isogeny.
static void eval_4_isog(point_proj_t P, f2elm_t* coeff);

// Tripling of a Montgomery point in projective coordinates (X:Z).
static void xTPL(const point_proj_t P, point_proj_t Q, const f2elm_t A24minus, const f2elm_t A24plus);

// Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings.
static void xTPLe(const point_proj_t P, point_proj_t Q, const f2elm_t A24minus, const f2elm_t A24plus, const int e);

// Computes the corresponding 3-isogeny of a projective Montgomery point (X3:Z3) of order 3.
static void get_3_isog(const point_proj_t P, f2elm_t A24minus, f2elm_t A24plus, f2elm_t* coeff);

// Computes the 3-isogeny R=phi(X:Z), given projective point (X3:Z3) of order 3 on a Montgomery curve and a point P with coefficients given in coeff.
static void eval_3_isog(point_proj_t Q, const f2elm_t* coeff);

// 3-way simultaneous inversion
static void inv_3_way(f2elm_t z1, f2elm_t z2, f2elm_t z3);

// Given the x-coordinates of P, Q, and R, returns the value A corresponding to the Montgomery curve E_A: y^2=x^3+A*x^2+x such that R=Q-P on E_A.
static void get_A(const f2elm_t xP, const f2elm_t xQ, const f2elm_t xR, f2elm_t A);


#endif
