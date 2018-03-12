/*
Implementation by Vladimir Sedach, hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

////////////////////////////////////////////////////////////////////////////////
// Important: "state" parameter must be SnP_align byte aligned and SnP_stateSizeInBytes long.
// Compile with either -mavx2 or /arch:AVX and -O2 or /O2 options.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#ifdef __GNUC__
    #include <x86intrin.h>
#else
    #include <immintrin.h>
#endif

#include "KeccakP-1600-SnP.h"

#ifdef _MSC_VER
    #pragma warning(disable: 4003)  //not enough actual parameters for macro
#endif

#ifdef __GNUC__
    #define __ALIGN(x)      __attribute__((aligned(x)))
#else
    #define __ALIGN(x)      __declspec(align(x))
#endif

typedef unsigned long long  UINT64;
typedef long long           INT64;

//*******************
struct keccak_state_t
//*******************
{
    __m256i a0, a1, a2, a3, a4; //a[row, 0..3] rows
    __m256i c4;                 //a[0..3, 4] column
    __m256i a44;                //a[4, 4]
};

#define SET(i0, i1, i2, i3)             _mm256_setr_epi64x(i0, i1, i2, i3)
#define XOR(a, b)                       _mm256_xor_si256(a, b)
#define PERMUTE(a, i0, i1, i2, i3)      _mm256_permute4x64_epi64(a, _MM_SHUFFLE(i3, i2, i1, i0))
#define BLEND(a, b, i0, i1, i2, i3)     _mm256_blend_epi32(a, b, _MM_SHUFFLE(3*(i3), 3*(i2), 3*(i1), 3*(i0)))

#define MASKLOAD(p, i0, i1, i2, i3)     _mm256_maskload_epi64((const INT64 *)(p), \
                                            SET((UINT64)(i0) << 63, (UINT64)(i1) << 63, (UINT64)(i2) << 63, (UINT64)(i3) << 63))
#define MASKSTORE(p, i0, i1, i2, i3, a) _mm256_maskstore_epi64((INT64 *)(p), \
                                            SET((UINT64)(i0) << 63, (UINT64)(i1) << 63, (UINT64)(i2) << 63, (UINT64)(i3) << 63), a)
#define LOAD(p)                         _mm256_load_si256((const __m256i *)(p))
#define LOADU(p)                        _mm256_loadu_si256((const __m256i *)(p))
#define STORE(p, a)                     _mm256_store_si256((__m256i *)(p), a)
#define STOREU(p, a)                    _mm256_storeu_si256((__m256i *)(p), a)

#define LOAD0(p)                        _mm256_castsi128_si256(_mm_move_epi64(*(__m128i *)(p)))

#define ROLV_TYPE       const static __m256i

#ifdef __GNUC__
    #define _ROLV_TYPE  const static __m256i
#else
    #define _ROLV_TYPE  static __m256i
#endif

#define ROLV_CONST(name, i0, i1, i2, i3) \
    ROLV_TYPE   SLLV##name = SET(i0, i1, i2, i3); \
    ROLV_TYPE   SRLV##name = SET(64 - i0, 64 - i1, 64 - i2, 64 - i3);

#define _ROLV_CONST(name, i0, i1, i2, i3) \
    _ROLV_TYPE  SLLV##name = SET(i0, i1, i2, i3); \
    _ROLV_TYPE  SRLV##name = SET(64 - i0, 64 - i1, 64 - i2, 64 - i3);

// Rotation constants w/o "volatile" attribute.
ROLV_CONST(A0,  0,  1, 62, 28)
ROLV_CONST(A1, 36, 44,  6, 55)
ROLV_CONST(A2,  3, 10, 43, 25)
ROLV_CONST(A3, 41, 45, 15, 21)
ROLV_CONST(A4, 18,  2, 61, 56)
ROLV_CONST(C4, 27, 20, 39,  8)

// Rotation constants with "volatile" attribute (GC only).
_ROLV_CONST(_A0,  0,  1, 62, 28)
_ROLV_CONST(_A1, 36, 44,  6, 55)
_ROLV_CONST(_A2,  3, 10, 43, 25)
_ROLV_CONST(_A3, 41, 45, 15, 21)
_ROLV_CONST(_A4, 18,  2, 61, 56)
_ROLV_CONST(_C4, 27, 20, 39,  8)

#define ROLV(a, name) \
    XOR(_mm256_sllv_epi64(a, SLLV##name), \
        _mm256_srlv_epi64(a, SRLV##name))

#define ROL(a, i) \
    XOR(_mm256_slli_epi64(a, i), \
        _mm256_srli_epi64(a, 64 - i))
/*
#define ROLV(a, i0, i1, i2, i3) \
    XOR(_mm256_sllv_epi64(a, SET(i0, i1, i2, i3)), \
        _mm256_srlv_epi64(a, SET(64 - i0, 64 - i1, 64 - i2, 64 - i3)))
*/

/**************************/\
#define KECCAK_PERMUTE_VARS \
/**************************/\
    __m256i a0, a1, a2, a3, a4, c4; \
    __m256i a04, a14, a24, a34, a44; \
    __m256i b0, b1, b2, b3, b4; \
    __m256i b04, b14, b24, b34, b44; \
    __m256i r0, r1, r2, r3; \
\
    keccak_state_t  &s = *(keccak_state_t *)state; \
    ptrdiff_t       round_i;

/******************/\
#define KECCAK_LOAD \
/******************/\
    a0 = LOAD(&s.a0); \
    a1 = LOAD(&s.a1); \
    a2 = LOAD(&s.a2); \
    a3 = LOAD(&s.a3); \
    a4 = LOAD(&s.a4); \
    c4 = LOAD(&s.c4); \
    a44 = LOAD(&s.a44);

/*******************/\
#define KECCAK_STORE \
/*******************/\
    STORE(&s.a0, a0); \
    STORE(&s.a1, a1); \
    STORE(&s.a2, a2); \
    STORE(&s.a3, a3); \
    STORE(&s.a4, a4); \
    STORE(&s.c4, c4); \
    STORE(&s.a44, a44);

#define KECCAK_NO_ASM // !!!
#if defined(KECCAK_NO_ASM) || !(defined(__x86_64__) || defined(__X86_64__) || defined(__LP64__) || \
    defined(_M_X64) || defined(_M_AMD64) || defined(_WIN64)) || \
    !defined(__GNUC__)

// const_pref: "_" or "" to choose the ROLV_CONST rotation constants with or w/o "volatile".
/*********************************/\
#define KECCAK_PERMUTE_LOOP(const_pref, nrRounds) \
/*********************************/\
    for (round_i = (nrRounds-1); round_i >= 0; round_i--) \
    { \
        /* a0..a4 are rows a[row, 0..3], c4 is column a[0..3, 4], and a44 is element a[4, 4]. */ \
        /* C[x] = A[0, x] ^ A[1, x] ^ A[2, x] ^ A[3, x] ^ A[4, x] */ \
        r0 = XOR(a0, a1); \
        r0 = XOR(r0, a2); \
        r0 = XOR(r0, a3); \
        r0 = XOR(r0, a4);                   /*C[0, 1, 2, 3]*/ \
\
        r1 = XOR(c4, _mm256_permute2x128_si256(c4, c4, 0x11)); \
        r1 = XOR(r1, _mm256_unpackhi_epi64(r1, r1)); \
        r1 = XOR(r1, a44);                  /*C[4]*/ \
\
        /* D[x] = C[x - 1] ^ rot(C[x + 1], 1) */ \
\
        /* (b0, b04) = C[4, 0, 1, 2, 3]. */ \
        b0 = PERMUTE(r0, 3, 0, 1, 2);       /*C[3, 0, 1, 2]*/ \
        b04 = b0;                           /*C[3]*/ \
        b0 = BLEND(b0, r1, 1, 0, 0, 0);     /*C[4, 0, 1, 2]*/ \
\
        r0 = ROL(r0, 1);                    /*rot(C[0, 1, 2, 3])*/ \
        r1 = ROL(r1, 1);                    /*rot(C[4])*/ \
\
        /* (r1, r0) = rot(C[1, 2, 3, 4, 0]). */ \
        r1 = BLEND(r0, r1, 1, 0, 0, 0);     /*rot(C[4, 1, 2, 3])*/ \
        r1 = PERMUTE(r1, 1, 2, 3, 0);       /*rot(C[1, 2, 3, 4])*/ \
\
        /* (b0, b04) = D[0, 1, 2, 3, 4]. */ \
        b0 = XOR(b0, r1); \
        b04 = XOR(b04, r0); \
\
        /* A[y, x] = A[y, x] ^ D[x] */ \
        a0 = XOR(a0, b0); \
        a1 = XOR(a1, b0); \
        a2 = XOR(a2, b0); \
        a3 = XOR(a3, b0); \
        a4 = XOR(a4, b0); \
\
        a44 = XOR(a44, b04); \
        c4 = XOR(c4, _mm256_broadcastq_epi64(_mm256_castsi256_si128(b04))); \
\
        /* B[2*x + 3*y, y] = rot(A[y, x], R[y, x]) */ \
        /* After this, y-rows of A become y-columns of B. */ \
\
        /* b0..b4 are rows a[row, 0..3], c4 is column a[0..3, 4], and a44 is element a[4, 4]. */ \
        b0 = ROLV(a0, const_pref##A0); \
        b1 = ROLV(a1, const_pref##A1); \
        b2 = ROLV(a2, const_pref##A2); \
        b3 = ROLV(a3, const_pref##A3); \
        b4 = ROLV(a4, const_pref##A4); \
        c4 = ROLV(c4, const_pref##C4); \
\
/*      c4 = PERMUTE(c4, 2, 1, 3, 0);   //to avoid r1 calc below; makes slower other parts */ \
        a44 = ROL(a44, 14); \
\
        /* Now b0..b4 are columns a[0..3, col], b04..b44 are last elements a[4, 0..4] of those columns. */ \
        r0 = PERMUTE(b0, 0, 3, 1, 0); \
        r1 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(c4)); \
        b04 = _mm256_permute2x128_si256(b0, b0, 0x11); \
        b0 = BLEND(r0, r1, 0, 0, 0, 1); \
\
        r0 = PERMUTE(b1, 1, 3, 2, 0); \
        r1 = _mm256_unpackhi_epi64(c4, c4); \
        b14 = PERMUTE(b1, 3, 3, 3, 3); \
/*      b14 = _mm256_unpackhi_epi64(r0, r0); */ \
        b1 = BLEND(r0, r1, 0, 1, 0, 0); \
\
        b2 = PERMUTE(b2, 2, 0, 3, 1); \
        b24 = _mm256_permute2x128_si256(c4, c4, 0x11); \
\
        r0 = PERMUTE(b3, 3, 1, 0, 2); \
        r1 = PERMUTE(c4, 3, 3, 3, 3); \
        b34 = b3; \
        b3 = BLEND(r0, r1, 0, 0, 1, 0); \
\
        r0 = PERMUTE(b4, 1, 2, 0, 3); \
        r1 = _mm256_broadcastq_epi64(_mm256_castsi256_si128(a44)); \
        b44 = _mm256_unpackhi_epi64(b4, b4); \
/*      b44 = r0; */ \
        b4 = BLEND(r0, r1, 1, 0, 0, 0); \
\
        /* A[y, x] = B[y, x] ^ (~B[y, x + 1] & B[y, x + 2]) */ \
        /* A[0, 0] = A[0, 0] ^ RC */ \
\
        /* a0..a3, c4 are columnss a[0..3, col]. */ \
        a0 = XOR(b0, _mm256_andnot_si256(b1, b2)); \
        a0 = XOR(a0, *(__m256i *)(keccak_rc + round_i)); \
\
        a1 = XOR(b1, _mm256_andnot_si256(b2, b3)); \
        a2 = XOR(b2, _mm256_andnot_si256(b3, b4)); \
        a3 = XOR(b3, _mm256_andnot_si256(b4, b0)); \
        c4 = XOR(b4, _mm256_andnot_si256(b0, b1)); \
\
        /* Transpose A[] so that a0..a4 are rows again. */ \
        r0 = _mm256_unpacklo_epi64(a0, a1); \
        r1 = _mm256_unpackhi_epi64(a0, a1); \
        r2 = _mm256_unpacklo_epi64(a2, a3); \
        r3 = _mm256_unpackhi_epi64(a2, a3); \
        a0 = _mm256_permute2x128_si256(r0, r2, 0x20); \
        a1 = _mm256_permute2x128_si256(r1, r3, 0x20); \
        a2 = _mm256_permute2x128_si256(r2, r0, 0x13); \
        a3 = _mm256_permute2x128_si256(r3, r1, 0x13); \
\
        a04 = XOR(b04, _mm256_andnot_si256(b14, b24)); \
        a14 = XOR(b14, _mm256_andnot_si256(b24, b34)); \
        a24 = XOR(b24, _mm256_andnot_si256(b34, b44)); \
        a34 = XOR(b34, _mm256_andnot_si256(b44, b04)); \
        a44 = XOR(b44, _mm256_andnot_si256(b04, b14)); \
\
        r0 = _mm256_unpacklo_epi64(a04, a14); \
        r1 = _mm256_unpacklo_epi64(a24, a34); \
        a4 = _mm256_permute2x128_si256(r0, r1, 0x20); \
    } //for (round_i

#define KECCAK_PERMUTE(const_pref) KECCAK_PERMUTE_LOOP(const_pref, 24)
#define KECCAK_PERMUTE_12rounds(const_pref) KECCAK_PERMUTE_LOOP(const_pref, 12)

#else

/*********************************/\
#define KECCAK_PERMUTE_LOOP(const_pref, nrRounds) \
/*********************************/\
__asm volatile \
( \
    "movq           %7, %%rax\n" \
"1:\n" \
    "vpxor          %1, %0, %%ymm9\n" \
    "vpxor          %2, %%ymm9, %%ymm9\n" \
    "vpxor          %3, %%ymm9, %%ymm9\n" \
    "vpxor          %4, %%ymm9, %%ymm9\n" \
    "vpermq         $147, %%ymm9, %%ymm8\n" \
    "vpsrlq         $63, %%ymm9, %%ymm7\n" \
    "vpsllq         $1, %%ymm9, %%ymm9\n" \
    "vperm2i128     $17, %5, %5, %%ymm0\n" \
    "vpxor          %%ymm0, %5, %%ymm0\n" \
    "vpunpckhqdq    %%ymm0, %%ymm0, %%ymm6\n" \
    "vpxor          %%ymm6, %%ymm0, %%ymm6\n" \
    "vpxor          %6, %%ymm6, %%ymm6\n" \
    "vpxor          %%ymm7, %%ymm9, %%ymm7\n" \
    "vpblendd       $3, %%ymm6, %%ymm8, %%ymm0\n" \
    "vpsrlq         $63, %%ymm6, %%ymm9\n" \
    "vpsllq         $1, %%ymm6, %%ymm6\n" \
    "vpxor          %%ymm9, %%ymm6, %%ymm6\n" \
    "vpblendd       $3, %%ymm6, %%ymm7, %%ymm6\n" \
    "vpxor          %%ymm7, %%ymm8, %%ymm7\n" \
    "vpxor          %%ymm7, %6, %%ymm9\n" \
    "vpermq         $57, %%ymm6, %%ymm6\n" \
    "vpxor          %%ymm6, %%ymm0, %%ymm0\n" \
    "vpxor          %%ymm0, %0, %0\n" \
    "vpxor          %%ymm0, %1, %1\n" \
    "vpbroadcastq   %%xmm7, %%ymm7\n" \
    "vpxor          %%ymm7, %5, %5\n" \
    "vpxor          %%ymm0, %2, %2\n" \
    "vpxor          %%ymm0, %3, %3\n" \
    "vpxor          %%ymm0, %4, %4\n" \
    "vmovdqa        %[SRLV_A0], %%ymm6\n" \
    "vmovdqa        %[SLLV_A0], %6\n" \
    "vmovdqa        %[SRLV_A1], %%ymm7\n" \
    "vpsrlvq        %%ymm6, %0, %%ymm6\n" \
    "vpsllvq        %6, %0, %0\n" \
    "vmovdqa        %[SLLV_A1], %6\n" \
    "vmovdqa        %[SRLV_A2], %%ymm0\n" \
    "vpsrlvq        %%ymm7, %1, %%ymm7\n" \
    "vpsllvq        %6, %1, %1\n" \
    "vmovdqa        %[SLLV_A2], %6\n" \
    "vmovdqa        %[SRLV_A3], %%ymm10\n" \
    "vpsrlvq        %%ymm0, %2, %%ymm0\n" \
    "vpsllvq        %6, %2, %2\n" \
    "vpxor          %%ymm7, %1, %%ymm7\n" \
    "vpxor          %%ymm6, %0, %%ymm6\n" \
    "vpermq         $28, %%ymm6, %1\n" \
    "vperm2i128     $17, %%ymm6, %%ymm6, %%ymm6\n" \
    "vpxor          %%ymm0, %2, %2\n" \
    "vpsrlvq        %%ymm10, %3, %%ymm0\n" \
    "vpermq         $114, %2, %2\n" \
    "vmovdqa        %[SLLV_A3], %%ymm10\n" \
    "vpsllvq        %%ymm10, %3, %3\n" \
    "vpxor          %%ymm0, %3, %%ymm10\n" \
    "vpermq         $135, %%ymm10, %3\n" \
    "vmovdqa        %[SRLV_A4], %%ymm0\n" \
    "vpsrlvq        %%ymm0, %4, %6\n" \
    "vmovdqa        %[SLLV_A4], %%ymm0\n" \
    "vpsllvq        %%ymm0, %4, %4\n" \
    "vpxor          %6, %4, %%ymm0\n" \
    "vpermq         $201, %%ymm0, %0\n" \
    "vpunpckhqdq    %%ymm0, %%ymm0, %%ymm0\n" \
    "vmovdqa        %[SRLV_C4], %4\n" \
    "vpsrlvq        %4, %5, %6\n" \
    "vmovdqa        %[SLLV_C4], %4\n" \
    "vpsllvq        %4, %5, %5\n" \
    "vpxor          %6, %5, %4\n" \
    "vpsrlq         $50, %%ymm9, %5\n" \
    "vpsllq         $14, %%ymm9, %6\n" \
    "vperm2i128     $17, %4, %4, %%ymm8\n" \
    "vpxor          %5, %6, %%ymm9\n" \
    "vmovdqa        %x4, %x6\n" \
    "vpunpckhqdq    %4, %4, %5\n" \
    "vpbroadcastq   %%xmm9, %%ymm9\n" \
    "vpbroadcastq   %x6, %6\n" \
    "vpermq         $255, %4, %4\n" \
    "vpblendd       $48, %4, %3, %4\n" \
    "vpblendd       $3, %%ymm9, %0, %3\n" \
    "vpblendd       $192, %6, %1, %1\n" \
    "vpermq         $45, %%ymm7, %6\n" \
    "vpblendd       $12, %5, %6, %5\n" \
    "vpermq         $255, %%ymm7, %%ymm7\n" \
    "vpandn         %2, %5, %%ymm9\n" \
    "subq           $32, %%rax\n" \
    "vpxor          %1, %%ymm9, %%ymm9\n" \
    "vpandn         %4, %2, %6\n" \
    "vpandn         %3, %4, %0\n" \
    "vpxor          (%%rdx, %%rax), %%ymm9, %%ymm9\n" \
    "vpxor          %0, %2, %0\n" \
    "vpxor          %5, %6, %6\n" \
    "vpandn         %1, %3, %2\n" \
    "vpandn         %5, %1, %5\n" \
    "vpxor          %4, %2, %4\n" \
    "vpxor          %3, %5, %5\n" \
    "vpunpcklqdq    %6, %%ymm9, %2\n" \
    "vpunpckhqdq    %6, %%ymm9, %6\n" \
    "vpunpcklqdq    %4, %0, %%ymm9\n" \
    "vpunpckhqdq    %4, %0, %4\n" \
    "vperm2i128     $32, %%ymm9, %2, %0\n" \
    "vperm2i128     $32, %4, %6, %1\n" \
    "vperm2i128     $19, %6, %4, %3\n" \
    "vperm2i128     $19, %2, %%ymm9, %2\n" \
    "vpandn         %%ymm10, %%ymm8, %4\n" \
    "vpandn         %%ymm0, %%ymm10, %6\n" \
    "vpandn         %%ymm8, %%ymm7, %%ymm9\n" \
    "vpxor          %4, %%ymm7, %4\n" \
    "vpxor          %6, %%ymm8, %%ymm8\n" \
    "vpxor          %%ymm9, %%ymm6, %%ymm9\n" \
    "vpandn         %%ymm6, %%ymm0, %6\n" \
    "vpxor          %6, %%ymm10, %%ymm10\n" \
    "vpandn         %%ymm7, %%ymm6, %6\n" \
    "vpunpcklqdq    %4, %%ymm9, %%ymm9\n" \
    "vpunpcklqdq    %%ymm10, %%ymm8, %%ymm8\n" \
    "vperm2i128     $32, %%ymm8, %%ymm9, %4\n" \
    "vpxor          %6, %%ymm0, %6\n" \
    "jnz            1b\n" \
\
    : "+x"(a0), "+x"(a1), "+x"(a2), "+x"(a3), "+x"(a4), "+x"(c4), "+x"(a44) \
    : "i"(8*4*nrRounds), "d"(keccak_rc), \
        [SLLV_A0] "m"(SLLV_A0), [SRLV_A0] "m"(SRLV_A0), \
        [SLLV_A1] "m"(SLLV_A1), [SRLV_A1] "m"(SRLV_A1), \
        [SLLV_A2] "m"(SLLV_A2), [SRLV_A2] "m"(SRLV_A2), \
        [SLLV_A3] "m"(SLLV_A3), [SRLV_A3] "m"(SRLV_A3), \
        [SLLV_A4] "m"(SLLV_A4), [SRLV_A4] "m"(SRLV_A4), \
        [SLLV_C4] "m"(SLLV_C4), [SRLV_C4] "m"(SRLV_C4) \
    : "rax", "xmm0", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10" \
);

#define KECCAK_PERMUTE(const_pref) KECCAK_PERMUTE_LOOP(const_pref, 24)
#define KECCAK_PERMUTE_12rounds(const_pref) KECCAK_PERMUTE_LOOP(const_pref, 12)
#endif //__X64 && __GNUC__

typedef UINT64  keccak_rc_t[4];

// Reverse order.
__ALIGN(32) keccak_rc_t keccak_rc[24] =
{
    {0x8000000080008008ull},    //round 23
    {0x0000000080000001ull},
    {0x8000000000008080ull},
    {0x8000000080008081ull},
    {0x800000008000000Aull},
    {0x000000000000800Aull},
    {0x8000000000000080ull},
    {0x8000000000008002ull},
    {0x8000000000008003ull},
    {0x8000000000008089ull},
    {0x800000000000008Bull},
    {0x000000008000808Bull},
    {0x000000008000000Aull},
    {0x0000000080008009ull},
    {0x0000000000000088ull},
    {0x000000000000008Aull},
    {0x8000000000008009ull},
    {0x8000000080008081ull},
    {0x0000000080000001ull},
    {0x000000000000808Bull},
    {0x8000000080008000ull},
    {0x800000000000808Aull},
    {0x0000000000008082ull},
    {0x0000000000000001ull},    //round 0
};

//*****************************
void KeccakP1600_StaticInitialize(void)
//*****************************
{}

//******************************
void KeccakP1600_Initialize(void *state)
//******************************
{   memset(state, 0, sizeof(keccak_state_t));}

//__KeccakP1600_AddByte
//*****************************************************************************
void KeccakP1600_AddByte(void *state, UINT8 byte, size_t offset)
//*****************************************************************************
{
    // TODO: optimize this
    KeccakP1600_AddBytes(state, &byte, offset, 1);
}

//__KeccakP1600_AddBytes
//*****************************************************************************
void KeccakP1600_AddBytes(void *state, const UINT8 *data, size_t offset, size_t length)
//*****************************************************************************
{
    keccak_state_t  &s = *(keccak_state_t *)state;
    UINT64      *d = (UINT64 *)data;
    UINT8       *t1, *d1;
    UINT64      t[25];
    UINT64      *t0;
    ptrdiff_t   lane_n = length / sizeof(UINT64);
    ptrdiff_t   byte_n = length % sizeof(UINT64);
    ptrdiff_t   i;

    KeccakP1600_ExtractBytes(state, (UINT8 *)t, 0, sizeof(t));

/*
    // "trailingBits + 256" is passed as offset to do "state ^ trailingBits".
    if (offset >= 256)
    {
        if (length < sizeof(t))
            ((UINT8 *)t)[length] ^= (UINT8)offset;
        offset = 0;
    }
*/

    t0 = (UINT64 *)((UINT8 *)t + offset);

    for (i = 0; i < lane_n; i++)
        t0[i] ^= d[i];

    if (byte_n)
    {
        t1 = (UINT8 *)(t0 + i);
        d1 = (UINT8 *)(d + i);

        for (i = 0; i < byte_n; i++)
            t1[i] ^= d1[i];
    }

    s.a0 = LOADU(t + 0*5);
    s.a1 = LOADU(t + 1*5);
    s.a2 = LOADU(t + 2*5);
    s.a3 = LOADU(t + 3*5);
    s.a4 = LOADU(t + 4*5);
    s.c4 = SET(t[0*5 + 4], t[1*5 + 4], t[2*5 + 4], t[3*5 + 4]);
    s.a44 = _mm256_set1_epi64x(t[4*5 + 4]);
} //KeccakP1600_AddBytes

//***********************************************************************************
void KeccakP1600_OverwriteBytes(void *state, const UINT8 *data, size_t offset, size_t length)
//***********************************************************************************
{
    keccak_state_t  &s = *(keccak_state_t *)state;
    UINT64      *d = (UINT64 *)data;
    UINT8       *t1, *d1;
    UINT64      t[25];
    UINT64      *t0;
    ptrdiff_t   lane_n = length / sizeof(UINT64);
    ptrdiff_t   byte_n = length % sizeof(UINT64);
    ptrdiff_t   i;

    KeccakP1600_ExtractBytes(state, (UINT8 *)t, 0, sizeof(t));

    t0 = (UINT64 *)((UINT8 *)t + offset);

    for (i = 0; i < lane_n; i++)
        t0[i] = d[i];

    if (byte_n)
    {
        t1 = (UINT8 *)(t0 + i);
        d1 = (UINT8 *)(d + i);

        for (i = 0; i < byte_n; i++)
            t1[i] = d1[i];
    }

    s.a0 = LOADU(t + 0*5);
    s.a1 = LOADU(t + 1*5);
    s.a2 = LOADU(t + 2*5);
    s.a3 = LOADU(t + 3*5);
    s.a4 = LOADU(t + 4*5);
    s.c4 = SET(t[0*5 + 4], t[1*5 + 4], t[2*5 + 4], t[3*5 + 4]);
    s.a44 = _mm256_set1_epi64x(t[4*5 + 4]);
} //KeccakP1600_OverwriteBytes

//*********************************************************
void KeccakP1600_OverwriteWithZeroes(void *state, size_t byteCount)
//*********************************************************
{
    keccak_state_t  &s = *(keccak_state_t *)state;
    UINT64      t[25];

    KeccakP1600_ExtractBytes(state, (UINT8 *)t, 0, sizeof(t));
    memset(t, 0, byteCount);

    s.a0 = LOADU(t + 0*5);
    s.a1 = LOADU(t + 1*5);
    s.a2 = LOADU(t + 2*5);
    s.a3 = LOADU(t + 3*5);
    s.a4 = LOADU(t + 4*5);
    s.c4 = SET(t[0*5 + 4], t[1*5 + 4], t[2*5 + 4], t[3*5 + 4]);
    s.a44 = _mm256_set1_epi64x(t[4*5 + 4]);
} //KeccakP1600_OverwriteWithZeroes

//__KeccakP1600_ExtractBytes
//*********************************************************************************
void KeccakP1600_ExtractBytes(const void *state, UINT8 *data, size_t offset, size_t length)
//*********************************************************************************
{
    keccak_state_t  &s = *(keccak_state_t *)state;
    UINT64  t[25];
    UINT64  *d = (!offset && (length >= sizeof(t))) ? (UINT64 *)data : t;
    UINT64  *c4 = (UINT64 *)&s.c4;

    if ((d == t) && (length > sizeof(t)))
        length = sizeof(t);

    STOREU(d + 0*5, s.a0);
    STOREU(d + 1*5, s.a1);
    STOREU(d + 2*5, s.a2);
    STOREU(d + 3*5, s.a3);
    STOREU(d + 4*5, s.a4);

    d[0*5 + 4] = c4[0];
    d[1*5 + 4] = c4[1];
    d[2*5 + 4] = c4[2];
    d[3*5 + 4] = c4[3];
    d[4*5 + 4] = c4[4]; //s.a44[0]

    if (d == t)
        memcpy(data, (UINT8 *)t + offset, length);
} //KeccakP1600_ExtractBytes

//***************************************************************************************
void KeccakP1600_ExtractAndAddBytes(const void *state, const UINT8 *input, UINT8 *output, size_t offset, size_t length)
//***************************************************************************************
{
    UINT64      t[25];
    UINT64      *t0;
    const UINT64 *dIn = (UINT64 *)input;
    UINT64      *dOut = (UINT64 *)output;
    UINT8       *t1, *dlIn, *dlOut;
    ptrdiff_t   lane_n = length / sizeof(UINT64);
    ptrdiff_t   byte_n = length % sizeof(UINT64);
    ptrdiff_t   i;

    KeccakP1600_ExtractBytes(state, (UINT8 *)t, 0, sizeof(t));

    t0 = (UINT64 *)((UINT8 *)t + offset);

    for (i = 0; i < lane_n; i++)
        dOut[i] = dIn[i] ^ t0[i];

    if (byte_n)
    {
        t1 = (UINT8 *)(t0 + i);
        dlIn = (UINT8 *)(dIn + i);
        dlOut = (UINT8 *)(dOut + i);

        for (i = 0; i < byte_n; i++)
            dlOut[i] = dlIn[i] ^ t1[i];
    }
} //KeccakP1600_ExtractAndAddBytes


//***************************
void KeccakP1600_Permute_Nrounds(void *state, unsigned int nrounds)
//***************************
{
    KECCAK_PERMUTE_VARS

    KECCAK_LOAD

    KECCAK_PERMUTE_LOOP(, nrounds)

    KECCAK_STORE
}

//***************************
void KeccakP1600_Permute_24rounds(void *state)
//***************************
{
    KECCAK_PERMUTE_VARS

    KECCAK_LOAD

    KECCAK_PERMUTE()

    KECCAK_STORE
} //KeccakP1600_Permute_24rounds

//***************************
void KeccakP1600_Permute_12rounds(void *state)
//***************************
{
    KECCAK_PERMUTE_VARS

    KECCAK_LOAD

    KECCAK_PERMUTE_12rounds()
    
    KECCAK_STORE
} //KeccakP1600_Permute_12rounds

//__KeccakF1600_FastLoop_Absorb
//**************************************************************************************************************
size_t KeccakF1600_FastLoop_Absorb(void *state, size_t laneCount, const UINT8 *data, size_t dataByteLen)
//**************************************************************************************************************
{
    KECCAK_PERMUTE_VARS
    const UINT64    *d;
    ptrdiff_t       di;

    KECCAK_LOAD

    for (di = 0; di <= (ptrdiff_t)(dataByteLen / sizeof(UINT64) - laneCount); di += laneCount)
    {
        d = (UINT64 *)data + di;

        switch (laneCount)
        {
        case 9:     //576
            a0 = XOR(a0, LOADU(d + 0*5));
            a1 = XOR(a1, LOADU(d + 1*5));
            c4 = XOR(c4, MASKLOAD(d + 0*5 + 4, 1, 0, 0, 0));
            break;

        case 13:    //832
            a0 = XOR(a0, LOADU(d + 0*5));
            a1 = XOR(a1, LOADU(d + 1*5));
            a2 = XOR(a2, MASKLOAD(d + 2*5, 1, 1, 1, 0));
            c4 = XOR(c4, SET(d[0*5 + 4], d[1*5 + 4], 0, 0));
            break;

        case 16:    //1024
            a0 = XOR(a0, LOADU(d + 0*5));
            a1 = XOR(a1, LOADU(d + 1*5));
            a2 = XOR(a2, LOADU(d + 2*5));
            a3 = XOR(a3, MASKLOAD(d + 3*5, 1, 0, 0, 0));
            c4 = XOR(c4, SET(d[0*5 + 4], d[1*5 + 4], d[2*5 + 4], 0));
            break;

        case 17:    //1088
            a0 = XOR(a0, LOADU(d + 0*5));
            a1 = XOR(a1, LOADU(d + 1*5));
            a2 = XOR(a2, LOADU(d + 2*5));
            a3 = XOR(a3, MASKLOAD(d + 3*5, 1, 1, 0, 0));
            c4 = XOR(c4, SET(d[0*5 + 4], d[1*5 + 4], d[2*5 + 4], 0));
            break;

        case 18:    //1152
            a0 = XOR(a0, LOADU(d + 0*5));
            a1 = XOR(a1, LOADU(d + 1*5));
            a2 = XOR(a2, LOADU(d + 2*5));
            a3 = XOR(a3, MASKLOAD(d + 3*5, 1, 1, 1, 0));
            c4 = XOR(c4, SET(d[0*5 + 4], d[1*5 + 4], d[2*5 + 4], 0));
            break;

        case 21:    //1344
            a0 = XOR(a0, LOADU(d + 0*5));
            a1 = XOR(a1, LOADU(d + 1*5));
            a2 = XOR(a2, LOADU(d + 2*5));
            a3 = XOR(a3, LOADU(d + 3*5));
            a4 = XOR(a4, MASKLOAD(d + 4*5, 1, 0, 0, 0));
            c4 = XOR(c4, SET(d[0*5 + 4], d[1*5 + 4], d[2*5 + 4], d[3*5 + 4]));
            break;

        case 25:    //1600
            a0 = XOR(a0, LOADU(d + 0*5));
            a1 = XOR(a1, LOADU(d + 1*5));
            a2 = XOR(a2, LOADU(d + 2*5));
            a3 = XOR(a3, LOADU(d + 3*5));
            a4 = XOR(a4, LOADU(d + 4*5));
            c4 = XOR(c4, SET(d[0*5 + 4], d[1*5 + 4], d[2*5 + 4], d[3*5 + 4]));
            a44 = XOR(a44, LOAD0(d + 4*5 + 4));
            break;

        default:
            KECCAK_STORE

            KeccakP1600_AddBytes(state, (UINT8 *)d, 0, laneCount * sizeof(UINT64));

            KECCAK_LOAD
        } //switch (laneCount)

        KECCAK_PERMUTE(_)
    } //for (di
    
    KECCAK_STORE

    return di * sizeof(UINT64);
} //KeccakF1600_FastLoop_Absorb
