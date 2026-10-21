/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Copyright IBM Corp. 2025, 2026
 *
 * ===================================================================================
 * Written by Danny Tsen <dtsen@us.ibm.com>
 *
 * Optimized inverse NTT implementation for ppc64be.
 *
 * Enable optimized inverse NTT implementation for PPC Big Endian by
 * Sandeep Umesh <sanumesh@in.ibm.com> assisted by Bob.
 */

#define ML_DSA_Q 8380417
#define ML_DSA_Q_NEG_INV 4236238847

#define Q_NEG_INV_OFFSET 16
#define FCONST_OFFSET 32
#define ZETA_INTT_OFFSET 48

#define Q_NEG_INV    0
#define V_Q          1

#define V_F          2
#define V_ZETA       2
#define V_Z0         2
#define V_Z1         3
#define V_Z2         4
#define V_Z3         5

#define GPR_OFFSET_C0 9
#define GPR_OFFSET_C1 11
#define GPR_OFFSET_C2 15
#define GPR_OFFSET_C3 17

#define GPR_OFFSET_P0 10
#define GPR_OFFSET_P1 12
#define GPR_OFFSET_P2 16
#define GPR_OFFSET_P3 18

/*
 * Word-size dependent definitions: the same source is used for 32-bit and
 * 64-bit AIX builds.
 */
#if defined(__64BIT__) || defined(_LP64) || defined(__LP64__) || defined(__powerpc64__)
#define STD       std
#define STDU      stdu
#define LD        ld
#define ADDR_WORD .llong
#else
#define STD       stw
#define STDU      stwu
#define LD        lwz
#define ADDR_WORD .long
#endif

.machine "any"
.csect .text[PR]

/*
 * SAVE_REGS / RESTORE_REGS
 * Saves GPRs 14-21 and VSX registers 52-61 (VRs 20-29).
 */
#define SAVE_REGS \
        STDU    1, -352(1); \
        mflr    0; \
        STD     14, 56(1); \
        STD     15, 64(1); \
        STD     16, 72(1); \
        STD     17, 80(1); \
        STD     18, 88(1); \
        STD     19, 96(1); \
        STD     20, 104(1); \
        STD     21, 112(1); \
        li      10, 128; \
        li      11, 144; \
        li      12, 160; \
        li      14, 176; \
        li      15, 192; \
        li      16, 208; \
        stxvx   52, 10, 1; \
        stxvx   53, 11, 1; \
        stxvx   54, 12, 1; \
        stxvx   55, 14, 1; \
        stxvx   56, 15, 1; \
        stxvx   57, 16, 1; \
        li      10, 224; \
        li      11, 240; \
        li      12, 256; \
        li      14, 272; \
        stxvx   58, 10, 1; \
        stxvx   59, 11, 1; \
        stxvx   60, 12, 1; \
        stxvx   61, 14, 1

#define RESTORE_REGS \
        li      10, 128; \
        li      11, 144; \
        li      12, 160; \
        li      14, 176; \
        li      15, 192; \
        li      16, 208; \
        lxvx    52, 10, 1; \
        lxvx    53, 11, 1; \
        lxvx    54, 12, 1; \
        lxvx    55, 14, 1; \
        lxvx    56, 15, 1; \
        lxvx    57, 16, 1; \
        li      10, 224; \
        li      11, 240; \
        li      12, 256; \
        li      14, 272; \
        lxvx    58, 10, 1; \
        lxvx    59, 11, 1; \
        lxvx    60, 12, 1; \
        lxvx    61, 14, 1; \
        LD      14, 56(1); \
        LD      15, 64(1); \
        LD      16, 72(1); \
        LD      17, 80(1); \
        LD      18, 88(1); \
        LD      19, 96(1); \
        LD      20, 104(1); \
        LD      21, 112(1); \
        mtlr    0; \
        addi    1, 1, 352

/*
 * Modular arithmetic primitives
 */
#define reduce_once_1x(vt, vsx_vt) \
        vsubuwm  16, vt, V_Q; \
        vcmpgtsw 17, V_Q, vt; \
        xxsel    vsx_vt, 48, vsx_vt, 49

#define Load_4zetas(vz0, vz1, vz2, vz3) \
        lxvw4x  34, 0, 14; \
        addi    14, 14, 16; \
        lxvw4x  35, 0, 14; \
        addi    14, 14, 16; \
        lxvw4x  36, 0, 14; \
        addi    14, 14, 16; \
        lxvw4x  37, 0, 14; \
        addi    14, 14, 16

#define Mont_scalar_mul_4x(vz0, vz1, vz2, vz3) \
        vmuleuw 10, 6, vz0; \
        vmulouw 11, 6, vz0; \
        vmuleuw 12, 7, vz1; \
        vmulouw 13, 7, vz1; \
        vmuleuw 14, 8, vz2; \
        vmulouw 15, 8, vz2; \
        vmuleuw 16, 9, vz3; \
        vmulouw 17, 9, vz3

#define Mont_reduce_4x \
        vmulouw 18, 10, Q_NEG_INV; \
        vmulouw 19, 11, Q_NEG_INV; \
        vmulouw 20, 12, Q_NEG_INV; \
        vmulouw 21, 13, Q_NEG_INV; \
        vmulouw 22, 14, Q_NEG_INV; \
        vmulouw 23, 15, Q_NEG_INV; \
        vmulouw 24, 16, Q_NEG_INV; \
        vmulouw 25, 17, Q_NEG_INV; \
        vmulouw 18, 18, V_Q; \
        vmulouw 19, 19, V_Q; \
        vmulouw 20, 20, V_Q; \
        vmulouw 21, 21, V_Q; \
        vmulouw 22, 22, V_Q; \
        vmulouw 23, 23, V_Q; \
        vmulouw 24, 24, V_Q; \
        vmulouw 25, 25, V_Q; \
        vaddudm 18, 18, 10; \
        vaddudm 19, 19, 11; \
        vaddudm 20, 20, 12; \
        vaddudm 21, 21, 13; \
        vaddudm 22, 22, 14; \
        vaddudm 23, 23, 15; \
        vaddudm 24, 24, 16; \
        vaddudm 25, 25, 17; \
        vmrgew  10, 18, 19; \
        vmrgew  11, 20, 21; \
        vmrgew  12, 22, 23; \
        vmrgew  13, 24, 25; \
        reduce_once_1x(10, 42); \
        reduce_once_1x(11, 43); \
        reduce_once_1x(12, 44); \
        reduce_once_1x(13, 45)

#define mont_mul_reduce_4x(vz0, vz1, vz2, vz3) \
        Mont_scalar_mul_4x(vz0, vz1, vz2, vz3); \
        Mont_reduce_4x

#define _Compute_4Coeff \
        vadduwm 26, 14, 18; \
        vsubuwm 10, 14, 18; \
        vadduwm 6,  10, V_Q; \
        vadduwm 27, 15, 19; \
        vsubuwm 11, 15, 19; \
        vadduwm 7,  11, V_Q; \
        vadduwm 28, 16, 20; \
        vsubuwm 12, 16, 20; \
        vadduwm 8,  12, V_Q; \
        vadduwm 29, 17, 21; \
        vsubuwm 13, 17, 21; \
        vadduwm 9,  13, V_Q; \
        reduce_once_1x(26, 58); \
        reduce_once_1x(27, 59); \
        reduce_once_1x(28, 60); \
        reduce_once_1x(29, 61)

#define Load_vmrg_coeffs_be(c1, c2, c3, c4, p1, p2, p3, p4) \
        lxvw4x  42, GPR_OFFSET_C0, 5; \
        lxvw4x  43, GPR_OFFSET_P0, 5; \
        vmrgew  c1, 10, 11; \
        vmrgow  p1, 10, 11; \
        lxvw4x  44, GPR_OFFSET_C1, 5; \
        lxvw4x  45, GPR_OFFSET_P1, 5; \
        vmrgew  c2, 12, 13; \
        vmrgow  p2, 12, 13; \
        lxvw4x  42, GPR_OFFSET_C2, 5; \
        lxvw4x  43, GPR_OFFSET_P2, 5; \
        vmrgew  c3, 10, 11; \
        vmrgow  p3, 10, 11; \
        lxvw4x  44, GPR_OFFSET_C3, 5; \
        lxvw4x  45, GPR_OFFSET_P3, 5; \
        vmrgew  c4, 12, 13; \
        vmrgow  p4, 12, 13

#define Load_xxperm_coeffs_be(c1_vsx, c2_vsx, c3_vsx, c4_vsx, p1_vsx, p2_vsx, p3_vsx, p4_vsx) \
        lxvw4x   1, GPR_OFFSET_C0, 5; \
        lxvw4x   2, GPR_OFFSET_P0, 5; \
        xxpermdi c1_vsx, 1, 2, 0; \
        xxpermdi p1_vsx, 1, 2, 3; \
        lxvw4x   3, GPR_OFFSET_C1, 5; \
        lxvw4x   4, GPR_OFFSET_P1, 5; \
        xxpermdi c2_vsx, 3, 4, 0; \
        xxpermdi p2_vsx, 3, 4, 3; \
        lxvw4x   1, GPR_OFFSET_C2, 5; \
        lxvw4x   2, GPR_OFFSET_P2, 5; \
        xxpermdi c3_vsx, 1, 2, 0; \
        xxpermdi p3_vsx, 1, 2, 3; \
        lxvw4x   3, GPR_OFFSET_C3, 5; \
        lxvw4x   4, GPR_OFFSET_P3, 5; \
        xxpermdi c4_vsx, 3, 4, 0; \
        xxpermdi p4_vsx, 3, 4, 3

#define delayed_writes_curr_peer_be(c1_vsx, p1_vsx, c2_vsx, p2_vsx, c3_vsx, p3_vsx, c4_vsx, p4_vsx) \
        stxvw4x c1_vsx, GPR_OFFSET_C0, 5; \
        stxvw4x p1_vsx, GPR_OFFSET_P0, 5; \
        stxvw4x c2_vsx, GPR_OFFSET_C1, 5; \
        stxvw4x p2_vsx, GPR_OFFSET_P1, 5; \
        stxvw4x c3_vsx, GPR_OFFSET_C2, 5; \
        stxvw4x p3_vsx, GPR_OFFSET_P2, 5; \
        stxvw4x c4_vsx, GPR_OFFSET_C3, 5; \
        stxvw4x p4_vsx, GPR_OFFSET_P3, 5

#define _delayed_writes_xxperm \
        xxpermdi 46, 58, 42, 0; \
        xxpermdi 47, 58, 42, 3; \
        xxpermdi 48, 59, 43, 0; \
        xxpermdi 49, 59, 43, 3; \
        xxpermdi 50, 60, 44, 0; \
        xxpermdi 51, 60, 44, 3; \
        xxpermdi 52, 61, 45, 0; \
        xxpermdi 53, 61, 45, 3; \
        delayed_writes_curr_peer_be(46, 47, 48, 49, 50, 51, 52, 53)

#define _delayed_writes_vmrg \
        vmrgew 14, 26, 10; \
        vmrgow 15, 26, 10; \
        vmrgew 16, 27, 11; \
        vmrgow 17, 27, 11; \
        vmrgew 18, 28, 12; \
        vmrgow 19, 28, 12; \
        vmrgew 20, 29, 13; \
        vmrgow 21, 29, 13; \
        delayed_writes_curr_peer_be(46, 47, 48, 49, 50, 51, 52, 53)

#define INTT_Layer1_4x \
        lxvw4x  34, 0, 14; \
        lxvw4x  35, 10, 14; \
        lxvw4x  36, 11, 14; \
        lxvw4x  37, 12, 14; \
        addi    14, 14, 64; \
        Load_vmrg_coeffs_be(14, 15, 16, 17, 18, 19, 20, 21); \
        _Compute_4Coeff; \
        mont_mul_reduce_4x(V_Z0, V_Z1, V_Z2, V_Z3); \
        _delayed_writes_vmrg; \
        addi    5, 5, 128

#define INTT_Layer2_4x \
        lxvw4x  34, 0, 14; \
        lxvw4x  35, 10, 14; \
        lxvw4x  36, 11, 14; \
        lxvw4x  37, 12, 14; \
        addi    14, 14, 64; \
        Load_xxperm_coeffs_be(46, 47, 48, 49, 50, 51, 52, 53); \
        _Compute_4Coeff; \
        mont_mul_reduce_4x(V_Z0, V_Z1, V_Z2, V_Z3); \
        _delayed_writes_xxperm; \
        addi    5, 5, 128

#define _load_curr_peer_coeffs \
        lxvw4x  50, GPR_OFFSET_P0, 5; \
        lxvw4x  51, GPR_OFFSET_P1, 5; \
        lxvw4x  52, GPR_OFFSET_P2, 5; \
        lxvw4x  53, GPR_OFFSET_P3, 5; \
        lxvw4x  46, GPR_OFFSET_C0, 5; \
        lxvw4x  47, GPR_OFFSET_C1, 5; \
        lxvw4x  48, GPR_OFFSET_C2, 5; \
        lxvw4x  49, GPR_OFFSET_C3, 5

#define INTT_Layer345_4x(vz0, vz1, vz2, vz3) \
        _load_curr_peer_coeffs; \
        _Compute_4Coeff; \
        mont_mul_reduce_4x(vz0, vz1, vz2, vz3); \
        delayed_writes_curr_peer_be(58, 42, 59, 43, 60, 44, 61, 45); \
        addi    5, 5, 128

#define INTT_Layer678(vz0, vz1, vz2, vz3) \
        _load_curr_peer_coeffs; \
        _Compute_4Coeff; \
        mont_mul_reduce_4x(vz0, vz1, vz2, vz3); \
        delayed_writes_curr_peer_be(58, 42, 59, 43, 60, 44, 61, 45); \
        addi    5, 5, 64

#define _Reload_4coeffs \
        lxvw4x  38, 0, 6; \
        lxvw4x  39, 10, 6; \
        lxvw4x  40, 11, 6; \
        lxvw4x  41, 12, 6

#define _update_curr_coeffs_4x \
        stxvw4x 42, 0, 6; \
        stxvw4x 43, 10, 6; \
        stxvw4x 44, 11, 6; \
        stxvw4x 45, 12, 6; \
        addi    6, 6, 64

#define POLY_Mont_Reduce_4x \
        _Reload_4coeffs; \
        mont_mul_reduce_4x(V_F, V_F, V_F, V_F); \
        _update_curr_coeffs_4x; \
        _Reload_4coeffs; \
        mont_mul_reduce_4x(V_F, V_F, V_F, V_F); \
        _update_curr_coeffs_4x; \
        _Reload_4coeffs; \
        mont_mul_reduce_4x(V_F, V_F, V_F, V_F); \
        _update_curr_coeffs_4x; \
        _Reload_4coeffs; \
        mont_mul_reduce_4x(V_F, V_F, V_F, V_F); \
        _update_curr_coeffs_4x

/* ===================================================================== */
/*
 * mldsa_poly_ntt_inverse_ppcbe(int32_t *r)
 *   Compute Inverse NTT based on the 8 layers:
 *     len = 1, 2, 4, 8, 16, 32, 64, 128.
 */
.globl  .mldsa_poly_ntt_inverse_ppcbe
.globl  mldsa_poly_ntt_inverse_ppcbe
.csect  mldsa_poly_ntt_inverse_ppcbe[DS]
mldsa_poly_ntt_inverse_ppcbe:
        ADDR_WORD  .mldsa_poly_ntt_inverse_ppcbe, TOC[TC0], 0

.csect  .text[PR]
.align  4
.mldsa_poly_ntt_inverse_ppcbe:

        SAVE_REGS

        /* load address of read-only constants through XCOFF TOC */
        LD      8, .Lmldsa_consts(2)
        lxvw4x  33, 0, 8
        li      10, Q_NEG_INV_OFFSET
        lxvw4x  32, 10, 8

        /* set zetas array */
        addi    14, 8, ZETA_INTT_OFFSET

.align 4
        /*
         * Layer 1, len = 1
         */
        mr      5, 3

        li      GPR_OFFSET_C0, 0
        li      GPR_OFFSET_C1, 0x20
        li      GPR_OFFSET_C2, 0x40
        li      GPR_OFFSET_C3, 0x60

        li      GPR_OFFSET_P0, 0x10
        li      GPR_OFFSET_P1, 0x30
        li      GPR_OFFSET_P2, 0x50
        li      GPR_OFFSET_P3, 0x70

        INTT_Layer1_4x
        INTT_Layer1_4x
        INTT_Layer1_4x
        INTT_Layer1_4x
        INTT_Layer1_4x
        INTT_Layer1_4x
        INTT_Layer1_4x
        INTT_Layer1_4x

.align 4
        /*
         * Layer 2, len = 2
         */
        mr      5, 3

        INTT_Layer2_4x
        INTT_Layer2_4x
        INTT_Layer2_4x
        INTT_Layer2_4x
        INTT_Layer2_4x
        INTT_Layer2_4x
        INTT_Layer2_4x
        INTT_Layer2_4x

.align 4
        /*
         * Layer 3, len = 4
         */
        mr      5, 3

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z1, V_Z2, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z1, V_Z2, V_Z3)

.align 4
        /*
         * Layer 4, len = 8
         */
        mr      5, 3

        li      GPR_OFFSET_C1, 0x10
        li      GPR_OFFSET_C2, 0x40
        li      GPR_OFFSET_C3, 0x50

        li      GPR_OFFSET_P0, 0x20
        li      GPR_OFFSET_P1, 0x30
        li      GPR_OFFSET_P2, 0x60
        li      GPR_OFFSET_P3, 0x70

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z0, V_Z1, V_Z1)
        INTT_Layer345_4x(V_Z2, V_Z2, V_Z3, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z0, V_Z1, V_Z1)
        INTT_Layer345_4x(V_Z2, V_Z2, V_Z3, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z0, V_Z1, V_Z1)
        INTT_Layer345_4x(V_Z2, V_Z2, V_Z3, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z0, V_Z1, V_Z1)
        INTT_Layer345_4x(V_Z2, V_Z2, V_Z3, V_Z3)

.align 4
        /*
         * Layer 5, len = 16
         */
        mr      5, 3

        li      GPR_OFFSET_C1, 0x10
        li      GPR_OFFSET_C2, 0x20
        li      GPR_OFFSET_C3, 0x30

        li      GPR_OFFSET_P0, 0x40
        li      GPR_OFFSET_P1, 0x50
        li      GPR_OFFSET_P2, 0x60
        li      GPR_OFFSET_P3, 0x70

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z0, V_Z0, V_Z0)
        INTT_Layer345_4x(V_Z1, V_Z1, V_Z1, V_Z1)
        INTT_Layer345_4x(V_Z2, V_Z2, V_Z2, V_Z2)
        INTT_Layer345_4x(V_Z3, V_Z3, V_Z3, V_Z3)

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer345_4x(V_Z0, V_Z0, V_Z0, V_Z0)
        INTT_Layer345_4x(V_Z1, V_Z1, V_Z1, V_Z1)
        INTT_Layer345_4x(V_Z2, V_Z2, V_Z2, V_Z2)
        INTT_Layer345_4x(V_Z3, V_Z3, V_Z3, V_Z3)

.align 4
        /*
         * Layer 6, len = 32
         */
        mr      5, 3

        li      GPR_OFFSET_P0, 0x80
        li      GPR_OFFSET_P1, 0x90
        li      GPR_OFFSET_P2, 0xa0
        li      GPR_OFFSET_P3, 0xb0

        Load_4zetas(V_Z0, V_Z1, V_Z2, V_Z3)
        INTT_Layer678(V_Z0, V_Z0, V_Z0, V_Z0)
        INTT_Layer678(V_Z0, V_Z0, V_Z0, V_Z0)
        addi    5, 5, 0x80

        INTT_Layer678(V_Z1, V_Z1, V_Z1, V_Z1)
        INTT_Layer678(V_Z1, V_Z1, V_Z1, V_Z1)
        addi    5, 5, 0x80

        INTT_Layer678(V_Z2, V_Z2, V_Z2, V_Z2)
        INTT_Layer678(V_Z2, V_Z2, V_Z2, V_Z2)
        addi    5, 5, 0x80

        INTT_Layer678(V_Z3, V_Z3, V_Z3, V_Z3)
        INTT_Layer678(V_Z3, V_Z3, V_Z3, V_Z3)

.align 4
        /*
         * Layer 7, len = 64
         */
        mr      5, 3

        li      GPR_OFFSET_P0, 0x100
        li      GPR_OFFSET_P1, 0x110
        li      GPR_OFFSET_P2, 0x120
        li      GPR_OFFSET_P3, 0x130

        lxvw4x  34, 0, 14
        addi    14, 14, 16
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        addi    5, 5, 0x100

        lxvw4x  34, 0, 14
        addi    14, 14, 16
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)

        /*
         * Layer 8, len = 128
         */
        mr      5, 3

        li      GPR_OFFSET_P0, 0x200
        li      GPR_OFFSET_P1, 0x210
        li      GPR_OFFSET_P2, 0x220
        li      GPR_OFFSET_P3, 0x230

        lxvw4x  34, 0, 14
        addi    14, 14, 16

        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)
        INTT_Layer678(V_ZETA, V_ZETA, V_ZETA, V_ZETA)

        /*
         * Montgomery reduce loops with
         *   constant inverse_degree_montgomery f=41978 (mont^2/256)
         *  updated coeff = montgomery_reduce((int64_t)f * coeff)
         */
        addi    10, 8, FCONST_OFFSET
        lxvw4x  34, 0, 10

        li      10, 16
        li      11, 32
        li      12, 48

        mr      6, 3

        POLY_Mont_Reduce_4x
        POLY_Mont_Reduce_4x
        POLY_Mont_Reduce_4x
        POLY_Mont_Reduce_4x

        RESTORE_REGS
        blr
.long 0
.byte 0,12,0x14,0,0,0,0,0

/* ===================================================================== */

.toc
.Lmldsa_consts:
        .tc .mldsa_consts[TC],.mldsa_consts[RO]

.csect .mldsa_consts[RO], 4
.align 4
.mldsa_consts:
.long ML_DSA_Q, ML_DSA_Q, ML_DSA_Q, ML_DSA_Q
.long ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV, ML_DSA_Q_NEG_INV
.long 41978, 41978, 41978, 41978

.mldsa_izetas:
/* Zetas for Len=1 */
.long 6403635, 6979993, 846154, 4442679, 1362209, 4460757, 48306, 554416
.long 3545687, 976891, 6767575, 8196974, 2286327, 2235985, 420899, 2939036
.long 3833893, 1104333, 260646, 1667432, 6470041, 6656817, 1803090, 426683
.long 7908339, 975884, 6662682, 6167306, 8110657, 4856520, 4513516, 3038916
.long 1799107, 6727783, 3694233, 7570268, 5366416, 8217573, 6764025, 3183426
.long 1207385, 5011305, 8194886, 6423145, 164721, 5948022, 5925962, 2013608
.long 3776993, 3724270, 7786281, 2584293, 1846953, 2831860, 1671176, 542412
.long 4974386, 7603226, 6144537, 6880252, 1374803, 6463336, 2546312, 1279661
.long 1962642, 7067962, 5074302, 451100, 1430225, 7143142, 3318210, 1333058
.long 1050970, 6511298, 6476982, 2994039, 3548272, 7129923, 5744496, 3767016
.long 6784443, 7132797, 5894064, 4325093, 7115408, 5688936, 2590150, 5538076
.long 8177373, 3342277, 6644538, 4943130, 4272102, 8093429, 2437823, 8038120
.long 3595838, 525098, 768622, 3556995, 5173371, 3122442, 6348669, 655327
.long 522500, 1613174, 43260, 7884926, 7561383, 6521319, 7470875, 7479715
.long 3193378, 3759364, 1197226, 3520352, 4867236, 5945978, 1235728, 8113420
.long 3562462, 6136326, 2446433, 3342478, 4562441, 4972711, 6063917, 6288750
/* For Len=2 */
.long 4540456, 4540456, 3628969, 3628969, 3881060, 3881060, 3019102, 3019102
.long 1439742, 1439742, 812732, 812732, 1584928, 1584928, 7094748, 7094748
.long 7039087, 7039087, 7064828, 7064828, 177440, 177440, 2409325, 2409325
.long 1851402, 1851402, 5220671, 5220671, 3553272, 3553272, 8190869, 8190869
.long 1316856, 1316856, 7620448, 7620448, 210977, 210977, 5991061, 5991061
.long 3249728, 3249728, 6727353, 6727353, 8578, 8578, 3724342, 3724342
.long 4421799, 4421799, 7475901, 7475901, 1100098, 1100098, 8336129, 8336129
.long 5282425, 5282425, 7871466, 7871466, 8115473, 8115473, 3343383, 3343383
.long 1430430, 1430430, 6527646, 6527646, 7031341, 7031341, 381987, 381987
.long 1308169, 1308169, 22981, 22981, 1228525, 1228525, 671102, 671102
.long 2477047, 2477047, 411027, 411027, 3693493, 3693493, 2967645, 2967645
.long 5665122, 5665122, 6232521, 6232521, 983419, 983419, 4968207, 4968207
.long 8253495, 8253495, 3632928, 3632928, 3157330, 3157330, 3190144, 3190144
.long 1000202, 1000202, 4083598, 4083598, 6441103, 6441103, 1257611, 1257611
.long 1585221, 1585221, 6203962, 6203962, 4904467, 4904467, 1452451, 1452451
.long 3041255, 3041255, 3677745, 3677745, 1528703, 1528703, 3930395, 3930395
/* For Len=4 */
.long 2797779, 2797779, 2797779, 2797779, 6308525, 6308525, 6308525, 6308525
.long 2556880, 2556880, 2556880, 2556880, 4479693, 4479693, 4479693, 4479693
.long 4499374, 4499374, 4499374, 4499374, 7426187, 7426187, 7426187, 7426187
.long 7849063, 7849063, 7849063, 7849063, 7568473, 7568473, 7568473, 7568473
.long 4680821, 4680821, 4680821, 4680821, 1600420, 1600420, 1600420, 1600420
.long 2140649, 2140649, 2140649, 2140649, 4873154, 4873154, 4873154, 4873154
.long 3821735, 3821735, 3821735, 3821735, 4874723, 4874723, 4874723, 4874723
.long 1643818, 1643818, 1643818, 1643818, 1699267, 1699267, 1699267, 1699267
.long 539299, 539299, 539299, 539299, 6031717, 6031717, 6031717, 6031717
.long 300467, 300467, 300467, 300467, 4840449, 4840449, 4840449, 4840449
.long 2867647, 2867647, 2867647, 2867647, 4805995, 4805995, 4805995, 4805995
.long 3043716, 3043716, 3043716, 3043716, 3861115, 3861115, 3861115, 3861115
.long 4464978, 4464978, 4464978, 4464978, 2537516, 2537516, 2537516, 2537516
.long 3592148, 3592148, 3592148, 3592148, 1661693, 1661693, 1661693, 1661693
.long 4849980, 4849980, 4849980, 4849980, 5303092, 5303092, 5303092, 5303092
.long 8284641, 8284641, 8284641, 8284641, 5674394, 5674394, 5674394, 5674394
/* zetas for other len */
.long 8100412, 8100412, 8100412, 8100412, 4369920, 4369920, 4369920, 4369920
.long 19422, 19422, 19422, 19422, 6623180, 6623180, 6623180, 6623180
.long 3277672, 3277672, 3277672, 3277672, 1399561, 1399561, 1399561, 1399561
.long 3859737, 3859737, 3859737, 3859737, 2118186, 2118186, 2118186, 2118186
.long 2108549, 2108549, 2108549, 2108549, 5760665, 5760665, 5760665, 5760665
.long 1119584, 1119584, 1119584, 1119584, 549488, 549488, 549488, 549488
.long 4794489, 4794489, 4794489, 4794489, 1079900, 1079900, 1079900, 1079900
.long 7356305, 7356305, 7356305, 7356305, 5654953, 5654953, 5654953, 5654953
.long 5700314, 5700314, 5700314, 5700314, 5268920, 5268920, 5268920, 5268920
.long 2884855, 2884855, 2884855, 2884855, 5260684, 5260684, 5260684, 5260684
.long 2091905, 2091905, 2091905, 2091905, 359251, 359251, 359251, 359251
.long 6026966, 6026966, 6026966, 6026966, 6554070, 6554070, 6554070, 6554070
.long 7913949, 7913949, 7913949, 7913949, 876248, 876248, 876248, 876248
.long 777960, 777960, 777960, 777960, 8143293, 8143293, 8143293, 8143293
.long 518909, 518909, 518909, 518909, 2608894, 2608894, 2608894, 2608894
.long 8354570, 8354570, 8354570, 8354570
