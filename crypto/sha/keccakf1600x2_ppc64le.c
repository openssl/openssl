/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
 * Written by Nimet Ozkan <nimet.ozkan@ibm.com>
 */

#include "shakex2_ppc64le.h"

/* ============================================================================
 * Vector Type Constructors and Constants
 * ============================================================================ */
static const v2_u64 VROUND_TABLE[24] = {
	{ 0x0000000000000001ULL, 0x0000000000000001ULL },
	{ 0x0000000000008082ULL, 0x0000000000008082ULL },
	{ 0x800000000000808aULL, 0x800000000000808aULL },
	{ 0x8000000080008000ULL, 0x8000000080008000ULL },
	{ 0x000000000000808bULL, 0x000000000000808bULL },
	{ 0x0000000080000001ULL, 0x0000000080000001ULL },
	{ 0x8000000080008081ULL, 0x8000000080008081ULL },
	{ 0x8000000000008009ULL, 0x8000000000008009ULL },
	{ 0x000000000000008aULL, 0x000000000000008aULL },
	{ 0x0000000000000088ULL, 0x0000000000000088ULL },
	{ 0x0000000080008009ULL, 0x0000000080008009ULL },
	{ 0x000000008000000aULL, 0x000000008000000aULL },
	{ 0x000000008000808bULL, 0x000000008000808bULL },
	{ 0x800000000000008bULL, 0x800000000000008bULL },
	{ 0x8000000000008089ULL, 0x8000000000008089ULL },
	{ 0x8000000000008003ULL, 0x8000000000008003ULL },
	{ 0x8000000000008002ULL, 0x8000000000008002ULL },
	{ 0x8000000000000080ULL, 0x8000000000000080ULL },
	{ 0x000000000000800aULL, 0x000000000000800aULL },
	{ 0x800000008000000aULL, 0x800000008000000aULL },
	{ 0x8000000080008081ULL, 0x8000000080008081ULL },
	{ 0x8000000000008080ULL, 0x8000000000008080ULL },
	{ 0x0000000080000001ULL, 0x0000000080000001ULL },
	{ 0x8000000080008008ULL, 0x8000000080008008ULL }
};

#define VCONST(n) ((__vector uint64_t) { n, n })
#define V0 ((__vector uint64_t) { 0, 0 })
#define V1 ((__vector uint64_t) { 1, 1 })
#define U8_ST(u64arr) ((uint8_t *) (u64arr))

/* ============================================================================
 * Keccak Rho Step Rotation Constants
 * ============================================================================ */
#define RHO0 VCONST(1)
#define RHO1 VCONST(3)
#define RHO2 VCONST(6)
#define RHO3 VCONST(10)
#define RHO4 VCONST(15)
#define RHO5 VCONST(21)
#define RHO6 VCONST(28)
#define RHO7 VCONST(36)
#define RHO8 VCONST(45)
#define RHO9 VCONST(55)
#define RHO10 VCONST(2)
#define RHO11 VCONST(14)
#define RHO12 VCONST(27)
#define RHO13 VCONST(41)
#define RHO14 VCONST(56)
#define RHO15 VCONST(8)
#define RHO16 VCONST(25)
#define RHO17 VCONST(43)
#define RHO18 VCONST(62)
#define RHO19 VCONST(18)
#define RHO20 VCONST(39)
#define RHO21 VCONST(61)
#define RHO22 VCONST(20)
#define RHO23 VCONST(44)

#define OR(c, a, b) c = (a | b)
#define XOR(c, a, b) c = (a ^ b)
#define AND(c, a, b) c = (a & b)
#define ADD(c, a, b) c = (a + b)
#define LSL(c, a, b) c = (a << b)
#define VRL(c, a, b) c = vec_rl(a, b)

#define CTHETA(out, a, b, c, d, e) \
	XOR(out, a, b);            \
	XOR(out, out, c);          \
	XOR(out, out, d);          \
	XOR(out, out, e);

#define VROTL64(c, a, b) \
	VRL(c, a, b);

#define DTHETA(c, a, b)    \
	VROTL64(c, b, V1); \
	XOR(c, c, a);

#define CHI(out, a, b, c) \
	XOR(out, a, vec_andc(c, b));

#define RHOPI(x, y, z, t) \
	x = y;            \
	VROTL64(y, z, t);

#define XSTATEVARS                                 \
	__vector uint64_t r0, r1, r2, r3, r4;      \
	__vector uint64_t r5, r6, r7, r8, r9;      \
	__vector uint64_t r10, r11, r12, r13, r14; \
	__vector uint64_t r15, r16, r17, r18, r19; \
	__vector uint64_t r20, r21, r22, r23, r24;

#define XTHETAVARS                            \
	__vector uint64_t c0, c1, c2, c3, c4; \
	__vector uint64_t d0, d1, d2, d3, d4;

#define XRhoPIChiVARS \
	__vector uint64_t t0, t1, t2, t3, t4;

#define LOADST(state)            \
	r0 = VCONST(state[0]);   \
	r1 = VCONST(state[1]);   \
	r2 = VCONST(state[2]);   \
	r3 = VCONST(state[3]);   \
	r4 = VCONST(state[4]);   \
	r5 = VCONST(state[5]);   \
	r6 = VCONST(state[6]);   \
	r7 = VCONST(state[7]);   \
	r8 = VCONST(state[8]);   \
	r9 = VCONST(state[9]);   \
	r10 = VCONST(state[10]); \
	r11 = VCONST(state[11]); \
	r12 = VCONST(state[12]); \
	r13 = VCONST(state[13]); \
	r14 = VCONST(state[14]); \
	r15 = VCONST(state[15]); \
	r16 = VCONST(state[16]); \
	r17 = VCONST(state[17]); \
	r18 = VCONST(state[18]); \
	r19 = VCONST(state[19]); \
	r20 = VCONST(state[20]); \
	r21 = VCONST(state[21]); \
	r22 = VCONST(state[22]); \
	r23 = VCONST(state[23]); \
	r24 = VCONST(state[24]);

#define STOREST(state)      \
	state[0] = r0[0];   \
	state[1] = r1[0];   \
	state[2] = r2[0];   \
	state[3] = r3[0];   \
	state[4] = r4[0];   \
	state[5] = r5[0];   \
	state[6] = r6[0];   \
	state[7] = r7[0];   \
	state[8] = r8[0];   \
	state[9] = r9[0];   \
	state[10] = r10[0]; \
	state[11] = r11[0]; \
	state[12] = r12[0]; \
	state[13] = r13[0]; \
	state[14] = r14[0]; \
	state[15] = r15[0]; \
	state[16] = r16[0]; \
	state[17] = r17[0]; \
	state[18] = r18[0]; \
	state[19] = r19[0]; \
	state[20] = r20[0]; \
	state[21] = r21[0]; \
	state[22] = r22[0]; \
	state[23] = r23[0]; \
	state[24] = r24[0];

#define XLOADST_MULT(state1, state2)                          \
	r0 = (__vector uint64_t) { state1[0], state2[0] };    \
	r1 = (__vector uint64_t) { state1[1], state2[1] };    \
	r2 = (__vector uint64_t) { state1[2], state2[2] };    \
	r3 = (__vector uint64_t) { state1[3], state2[3] };    \
	r4 = (__vector uint64_t) { state1[4], state2[4] };    \
	r5 = (__vector uint64_t) { state1[5], state2[5] };    \
	r6 = (__vector uint64_t) { state1[6], state2[6] };    \
	r7 = (__vector uint64_t) { state1[7], state2[7] };    \
	r8 = (__vector uint64_t) { state1[8], state2[8] };    \
	r9 = (__vector uint64_t) { state1[9], state2[9] };    \
	r10 = (__vector uint64_t) { state1[10], state2[10] }; \
	r11 = (__vector uint64_t) { state1[11], state2[11] }; \
	r12 = (__vector uint64_t) { state1[12], state2[12] }; \
	r13 = (__vector uint64_t) { state1[13], state2[13] }; \
	r14 = (__vector uint64_t) { state1[14], state2[14] }; \
	r15 = (__vector uint64_t) { state1[15], state2[15] }; \
	r16 = (__vector uint64_t) { state1[16], state2[16] }; \
	r17 = (__vector uint64_t) { state1[17], state2[17] }; \
	r18 = (__vector uint64_t) { state1[18], state2[18] }; \
	r19 = (__vector uint64_t) { state1[19], state2[19] }; \
	r20 = (__vector uint64_t) { state1[20], state2[20] }; \
	r21 = (__vector uint64_t) { state1[21], state2[21] }; \
	r22 = (__vector uint64_t) { state1[22], state2[22] }; \
	r23 = (__vector uint64_t) { state1[23], state2[23] }; \
	r24 = (__vector uint64_t) { state1[24], state2[24] };

#define XSTOREST_MULT(state1, state2) \
	do {                          \
		state1[0] = r0[0];    \
		state2[0] = r0[1];    \
		state1[1] = r1[0];    \
		state2[1] = r1[1];    \
		state1[2] = r2[0];    \
		state2[2] = r2[1];    \
		state1[3] = r3[0];    \
		state2[3] = r3[1];    \
		state1[4] = r4[0];    \
		state2[4] = r4[1];    \
		state1[5] = r5[0];    \
		state2[5] = r5[1];    \
		state1[6] = r6[0];    \
		state2[6] = r6[1];    \
		state1[7] = r7[0];    \
		state2[7] = r7[1];    \
		state1[8] = r8[0];    \
		state2[8] = r8[1];    \
		state1[9] = r9[0];    \
		state2[9] = r9[1];    \
		state1[10] = r10[0];  \
		state2[10] = r10[1];  \
		state1[11] = r11[0];  \
		state2[11] = r11[1];  \
		state1[12] = r12[0];  \
		state2[12] = r12[1];  \
		state1[13] = r13[0];  \
		state2[13] = r13[1];  \
		state1[14] = r14[0];  \
		state2[14] = r14[1];  \
		state1[15] = r15[0];  \
		state2[15] = r15[1];  \
		state1[16] = r16[0];  \
		state2[16] = r16[1];  \
		state1[17] = r17[0];  \
		state2[17] = r17[1];  \
		state1[18] = r18[0];  \
		state2[18] = r18[1];  \
		state1[19] = r19[0];  \
		state2[19] = r19[1];  \
		state1[20] = r20[0];  \
		state2[20] = r20[1];  \
		state1[21] = r21[0];  \
		state2[21] = r21[1];  \
		state1[22] = r22[0];  \
		state2[22] = r22[1];  \
		state1[23] = r23[0];  \
		state2[23] = r23[1];  \
		state1[24] = r24[0];  \
		state2[24] = r24[1];  \
	} while (0)

#define SET_R0_TO_R4 \
	t0 = r0;     \
	t1 = r1;     \
	t2 = r2;     \
	t3 = r3;     \
	t4 = r4;
#define SET_R5_TO_R9 \
	t0 = r5;     \
	t1 = r6;     \
	t2 = r7;     \
	t3 = r8;     \
	t4 = r9;
#define SET_R10_TO_R14 \
	t0 = r10;      \
	t1 = r11;      \
	t2 = r12;      \
	t3 = r13;      \
	t4 = r14;
#define SET_R15_TO_R19 \
	t0 = r15;      \
	t1 = r16;      \
	t2 = r17;      \
	t3 = r18;      \
	t4 = r19;
#define SET_R20_TO_R24 \
	t0 = r20;      \
	t1 = r21;      \
	t2 = r22;      \
	t3 = r23;      \
	t4 = r24;

#define KECCAKF_THETA_INIT                 \
	CTHETA(c0, r0, r5, r10, r15, r20); \
	CTHETA(c1, r1, r6, r11, r16, r21); \
	CTHETA(c2, r2, r7, r12, r17, r22); \
	CTHETA(c3, r3, r8, r13, r18, r23); \
	CTHETA(c4, r4, r9, r14, r19, r24); \
	DTHETA(d0, c4, c1);                \
	DTHETA(d1, c0, c2);                \
	DTHETA(d2, c1, c3);                \
	DTHETA(d3, c2, c4);                \
	DTHETA(d4, c3, c0);

#define KECCAKF_THETA_PROCESS \
	XOR(r0, r0, d0);      \
	XOR(r5, r5, d0);      \
	XOR(r10, r10, d0);    \
	XOR(r15, r15, d0);    \
	XOR(r20, r20, d0);    \
	XOR(r1, r1, d1);      \
	XOR(r6, r6, d1);      \
	XOR(r11, r11, d1);    \
	XOR(r16, r16, d1);    \
	XOR(r21, r21, d1);    \
	XOR(r2, r2, d2);      \
	XOR(r7, r7, d2);      \
	XOR(r12, r12, d2);    \
	XOR(r17, r17, d2);    \
	XOR(r22, r22, d2);    \
	XOR(r3, r3, d3);      \
	XOR(r8, r8, d3);      \
	XOR(r13, r13, d3);    \
	XOR(r18, r18, d3);    \
	XOR(r23, r23, d3);    \
	XOR(r4, r4, d4);      \
	XOR(r9, r9, d4);      \
	XOR(r14, r14, d4);    \
	XOR(r19, r19, d4);    \
	XOR(r24, r24, d4);

#define KECCAKF_RHOPI              \
	RHOPI(t0, r10, r1, RHO0);  \
	RHOPI(t1, r7, t0, RHO1);   \
	RHOPI(t2, r11, t1, RHO2);  \
	RHOPI(t3, r17, t2, RHO3);  \
	RHOPI(t0, r18, t3, RHO4);  \
	RHOPI(t1, r3, t0, RHO5);   \
	RHOPI(t2, r5, t1, RHO6);   \
	RHOPI(t3, r16, t2, RHO7);  \
	RHOPI(t0, r8, t3, RHO8);   \
	RHOPI(t1, r21, t0, RHO9);  \
	RHOPI(t2, r24, t1, RHO10); \
	RHOPI(t3, r4, t2, RHO11);  \
	RHOPI(t0, r15, t3, RHO12); \
	RHOPI(t1, r23, t0, RHO13); \
	RHOPI(t2, r19, t1, RHO14); \
	RHOPI(t3, r13, t2, RHO15); \
	RHOPI(t0, r12, t3, RHO16); \
	RHOPI(t1, r2, t0, RHO17);  \
	RHOPI(t2, r20, t1, RHO18); \
	RHOPI(t3, r14, t2, RHO19); \
	RHOPI(t0, r22, t3, RHO20); \
	RHOPI(t1, r9, t0, RHO21);  \
	RHOPI(t2, r6, t1, RHO22);  \
	RHOPI(t3, r1, t2, RHO23);

#define KECCAKF_CHI            \
	SET_R0_TO_R4           \
	CHI(r0, r0, t1, t2);   \
	CHI(r1, r1, t2, t3);   \
	CHI(r2, r2, t3, t4);   \
	CHI(r3, r3, t4, t0);   \
	CHI(r4, r4, t0, t1);   \
	SET_R5_TO_R9           \
	CHI(r5, r5, t1, t2);   \
	CHI(r6, r6, t2, t3);   \
	CHI(r7, r7, t3, t4);   \
	CHI(r8, r8, t4, t0);   \
	CHI(r9, r9, t0, t1);   \
	SET_R10_TO_R14         \
	CHI(r10, r10, t1, t2); \
	CHI(r11, r11, t2, t3); \
	CHI(r12, r12, t3, t4); \
	CHI(r13, r13, t4, t0); \
	CHI(r14, r14, t0, t1); \
	SET_R15_TO_R19         \
	CHI(r15, r15, t1, t2); \
	CHI(r16, r16, t2, t3); \
	CHI(r17, r17, t3, t4); \
	CHI(r18, r18, t4, t0); \
	CHI(r19, r19, t0, t1); \
	SET_R20_TO_R24         \
	CHI(r20, r20, t1, t2); \
	CHI(r21, r21, t2, t3); \
	CHI(r22, r22, t3, t4); \
	CHI(r23, r23, t4, t0); \
	CHI(r24, r24, t0, t1);

#define KECCAKF_IOTA(round) \
	XOR(r0, r0, (VROUND_TABLE[round]));

#define KECCAKF_ROUND(round)  \
	KECCAKF_THETA_INIT    \
	KECCAKF_THETA_PROCESS \
	KECCAKF_RHOPI         \
	KECCAKF_CHI           \
	KECCAKF_IOTA(round)

#define XKECCAKF_ROUND24   \
	KECCAKF_ROUND(0);  \
	KECCAKF_ROUND(1);  \
	KECCAKF_ROUND(2);  \
	KECCAKF_ROUND(3);  \
	KECCAKF_ROUND(4);  \
	KECCAKF_ROUND(5);  \
	KECCAKF_ROUND(6);  \
	KECCAKF_ROUND(7);  \
	KECCAKF_ROUND(8);  \
	KECCAKF_ROUND(9);  \
	KECCAKF_ROUND(10); \
	KECCAKF_ROUND(11); \
	KECCAKF_ROUND(12); \
	KECCAKF_ROUND(13); \
	KECCAKF_ROUND(14); \
	KECCAKF_ROUND(15); \
	KECCAKF_ROUND(16); \
	KECCAKF_ROUND(17); \
	KECCAKF_ROUND(18); \
	KECCAKF_ROUND(19); \
	KECCAKF_ROUND(20); \
	KECCAKF_ROUND(21); \
	KECCAKF_ROUND(22); \
	KECCAKF_ROUND(23);

#define keccakf_1600_mult(state1, state2)      \
	do {                                   \
		XSTATEVARS;                    \
		XTHETAVARS;                    \
		XRhoPIChiVARS;                 \
		XLOADST_MULT(state1, state2);  \
		XKECCAKF_ROUND24;              \
		XSTOREST_MULT(state1, state2); \
	} while (0)

static void keccak_reset0(shakex2_ppc64le_ctx_t *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

static void keccakf1600x2_ppc64le(uint64_t *state1, uint64_t *state2)
{
	keccakf_1600_mult(state1, state2);
}

/* Initialize SHAKE context with specified security level */
void shakex2_config_ppc64le(shakex2_ppc64le_ctx_t *ctx, int bits) {
    keccak_reset0(ctx);
    ctx->sponge._block_rate = (_bytes(KECCAK_BITS_TOTAL - (2 * bits)));
    ctx->sponge._capacity = 2 * bits;
    ctx->sponge._digestsz = 0;
    ctx->sponge._pad = SHAKE_SUFFIX;
    ctx->sponge._avail = ctx->sponge._block_rate;
    ctx->sponge._threshold = 0;
}

/* Absorb data into both SHAKE states (matching reference keccak_shake_absorb_mult) */
void shakex2_absorb_ppc64le(shakex2_ppc64le_ctx_t *ctx, const void *data0, size_t len0,
                                                      const void *data1, size_t len1) {
    const uint8_t *entry1;
    const uint8_t *entry2;
    uint64_t i;
    uint8_t *st1, *st2;
    uint64_t *stptr1, *stptr2;
    uint64_t nwords;
    uint32_t cont;
    size_t entrysz;

    entrysz = (len0 > len1) ? len0 : len1;

    st1 = (uint8_t *)ctx->st.statex2[0];
    st2 = (uint8_t *)ctx->st.statex2[1];

    entry1 = (const uint8_t *)data0;
    entry2 = (const uint8_t *)data1;

    while (entrysz > 0) {
        i = 0;
        uint64_t untouched;
        uint64_t *vstate1;
	uint64_t *vstate2;

	untouched = get_min_bsize((ctx->sponge._block_rate - ctx->sponge._threshold), entrysz);
        nwords = (_bytes(untouched));;

        vstate1 = (uint64_t *)&st1[ctx->sponge._threshold];
        vstate2 = (uint64_t *)&st2[ctx->sponge._threshold];

        /* XORing in 8-byte chunks */
        for (; i < nwords; i++) {
            if (entry1 && len0 > 0) {
                stptr1 = &vstate1[i];
                *stptr1 ^= *((uint64_t *)&entry1[i * 8]);
            }
            if (entry2 && len1 > 0) {
                stptr2 = &vstate2[i];
                *stptr2 ^= *((uint64_t *)&entry2[i * 8]);
            }
        }

        /* XOR remaining bytes */
        cont = nwords * 8;
        for (i = cont; i < untouched; i++) {
            if (entry1 && len0 > 0)
                ((uint8_t *)vstate1)[i] ^= entry1[i];
            if (entry2 && len1 > 0)
                ((uint8_t *)vstate2)[i] ^= entry2[i];
        }

        ctx->sponge._threshold += untouched;

	if (entry1) entry1 += untouched;
        if (entry2) entry2 += untouched;
        if (len0 > untouched) len0 -= untouched;
        else len0 = 0;
        if (len1 > untouched) len1 -= untouched;
        else len1 = 0;

	entrysz -= untouched;

        if (ctx->sponge._threshold == ctx->sponge._block_rate) {
            keccakf1600x2_ppc64le(ctx->st.statex2[0], ctx->st.statex2[1]);
            ctx->sponge._threshold = 0;
        }
    }
}

/* Complete absorption phase with padding */
static void shakex2_complete_absorb_ppc64le(shakex2_ppc64le_ctx_t *ctx) {
    uint8_t *state0;
    uint8_t *state1;

    state0 = (uint8_t *)ctx->st.statex2[0];
    state1 = (uint8_t *)ctx->st.statex2[1];

    if (ctx->sponge._threshold != ctx->sponge._block_rate)
    {
        state0[ctx->sponge._threshold] ^= ctx->sponge._pad;
        state0[ctx->sponge._block_rate - 1] ^= KECCAK_DOM;

        state1[ctx->sponge._threshold] ^= ctx->sponge._pad;
        state1[ctx->sponge._block_rate - 1] ^= KECCAK_DOM;
    }

    keccakf1600x2_ppc64le(ctx->st.statex2[0], ctx->st.statex2[1]);
    ctx->sponge._threshold = 0;
}

/*
 * Finalize absorption w/ padding && squeeze the first output bytes from both SHAKE states.
 */
static void shakex2_finalize_pc64le(uint8_t *out0, uint8_t *out1,
                                            size_t outlen, shakex2_ppc64le_ctx_t *ctx)
{
    uint64_t i;
    uint64_t block;
    uint64_t offset;
    uint8_t *st0;
    uint8_t *st1;
    uint64_t remaining;

    shakex2_complete_absorb_ppc64le(ctx);

    st0 = (uint8_t *)ctx->st.statex2[0];
    st1 = (uint8_t *)ctx->st.statex2[1];

    remaining = outlen;
    i = 0;

    while (remaining > 0) {
        block = get_min_bsize(remaining, ctx->sponge._avail);
        offset = ctx->sponge._block_rate - ctx->sponge._avail;

        memcpy(out0 + i, st0 + offset, block);
        memcpy(out1 + i, st1 + offset, block);

        i += block;
        remaining -= block;
        ctx->sponge._avail -= block;

        if (remaining > 0) {
            keccakf1600x2_ppc64le(ctx->st.statex2[0], ctx->st.statex2[1]);
            if (!(ctx->sponge._avail))
                ctx->sponge._avail = ctx->sponge._block_rate;
        }
    }
}

/*
 * Squeeze additional output bytes from an already-finalized SHAKE context.
 * The caller must have already completed absorption with padding
 */
static int shakex2_squeeze_cont_pc64le(shakex2_ppc64le_ctx_t *ctx, uint8_t *out0,
                                   uint8_t *out1, size_t len)
{
    uint64_t i;
    uint64_t block;
    uint64_t offset;
    uint8_t *st0;
    uint8_t *st1;
    uint64_t remaining;

    st0 = (uint8_t *)ctx->st.statex2[0];
    st1 = (uint8_t *)ctx->st.statex2[1];

    i = 0;
    remaining = len;

    while (remaining > 0) {
        block = get_min_bsize(remaining, ctx->sponge._avail);
        offset = ctx->sponge._block_rate - ctx->sponge._avail;

        memcpy(out0 + i, st0 + offset, block);
        memcpy(out1 + i, st1 + offset, block);

        i += block;
        remaining -= block;
        ctx->sponge._avail -= block;

        if (remaining > 0) {
            keccakf1600x2_ppc64le(ctx->st.statex2[0], ctx->st.statex2[1]);
            if (!(ctx->sponge._avail))
                ctx->sponge._avail = ctx->sponge._block_rate;
        }
    }

    return 1;
}

/* Wrappers for MLDSA/MLKEM side*/
int shake128x2_ppc64le(const void *seed0, size_t seed0_len,
                                                 const void *seed1, size_t seed1_len,
                                                 shakex2_ppc64le_ctx_t *ctx,
                                                 uint8_t *out0, size_t out0_len,
                                                 uint8_t *out1, size_t out1_len)
{
    if (out0_len != out1_len)
        return 0;

    shakex2_config_ppc64le(ctx, SHAKE128_DIGEST);

    shakex2_absorb_ppc64le(ctx, seed0, seed0_len, seed1, seed1_len);

    shakex2_finalize_pc64le(out0, out1, out0_len, ctx);

    return 1;
}

int shake128x2_squeeze_once_ppc64le(shakex2_ppc64le_ctx_t *ctx,
                                           uint8_t *out0, size_t out0_len,
                                           uint8_t *out1, size_t out1_len)
{
    if (out0_len != out1_len)
        return 0;

    return shakex2_squeeze_cont_pc64le(ctx, out0, out1, out0_len);
}

int shake256x2_ppc64le(const void *seed0, size_t seed0_len,
                                                 const void *seed1, size_t seed1_len,
                                                 shakex2_ppc64le_ctx_t *ctx,
                                                 uint8_t *out0, size_t out0_len,
                                                 uint8_t *out1, size_t out1_len)
{
    if (out0_len != out1_len)
        return 0;

    shakex2_config_ppc64le(ctx, SHAKE256_DIGEST);

    shakex2_absorb_ppc64le(ctx, seed0, seed0_len, seed1, seed1_len);

    shakex2_finalize_pc64le(out0, out1, out0_len, ctx);

    return 1;
}

int shake256x2_squeeze_once_ppc64le(shakex2_ppc64le_ctx_t *ctx,
                                           uint8_t *out0, size_t out0_len,
                                           uint8_t *out1, size_t out1_len)
{
    if (out0_len != out1_len)
        return 0;

    return shakex2_squeeze_cont_pc64le(ctx, out0, out1, out0_len);
}
