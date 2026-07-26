/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Details about Montgomery multiplication algorithms can be found at
 * http://security.ece.orst.edu/publications.html, e.g.
 * http://security.ece.orst.edu/koc/papers/j37acmon.pdf and
 * sections 3.8 and 4.2 in http://security.ece.orst.edu/koc/papers/r01rsasw.pdf
 */

#include "crypto/fn.h"
#include "crypto/fnerr.h"
#include "crypto/bn.h"
#include "internal/safe_math.h"
#include "fn_local.h"
#include <openssl/err.h>

OSSL_SAFE_MATH_ADDU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))
OSSL_SAFE_MATH_MULU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))
OSSL_SAFE_MATH_MULS(int, int, OSSL_SAFE_MATH_MINS(int), OSSL_SAFE_MATH_MAXS(int))

/*
 * Precompute the Montgomery context (N, n0, RR) for a modulus.
 *
 * This is one-time setup that is expected to run on a public modulus; it is
 * not constant-time in the modulus value.
 *
 * Constant-time profile:
 *   - No masked conditional swap/select is used, and none is attempted.
 *   - What leaks: essentially the whole modulus value.  The parity/size guard
 *     (mod->d[0] & 1) and the mod_len <= 1 early return branch on the value
 *     and bit length; the RR-generation loop's control flow -- the
 *     OSSL_FN_cmp(RR, mod) test and the left-shift amounts j derived from the
 *     bit lengths of mod and RR -- depends on the modulus value throughout,
 *     so the loop's iteration pattern reveals it.  The Hensel-lifting loop
 *     that computes n0 is itself constant-time (a fixed 6 iterations of
 *     multiplies) but consumes the low word(s) of mod.
 *   - The OSSL_FN primitives used here (OSSL_FN_num_bits, OSSL_FN_lshift,
 *     OSSL_FN_lshift1, OSSL_FN_cmp, OSSL_FN_sub) branch only on public widths,
 *     not on limb values; the leak above is the value-dependent control flow
 *     that drives them, not the primitives themselves.  OSSL_FN_num_bits and
 *     OSSL_FN_cmp compute in constant time but their returned values feed that
 *     control flow.
 */
OSSL_FN_MONT_CTX *OSSL_FN_MONT_CTX_new(const OSSL_FN *mod)
{
    size_t i, j;
    int err = 0;

    if (mod == NULL || mod->dsize <= 0
        || (mod->d[0] & OSSL_FN_ULONG_C(1)) == 0) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    size_t mod_size = safe_mul_size_t(mod->dsize, sizeof(OSSL_FN_ULONG), &err);
    mod_size = safe_add_size_t(mod_size, sizeof(OSSL_FN), &err);
    size_t ctx_size = safe_mul_size_t(2, mod_size, &err);
    ctx_size = safe_add_size_t(ctx_size, sizeof(OSSL_FN_MONT_CTX), &err);
    int ri = safe_mul_int(mod->dsize, OSSL_FN_BYTES * 8, &err);
    if (err) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_OVERFLOW);
        return NULL;
    }
    OSSL_FN_MONT_CTX *ctx;
    if (mod->is_securely_allocated)
        ctx = OPENSSL_secure_zalloc(ctx_size);
    else
        ctx = OPENSSL_zalloc(ctx_size);
    if (ctx == NULL)
        return NULL;
    ctx->is_securely_allocated = mod->is_securely_allocated;

    /*
     * OSSL_FN embeds a flexible array member of type OSSL_FN_ULONG, so its
     * alignment is at least alignof(OSSL_FN_ULONG) and sizeof(OSSL_FN) is
     * therefore a multiple of sizeof(OSSL_FN_ULONG).
     * Hence mod_size is an exact multiple of sizeof(OSSL_FN_ULONG),
     * so the RR offset below (mod_size / sizeof(OSSL_FN_ULONG)) divides evenly
     * and the N and RR sub-blocks never overlap.
     */
    OSSL_FN *N = (OSSL_FN *)ctx->memory;
    OSSL_FN *RR = (OSSL_FN *)(ctx->memory + mod_size / sizeof(OSSL_FN_ULONG));
    N->dsize = RR->dsize = mod->dsize;
    ctx->N = N;
    ctx->RR = RR;

    ctx->ri = ri;

    uint64_t tmod; /* The lower 64 bits of the modulus */
    if (ossl_unlikely(mod->dsize == 1))
        tmod = mod->d[0];
    else
#if OSSL_FN_BYTES == 4
        tmod = (uint64_t)mod->d[1] << 32 | (uint64_t)mod->d[0];
#elif OSSL_FN_BYTES == 8
        tmod = mod->d[0];
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif

    /* Solve the equation tmod * n0 = -1 (mod 2^64) using Hensel's lifting */
    uint64_t inv = 1;
    for (i = 0; i < 6; i++)
        inv *= 2 - tmod * inv;
#if OSSL_FN_BYTES == 4
    inv = 0 - inv;
    ctx->n0[0] = (OSSL_FN_ULONG)(inv & 0xFFFFFFFF);
    ctx->n0[1] = (OSSL_FN_ULONG)(inv >> 32);
#elif OSSL_FN_BYTES == 8
    ctx->n0[0] = 0 - inv;
    ctx->n0[1] = 0;
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif

    /*
     * There is no need to use safe_mul_size_t() here,
     * the absence of overflow was checked when calculating mod_size.
     */
    memcpy(N->d, mod->d, mod->dsize * sizeof(OSSL_FN_ULONG));

    size_t mod_len = OSSL_FN_num_bits(mod);
    if (ossl_unlikely(mod_len <= 1))
        return ctx;

    RR->d[0] = 1;
    size_t rr_bits = 2 * (size_t)ctx->ri;
    for (i = 0; i < rr_bits;) {
        j = mod_len - OSSL_FN_num_bits(RR);
        if (j > rr_bits - i)
            j = rr_bits - i;
        if (j > 0) {
            OSSL_FN_lshift(RR, RR, (int)j);
            i += j;
        }
        if (OSSL_FN_cmp(RR, mod) < 0) {
            if (i == rr_bits)
                break;
            OSSL_FN_lshift1(RR, RR);
            i++;
        }
        OSSL_FN_sub(RR, RR, mod);
    }

    return ctx;
}

/*
 * Free a Montgomery context.
 *
 * Constant-time profile:
 *   - There is no value-dependent control flow. The branch on
 *     is_securely_allocated is on the allocation strategy, not on anything
 *     derived from N.
 *   - What leaks: nothing about the modulus value.  The only value-dependent
 *     timing is that OPENSSL_secure_clear_free() zeroizes ctx_size bytes, so
 *     the free's duration scales with the buffer size -- a function of the
 *     public width N->dsize (read from the field, not computed from the limb
 *     values).  No limb value is inspected.
 */
void OSSL_FN_MONT_CTX_free(OSSL_FN_MONT_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->is_securely_allocated) {
        size_t mod_size = sizeof(OSSL_FN) + ctx->N->dsize * sizeof(OSSL_FN_ULONG);
        size_t ctx_size = sizeof(OSSL_FN_MONT_CTX) + 2 * mod_size;
        OPENSSL_secure_clear_free(ctx, ctx_size);
    } else {
        OPENSSL_free(ctx);
    }
}

/*
 * Duplicate a Montgomery context.
 *
 * Constant-time profile:
 *   - There is no value-dependent control flow.
 *   - What leaks: nothing about the modulus value. The only value-dependent
 *     timing is that memcpy copies ctx_size bytes, so the duration scales with
 *     the buffer size -- a function of the public width N->dsize. The bytes
 *     are copied regardless of the limb values, so the modulus value does not
 *     leak.
 */
OSSL_FN_MONT_CTX *OSSL_FN_MONT_CTX_dup(OSSL_FN_MONT_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    size_t mod_size = sizeof(OSSL_FN) + ctx->N->dsize * sizeof(OSSL_FN_ULONG);
    size_t ctx_size = sizeof(OSSL_FN_MONT_CTX) + 2 * mod_size;
    OSSL_FN_MONT_CTX *ret;
    if (ctx->is_securely_allocated)
        ret = OPENSSL_secure_malloc(ctx_size);
    else
        ret = OPENSSL_malloc(ctx_size);
    if (ret == NULL)
        return NULL;
    memcpy(ret, ctx, ctx_size);
    ret->N = (OSSL_FN *)ret->memory;
    ret->RR = (OSSL_FN *)(ret->memory + mod_size / sizeof(OSSL_FN_ULONG));
    return ret;
}

/*
 * Arena payload size needed by OSSL_FN_mul_mont_quick().
 *
 * Constant-time profile:
 *   - What leaks: nothing.  The function is straight-line and inspects no
 *     limb values; N->dsize is a public width and the returned size is the
 *     function's declared output, not a side channel.
 */
size_t OSSL_FN_mul_mont_quick_ctx_size(OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *b, OSSL_FN_MONT_CTX *mont)
{
    if (!ossl_assert(mont != NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return OSSL_FN_CTX_size(1, 1, (size_t)mont->N->dsize + 2);
}

/*
 * Montgomery multiplication r = (a*b)/(2^mont->ri) mod mont->N.
 * r, a, b, and mont->N must be of the same size,
 * a and b must be less than mont->N.
 *
 * Constant-time profile:
 *   - A masked conditional select is used: the final reduction
 *     is an unconditional bn_sub_words() followed by the masked select
 *     r->d[i] = (carry & T->d[i]) | (~carry & r->d[i]), so whether the
 *     subtraction was actually needed does not leak.  The CIOS loop rotates
 *     nothing by value; its carries propagate branchlessly.
 *   - What leaks: only public widths -- the limb count len drives the loop
 *     trip counts, the buffer size, and the len > 1 test that selects the
 *     bn_mul_mont() assembly path.  No branch or memory access depends on the
 *     values of a, b, N, n0, or the intermediate T.
 *   - The primitives used (bn_mul_add_words, bn_sub_words) scan all len limbs
 *     regardless of value, and the OPENSSL_BN_ASM_MONT path (bn_mul_mont) is
 *     likewise constant-time in the operand values.
 */
int OSSL_FN_mul_mont_quick(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    if (!ossl_assert(r != NULL) || !ossl_assert(a != NULL)
        || !ossl_assert(b != NULL) || !ossl_assert(mont != NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    OSSL_FN_ULONG m, carry = 0;
    int i, j, ret = 0;
    int len = mont->N->dsize;
    if (!ossl_assert(r->dsize == len) || !ossl_assert(a->dsize == len)
        || !ossl_assert(b->dsize == len)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

#if defined(OPENSSL_BN_ASM_MONT)
    if (len > 1)
        if (bn_mul_mont(r->d, a->d, b->d, mont->N->d, mont->n0, len) != 0)
            return 1;
#endif

    const void *token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    OSSL_FN *T = OSSL_FN_CTX_get_limbs(ctx, (size_t)len + 2);
    if (T == NULL)
        goto end;
    OSSL_FN_clear(T);

    /*
     * CIOS Montgomery multiplication.  T->d[len] and T->d[len + 1] are two
     * guard words; the carries into them are propagated without any
     * data-dependent branch (each "(T->d[len] < carry)" test evaluates to 0/1
     * and only ever feeds arithmetic), following the style of
     * bn_from_montgomery_word().
     */
    for (i = 0; i < len; i++) {
        carry = bn_mul_add_words(T->d, a->d, len, b->d[i]);
        T->d[len] += carry;
        T->d[len + 1] += (T->d[len] < carry);
        m = T->d[0] * mont->n0[0];
        carry = bn_mul_add_words(T->d, mont->N->d, len, m);
        T->d[len] += carry;
        T->d[len + 1] += (T->d[len] < carry);
        for (j = 0; j <= len; j++)
            T->d[j] = T->d[j + 1];
        T->d[len + 1] = 0;
    }

    /*
     * With a, b < N the reduction guarantees the accumulated value is < 2N.
     * Since N occupies len limbs (N < 2^(len * OSSL_FN_BITS2)), a value < 2N
     * needs at most one extra bit beyond len limbs, so the result is held in
     * T->d[0 .. len - 1] with a carry of 0 or 1 in T->d[len] (T->d[len + 1] is
     * already 0).  Reduce it into [0, N) with an unconditional subtraction and
     * a constant-time masked select, exactly as bn_from_montgomery_word() does,
     * so that whether or not the subtraction was needed does not leak.
     */
    carry = T->d[len];
    carry -= bn_sub_words(r->d, T->d, mont->N->d, len);
    /*
     * carry is now all-ones if the subtraction was not needed, or zero if it
     * was; it cannot be 1.  Use it directly as a select mask.
     */
    for (i = 0; i < len; i++)
        r->d[i] = (carry & T->d[i]) | (~carry & r->d[i]);

    ret = 1;
end:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

/*
 * Arena payload size needed by OSSL_FN_mul_mont().
 *
 * Constant-time profile:
 *   - This function is NOT fully constand-time.
 *   - What leaks: the a->dsize != len and OSSL_FN_cmp(a, N) >= 0 tests (and
 *     the same for b) branch on the operand values to choose how many scratch
 *     limbs to budget, so both the branch taken and the returned size reveal
 *     whether each operand was already reduced and correctly sized.  The
 *     comparison OSSL_FN_cmp is itself constant-time; no other value leak.
 *   - The primitives used (OSSL_FN_cmp, OSSL_FN_mod_ctx_size) branch only on
 *     public widths, except that OSSL_FN_cmp performs a value comparison.
 */
size_t OSSL_FN_mul_mont_ctx_size(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    OSSL_FN_MONT_CTX *mont)
{
    if (!ossl_assert(a != NULL) || !ossl_assert(b != NULL)
        || !ossl_assert(mont != NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    int len = mont->N->dsize;
    int num = 0;
    size_t ret = 0, tmp;
    int err = 0;

    if (a->dsize != len || OSSL_FN_cmp(a, mont->N) >= 0) {
        num++;
        tmp = OSSL_FN_mod_ctx_size(NULL, a, mont->N);
        if (tmp > ret)
            ret = tmp;
    }

    if (b->dsize != len || OSSL_FN_cmp(b, mont->N) >= 0) {
        num++;
        tmp = OSSL_FN_mod_ctx_size(NULL, b, mont->N);
        if (tmp > ret)
            ret = tmp;
    }

    if (r != NULL && r->dsize != len)
        num++;

    if (ossl_unlikely(num > 0 && (size_t)len > SIZE_MAX / num))
        return 0;

    tmp = OSSL_FN_mul_mont_quick_ctx_size(NULL, NULL, NULL, mont);
    if (tmp > ret)
        ret = tmp;

    ret = safe_add_size_t(ret, OSSL_FN_CTX_size(1, num, num * (size_t)len),
        &err);

    return err == 0 ? ret : 0;
}

/*
 * Montgomery multiplication that first canonicalises a and b into [0, N).
 *
 * This function is NOT constant-time when operands need canonicalising
 * (see below); the constant-time core is OSSL_FN_mul_mont_quick().
 *
 * Constant-time profile:
 *   - What leaks: whether each operand is already reduced -- the
 *     a->dsize != len || OSSL_FN_cmp(a, N) >= 0 test (and the same for b)
 *     selects whether the operand is first reduced with OSSL_FN_mod.  When
 *     that branch is taken, OSSL_FN_mod / OSSL_FN_div scans the denominator
 *     N's significant limbs and is NOT constant-time, leaking N and the
 *     operand.  For already-reduced, correctly-sized inputs the branch is not
 *     taken, the only value-dependent work is the constant-time OSSL_FN_cmp,
 *     and the rest reduces to the constant-time mul_mont_quick.
 *   - The primitives used branch only on public widths, except OSSL_FN_cmp
 *     (a value comparison) and OSSL_FN_mod / OSSL_FN_div (scans the
 *     denominator's significant limbs; see OSSL_FN_div).
 */
int OSSL_FN_mul_mont(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    if (!ossl_assert(r != NULL) || !ossl_assert(a != NULL)
        || !ossl_assert(b != NULL) || !ossl_assert(mont != NULL)
        || !ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    int len = mont->N->dsize;
    const OSSL_FN *aa = a;
    const OSSL_FN *bb = b;
    OSSL_FN *rr = r;
    OSSL_FN *tmp;
    int ret = 0;

    const void *token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    if (a->dsize != len || OSSL_FN_cmp(a, mont->N) >= 0) {
        tmp = OSSL_FN_CTX_get_limbs(ctx, len);
        if (tmp == NULL)
            goto end;
        if (OSSL_FN_mod(tmp, a, mont->N, ctx) == 0)
            goto end;
        aa = tmp;
    }

    if (b->dsize != len || OSSL_FN_cmp(b, mont->N) >= 0) {
        tmp = OSSL_FN_CTX_get_limbs(ctx, len);
        if (tmp == NULL)
            goto end;
        if (OSSL_FN_mod(tmp, b, mont->N, ctx) == 0)
            goto end;
        bb = tmp;
    }

    if (r->dsize != len) {
        rr = OSSL_FN_CTX_get_limbs(ctx, len);
        if (rr == NULL)
            goto end;
    }

    ret = OSSL_FN_mul_mont_quick(rr, aa, bb, mont, ctx);

    if (r != rr)
        ret &= (OSSL_FN_copy_truncate(r, rr) != NULL);

end:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

/*
 * Arena payload size needed by OSSL_FN_to_mont().
 *
 * Constant-time profile:
 *   - This function is NOT constant-time when an operand needs canonicalising.
 *   - What leaks: the a->dsize != len and OSSL_FN_cmp(a, N) >= 0 tests branch
 *     on the operand value to choose how many scratch limbs to budget, so
 *     both the branch taken and the returned size reveal whether a was already
 *     reduced and correctly sized.  OSSL_FN_cmp is itself constant-time; no
 *     other value leak.
 */
size_t OSSL_FN_to_mont_ctx_size(OSSL_FN *r, const OSSL_FN *a,
    OSSL_FN_MONT_CTX *mont)
{
    if (!ossl_assert(a != NULL) || !ossl_assert(mont != NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    int len = mont->N->dsize;
    int num = 0;
    size_t ret = 0, tmp;
    int err = 0;

    if (a->dsize != len || OSSL_FN_cmp(a, mont->N) >= 0) {
        num++;
        tmp = OSSL_FN_mod_ctx_size(NULL, a, mont->N);
        if (tmp > ret)
            ret = tmp;
    }

    if (r != NULL && r->dsize != len)
        num++;

    if (ossl_unlikely(num > 0 && (size_t)len > SIZE_MAX / num))
        return 0;

    tmp = OSSL_FN_mul_mont_quick_ctx_size(NULL, NULL, NULL, mont);
    if (tmp > ret)
        ret = tmp;

    ret = safe_add_size_t(ret, OSSL_FN_CTX_size(1, num, num * (size_t)len),
        &err);

    return err == 0 ? ret : 0;
}

/*
 * Convert a into Montgomery form: r = a * R mod N, via mul_mont(a, RR).
 *
 * This function is NOT constant-time when an operand needs canonicalising,
 * since it inherits the OSSL_FN_mul_mont profile below.
 *
 * Constant-time profile:
 *   - What leaks: this forwards to OSSL_FN_mul_mont(r, a, mont->RR), so it
 *     inherits that profile -- the canonicalisation test on a may invoke the
 *     non-constant-time OSSL_FN_mod (leaking a and N).  RR is precomputed and
 *     already reduced, so its own test never triggers a reduction.  The
 *     r->dsize == N->dsize assert is on public widths.
 *   - See OSSL_FN_mul_mont for the primitives' constant-time behaviour.
 */
int OSSL_FN_to_mont(OSSL_FN *r, const OSSL_FN *a,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    if (!ossl_assert(mont != NULL) || !ossl_assert(r != NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (!ossl_assert(r->dsize == mont->N->dsize)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    return OSSL_FN_mul_mont(r, a, mont->RR, mont, ctx);
}

/*
 * Arena payload size needed by OSSL_FN_from_mont().
 *
 * Constant-time profile:
 *   - This function is constant-time.
 *   - What leaks: nothing.  The function is straight-line and inspects no
 *     limb values; N->dsize is a public width and the returned size is the
 *     function's declared output, not a side channel.
 */
size_t OSSL_FN_from_mont_ctx_size(OSSL_FN *r, const OSSL_FN *a,
    OSSL_FN_MONT_CTX *mont)
{
    if (!ossl_assert(mont != NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /*
     * from_mont is mul_mont_quick specialised to b == 1, so it uses the same
     * len + 2 scratch buffer (len limbs plus the two CIOS guard words).
     */
    return OSSL_FN_CTX_size(1, 1, (size_t)mont->N->dsize + 2);
}

/*
 * Convert a out of Montgomery form: r = a * R^-1 mod N.  This is
 * OSSL_FN_mul_mont_quick() specialised to b == 1 (see the body).
 *
 * Constant-time profile:
 *   - A masked conditional select is used: the final reduction
 *     is an unconditional bn_sub_words() followed by the masked select
 *     r->d[i] = (carry & T->d[i]) | (~carry & r->d[i]), so whether the
 *     subtraction was needed does not leak.  The reduction loop rotates
 *     nothing by value; its carries propagate branchlessly.
 *   - What leaks: only public widths -- the limb count len drives the loop
 *     trip count and the buffer size.  No branch or memory access depends on
 *     the values of a, N, n0, or the intermediate T.
 *   - The primitives used (bn_mul_add_words, bn_sub_words) scan all len limbs
 *     regardless of value, and OSSL_FN_copy copies a fixed len limbs.
 */
int OSSL_FN_from_mont(OSSL_FN *r, const OSSL_FN *a,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    OSSL_FN_ULONG m, carry = 0;
    int i, j, ret = 0;

    if (!ossl_assert(r != NULL) || !ossl_assert(a != NULL)
        || !ossl_assert(mont != NULL) || !ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    int len = mont->N->dsize;
    if (!ossl_assert(r->dsize == len) || !ossl_assert(a->dsize == len)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    const void *token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    OSSL_FN *T = OSSL_FN_CTX_get_limbs(ctx, (size_t)len + 2);
    if (T == NULL)
        goto end;

    /*
     * from_mont(a) = a * R^-1 mod N is exactly OSSL_FN_mul_mont_quick(a, 1):
     * with b == 1 the only nonzero b digit is the lowest, so rather than a
     * per-iteration a * b[i] step we load a once (into T->d[0 .. len - 1]) and
     * then run len Montgomery reduction steps.  No full 2 * len product is ever
     * formed, so the same len + 2 scratch buffer as mul_mont_quick suffices.
     * T->d[len] and T->d[len + 1] are the two guard words; the carries into
     * them are propagated branchlessly (each "(T->d[len] < carry)" test is
     * 0/1).
     */
    if (OSSL_FN_copy(T, a) == NULL)
        goto end;

    for (i = 0; i < len; i++) {
        m = T->d[0] * mont->n0[0];
        carry = bn_mul_add_words(T->d, mont->N->d, len, m);
        T->d[len] += carry;
        T->d[len + 1] += (T->d[len] < carry);
        for (j = 0; j <= len; j++)
            T->d[j] = T->d[j + 1];
        T->d[len + 1] = 0;
    }

    /*
     * With a < R the reduction leaves a value < 2N in T->d[0 .. len - 1] plus a
     * carry of 0 or 1 in T->d[len] (N occupies len limbs, so a value < 2N needs
     * at most one extra bit).  Reduce it into [0, N) with an unconditional
     * subtraction and a constant-time masked select, so that whether or not the
     * subtraction was needed does not leak.
     */
    carry = T->d[len];
    carry -= bn_sub_words(r->d, T->d, mont->N->d, len);
    /*
     * carry is now all-ones if T - N underflowed (i.e. no reduction was
     * needed) or zero otherwise; it cannot be 1, since at most one subtraction
     * is ever required.  Use it directly as a select mask.
     */
    for (i = 0; i < len; i++)
        r->d[i] = (carry & T->d[i]) | (~carry & r->d[i]);

    ret = 1;
end:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}
