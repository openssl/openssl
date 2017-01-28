/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "e_os.h"
#include <internal/numbers.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "testutil.h"
#include "test_main_custom.h"

/*
 * In bn_lcl.h, bn_expand() is defined as a static ossl_inline function.
 * This is fine in itself, it will end up as an unused static function in
 * the worst case.  However, it references bn_expand2(), which is a private
 * function in libcrypto and therefore unavailable on some systems.  This
 * may result in a linker error because of unresolved symbols.
 *
 * To avoid this, we define a dummy variant of bn_expand2() here, and to
 * avoid possible clashes with libcrypto, we rename it first, using a macro.
 */
#define bn_expand2 dummy_bn_expand2
BIGNUM *bn_expand2(BIGNUM *b, int words);
BIGNUM *bn_expand2(BIGNUM *b, int words) { return NULL; }
#include "../crypto/bn/bn_lcl.h"

#define MAXPAIRS        20

/*
 * Things in boring, not in openssl.  TODO we should add them.
 */
#define HAVE_BN_PADDED 0
#define HAVE_BN_SQRT 0

typedef struct pair_st {
    char *key;
    char *value;
} PAIR;

typedef struct stanza_st {
    int start;
    int numpairs;
    PAIR pairs[MAXPAIRS];
} STANZA;

typedef struct filetest_st {
    const char *name;
    int (*func)(STANZA *s);
} FILETEST;

typedef struct mpitest_st {
    const char *base10;
    const char *mpi;
    size_t mpi_len;
} MPITEST;

static const int NUM0 = 100;           /* number of tests */
static const int NUM1 = 50;            /* additional tests for some functions */
static FILE *fp;
static BN_CTX *ctx;


/*
 * Look for |key| in the stanza and return it or NULL if not found.
 */
static const char *findattr(STANZA *s, const char *key)
{
    int i = s->numpairs;
    PAIR *pp = s->pairs;

    for ( ; --i >= 0; pp++)
        if (strcasecmp(pp->key, key) == 0)
            return pp->value;
    return NULL;
}

/*
 * Parse BIGNUM, return number of bytes parsed.
 */
static int parseBN(BIGNUM **out, const char *in)
{
    *out = NULL;
    return BN_hex2bn(out, in);
}

static int parsedecBN(BIGNUM **out, const char *in)
{
    *out = NULL;
    return BN_dec2bn(out, in);
}

static BIGNUM *getBN(STANZA *s, const char *attribute)
{
    const char *hex;
    BIGNUM *ret = NULL;

    if ((hex = findattr(s, attribute)) == NULL) {
        fprintf(stderr, "Can't find %s in test at line %d\n",
                attribute, s->start);
        return NULL;
    }

    if (parseBN(&ret, hex) != (int)strlen(hex)) {
        fprintf(stderr, "Could not decode '%s'.\n", hex);
        return NULL;
    }
    return ret;
}

static int getint(STANZA *s, int *out, const char *attribute)
{
    BIGNUM *ret = getBN(s, attribute);
    BN_ULONG word;
    int st = 0;

    if (ret == NULL)
        goto err;

    if ((word = BN_get_word(ret)) > INT_MAX)
        goto err;

    *out = (int)word;
    st = 1;
err:
    BN_free(ret);
    return st;
}

static int equalBN(const char *op, const BIGNUM *expected, const BIGNUM *actual)
{
    char *exstr = NULL;
    char *actstr = NULL;

    if (BN_cmp(expected, actual) == 0)
        return 1;

    exstr = BN_bn2hex(expected);
    actstr = BN_bn2hex(actual);
    if (exstr == NULL || actstr == NULL)
        goto err;

    fprintf(stderr, "Got %s =\n", op);
    fprintf(stderr, "\t%s\n", actstr);
    fprintf(stderr, "wanted:\n");
    fprintf(stderr, "\t%s\n", exstr);

err:
    OPENSSL_free(exstr);
    OPENSSL_free(actstr);
    return 0;
}


/*
 * Return a "random" flag for if a BN should be negated.
 */
static int rand_neg(void)
{
    static unsigned int neg = 0;
    static int sign[8] = { 0, 0, 0, 1, 1, 0, 1, 1 };

    return sign[(neg++) % 8];
}


static int test_sub()
{
    BIGNUM *a, *b, *c;
    int i;

    a = BN_new();
    b = BN_new();
    c = BN_new();

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            BN_bntest_rand(a, 512, 0, 0);
            BN_copy(b, a);
            if (BN_set_bit(a, i) == 0)
                return 0;
            BN_add_word(b, i);
        } else {
            BN_bntest_rand(b, 400 + i - NUM1, 0, 0);
            a->neg = rand_neg();
            b->neg = rand_neg();
        }
        BN_sub(c, a, b);
        BN_add(c, c, b);
        BN_sub(c, c, a);
        if (!BN_is_zero(c)) {
            printf("Subtract test failed!\n");
            return 0;
        }
    }
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return 1;
}


static int test_div_recip()
{
    BIGNUM *a, *b, *c, *d, *e;
    BN_RECP_CTX *recp;
    int i;

    recp = BN_RECP_CTX_new();
    a = BN_new();
    b = BN_new();
    c = BN_new();
    d = BN_new();
    e = BN_new();

    for (i = 0; i < NUM0 + NUM1; i++) {
        if (i < NUM1) {
            BN_bntest_rand(a, 400, 0, 0);
            BN_copy(b, a);
            BN_lshift(a, a, i);
            BN_add_word(a, i);
        } else
            BN_bntest_rand(b, 50 + 3 * (i - NUM1), 0, 0);
        a->neg = rand_neg();
        b->neg = rand_neg();
        BN_RECP_CTX_set(recp, b, ctx);
        BN_div_recp(d, c, a, recp, ctx);
        BN_mul(e, d, b, ctx);
        BN_add(d, e, c);
        BN_sub(d, d, a);
        if (!BN_is_zero(d)) {
            printf("Reciprocal division test failed!\n");
            printf("a=");
            BN_print_fp(stdout, a);
            printf("\nb=");
            BN_print_fp(stdout, b);
            printf("\n");
            return 0;
        }
    }
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_RECP_CTX_free(recp);
    return 1;
}


static int test_mod()
{
    BIGNUM *a, *b, *c, *d, *e;
    int i;

    a = BN_new();
    b = BN_new();
    c = BN_new();
    d = BN_new();
    e = BN_new();

    BN_bntest_rand(a, 1024, 0, 0);
    for (i = 0; i < NUM0; i++) {
        BN_bntest_rand(b, 450 + i * 10, 0, 0);
        a->neg = rand_neg();
        b->neg = rand_neg();
        BN_mod(c, a, b, ctx);
        BN_div(d, e, a, b, ctx);
        BN_sub(e, e, c);
        if (!BN_is_zero(e)) {
            printf("Modulo test failed!\n");
            return 0;
        }
    }
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return 1;
}

static const char *bn1strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000FFFFFFFF00",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000FFFFFFFFFFFFFF",
    NULL
};

static const char *bn2strings[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000FFFFFFFF0000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000FFFFFFFFFFFFFF00000000",
    NULL
};

static char *glue(const char *list[])
{
    size_t len = 0;
    char *p, *save;
    int i;

    for (i = 0; list[i] != NULL; i++)
        len += strlen(list[i]);
    p = save = OPENSSL_malloc(len + 1);
    if (p != NULL) {
        for (i = 0; list[i] != NULL; i++)
            p += strlen(strcpy(p, list[i]));
    }
    return save;
}

/*
 * Test constant-time modular exponentiation with 1024-bit inputs, which on
 * x86_64 cause a different code branch to be taken.
 */
static int test_modexp_mont5()
{
    BIGNUM *a, *p, *m, *d, *e, *b, *n, *c;
    BN_MONT_CTX *mont;
    char *bigstring;

    a = BN_new();
    p = BN_new();
    m = BN_new();
    d = BN_new();
    e = BN_new();
    b = BN_new();
    n = BN_new();
    c = BN_new();
    mont = BN_MONT_CTX_new();

    BN_bntest_rand(m, 1024, 0, 1); /* must be odd for montgomery */
    /* Zero exponent */
    BN_bntest_rand(a, 1024, 0, 0);
    BN_zero(p);
    if (!BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL))
        return 0;
    if (!BN_is_one(d)) {
        printf("Modular exponentiation test failed!\n");
        return 0;
    }

    /* Regression test for carry bug in mulx4x_mont */
    BN_hex2bn(&a,
        "7878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878");
    BN_hex2bn(&b,
        "095D72C08C097BA488C5E439C655A192EAFB6380073D8C2664668EDDB4060744"
        "E16E57FB4EDB9AE10A0CEFCDC28A894F689A128379DB279D48A2E20849D68593"
        "9B7803BCF46CEBF5C533FB0DD35B080593DE5472E3FE5DB951B8BFF9B4CB8F03"
        "9CC638A5EE8CDD703719F8000E6A9F63BEED5F2FCD52FF293EA05A251BB4AB81");
    BN_hex2bn(&n,
        "D78AF684E71DB0C39CFF4E64FB9DB567132CB9C50CC98009FEB820B26F2DED9B"
        "91B9B5E2B83AE0AE4EB4E0523CA726BFBE969B89FD754F674CE99118C3F2D1C5"
        "D81FDC7C54E02B60262B241D53C040E99E45826ECA37A804668E690E1AFC1CA4"
        "2C9A15D84D4954425F0B7642FC0BD9D7B24E2618D2DCC9B729D944BADACFDDAF");
    BN_MONT_CTX_set(mont, n, ctx);
    BN_mod_mul_montgomery(c, a, b, mont, ctx);
    BN_mod_mul_montgomery(d, b, a, mont, ctx);
    if (BN_cmp(c, d)) {
        fprintf(stderr, "Montgomery multiplication test failed:"
                        " a*b != b*a.\n");
        return 0;
    }

    /* Regression test for carry bug in sqr[x]8x_mont */
    bigstring = glue(bn1strings);
    BN_hex2bn(&n, bigstring);
    OPENSSL_free(bigstring);
    bigstring = glue(bn2strings);
    BN_hex2bn(&a, bigstring);
    OPENSSL_free(bigstring);
    BN_free(b);
    b = BN_dup(a);
    BN_MONT_CTX_set(mont, n, ctx);
    BN_mod_mul_montgomery(c, a, a, mont, ctx);
    BN_mod_mul_montgomery(d, a, b, mont, ctx);
    if (BN_cmp(c, d)) {
        fprintf(stderr, "Montgomery multiplication test failed:"
                        " a**2 != a*a.\n");
        return 0;
    }

    /* Zero input */
    BN_bntest_rand(p, 1024, 0, 0);
    BN_zero(a);
    if (!BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL))
        return 0;
    if (!BN_is_zero(d)) {
        fprintf(stderr, "Modular exponentiation test failed!\n");
        return 0;
    }
    /*
     * Craft an input whose Montgomery representation is 1, i.e., shorter
     * than the modulus m, in order to test the const time precomputation
     * scattering/gathering.
     */
    BN_one(a);
    BN_MONT_CTX_set(mont, m, ctx);
    if (!BN_from_montgomery(e, a, mont, ctx))
        return 0;
    if (!BN_mod_exp_mont_consttime(d, e, p, m, ctx, NULL))
        return 0;
    if (!BN_mod_exp_simple(a, e, p, m, ctx))
        return 0;
    if (BN_cmp(a, d) != 0) {
        printf("Modular exponentiation test failed!\n");
        return 0;
    }
    /* Finally, some regular test vectors. */
    BN_bntest_rand(e, 1024, 0, 0);
    if (!BN_mod_exp_mont_consttime(d, e, p, m, ctx, NULL))
        return 0;
    if (!BN_mod_exp_simple(a, e, p, m, ctx))
        return 0;
    if (BN_cmp(a, d) != 0) {
        printf("Modular exponentiation test failed!\n");
        return 0;
    }
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_free(d);
    BN_free(e);
    BN_free(b);
    BN_free(n);
    BN_free(c);
    return 1;
}

#ifndef OPENSSL_NO_EC2M
static int test_gf2m_add()
{
    BIGNUM *a, *b, *c;
    int i, st = 0;

    a = BN_new();
    b = BN_new();
    c = BN_new();

    for (i = 0; i < NUM0; i++) {
        BN_rand(a, 512, 0, 0);
        BN_copy(b, BN_value_one());
        a->neg = rand_neg();
        b->neg = rand_neg();
        BN_GF2m_add(c, a, b);
        /* Test that two added values have the correct parity. */
        if ((BN_is_odd(a) && BN_is_odd(c))
            || (!BN_is_odd(a) && !BN_is_odd(c))) {
            printf("GF(2^m) addition test (a) failed!\n");
            goto err;
        }
        BN_GF2m_add(c, c, c);
        /* Test that c + c = 0. */
        if (!BN_is_zero(c)) {
            printf("GF(2^m) addition test (b) failed!\n");
            goto err;
        }
    }
    st = 1;
 err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    return st;
}

static int test_gf2m_mod()
{
    static int p0[] = { 163, 7, 6, 3, 0, -1 };
    static int p1[] = { 193, 15, 0, -1 };
    BIGNUM *a, *b[2], *c, *d, *e;
    int i, j, st = 0;

    a = BN_new();
    b[0] = BN_new();
    b[1] = BN_new();
    c = BN_new();
    d = BN_new();
    e = BN_new();

    BN_GF2m_arr2poly(p0, b[0]);
    BN_GF2m_arr2poly(p1, b[1]);

    for (i = 0; i < NUM0; i++) {
        BN_bntest_rand(a, 1024, 0, 0);
        for (j = 0; j < 2; j++) {
            BN_GF2m_mod(c, a, b[j]);
            BN_GF2m_add(d, a, c);
            BN_GF2m_mod(e, d, b[j]);
            /* Test that a + (a mod p) mod p == 0. */
            if (!BN_is_zero(e)) {
                printf("GF(2^m) modulo test failed!\n");
                goto err;
            }
        }
    }
    st = 1;
 err:
    BN_free(a);
    BN_free(b[0]);
    BN_free(b[1]);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
}

static int test_gf2m_mul()
{
    BIGNUM *a, *b[2], *c, *d, *e, *f, *g, *h;
    int i, j, st = 0;
    int p0[] = { 163, 7, 6, 3, 0, -1 };
    int p1[] = { 193, 15, 0, -1 };

    a = BN_new();
    b[0] = BN_new();
    b[1] = BN_new();
    c = BN_new();
    d = BN_new();
    e = BN_new();
    f = BN_new();
    g = BN_new();
    h = BN_new();

    BN_GF2m_arr2poly(p0, b[0]);
    BN_GF2m_arr2poly(p1, b[1]);

    for (i = 0; i < NUM0; i++) {
        BN_bntest_rand(a, 1024, 0, 0);
        BN_bntest_rand(c, 1024, 0, 0);
        BN_bntest_rand(d, 1024, 0, 0);
        for (j = 0; j < 2; j++) {
            BN_GF2m_mod_mul(e, a, c, b[j], ctx);
            BN_GF2m_add(f, a, d);
            BN_GF2m_mod_mul(g, f, c, b[j], ctx);
            BN_GF2m_mod_mul(h, d, c, b[j], ctx);
            BN_GF2m_add(f, e, g);
            BN_GF2m_add(f, f, h);
            /* Test that (a+d)*c = a*c + d*c. */
            if (!BN_is_zero(f)) {
                printf("GF(2^m) modular multiplication test failed!\n");
                goto err;
            }
        }
    }
    st = 1;
 err:
    BN_free(a);
    BN_free(b[0]);
    BN_free(b[1]);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_free(f);
    BN_free(g);
    BN_free(h);
    return st;
}

static int test_gf2m_sqr()
{
    BIGNUM *a, *b[2], *c, *d;
    int i, j, st = 0;
    int p0[] = { 163, 7, 6, 3, 0, -1 };
    int p1[] = { 193, 15, 0, -1 };

    a = BN_new();
    b[0] = BN_new();
    b[1] = BN_new();
    c = BN_new();
    d = BN_new();

    BN_GF2m_arr2poly(p0, b[0]);
    BN_GF2m_arr2poly(p1, b[1]);

    for (i = 0; i < NUM0; i++) {
        BN_bntest_rand(a, 1024, 0, 0);
        for (j = 0; j < 2; j++) {
            BN_GF2m_mod_sqr(c, a, b[j], ctx);
            BN_copy(d, a);
            BN_GF2m_mod_mul(d, a, d, b[j], ctx);
            BN_GF2m_add(d, c, d);
            /* Test that a*a = a^2. */
            if (!BN_is_zero(d)) {
                printf("GF(2^m) modular squaring test failed!\n");
                goto err;
            }
        }
    }
    st = 1;
 err:
    BN_free(a);
    BN_free(b[0]);
    BN_free(b[1]);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_gf2m_modinv()
{
    BIGNUM *a, *b[2], *c, *d;
    int i, j, st = 0;
    int p0[] = { 163, 7, 6, 3, 0, -1 };
    int p1[] = { 193, 15, 0, -1 };

    a = BN_new();
    b[0] = BN_new();
    b[1] = BN_new();
    c = BN_new();
    d = BN_new();

    BN_GF2m_arr2poly(p0, b[0]);
    BN_GF2m_arr2poly(p1, b[1]);

    for (i = 0; i < NUM0; i++) {
        BN_bntest_rand(a, 512, 0, 0);
        for (j = 0; j < 2; j++) {
            BN_GF2m_mod_inv(c, a, b[j], ctx);
            BN_GF2m_mod_mul(d, a, c, b[j], ctx);
            /* Test that ((1/a)*a) = 1. */
            if (!BN_is_one(d)) {
                printf("GF(2^m) modular inversion test failed!\n");
                goto err;
            }
        }
    }
    st = 1;
 err:
    BN_free(a);
    BN_free(b[0]);
    BN_free(b[1]);
    BN_free(c);
    BN_free(d);
    return st;
}

static int test_gf2m_moddiv()
{
    BIGNUM *a, *b[2], *c, *d, *e, *f;
    int i, j, st = 0;
    int p0[] = { 163, 7, 6, 3, 0, -1 };
    int p1[] = { 193, 15, 0, -1 };

    a = BN_new();
    b[0] = BN_new();
    b[1] = BN_new();
    c = BN_new();
    d = BN_new();
    e = BN_new();
    f = BN_new();

    BN_GF2m_arr2poly(p0, b[0]);
    BN_GF2m_arr2poly(p1, b[1]);

    for (i = 0; i < NUM0; i++) {
        BN_bntest_rand(a, 512, 0, 0);
        BN_bntest_rand(c, 512, 0, 0);
        for (j = 0; j < 2; j++) {
            BN_GF2m_mod_div(d, a, c, b[j], ctx);
            BN_GF2m_mod_mul(e, d, c, b[j], ctx);
            BN_GF2m_mod_div(f, a, e, b[j], ctx);
            /* Test that ((a/c)*c)/a = 1. */
            if (!BN_is_one(f)) {
                printf("GF(2^m) modular division test failed!\n");
                goto err;
            }
        }
    }
    st = 1;
 err:
    BN_free(a);
    BN_free(b[0]);
    BN_free(b[1]);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_free(f);
    return st;
}

static int test_gf2m_modexp()
{
    BIGNUM *a, *b[2], *c, *d, *e, *f;
    int i, j, st = 0;
    int p0[] = { 163, 7, 6, 3, 0, -1 };
    int p1[] = { 193, 15, 0, -1 };

    a = BN_new();
    b[0] = BN_new();
    b[1] = BN_new();
    c = BN_new();
    d = BN_new();
    e = BN_new();
    f = BN_new();

    BN_GF2m_arr2poly(p0, b[0]);
    BN_GF2m_arr2poly(p1, b[1]);

    for (i = 0; i < NUM0; i++) {
        BN_bntest_rand(a, 512, 0, 0);
        BN_bntest_rand(c, 512, 0, 0);
        BN_bntest_rand(d, 512, 0, 0);
        for (j = 0; j < 2; j++) {
            BN_GF2m_mod_exp(e, a, c, b[j], ctx);
            BN_GF2m_mod_exp(f, a, d, b[j], ctx);
            BN_GF2m_mod_mul(e, e, f, b[j], ctx);
            BN_add(f, c, d);
            BN_GF2m_mod_exp(f, a, f, b[j], ctx);
            BN_GF2m_add(f, e, f);
            /* Test that a^(c+d)=a^c*a^d. */
            if (!BN_is_zero(f)) {
                printf("GF(2^m) modular exponentiation test failed!\n");
                goto err;
            }
        }
    }
    st = 1;
 err:
    BN_free(a);
    BN_free(b[0]);
    BN_free(b[1]);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_free(f);
    return st;
}

static int test_gf2m_modsqrt()
{
    BIGNUM *a, *b[2], *c, *d, *e, *f;
    int i, j, st = 0;
    int p0[] = { 163, 7, 6, 3, 0, -1 };
    int p1[] = { 193, 15, 0, -1 };

    a = BN_new();
    b[0] = BN_new();
    b[1] = BN_new();
    c = BN_new();
    d = BN_new();
    e = BN_new();
    f = BN_new();

    BN_GF2m_arr2poly(p0, b[0]);
    BN_GF2m_arr2poly(p1, b[1]);

    for (i = 0; i < NUM0; i++) {
        BN_bntest_rand(a, 512, 0, 0);
        for (j = 0; j < 2; j++) {
            BN_GF2m_mod(c, a, b[j]);
            BN_GF2m_mod_sqrt(d, a, b[j], ctx);
            BN_GF2m_mod_sqr(e, d, b[j], ctx);
            BN_GF2m_add(f, c, e);
            /* Test that d^2 = a, where d = sqrt(a). */
            if (!BN_is_zero(f)) {
                printf("GF(2^m) modular square root test failed!\n");
                goto err;
            }
        }
    }
    st = 1;
 err:
    BN_free(a);
    BN_free(b[0]);
    BN_free(b[1]);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_free(f);
    return st;
}

static int test_gf2m_modsolvequad()
{
    BIGNUM *a, *b[2], *c, *d, *e;
    int i, j, s = 0, t, st = 0;
    int p0[] = { 163, 7, 6, 3, 0, -1 };
    int p1[] = { 193, 15, 0, -1 };

    a = BN_new();
    b[0] = BN_new();
    b[1] = BN_new();
    c = BN_new();
    d = BN_new();
    e = BN_new();

    BN_GF2m_arr2poly(p0, b[0]);
    BN_GF2m_arr2poly(p1, b[1]);

    for (i = 0; i < NUM0; i++) {
        BN_bntest_rand(a, 512, 0, 0);
        for (j = 0; j < 2; j++) {
            t = BN_GF2m_mod_solve_quad(c, a, b[j], ctx);
            if (t) {
                s++;
                BN_GF2m_mod_sqr(d, c, b[j], ctx);
                BN_GF2m_add(d, c, d);
                BN_GF2m_mod(e, a, b[j]);
                BN_GF2m_add(e, e, d);
                /*
                 * Test that solution of quadratic c satisfies c^2 + c = a.
                 */
                if (!BN_is_zero(e)) {
                    printf("GF(2^m) modular solve quadratic test failed!\n");
                    goto err;
                }

            }
        }
    }
    if (s == 0) {
        printf("All %i tests of GF(2^m) modular solve quadratic resulted in no roots;\n",
                NUM0);
        printf("this is very unlikely and probably indicates an error.\n");
        goto err;
    }
    st = 1;
 err:
    BN_free(a);
    BN_free(b[0]);
    BN_free(b[1]);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    return st;
}
#endif

static int test_kronecker()
{
    BIGNUM *a, *b, *r, *t;
    int i;
    int legendre, kronecker;
    int st = 0;

    a = BN_new();
    b = BN_new();
    r = BN_new();
    t = BN_new();
    if (a == NULL || b == NULL || r == NULL || t == NULL)
        goto err;

    /*
     * We test BN_kronecker(a, b, ctx) just for b odd (Jacobi symbol). In
     * this case we know that if b is prime, then BN_kronecker(a, b, ctx) is
     * congruent to $a^{(b-1)/2}$, modulo $b$ (Legendre symbol). So we
     * generate a random prime b and compare these values for a number of
     * random a's.  (That is, we run the Solovay-Strassen primality test to
     * confirm that b is prime, except that we don't want to test whether b
     * is prime but whether BN_kronecker works.)
     */

    if (!BN_generate_prime_ex(b, 512, 0, NULL, NULL, NULL))
        goto err;
    b->neg = rand_neg();

    for (i = 0; i < NUM0; i++) {
        if (!BN_bntest_rand(a, 512, 0, 0))
            goto err;
        a->neg = rand_neg();

        /* t := (|b|-1)/2  (note that b is odd) */
        if (!BN_copy(t, b))
            goto err;
        t->neg = 0;
        if (!BN_sub_word(t, 1))
            goto err;
        if (!BN_rshift1(t, t))
            goto err;
        /* r := a^t mod b */
        b->neg = 0;

        if (!BN_mod_exp_recp(r, a, t, b, ctx))
            goto err;
        b->neg = 1;

        if (BN_is_word(r, 1))
            legendre = 1;
        else if (BN_is_zero(r))
            legendre = 0;
        else {
            if (!BN_add_word(r, 1))
                goto err;
            if (0 != BN_ucmp(r, b)) {
                printf("Legendre symbol computation failed\n");
                goto err;
            }
            legendre = -1;
        }

        kronecker = BN_kronecker(a, b, ctx);
        if (kronecker < -1)
            goto err;
        /* we actually need BN_kronecker(a, |b|) */
        if (a->neg && b->neg)
            kronecker = -kronecker;

        if (legendre != kronecker) {
            printf("legendre != kronecker; a = ");
            BN_print_fp(stdout, a);
            printf(", b = ");
            BN_print_fp(stdout, b);
            printf("\n");
            goto err;
        }
    }

    st = 1;
 err:
    BN_free(a);
    BN_free(b);
    BN_free(r);
    BN_free(t);
    return st;
}

static int file_sum(STANZA *s)
{
    BIGNUM *a = getBN(s, "A");
    BIGNUM *b = getBN(s, "B");
    BIGNUM *sum = getBN(s, "Sum");
    BIGNUM *ret = BN_new();
    BN_ULONG b_word;
    int st = 0;

    if (a == NULL || b == NULL || sum == NULL || ret == NULL)
        goto err;

    if (!BN_add(ret, a, b)
            || !equalBN("A + B", sum, ret)
            || !BN_sub(ret, sum, a)
            || !equalBN("Sum - A", b, ret)
            || !BN_sub(ret, sum, b)
            || !equalBN("Sum - B", a, ret))
        goto err;

    /*
     * Test that the functions work when |r| and |a| point to the same BIGNUM,
     * or when |r| and |b| point to the same BIGNUM.
     * TODO: Test where all of |r|, |a|, and |b| point to the same BIGNUM.
     */
    if (!BN_copy(ret, a)
            || !BN_add(ret, ret, b)
            || !equalBN("A + B (r is a)", sum, ret)
            || !BN_copy(ret, b)
            || !BN_add(ret, a, ret)
            || !equalBN("A + B (r is b)", sum, ret)
            || !BN_copy(ret, sum)
            || !BN_sub(ret, ret, a)
            || !equalBN("Sum - A (r is a)", b, ret)
            || !BN_copy(ret, a)
            || !BN_sub(ret, sum, ret)
            || !equalBN("Sum - A (r is b)", b, ret)
            || !BN_copy(ret, sum)
            || !BN_sub(ret, ret, b)
            || !equalBN("Sum - B (r is a)", a, ret)
            || !BN_copy(ret, b)
            || !BN_sub(ret, sum, ret)
            || !equalBN("Sum - B (r is b)", a, ret))
        goto err;

    /*
     * Test BN_uadd() and BN_usub() with the prerequisites they are
     * documented as having. Note that these functions are frequently used
     * when the prerequisites don't hold. In those cases, they are supposed
     * to work as if the prerequisite hold, but we don't test that yet.
     * TODO: test that.
     */
    if (!BN_is_negative(a) && !BN_is_negative(b) && BN_cmp(a, b) >= 0) {
        if (!BN_uadd(ret, a, b)
                || !equalBN("A +u B", sum, ret)
                || !BN_usub(ret, sum, a)
                || !equalBN("Sum -u A", b, ret)
                || !BN_usub(ret, sum, b)
                || !equalBN("Sum -u B", a, ret))
            goto err;
        /*
         * Test that the functions work when |r| and |a| point to the same
         * BIGNUM, or when |r| and |b| point to the same BIGNUM.
         * TODO: Test where all of |r|, |a|, and |b| point to the same BIGNUM.
         */
        if (!BN_copy(ret, a)
                || !BN_uadd(ret, ret, b)
                || !equalBN("A +u B (r is a)", sum, ret)
                || !BN_copy(ret, b)
                || !BN_uadd(ret, a, ret)
                || !equalBN("A +u B (r is b)", sum, ret)
                || !BN_copy(ret, sum)
                || !BN_usub(ret, ret, a)
                || !equalBN("Sum -u A (r is a)", b, ret)
                || !BN_copy(ret, a)
                || !BN_usub(ret, sum, ret)
                || !equalBN("Sum -u A (r is b)", b, ret)
                || !BN_copy(ret, sum)
                || !BN_usub(ret, ret, b)
                || !equalBN("Sum -u B (r is a)", a, ret)
                || !BN_copy(ret, b)
                || !BN_usub(ret, sum, ret)
                || !equalBN("Sum -u B (r is b)", a, ret))
            goto err;
    }

    /*
     * Test with BN_add_word() and BN_sub_word() if |b| is small enough.
     */
    b_word = BN_get_word(b);
    if (!BN_is_negative(b) && b_word != (BN_ULONG)-1) {
        if (!BN_copy(ret, a)
                || !BN_add_word(ret, b_word)
                || !equalBN("A + B (word)", sum, ret)
                || !BN_copy(ret, sum)
                || !BN_sub_word(ret, b_word)
                || !equalBN("Sum - B (word)", a, ret))
            goto err;
    }
    st = 1;

err:
    BN_free(a);
    BN_free(b);
    BN_free(sum);
    BN_free(ret);
    return st;
}

static int file_lshift1(STANZA *s)
{
    BIGNUM *a = getBN(s, "A");
    BIGNUM *lshift1 = getBN(s, "LShift1");
    BIGNUM *zero = BN_new();
    BIGNUM *ret = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *remainder = BN_new();
    int st = 0;

    if (a == NULL || lshift1 == NULL || zero == NULL
            || ret == NULL || two == NULL || remainder == NULL)
        goto err;

    BN_zero(zero);

    if (!BN_set_word(two, 2)
            || !BN_add(ret, a, a)
            || !equalBN("A + A", lshift1, ret)
            || !BN_mul(ret, a, two, ctx)
            || !equalBN("A * 2", lshift1, ret)
            || !BN_div(ret, remainder, lshift1, two, ctx)
            || !equalBN("LShift1 / 2", a, ret)
            || !equalBN("LShift1 % 2", zero, remainder)
            || !BN_lshift1(ret, a)
            || !equalBN("A << 1", lshift1, ret)
            || !BN_rshift1(ret, lshift1)
            || !equalBN("LShift >> 1", a, ret)
            || !BN_rshift1(ret, lshift1)
            || !equalBN("LShift >> 1", a, ret))
        goto err;

    /* Set the LSB to 1 and test rshift1 again. */
    if (!BN_set_bit(lshift1, 0)
            || !BN_div(ret, NULL /* rem */ , lshift1, two, ctx)
            || !equalBN("(LShift1 | 1) / 2", a, ret)
            || !BN_rshift1(ret, lshift1)
            || !equalBN("(LShift | 1) >> 1", a, ret))
        goto err;

    st = 1;
err:
    BN_free(a);
    BN_free(lshift1);
    BN_free(zero);
    BN_free(ret);
    BN_free(two);
    BN_free(remainder);

    return st;
}

static int file_lshift(STANZA *s)
{
    BIGNUM *a = getBN(s, "A");
    BIGNUM *lshift = getBN(s, "LShift");
    BIGNUM *ret = BN_new();
    int n = 0;
    int st = 0;

    if (a == NULL || lshift == NULL || ret == NULL || !getint(s, &n, "N"))
        goto err;

    if (!BN_lshift(ret, a, n)
            || !equalBN("A << N", lshift, ret)
            || !BN_rshift(ret, lshift, n)
            || !equalBN("A >> N", a, ret))
        goto err;

    st = 1;
err:
    BN_free(a);
    BN_free(lshift);
    BN_free(ret);
    return st;
}

static int file_rshift(STANZA *s)
{
    BIGNUM *a = getBN(s, "A");
    BIGNUM *rshift = getBN(s, "RShift");
    BIGNUM *ret = BN_new();
    int n = 0;
    int st = 0;

    if (a == NULL || rshift == NULL || ret == NULL || !getint(s, &n, "N"))
        goto err;

    if (!BN_rshift(ret, a, n)
            || !equalBN("A >> N", rshift, ret))
        goto err;

    st = 1;
err:
    BN_free(a);
    BN_free(rshift);
    BN_free(ret);
    return st;
}

static int file_square(STANZA *s)
{
    BIGNUM *a = getBN(s, "A");
    BIGNUM *square = getBN(s, "Square");
    BIGNUM *zero = BN_new();
    BIGNUM *ret = BN_new();
    BIGNUM *remainder = BN_new();
    BIGNUM *tmp = NULL;
    int st = 0;

    if (a == NULL || square == NULL || zero == NULL || ret == NULL
            || remainder == NULL)
        goto err;

    BN_zero(zero);

    if (!BN_sqr(ret, a, ctx)
            || !equalBN("A^2", square, ret)
            || !BN_mul(ret, a, a, ctx)
            || !equalBN("A * A", square, ret)
            || !BN_div(ret, remainder, square, a, ctx)
            || !equalBN("Square / A", a, ret)
            || !equalBN("Square % A", zero, remainder))
        goto err;

#if HAVE_BN_SQRT
    BN_set_negative(a, 0);
    if (!BN_sqrt(ret, square, ctx)
            || !equalBN("sqrt(Square)", a, ret))
        goto err;

    /* BN_sqrt should fail on non-squares and negative numbers. */
    if (!BN_is_zero(square)) {
        tmp = BN_new();
        if (tmp == NULL || !BN_copy(tmp, square))
            goto err;
        BN_set_negative(tmp, 1);

        if (BN_sqrt(ret, tmp, ctx)) {
            fprintf(stderr, "BN_sqrt succeeded on a negative number");
            goto err;
        }
        ERR_clear_error();

        BN_set_negative(tmp, 0);
        if (BN_add(tmp, tmp, BN_value_one()))
            goto err;
        if (BN_sqrt(ret, tmp, ctx)) {
            fprintf(stderr, "BN_sqrt succeeded on a non-square");
            goto err;
        }
        ERR_clear_error();
    }
#endif

    st = 1;
err:
    BN_free(a);
    BN_free(square);
    BN_free(zero);
    BN_free(ret);
    BN_free(remainder);
    BN_free(tmp);
    return st;
}

static int file_product(STANZA *s)
{
    BIGNUM *a = getBN(s, "A");
    BIGNUM *b = getBN(s, "B");
    BIGNUM *product = getBN(s, "Product");
    BIGNUM *ret = BN_new();
    BIGNUM *remainder = BN_new();
    BIGNUM *zero = BN_new();
    int st = 0;

    if (a == NULL || b == NULL || product == NULL || ret == NULL
            || remainder == NULL || zero == NULL)
        goto err;

    BN_zero(zero);

    if (!BN_mul(ret, a, b, ctx)
            || !equalBN("A * B", product, ret)
            || !BN_div(ret, remainder, product, a, ctx)
            || !equalBN("Product / A", b, ret)
            || !equalBN("Product % A", zero, remainder)
            || !BN_div(ret, remainder, product, b, ctx)
            || !equalBN("Product / B", a, ret)
            || !equalBN("Product % B", zero, remainder))
        goto err;

    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(product);
    BN_free(ret);
    BN_free(remainder);
    BN_free(zero);
    return st;
}

static int file_quotient(STANZA *s)
{
    BIGNUM *a = getBN(s, "A");
    BIGNUM *b = getBN(s, "B");
    BIGNUM *quotient = getBN(s, "Quotient");
    BIGNUM *remainder = getBN(s, "Remainder");
    BIGNUM *ret = BN_new();
    BIGNUM *ret2 = BN_new();
    BIGNUM *nnmod = BN_new();
    BN_ULONG b_word, ret_word;
    int st = 0;

    if (a == NULL || b == NULL || quotient == NULL || remainder == NULL
            || ret == NULL || ret2 == NULL || nnmod == NULL)
        goto err;

    if (!BN_div(ret, ret2, a, b, ctx)
            || !equalBN("A / B", quotient, ret)
            || !equalBN("A % B", remainder, ret2)
            || !BN_mul(ret, quotient, b, ctx)
            || !BN_add(ret, ret, remainder)
            || !equalBN("Quotient * B + Remainder", a, ret))
        goto err;

    /*
     * Test with BN_mod_word() and BN_div_word() if the divisor is
     * small enough.
     */
    b_word = BN_get_word(b);
    if (!BN_is_negative(b) && b_word != (BN_ULONG)-1) {
        BN_ULONG remainder_word = BN_get_word(remainder);

        assert(remainder_word != (BN_ULONG)-1);
        if (!BN_copy(ret, a))
            goto err;
        ret_word = BN_div_word(ret, b_word);
        if (ret_word != remainder_word) {
#ifdef BN_DEC_FMT1
            fprintf(stderr,
                    "Got A %% B (word) = " BN_DEC_FMT1 ", wanted " BN_DEC_FMT1 "\n",
                    ret_word, remainder_word);
#else
            fprintf(stderr, "Got A %% B (word) mismatch\n");
#endif
            goto err;
        }
        if (!equalBN ("A / B (word)", quotient, ret))
            goto err;

        ret_word = BN_mod_word(a, b_word);
        if (ret_word != remainder_word) {
#ifdef BN_DEC_FMT1
            fprintf(stderr,
                    "Got A %% B (word) = " BN_DEC_FMT1 ", wanted " BN_DEC_FMT1 "\n",
                    ret_word, remainder_word);
#else
            fprintf(stderr, "Got A %% B (word) mismatch\n");
#endif
            goto err;
        }
    }

    /* Test BN_nnmod. */
    if (!BN_is_negative(b)) {
        if (!BN_copy(nnmod, remainder)
                || (BN_is_negative(nnmod) && !BN_add(nnmod, nnmod, b))
                || !BN_nnmod(ret, a, b, ctx)
                || !equalBN("A % B (non-negative)", nnmod, ret))
            goto err;
    }

    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(quotient);
    BN_free(remainder);
    BN_free(ret);
    BN_free(ret2);
    BN_free(nnmod);
    return st;
}

static int file_modmul(STANZA *s)
{
    BIGNUM *a = getBN(s, "A");
    BIGNUM *b = getBN(s, "B");
    BIGNUM *m = getBN(s, "M");
    BIGNUM *mod_mul = getBN(s, "ModMul");
    BIGNUM *ret = BN_new();
    int st = 0;

    if (a == NULL || b == NULL || m == NULL || mod_mul == NULL || ret == NULL)
        goto err;

    if (!BN_mod_mul(ret, a, b, m, ctx)
            || !equalBN("A * B (mod M)", mod_mul, ret))
        goto err;

    if (BN_is_odd(m)) {
        /* Reduce |a| and |b| and test the Montgomery version. */
        BN_MONT_CTX *mont = BN_MONT_CTX_new();
        BIGNUM *a_tmp = BN_new();
        BIGNUM *b_tmp = BN_new();
        if (mont == NULL || a_tmp == NULL || b_tmp == NULL
                || !BN_MONT_CTX_set(mont, m, ctx)
                || !BN_nnmod(a_tmp, a, m, ctx)
                || !BN_nnmod(b_tmp, b, m, ctx)
                || !BN_to_montgomery(a_tmp, a_tmp, mont, ctx)
                || !BN_to_montgomery(b_tmp, b_tmp, mont, ctx)
                || !BN_mod_mul_montgomery(ret, a_tmp, b_tmp, mont, ctx)
                || !BN_from_montgomery(ret, ret, mont, ctx)
                || !equalBN("A * B (mod M) (mont)", mod_mul, ret)) {
            st = 0;
        } else {
            st = 1;
        }
        BN_MONT_CTX_free(mont);
        BN_free(a_tmp);
        BN_free(b_tmp);
        if (st == 0)
            goto err;
    }

    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(m);
    BN_free(mod_mul);
    BN_free(ret);
    return st;
}

static int file_modexp(STANZA *s)
{
    BIGNUM *a = getBN(s, "A");
    BIGNUM *e = getBN(s, "E");
    BIGNUM *m = getBN(s, "M");
    BIGNUM *mod_exp = getBN(s, "ModExp");
    BIGNUM *ret = BN_new();
    BIGNUM *b = NULL, *c = NULL, *d = BN_new();
    int st = 0;

    if (a == NULL || e == NULL || m == NULL || mod_exp == NULL || ret == NULL)
        goto err;

    if (!BN_mod_exp(ret, a, e, m, ctx)
            || !equalBN("A ^ E (mod M)", mod_exp, ret))
        goto err;

    if (BN_is_odd(m)) {
        if (!BN_mod_exp_mont(ret, a, e, m, ctx, NULL)
                || !equalBN("A ^ E (mod M) (mont)", mod_exp, ret)
                || !BN_mod_exp_mont_consttime(ret, a, e, m, ctx, NULL)
                || !equalBN("A ^ E (mod M) (mont const", mod_exp, ret))
            goto err;
    }

    /* Regression test for carry propagation bug in sqr8x_reduction */
    BN_hex2bn(&a, "050505050505");
    BN_hex2bn(&b, "02");
    BN_hex2bn(&c,
        "4141414141414141414141274141414141414141414141414141414141414141"
        "4141414141414141414141414141414141414141414141414141414141414141"
        "4141414141414141414141800000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000001");
    BN_mod_exp(d, a, b, c, ctx);
    BN_mul(e, a, a, ctx);
    if (BN_cmp(d, e)) {
        fprintf(stderr, "BN_mod_exp and BN_mul produce different results!\n");
        goto err;
    }

    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(e);
    BN_free(m);
    BN_free(mod_exp);
    BN_free(ret);
    return st;
}

static int file_exp(STANZA *s)
{
    BIGNUM *a = getBN(s, "A");
    BIGNUM *e = getBN(s, "E");
    BIGNUM *exp = getBN(s, "Exp");
    BIGNUM *ret = BN_new();
    int st = 0;

    if (a == NULL || e == NULL || exp == NULL || ret == NULL)
        goto err;

    if (!BN_exp(ret, a, e, ctx)
            || !equalBN("A ^ E", exp, ret))
        goto err;

    st = 1;
err:
    BN_free(a);
    BN_free(e);
    BN_free(exp);
    BN_free(ret);
    return st;
}

static int file_modsqrt(STANZA *s)
{
    BIGNUM *a = getBN(s, "A");
    BIGNUM *p = getBN(s, "P");
    BIGNUM *mod_sqrt = getBN(s, "ModSqrt");
    BIGNUM *ret = BN_new();
    BIGNUM *ret2 = BN_new();
    int st = 0;

    if (a == NULL || p == NULL || mod_sqrt == NULL
            || ret == NULL || ret2 == NULL)
        goto err;

    /* There are two possible answers. */
    if (!BN_mod_sqrt(ret, a, p, ctx) || !BN_sub(ret2, p, ret))
        goto err;

    if (BN_cmp(ret2, mod_sqrt) != 0
            && !equalBN("sqrt(A) (mod P)", mod_sqrt, ret))
        goto err;

    st = 1;
err:
    BN_free(a);
    BN_free(p);
    BN_free(mod_sqrt);
    BN_free(ret);
    BN_free(ret2);
    return st;
}

static int test_bn2padded()
{
#if HAVE_BN_PADDED
    uint8_t zeros[256], out[256], reference[128];
    BIGNUM *n = BN_new();
    int st = 0;

    /* Test edge case at 0. */
    if (n == NULL)
        goto err;
    if (!BN_bn2bin_padded(NULL, 0, n)) {
        fprintf(stderr,
                "BN_bn2bin_padded failed to encode 0 in an empty buffer.\n");
        goto err;
    }
    memset(out, -1, sizeof(out));
    if (!BN_bn2bin_padded(out, sizeof(out), n)) {
        fprintf(stderr,
                "BN_bn2bin_padded failed to encode 0 in a non-empty buffer.\n");
        goto err;
    }
    memset(zeros, 0, sizeof(zeros));
    if (memcmp(zeros, out, sizeof(out))) {
        fprintf(stderr, "BN_bn2bin_padded did not zero buffer.\n");
        goto err;
    }

    /* Test a random numbers at various byte lengths. */
    for (size_t bytes = 128 - 7; bytes <= 128; bytes++) {
#define TOP_BIT_ON 0
#define BOTTOM_BIT_NOTOUCH 0
        if (!BN_rand(n, bytes * 8, TOP_BIT_ON, BOTTOM_BIT_NOTOUCH)) {
            ERR_print_errors_fp(stderr);
            goto err;
        }
        if (BN_num_bytes(n) != bytes
                || BN_bn2bin(n, reference) != bytes) {
            fprintf(stderr, "Bad result from BN_rand; bytes.\n");
            goto err;
        }
        /* Empty buffer should fail. */
        if (BN_bn2bin_padded(NULL, 0, n)) {
            fprintf(stderr,
                    "BN_bn2bin_padded incorrectly succeeded on empty buffer.\n");
            goto err;
        }
        /* One byte short should fail. */
        if (BN_bn2bin_padded(out, bytes - 1, n)) {
            fprintf(stderr,
                    "BN_bn2bin_padded incorrectly succeeded on short.\n");
            goto err;
        }
        /* Exactly right size should encode. */
        if (!BN_bn2bin_padded(out, bytes, n)
                || memcmp(out, reference, bytes) != 0) {
            fprintf(stderr,
                    "BN_bn2bin_padded gave a bad result.\n");
            goto err;
        }
        /* Pad up one byte extra. */
        if (!BN_bn2bin_padded(out, bytes + 1, n)
                || memcmp(out + 1, reference, bytes)
                || memcmp(out, zeros, 1)) {
            fprintf(stderr,
                    "BN_bn2bin_padded gave a bad result.\n");
            goto err;
        }
        /* Pad up to 256. */
        if (!BN_bn2bin_padded(out, sizeof(out), n)
                || memcmp(out + sizeof(out) - bytes, reference, bytes)
                || memcmp(out, zeros, sizeof(out) - bytes)) {
            fprintf(stderr,
                    "BN_bn2bin_padded gave a bad result.\n");
            goto err;
        }
    }

    st = 1;
err:
    BN_free(n);
    return st;
#else
    return ctx != NULL;
#endif
}

static int test_dec2bn()
{
    BIGNUM *bn = NULL;
    int st = 0;

    int ret = parsedecBN(&bn, "0");
    if (ret != 1 || !BN_is_zero(bn) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_dec2bn(0) gave a bad result.\n");
        goto err;
    }
    BN_free(bn);

    ret = parsedecBN(&bn, "256");
    if (ret != 3 || !BN_is_word(bn, 256) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_dec2bn(256) gave a bad result.\n");
        goto err;
    }
    BN_free(bn);

    ret = parsedecBN(&bn, "-42");
    if (ret != 3 || !BN_abs_is_word(bn, 42) || !BN_is_negative(bn)) {
        fprintf(stderr, "BN_dec2bn(42) gave a bad result.\n");
        goto err;
    }
    BN_free(bn);

    ret = parsedecBN(&bn, "-0");
    if (ret != 2 || !BN_is_zero(bn) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_dec2bn(-0) gave a bad result.\n");
        goto err;
    }
    BN_free(bn);

    ret = parsedecBN(&bn, "42trailing garbage is ignored");
    if (ret != 2 || !BN_abs_is_word(bn, 42)
            || BN_is_negative(bn)) {
        fprintf(stderr, "BN_dec2bn(42trailing...) gave a bad result.\n");
        goto err;
    }

    st = 1;
err:
    BN_free(bn);
    return st;
}

static int test_hex2bn()
{
    BIGNUM *bn = NULL;
    int ret, st = 0;

    ret = parseBN(&bn, "0");
    if (ret != 1 || !BN_is_zero(bn) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_hex2bn(0) gave a bad result.\n");
        goto err;
    }
    BN_free(bn);

    ret = parseBN(&bn, "256");
    if (ret != 3 || !BN_is_word(bn, 0x256) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_hex2bn(256) gave a bad result.\n");
        goto err;
    }
    BN_free(bn);

    ret = parseBN(&bn, "-42");
    if (ret != 3 || !BN_abs_is_word(bn, 0x42) || !BN_is_negative(bn)) {
        fprintf(stderr, "BN_hex2bn(-42) gave a bad result.\n");
        goto err;
    }
    BN_free(bn);

    ret = parseBN(&bn, "-0");
    if (ret != 2 || !BN_is_zero(bn) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_hex2bn(-0) gave a bad result.\n");
        goto err;
    }
    BN_free(bn);

    ret = parseBN(&bn, "abctrailing garbage is ignored");
    if (ret != 3 || !BN_is_word(bn, 0xabc) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_hex2bn(abctrail...) gave a bad result.\n");
        goto err;
    }
    st = 1;

err:
    BN_free(bn);
    return st;
}

static int test_asc2bn()
{
    BIGNUM *bn = BN_new();
    int st = 0;

    if (!BN_asc2bn(&bn, "0") || !BN_is_zero(bn) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_asc2bn(0) gave a bad result.\n");
        goto err;
    }

    if (!BN_asc2bn(&bn, "256") || !BN_is_word(bn, 256) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_asc2bn(256) gave a bad result.\n");
        goto err;
    }

    if (!BN_asc2bn(&bn, "-42")
            || !BN_abs_is_word(bn, 42) || !BN_is_negative(bn)) {
        fprintf(stderr, "BN_asc2bn(-42) gave a bad result.\n");
        goto err;
    }

    if (!BN_asc2bn(&bn, "0x1234")
            || !BN_is_word(bn, 0x1234) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_asc2bn(0x1234) gave a bad result.\n");
        goto err;
    }

    if (!BN_asc2bn(&bn, "0X1234")
            || !BN_is_word(bn, 0x1234) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_asc2bn(0X1234) gave a bad result.\n");
        goto err;
    }

    if (!BN_asc2bn(&bn, "-0xabcd")
            || !BN_abs_is_word(bn, 0xabcd) || !BN_is_negative(bn)) {
        fprintf(stderr, "BN_asc2bn(-0xabcd) gave a bad result.\n");
        goto err;
    }

    if (!BN_asc2bn(&bn, "-0") || !BN_is_zero(bn) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_asc2bn(-0) gave a bad result.\n");
        goto err;
    }

    if (!BN_asc2bn(&bn, "123trailing garbage is ignored")
            || !BN_is_word(bn, 123) || BN_is_negative(bn)) {
        fprintf(stderr, "BN_asc2bn(123trail...) gave a bad result.\n");
        goto err;
    }

    st = 1;
err:
    BN_free(bn);
    return st;
}

static const MPITEST kMPITests[] = {
    {"0", "\x00\x00\x00\x00", 4},
    {"1", "\x00\x00\x00\x01\x01", 5},
    {"-1", "\x00\x00\x00\x01\x81", 5},
    {"128", "\x00\x00\x00\x02\x00\x80", 6},
    {"256", "\x00\x00\x00\x02\x01\x00", 6},
    {"-256", "\x00\x00\x00\x02\x81\x00", 6},
};

static int test_mpi()
{
    uint8_t scratch[8];
    int i = (int)sizeof(kMPITests) / sizeof(kMPITests[0]);
    const MPITEST *test = kMPITests;
    size_t mpi_len, mpi_len2;
    BIGNUM *bn = BN_new();
    BIGNUM *bn2 = NULL;
    int st = 0;

    for ( ; --i >= 0; test++) {
        if (!BN_asc2bn(&bn, test->base10)) {
            fprintf(stderr, "Can't convert %s\n", test->base10);
            goto err;
        }
        mpi_len = BN_bn2mpi(bn, NULL);
        if (mpi_len > sizeof (scratch)) {
            fprintf(stderr,
                    "MPI test #%u: MPI size is too large to test.\n",
                    (unsigned)i);
            goto err;
        }

        mpi_len2 = BN_bn2mpi(bn, scratch);
        if (mpi_len != mpi_len2) {
            fprintf(stderr, "MPI test #%u: length changes.\n",
                    (unsigned)i);
            goto err;
        }

        if (mpi_len != test->mpi_len
                || memcmp(test->mpi, scratch, mpi_len) != 0) {
            fprintf(stderr, "MPI test #%u failed:\n", (unsigned)i);
            goto err;
        }

        bn2 = BN_mpi2bn(scratch, mpi_len, NULL);
        if (bn2 == NULL) {
            fprintf(stderr, "MPI test #%u: failed to parse\n",
                    (unsigned)i);
            goto err;
        }

        if (BN_cmp(bn, bn2) != 0) {
            fprintf(stderr, "MPI test #%u: wrong result\n",
                    (unsigned)i);
            BN_free(bn2);
            goto err;
        }
        BN_free(bn2);
    }

    st = 1;
err:
    BN_free(bn);
    return st;
}

static int test_rand()
{
    BIGNUM *bn = BN_new();
    int st = 0;

    if (bn == NULL)
        return 0;

    /*
     * Test BN_rand for degenerate cases with |top| and |bottom| parameters.
     */
    if (BN_rand(bn, 0, 0 /* top */ , 0 /* bottom */ )) {
        fprintf(stderr, "BN_rand1 gave a bad result.\n");
        goto err;
    }
    if (BN_rand(bn, 0, 1 /* top */ , 1 /* bottom */ )) {
        fprintf(stderr, "BN_rand2 gave a bad result.\n");
        goto err;
    }

    if (!BN_rand(bn, 1, 0 /* top */ , 0 /* bottom */ ) || !BN_is_word(bn, 1)) {
        fprintf(stderr, "BN_rand3 gave a bad result.\n");
        goto err;
    }
    if (BN_rand(bn, 1, 1 /* top */ , 0 /* bottom */ )) {
        fprintf(stderr, "BN_rand4 gave a bad result.\n");
        goto err;
    }
    if (!BN_rand(bn, 1, -1 /* top */ , 1 /* bottom */ ) || !BN_is_word(bn, 1)) {
        fprintf(stderr, "BN_rand5 gave a bad result.\n");
        goto err;
    }

    if (!BN_rand(bn, 2, 1 /* top */ , 0 /* bottom */ ) || !BN_is_word(bn, 3)) {
        fprintf(stderr, "BN_rand6 gave a bad result.\n");
        goto err;
    }

    st = 1;
err:
    BN_free(bn);
    return st;
}

static int test_negzero()
{
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *numerator = NULL, *denominator = NULL;
    int consttime, st = 0;

    if (a == NULL || b == NULL || c == NULL || d == NULL)
        goto err;

    /* Test that BN_mul never gives negative zero. */
    if (!BN_set_word(a, 1))
        goto err;
    BN_set_negative(a, 1);
    BN_zero(b);
    if (!BN_mul(c, a, b, ctx))
        goto err;
    if (!BN_is_zero(c) || BN_is_negative(c)) {
        fprintf(stderr, "Multiplication test failed!\n");
        goto err;
    }

    for (consttime = 0; consttime < 2; consttime++) {
        numerator = BN_new();
        denominator = BN_new();
        if (numerator == NULL || denominator == NULL)
            goto err;
        if (consttime) {
            BN_set_flags(numerator, BN_FLG_CONSTTIME);
            BN_set_flags(denominator, BN_FLG_CONSTTIME);
        }
        /* Test that BN_div never gives negative zero in the quotient. */
        if (!BN_set_word(numerator, 1) || !BN_set_word(denominator, 2))
            goto err;
        BN_set_negative(numerator, 1);
        if (!BN_div(a, b, numerator, denominator, ctx))
            goto err;
        if (!BN_is_zero(a) || BN_is_negative(a)) {
            fprintf(stderr, "Incorrect quotient (consttime = %d).\n",
                    consttime);
            goto err;
        }

        /* Test that BN_div never gives negative zero in the remainder. */
        if (!BN_set_word(denominator, 1))
            goto err;
        if (!BN_div(a, b, numerator, denominator, ctx))
            goto err;
        if (!BN_is_zero(b) || BN_is_negative(b)) {
            fprintf(stderr, "Incorrect remainder (consttime = %d).\n",
                    consttime);
            goto err;
        }
        BN_free(numerator);
        BN_free(denominator);
        numerator = denominator = NULL;
    }

    /* Test that BN_set_negative will not produce a negative zero. */
    BN_zero(a);
    BN_set_negative(a, 1);
    if (BN_is_negative(a)) {
        fprintf(stderr, "BN_set_negative produced a negative zero.\n");
        goto err;
    }

    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(d);
    BN_free(numerator);
    BN_free(denominator);
    return st;
}

static int test_badmod()
{
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *zero = BN_new();
    BN_MONT_CTX *mont = BN_MONT_CTX_new();
    int st = 0;

    if (a == NULL || b == NULL || zero == NULL || mont == NULL)
        goto err;
    BN_zero(zero);

    if (BN_div(a, b, BN_value_one(), zero, ctx)) {
        fprintf(stderr, "Division by zero succeeded!\n");
        goto err;
    }
    ERR_clear_error();

    if (BN_mod_mul(a, BN_value_one(), BN_value_one(), zero, ctx)) {
        fprintf(stderr, "BN_mod_mul with zero modulus succeeded!\n");
        goto err;
    }
    ERR_clear_error();

    if (BN_mod_exp(a, BN_value_one(), BN_value_one(), zero, ctx)) {
        fprintf(stderr, "BN_mod_exp with zero modulus succeeded!\n");
        goto err;
    }
    ERR_clear_error();

    if (BN_mod_exp_mont(a, BN_value_one(), BN_value_one(), zero, ctx, NULL)) {
        fprintf(stderr, "BN_mod_exp_mont with zero modulus succeeded!\n");
        goto err;
    }
    ERR_clear_error();

    if (BN_mod_exp_mont_consttime(a, BN_value_one(), BN_value_one(),
                                  zero, ctx, NULL)) {
        fprintf(stderr,
                "BN_mod_exp_mont_consttime with zero modulus succeeded!\n");
        goto err;
    }
    ERR_clear_error();

    if (BN_MONT_CTX_set(mont, zero, ctx)) {
        fprintf(stderr, "BN_MONT_CTX_set succeeded for zero modulus!\n");
        goto err;
    }
    ERR_clear_error();

    /* Some operations also may not be used with an even modulus. */
    if (!BN_set_word(b, 16))
        goto err;

    if (BN_MONT_CTX_set(mont, b, ctx)) {
        fprintf(stderr,
                "BN_MONT_CTX_set succeeded for even modulus!\n");
        goto err;
    }
    ERR_clear_error();

    if (BN_mod_exp_mont(a, BN_value_one(), BN_value_one(), b, ctx, NULL)) {
        fprintf(stderr,
                "BN_mod_exp_mont with even modulus succeeded!\n");
        goto err;
    }
    ERR_clear_error();

    if (BN_mod_exp_mont_consttime(a, BN_value_one(), BN_value_one(),
                                  b, ctx, NULL)) {
        fprintf(stderr,
                "BN_mod_exp_mont_consttime with even modulus succeeded!\n");
        goto err;
    }
    ERR_clear_error();

    st = 1;
err:
    BN_free(a);
    BN_free(b);
    BN_free(zero);
    BN_MONT_CTX_free(mont);
    return st;
}

static int test_expmodzero()
{
    BIGNUM *zero = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *r = BN_new();
    int st = 0;

    if (zero == NULL || a == NULL || r == NULL || !BN_rand(a, 1024, 0, 0))
        goto err;
    BN_zero(zero);

    if (!BN_mod_exp(r, a, zero, BN_value_one(), NULL)
            || !BN_is_zero(r)
            || !BN_mod_exp_mont(r, a, zero, BN_value_one(), NULL, NULL)
            || !BN_is_zero(r)
            || !BN_mod_exp_mont_consttime(r, a, zero, BN_value_one(), NULL, NULL)
            || !BN_is_zero(r)
            || !BN_mod_exp_mont_word(r, 42, zero, BN_value_one(), NULL, NULL)
            || !BN_is_zero(r))
        goto err;

    st = 1;
err:
    BN_free(zero);
    BN_free(a);
    BN_free(r);
    return st;
}

static int test_smallprime()
{
    static const int kBits = 10;
    BIGNUM *r = BN_new();
    int st = 0;

    if (r == NULL
            || !BN_generate_prime_ex(r, (int)kBits, 0, NULL, NULL, NULL))
        goto err;
    if (BN_num_bits(r) != kBits) {
        fprintf(stderr, "Expected %u bit prime, got %u bit number\n",
                kBits, BN_num_bits(r));
        goto err;
    }

    st = 1;
err:
    BN_free(r);
    return st;
}


/* Delete leading and trailing spaces from a string */
static char *strip_spaces(char *p)
{
    char *q;

    /* Skip over leading spaces */
    while (*p && isspace(*p))
        p++;
    if (!*p)
        return NULL;

    for (q = p + strlen(p) - 1; q != p && isspace(*q); )
        *q-- = '\0';
    return *p ? p : NULL;
}

/*
 * Read next test stanza; return 1 if found, 0 on EOF or error.
 */
static int readstanza(STANZA *s, int *linesread)
{
    PAIR *pp = s->pairs;
    char *p, *equals, *key, *value;
    char buff[1024];

    while (fgets(buff, sizeof(buff), fp) != NULL) {
        (*linesread)++;
        if ((p = strchr(buff, '\n')) == NULL) {
            fprintf(stderr, "Line %d too long.\n", s->start);
            return 0;
        }
        *p = '\0';

        /* Blank line marks end of tests. */
        if (buff[0] == '\0')
            break;

        /* Lines starting with a pound sign are ignored. */
        if (buff[0] == '#')
            continue;

        if ((equals = strchr(buff, '=')) == NULL) {
            fprintf(stderr, "Line %d missing equals.\n", s->start);
            return 0;
        }
        *equals++ = '\0';

        key = strip_spaces(buff);
        value = strip_spaces(equals);
        if (key == NULL || value == NULL) {
            fprintf(stderr, "Line %d missing field.\n", s->start);
            return 0;
        }
        s->numpairs++;
        if (s->numpairs >= MAXPAIRS) {
            fprintf(stderr, "Line %d too many lines\n", s->start);
            return 0;
        }
        pp->key = OPENSSL_strdup(key);
        pp->value = OPENSSL_strdup(value);
        pp++;
    }

    /* If we read anything, return ok. */
    return 1;
}

static void clearstanza(STANZA *s)
{
    PAIR *pp = s->pairs;
    int i = s->numpairs;
    int start = s->start;

    for ( ; --i >= 0; pp++) {
        OPENSSL_free(pp->key);
        OPENSSL_free(pp->value);
    }
    memset(s, 0, sizeof(*s));
    s->start = start;
}

static int file_test_run(STANZA *s)
{
    static const FILETEST filetests[] = {
        {"Sum", file_sum},
        {"LShift1", file_lshift1},
        {"LShift", file_lshift},
        {"RShift", file_rshift},
        {"Square", file_square},
        {"Product", file_product},
        {"Quotient", file_quotient},
        {"ModMul", file_modmul},
        {"ModExp", file_modexp},
        {"Exp", file_exp},
        {"ModSqrt", file_modsqrt},
    };
    int numtests = OSSL_NELEM(filetests);
    const FILETEST *tp = filetests;

    for ( ; --numtests >= 0; tp++) {
        if (findattr(s, tp->name) != NULL)
            return tp->func(s);
    }
    fprintf(stderr, "Unknown test at %d\n", s->start);
    return 0;
}

static int file_tests()
{
    STANZA s;
    int linesread = 0, result = 0;

    /* Read test file. */
    memset(&s, 0, sizeof(s));
    while (!feof(fp) && readstanza(&s, &linesread)) {
        if (s.numpairs == 0)
            continue;
        if (!file_test_run(&s)) {
            if (result == 0)
                fprintf(stderr, "Test at %d failed\n", s.start);
            goto err;
        }
        clearstanza(&s);
        s.start = linesread;
    }
    result = 1;

err:
    return result;
}

int test_main(int argc, char *argv[])
{
    static const char rnd_seed[] =
        "If not seeded, BN_generate_prime might fail";
    int result = 0;

    if (argc != 2) {
        fprintf(stderr, "%s TEST_FILE\n", argv[0]);
        return 1;
    }

    ADD_TEST(test_sub);
    ADD_TEST(test_div_recip);
    ADD_TEST(test_mod);
    ADD_TEST(test_modexp_mont5);
    ADD_TEST(test_kronecker);
    ADD_TEST(test_rand);
    ADD_TEST(test_bn2padded);
    ADD_TEST(test_dec2bn);
    ADD_TEST(test_hex2bn);
    ADD_TEST(test_asc2bn);
    ADD_TEST(test_mpi);
    ADD_TEST(test_negzero);
    ADD_TEST(test_badmod);
    ADD_TEST(test_expmodzero);
    ADD_TEST(test_smallprime);
#ifndef OPENSSL_NO_EC2M
    ADD_TEST(test_gf2m_add);
    ADD_TEST(test_gf2m_mod);
    ADD_TEST(test_gf2m_mul);
    ADD_TEST(test_gf2m_sqr);
    ADD_TEST(test_gf2m_modinv);
    ADD_TEST(test_gf2m_moddiv);
    ADD_TEST(test_gf2m_modexp);
    ADD_TEST(test_gf2m_modsqrt);
    ADD_TEST(test_gf2m_modsolvequad);
#endif
    ADD_TEST(file_tests);

    RAND_seed(rnd_seed, sizeof rnd_seed);
    ctx = BN_CTX_new();
    TEST_check(ctx != NULL);

    fp = fopen(argv[1], "r");
    TEST_check(fp != NULL);
    result = run_tests(argv[0]);
    fclose(fp);

    BN_CTX_free(ctx);
    return result;
}
