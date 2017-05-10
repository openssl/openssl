/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../testutil.h"
#include "output.h"
#include "tu_local.h"

#include <string.h>
#include <ctype.h>
#include "../../e_os.h"

/* The size of memory buffers to display on failure */
#define MEM_BUFFER_SIZE     (33)
#define MAX_STRING_WIDTH    (80)

/* Special representation of -0 */
static char BN_minus_zero[] = "-0";

/* Output a failed test first line */
static void test_fail_message_prefix(const char *prefix, const char *file,
                                     int line, const char *type,
                                     const char *left, const char *right,
                                     const char *op)
{
    test_printf_stderr("%*s# %s: ", subtest_level(), "",
                       prefix != NULL ? prefix : "ERROR");
    if (type)
        test_printf_stderr("(%s) ", type);
    if (op != NULL)
        test_printf_stderr("'%s %s %s' failed", left, op, right);
    if (file != NULL) {
        test_printf_stderr(" @ %s:%d", file, line);
    }
    test_printf_stderr("\n");
}

/* Output a diff header */
static void test_diff_header(const char *left, const char *right)
{
    test_printf_stderr("%*s# --- %s\n", subtest_level(), "", left);
    test_printf_stderr("%*s# +++ %s\n", subtest_level(), "", right);
}

/*
 * A common routine to output test failure messages.  Generally this should not
 * be called directly, rather it should be called by the following functions.
 *
 * |desc| is a printf formatted description with arguments |args| that is
 * supplied by the user and |desc| can be NULL.  |type| is the data type
 * that was tested (int, char, ptr, ...).  |fmt| is a system provided
 * printf format with following arguments that spell out the failure
 * details i.e. the actual values compared and the operator used.
 *
 * The typical use for this is from an utility test function:
 *
 * int test6(const char *file, int line, int n) {
 *     if (n != 6) {
 *         test_fail_message(1, file, line, "int", "value %d is not %d", n, 6);
 *         return 0;
 *     }
 *     return 1;
 * }
 *
 * calling test6(3, "oops") will return 0 and produce out along the lines of:
 *      FAIL oops: (int) value 3 is not 6\n
 */
static void test_fail_message(const char *prefix, const char *file, int line,
                              const char *type, const char *left,
                              const char *right, const char *op,
                              const char *fmt, ...)
            PRINTF_FORMAT(8, 9);

static void test_fail_message_va(const char *prefix, const char *file,
                                 int line, const char *type,
                                 const char *left, const char *right,
                                 const char *op, const char *fmt, va_list ap)
{
    test_fail_message_prefix(prefix, file, line, type, left, right, op);
    if (fmt != NULL) {
        test_printf_stderr("%*s# ", subtest_level(), "");
        test_vprintf_stderr(fmt, ap);
        test_printf_stderr("\n");
    }
    test_printf_stderr("\n");
    test_flush_stderr();
}

static void test_fail_string_message(const char *prefix, const char *file,
                                     int line, const char *type,
                                     const char *left, const char *right,
                                     const char *op, const char *m1, size_t l1,
                                     const char *m2, size_t l2)
{
    const int indent = subtest_level();
    const size_t width = (MAX_STRING_WIDTH - indent - 12) / 16 * 16;
    char b1[MAX_STRING_WIDTH + 1], b2[MAX_STRING_WIDTH + 1];
    char bdiff[MAX_STRING_WIDTH + 1];
    size_t n1, n2, i;
    unsigned int cnt = 0, diff;

    test_fail_message_prefix(prefix, file, line, type, left, right, op);
    if (m1 == NULL)
        l1 = 0;
    if (m2 == NULL)
        l2 = 0;
    if (l1 == 0 && l2 == 0) {
        if ((m1 == NULL) == (m2 == NULL)) {
            test_printf_stderr("%*s# % 4s   %s\n", indent, "", "",
                               m1 == NULL ? "NULL" : "''");
        } else {
            test_diff_header(left, right);
            test_printf_stderr("%*s# % 4s - %s\n", indent, "", "",
                               m1 == NULL ? "NULL" : "''");
            test_printf_stderr("%*s# % 4s + %s\n", indent, "", "",
                               m2 == NULL ? "NULL" : "''");
        }
        goto fin;
    }

    if (l1 != l2 || strcmp(m1, m2) != 0)
        test_diff_header(left, right);

    while (l1 > 0 || l2 > 0) {
        n1 = n2 = 0;
        if (l1 > 0) {
            b1[n1 = l1 > width ? width : l1] = 0;
            for (i = 0; i < n1; i++)
                b1[i] = isprint(m1[i]) ? m1[i] : '.';
        }
        if (l2 > 0) {
            b2[n2 = l2 > width ? width : l2] = 0;
            for (i = 0; i < n2; i++)
                b2[i] = isprint(m2[i]) ? m2[i] : '.';
        }
        diff = n1 != n2;
        i = 0;
        if (n1 > 0 && n2 > 0) {
            const size_t j = n1 < n2 ? n1 : n2;
            const size_t k = n1 > n2 ? n1 : n2;

            for (; i < j; i++)
                if (m1[i] == m2[i]) {
                    bdiff[i] = ' ';
                } else {
                    bdiff[i] = '^';
                    diff = 1;
                }
            for (; i < k; i++)
                bdiff[i] = '^';
            bdiff[i] = '\0';
        }
        if (!diff) {
            test_printf_stderr("%*s# % 4u:  '%s'\n", indent, "", cnt, b1);
        } else {
            if (cnt == 0 && m1 == NULL)
                test_printf_stderr("%*s# % 4s - NULL\n", indent, "", "");
            else if (cnt == 0 && *m1 == '\0')
                test_printf_stderr("%*s# % 4s - ''\n", indent, "", "");
            else if (n1 > 0)
                test_printf_stderr("%*s# % 4u:- '%s'\n", indent, "", cnt, b1);
            if (cnt == 0 && m2 == NULL)
                test_printf_stderr("%*s# % 4s + NULL\n", indent, "", "");
            else if (cnt == 0 && *m2 == '\0')
                test_printf_stderr("%*s# % 4s + ''\n", indent, "", "");
            else if (n2 > 0)
                test_printf_stderr("%*s# % 4u:+ '%s'\n", indent, "", cnt, b2);
            if (i > 0)
                test_printf_stderr("%*s# % 4s    %s\n", indent, "", "", bdiff);
        }
        m1 += n1;
        m2 += n2;
        l1 -= n1;
        l2 -= n2;
        cnt += width;
    }
fin:
    test_printf_stderr("\n");
    test_flush_stderr();
}

static char *convertBN(const BIGNUM *b)
{
    if (b == NULL)
        return NULL;
    if (BN_is_zero(b) && BN_is_negative(b))
        return BN_minus_zero;
    return BN_bn2hex(b);
}

static void test_fail_bignum_message(const char *prefix, const char *file,
                                     int line, const char *type,
                                     const char *left, const char *right,
                                     const char *op,
                                     const BIGNUM *bn1, const BIGNUM *bn2)
{
    char *s1 = convertBN(bn1), *s2 = convertBN(bn2);
    size_t l1 = s1 != NULL ? strlen(s1) : 0;
    size_t l2 = s2 != NULL ? strlen(s2) : 0;

    test_fail_string_message(prefix, file, line, type, left, right, op,
                             s1, l1, s2, l2);
    if (s1 != BN_minus_zero)
        OPENSSL_free(s1);
    if (s2 != BN_minus_zero)
        OPENSSL_free(s2);
}

static void test_fail_bignum_mono_message(const char *prefix, const char *file,
                                          int line, const char *type,
                                          const char *left, const char *right,
                                          const char *op, const BIGNUM *bn)
{
    char *s = convertBN(bn);
    size_t l = s != NULL ? strlen(s) : 0;

    test_fail_string_message(prefix, file, line, type, left, right, op,
                             s, l, s, l);
    if (s != BN_minus_zero)
        OPENSSL_free(s);
}

static void hex_convert_memory(const char *m, size_t n, char *b)
{
    size_t i;

    for (i = 0; i < n; i++) {
        const unsigned char c = *m++;

        *b++ = "0123456789abcdef"[c >> 4];
        *b++ = "0123456789abcdef"[c & 15];
        if ((i % 8) == 7 && i != n - 1)
            *b++ = ' ';
    }
    *b = '\0';
}

static void test_fail_memory_message(const char *prefix, const char *file,
                                     int line, const char *type,
                                     const char *left, const char *right,
                                     const char *op, const char *m1, size_t l1,
                                     const char *m2, size_t l2)
{
    const int indent = subtest_level();
    const size_t bytes = (MAX_STRING_WIDTH - 9) / 17 * 8;
    char b1[MAX_STRING_WIDTH + 1], b2[MAX_STRING_WIDTH + 1];
    char *p, bdiff[MAX_STRING_WIDTH + 1];
    size_t n1, n2, i;
    unsigned int cnt = 0, diff;

    test_fail_message_prefix(prefix, file, line, type, left, right, op);
    if (m1 == NULL)
        l1 = 0;
    if (m2 == NULL)
        l2 = 0;
    if (l1 == 0 && l2 == 0) {
        if ((m1 == NULL) == (m2 == NULL)) {
            test_printf_stderr("%*s# %04s  %s\n", indent, "", "",
                               m1 == NULL ? "NULL" : "empty");
        } else {
            test_diff_header(left, right);
            test_printf_stderr("%*s# %04s -%s\n", indent, "", "",
                               m1 == NULL ? "NULL" : "empty");
            test_printf_stderr("%*s# %04s +%s\n", indent, "", "",
                               m2 == NULL ? "NULL" : "empty");
        }
        goto fin;
    }

    if (l1 != l2 || memcmp(m1, m2, l1) != 0)
        test_diff_header(left, right);

    while (l1 > 0 || l2 > 0) {
        n1 = n2 = 0;
        if (l1 > 0) {
            n1 = l1 > bytes ? bytes : l1;
            hex_convert_memory(m1, n1, b1);
        }
        if (l2 > 0) {
            n2 = l2 > bytes ? bytes : l2;
            hex_convert_memory(m2, n2, b2);
        }

        diff = n1 != n2;
        i = 0;
        p = bdiff;
        if (n1 > 0 && n2 > 0) {
            const size_t j = n1 < n2 ? n1 : n2;
            const size_t k = n1 > n2 ? n1 : n2;

            for (; i < j; i++) {
                if (m1[i] == m2[i]) {
                    *p++ = ' ';
                    *p++ = ' ';
                } else {
                    *p++ = '^';
                    *p++ = '^';
                    diff = 1;
                }
                if ((i % 8) == 7 && (i != j - 1 || j != k))
                    *p++ = ' ';
            }

            for (; i < k; i++) {
                *p++ = '^';
                *p++ = '^';
                if ((i % 8) == 7 && i != k - 1)
                    *p++ = ' ';
            }
            *p++ = '\0';
        }

        if (!diff) {
            test_printf_stderr("%*s# %04x: %s\n", indent, "", cnt, b1);
        } else {
            if (cnt == 0 && m1 == NULL)
                test_printf_stderr("%*s# %04s -NULL\n", indent, "", "");
            else if (cnt == 0 && l1 == 0)
                test_printf_stderr("%*s# %04s -empty\n", indent, "", "");
            else if (n1 > 0)
                test_printf_stderr("%*s# %04x:-%s\n", indent, "", cnt, b1);
            if (cnt == 0 && m2 == NULL)
                test_printf_stderr("%*s# %04s +NULL\n", indent, "", "");
            else if (cnt == 0 && l2 == 0)
                test_printf_stderr("%*s# %04s +empty\n", indent, "", "");
            else if (n2 > 0)
                test_printf_stderr("%*s# %04x:+%s\n", indent, "", cnt, b2);
            if (i > 0)
                test_printf_stderr("%*s# % 4s  %s\n", indent, "", "", bdiff);
        }
        m1 += n1;
        m2 += n2;
        l1 -= n1;
        l2 -= n2;
        cnt += bytes;
    }
fin:
    test_printf_stderr("\n");
    test_flush_stderr();
}

static void test_fail_message(const char *prefix, const char *file,
                              int line, const char *type,
                              const char *left, const char *right,
                              const char *op, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    test_fail_message_va(prefix, file, line, type, left, right, op, fmt, ap);
    va_end(ap);
}

void test_info_c90(const char *desc, ...)
{
    va_list ap;

    va_start(ap, desc);
    test_fail_message_va("INFO", NULL, -1, NULL, NULL, NULL, NULL, desc, ap);
    va_end(ap);
}

void test_info(const char *file, int line, const char *desc, ...)
{
    va_list ap;

    va_start(ap, desc);
    test_fail_message_va("INFO", file, line, NULL, NULL, NULL, NULL, desc, ap);
    va_end(ap);
}

void test_error_c90(const char *desc, ...)
{
    va_list ap;

    va_start(ap, desc);
    test_fail_message(NULL, NULL, -1, NULL, NULL, NULL, NULL, desc, ap);
    va_end(ap);
}

void test_error(const char *file, int line, const char *desc, ...)
{
    va_list ap;

    va_start(ap, desc);
    test_fail_message_va(NULL, file, line, NULL, NULL, NULL, NULL, desc, ap);
    va_end(ap);
}

void test_openssl_errors(void)
{
    ERR_print_errors_cb(openssl_error_cb, NULL);
}

/*
 * Define some comparisons between pairs of various types.
 * These functions return 1 if the test is true.
 * Otherwise, they return 0 and pretty-print diagnostics.
 *
 * In each case the functions produced are:
 *  int test_name_eq(const type t1, const type t2, const char *desc, ...);
 *  int test_name_ne(const type t1, const type t2, const char *desc, ...);
 *  int test_name_lt(const type t1, const type t2, const char *desc, ...);
 *  int test_name_le(const type t1, const type t2, const char *desc, ...);
 *  int test_name_gt(const type t1, const type t2, const char *desc, ...);
 *  int test_name_ge(const type t1, const type t2, const char *desc, ...);
 *
 * The t1 and t2 arguments are to be compared for equality, inequality,
 * less than, less than or equal to, greater than and greater than or
 * equal to respectively.  If the specified condition holds, the functions
 * return 1.  If the condition does not hold, the functions print a diagnostic
 * message and return 0.
 *
 * The desc argument is a printf format string followed by its arguments and
 * this is included in the output if the condition being tested for is false.
 */
#define DEFINE_COMPARISON(type, name, opname, op, fmt)                  \
    int test_ ## name ## _ ## opname(const char *file, int line,        \
                                     const char *s1, const char *s2,    \
                                     const type t1, const type t2)      \
    {                                                                   \
        if (t1 op t2)                                                   \
            return 1;                                                   \
        test_fail_message(NULL, file, line, #type, s1, s2, #op,         \
                          "[" fmt "] compared to [" fmt "]",            \
                          t1, t2);                                      \
        return 0;                                                       \
    }

#define DEFINE_COMPARISONS(type, name, fmt)                             \
    DEFINE_COMPARISON(type, name, eq, ==, fmt)                          \
    DEFINE_COMPARISON(type, name, ne, !=, fmt)                          \
    DEFINE_COMPARISON(type, name, lt, <, fmt)                           \
    DEFINE_COMPARISON(type, name, le, <=, fmt)                          \
    DEFINE_COMPARISON(type, name, gt, >, fmt)                           \
    DEFINE_COMPARISON(type, name, ge, >=, fmt)

DEFINE_COMPARISONS(int, int, "%d")
DEFINE_COMPARISONS(unsigned int, uint, "%u")
DEFINE_COMPARISONS(char, char, "%c")
DEFINE_COMPARISONS(unsigned char, uchar, "%u")
DEFINE_COMPARISONS(long, long, "%ld")
DEFINE_COMPARISONS(unsigned long, ulong, "%lu")
DEFINE_COMPARISONS(size_t, size_t, "%zu")

DEFINE_COMPARISON(void *, ptr, eq, ==, "%p")
DEFINE_COMPARISON(void *, ptr, ne, !=, "%p")

int test_ptr_null(const char *file, int line, const char *s, const void *p)
{
    if (p == NULL)
        return 1;
    test_fail_message(NULL, file, line, "ptr", s, "NULL", "==", "%p", p);
    return 0;
}

int test_ptr(const char *file, int line, const char *s, const void *p)
{
    if (p != NULL)
        return 1;
    test_fail_message(NULL, file, line, "ptr", s, "NULL", "!=", "%p", p);
    return 0;
}

int test_true(const char *file, int line, const char *s, int b)
{
    if (b)
        return 1;
    test_fail_message(NULL, file, line, "bool", s, "true", "==", "false");
    return 0;
}

int test_false(const char *file, int line, const char *s, int b)
{
    if (!b)
        return 1;
    test_fail_message(NULL, file, line, "bool", s, "false", "==", "true");
    return 0;
}

int test_str_eq(const char *file, int line, const char *st1, const char *st2,
                const char *s1, const char *s2)
{
    if (s1 == NULL && s2 == NULL)
      return 1;
    if (s1 == NULL || s2 == NULL || strcmp(s1, s2) != 0) {
        test_fail_string_message(NULL, file, line, "string", st1, st2, "==",
                                 s1, s1 == NULL ? 0 : strlen(s1),
                                 s2, s2 == NULL ? 0 : strlen(s2));
        return 0;
    }
    return 1;
}

int test_str_ne(const char *file, int line, const char *st1, const char *st2,
                const char *s1, const char *s2)
{
    if ((s1 == NULL) ^ (s2 == NULL))
      return 1;
    if (s1 == NULL || strcmp(s1, s2) == 0) {
        test_fail_string_message(NULL, file, line, "string", st1, st2, "!=",
                                 s1, s1 == NULL ? 0 : strlen(s1),
                                 s2, s2 == NULL ? 0 : strlen(s2));
        return 0;
    }
    return 1;
}

int test_strn_eq(const char *file, int line, const char *st1, const char *st2,
                 const char *s1, const char *s2, size_t len)
{
    if (s1 == NULL && s2 == NULL)
      return 1;
    if (s1 == NULL || s2 == NULL || strncmp(s1, s2, len) != 0) {
        test_fail_string_message(NULL, file, line, "string", st1, st2, "==",
                                 s1, s1 == NULL ? 0 : OPENSSL_strnlen(s1, len),
                                 s2, s2 == NULL ? 0 : OPENSSL_strnlen(s2, len));
        return 0;
    }
    return 1;
}

int test_strn_ne(const char *file, int line, const char *st1, const char *st2,
                 const char *s1, const char *s2, size_t len)
{
    if ((s1 == NULL) ^ (s2 == NULL))
      return 1;
    if (s1 == NULL || strncmp(s1, s2, len) == 0) {
        test_fail_string_message(NULL, file, line, "string", st1, st2, "!=",
                                 s1, s1 == NULL ? 0 : OPENSSL_strnlen(s1, len),
                                 s2, s2 == NULL ? 0 : OPENSSL_strnlen(s2, len));
        return 0;
    }
    return 1;
}

int test_mem_eq(const char *file, int line, const char *st1, const char *st2,
                const void *s1, size_t n1, const void *s2, size_t n2)
{
    if (s1 == NULL && s2 == NULL)
        return 1;
    if (n1 != n2 || s1 == NULL || s2 == NULL || memcmp(s1, s2, n1) != 0) {
        test_fail_memory_message(NULL, file, line, "memory", st1, st2, "==",
                                 s1, n1, s2, n2);
        return 0;
    }
    return 1;
}

int test_mem_ne(const char *file, int line, const char *st1, const char *st2,
                const void *s1, size_t n1, const void *s2, size_t n2)
{
    if ((s1 == NULL) ^ (s2 == NULL))
        return 1;
    if (n1 != n2)
        return 1;
    if (s1 == NULL || memcmp(s1, s2, n1) == 0) {
        test_fail_memory_message(NULL, file, line, "memory", st1, st2, "!=",
                                 s1, n1, s2, n2);
        return 0;
    }
    return 1;
}

#define DEFINE_BN_COMPARISONS(opname, op, zero_cond)                    \
    int test_BN_ ## opname(const char *file, int line,                  \
                           const char *s1, const char *s2,              \
                           const BIGNUM *t1, const BIGNUM *t2)          \
    {                                                                   \
        if (BN_cmp(t1, t2) op 0)                                        \
            return 1;                                                   \
        test_fail_bignum_message(NULL, file, line, "BIGNUM", s1, s2,    \
                                 #op, t1, t2);                          \
        return 0;                                                       \
    }                                                                   \
    int test_BN_ ## opname ## _zero(const char *file, int line,         \
                                    const char *s, const BIGNUM *a)     \
    {                                                                   \
        if (a != NULL &&(zero_cond))                                    \
            return 1;                                                   \
        test_fail_bignum_mono_message(NULL, file, line, "BIGNUM",       \
                                      s, "0", #op, a);                  \
        return 0;                                                       \
    }

DEFINE_BN_COMPARISONS(eq, ==, BN_is_zero(a))
DEFINE_BN_COMPARISONS(ne, !=, !BN_is_zero(a))
DEFINE_BN_COMPARISONS(gt, >,  !BN_is_negative(a) && !BN_is_zero(a))
DEFINE_BN_COMPARISONS(ge, >=, !BN_is_negative(a) || BN_is_zero(a))
DEFINE_BN_COMPARISONS(lt, <,  BN_is_negative(a) && !BN_is_zero(a))
DEFINE_BN_COMPARISONS(le, <=, BN_is_negative(a) || BN_is_zero(a))

int test_BN_eq_one(const char *file, int line, const char *s, const BIGNUM *a)
{
    if (a != NULL && BN_is_one(a))
        return 1;
    test_fail_bignum_mono_message(NULL, file, line, "BIGNUM", s, "1", "==", a);
    return 0;
}

int test_BN_odd(const char *file, int line, const char *s, const BIGNUM *a)
{
    if (a != NULL && BN_is_odd(a))
        return 1;
    test_fail_bignum_mono_message(NULL, file, line, "BIGNUM", "ODD(", ")", s,
                                  a);
    return 0;
}

int test_BN_even(const char *file, int line, const char *s, const BIGNUM *a)
{
    if (a != NULL && !BN_is_odd(a))
        return 1;
    test_fail_bignum_mono_message(NULL, file, line, "BIGNUM", "EVEN(", ")", s,
                                  a);
    return 0;
}

int test_BN_eq_word(const char *file, int line, const char *bns, const char *ws,
                    const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw;

    if (a != NULL && BN_is_word(a, w))
        return 1;
    bw = BN_new();
    BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "==", a, bw);
    BN_free(bw);
    return 0;
}

int test_BN_abs_eq_word(const char *file, int line, const char *bns,
                        const char *ws, const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw, *aa;

    if (a != NULL && BN_abs_is_word(a, w))
        return 1;
    bw = BN_new();
    aa = BN_dup(a);
    BN_set_negative(aa, 0);
    BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "abs==",
                             aa, bw);
    BN_free(bw);
    BN_free(aa);
    return 0;
}
