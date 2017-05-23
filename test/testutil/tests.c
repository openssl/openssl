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
#define MEM_BUFFER_SIZE     (2000)
#define MAX_STRING_WIDTH    (80)
#define BN_OUTPUT_SIZE      (8)

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

static void test_string_null_empty(const char *m, int indent, char c)
{
    if (m == NULL)
        test_printf_stderr("%*s# % 4s %c NULL\n", indent, "", "", c);
    else
        test_printf_stderr("%*s# % 4u:%c ''\n", indent, "", 0u, c);
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
            test_string_null_empty(m1, indent, ' ');
        } else {
            test_diff_header(left, right);
            test_string_null_empty(m1, indent, '-');
            test_string_null_empty(m2, indent, '+');
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
        diff = 0;
        i = 0;
        if (n1 > 0 && n2 > 0) {
            const size_t j = n1 < n2 ? n1 : n2;

            for (; i < j; i++)
                if (m1[i] == m2[i]) {
                    bdiff[i] = ' ';
                } else {
                    bdiff[i] = '^';
                    diff = 1;
                }
            bdiff[i] = '\0';
        }
        if (n1 == n2 && !diff) {
            test_printf_stderr("%*s# % 4u:  '%s'\n", indent, "", cnt,
                               n2 > n1 ? b2 : b1);
        } else {
            if (cnt == 0 && (m1 == NULL || *m1 == '\0'))
                test_string_null_empty(m1, indent, '-');
            else if (n1 > 0)
                test_printf_stderr("%*s# % 4u:- '%s'\n", indent, "", cnt, b1);
            if (cnt == 0 && (m2 == NULL || *m2 == '\0'))
               test_string_null_empty(m2, indent, '+');
            else if (n2 > 0)
                test_printf_stderr("%*s# % 4u:+ '%s'\n", indent, "", cnt, b2);
            if (diff && i > 0)
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

static void hex_convert_memory(const unsigned char *m, size_t n, char *b,
                               size_t width)
{
    size_t i;

    for (i = 0; i < n; i++) {
        const unsigned char c = *m++;

        *b++ = "0123456789abcdef"[c >> 4];
        *b++ = "0123456789abcdef"[c & 15];
        if (i % width == width - 1 && i != n - 1)
            *b++ = ' ';
    }
    *b = '\0';
}

static const int bn_bytes = (MAX_STRING_WIDTH - 9) / (BN_OUTPUT_SIZE * 2 + 1)
                            * BN_OUTPUT_SIZE;
static const int bn_chars = (MAX_STRING_WIDTH - 9) / (BN_OUTPUT_SIZE * 2 + 1)
                            * (BN_OUTPUT_SIZE * 2 + 1) - 1;

static void test_bignum_header_line(void)
{
    test_printf_stderr("%*s#  %*s\n", subtest_level(), "", bn_chars + 6,
                       "bit position");
}

static void test_bignum_zero_print(const BIGNUM *bn, char sep)
{
    const char *v = "NULL", *suf = "";
    if (bn != NULL) {
        suf = ":    0";
        v = BN_is_negative(bn) ? "-0" : "0";
    }
    test_printf_stderr("%*s# %c%*s%s\n", subtest_level(), "", sep, bn_chars,
                       v, suf);
}

static int convert_bn_memory(const unsigned char *in, size_t bytes,
                             char *out, int *lz, const BIGNUM *bn)
{
    int n = bytes * 2, i;
    char *p = out, *q = NULL;

    if (bn != NULL && !BN_is_zero(bn)) {
        hex_convert_memory(in, bytes, out, BN_OUTPUT_SIZE);
        if (*lz) {
            for (; *p == '0' || *p == ' '; p++)
                if (*p == '0') {
                    q = p;
                    *p = ' ';
                    n--;
                }
            if (*p == '\0') {
                /*
                 * in[bytes] is defined because we're converting a non-zero
                 * number and we've not seen a non-zero yet.
                 */
                if ((in[bytes] & 0xf0) != 0 && BN_is_negative(bn)) {
                    *lz = 0;
                    *q = '-';
                    n++;
                }
            } else {
                *lz = 0;
                if (BN_is_negative(bn)) {
                    /*
                     * This is valid because we always convert more digits than
                     * the number holds.
                     */
                    *q = '-';
                    n++;
                }
            }
        }
       return n;
    }

    for (i = 0; i < n; i++) {
        *p++ = ' ';
        if (i % (2 * BN_OUTPUT_SIZE) == 2 * BN_OUTPUT_SIZE - 1 && i != n - 1)
            *p++ = ' ';
    }
    *p = '\0';
    if (bn == NULL)
        q = "NULL";
    else
        q = BN_is_negative(bn) ? "-0" : "0";
    strcpy(p - strlen(q), q);
    return 0;
}

static void test_fail_bignum_common(const char *prefix, const char *file,
                                    int line, const char *type,
                                    const char *left, const char *right,
                                    const char *op,
                                    const BIGNUM *bn1, const BIGNUM *bn2)
{
    const int indent = subtest_level();
    const size_t bytes = bn_bytes;
    char b1[MAX_STRING_WIDTH + 1], b2[MAX_STRING_WIDTH + 1];
    char *p, bdiff[MAX_STRING_WIDTH + 1];
    size_t l1, l2, n1, n2, i, len;
    unsigned int cnt, diff, real_diff;
    unsigned char *m1 = NULL, *m2 = NULL;
    int lz1 = 1, lz2 = 1;
    unsigned char buffer[MEM_BUFFER_SIZE * 2], *bufp = buffer;

    l1 = bn1 == NULL ? 0 : (BN_num_bytes(bn1) + (BN_is_negative(bn1) ? 1 : 0));
    l2 = bn2 == NULL ? 0 : (BN_num_bytes(bn2) + (BN_is_negative(bn2) ? 1 : 0));
    if (l1 == 0 && l2 == 0) {
        if ((bn1 == NULL) == (bn2 == NULL)) {
            test_bignum_header_line();
            test_bignum_zero_print(bn1, ' ');
        } else {
            test_diff_header(left, right);
            test_bignum_header_line();
            test_bignum_zero_print(bn1, '-');
            test_bignum_zero_print(bn2, '+');
        }
        goto fin;
    }

    if (l1 != l2 || bn1 == NULL || bn2 == NULL || BN_cmp(bn1, bn2) != 0)
        test_diff_header(left, right);
    test_bignum_header_line();

    len = ((l1 > l2 ? l1 : l2) + bytes - 1) / bytes * bytes;

    if (len > MEM_BUFFER_SIZE && (bufp = OPENSSL_malloc(len * 2)) == NULL) {
        bufp = buffer;
        len = MEM_BUFFER_SIZE;
        test_printf_stderr("%*s# WARNING: these BIGNUMs have been truncated",
                           indent, "");
    }

    if (bn1 != NULL) {
        m1 = bufp;
        BN_bn2binpad(bn1, m1, len);
    }
    if (bn2 != NULL) {
        m2 = bufp + len;
        BN_bn2binpad(bn2, m2, len);
    }

    while (len > 0) {
        cnt = 8 * (len - bytes);
        n1 = convert_bn_memory(m1, bytes, b1, &lz1, bn1);
        n2 = convert_bn_memory(m2, bytes, b2, &lz2, bn2);

        diff = real_diff = 0;
        i = 0;
        p = bdiff;
        for (i=0; b1[i] != '\0'; i++)
            if (b1[i] == b2[i] || b1[i] == ' ' || b2[i] == ' ') {
                *p++ = ' ';
                diff |= b1[i] != b2[i];
            } else {
                *p++ = '^';
                real_diff = diff = 1;
            }
        *p++ = '\0';
        if (!diff) {
            test_printf_stderr("%*s#  %s:% 5d\n", indent, "",
                               n2 > n1 ? b2 : b1, cnt);
        } else {
            if (cnt == 0 && bn1 == NULL)
                test_printf_stderr("%*s# -%s\n", indent, "", b1);
            else if (cnt == 0 || n1 > 0)
                test_printf_stderr("%*s# -%s:% 5d\n", indent, "", b1, cnt);
            if (cnt == 0 && bn2 == NULL)
                test_printf_stderr("%*s# +%s\n", indent, "", b2);
            else if (cnt == 0 || n2 > 0)
                test_printf_stderr("%*s# +%s:% 5d\n", indent, "", b2, cnt);
            if (real_diff && (cnt == 0 || (n1 > 0 && n2 > 0))
                    && bn1 != NULL && bn2 != NULL)
                test_printf_stderr("%*s#  %s\n", indent, "", bdiff);
        }
        if (m1 != NULL)
            m1 += bytes;
        if (m2 != NULL)
            m2 += bytes;
        len -= bytes;
    }
fin:
    test_printf_stderr("\n");
    test_flush_stderr();
    if (bufp != buffer)
        OPENSSL_free(bufp);
}

static void test_fail_bignum_message(const char *prefix, const char *file,
                                     int line, const char *type,
                                     const char *left, const char *right,
                                     const char *op,
                                     const BIGNUM *bn1, const BIGNUM *bn2)
{
    test_fail_message_prefix(prefix, file, line, type, left, right, op);
    test_fail_bignum_common(prefix, file, line, type, left, right, op, bn1, bn2);
}

static void test_fail_bignum_mono_message(const char *prefix, const char *file,
                                          int line, const char *type,
                                          const char *left, const char *right,
                                          const char *op, const BIGNUM *bn)
{
    test_fail_message_prefix(prefix, file, line, type, left, right, op);
    test_fail_bignum_common(prefix, file, line, type, left, right, op, bn, bn);
}

static void test_memory_null_empty(const unsigned char *m, int indent, char c)
{
    if (m == NULL)
        test_printf_stderr("%*s# % 4s %c%s\n", indent, "", "", c, "NULL");
    else
        test_printf_stderr("%*s# %04x %c%s\n", indent, "", 0u, c, "empty");
}

static void test_fail_memory_message(const char *prefix, const char *file,
                                     int line, const char *type,
                                     const char *left, const char *right,
                                     const char *op,
                                     const unsigned char *m1, size_t l1,
                                     const unsigned char *m2, size_t l2)
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
            test_memory_null_empty(m1, indent, ' ');
        } else {
            test_diff_header(left, right);
            test_memory_null_empty(m1, indent, '-');
            test_memory_null_empty(m2, indent, '+');
        }
        goto fin;
    }

    if (l1 != l2 || memcmp(m1, m2, l1) != 0)
        test_diff_header(left, right);

    while (l1 > 0 || l2 > 0) {
        n1 = n2 = 0;
        if (l1 > 0) {
            n1 = l1 > bytes ? bytes : l1;
            hex_convert_memory(m1, n1, b1, 8);
        }
        if (l2 > 0) {
            n2 = l2 > bytes ? bytes : l2;
            hex_convert_memory(m2, n2, b2, 8);
        }

        diff = 0;
        i = 0;
        p = bdiff;
        if (n1 > 0 && n2 > 0) {
            const size_t j = n1 < n2 ? n1 : n2;

            for (; i < j; i++) {
                if (m1[i] == m2[i]) {
                    *p++ = ' ';
                    *p++ = ' ';
                } else {
                    *p++ = '^';
                    *p++ = '^';
                    diff = 1;
                }
                if (i % 8 == 7 && i != j - 1)
                    *p++ = ' ';
            }
            *p++ = '\0';
        }

        if (n1 == n2 && !diff) {
            test_printf_stderr("%*s# %04x: %s\n", indent, "", cnt, b1);
        } else {
            if (cnt == 0 && (m1 == NULL || l1 == 0))
                test_memory_null_empty(m1, indent, '-');
            else if (n1 > 0)
                test_printf_stderr("%*s# %04x:-%s\n", indent, "", cnt, b1);
            if (cnt == 0 && (m2 == NULL || l2 == 0))
                test_memory_null_empty(m2, indent, '+');
            else if (n2 > 0)
                test_printf_stderr("%*s# %04x:+%s\n", indent, "", cnt, b2);
            if (diff && i > 0)
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
    test_fail_message_va(NULL, NULL, -1, NULL, NULL, NULL, NULL, desc, ap);
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
    test_fail_bignum_mono_message(NULL, file, line, "BIGNUM", "ODD(", ")", s, a);
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
