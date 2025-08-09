/*
 * Copyright 2016-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define TESTUTIL_NO_size_t_COMPARISON

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include "internal/nelem.h"
#include "internal/numbers.h"
#include "testutil.h"
#include "testutil/output.h"

static int justprint = 0;

static const char * const fpexpected[][11][5] = {
    {
        /*  0.00 */ { "0.0000e+00", "0.0000", "0", "0.0000E+00", "0" },
        /*  0.01 */ { "6.7000e-01", "0.6700", "0.67", "6.7000E-01", "0.67" },
        /*  0.02 */ { "6.6667e-01", "0.6667", "0.6667", "6.6667E-01", "0.6667" },
        /*  0.03 */ { "6.6667e-04", "0.0007", "0.0006667", "6.6667E-04", "0.0006667" },
        /*  0.04 */ { "6.6667e-05", "0.0001", "6.667e-05", "6.6667E-05", "6.667E-05" },
        /*  0.05 */ { "6.6667e+00", "6.6667", "6.667", "6.6667E+00", "6.667" },
        /*  0.06 */ { "6.6667e+01", "66.6667", "66.67", "6.6667E+01", "66.67" },
        /*  0.07 */ { "6.6667e+02", "666.6667", "666.7", "6.6667E+02", "666.7" },
        /*  0.08 */ { "6.6667e+03", "6666.6667", "6667", "6.6667E+03", "6667" },
        /*  0.09 */ { "6.6667e+04", "66666.6667", "6.667e+04", "6.6667E+04", "6.667E+04" },
        /*  0.10 */ { "-6.6667e+04", "-66666.6667", "-6.667e+04", "-6.6667E+04", "-6.667E+04" },
    },
    {
        /*  1.00 */ { "0.00000e+00", "0.00000", "0", "0.00000E+00", "0" },
        /*  1.01 */ { "6.70000e-01", "0.67000", "0.67", "6.70000E-01", "0.67" },
        /*  1.02 */ { "6.66667e-01", "0.66667", "0.66667", "6.66667E-01", "0.66667" },
        /*  1.03 */ { "6.66667e-04", "0.00067", "0.00066667", "6.66667E-04", "0.00066667" },
        /*  1.04 */ { "6.66667e-05", "0.00007", "6.6667e-05", "6.66667E-05", "6.6667E-05" },
        /*  1.05 */ { "6.66667e+00", "6.66667", "6.6667", "6.66667E+00", "6.6667" },
        /*  1.06 */ { "6.66667e+01", "66.66667", "66.667", "6.66667E+01", "66.667" },
        /*  1.07 */ { "6.66667e+02", "666.66667", "666.67", "6.66667E+02", "666.67" },
        /*  1.08 */ { "6.66667e+03", "6666.66667", "6666.7", "6.66667E+03", "6666.7" },
        /*  1.09 */ { "6.66667e+04", "66666.66667", "66667", "6.66667E+04", "66667" },
        /*  1.10 */ { "-6.66667e+04", "-66666.66667", "-66667", "-6.66667E+04", "-66667" },
    },
    {
        /*  2.00 */ { "  0.0000e+00", "      0.0000", "           0", "  0.0000E+00", "           0" },
        /*  2.01 */ { "  6.7000e-01", "      0.6700", "        0.67", "  6.7000E-01", "        0.67" },
        /*  2.02 */ { "  6.6667e-01", "      0.6667", "      0.6667", "  6.6667E-01", "      0.6667" },
        /*  2.03 */ { "  6.6667e-04", "      0.0007", "   0.0006667", "  6.6667E-04", "   0.0006667" },
        /*  2.04 */ { "  6.6667e-05", "      0.0001", "   6.667e-05", "  6.6667E-05", "   6.667E-05" },
        /*  2.05 */ { "  6.6667e+00", "      6.6667", "       6.667", "  6.6667E+00", "       6.667" },
        /*  2.06 */ { "  6.6667e+01", "     66.6667", "       66.67", "  6.6667E+01", "       66.67" },
        /*  2.07 */ { "  6.6667e+02", "    666.6667", "       666.7", "  6.6667E+02", "       666.7" },
        /*  2.08 */ { "  6.6667e+03", "   6666.6667", "        6667", "  6.6667E+03", "        6667" },
        /*  2.09 */ { "  6.6667e+04", "  66666.6667", "   6.667e+04", "  6.6667E+04", "   6.667E+04" },
        /*  2.10 */ { " -6.6667e+04", " -66666.6667", "  -6.667e+04", " -6.6667E+04", "  -6.667E+04" },
    },
    {
        /*  3.00 */ { " 0.00000e+00", "     0.00000", "           0", " 0.00000E+00", "           0" },
        /*  3.01 */ { " 6.70000e-01", "     0.67000", "        0.67", " 6.70000E-01", "        0.67" },
        /*  3.02 */ { " 6.66667e-01", "     0.66667", "     0.66667", " 6.66667E-01", "     0.66667" },
        /*  3.03 */ { " 6.66667e-04", "     0.00067", "  0.00066667", " 6.66667E-04", "  0.00066667" },
        /*  3.04 */ { " 6.66667e-05", "     0.00007", "  6.6667e-05", " 6.66667E-05", "  6.6667E-05" },
        /*  3.05 */ { " 6.66667e+00", "     6.66667", "      6.6667", " 6.66667E+00", "      6.6667" },
        /*  3.06 */ { " 6.66667e+01", "    66.66667", "      66.667", " 6.66667E+01", "      66.667" },
        /*  3.07 */ { " 6.66667e+02", "   666.66667", "      666.67", " 6.66667E+02", "      666.67" },
        /*  3.08 */ { " 6.66667e+03", "  6666.66667", "      6666.7", " 6.66667E+03", "      6666.7" },
        /*  3.09 */ { " 6.66667e+04", " 66666.66667", "       66667", " 6.66667E+04", "       66667" },
        /*  3.10 */ { "-6.66667e+04", "-66666.66667", "      -66667", "-6.66667E+04", "      -66667" },
    },
    {
        /*  4.00 */ { "0e+00", "0", "0", "0E+00", "0" },
        /*  4.01 */ { "7e-01", "1", "0.7", "7E-01", "0.7" },
        /*  4.02 */ { "7e-01", "1", "0.7", "7E-01", "0.7" },
        /*  4.03 */ { "7e-04", "0", "0.0007", "7E-04", "0.0007" },
        /*  4.04 */ { "7e-05", "0", "7e-05", "7E-05", "7E-05" },
        /*  4.05 */ { "7e+00", "7", "7", "7E+00", "7" },
        /*  4.06 */ { "7e+01", "67", "7e+01", "7E+01", "7E+01" },
        /*  4.07 */ { "7e+02", "667", "7e+02", "7E+02", "7E+02" },
        /*  4.08 */ { "7e+03", "6667", "7e+03", "7E+03", "7E+03" },
        /*  4.09 */ { "7e+04", "66667", "7e+04", "7E+04", "7E+04" },
        /*  4.10 */ { "-7e+04", "-66667", "-7e+04", "-7E+04", "-7E+04" },
    },
    {
        /*  5.00 */ { "0.000000e+00", "0.000000", "0", "0.000000E+00", "0" },
        /*  5.01 */ { "6.700000e-01", "0.670000", "0.67", "6.700000E-01", "0.67" },
        /*  5.02 */ { "6.666667e-01", "0.666667", "0.666667", "6.666667E-01", "0.666667" },
        /*  5.03 */ { "6.666667e-04", "0.000667", "0.000666667", "6.666667E-04", "0.000666667" },
        /*  5.04 */ { "6.666667e-05", "0.000067", "6.66667e-05", "6.666667E-05", "6.66667E-05" },
        /*  5.05 */ { "6.666667e+00", "6.666667", "6.66667", "6.666667E+00", "6.66667" },
        /*  5.06 */ { "6.666667e+01", "66.666667", "66.6667", "6.666667E+01", "66.6667" },
        /*  5.07 */ { "6.666667e+02", "666.666667", "666.667", "6.666667E+02", "666.667" },
        /*  5.08 */ { "6.666667e+03", "6666.666667", "6666.67", "6.666667E+03", "6666.67" },
        /*  5.09 */ { "6.666667e+04", "66666.666667", "66666.7", "6.666667E+04", "66666.7" },
        /*  5.10 */ { "-6.666667e+04", "-66666.666667", "-66666.7", "-6.666667E+04", "-66666.7" },
    },
    {
        /*  6.00 */ { "0.0000e+00", "000.0000", "00000000", "0.0000E+00", "00000000" },
        /*  6.01 */ { "6.7000e-01", "000.6700", "00000.67", "6.7000E-01", "00000.67" },
        /*  6.02 */ { "6.6667e-01", "000.6667", "000.6667", "6.6667E-01", "000.6667" },
        /*  6.03 */ { "6.6667e-04", "000.0007", "0.0006667", "6.6667E-04", "0.0006667" },
        /*  6.04 */ { "6.6667e-05", "000.0001", "6.667e-05", "6.6667E-05", "6.667E-05" },
        /*  6.05 */ { "6.6667e+00", "006.6667", "0006.667", "6.6667E+00", "0006.667" },
        /*  6.06 */ { "6.6667e+01", "066.6667", "00066.67", "6.6667E+01", "00066.67" },
        /*  6.07 */ { "6.6667e+02", "666.6667", "000666.7", "6.6667E+02", "000666.7" },
        /*  6.08 */ { "6.6667e+03", "6666.6667", "00006667", "6.6667E+03", "00006667" },
        /*  6.09 */ { "6.6667e+04", "66666.6667", "6.667e+04", "6.6667E+04", "6.667E+04" },
        /*  6.10 */ { "-6.6667e+04", "-66666.6667", "-6.667e+04", "-6.6667E+04", "-6.667E+04" },
    },
};

enum int_size {
    ISZ_CHAR, ISZ_SHORT, ISZ_INT, ISZ_LONG, ISZ_LLONG
};

static const struct int_data {
    union {
        unsigned char hh;
        unsigned short h;
        unsigned int i;
        unsigned long l;
        unsigned long long ll;
    } value;
    enum int_size size;
    const char *format;
    const char *expected;
    bool skip_libc_check;
} int_data[] = {
    { { .hh = 0x42 }, ISZ_CHAR, "%+hhu", "66" },
    { { .hh = 0x88 }, ISZ_CHAR, "%hhd", "-120" },
    { { .hh = 0x0 }, ISZ_CHAR, "%hho", "0" },
    { { .hh = 0x0 }, ISZ_CHAR, "%#hho", "0" },
    { { .hh = 0x1 }, ISZ_CHAR, "%hho", "1" },
    { { .hh = 0x1 }, ISZ_CHAR, "%#hho", "01" },
    { { .hh = 0x0 }, ISZ_CHAR, "%+hhx", "0" },
    { { .hh = 0x0 }, ISZ_CHAR, "%#hhx", "0" },
    { { .hh = 0xf }, ISZ_CHAR, "%hhx", "f" },
    { { .hh = 0xe }, ISZ_CHAR, "%hhX", "E" },
    { { .hh = 0xd }, ISZ_CHAR, "%#hhx", "0xd" },
    { { .hh = 0xc }, ISZ_CHAR, "%#hhX", "0XC" },
    { { .hh = 0xb }, ISZ_CHAR, "%#04hhX", "0X0B" },
    { { .hh = 0xa }, ISZ_CHAR, "%#-015hhx", "0xa            " },
    { { .hh = 0x9 }, ISZ_CHAR, "%#+01hho", "011" },
    { { .hh = 0x8 }, ISZ_CHAR, "%#09hho", "000000010" },
    { { .hh = 0x7 }, ISZ_CHAR, "%#+ 9hhd", "       +7" },
    { { .hh = 0x6 }, ISZ_CHAR, "%# 9hhd", "        6" },
    { { .hh = 0x95 }, ISZ_CHAR, "%#06hhi", "-00107" },
    { { .hh = 0x4 }, ISZ_CHAR, "%# hhd", " 4" },
    { { .hh = 0x3 }, ISZ_CHAR, "%# hhu", "3" },
    { { .h = 1 }, ISZ_SHORT, "%4.2hd", "  01" },
    { { .h = 2 }, ISZ_SHORT, "%-4.3hu", "002 " },
    { { .h = 3 }, ISZ_SHORT, "%+.3hu", "003" },
    { { .h = 9 }, ISZ_SHORT, "%#5.2ho", "  011" },
    { { .h = 0xf }, ISZ_SHORT, "%#-6.2hx", "0x0f  " },
    { { .h = 0xaa }, ISZ_SHORT, "%#8.0hX", "    0XAA" },
    { { .h = 0xdead }, ISZ_SHORT, "%#hi", "-8531" },
    { { .h = 0xcafe }, ISZ_SHORT, "%#0.1hX", "0XCAFE" },
    { { .i = 0xdeadc0de }, ISZ_INT, "%#+67.65d",
      " -0000000000000000000000000000000000000000000000000000000055903" },
    { { .i = 0xfeedface }, ISZ_INT, "%#+70.10X",
      "                                                          0X00F" },
    { { .i = 0xdecaffee }, ISZ_INT, "%76.15o",
      "                                                             00" },
    { { .i = 0x5ad }, ISZ_INT, "%#67.x",
      "                                                              0" },
    { { .i = 0x1337 }, ISZ_INT, "|%2147483639.x|",
      "|                                                              " },
    /* Seems like MS CRT can't handle this one. */
    { { .i = 0x1337 }, ISZ_INT, "|%.2147483639x|",
      "|00000000000000000000000000000000000000000000000000000000000000", true },
    /*
     * glibc just bails out on the following three, treating everything greater
     * than 1 << 31 - 8 as an error worth stopping parsing the format string.
     */
    { { .i = 0x1337 }, ISZ_INT, "|%2147483647.x|",
      "|                                                              ", true },
    { { .i = 0x1337 }, ISZ_INT, "|%4294967295.x|",
      "|                                                              ", true },
    { { .i = 0x1337 }, ISZ_INT, "|%4294967302.x|",
      "|                                                              ", true },
    { { .i = 0xbeeface }, ISZ_INT, "%#+-12.1d", "+200211150  " },
    { { .l = 0xfacefed }, ISZ_LONG, "%#-1.14d", "00000262991853" },
    { { .l = 0xdefaced }, ISZ_LONG, "%#+12.11i", "+00233811181" },
    { { .l = 0xfacade }, ISZ_LONG, "%#0.14o", "00000076545336" },
    { { .l = 0 }, ISZ_LONG, "%#0.14o", "00000000000000" },
    { { .l = 0xfacade }, ISZ_LONG, "%#0.14x", "0x00000000facade" },
    { { .ll = 0xffffFFFFffffFFFFULL }, ISZ_LLONG, "%#-032llo",
      "01777777777777777777777         " },
    { { .ll = 0xbadc0deddeadfaceULL }, ISZ_LLONG, "%022lld",
      "-004982091772484257074" },
};

static int test_int(int i)
{
    char bio_buf[64];
    char std_buf[64];
    const struct int_data *data = int_data + i;

    switch (data->size) {
    case ISZ_CHAR:
        BIO_snprintf(bio_buf, sizeof(bio_buf), data->format, data->value.hh);
        if (!data->skip_libc_check)
            snprintf(std_buf, sizeof(std_buf), data->format, data->value.hh);
        break;
    case ISZ_SHORT:
        BIO_snprintf(bio_buf, sizeof(bio_buf), data->format, data->value.h);
        if (!data->skip_libc_check)
            snprintf(std_buf, sizeof(std_buf), data->format, data->value.h);
        break;
    case ISZ_INT:
        BIO_snprintf(bio_buf, sizeof(bio_buf), data->format, data->value.i);
        if (!data->skip_libc_check)
            snprintf(std_buf, sizeof(std_buf), data->format, data->value.i);
        break;
    case ISZ_LONG:
        BIO_snprintf(bio_buf, sizeof(bio_buf), data->format, data->value.l);
        if (!data->skip_libc_check)
            snprintf(std_buf, sizeof(std_buf), data->format, data->value.l);
        break;
    case ISZ_LLONG:
        BIO_snprintf(bio_buf, sizeof(bio_buf), data->format, data->value.ll);
        if (!data->skip_libc_check)
            snprintf(std_buf, sizeof(std_buf), data->format, data->value.ll);
        break;
    }

    if (!TEST_str_eq(bio_buf, data->expected)
        + !(data->skip_libc_check || TEST_str_eq(bio_buf, std_buf)))
        return 0;

    return 1;
}

static const struct str_wp_data {
    const char *value;
    const char *format;
    const char *expected;
    int num_args;
    int arg1;
    int arg2;
    bool skip_libc_check;
} str_wp_data[] = {
    { "01234", "%12s", "       01234" },
    { "01234", "%-12s", "01234       " },
    { "01234", "%.12s", "01234" },
    { "01234", "%.2s", "01" },

    { "abc", "%*s", "         abc", 1, 12 },
    { "abc", "%*s", "abc         ", 1, -12 },
    { "abc", "%-*s", "abc         ", 1, 12 },
    { "abc", "%-*s", "abc         ", 1, -12 },

    { "ABC", "%*.*s", "         ABC", 2, 12, 5 },
    { "ABC", "%*.*s", "AB          ", 2, -12, 2 },
    { "ABC", "%-*.*s", "ABC         ", 2, 12, -5 },
    { "ABC", "%-*.*s", "ABC         ", 2, -12, -2 },

    { "def", "%.*s", "def", 1, 12 },
    { "%%s0123456789", "%.*s", "%%s01", 1, 5 },

    { "DEF", "%-2147483648s",
      "DEF                                                            ",
      .skip_libc_check = true },
    { "DEF", "%*s",
      "                                                               ",
      1, 2147483647, .skip_libc_check = true },
};

static int test_str_wp(int i)
{
    char bio_buf[64];
    char std_buf[64];
    const struct str_wp_data *data = str_wp_data + i;

    switch (data->num_args) {
    case 2:
        BIO_snprintf(bio_buf, sizeof(bio_buf), data->format,
                     data->arg1, data->arg2, data->value);
        snprintf(std_buf, sizeof(std_buf), data->format,
                 data->arg1, data->arg2, data->value);
        break;

    case 1:
        BIO_snprintf(bio_buf, sizeof(bio_buf), data->format,
                     data->arg1, data->value);
        snprintf(std_buf, sizeof(std_buf), data->format,
                 data->arg1, data->value);
        break;

    case 0:
    default:
        BIO_snprintf(bio_buf, sizeof(bio_buf), data->format, data->value);
        snprintf(std_buf, sizeof(std_buf), data->format, data->value);
    }

    if (!TEST_str_eq(bio_buf, data->expected)
        + (!data->skip_libc_check && !TEST_str_eq(bio_buf, std_buf)))
        return 0;

    return 1;
}

typedef struct z_data_st {
    size_t value;
    const char *format;
    const char *expected;
} z_data;

static const z_data zu_data[] = {
    { SIZE_MAX, "%zu", (sizeof(size_t) == 4 ? "4294967295"
                        : sizeof(size_t) == 8 ? "18446744073709551615"
                        : "") },
    /*
     * in 2-complement, the unsigned number divided by two plus one becomes the
     * smallest possible negative signed number of the corresponding type
     */
    { SIZE_MAX / 2 + 1, "%zi", (sizeof(size_t) == 4 ? "-2147483648"
                                : sizeof(size_t) == 8 ? "-9223372036854775808"
                                : "") },
    { 0, "%zu", "0" },
    { 0, "%zi", "0" },
};

static int test_zu(int i)
{
    char bio_buf[80];
    char std_buf[80];
    const z_data *data = &zu_data[i];

    BIO_snprintf(bio_buf, sizeof(bio_buf) - 1, data->format, data->value);
    snprintf(std_buf, sizeof(std_buf) - 1, data->format, data->value);
    if (!TEST_str_eq(bio_buf, data->expected)
        + !TEST_str_eq(bio_buf, std_buf))
        return 0;
    return 1;
}

typedef struct j_data_st {
    uint64_t value;
    const char *format;
    const char *expected;
} j_data;

static const j_data jf_data[] = {
    { 0xffffffffffffffffULL, "%ju", "18446744073709551615" },
    { 0xffffffffffffffffULL, "%jx", "ffffffffffffffff" },
    { 0x8000000000000000ULL, "%ju", "9223372036854775808" },
    /*
     * These tests imply two's complement, but it's the only binary
     * representation we support, see test/sanitytest.c...
     */
    { 0x8000000000000000ULL, "%ji", "-9223372036854775808" },
};

static int test_j(int i)
{
    const j_data *data = &jf_data[i];
    char bio_buf[80];
    char std_buf[80];

    BIO_snprintf(bio_buf, sizeof(bio_buf) - 1, data->format, data->value);
    snprintf(std_buf, sizeof(std_buf) - 1, data->format, data->value);
    if (!TEST_str_eq(bio_buf, data->expected)
        + !TEST_str_eq(bio_buf, std_buf))
        return 0;
    return 1;
}


/* Precision and width. */
typedef struct pw_st {
    int p;
    const char *w;
} pw;

static const pw pw_params[] = {
    { 4, "" },
    { 5, "" },
    { 4, "12" },
    { 5, "12" },
    { 0, "" },
    { -1, "" },
    { 4, "08" }
};

static int dofptest(int test, int sub, double val, const char *width, int prec)
{
    static const char *fspecs[] = {
        "e", "f", "g", "E", "G"
    };
    char format[80], result[80], std_result[80];
    int ret = 1, i;

    for (i = 0; i < (int)OSSL_NELEM(fspecs); i++) {
        const char *fspec = fspecs[i];

        if (prec >= 0)
            BIO_snprintf(format, sizeof(format), "%%%s.%d%s", width, prec,
                         fspec);
        else
            BIO_snprintf(format, sizeof(format), "%%%s%s", width, fspec);
        BIO_snprintf(result, sizeof(result), format, val);
        snprintf(std_result, sizeof(std_result), format, val);

        if (justprint) {
            if (i == 0)
                printf("    /*  %d.%02d */ { \"%s\"", test, sub, result);
            else
                printf(", \"%s\"", result);
        } else if (!TEST_str_eq(fpexpected[test][sub][i], result)
                   + !TEST_str_eq(result, std_result)) {
            TEST_info("test %d format=|%s| exp=|%s|, ret=|%s|, stdlib_ret=|%s|",
                    test, format, fpexpected[test][sub][i], result, std_result);
            ret = 0;
        }
    }
    if (justprint)
        printf(" },\n");
    return ret;
}

static int test_fp(int i)
{
    int t = 0, r;
    const double frac = 2.0 / 3.0;
    const pw *pwp = &pw_params[i];

    if (justprint)
        printf("    {\n");
    r = TEST_true(dofptest(i, t++, 0.0, pwp->w, pwp->p))
        && TEST_true(dofptest(i, t++, 0.67, pwp->w, pwp->p))
        && TEST_true(dofptest(i, t++, frac, pwp->w, pwp->p))
        && TEST_true(dofptest(i, t++, frac / 1000, pwp->w, pwp->p))
        && TEST_true(dofptest(i, t++, frac / 10000, pwp->w, pwp->p))
        && TEST_true(dofptest(i, t++, 6.0 + frac, pwp->w, pwp->p))
        && TEST_true(dofptest(i, t++, 66.0 + frac, pwp->w, pwp->p))
        && TEST_true(dofptest(i, t++, 666.0 + frac, pwp->w, pwp->p))
        && TEST_true(dofptest(i, t++, 6666.0 + frac, pwp->w, pwp->p))
        && TEST_true(dofptest(i, t++, 66666.0 + frac, pwp->w, pwp->p))
        && TEST_true(dofptest(i, t++, -66666.0 - frac, pwp->w, pwp->p));
    if (justprint)
        printf("    },\n");
    return r;
}

static int test_big(void)
{
    char buf[80];

    /* Test excessively big number. Should fail */
    if (!TEST_int_eq(BIO_snprintf(buf, sizeof(buf),
                                  "%f\n", 2 * (double)ULONG_MAX), -1))
        return 0;

    return 1;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_PRINT,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "expected", OPT_PRINT, '-', "Output values" },
        { NULL }
    };
    return options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_PRINT:
            justprint = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    ADD_TEST(test_big);
    ADD_ALL_TESTS(test_fp, OSSL_NELEM(pw_params));
    ADD_ALL_TESTS(test_int, OSSL_NELEM(int_data));
    ADD_ALL_TESTS(test_str_wp, OSSL_NELEM(str_wp_data));
    ADD_ALL_TESTS(test_zu, OSSL_NELEM(zu_data));
    ADD_ALL_TESTS(test_j, OSSL_NELEM(jf_data));
    return 1;
}

/*
 * Replace testutil output routines.  We do this to eliminate possible sources
 * of BIO error
 */
BIO *bio_out = NULL;
BIO *bio_err = NULL;

static int tap_level = 0;

void test_open_streams(void)
{
}

void test_adjust_streams_tap_level(int level)
{
    tap_level = level;
}

void test_close_streams(void)
{
}

/*
 * This works out as long as caller doesn't use any "fancy" formats.
 * But we are caller's caller, and test_str_eq is the only one called,
 * and it uses only "%s", which is not "fancy"...
 */
int test_vprintf_stdout(const char *fmt, va_list ap)
{
    return fprintf(stdout, "%*s# ", tap_level, "") + vfprintf(stdout, fmt, ap);
}

int test_vprintf_stderr(const char *fmt, va_list ap)
{
    return fprintf(stderr, "%*s# ", tap_level, "") + vfprintf(stderr, fmt, ap);
}

int test_flush_stdout(void)
{
    return fflush(stdout);
}

int test_flush_stderr(void)
{
    return fflush(stderr);
}

int test_vprintf_tapout(const char *fmt, va_list ap)
{
    return fprintf(stdout, "%*s", tap_level, "") + vfprintf(stdout, fmt, ap);
}

int test_vprintf_taperr(const char *fmt, va_list ap)
{
    return fprintf(stderr, "%*s", tap_level, "") + vfprintf(stderr, fmt, ap);
}

int test_flush_tapout(void)
{
    return fflush(stdout);
}

int test_flush_taperr(void)
{
    return fflush(stderr);
}

