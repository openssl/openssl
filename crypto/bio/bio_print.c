/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include "internal/cryptlib.h"
#include "crypto/ctype.h"
#include "internal/numbers.h"
#include <openssl/bio.h>
#include <openssl/configuration.h>

/*
 * Copyright Patrick Powell 1995
 * This code is based on code written by Patrick Powell <papowell@astart.com>
 * It may be used for any purpose as long as this notice remains intact
 * on all source code distributions.
 */

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long double
#else
# define LDOUBLE double
#endif

struct pr_desc {
    /** Static buffer */
    char *sbuffer;
    /** Dynamic buffer */
    char **buffer;
    /** Current writing position */
    size_t currlen;
    /** Buffer size */
    size_t maxlen;
    /** "Write position", for proper %n support */
    long long pos;
};

static int fmtstr(struct pr_desc *, const char *, int, int, int);
static int fmtint(struct pr_desc *, int64_t, int, int, int, int);
#ifndef OPENSSL_SYS_UEFI
static int fmtfp(struct pr_desc *, LDOUBLE, int, int, int, int);
#endif
static int doapr_outch(struct pr_desc *, int);
static int eob_ok(struct pr_desc *desc, long long left);
static int _dopr(char **sbuffer, char **buffer,
                 size_t *maxlen, size_t *retlen, int *truncated,
                 const char *format, va_list args);

/* format read states */
#define DP_S_DEFAULT    0
#define DP_S_FLAGS      1
#define DP_S_MIN        2
#define DP_S_DOT        3
#define DP_S_MAX        4
#define DP_S_MOD        5
#define DP_S_CONV       6
#define DP_S_DONE       7

/* format flags - Bits */
/* left-aligned padding */
#define DP_F_MINUS      (1 << 0)
/* print an explicit '+' for a value with positive sign */
#define DP_F_PLUS       (1 << 1)
/* print an explicit ' ' for a value with positive sign */
#define DP_F_SPACE      (1 << 2)
/* print 0/0x prefix for octal/hex and decimal point for floating point */
#define DP_F_NUM        (1 << 3)
/* print leading zeroes */
#define DP_F_ZERO       (1 << 4)
/* print HEX in UPPERcase */
#define DP_F_UP         (1 << 5)
/* treat value as unsigned */
#define DP_F_UNSIGNED   (1 << 6)

/* conversion flags */
#define DP_C_CHAR       1
#define DP_C_SHORT      2
#define DP_C_LONG       3
#define DP_C_LDOUBLE    4
#define DP_C_LLONG      5
#define DP_C_SIZE       6
#define DP_C_PTRDIFF    7

/* Floating point formats */
#define F_FORMAT        0
#define E_FORMAT        1
#define G_FORMAT        2

/* some handy macros */
#define char_to_int(p) (p - '0')
#define OSSL_MAX(p,q) ((p >= q) ? p : q)

static int
_dopr(char **sbuffer,
      char **buffer,
      size_t *maxlen,
      size_t *retlen, int *truncated, const char *format, va_list args)
{
    char ch;
    int64_t value;
#ifndef OPENSSL_SYS_UEFI
    LDOUBLE fvalue;
#endif
    char *strvalue;
    int min;
    int max;
    int state;
    int flags;
    int cflags;
    struct pr_desc desc = { *sbuffer, buffer, 0, *maxlen, 0 };
    int ret = 0;

    state = DP_S_DEFAULT;
    flags = cflags = min = 0;
    max = -1;
    ch = *format++;

    while (state != DP_S_DONE) {
        if (ch == '\0')
            state = DP_S_DONE;

        switch (state) {
        case DP_S_DEFAULT:
            if (ch == '%')
                state = DP_S_FLAGS;
            else
                if (!doapr_outch(&desc, ch))
                    goto out;
            ch = *format++;
            break;
        case DP_S_FLAGS:
            switch (ch) {
            case '-':
                flags |= DP_F_MINUS;
                ch = *format++;
                break;
            case '+':
                flags |= DP_F_PLUS;
                ch = *format++;
                break;
            case ' ':
                flags |= DP_F_SPACE;
                ch = *format++;
                break;
            case '#':
                flags |= DP_F_NUM;
                ch = *format++;
                break;
            case '0':
                flags |= DP_F_ZERO;
                ch = *format++;
                break;
            default:
                state = DP_S_MIN;
                break;
            }
            break;
        case DP_S_MIN: /* width */
            if (ossl_isdigit(ch)) {
                /*
                 * Most implementations cap the possible explicitly specified
                 * width by (INT_MAX / 10) * 10 - 1 or so (the standard gives
                 * no clear limit on this), we can do the same.
                 */
                if (min < INT_MAX / 10)
                    min = 10 * min + char_to_int(ch);
                else
                    goto out;
                ch = *format++;
            } else if (ch == '*') {
                min = va_arg(args, int);
                if (min < 0) {
                    flags |= DP_F_MINUS;
                    min = -min;
                }
                ch = *format++;
                state = DP_S_DOT;
            } else
                state = DP_S_DOT;
            break;
        case DP_S_DOT:
            if (ch == '.') {
                state = DP_S_MAX;
                ch = *format++;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MAX: /* precision */
            if (ossl_isdigit(ch)) {
                if (max < 0)
                    max = 0;
                /*
                 * Most implementations cap the possible explicitly specified
                 * width by (INT_MAX / 10) * 10 - 1 or so (the standard gives
                 * no clear limit on this), we can do the same.
                 */
                if (max < INT_MAX / 10)
                    max = 10 * max + char_to_int(ch);
                else
                    goto out;
                ch = *format++;
            } else if (ch == '*') {
                max = va_arg(args, int);
                ch = *format++;
                state = DP_S_MOD;
            } else {
                if (max < 0)
                    max = 0;
                state = DP_S_MOD;
            }
            break;
        case DP_S_MOD:
            switch (ch) {
            case 'h':
                if (*format == 'h') {
                    cflags = DP_C_CHAR;
                    format++;
                } else {
                    cflags = DP_C_SHORT;
                }
                ch = *format++;
                break;
            case 'l':
                if (*format == 'l') {
                    cflags = DP_C_LLONG;
                    format++;
                } else
                    cflags = DP_C_LONG;
                ch = *format++;
                break;
            case 'q':
            case 'j':
                cflags = DP_C_LLONG;
                ch = *format++;
                break;
            case 'L':
                cflags = DP_C_LDOUBLE;
                ch = *format++;
                break;
            case 'z':
                cflags = DP_C_SIZE;
                ch = *format++;
                break;
            case 't':
                cflags = DP_C_PTRDIFF;
                ch = *format++;
                break;
            default:
                break;
            }
            state = DP_S_CONV;
            break;
        case DP_S_CONV:
            switch (ch) {
            case 'd':
            case 'i':
                switch (cflags) {
                case DP_C_CHAR:
                    value = (signed char)va_arg(args, int);
                    break;
                case DP_C_SHORT:
                    value = (short int)va_arg(args, int);
                    break;
                case DP_C_LONG:
                    value = va_arg(args, long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, int64_t);
                    break;
                case DP_C_SIZE:
                    value = va_arg(args, ossl_ssize_t);
                    break;
                case DP_C_PTRDIFF:
                    value = va_arg(args, ptrdiff_t);
                    break;
                default:
                    value = va_arg(args, int);
                    break;
                }
                if (!fmtint(&desc, value, 10, min, max, flags))
                    goto out;
                break;
            case 'X':
                flags |= DP_F_UP;
                /* FALLTHROUGH */
            case 'x':
            case 'o':
            case 'u':
                flags |= DP_F_UNSIGNED;
                switch (cflags) {
                case DP_C_CHAR:
                    value = (unsigned char)va_arg(args, unsigned int);
                    break;
                case DP_C_SHORT:
                    value = (unsigned short int)va_arg(args, unsigned int);
                    break;
                case DP_C_LONG:
                    value = va_arg(args, unsigned long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, uint64_t);
                    break;
                case DP_C_SIZE:
                    value = va_arg(args, size_t);
                    break;
                case DP_C_PTRDIFF:
                    /*
                     * There is no unsigned variant of ptrdiff_t, and POSIX
                     * requires using a "corresponding unsigned type argument".
                     * Assuming it is power of two in size, at least.
                     */
                    if (sizeof(ptrdiff_t) == sizeof(uint64_t))
                        value = va_arg(args, uint64_t);
                    else
                        value = va_arg(args, unsigned int);
                    break;
                default:
                    value = va_arg(args, unsigned int);
                    break;
                }
                if (!fmtint(&desc, value,
                            ch == 'o' ? 8 : (ch == 'u' ? 10 : 16),
                            min, max, flags))
                    goto out;
                break;
#ifndef OPENSSL_SYS_UEFI
            case 'f':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                if (!fmtfp(&desc, fvalue, min, max, flags, F_FORMAT))
                    goto out;
                break;
            case 'E':
                flags |= DP_F_UP;
                /* fall through */
            case 'e':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                if (!fmtfp(&desc, fvalue, min, max, flags, E_FORMAT))
                    goto out;
                break;
            case 'G':
                flags |= DP_F_UP;
                /* fall through */
            case 'g':
                if (cflags == DP_C_LDOUBLE)
                    fvalue = va_arg(args, LDOUBLE);
                else
                    fvalue = va_arg(args, double);
                if (!fmtfp(&desc, fvalue, min, max, flags, G_FORMAT))
                    goto out;
                break;
#else
            case 'f':
            case 'E':
            case 'e':
            case 'G':
            case 'g':
                /* not implemented for UEFI */
                ERR_raise(ERR_LIB_BIO, ERR_R_UNSUPPORTED);
                goto out;
#endif
            case 'c':
                if (!doapr_outch(&desc, va_arg(args, int)))
                    goto out;
                break;
            case 's':
                strvalue = va_arg(args, char *);
                if (max < 0)
                    max = INT_MAX;
                if (!fmtstr(&desc, strvalue, flags, min, max))
                    goto out;
                break;
            case 'p':
                value = (size_t)va_arg(args, void *);
                if (!fmtint(&desc, value, 16, min, max, flags | DP_F_NUM))
                    goto out;
                break;
            case 'n':
                switch (cflags) {
#define HANDLE_N(type)              \
    do {                            \
        type *num;                  \
                                    \
        num = va_arg(args, type *); \
        *num = (type) desc.pos;     \
    } while (0)
                case DP_C_CHAR:
                    HANDLE_N(signed char);
                    break;
                case DP_C_SHORT:
                    HANDLE_N(short);
                    break;
                case DP_C_LONG:
                    HANDLE_N(long);
                    break;
                case DP_C_LLONG:
                    HANDLE_N(long long);
                    break;
                case DP_C_SIZE:
                    HANDLE_N(ossl_ssize_t);
                    break;
                case DP_C_PTRDIFF:
                    HANDLE_N(ptrdiff_t);
                    break;
                default:
                    HANDLE_N(int);
                    break;
#undef HANDLE_N
                }
                break;
            case '%':
                if (!doapr_outch(&desc, ch))
                    goto out;
                break;
            case 'w':
                /* not supported yet, treat as next char */
                format++;
                break;
            default:
                /* unknown, skip */
                break;
            }
            ch = *format++;
            state = DP_S_DEFAULT;
            flags = cflags = min = 0;
            max = -1;
            break;
        case DP_S_DONE:
            break;
        default:
            break;
        }
    }
    ret = 1;

out:
    /*
     * We have to truncate if there is no dynamic buffer and we have filled the
     * static buffer.
     */
    if (buffer == NULL) {
        *truncated = (desc.currlen > desc.maxlen - 1);
        if (*truncated)
            desc.currlen = desc.maxlen - 1;
    }

    if (!doapr_outch(&desc, '\0'))
        ret = 0;

    *retlen = desc.currlen - 1;
    *sbuffer = desc.sbuffer;
    *maxlen = desc.maxlen;

    return ret;
}

static int
fmtstr(struct pr_desc *desc, const char *value, int flags, int min, int max)
{
    int padlen = 0;
    size_t strln;
    int cnt = 0;

    if (value == 0)
        value = "<NULL>";

    strln = OPENSSL_strnlen(value, max < 0 ? SIZE_MAX : (size_t)max);

    if (min >= 0 && strln < INT_MAX) {
        padlen = min - (int)strln;
        if (padlen < 0)
            padlen = 0;
    }
    if (max >= 0) {
        /*
         * Calculate the maximum output including padding.
         * Make sure max doesn't overflow into negativity
         */
        if (max < INT_MAX - padlen)
            max += padlen;
        else
            max = INT_MAX;
    }

    if (!(flags & DP_F_MINUS) && padlen > 0) {
        /* cap padlen to max so we can pass it as-is to eob_ok() */
        if (max >= 0) {
            if (padlen > max)
                padlen = max;
            cnt = padlen;
        }
        while (padlen > 0 && eob_ok(desc, padlen)) {
            if (!doapr_outch(desc, ' '))
                return 0;
            --padlen;
        }
    }
    if (max >= 0) {
        /* cap strln to (max - cnt) so we can pass it as-is to eob_ok() */
        if (strln > INT_MAX || (int)strln > max - cnt)
            strln = max - cnt;
        cnt += (int)strln;
    }
    while (strln > 0 && eob_ok(desc, strln)) {
        if (!doapr_outch(desc, *value++))
            return 0;
        --strln;
    }
    if ((flags & DP_F_MINUS) && padlen > 0) {
        /* cap padlen to (max - cnt) so we can pass it as-is to eob_ok() */
        if (max >= 0) {
            if (padlen > max - cnt)
                padlen = max - cnt;
        }
        while (padlen > 0 && eob_ok(desc, padlen)) {
            if (!doapr_outch(desc, ' '))
                return 0;
            --padlen;
        }
    }
    return 1;
}

static int
fmtint(struct pr_desc *desc,
       int64_t value, int base, int min, int max, int flags)
{
    static const char oct_prefix[] = "0";

    int signvalue = 0;
    const char *prefix = "";
    uint64_t uvalue;
    char convert[DECIMAL_SIZE(value) + 3];
    int place = 0;
    int spadlen = 0;
    int zpadlen = 0;
    int caps = 0;

    if (max < 0) {
        /* A negative precision is taken as if the precision were omitted. */
        max = 1;
    } else {
        /*
         * If a precision is given with an integer conversion,
         * the 0 flag is ignored.
         */
        flags &= ~DP_F_ZERO;
    }
    uvalue = value;
    if (!(flags & DP_F_UNSIGNED)) {
        if (value < 0) {
            signvalue = '-';
            uvalue = 0 - (uint64_t)value;
        } else if (flags & DP_F_PLUS)
            signvalue = '+';
        else if (flags & DP_F_SPACE)
            signvalue = ' ';
    }
    if (flags & DP_F_NUM) {
        if (base == 8)
            prefix = oct_prefix;
        if (value != 0) {
            if (base == 16)
                prefix = flags & DP_F_UP ? "0X" : "0x";
        }
    }
    if (flags & DP_F_UP)
        caps = 1;
    /* When 0 is printed with an explicit precision 0, the output is empty. */
    while (uvalue && (place < (int)sizeof(convert))) {
        convert[place++] = (caps ? "0123456789ABCDEF" : "0123456789abcdef")
            [uvalue % (unsigned)base];
        uvalue = (uvalue / (unsigned)base);
    }
    if (place == sizeof(convert))
        place--;
    convert[place] = 0;

    /*
     * "#" (alternative form):
     *   - For o conversion, it shall increase the precision, if and only
     *     if necessary, to force the first digit of the result to be a zero
     */
    zpadlen = max - place - (prefix == oct_prefix);
    if (zpadlen < 0)
        zpadlen = 0;
    spadlen =
        min - OSSL_MAX(max, place + zpadlen + (signvalue ? 1 : 0) + (int)strlen(prefix));
    if (spadlen < 0)
        spadlen = 0;
    if (flags & DP_F_MINUS) {
        spadlen = -spadlen;
    } else if (flags & DP_F_ZERO) {
        zpadlen = zpadlen + spadlen;
        spadlen = 0;
    }

    /* spaces */
    while (spadlen > 0 && eob_ok(desc, spadlen)) {
        if (!doapr_outch(desc, ' '))
            return 0;
        --spadlen;
    }

    /* sign */
    if (signvalue)
        if (!doapr_outch(desc, signvalue))
            return 0;

    /* prefix */
    while (*prefix) {
        if (!doapr_outch(desc, *prefix))
            return 0;
        prefix++;
    }

    /* zeros */
    if (zpadlen > 0) {
        while (zpadlen > 0 && eob_ok(desc, zpadlen)) {
            if (!doapr_outch(desc, '0'))
                return 0;
            --zpadlen;
        }
    }
    /* digits */
    while (place > 0) {
        if (!doapr_outch(desc, convert[--place]))
            return 0;
    }

    /* left justified spaces */
    if (spadlen < 0) {
        spadlen = -spadlen;

        while (spadlen > 0 && eob_ok(desc, spadlen)) {
            if (!doapr_outch(desc, ' '))
                return 0;
            --spadlen;
        }
    }
    return 1;
}

#ifndef OPENSSL_SYS_UEFI

static LDOUBLE abs_val(LDOUBLE value)
{
    LDOUBLE result = value;
    if (value < 0)
        result = -value;
    if (result > 0 && result / 2 == result) /* INF */
        result = 0;
    else if (result != result) /* NAN */
        result = 0;
    return result;
}

static LDOUBLE pow_10(int in_exp)
{
    LDOUBLE result = 1;
    while (in_exp) {
        result *= 10;
        in_exp--;
    }
    return result;
}

static long roundv(LDOUBLE value)
{
    long intpart;
    intpart = (long)value;
    value = value - intpart;
    if (value >= 0.5)
        intpart++;
    return intpart;
}

static int
fmtfp(struct pr_desc *desc,
      LDOUBLE fvalue, int min, int max, int flags, int style)
{
    int signvalue = 0;
    LDOUBLE ufvalue;
    LDOUBLE tmpvalue;
    char iconvert[20];
    char fconvert[20];
    char econvert[20];
    int iplace = 0;
    int fplace = 0;
    int eplace = 0;
    int padlen = 0;
    int zpadlen = 0;
    long exp = 0;
    unsigned long intpart;
    unsigned long fracpart;
    unsigned long max10;
    int realstyle;

    if (max < 0)
        max = 6;

    if (fvalue < 0)
        signvalue = '-';
    else if (flags & DP_F_PLUS)
        signvalue = '+';
    else if (flags & DP_F_SPACE)
        signvalue = ' ';
    ufvalue = abs_val(fvalue);
    if (ufvalue == 0 && fvalue != 0) /* INF or NAN? */
        signvalue = '?';

    /*
     * G_FORMAT sometimes prints like E_FORMAT and sometimes like F_FORMAT
     * depending on the number to be printed. Work out which one it is and use
     * that from here on.
     */
    if (style == G_FORMAT) {
        if (ufvalue == 0.0) {
            realstyle = F_FORMAT;
        } else if (ufvalue < 0.0001) {
            realstyle = E_FORMAT;
        } else if ((max == 0 && ufvalue >= 10)
                   || (max > 0 && ufvalue >= pow_10(max))) {
            realstyle = E_FORMAT;
        } else {
            realstyle = F_FORMAT;
        }
    } else {
        realstyle = style;
    }

    if (style != F_FORMAT) {
        tmpvalue = ufvalue;
        /* Calculate the exponent */
        if (ufvalue != 0.0) {
            while (tmpvalue < 1) {
                tmpvalue *= 10;
                exp--;
            }
            while (tmpvalue > 10) {
                tmpvalue /= 10;
                exp++;
            }
        }
        if (style == G_FORMAT) {
            /*
             * In G_FORMAT the "precision" represents significant digits. We
             * always have at least 1 significant digit.
             */
            if (max == 0)
                max = 1;
            /* Now convert significant digits to decimal places */
            if (realstyle == F_FORMAT) {
                max -= (exp + 1);
                if (max < 0) {
                    /*
                     * Should not happen. If we're in F_FORMAT then exp < max?
                     */
                    (void)doapr_outch(desc, '\0');
                    return 0;
                }
            } else {
                /*
                 * In E_FORMAT there is always one significant digit in front
                 * of the decimal point, so:
                 * significant digits == 1 + decimal places
                 */
                max--;
            }
        }
        if (realstyle == E_FORMAT)
            ufvalue = tmpvalue;
    }

    /*
     * By subtracting 65535 (2^16-1) we cancel the low order 15 bits
     * of ULONG_MAX to avoid using imprecise floating point values.
     */
    if (ufvalue >= (double)(ULONG_MAX - 65535) + 65536.0) {
        /* Number too big */
        (void)doapr_outch(desc, '\0');
        return 0;
    }
    intpart = (unsigned long)ufvalue;

    /*
     * sorry, we only support 9 digits past the decimal because of our
     * conversion method
     */
    if (max > 9)
        max = 9;

    /*
     * we "cheat" by converting the fractional part to integer by multiplying
     * by a factor of 10
     */
    max10 = roundv(pow_10(max));
    fracpart = roundv(pow_10(max) * (ufvalue - intpart));

    if (fracpart >= max10) {
        intpart++;
        fracpart -= max10;
    }

    /* convert integer part */
    do {
        iconvert[iplace++] = "0123456789"[intpart % 10];
        intpart = (intpart / 10);
    } while (intpart && (iplace < (int)sizeof(iconvert)));
    if (iplace == sizeof(iconvert))
        iplace--;
    iconvert[iplace] = 0;

    /* convert fractional part */
    while (fplace < max) {
        if (style == G_FORMAT && fplace == 0 && (fracpart % 10) == 0) {
            /* We strip trailing zeros in G_FORMAT */
            max--;
            fracpart = fracpart / 10;
            if (fplace < max)
                continue;
            break;
        }
        fconvert[fplace++] = "0123456789"[fracpart % 10];
        fracpart = (fracpart / 10);
    }

    fconvert[fplace] = 0;

    /* convert exponent part */
    if (realstyle == E_FORMAT) {
        int tmpexp;
        if (exp < 0)
            tmpexp = -exp;
        else
            tmpexp = exp;

        do {
            econvert[eplace++] = "0123456789"[tmpexp % 10];
            tmpexp = (tmpexp / 10);
        } while (tmpexp > 0 && eplace < (int)sizeof(econvert));
        /* Exponent is huge!! Too big to print */
        if (tmpexp > 0) {
            (void)doapr_outch(desc, '\0');
            return 0;
        }
        /* Add a leading 0 for single digit exponents */
        if (eplace == 1)
            econvert[eplace++] = '0';
    }

    /*
     * -1 for decimal point (if we have one, i.e. max > 0),
     * another -1 if we are printing a sign
     */
    padlen = min - iplace - max - (max > 0 ? 1 : 0) - ((signvalue) ? 1 : 0);
    /* Take some off for exponent prefix "+e" and exponent */
    if (realstyle == E_FORMAT)
        padlen -= 2 + eplace;
    zpadlen = max - fplace;
    if (zpadlen < 0)
        zpadlen = 0;
    if (padlen < 0)
        padlen = 0;
    if (flags & DP_F_MINUS)
        padlen = -padlen;

    if ((flags & DP_F_ZERO) && (padlen > 0)) {
        if (signvalue) {
            if (!doapr_outch(desc, signvalue))
                return 0;
            --padlen;
            signvalue = 0;
        }
        while (padlen > 0 && eob_ok(desc, padlen)) {
            if (!doapr_outch(desc, '0'))
                return 0;
            --padlen;
        }
        padlen = 0;
    }
    while (padlen > 0 && eob_ok(desc, padlen)) {
        if (!doapr_outch(desc, ' '))
            return 0;
        --padlen;
    }
    padlen = 0;
    if (signvalue && !doapr_outch(desc, signvalue))
        return 0;

    while (iplace > 0) {
        if (!doapr_outch(desc, iconvert[--iplace]))
            return 0;
    }

    /*
     * Decimal point. This should probably use locale to find the correct
     * char to print out.
     */
    if (max > 0 || (flags & DP_F_NUM)) {
        if (!doapr_outch(desc, '.'))
            return 0;

        while (fplace > 0) {
            if (!doapr_outch(desc, fconvert[--fplace]))
                return 0;
        }
    }
    while (zpadlen > 0 && eob_ok(desc, zpadlen)) {
        if (!doapr_outch(desc, '0'))
            return 0;
        --zpadlen;
    }
    if (realstyle == E_FORMAT) {
        char ech;

        if ((flags & DP_F_UP) == 0)
            ech = 'e';
        else
            ech = 'E';
        if (!doapr_outch(desc, ech))
            return 0;
        if (exp < 0) {
            if (!doapr_outch(desc, '-'))
                return 0;
        } else {
            if (!doapr_outch(desc, '+'))
                return 0;
        }
        while (eplace > 0) {
            if (!doapr_outch(desc, econvert[--eplace]))
                return 0;
        }
    }

    if (padlen < 0) {
        padlen = -padlen;

        while (padlen > 0 && eob_ok(desc, padlen)) {
            if (!doapr_outch(desc, ' '))
                return 0;
            --padlen;
        }
    }
    return 1;
}

#endif /* OPENSSL_SYS_UEFI */

#define BUFFER_INC  1024

static int
doapr_outch(struct pr_desc *desc, int c)
{
    /* If we haven't at least one buffer, someone has done a big booboo */
    if (!ossl_assert(desc->sbuffer != NULL || desc->buffer != NULL))
        return 0;

    /* |currlen| must always be <= |*maxlen| */
    if (!ossl_assert(desc->currlen <= desc->maxlen))
        return 0;

    if (desc->buffer != NULL && desc->currlen == desc->maxlen) {
        if (desc->maxlen > INT_MAX - BUFFER_INC)
            return 0;

        desc->maxlen += BUFFER_INC;
        if (*(desc->buffer) == NULL) {
            if ((*(desc->buffer) = OPENSSL_malloc(desc->maxlen)) == NULL)
                return 0;
            if (desc->currlen > 0) {
                if (!ossl_assert(desc->sbuffer != NULL))
                    return 0;
                memcpy(*(desc->buffer), desc->sbuffer, desc->currlen);
            }
            desc->sbuffer = NULL;
        } else {
            char *tmpbuf;

            tmpbuf = OPENSSL_realloc(*(desc->buffer), desc->maxlen);
            if (tmpbuf == NULL)
                return 0;
            *(desc->buffer) = tmpbuf;
        }
    }

    if (desc->currlen < desc->maxlen) {
        if (desc->sbuffer)
            (desc->sbuffer)[(desc->currlen)++] = (char)c;
        else
            (*(desc->buffer))[(desc->currlen)++] = (char)c;
    }

    if (desc->pos < LLONG_MAX)
        desc->pos++;

    return 1;
}

/**
 * Checks if we reached an end of a non-extandable buffer (sbuffer) and updates
 * desc->pos by adding the amount of bytes left if the end of buffer is reached.
 * That allow quickly short-circuiting long loops with unreasonably long paddings
 * and widths.
 *
 * @param desc Pointer to a print descriptor.
 * @param left Bytes left in the chunk caller is currently processing.
 * @return 0 - end of buffer is reached, no need to continue;
 *         1 - there is still space in the buffer, the caller may continue to
 *         try to output bytes in the buffer with doapr_outch().
 */
static int eob_ok(struct pr_desc *desc, long long left)
{
    /*
     * desc->buffer is auto-sizeable, so we are never supposed to reach the end
     * of it.
     */
    if (desc->buffer != NULL)
        return 1;

    if (desc->currlen >= desc->maxlen) {
        if (left > 0) {
            if (desc->pos < LLONG_MAX - left) {
                desc->pos += left;
            } else {
                desc->pos = LLONG_MAX;
            }
        }

        return 0;
    }

    return 1;
}

/***************************************************************************/

int BIO_printf(BIO *bio, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);

    ret = BIO_vprintf(bio, format, args);

    va_end(args);
    return ret;
}

int BIO_vprintf(BIO *bio, const char *format, va_list args)
{
    int ret;
    size_t retlen;
    char hugebuf[1024 * 2];     /* Was previously 10k, which is unreasonable
                                 * in small-stack environments, like threads
                                 * or DOS programs. */
    char *hugebufp = hugebuf;
    size_t hugebufsize = sizeof(hugebuf);
    char *dynbuf = NULL;
    int ignored;

    dynbuf = NULL;
    if (!_dopr(&hugebufp, &dynbuf, &hugebufsize, &retlen, &ignored, format,
                args)) {
        OPENSSL_free(dynbuf);
        return -1;
    }
    if (dynbuf) {
        ret = BIO_write(bio, dynbuf, (int)retlen);
        OPENSSL_free(dynbuf);
    } else {
        ret = BIO_write(bio, hugebuf, (int)retlen);
    }
    return ret;
}

/*
 * As snprintf is not available everywhere, we provide our own
 * implementation. This function has nothing to do with BIOs, but it's
 * closely related to BIO_printf, and we need *some* name prefix ... (XXX the
 * function should be renamed, but to what?)
 */
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);

    ret = BIO_vsnprintf(buf, n, format, args);

    va_end(args);
    return ret;
}

int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
{
    size_t retlen;
    int truncated;

    if (!_dopr(&buf, NULL, &n, &retlen, &truncated, format, args))
        return -1;

    if (truncated)
        /*
         * In case of truncation, return -1 like traditional snprintf.
         * (Current drafts for ISO/IEC 9899 say snprintf should return the
         * number of characters that would have been written, had the buffer
         * been large enough.)
         */
        return -1;
    return (retlen <= INT_MAX) ? (int)retlen : -1;
}
