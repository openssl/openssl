/*
 * Copyright 1999-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

ASN1_SEQUENCE(TIME_SPEC_ABSOLUTE) = {
    ASN1_EXP_OPT(TIME_SPEC_ABSOLUTE, startTime, ASN1_GENERALIZEDTIME, 0),
    ASN1_EXP_OPT(TIME_SPEC_ABSOLUTE, endTime, ASN1_GENERALIZEDTIME, 1),
} ASN1_SEQUENCE_END(TIME_SPEC_ABSOLUTE)

ASN1_SEQUENCE(DAY_TIME) = {
    ASN1_EXP_OPT(DAY_TIME, hour, ASN1_INTEGER, 0),
    ASN1_EXP_OPT(DAY_TIME, minute, ASN1_INTEGER, 1),
    ASN1_EXP_OPT(DAY_TIME, second, ASN1_INTEGER, 2),
} ASN1_SEQUENCE_END(DAY_TIME)

ASN1_SEQUENCE(DAY_TIME_BAND) = {
    ASN1_EXP_OPT(DAY_TIME_BAND, startDayTime, DAY_TIME, 0),
    ASN1_EXP_OPT(DAY_TIME_BAND, endDayTime, DAY_TIME, 1),
} ASN1_SEQUENCE_END(DAY_TIME_BAND)

ASN1_CHOICE(NAMED_DAY) = {
    ASN1_SET_OF(NAMED_DAY, choice.intNamedDays, ASN1_ENUMERATED),
    ASN1_SIMPLE(NAMED_DAY, choice.bitNamedDays, ASN1_BIT_STRING),
} ASN1_CHOICE_END(NAMED_DAY)

ASN1_CHOICE(TIME_SPEC_X_DAY_OF) = {
    ASN1_EXP(TIME_SPEC_X_DAY_OF, choice.first, NAMED_DAY, 1),
    ASN1_EXP(TIME_SPEC_X_DAY_OF, choice.second, NAMED_DAY, 2),
    ASN1_EXP(TIME_SPEC_X_DAY_OF, choice.third, NAMED_DAY, 3),
    ASN1_EXP(TIME_SPEC_X_DAY_OF, choice.fourth, NAMED_DAY, 4),
    ASN1_EXP(TIME_SPEC_X_DAY_OF, choice.fifth, NAMED_DAY, 5),
} ASN1_CHOICE_END(TIME_SPEC_X_DAY_OF)

ASN1_CHOICE(TIME_SPEC_DAY) = {
    ASN1_SET_OF(TIME_SPEC_DAY, choice.intDay, ASN1_INTEGER),
    ASN1_SIMPLE(TIME_SPEC_DAY, choice.bitDay, ASN1_BIT_STRING),
    ASN1_SIMPLE(TIME_SPEC_DAY, choice.dayOf, TIME_SPEC_X_DAY_OF),
} ASN1_CHOICE_END(TIME_SPEC_DAY)

ASN1_CHOICE(TIME_SPEC_WEEKS) = {
    ASN1_SIMPLE(TIME_SPEC_WEEKS, choice.allWeeks, ASN1_NULL),
    ASN1_SET_OF(TIME_SPEC_WEEKS, choice.intWeek, ASN1_INTEGER),
    ASN1_SIMPLE(TIME_SPEC_WEEKS, choice.bitWeek, ASN1_BIT_STRING),
} ASN1_CHOICE_END(TIME_SPEC_WEEKS)

ASN1_CHOICE(TIME_SPEC_MONTH) = {
    ASN1_SIMPLE(TIME_SPEC_MONTH, choice.allMonths, ASN1_NULL),
    ASN1_SET_OF(TIME_SPEC_MONTH, choice.intMonth, ASN1_INTEGER),
    ASN1_SIMPLE(TIME_SPEC_MONTH, choice.bitMonth, ASN1_BIT_STRING),
} ASN1_CHOICE_END(TIME_SPEC_MONTH)

ASN1_SEQUENCE(TIME_PERIOD) = {
    ASN1_EXP_SET_OF_OPT(TIME_PERIOD, timesOfDay, DAY_TIME_BAND, 0),
    ASN1_EXP_OPT(TIME_PERIOD, days, TIME_SPEC_DAY, 1),
    ASN1_EXP_OPT(TIME_PERIOD, weeks, TIME_SPEC_WEEKS, 2),
    ASN1_EXP_OPT(TIME_PERIOD, months, TIME_SPEC_MONTH, 3),
    ASN1_EXP_SET_OF_OPT(TIME_PERIOD, years, ASN1_INTEGER, 4),
} ASN1_SEQUENCE_END(TIME_PERIOD)

ASN1_CHOICE(TIME_SPEC_TIME) = {
    ASN1_SIMPLE(TIME_SPEC_TIME, choice.absolute, TIME_SPEC_ABSOLUTE),
    ASN1_SET_OF(TIME_SPEC_TIME, choice.periodic, TIME_PERIOD)
} ASN1_CHOICE_END(TIME_SPEC_TIME)

ASN1_SEQUENCE(TIME_SPEC) = {
    ASN1_SIMPLE(TIME_SPEC, time, TIME_SPEC_TIME),
    ASN1_OPT(TIME_SPEC, notThisTime, ASN1_FBOOLEAN),
    ASN1_OPT(TIME_SPEC, timeZone, ASN1_INTEGER),
} ASN1_SEQUENCE_END(TIME_SPEC)

IMPLEMENT_ASN1_FUNCTIONS(TIME_SPEC_ABSOLUTE)
IMPLEMENT_ASN1_FUNCTIONS(TIME_SPEC_TIME)
IMPLEMENT_ASN1_FUNCTIONS(TIME_SPEC)

static int i2r_TIME_SPEC_ABSOLUTE(X509V3_EXT_METHOD *method,
                                  TIME_SPEC_ABSOLUTE *time,
                                  BIO *out, int indent)
{
    if (time->startTime != NULL && time->endTime != NULL) {
        if (!BIO_puts(out, "Any time between ")) {
            return 0;
        }
        if (!ossl_asn1_time_print_ex(out, time->startTime, 0)) {
            return 0;
        }
        if (!BIO_puts(out, " and ")) {
            return 0;
        }
        if (!ossl_asn1_time_print_ex(out, time->endTime, 0)) {
            return 0;
        }
    } else if (time->startTime != NULL) {
        if (!BIO_puts(out, "Any time after ")) {
            return 0;
        }
        if (!ossl_asn1_time_print_ex(out, time->startTime, 0)) {
            return 0;
        }
        BIO_printf(out, "%.*s", time->startTime->length, time->startTime->data);
    } else if (time->endTime != NULL) {
        if (!BIO_puts(out, "Any time until ")) {
            return 0;
        }
        if (!ossl_asn1_time_print_ex(out, time->endTime, 0)) {
            return 0;
        }
    } else { // Invalid: there must be SOME time specified.
        return BIO_puts(out, "INVALID (EMPTY)");
    }
    return 1;
}

static int i2r_DAY_TIME(X509V3_EXT_METHOD *method,
                        DAY_TIME *dt,
                        BIO *out, int indent)
{
    int64_t h;
    int64_t m;
    int64_t s;

    if (!ASN1_INTEGER_get_int64(&h, dt->hour)) {
        return 0;
    }
    if (dt->minute && !ASN1_INTEGER_get_int64(&m, dt->minute)) {
        return 0;
    }
    if (dt->minute && !ASN1_INTEGER_get_int64(&s, dt->second)) {
        return 0;
    }
    return BIO_printf(out, "%02ld:%02ld:%02ld", h, m, s);
}

static int i2r_DAY_TIME_BAND(X509V3_EXT_METHOD *method,
                             DAY_TIME_BAND *band,
                             BIO *out, int indent)
{
    if (band->startDayTime) {
        if (!i2r_DAY_TIME(method, band->startDayTime, out, indent)) {
            return 0;
        }
    } else {
        if (!BIO_puts(out, "00:00:00")) {
            return 0;
        }
    }
    if (!BIO_puts(out, " - ")) {
        return 0;
    }
    if (band->endDayTime) {
        if (!i2r_DAY_TIME(method, band->endDayTime, out, indent)) {
            return 0;
        }
    } else {
        if (!BIO_puts(out, "23:59:59")) {
            return 0;
        }
    }
    return 1;
}

static int print_int_month (BIO *out, int64_t month) {
    switch (month) {
        case (TIME_SPEC_INT_MONTH_JAN): return BIO_puts(out, "JAN");
        case (TIME_SPEC_INT_MONTH_FEB): return BIO_puts(out, "FEB");
        case (TIME_SPEC_INT_MONTH_MAR): return BIO_puts(out, "MAR");
        case (TIME_SPEC_INT_MONTH_APR): return BIO_puts(out, "APR");
        case (TIME_SPEC_INT_MONTH_MAY): return BIO_puts(out, "MAY");
        case (TIME_SPEC_INT_MONTH_JUN): return BIO_puts(out, "JUN");
        case (TIME_SPEC_INT_MONTH_JUL): return BIO_puts(out, "JUL");
        case (TIME_SPEC_INT_MONTH_AUG): return BIO_puts(out, "AUG");
        case (TIME_SPEC_INT_MONTH_SEP): return BIO_puts(out, "SEP");
        case (TIME_SPEC_INT_MONTH_OCT): return BIO_puts(out, "OCT");
        case (TIME_SPEC_INT_MONTH_NOV): return BIO_puts(out, "NOV");
        case (TIME_SPEC_INT_MONTH_DEC): return BIO_puts(out, "DEC");
        default: return 0;
    }
    return 0;
}

static int print_bit_month (BIO *out, ASN1_BIT_STRING *bs) {
    int i;
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_JAN)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "JAN")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_FEB)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "FEB")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_MAR)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "MAR")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_APR)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "APR")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_MAY)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "MAY")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_JUN)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "JUN")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_JUL)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "JUL")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_AUG)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "AUG")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_SEP)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "SEP")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_OCT)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "OCT")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_NOV)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "NOV")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_MONTH_DEC)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "DEC")) {
            return 0;
        }
    }
    return 1;
}

/* It might seem like you could just print the bits of the
string numerically, but the fifth bit has the special meaning
of "the final week" imputed to it by the text of ITU Rec. X.520. */
static int print_bit_week (BIO *out, ASN1_BIT_STRING *bs) {
    int i;
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_WEEKS_1)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "first")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_WEEKS_2)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "second")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_WEEKS_3)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "third")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_WEEKS_4)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "fourth")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_BIT_WEEKS_5)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "final")) {
            return 0;
        }
    }
    return 1;
}

static int print_day_of_week (BIO *out, ASN1_BIT_STRING *bs) {
    int i;
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_DAY_BIT_SUN)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "SUN")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_DAY_BIT_MON)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "MON")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_DAY_BIT_TUE)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "TUE")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_DAY_BIT_WED)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "WED")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_DAY_BIT_THU)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "THU")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_DAY_BIT_FRI)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "FRI")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, TIME_SPEC_DAY_BIT_SAT)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "SAT")) {
            return 0;
        }
    }
    return 1;
}

static int print_int_day_of_week (BIO *out, int64_t month) {
    switch (month) {
        case (TIME_SPEC_DAY_INT_SUN): return BIO_puts(out, "SUN");
        case (TIME_SPEC_DAY_INT_MON): return BIO_puts(out, "MON");
        case (TIME_SPEC_DAY_INT_TUE): return BIO_puts(out, "TUE");
        case (TIME_SPEC_DAY_INT_WED): return BIO_puts(out, "WED");
        case (TIME_SPEC_DAY_INT_THU): return BIO_puts(out, "THU");
        case (TIME_SPEC_DAY_INT_FRI): return BIO_puts(out, "FRI");
        case (TIME_SPEC_DAY_INT_SAT): return BIO_puts(out, "SAT");
        default: return 0;
    }
    return 0;
}

static int print_int_named_day (BIO *out, int64_t nd) {
    switch (nd) {
        case (NAMED_DAY_INT_SUN): return BIO_puts(out, "SUN");
        case (NAMED_DAY_INT_MON): return BIO_puts(out, "MON");
        case (NAMED_DAY_INT_TUE): return BIO_puts(out, "TUE");
        case (NAMED_DAY_INT_WED): return BIO_puts(out, "WED");
        case (NAMED_DAY_INT_THU): return BIO_puts(out, "THU");
        case (NAMED_DAY_INT_FRI): return BIO_puts(out, "FRI");
        case (NAMED_DAY_INT_SAT): return BIO_puts(out, "SAT");
        default: return 0;
    }
    return 0;
}

static int print_bit_named_day (BIO *out, ASN1_BIT_STRING *bs) {
    int i = 0;
    if (ASN1_BIT_STRING_get_bit(bs, NAMED_DAY_BIT_SUN)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "SUN")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, NAMED_DAY_BIT_MON)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "MON")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, NAMED_DAY_BIT_TUE)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "TUE")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, NAMED_DAY_BIT_WED)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "WED")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, NAMED_DAY_BIT_THU)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "THU")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, NAMED_DAY_BIT_FRI)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "FRI")) {
            return 0;
        }
    }
    if (ASN1_BIT_STRING_get_bit(bs, NAMED_DAY_BIT_SAT)) {
        if (i > 0 && !BIO_puts(out, ", ")) {
            return 0;
        }
        i++;
        if (!BIO_puts(out, "SAT")) {
            return 0;
        }
    }
    return 1;
}

static int i2r_PERIOD(X509V3_EXT_METHOD *method,
                      TIME_PERIOD *p,
                      BIO *out, int indent)
{
    if (BIO_printf(out, "%*sPeriod:\n", indent, "") <= 0) {
        return 0;
    }
    int i;
    if (p->timesOfDay) {
        DAY_TIME_BAND *band;
        BIO_printf(out, "%*sDaytime bands:\n", indent + 4, "");
        for (i = 0; i < sk_DAY_TIME_BAND_num(p->timesOfDay); i++) {
            band = sk_DAY_TIME_BAND_value(p->timesOfDay, i);
            if (BIO_printf(out, "%*s", indent + 8, "") <= 0) {
                return 0;
            }
            if (!i2r_DAY_TIME_BAND(method, band, out, indent + 8)) {
                return 0;
            }
            if (!BIO_puts(out, "\n")) {
                return 0;
            }
        }
        if (!BIO_puts(out, "\n")) {
            return 0;
        }
    }
    if (p->days) {
        if (p->days->type == TIME_SPEC_DAY_TYPE_INT) {
            if (p->weeks != NULL) {
                if (!BIO_printf(out, "%*sDays of the week: ", indent + 4, "")) {
                    return 0;
                }
            } else if (p->months != NULL) {
                if (!BIO_printf(out, "%*sDays of the month: ", indent + 4, "")) {
                    return 0;
                }
            } else if (p->years != NULL) {
                if (!BIO_printf(out, "%*sDays of the year: ", indent + 4, "")) {
                    return 0;
                }
            }
        } else {
            if (!BIO_printf(out, "%*sDays: ", indent + 4, "")) {
                return 0;
            }
        }

        switch (p->days->type) {
            case (TIME_SPEC_DAY_TYPE_INT): {
                for (i = 0; i < sk_ASN1_INTEGER_num(p->days->choice.intDay); i++) {
                    ASN1_INTEGER *big_day;
                    int64_t day;

                    big_day = sk_ASN1_INTEGER_value(p->days->choice.intDay, i);
                    if (!ASN1_INTEGER_get_int64(&day, big_day)) {
                        return 0;
                    }
                    if (i > 0 && !BIO_puts(out, ", ")) {
                        return 0;
                    }
                    // If weeks is defined, then print day of week by name.
                    if (p->weeks != NULL) {
                        if (!print_int_day_of_week(out, day)) {
                            return 0;
                        }
                    } else if (!BIO_printf(out, "%ld", day)) {
                        return 0;
                    }
                }
                break;
            }
            case (TIME_SPEC_DAY_TYPE_BIT): {
                if (!print_day_of_week(out, p->days->choice.bitDay)) {
                    return 0;
                }
                break;
            }
            case (TIME_SPEC_DAY_TYPE_DAY_OF): {
                NAMED_DAY *nd;
                switch (p->days->choice.dayOf->type) {
                    case (TIME_SPEC_X_DAY_OF_FIRST): {
                        if (!BIO_puts(out, "FIRST ")) {
                            return 0;
                        }
                        nd = p->days->choice.dayOf->choice.first;
                        break;
                    }
                    case (TIME_SPEC_X_DAY_OF_SECOND): {
                        if (!BIO_puts(out, "SECOND ")) {
                            return 0;
                        }
                        nd = p->days->choice.dayOf->choice.second;
                        break;
                    }
                    case (TIME_SPEC_X_DAY_OF_THIRD): {
                        if (!BIO_puts(out, "THIRD ")) {
                            return 0;
                        }
                        nd = p->days->choice.dayOf->choice.third;
                        break;
                    }
                    case (TIME_SPEC_X_DAY_OF_FOURTH): {
                        if (!BIO_puts(out, "FOURTH ")) {
                            return 0;
                        }
                        nd = p->days->choice.dayOf->choice.fourth;
                        break;
                    }
                    case (TIME_SPEC_X_DAY_OF_FIFTH): {
                        if (!BIO_puts(out, "FIFTH ")) {
                            return 0;
                        }
                        nd = p->days->choice.dayOf->choice.fifth;
                        break;
                    }
                    default: return 0;
                }
                switch (nd->type) {
                    case (NAMED_DAY_TYPE_INT): {
                        int64_t day;

                        if (!ASN1_INTEGER_get_int64(&day, nd->choice.intNamedDays)) {
                            return 0;
                        }
                        if (!print_int_named_day(out, day)) {
                            return 0;
                        }
                        break;
                    }
                    case (NAMED_DAY_TYPE_BIT): {
                        if (!print_bit_named_day(out, nd->choice.bitNamedDays)) {
                            return 0;
                        }
                        break;
                    }
                    default: return 0;
                }
                break;
            }
            default: return 0;   
        }
        if (!BIO_puts(out, "\n")) {
            return 0;
        }
    }
    if (p->weeks) {
        if (p->weeks->type == TIME_SPEC_WEEKS_TYPE_INT) {
            if (p->months != NULL) {
                if (!BIO_printf(out, "%*sWeeks of the month: ", indent + 4, "")) {
                    return 0;
                }
            } else if (p->years != NULL) {
                if (!BIO_printf(out, "%*sWeeks of the year: ", indent + 4, "")) {
                    return 0;
                }
            }
        } else {
            if (!BIO_printf(out, "%*sWeeks: ", indent + 4, "")) {
                return 0;
            }
        }

        switch (p->weeks->type) {
            case (TIME_SPEC_WEEKS_TYPE_ALL): {
                if (!BIO_puts(out, "ALL")) {
                    return 0;
                }
                break;
            }
            case (TIME_SPEC_WEEKS_TYPE_INT): {
                for (i = 0; i < sk_ASN1_INTEGER_num(p->weeks->choice.intWeek); i++) {
                    ASN1_INTEGER *big_week;
                    int64_t week;

                    big_week = sk_ASN1_INTEGER_value(p->weeks->choice.intWeek, i);
                    if (!ASN1_INTEGER_get_int64(&week, big_week)) {
                        return 0;
                    }
                    if (i > 0 && !BIO_puts(out, ", ")) {
                        return 0;
                    }
                    if (!BIO_printf(out, "%ld", week)) {
                        return 0;
                    }
                }
                break;
            }
            case (TIME_SPEC_WEEKS_TYPE_BIT): {
                if (!print_bit_week(out, p->weeks->choice.bitWeek)) {
                    return 0;
                }
                break;
            }
            default: return 0;    
        }
        if (!BIO_puts(out, "\n")) {
            return 0;
        }
    }
    if (p->months) {
        if (!BIO_printf(out, "%*sMonths: ", indent + 4, "")) {
            return 0;
        }
        switch (p->months->type) {
            case (TIME_SPEC_MONTH_TYPE_ALL): {
                if (!BIO_puts(out, "ALL")) {
                    return 0;
                }
                break;
            }
            case (TIME_SPEC_MONTH_TYPE_INT): {
                for (i = 0; i < sk_ASN1_INTEGER_num(p->months->choice.intMonth); i++) {
                    ASN1_INTEGER *big_month;
                    int64_t month;

                    big_month = sk_ASN1_INTEGER_value(p->months->choice.intMonth, i);
                    if (!ASN1_INTEGER_get_int64(&month, big_month)) {
                        return 0;
                    }
                    if (i > 0 && !BIO_puts(out, ", ")) {
                        return 0;
                    }
                    if (!print_int_month(out, month)) {
                        return 0;
                    }
                }
                break;
            }
            case (TIME_SPEC_MONTH_TYPE_BIT): {
                if (!print_bit_month(out, p->months->choice.bitMonth)) {
                    return 0;
                }
                break;
            }
            default: return 0;   
        }
        if (!BIO_puts(out, "\n")) {
            return 0;
        }
    }
    if (p->years) {
        if (!BIO_printf(out, "%*sYears: ", indent + 4, "")) {
            return 0;
        }
        for (i = 0; i < sk_ASN1_INTEGER_num(p->years); i++) {
            ASN1_INTEGER *big_year;
            int64_t year;

            big_year = sk_ASN1_INTEGER_value(p->years, i);
            if (!ASN1_INTEGER_get_int64(&year, big_year)) {
                return 0;
            }
            if (i > 0 && !BIO_puts(out, ", ")) {
                return 0;
            }
            if (!BIO_printf(out, "%04ld", year)) {
                return 0;
            }
        }
    }
    return 1;
}

static int i2r_TIME_SPEC_TIME(X509V3_EXT_METHOD *method,
                              TIME_SPEC_TIME *time,
                              BIO *out, int indent)
{
    TIME_PERIOD *tp;
    int i;
    switch (time->type) {
    case (TIME_SPEC_TIME_TYPE_ABSOLUTE): {
        if (BIO_printf(out, "%*sAbsolute: ", indent, "") <= 0) {
            return 0;
        }
        if (i2r_TIME_SPEC_ABSOLUTE(method, time->choice.absolute, out, indent + 4) <= 0) {
            return 0;
        }
        return BIO_puts(out, "\n");
    }
    case (TIME_SPEC_TIME_TYPE_PERIODIC): {
        if (BIO_printf(out, "%*sPeriodic:\n", indent, "") <= 0) {
            return 0;
        }
        for (i = 0; i < sk_TIME_PERIOD_num(time->choice.periodic); i++) {
            if (i > 0 && !BIO_puts(out, "\n")) {
                return 0;
            }
            tp = sk_TIME_PERIOD_value(time->choice.periodic, i);
            if (!i2r_PERIOD(method, tp, out, indent + 4)) {
                return 0;
            }
        }
        return BIO_puts(out, "\n");
    }
    default: return 0;
    }
    return 0;
}

static int i2r_TIME_SPEC(X509V3_EXT_METHOD *method,
                         TIME_SPEC *time,
                         BIO *out, int indent)
{
    if (time->timeZone) {
        int64_t tz;
        if (ASN1_INTEGER_get_int64(&tz, time->timeZone) != 1) {
            return 0;
        }
        if (BIO_printf(out, "%*sTimezone: UTC%+03ld:00\n", indent, "", tz) <= 0) {
            return 0;
        }
    }
    if (time->notThisTime > 0) {
        if (BIO_printf(out, "%*sNOT this time:\n", indent, "") <= 0) {
            return 0;
        }
    } else if (BIO_printf(out, "%*sTime:\n", indent, "") <= 0) {
        return 0;
    }
    return i2r_TIME_SPEC_TIME(method, time->time, out, indent + 4);
}

const X509V3_EXT_METHOD ossl_v3_time_specification = {
    NID_time_specification, X509V3_EXT_MULTILINE,
    ASN1_ITEM_ref(TIME_SPEC),
    0, 0, 0, 0,
    0, 0,
    0,
    0,
    (X509V3_EXT_I2R)i2r_TIME_SPEC,
    NULL,
    NULL
};
