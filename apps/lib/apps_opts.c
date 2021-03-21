/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include "apps_opts.h"
#include <string.h>

static unsigned long nmflag = 0;
static char nmflag_set = 0;

static int set_table_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl)
{
    char c;
    const NAME_EX_TBL *ptbl;
    c = arg[0];

    if (c == '-') {
        c = 0;
        arg++;
    } else if (c == '+') {
        c = 1;
        arg++;
    } else {
        c = 1;
    }

    for (ptbl = in_tbl; ptbl->name; ptbl++) {
        if (strcasecmp(arg, ptbl->name) == 0) {
            *flags &= ~ptbl->mask;
            if (c)
                *flags |= ptbl->flag;
            else
                *flags &= ~ptbl->flag;
            return 1;
        }
    }
    return 0;
}

int set_multi_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl)
{
    STACK_OF(CONF_VALUE) *vals;
    CONF_VALUE *val;
    int i, ret = 1;
    if (!arg)
        return 0;
    vals = X509V3_parse_list(arg);
    for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
        val = sk_CONF_VALUE_value(vals, i);
        if (!set_table_opts(flags, val->name, in_tbl))
            ret = 0;
    }
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    return ret;
}

int set_name_ex(unsigned long *flags, const char *arg)
{
    static const NAME_EX_TBL ex_tbl[] = {
        {"esc_2253", ASN1_STRFLGS_ESC_2253, 0},
        {"esc_2254", ASN1_STRFLGS_ESC_2254, 0},
        {"esc_ctrl", ASN1_STRFLGS_ESC_CTRL, 0},
        {"esc_msb", ASN1_STRFLGS_ESC_MSB, 0},
        {"use_quote", ASN1_STRFLGS_ESC_QUOTE, 0},
        {"utf8", ASN1_STRFLGS_UTF8_CONVERT, 0},
        {"ignore_type", ASN1_STRFLGS_IGNORE_TYPE, 0},
        {"show_type", ASN1_STRFLGS_SHOW_TYPE, 0},
        {"dump_all", ASN1_STRFLGS_DUMP_ALL, 0},
        {"dump_nostr", ASN1_STRFLGS_DUMP_UNKNOWN, 0},
        {"dump_der", ASN1_STRFLGS_DUMP_DER, 0},
        {"compat", XN_FLAG_COMPAT, 0xffffffffL},
        {"sep_comma_plus", XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_MASK},
        {"sep_comma_plus_space", XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK},
        {"sep_semi_plus_space", XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SEP_MASK},
        {"sep_multiline", XN_FLAG_SEP_MULTILINE, XN_FLAG_SEP_MASK},
        {"dn_rev", XN_FLAG_DN_REV, 0},
        {"nofname", XN_FLAG_FN_NONE, XN_FLAG_FN_MASK},
        {"sname", XN_FLAG_FN_SN, XN_FLAG_FN_MASK},
        {"lname", XN_FLAG_FN_LN, XN_FLAG_FN_MASK},
        {"align", XN_FLAG_FN_ALIGN, 0},
        {"oid", XN_FLAG_FN_OID, XN_FLAG_FN_MASK},
        {"space_eq", XN_FLAG_SPC_EQ, 0},
        {"dump_unknown", XN_FLAG_DUMP_UNKNOWN_FIELDS, 0},
        {"RFC2253", XN_FLAG_RFC2253, 0xffffffffL},
        {"oneline", XN_FLAG_ONELINE, 0xffffffffL},
        {"multiline", XN_FLAG_MULTILINE, 0xffffffffL},
        {"ca_default", XN_FLAG_MULTILINE, 0xffffffffL},
        {NULL, 0, 0}
    };
    if (set_multi_opts(flags, arg, ex_tbl) == 0)
        return 0;
    if (*flags != XN_FLAG_COMPAT
        && (*flags & XN_FLAG_SEP_MASK) == 0)
        *flags |= XN_FLAG_SEP_CPLUS_SPC;
    return 1;
}

int set_nameopt(const char *arg)
{
    int ret = set_name_ex(&nmflag, arg);

    if (ret)
        nmflag_set = 1;

    return ret;
}

unsigned long get_nameopt(void)
{
    return (nmflag_set) ? nmflag : XN_FLAG_ONELINE;
}


