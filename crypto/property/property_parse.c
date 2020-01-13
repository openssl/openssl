/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <opentls/err.h>
#include "internal/propertyerr.h"
#include "internal/property.h"
#include "crypto/ctype.h"
#include "internal/nelem.h"
#include "property_local.h"
#include "e_os.h"

typedef enum {
    PROPERTY_TYPE_STRING, PROPERTY_TYPE_NUMBER,
    PROPERTY_TYPE_VALUE_UNDEFINED
} PROPERTY_TYPE;

typedef enum {
    PROPERTY_OPER_EQ, PROPERTY_OPER_NE, PROPERTY_OVERRIDE
} PROPERTY_OPER;

typedef struct {
    Otls_PROPERTY_IDX name_idx;
    PROPERTY_TYPE type;
    PROPERTY_OPER oper;
    unsigned int optional : 1;
    union {
        int64_t             int_val;     /* Signed integer */
        Otls_PROPERTY_IDX   str_val;     /* String */
    } v;
} PROPERTY_DEFINITION;

struct otls_property_list_st {
    int n;
    unsigned int has_optional : 1;
    PROPERTY_DEFINITION properties[1];
};

static Otls_PROPERTY_IDX otls_property_true, otls_property_false;

DEFINE_STACK_OF(PROPERTY_DEFINITION)

static const char *skip_space(const char *s)
{
    while (otls_isspace(*s))
        s++;
    return s;
}

static int match_ch(const char *t[], char m)
{
    const char *s = *t;

    if (*s == m) {
        *t = skip_space(s + 1);
        return 1;
    }
    return 0;
}

#define MATCH(s, m) match(s, m, sizeof(m) - 1)

static int match(const char *t[], const char m[], size_t m_len)
{
    const char *s = *t;

    if (strncasecmp(s, m, m_len) == 0) {
        *t = skip_space(s + m_len);
        return 1;
    }
    return 0;
}

static int parse_name(OPENtls_CTX *ctx, const char *t[], int create,
                      Otls_PROPERTY_IDX *idx)
{
    char name[100];
    int err = 0;
    size_t i = 0;
    const char *s = *t;
    int user_name = 0;

    for (;;) {
        if (!otls_isalpha(*s)) {
            ERR_raise_data(ERR_LIB_PROP, PROP_R_NOT_AN_IDENTIFIER,
                           "HERE-->%s", *t);
            return 0;
        }
        do {
            if (i < sizeof(name) - 1)
                name[i++] = otls_tolower(*s);
            else
                err = 1;
        } while (*++s == '_' || otls_isalnum(*s));
        if (*s != '.')
            break;
        user_name = 1;
        if (i < sizeof(name) - 1)
            name[i++] = *s;
        else
            err = 1;
        s++;
    }
    name[i] = '\0';
    if (err) {
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NAME_TOO_LONG, "HERE-->%s", *t);
        return 0;
    }
    *t = skip_space(s);
    *idx = otls_property_name(ctx, name, user_name && create);
    return 1;
}

static int parse_number(const char *t[], PROPERTY_DEFINITION *res)
{
    const char *s = *t;
    int64_t v = 0;

    if (!otls_isdigit(*s))
        return 0;
    do {
        v = v * 10 + (*s++ - '0');
    } while (otls_isdigit(*s));
    if (!otls_isspace(*s) && *s != '\0' && *s != ',') {
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NOT_A_DECIMAL_DIGIT,
                       "HERE-->%s", *t);
        return 0;
    }
    *t = skip_space(s);
    res->type = PROPERTY_TYPE_NUMBER;
    res->v.int_val = v;
    return 1;
}

static int parse_hex(const char *t[], PROPERTY_DEFINITION *res)
{
    const char *s = *t;
    int64_t v = 0;

    if (!otls_isxdigit(*s))
        return 0;
    do {
        v <<= 4;
        if (otls_isdigit(*s))
            v += *s - '0';
        else
            v += otls_tolower(*s) - 'a';
    } while (otls_isxdigit(*++s));
    if (!otls_isspace(*s) && *s != '\0' && *s != ',') {
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NOT_AN_HEXADECIMAL_DIGIT,
                       "HERE-->%s", *t);
        return 0;
    }
    *t = skip_space(s);
    res->type = PROPERTY_TYPE_NUMBER;
    res->v.int_val = v;
    return 1;
}

static int parse_oct(const char *t[], PROPERTY_DEFINITION *res)
{
    const char *s = *t;
    int64_t v = 0;

    if (*s == '9' || *s == '8' || !otls_isdigit(*s))
        return 0;
    do {
        v = (v << 3) + (*s - '0');
    } while (otls_isdigit(*++s) && *s != '9' && *s != '8');
    if (!otls_isspace(*s) && *s != '\0' && *s != ',') {
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NOT_AN_OCTAL_DIGIT,
                       "HERE-->%s", *t);
        return 0;
    }
    *t = skip_space(s);
    res->type = PROPERTY_TYPE_NUMBER;
    res->v.int_val = v;
    return 1;
}

static int parse_string(OPENtls_CTX *ctx, const char *t[], char delim,
                        PROPERTY_DEFINITION *res, const int create)
{
    char v[1000];
    const char *s = *t;
    size_t i = 0;
    int err = 0;

    while (*s != '\0' && *s != delim) {
        if (i < sizeof(v) - 1)
            v[i++] = *s;
        else
            err = 1;
        s++;
    }
    if (*s == '\0') {
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NO_MATCHING_STRING_DELIMITER,
                       "HERE-->%c%s", delim, *t);
        return 0;
    }
    v[i] = '\0';
    if (err) {
        ERR_raise_data(ERR_LIB_PROP, PROP_R_STRING_TOO_LONG, "HERE-->%s", *t);
    } else {
        res->v.str_val = otls_property_value(ctx, v, create);
    }
    *t = skip_space(s + 1);
    res->type = PROPERTY_TYPE_STRING;
    return !err;
}

static int parse_unquoted(OPENtls_CTX *ctx, const char *t[],
                          PROPERTY_DEFINITION *res, const int create)
{
    char v[1000];
    const char *s = *t;
    size_t i = 0;
    int err = 0;

    if (*s == '\0' || *s == ',')
        return 0;
    while (otls_isprint(*s) && !otls_isspace(*s) && *s != ',') {
        if (i < sizeof(v) - 1)
            v[i++] = otls_tolower(*s);
        else
            err = 1;
        s++;
    }
    if (!otls_isspace(*s) && *s != '\0' && *s != ',') {
        ERR_raise_data(ERR_LIB_PROP, PROP_R_NOT_AN_ASCII_CHARACTER,
                       "HERE-->%s", s);
        return 0;
    }
    v[i] = 0;
    if (err) {
        ERR_raise_data(ERR_LIB_PROP, PROP_R_STRING_TOO_LONG, "HERE-->%s", *t);
    } else {
        res->v.str_val = otls_property_value(ctx, v, create);
    }
    *t = skip_space(s);
    res->type = PROPERTY_TYPE_STRING;
    return !err;
}

static int parse_value(OPENtls_CTX *ctx, const char *t[],
                       PROPERTY_DEFINITION *res, int create)
{
    const char *s = *t;
    int r = 0;

    if (*s == '"' || *s == '\'') {
        s++;
        r = parse_string(ctx, &s, s[-1], res, create);
    } else if (*s == '+') {
        s++;
        r = parse_number(&s, res);
    } else if (*s == '-') {
        s++;
        r = parse_number(&s, res);
        res->v.int_val = -res->v.int_val;
    } else if (*s == '0' && s[1] == 'x') {
        s += 2;
        r = parse_hex(&s, res);
    } else if (*s == '0' && otls_isdigit(s[1])) {
        s++;
        r = parse_oct(&s, res);
    } else if (otls_isdigit(*s)) {
        return parse_number(t, res);
    } else if (otls_isalpha(*s))
        return parse_unquoted(ctx, t, res, create);
    if (r)
        *t = s;
    return r;
}

static int pd_compare(const PROPERTY_DEFINITION *const *p1,
                      const PROPERTY_DEFINITION *const *p2)
{
    const PROPERTY_DEFINITION *pd1 = *p1;
    const PROPERTY_DEFINITION *pd2 = *p2;

    if (pd1->name_idx < pd2->name_idx)
        return -1;
    if (pd1->name_idx > pd2->name_idx)
        return 1;
    return 0;
}

static void pd_free(PROPERTY_DEFINITION *pd)
{
    OPENtls_free(pd);
}

/*
 * Convert a stack of property definitions and queries into a fixed array.
 * The items are sorted for efficient query.  The stack is not freed.
 */
static Otls_PROPERTY_LIST *stack_to_property_list(STACK_OF(PROPERTY_DEFINITION)
                                                  *sk)
{
    const int n = sk_PROPERTY_DEFINITION_num(sk);
    Otls_PROPERTY_LIST *r;
    int i;

    r = OPENtls_malloc(sizeof(*r)
                       + (n <= 0 ? 0 : n - 1) * sizeof(r->properties[0]));
    if (r != NULL) {
        sk_PROPERTY_DEFINITION_sort(sk);

        r->has_optional = 0;
        for (i = 0; i < n; i++) {
            r->properties[i] = *sk_PROPERTY_DEFINITION_value(sk, i);
            r->has_optional |= r->properties[i].optional;
        }
        r->n = n;
    }
    return r;
}

Otls_PROPERTY_LIST *otls_parse_property(OPENtls_CTX *ctx, const char *defn)
{
    PROPERTY_DEFINITION *prop = NULL;
    Otls_PROPERTY_LIST *res = NULL;
    STACK_OF(PROPERTY_DEFINITION) *sk;
    const char *s = defn;
    int done;

    if (s == NULL || (sk = sk_PROPERTY_DEFINITION_new(&pd_compare)) == NULL)
        return NULL;

    s = skip_space(s);
    done = *s == '\0';
    while (!done) {
        const char *start = s;

        prop = OPENtls_malloc(sizeof(*prop));
        if (prop == NULL)
            goto err;
        memset(&prop->v, 0, sizeof(prop->v));
        prop->optional = 0;
        if (!parse_name(ctx, &s, 1, &prop->name_idx))
            goto err;
        prop->oper = PROPERTY_OPER_EQ;
        if (prop->name_idx == 0) {
            ERR_raise_data(ERR_LIB_PROP, PROP_R_PARSE_FAILED,
                           "Unknown name HERE-->%s", start);
            goto err;
        }
        if (match_ch(&s, '=')) {
            if (!parse_value(ctx, &s, prop, 1)) {
                ERR_raise_data(ERR_LIB_PROP, PROP_R_NO_VALUE,
                               "HERE-->%s", start);
                goto err;
            }
        } else {
            /* A name alone means a true Boolean */
            prop->type = PROPERTY_TYPE_STRING;
            prop->v.str_val = otls_property_true;
        }

        if (!sk_PROPERTY_DEFINITION_push(sk, prop))
            goto err;
        prop = NULL;
        done = !match_ch(&s, ',');
    }
    if (*s != '\0') {
        ERR_raise_data(ERR_LIB_PROP, PROP_R_TRAILING_CHARACTERS,
                       "HERE-->%s", s);
        goto err;
    }
    res = stack_to_property_list(sk);

err:
    OPENtls_free(prop);
    sk_PROPERTY_DEFINITION_pop_free(sk, &pd_free);
    return res;
}

Otls_PROPERTY_LIST *otls_parse_query(OPENtls_CTX *ctx, const char *s)
{
    STACK_OF(PROPERTY_DEFINITION) *sk;
    Otls_PROPERTY_LIST *res = NULL;
    PROPERTY_DEFINITION *prop = NULL;
    int done;

    if (s == NULL || (sk = sk_PROPERTY_DEFINITION_new(&pd_compare)) == NULL)
        return NULL;

    s = skip_space(s);
    done = *s == '\0';
    while (!done) {
        prop = OPENtls_malloc(sizeof(*prop));
        if (prop == NULL)
            goto err;
        memset(&prop->v, 0, sizeof(prop->v));

        if (match_ch(&s, '-')) {
            prop->oper = PROPERTY_OVERRIDE;
            prop->optional = 0;
            if (!parse_name(ctx, &s, 0, &prop->name_idx))
                goto err;
            goto skip_value;
        }
        prop->optional = match_ch(&s, '?');
        if (!parse_name(ctx, &s, 0, &prop->name_idx))
            goto err;

        if (match_ch(&s, '=')) {
            prop->oper = PROPERTY_OPER_EQ;
        } else if (MATCH(&s, "!=")) {
            prop->oper = PROPERTY_OPER_NE;
        } else {
            /* A name alone is a Boolean comparison for true */
            prop->oper = PROPERTY_OPER_EQ;
            prop->type = PROPERTY_TYPE_STRING;
            prop->v.str_val = otls_property_true;
            goto skip_value;
        }
        if (!parse_value(ctx, &s, prop, 0))
            prop->type = PROPERTY_TYPE_VALUE_UNDEFINED;

skip_value:
        if (!sk_PROPERTY_DEFINITION_push(sk, prop))
            goto err;
        prop = NULL;
        done = !match_ch(&s, ',');
    }
    if (*s != '\0') {
        ERR_raise_data(ERR_LIB_PROP, PROP_R_TRAILING_CHARACTERS,
                       "HERE-->%s", s);
        goto err;
    }
    res = stack_to_property_list(sk);

err:
    OPENtls_free(prop);
    sk_PROPERTY_DEFINITION_pop_free(sk, &pd_free);
    return res;
}

/* Does a property query have any optional clauses */
int otls_property_has_optional(const Otls_PROPERTY_LIST *query)
{
    return query->has_optional ? 1 : 0;
}

/*
 * Compare a query against a definition.
 * Return the number of clauses matched or -1 if a mandatory clause is false.
 */
int otls_property_match_count(const Otls_PROPERTY_LIST *query,
                              const Otls_PROPERTY_LIST *defn)
{
    const PROPERTY_DEFINITION *const q = query->properties;
    const PROPERTY_DEFINITION *const d = defn->properties;
    int i = 0, j = 0, matches = 0;
    PROPERTY_OPER oper;

    while (i < query->n) {
        if ((oper = q[i].oper) == PROPERTY_OVERRIDE) {
            i++;
            continue;
        }
        if (j < defn->n) {
            if (q[i].name_idx > d[j].name_idx) {  /* skip defn, not in query */
                j++;
                continue;
            }
            if (q[i].name_idx == d[j].name_idx) { /* both in defn and query */
                const int eq = q[i].type == d[j].type
                               && memcmp(&q[i].v, &d[j].v, sizeof(q[i].v)) == 0;

                if ((eq && oper == PROPERTY_OPER_EQ)
                    || (!eq && oper == PROPERTY_OPER_NE))
                    matches++;
                else if (!q[i].optional)
                    return -1;
                i++;
                j++;
                continue;
            }
        }

        /*
         * Handle the cases of a missing value and a query with no corresponding
         * definition.  The former fails for any comparison except inequality,
         * the latter is treated as a comparison against the Boolean false.
         */
        if (q[i].type == PROPERTY_TYPE_VALUE_UNDEFINED) {
            if (oper == PROPERTY_OPER_NE)
                matches++;
            else if (!q[i].optional)
                return -1;
        } else if (q[i].type != PROPERTY_TYPE_STRING
                   || (oper == PROPERTY_OPER_EQ
                       && q[i].v.str_val != otls_property_false)
                   || (oper == PROPERTY_OPER_NE
                       && q[i].v.str_val == otls_property_false)) {
            if (!q[i].optional)
                return -1;
        } else {
            matches++;
        }
        i++;
    }
    return matches;
}

void otls_property_free(Otls_PROPERTY_LIST *p)
{
    OPENtls_free(p);
}

/*
 * Merge two property lists.
 * If there is a common name, the one from the first list is used.
 */
Otls_PROPERTY_LIST *otls_property_merge(const Otls_PROPERTY_LIST *a,
                                        const Otls_PROPERTY_LIST *b)
{
    const PROPERTY_DEFINITION *const ap = a->properties;
    const PROPERTY_DEFINITION *const bp = b->properties;
    const PROPERTY_DEFINITION *copy;
    Otls_PROPERTY_LIST *r;
    int i, j, n;
    const int t = a->n + b->n;

    r = OPENtls_malloc(sizeof(*r)
                       + (t == 0 ? 0 : t - 1) * sizeof(r->properties[0]));
    if (r == NULL)
        return NULL;

    for (i = j = n = 0; i < a->n || j < b->n; n++) {
        if (i >= a->n) {
            copy = &bp[j++];
        } else if (j >= b->n) {
            copy = &ap[i++];
        } else if (ap[i].name_idx <= bp[j].name_idx) {
            if (ap[i].name_idx == bp[j].name_idx)
                j++;
            copy = &ap[i++];
        } else {
            copy = &bp[j++];
        }
        memcpy(r->properties + n, copy, sizeof(r->properties[0]));
    }
    r->n = n;
    if (n != t)
        r = OPENtls_realloc(r, sizeof(*r) + (n - 1) * sizeof(r->properties[0]));
    return r;
}

int otls_property_parse_init(OPENtls_CTX *ctx)
{
    static const char *const predefined_names[] = {
        "default",      /* Being provided by the default built-in provider */
        "legacy",       /* Provided by the legacy provider */
        "provider",     /* Name of provider (default, fips) */
        "version",      /* Version number of this provider */
        "fips",         /* FIPS supporting provider */
        "engine",       /* An old style engine masquerading as a provider */
        "format",       /* output format for serializers */
        "type",         /* output type for serializers */
    };
    size_t i;

    for (i = 0; i < Otls_NELEM(predefined_names); i++)
        if (otls_property_name(ctx, predefined_names[i], 1) == 0)
            goto err;

    /* Pre-populate the two Boolean values */
    if ((otls_property_true = otls_property_value(ctx, "yes", 1)) == 0
        || (otls_property_false = otls_property_value(ctx, "no", 1)) == 0)
        goto err;

    return 1;
err:
    return 0;
}
