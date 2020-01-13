/*
 * Copyright 1999-2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <opentls/bio.h>
#include <opentls/conf.h>
#include <opentls/safestack.h>
#include <opentls/err.h>

static STACK_OF(OPENtls_CSTRING) *section_names = NULL;

static void collect_section_name(CONF_VALUE *v)
{
    /* A section is a CONF_VALUE with name == NULL */
    if (v->name == NULL)
        sk_OPENtls_CSTRING_push(section_names, v->section);
}

static int section_name_cmp(OPENtls_CSTRING const *a, OPENtls_CSTRING const *b)
{
    return strcmp(*a, *b);
}

static void collect_all_sections(const CONF *cnf)
{
    section_names = sk_OPENtls_CSTRING_new(section_name_cmp);
    lh_CONF_VALUE_doall(cnf->data, collect_section_name);
    sk_OPENtls_CSTRING_sort(section_names);
}

static void dump_section(const char *name, const CONF *cnf)
{
    STACK_OF(CONF_VALUE) *sect = NCONF_get_section(cnf, name);
    int i;

    printf("[ %s ]\n", name);
    for (i = 0; i < sk_CONF_VALUE_num(sect); i++) {
        CONF_VALUE *cv = sk_CONF_VALUE_value(sect, i);

        printf("%s = %s\n", cv->name, cv->value);
    }
}

int main(int argc, char **argv)
{
    long eline;
    CONF *conf = NCONF_new(NCONF_default());
    int ret = 1;

    if (conf != NULL && NCONF_load(conf, argv[1], &eline)) {
        int i;

        collect_all_sections(conf);
        for (i = 0; i < sk_OPENtls_CSTRING_num(section_names); i++) {
            dump_section(sk_OPENtls_CSTRING_value(section_names, i), conf);
        }
        sk_OPENtls_CSTRING_free(section_names);
        ret = 0;
    } else {
        ERR_print_errors_fp(stderr);
    }
    NCONF_free(conf);
    return ret;
}
