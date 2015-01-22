/* asn_mstbl.c */
/*
 * Written by Stephen Henson (steve@openssl.org) for the OpenSSL project
 * 2012.
 */
/* ====================================================================
 * Copyright (c) 2012 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <openssl/crypto.h>
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/x509v3.h>

/* Multi string module: add table enstries from a given section */

static int do_tcreate(char *value, char *name);

static int stbl_module_init(CONF_IMODULE *md, const CONF *cnf)
{
    int i;
    const char *stbl_section;
    STACK_OF(CONF_VALUE) *sktmp;
    CONF_VALUE *mval;
    stbl_section = CONF_imodule_get_value(md);
    if (!(sktmp = NCONF_get_section(cnf, stbl_section))) {
        ASN1err(ASN1_F_STBL_MODULE_INIT, ASN1_R_ERROR_LOADING_SECTION);
        return 0;
    }
    for (i = 0; i < sk_CONF_VALUE_num(sktmp); i++) {
        mval = sk_CONF_VALUE_value(sktmp, i);
        if (!do_tcreate(mval->value, mval->name)) {
            ASN1err(ASN1_F_STBL_MODULE_INIT, ASN1_R_INVALID_VALUE);
            return 0;
        }
    }
    return 1;
}

static void stbl_module_finish(CONF_IMODULE *md)
{
    ASN1_STRING_TABLE_cleanup();
}

void ASN1_add_stable_module(void)
{
    CONF_module_add("stbl_section", stbl_module_init, stbl_module_finish);
}

/*
 * Create an table entry based on a name value pair. format is oid_name =
 * n1:v1, n2:v2,... where name is "min", "max", "mask" or "flags".
 */

static int do_tcreate(char *value, char *name)
{
    char *eptr;
    int nid, i, rv = 0;
    long tbl_min = -1, tbl_max = -1;
    unsigned long tbl_mask = 0, tbl_flags = 0;
    STACK_OF(CONF_VALUE) *lst = NULL;
    CONF_VALUE *cnf = NULL;
    nid = OBJ_sn2nid(name);
    if (nid == NID_undef)
        nid = OBJ_ln2nid(name);
    if (nid == NID_undef)
        goto err;
    lst = X509V3_parse_list(value);
    if (!lst)
        goto err;
    for (i = 0; i < sk_CONF_VALUE_num(lst); i++) {
        cnf = sk_CONF_VALUE_value(lst, i);
        if (!strcmp(cnf->name, "min")) {
            tbl_min = strtoul(cnf->value, &eptr, 0);
            if (*eptr)
                goto err;
        } else if (!strcmp(cnf->name, "max")) {
            tbl_max = strtoul(cnf->value, &eptr, 0);
            if (*eptr)
                goto err;
        } else if (!strcmp(cnf->name, "mask")) {
            if (!ASN1_str2mask(cnf->value, &tbl_mask) || !tbl_mask)
                goto err;
        } else if (!strcmp(cnf->name, "flags")) {
            if (!strcmp(cnf->value, "nomask"))
                tbl_flags = STABLE_NO_MASK;
            else if (!strcmp(cnf->value, "none"))
                tbl_flags = STABLE_FLAGS_CLEAR;
            else
                goto err;
        } else
            goto err;
    }
    rv = 1;
 err:
    if (rv == 0) {
        ASN1err(ASN1_F_DO_TCREATE, ASN1_R_INVALID_STRING_TABLE_VALUE);
        if (cnf)
            ERR_add_error_data(4, "field=", cnf->name,
                               ", value=", cnf->value);
        else
            ERR_add_error_data(4, "name=", name, ", value=", value);
    } else {
        rv = ASN1_STRING_TABLE_add(nid, tbl_min, tbl_max,
                                   tbl_mask, tbl_flags);
        if (!rv)
            ASN1err(ASN1_F_DO_TCREATE, ERR_R_MALLOC_FAILURE);
    }
    if (lst)
        sk_CONF_VALUE_pop_free(lst, X509V3_conf_free);
    return rv;
}
