/*
 * Written by Rob Stradling (rob@comodo.com) and Stephen Henson
 * (steve@openssl.org) for the OpenSSL project 2014.
 */
/* ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
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
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifdef OPENSSL_NO_CT
# error "CT is disabled"
#endif

#include "ct_locl.h"

static char *i2s_poison(const X509V3_EXT_METHOD *method, void *val)
{
    return OPENSSL_strdup("NULL");
}

static void *s2i_poison(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, const char *str)
{
   return ASN1_NULL_new();
}

static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
                 BIO *out, int indent)
{
    SCT_LIST_print(sct_list, out, indent, "\n", NULL);
    return 1;
}

/* Handlers for X509v3/OCSP Certificate Transparency extensions */
const X509V3_EXT_METHOD v3_ct_scts[] = {
    /* X509v3 extension in certificates that contains SCTs */
    { NID_ct_precert_scts, 0, NULL,
    NULL, (X509V3_EXT_FREE)SCT_LIST_free,
    (X509V3_EXT_D2I)d2i_SCT_LIST, (X509V3_EXT_I2D)i2d_SCT_LIST,
    NULL, NULL,
    NULL, NULL,
    (X509V3_EXT_I2R)i2r_SCT_LIST, NULL,
    NULL },

    /* X509v3 extension to mark a certificate as a pre-certificate */
    { NID_ct_precert_poison, 0, ASN1_ITEM_ref(ASN1_NULL),
    NULL, NULL, NULL, NULL,
    i2s_poison, s2i_poison,
    NULL, NULL,
    NULL, NULL,
    NULL },

    /* OCSP extension that contains SCTs */
    { NID_ct_cert_scts, 0, NULL,
    0, (X509V3_EXT_FREE)SCT_LIST_free,
    (X509V3_EXT_D2I)d2i_SCT_LIST, (X509V3_EXT_I2D)i2d_SCT_LIST,
    NULL, NULL,
    NULL, NULL,
    (X509V3_EXT_I2R)i2r_SCT_LIST, NULL,
    NULL },
};
