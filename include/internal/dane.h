/* dane.h */
/*
 * Written by Viktor Dukhovni (viktor@openssl.org) for the OpenSSL project
 * 2015.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
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
#ifndef HEADER_INTERNAL_DANE_H
#define HEADER_INTERNAL_DANE_H

#include <openssl/safestack.h>

/*-
 * Certificate usages:
 * https://tools.ietf.org/html/rfc6698#section-2.1.1
 */
#define DANETLS_USAGE_PKIX_TA   0
#define DANETLS_USAGE_PKIX_EE   1
#define DANETLS_USAGE_DANE_TA   2
#define DANETLS_USAGE_DANE_EE   3
#define DANETLS_USAGE_LAST      DANETLS_USAGE_DANE_EE

/*-
 * Selectors:
 * https://tools.ietf.org/html/rfc6698#section-2.1.2
 */
#define DANETLS_SELECTOR_CERT   0
#define DANETLS_SELECTOR_SPKI   1
#define DANETLS_SELECTOR_LAST   DANETLS_SELECTOR_SPKI

/*-
 * Matching types:
 * https://tools.ietf.org/html/rfc6698#section-2.1.3
 */
#define DANETLS_MATCHING_FULL   0
#define DANETLS_MATCHING_2256   1
#define DANETLS_MATCHING_2512   2
#define DANETLS_MATCHING_LAST   DANETLS_MATCHING_2512

typedef struct danetls_record_st {
    uint8_t usage;
    uint8_t selector;
    uint8_t mtype;
    unsigned char *data;
    size_t dlen;
    EVP_PKEY *spki;
} danetls_record;

DEFINE_STACK_OF(danetls_record)

/*
 * Shared DANE context
 */
struct dane_ctx_st {
    const EVP_MD  **mdevp;      /* mtype -> digest */
    uint8_t        *mdord;      /* mtype -> preference */
    uint8_t         mdmax;      /* highest supported mtype */
};

/*
 * Per connection DANE state
 */
struct dane_st {
    struct dane_ctx_st *dctx;
    STACK_OF(danetls_record) *trecs;
    STACK_OF(X509) *certs;      /* DANE-TA(2) Cert(0) Full(0) certs */
    danetls_record *mtlsa;      /* Matching TLSA record */
    X509           *mcert;      /* DANE matched cert */
    uint32_t        umask;      /* Usages present */
    int             mdpth;      /* Depth of matched cert */
    int             pdpth;      /* Depth of PKIX trust */
};

#define DANETLS_ENABLED(dane)  ((dane) && ((dane)->trecs != NULL))

#define DANETLS_USAGE_BIT(u)   (((uint32_t)1) << u)

#define DANETLS_PKIX_TA_MASK (DANETLS_USAGE_BIT(DANETLS_USAGE_PKIX_TA))
#define DANETLS_PKIX_EE_MASK (DANETLS_USAGE_BIT(DANETLS_USAGE_PKIX_EE))
#define DANETLS_DANE_TA_MASK (DANETLS_USAGE_BIT(DANETLS_USAGE_DANE_TA))
#define DANETLS_DANE_EE_MASK (DANETLS_USAGE_BIT(DANETLS_USAGE_DANE_EE))

#define DANETLS_PKIX_MASK (DANETLS_PKIX_TA_MASK | DANETLS_PKIX_EE_MASK)
#define DANETLS_DANE_MASK (DANETLS_DANE_TA_MASK | DANETLS_DANE_EE_MASK)
#define DANETLS_TA_MASK (DANETLS_PKIX_TA_MASK | DANETLS_DANE_TA_MASK)
#define DANETLS_EE_MASK (DANETLS_PKIX_EE_MASK | DANETLS_DANE_EE_MASK)

#define DANETLS_HAS_PKIX(dane) ((dane) && ((dane)->umask & DANETLS_PKIX_MASK))
#define DANETLS_HAS_DANE(dane) ((dane) && ((dane)->umask & DANETLS_DANE_MASK))
#define DANETLS_HAS_TA(dane)   ((dane) && ((dane)->umask & DANETLS_TA_MASK))
#define DANETLS_HAS_EE(dane)   ((dane) && ((dane)->umask & DANETLS_EE_MASK))

#define DANETLS_HAS_PKIX_TA(dane) ((dane)&&((dane)->umask & DANETLS_PKIX_TA_MASK))
#define DANETLS_HAS_PKIX_EE(dane) ((dane)&&((dane)->umask & DANETLS_PKIX_EE_MASK))
#define DANETLS_HAS_DANE_TA(dane) ((dane)&&((dane)->umask & DANETLS_DANE_TA_MASK))
#define DANETLS_HAS_DANE_EE(dane) ((dane)&&((dane)->umask & DANETLS_DANE_EE_MASK))

#endif /* HEADER_INTERNAL_DANE_H */
