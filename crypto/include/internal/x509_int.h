/* x509_int.h */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
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

/* Internal X509 structures and functions: not for application use */

/* Note: unless otherwise stated a field pointer is mandatory and should
 * never be set to NULL: the ASN.1 code and accessors rely on mandatory
 * fields never being NULL.
 */

/*
 * name entry structure, equivalent to AttributeTypeAndValue defined
 * in RFC5280 et al.
 */
struct X509_name_entry_st {
    ASN1_OBJECT *object;        /* AttributeType */
    ASN1_STRING *value;         /* AttributeValue */
    int set;                    /* index of RDNSequence for this entry */
    int size;                   /* temp variable */
};

/* Name from RFC 5280. */
struct X509_name_st {
    STACK_OF(X509_NAME_ENTRY) *entries; /* DN components */
    int modified;               /* true if 'bytes' needs to be built */
    BUF_MEM *bytes;             /* cached encoding: cannot be NULL */
    /* canonical encoding used for rapid Name comparison */
    unsigned char *canon_enc;
    int canon_enclen;
} /* X509_NAME */ ;

/* PKCS#10 certificate request */

struct X509_req_info_st {
    ASN1_ENCODING enc;          /* cached encoding of signed part */
    ASN1_INTEGER *version;      /* version, defaults to v1(0) so can be NULL */
    X509_NAME *subject;         /* certificate request DN */
    X509_PUBKEY *pubkey;        /* public key of request */
    /*
     * Zero or more attributes.
     * NB: although attributes is a mandatory field some broken
     * encodings omit it so this may be NULL in that case.
     */
    STACK_OF(X509_ATTRIBUTE) *attributes;
};

struct X509_req_st {
    X509_REQ_INFO req_info;     /* signed certificate request data */
    X509_ALGOR sig_alg;         /* signature algorithm */
    ASN1_BIT_STRING *signature; /* signature */
    int references;
};

struct X509_crl_info_st {
    ASN1_INTEGER *version;      /* version: defaults to v1(0) so may be NULL */
    X509_ALGOR sig_alg;         /* signagture algorithm */
    X509_NAME *issuer;          /* CRL issuer name */
    ASN1_TIME *lastUpdate;      /* lastUpdate field */
    ASN1_TIME *nextUpdate;      /* nextUpdate field: optional */
    STACK_OF(X509_REVOKED) *revoked; /* revoked entries: optional */
    STACK_OF(X509_EXTENSION) *extensions;   /* extensions: optional */
    ASN1_ENCODING enc;          /* encoding of signed portion of CRL */
};

struct X509_crl_st {
    X509_CRL_INFO crl;          /* signed CRL data */
    X509_ALGOR sig_alg;         /* CRL signature algorithm */
    ASN1_BIT_STRING signature; /* CRL signature */
    int references;
    int flags;
    /*
     * Cached copies of decoded extension values, since extensions
     * are optional any of these can be NULL.
     */
    AUTHORITY_KEYID *akid;
    ISSUING_DIST_POINT *idp;
    /* Convenient breakdown of IDP */
    int idp_flags;
    int idp_reasons;
    /* CRL and base CRL numbers for delta processing */
    ASN1_INTEGER *crl_number;
    ASN1_INTEGER *base_crl_number;
    STACK_OF(GENERAL_NAMES) *issuers;
    /* hash of CRL */
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    /* alternative method to handle this CRL */
    const X509_CRL_METHOD *meth;
    void *meth_data;
};

struct x509_revoked_st {
    ASN1_INTEGER serialNumber; /* revoked entry serial number */
    ASN1_TIME *revocationDate;  /* revocation date */
    STACK_OF(X509_EXTENSION) *extensions;   /* CRL entry extensions: optional */
    /* decoded value of CRLissuer extension: set if indirect CRL */
    STACK_OF(GENERAL_NAME) *issuer;
    /* revocation reason: set to CRL_REASON_NONE if reason extension absent */
    int reason;
    /*
     * CRL entries are reordered for faster lookup of serial numbers. This
     * field contains the original load sequence for this entry.
     */
    int sequence;
};

/*
 * This stuff is certificate "auxiliary info": it contains details which are
 * useful in certificate stores and databases. When used this is tagged onto
 * the end of the certificate itself. OpenSSL specific structure not defined
 * in any RFC.
 */

struct x509_cert_aux_st {
    STACK_OF(ASN1_OBJECT) *trust; /* trusted uses */
    STACK_OF(ASN1_OBJECT) *reject; /* rejected uses */
    ASN1_UTF8STRING *alias;     /* "friendly name" */
    ASN1_OCTET_STRING *keyid;   /* key id of private key */
    STACK_OF(X509_ALGOR) *other; /* other unspecified info */
};

struct x509_cinf_st {
    ASN1_INTEGER *version;      /* [ 0 ] default of v1 */
    ASN1_INTEGER serialNumber;
    X509_ALGOR signature;
    X509_NAME *issuer;
    X509_VAL validity;
    X509_NAME *subject;
    X509_PUBKEY *key;
    ASN1_BIT_STRING *issuerUID; /* [ 1 ] optional in v2 */
    ASN1_BIT_STRING *subjectUID; /* [ 2 ] optional in v2 */
    STACK_OF(X509_EXTENSION) *extensions; /* [ 3 ] optional in v3 */
    ASN1_ENCODING enc;
};

struct x509_st {
    X509_CINF cert_info;
    X509_ALGOR sig_alg;
    ASN1_BIT_STRING signature;
    int valid;
    int references;
    char *name;
    CRYPTO_EX_DATA ex_data;
    /* These contain copies of various extension values */
    long ex_pathlen;
    long ex_pcpathlen;
    uint32_t ex_flags;
    uint32_t ex_kusage;
    uint32_t ex_xkusage;
    uint32_t ex_nscert;
    ASN1_OCTET_STRING *skid;
    AUTHORITY_KEYID *akid;
    X509_POLICY_CACHE *policy_cache;
    STACK_OF(DIST_POINT) *crldp;
    STACK_OF(GENERAL_NAME) *altname;
    NAME_CONSTRAINTS *nc;
#ifndef OPENSSL_NO_RFC3779
    STACK_OF(IPAddressFamily) *rfc3779_addr;
    struct ASIdentifiers_st *rfc3779_asid;
# endif
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    X509_CERT_AUX *aux;
} /* X509 */ ;
