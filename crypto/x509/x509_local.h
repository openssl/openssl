/*
 * Copyright 2014-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/refcount.h"
#include "internal/hashtable.h"
#include "internal/x509.h"

#define X509V3_conf_add_error_name_value(val) \
    ERR_add_error_data(4, "name=", (val)->name, ", value=", (val)->value)

/* No error callback if depth < 0 */
int ossl_x509_check_cert_time(X509_STORE_CTX *ctx, X509 *x, int depth);

/* a sequence of these are used */
struct x509_attributes_st {
    ASN1_OBJECT *object;
    STACK_OF(ASN1_TYPE) *set;
};

struct X509_extension_st {
    ASN1_OBJECT *object;
    ASN1_BOOLEAN critical;
    ASN1_OCTET_STRING value;
};

/*
 * Method to handle CRL access. In general a CRL could be very large (several
 * Mb) and can consume large amounts of resources if stored in memory by
 * multiple processes. This method allows general CRL operations to be
 * redirected to more efficient callbacks: for example a CRL entry database.
 */

#define X509_CRL_METHOD_DYNAMIC         1

struct x509_crl_method_st {
    int flags;
    int (*crl_init) (X509_CRL *crl);
    int (*crl_free) (X509_CRL *crl);
    int (*crl_lookup) (X509_CRL *crl, X509_REVOKED **ret,
                       const ASN1_INTEGER *ser, const X509_NAME *issuer);
    int (*crl_verify) (X509_CRL *crl, EVP_PKEY *pk);
};

struct x509_lookup_method_st {
    char *name;
    int (*new_item) (X509_LOOKUP *ctx);
    void (*free) (X509_LOOKUP *ctx);
    int (*init) (X509_LOOKUP *ctx);
    int (*shutdown) (X509_LOOKUP *ctx);
    int (*ctrl) (X509_LOOKUP *ctx, int cmd, const char *argc, long argl,
                 char **ret);
    int (*get_by_subject) (X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                           const X509_NAME *name, X509_OBJECT *ret);
    int (*get_by_issuer_serial) (X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                                 const X509_NAME *name,
                                 const ASN1_INTEGER *serial,
                                 X509_OBJECT *ret);
    int (*get_by_fingerprint) (X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                               const unsigned char *bytes, int len,
                               X509_OBJECT *ret);
    int (*get_by_alias) (X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                         const char *str, int len, X509_OBJECT *ret);
    int (*get_by_subject_ex) (X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                              const X509_NAME *name, X509_OBJECT *ret,
                              OSSL_LIB_CTX *libctx, const char *propq);
    int (*ctrl_ex) (X509_LOOKUP *ctx, int cmd, const char *argc, long argl,
                    char **ret, OSSL_LIB_CTX *libctx, const char *propq);
};

/* This is the functions plus an instance of the local variables. */
struct x509_lookup_st {
    int init;                   /* have we been started */
    int skip;                   /* don't use us. */
    X509_LOOKUP_METHOD *method; /* the functions */
    void *method_data;          /* method data */
    X509_STORE *store_ctx;      /* who owns us */
};

HT_START_KEY_DEFN(objs_key)
HT_DEF_KEY_FIELD(xn_canon, unsigned char *)
HT_DEF_KEY_FIELD(xn_canon_enclen, int)
HT_END_KEY_DEFN(OBJS_KEY)

typedef struct lookup_dir_hashes_st BY_DIR_HASH;
typedef struct lookup_dir_entry_st BY_DIR_ENTRY;
DEFINE_STACK_OF(BY_DIR_HASH)
DEFINE_STACK_OF(BY_DIR_ENTRY)
typedef STACK_OF(X509_NAME_ENTRY) STACK_OF_X509_NAME_ENTRY;
DEFINE_STACK_OF(STACK_OF_X509_NAME_ENTRY)

int ossl_x509_likely_issued(X509 *issuer, X509 *subject);
int ossl_x509_signing_allowed(const X509 *issuer, const X509 *subject);
int ossl_x509_store_ctx_get_by_subject(const X509_STORE_CTX *ctx, X509_LOOKUP_TYPE type,
                                       const X509_NAME *name, X509_OBJECT *ret);
__owur int ossl_x509_store_read_lock(X509_STORE *xs);
STACK_OF(X509_OBJECT) *ossl_x509_store_ht_get_by_name(const X509_STORE *store,
                                                      const X509_NAME *xn);
