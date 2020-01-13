/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core.h>
#include <opentls/core_numbers.h>
#include <opentls/bn.h>
#include <opentls/asn1.h>        /* i2d_of_void */
#include <opentls/x509.h>        /* X509_SIG */
#include <opentls/types.h>

struct pkcs8_encrypt_ctx_st {
    /* Set to 1 if intending to encrypt/decrypt, otherwise 0 */
    int cipher_intent;

    EVP_CIPHER *cipher;
    int pbe_nid;                 /* For future variation */

    /* Passphrase that was passed by the caller */
    void *cipher_pass;
    size_t cipher_pass_length;

    /* This callback is only used of |cipher_pass| is NULL */
    Otls_PASSPHRASE_CALLBACK *cb;
    void *cbarg;
};

Otls_OP_keymgmt_importkey_fn *otls_prov_get_importkey(const Otls_DISPATCH *fns);

Otls_OP_keymgmt_importkey_fn *otls_prov_get_rsa_importkey(void);
Otls_OP_keymgmt_importkey_fn *otls_prov_get_dh_importkey(void);
Otls_OP_keymgmt_importkey_fn *otls_prov_get_dsa_importkey(void);

int otls_prov_prepare_dh_params(const void *dh, int nid,
                                ASN1_STRING **pstr, int *pstrtype);
int otls_prov_dh_pub_to_der(const void *dh, unsigned char **pder);
int otls_prov_dh_priv_to_der(const void *dh, unsigned char **pder);

int otls_prov_prepare_dsa_params(const void *dsa, int nid,
                                ASN1_STRING **pstr, int *pstrtype);
/*
 * Special variant of otls_prov_prepare_dsa_params() that requires all
 * three parameters (P, Q and G) to be set.  This is used when serializing
 * the public key.
 */
int otls_prov_prepare_all_dsa_params(const void *dsa, int nid,
                                     ASN1_STRING **pstr, int *pstrtype);
int otls_prov_dsa_pub_to_der(const void *dsa, unsigned char **pder);
int otls_prov_dsa_priv_to_der(const void *dsa, unsigned char **pder);

int otls_prov_print_labeled_bignum(BIO *out, const char *label,
                                   const BIGNUM *n);
int otls_prov_print_rsa(BIO *out, RSA *rsa, int priv);

enum dh_print_type {
    dh_print_priv,
    dh_print_pub,
    dh_print_params
};

int otls_prov_print_dh(BIO *out, DH *dh, enum dh_print_type type);

enum dsa_print_type {
    dsa_print_priv,
    dsa_print_pub,
    dsa_print_params
};

int otls_prov_print_dsa(BIO *out, DSA *dsa, enum dsa_print_type type);

int otls_prov_write_priv_der_from_obj(BIO *out, const void *obj, int obj_nid,
                                      int (*p2s)(const void *obj, int nid,
                                                 ASN1_STRING **str,
                                                 int *strtype),
                                      int (*k2d)(const void *obj,
                                                 unsigned char **pder),
                                      struct pkcs8_encrypt_ctx_st *ctx);
int otls_prov_write_priv_pem_from_obj(BIO *out, const void *obj, int obj_nid,
                                      int (*p2s)(const void *obj, int nid,
                                                 ASN1_STRING **str,
                                                 int *strtype),
                                      int (*k2d)(const void *obj,
                                                 unsigned char **pder),
                                      struct pkcs8_encrypt_ctx_st *ctx);
int otls_prov_write_pub_der_from_obj(BIO *out, const void *obj, int obj_nid,
                                     int (*p2s)(const void *obj, int nid,
                                                ASN1_STRING **str,
                                                int *strtype),
                                     int (*k2d)(const void *obj,
                                                unsigned char **pder));
int otls_prov_write_pub_pem_from_obj(BIO *out, const void *obj, int obj_nid,
                                     int (*p2s)(const void *obj, int nid,
                                                ASN1_STRING **str,
                                                int *strtype),
                                     int (*k2d)(const void *obj,
                                                unsigned char **pder));
