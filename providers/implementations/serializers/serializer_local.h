/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>        /* i2d_of_void */
#include <openssl/x509.h>        /* X509_SIG */
#include <openssl/types.h>
#include <crypto/ecx.h>
#include "internal/ffc.h"

struct pkcs8_encrypt_ctx_st {
    /* Set to 1 if intending to encrypt/decrypt, otherwise 0 */
    int cipher_intent;

    EVP_CIPHER *cipher;
    int pbe_nid;                 /* For future variation */

    /* Passphrase that was passed by the caller */
    void *cipher_pass;
    size_t cipher_pass_length;

    /* This callback is only used of |cipher_pass| is NULL */
    OSSL_PASSPHRASE_CALLBACK *cb;
    void *cbarg;
};

OSSL_OP_keymgmt_new_fn *ossl_prov_get_keymgmt_new(const OSSL_DISPATCH *fns);
OSSL_OP_keymgmt_free_fn *ossl_prov_get_keymgmt_free(const OSSL_DISPATCH *fns);
OSSL_OP_keymgmt_import_fn *ossl_prov_get_keymgmt_import(const OSSL_DISPATCH *fns);

OSSL_OP_keymgmt_new_fn *ossl_prov_get_keymgmt_rsa_new(void);
OSSL_OP_keymgmt_free_fn *ossl_prov_get_keymgmt_rsa_free(void);
OSSL_OP_keymgmt_import_fn *ossl_prov_get_keymgmt_rsa_import(void);
OSSL_OP_keymgmt_new_fn *ossl_prov_get_keymgmt_dh_new(void);
OSSL_OP_keymgmt_free_fn *ossl_prov_get_keymgmt_dh_free(void);
OSSL_OP_keymgmt_import_fn *ossl_prov_get_keymgmt_dh_import(void);
OSSL_OP_keymgmt_new_fn *ossl_prov_get_keymgmt_dsa_new(void);
OSSL_OP_keymgmt_free_fn *ossl_prov_get_keymgmt_dsa_free(void);
OSSL_OP_keymgmt_import_fn *ossl_prov_get_keymgmt_dsa_import(void);

void ec_get_new_free_import(OSSL_OP_keymgmt_new_fn **ec_new,
                            OSSL_OP_keymgmt_free_fn **ec_free,
                            OSSL_OP_keymgmt_import_fn **ec_import);

int ossl_prov_prepare_ec_params(const void *eckey, int nid,
                                void **pstr, int *pstrtype);
int ossl_prov_ec_pub_to_der(const void *eckey, unsigned char **pder);
int ossl_prov_ec_priv_to_der(const void *eckey, unsigned char **pder);

int ffc_params_prov_print(BIO *out, const FFC_PARAMS *ffc);
int ossl_prov_prepare_dh_params(const void *dh, int nid,
                                void **pstr, int *pstrtype);
int ossl_prov_dh_pub_to_der(const void *dh, unsigned char **pder);
int ossl_prov_dh_priv_to_der(const void *dh, unsigned char **pder);

#ifndef OPENSSL_NO_EC
void ecx_get_new_free_import(ECX_KEY_TYPE type,
                             OSSL_OP_keymgmt_new_fn **ecx_new,
                             OSSL_OP_keymgmt_free_fn **ecx_free,
                             OSSL_OP_keymgmt_import_fn **ecx_import);
int ossl_prov_ecx_pub_to_der(const void *ecxkey, unsigned char **pder);
int ossl_prov_ecx_priv_to_der(const void *ecxkey, unsigned char **pder);
#endif

int ossl_prov_prepare_dsa_params(const void *dsa, int nid,
                                void **pstr, int *pstrtype);
/*
 * Special variant of ossl_prov_prepare_dsa_params() that requires all
 * three parameters (P, Q and G) to be set.  This is used when serializing
 * the public key.
 */
int ossl_prov_prepare_all_dsa_params(const void *dsa, int nid,
                                     void **pstr, int *pstrtype);
int ossl_prov_dsa_pub_to_der(const void *dsa, unsigned char **pder);
int ossl_prov_dsa_priv_to_der(const void *dsa, unsigned char **pder);

/*
 * ossl_prov_prepare_rsa_params() is designed to work with the ossl_prov_write_
 * functions, hence 'void *rsa' rather than 'RSA *rsa'.
 */
int ossl_prov_prepare_rsa_params(const void *rsa, int nid,
                                 void **pstr, int *pstrtype);
int ossl_prov_rsa_type_to_evp(const RSA *rsa);

int ossl_prov_print_labeled_bignum(BIO *out, const char *label,
                                   const BIGNUM *bn);
int ossl_prov_print_labeled_buf(BIO *out, const char *label,
                                const unsigned char *buf, size_t buflen);
int ossl_prov_print_rsa(BIO *out, RSA *rsa, int priv);

enum dh_print_type {
    dh_print_priv,
    dh_print_pub,
    dh_print_params
};

int ossl_prov_print_dh(BIO *out, DH *dh, enum dh_print_type type);

#ifndef OPENSSL_NO_EC
enum ec_print_type {
    ec_print_priv,
    ec_print_pub,
    ec_print_params
};

int ossl_prov_print_eckey(BIO *out, EC_KEY *eckey, enum ec_print_type type);
#endif /*  OPENSSL_NO_EC */

enum dsa_print_type {
    dsa_print_priv,
    dsa_print_pub,
    dsa_print_params
};

int ossl_prov_print_dsa(BIO *out, DSA *dsa, enum dsa_print_type type);

enum ecx_print_type {
    ecx_print_priv,
    ecx_print_pub
};

#ifndef OPENSSL_NO_EC
int ossl_prov_print_ecx(BIO *out, ECX_KEY *ecxkey, enum ecx_print_type type);
#endif

int ossl_prov_write_priv_der_from_obj(BIO *out, const void *obj, int obj_nid,
                                      int (*p2s)(const void *obj, int nid,
                                                 void **str,
                                                 int *strtype),
                                      int (*k2d)(const void *obj,
                                                 unsigned char **pder),
                                      struct pkcs8_encrypt_ctx_st *ctx);
int ossl_prov_write_priv_pem_from_obj(BIO *out, const void *obj, int obj_nid,
                                      int (*p2s)(const void *obj, int nid,
                                                 void **str,
                                                 int *strtype),
                                      int (*k2d)(const void *obj,
                                                 unsigned char **pder),
                                      struct pkcs8_encrypt_ctx_st *ctx);
int ossl_prov_write_pub_der_from_obj(BIO *out, const void *obj, int obj_nid,
                                     int (*p2s)(const void *obj, int nid,
                                                void **str,
                                                int *strtype),
                                     int (*k2d)(const void *obj,
                                                unsigned char **pder));
int ossl_prov_write_pub_pem_from_obj(BIO *out, const void *obj, int obj_nid,
                                     int (*p2s)(const void *obj, int nid,
                                                void **str,
                                                int *strtype),
                                     int (*k2d)(const void *obj,
                                                unsigned char **pder));
