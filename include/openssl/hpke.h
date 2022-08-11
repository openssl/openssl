/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HPKE_H
# define OPENSSL_HPKE_H
# pragma once

# include <stddef.h>        /* size_t */
# include <openssl/types.h> /* EVP_PKEY */

# ifdef __cplusplus
extern "C" {
# endif

typedef struct ossl_hpke_kem_st OSSL_HPKE_KEM;
typedef struct ossl_hpke_ctx_st OSSL_HPKE_CTX;

OSSL_HPKE_KEM *OSSL_HPKE_KEM_new(const char *keyname, const char *curvename,
                                 const char *kdfname, const char *kdfdigestname);
void OSSL_HPKE_KEM_free(OSSL_HPKE_KEM *kem);

/* One shot sender seal functions */
int OSSL_HPKE_sender_seal(OSSL_HPKE_KEM *kem,
                          unsigned char *enc, size_t *enclen,
                          unsigned char *ct, size_t *ctlen,
                          EVP_PKEY *recippub,
                          const char *hpkedigest, const char *aeadname,
                          const unsigned char *ikme, size_t ikmelen,
                          const unsigned char *ksinfo, size_t ksinfolen,
                          const unsigned char *pt, size_t ptlen,
                          const unsigned char *aad, size_t aadlen,
                          OSSL_LIB_CTX *libctx, const char *propq);
int OSSL_HPKE_sender_sealPSK(OSSL_HPKE_KEM *kem,
                             unsigned char *enc, size_t *enclen,
                             unsigned char *ct, size_t *ctlen,
                             EVP_PKEY *recippub,
                             const char *hpkedigest, const char *aeadname,
                             const unsigned char *ikme, size_t ikmelen,
                             const unsigned char *ksinfo, size_t ksinfolen,
                             const unsigned char *pt, size_t ptlen,
                             const unsigned char *aad, size_t aadlen,
                             OSSL_LIB_CTX *libctx, const char *propq,
                             const unsigned char *psk, size_t psklen,
                             const unsigned char *pskid, size_t pskidlen);
int OSSL_HPKE_sender_sealAuth(OSSL_HPKE_KEM *kem,
                              unsigned char *enc, size_t *enclen,
                              unsigned char *ct, size_t *ctlen,
                              EVP_PKEY *recippub,
                              const char *hpkedigest, const char *aeadname,
                              const unsigned char *ikme, size_t ikmelen,
                              const unsigned char *ksinfo, size_t ksinfolen,
                              const unsigned char *pt, size_t ptlen,
                              const unsigned char *aad, size_t aadlen,
                              OSSL_LIB_CTX *libctx, const char *propq,
                              EVP_PKEY *authpriv);
int OSSL_HPKE_sender_sealAuthPSK(OSSL_HPKE_KEM *kem,
                                 unsigned char *enc, size_t *enclen,
                                 unsigned char *ct, size_t *ctlen,
                                 EVP_PKEY *recippub,
                                 const char *hpkedigest, const char *aeadname,
                                 const unsigned char *ikme, size_t ikmelen,
                                 const unsigned char *ksinfo, size_t ksinfolen,
                                 const unsigned char *pt, size_t ptlen,
                                 const unsigned char *aad, size_t aadlen,
                                 OSSL_LIB_CTX *libctx, const char *propq,
                                 const unsigned char *psk, size_t psklen,
                                 const unsigned char *pskid, size_t pskidlen,
                                 EVP_PKEY *authpriv);

/* One shot recipient open functions */
int OSSL_HPKE_recipient_open(OSSL_HPKE_KEM *kem,
        unsigned char *pt, size_t *ptlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ct, size_t ctlen,
        const unsigned char *aad, size_t aadlen,
        OSSL_LIB_CTX *libctx, const char *propq);
int OSSL_HPKE_recipient_openPSK(OSSL_HPKE_KEM *kem,
        unsigned char *pt, size_t *ptlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ct, size_t ctlen,
        const unsigned char *aad, size_t aadlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen);
int OSSL_HPKE_recipient_openAuth(OSSL_HPKE_KEM *kem,
        unsigned char *pt, size_t *ptlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ct, size_t ctlen,
        const unsigned char *aad, size_t aadlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        EVP_PKEY *authpub);
int OSSL_HPKE_recipient_openAuthPSK(OSSL_HPKE_KEM *kem,
        unsigned char *pt, size_t *ptlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ct, size_t ctlen,
        const unsigned char *aad, size_t aadlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen,
        EVP_PKEY *authpub);

/* One shot sender export only functions */
int OSSL_HPKE_sender_export(OSSL_HPKE_KEM *kem,
        unsigned char *enc, size_t *enclen,
        unsigned char *secret, size_t secretlen,
        EVP_PKEY *recippub,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ikme, size_t ikmelen,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq);
int OSSL_HPKE_sender_exportPSK(
        OSSL_HPKE_KEM *kem,
        unsigned char *enc, size_t *enclen,
        unsigned char *secret, size_t secretlen,
        EVP_PKEY *recippub,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ikme, size_t ikmelen,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen);
int OSSL_HPKE_sender_exportAuth(
        OSSL_HPKE_KEM *kem,
        unsigned char *enc, size_t *enclen,
        unsigned char *secret, size_t secretlen,
        EVP_PKEY *recippub,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ikme, size_t ikmelen,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        EVP_PKEY *authpriv);
int OSSL_HPKE_sender_exportAuthPSK(
        OSSL_HPKE_KEM *kem,
        unsigned char *enc, size_t *enclen,
        unsigned char *secret, size_t secretlen,
        EVP_PKEY *recippub,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ikme, size_t ikmelen,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen,
        EVP_PKEY *authpriv);

/* One shot recipient export only functions */
int OSSL_HPKE_recipient_export(
        OSSL_HPKE_KEM *kem,
        unsigned char *secret, size_t secretlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        const unsigned char *aad, size_t aadlen,
        OSSL_LIB_CTX *libctx, const char *propq);
int OSSL_HPKE_recipient_exportPSK(
        OSSL_HPKE_KEM *kem,
        unsigned char *secret, size_t secretlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen);
int OSSL_HPKE_recipient_exportAuth(
        OSSL_HPKE_KEM *kem,
        unsigned char *secret, size_t secretlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        EVP_PKEY *authpub);
int OSSL_HPKE_recipient_exportAuthPSK(
        OSSL_HPKE_KEM *kem,
        unsigned char *secret, size_t secretlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen,
        EVP_PKEY *authpub);

/* KEM derive key API */
int OSSL_HPKE_KEM_derivekey_init(OSSL_HPKE_KEM *kem,
                                 OSSL_LIB_CTX *libctx, const char *propq);
int OSSL_HPKE_KEM_derivekey(OSSL_HPKE_KEM *kem,
                            EVP_PKEY **privkeyout, EVP_PKEY **pubkeyout,
                            const unsigned char *ikm, size_t ikmlen);

/* KEM encapsulate, decapsulate API's */

int OSSL_HPKE_KEM_encapsulate_init(EVP_PKEY_CTX *rpub, OSSL_HPKE_KEM *kem,
                                   EVP_PKEY *authprivkey,
                                   const unsigned char *ikme, size_t ikmelen);
int OSSL_HPKE_KEM_encapsulate(EVP_PKEY_CTX *ctx,
                              unsigned char *enc, size_t *enclen,
                              unsigned char *secret, size_t *secretlen);

int OSSL_HPKE_KEM_decapsulate_init(EVP_PKEY_CTX *rpriv, OSSL_HPKE_KEM *kem,
                                   EVP_PKEY *authpubkey);
int OSSL_HPKE_KEM_decapsulate(EVP_PKEY_CTX *ctx,
                              unsigned char *secret, size_t *secretlen,
                              const unsigned char *enc, size_t enclen);

/* HPKE KeySchedule, Seal, Open, Export API's */

OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(OSSL_HPKE_KEM *kem, int sender,
                                 const char *kdfdigestalg, const char *aeadalg,
                                 OSSL_LIB_CTX *libctx, const char *propq);
void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx);
int OSSL_HPKE_CTX_keyschedule(OSSL_HPKE_CTX *ctx,
                              const unsigned char *info, size_t infolen,
                              const unsigned char *secret, size_t secretlen);
int OSSL_HPKE_CTX_keyschedule_psk(OSSL_HPKE_CTX *ctx,
                                  const unsigned char *info, size_t infolen,
                                  const unsigned char *secret, size_t secretlen,
                                  const unsigned char *psk, size_t psklen,
                                  const unsigned char *pskid, size_t pskidlen);

int OSSL_HPKE_CTX_seal_init(OSSL_HPKE_CTX *ctx);
int OSSL_HPKE_CTX_seal(OSSL_HPKE_CTX *ctx, unsigned char *ct, size_t *ctlen,
                       const unsigned char *aad, size_t aadlen,
                       const unsigned char *pt, size_t ptlen);
int OSSL_HPKE_CTX_open_init(OSSL_HPKE_CTX *ctx);
int OSSL_HPKE_CTX_open(OSSL_HPKE_CTX *hpke, unsigned char *pt, size_t *ptlen,
                       const unsigned char *aad, size_t aadlen,
                       const unsigned char *ct, size_t ctlen);
int OSSL_HPKE_CTX_export(OSSL_HPKE_CTX *ctx,
                         unsigned char *secret, size_t secretlen,
                         const unsigned char *context, size_t contextlen);

# ifdef __cplusplus
}
# endif
#endif
