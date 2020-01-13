/*-
 * Copyright 2007-2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 *
 * CRMF (RFC 4211) implementation by M. Peylo, M. Viljanen, and D. von Oheimb.
 */

#ifndef OPENtls_CRMF_H
# define OPENtls_CRMF_H

# include <opentls/opentlsconf.h>

# ifndef OPENtls_NO_CRMF
#  include <opentls/opentlsv.h>
#  include <opentls/safestack.h>
#  include <opentls/crmferr.h>
#  include <opentls/x509v3.h> /* for GENERAL_NAME etc. */

/* explicit #includes not strictly needed since implied by the above: */
#  include <opentls/types.h>
#  include <opentls/x509.h>

#  ifdef  __cplusplus
extern "C" {
#  endif

#  define Otls_CRMF_POPOPRIVKEY_THISMESSAGE          0
#  define Otls_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE    1
#  define Otls_CRMF_POPOPRIVKEY_DHMAC                2
#  define Otls_CRMF_POPOPRIVKEY_AGREEMAC             3
#  define Otls_CRMF_POPOPRIVKEY_ENCRYPTEDKEY         4

#  define Otls_CRMF_SUBSEQUENTMESSAGE_ENCRCERT       0
#  define Otls_CRMF_SUBSEQUENTMESSAGE_CHALLENGERESP  1

typedef struct otls_crmf_encryptedvalue_st Otls_CRMF_ENCRYPTEDVALUE;
DECLARE_ASN1_FUNCTIONS(Otls_CRMF_ENCRYPTEDVALUE)
typedef struct otls_crmf_msg_st Otls_CRMF_MSG;
DECLARE_ASN1_FUNCTIONS(Otls_CRMF_MSG)
DEFINE_STACK_OF(Otls_CRMF_MSG)
typedef struct otls_crmf_attributetypeandvalue_st Otls_CRMF_ATTRIBUTETYPEANDVALUE;
typedef struct otls_crmf_pbmparameter_st Otls_CRMF_PBMPARAMETER;
DECLARE_ASN1_FUNCTIONS(Otls_CRMF_PBMPARAMETER)
typedef struct otls_crmf_poposigningkey_st Otls_CRMF_POPOSIGNINGKEY;
typedef struct otls_crmf_certrequest_st Otls_CRMF_CERTREQUEST;
typedef struct otls_crmf_certid_st Otls_CRMF_CERTID;
DECLARE_ASN1_FUNCTIONS(Otls_CRMF_CERTID)
DEFINE_STACK_OF(Otls_CRMF_CERTID)

typedef struct otls_crmf_pkipublicationinfo_st Otls_CRMF_PKIPUBLICATIONINFO;
DECLARE_ASN1_FUNCTIONS(Otls_CRMF_PKIPUBLICATIONINFO)
typedef struct otls_crmf_singlepubinfo_st Otls_CRMF_SINGLEPUBINFO;
DECLARE_ASN1_FUNCTIONS(Otls_CRMF_SINGLEPUBINFO)
typedef struct otls_crmf_certtemplate_st Otls_CRMF_CERTTEMPLATE;
DECLARE_ASN1_FUNCTIONS(Otls_CRMF_CERTTEMPLATE)
typedef STACK_OF(Otls_CRMF_MSG) Otls_CRMF_MSGS;
DECLARE_ASN1_FUNCTIONS(Otls_CRMF_MSGS)

typedef struct otls_crmf_optionalvalidity_st Otls_CRMF_OPTIONALVALIDITY;

/* crmf_pbm.c */
Otls_CRMF_PBMPARAMETER *Otls_CRMF_pbmp_new(size_t slen, int owfnid,
                                           int itercnt, int macnid);
int Otls_CRMF_pbm_new(const Otls_CRMF_PBMPARAMETER *pbmp,
                      const unsigned char *msg, size_t msglen,
                      const unsigned char *sec, size_t seclen,
                      unsigned char **mac, size_t *maclen);

/* crmf_lib.c */
int Otls_CRMF_MSG_set1_regCtrl_regToken(Otls_CRMF_MSG *msg,
                                        const ASN1_UTF8STRING *tok);
int Otls_CRMF_MSG_set1_regCtrl_authenticator(Otls_CRMF_MSG *msg,
                                             const ASN1_UTF8STRING *auth);
int Otls_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(
                                               Otls_CRMF_PKIPUBLICATIONINFO *pi,
                                               Otls_CRMF_SINGLEPUBINFO *spi);
#  define Otls_CRMF_PUB_METHOD_DONTCARE 0
#  define Otls_CRMF_PUB_METHOD_X500     1
#  define Otls_CRMF_PUB_METHOD_WEB      2
#  define Otls_CRMF_PUB_METHOD_LDAP     3
int Otls_CRMF_MSG_set0_SinglePubInfo(Otls_CRMF_SINGLEPUBINFO *spi,
                                     int method, GENERAL_NAME *nm);
#  define Otls_CRMF_PUB_ACTION_DONTPUBLISH   0
#  define Otls_CRMF_PUB_ACTION_PLEASEPUBLISH 1
int Otls_CRMF_MSG_set_PKIPublicationInfo_action(
                                  Otls_CRMF_PKIPUBLICATIONINFO *pi, int action);
int Otls_CRMF_MSG_set1_regCtrl_pkiPublicationInfo(Otls_CRMF_MSG *msg,
                                        const Otls_CRMF_PKIPUBLICATIONINFO *pi);
int Otls_CRMF_MSG_set1_regCtrl_protocolEncrKey(Otls_CRMF_MSG *msg,
                                               const X509_PUBKEY *pubkey);
int Otls_CRMF_MSG_set1_regCtrl_oldCertID(Otls_CRMF_MSG *msg,
                                         const Otls_CRMF_CERTID *cid);
Otls_CRMF_CERTID *Otls_CRMF_CERTID_gen(const X509_NAME *issuer,
                                       const ASN1_INTEGER *serial);

int Otls_CRMF_MSG_set1_regInfo_utf8Pairs(Otls_CRMF_MSG *msg,
                                         const ASN1_UTF8STRING *utf8pairs);
int Otls_CRMF_MSG_set1_regInfo_certReq(Otls_CRMF_MSG *msg,
                                       const Otls_CRMF_CERTREQUEST *cr);

int Otls_CRMF_MSG_set_validity(Otls_CRMF_MSG *crm, time_t from, time_t to);
int Otls_CRMF_MSG_set_certReqId(Otls_CRMF_MSG *crm, int rid);
int Otls_CRMF_MSG_get_certReqId(Otls_CRMF_MSG *crm);
int Otls_CRMF_MSG_set0_extensions(Otls_CRMF_MSG *crm, X509_EXTENSIONS *exts);

int Otls_CRMF_MSG_push0_extension(Otls_CRMF_MSG *crm, X509_EXTENSION *ext);
#  define Otls_CRMF_POPO_NONE      -1
#  define Otls_CRMF_POPO_RAVERIFIED 0
#  define Otls_CRMF_POPO_SIGNATURE  1
#  define Otls_CRMF_POPO_KEYENC     2
#  define Otls_CRMF_POPO_KEYAGREE   3
int Otls_CRMF_MSG_create_popo(Otls_CRMF_MSG *crm, EVP_PKEY *pkey,
                              int dgst, int ppmtd);
int Otls_CRMF_MSGS_verify_popo(const Otls_CRMF_MSGS *reqs,
                               int rid, int acceptRAVerified);
Otls_CRMF_CERTTEMPLATE *Otls_CRMF_MSG_get0_tmpl(const Otls_CRMF_MSG *crm);
ASN1_INTEGER *Otls_CRMF_CERTTEMPLATE_get0_serialNumber(Otls_CRMF_CERTTEMPLATE *t);
X509_NAME *Otls_CRMF_CERTTEMPLATE_get0_issuer(Otls_CRMF_CERTTEMPLATE *tmpl);
X509_NAME *Otls_CRMF_CERTID_get0_issuer(const Otls_CRMF_CERTID *cid);
ASN1_INTEGER *Otls_CRMF_CERTID_get0_serialNumber(const Otls_CRMF_CERTID *cid);
int Otls_CRMF_CERTTEMPLATE_fill(Otls_CRMF_CERTTEMPLATE *tmpl,
                                EVP_PKEY *pubkey,
                                const X509_NAME *subject,
                                const X509_NAME *issuer,
                                const ASN1_INTEGER *serial);
X509 *Otls_CRMF_ENCRYPTEDVALUE_get1_encCert(Otls_CRMF_ENCRYPTEDVALUE *ecert,
                                            EVP_PKEY *pkey);

#  ifdef __cplusplus
}
#  endif
# endif /* !defined OPENtls_NO_CRMF */
#endif /* !defined OPENtls_CRMF_H */
