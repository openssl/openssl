/**********************************************************************
 *                          gost_keytrans.h                           *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 *   ASN1 structure declaration for GOST key transport                *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#ifndef GOST_KEY_TRANS_H
#define GOST_KEY_TRANS_H
#include <openssl/asn1t.h>
#include <openssl/x509.h>


typedef struct {
	ASN1_OCTET_STRING *encrypted_key;
	ASN1_OCTET_STRING *imit;
} GOST_KEY_INFO;

DECLARE_ASN1_FUNCTIONS(GOST_KEY_INFO)

typedef struct {
	ASN1_OBJECT *cipher;
	X509_PUBKEY *ephem_key;
	ASN1_OCTET_STRING *eph_iv;
} GOST_KEY_AGREEMENT_INFO;

DECLARE_ASN1_FUNCTIONS(GOST_KEY_AGREEMENT_INFO)
	
typedef struct {
	GOST_KEY_INFO *key_info;
	GOST_KEY_AGREEMENT_INFO *key_agreement_info;
} GOST_KEY_TRANSPORT;

DECLARE_ASN1_FUNCTIONS(GOST_KEY_TRANSPORT)

typedef struct { //FIXME incomplete
	GOST_KEY_TRANSPORT *gkt;
} GOST_CLIENT_KEY_EXCHANGE_PARAMS;

DECLARE_ASN1_FUNCTIONS(GOST_CLIENT_KEY_EXCHANGE_PARAMS)
typedef struct {
	ASN1_OBJECT *key_params;
	ASN1_OBJECT *hash_params;
	ASN1_OBJECT *cipher_params;
} GOST_KEY_PARAMS;

DECLARE_ASN1_FUNCTIONS(GOST_KEY_PARAMS)

typedef struct {
	ASN1_OCTET_STRING *iv;
	ASN1_OBJECT *enc_param_set;
} GOST_CIPHER_PARAMS; 

DECLARE_ASN1_FUNCTIONS(GOST_CIPHER_PARAMS)

#endif
