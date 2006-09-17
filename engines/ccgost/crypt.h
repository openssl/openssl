/**********************************************************************
 *                        gost_crypt.h                                *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 *          Declarations for GOST 28147-89 encryption algorithm       *
 *            OpenSSL 0.9.9 libraries required                        *
 **********************************************************************/            
#ifndef GOST_CRYPT_H
#define GOST_CRYPT_H
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "gost89.h"
#ifdef __cplusplus
 extern "C" {
#endif
/* Cipher context used for EVP_CIPHER operation */
struct ossl_gost_cipher_ctx {
	int paramNID;
	off_t count;
	int key_meshing;
	gost_ctx cctx;
};	
/* Structure to map parameter NID to S-block */
struct gost_cipher_info {
	int nid;
	gost_subst_block *sblock;
	int key_meshing;
};
#ifdef USE_SSL
/* Context for MAC */
struct ossl_gost_imit_ctx {
	gost_ctx cctx;
	unsigned char buffer[8];
	unsigned char partial_block[8];
	off_t count;
	int key_meshing;
	int bytes_left;
	int key_set;
};	
#endif
/* Table which maps parameter NID to S-blocks */
extern struct gost_cipher_info gost_cipher_list[];
/* Find encryption params from ASN1_OBJECT */
const struct gost_cipher_info *get_encryption_params(ASN1_OBJECT *obj);
/* Implementation of GOST 28147-89 cipher in CFB and CNT modes */
extern EVP_CIPHER cipher_gost;
#ifdef USE_SSL
#define EVP_MD_FLAG_NEEDS_KEY 0x20
#define EVP_MD_CTRL_GET_TLS_MAC_KEY_LENGTH (EVP_MD_CTRL_ALG_CTRL+1)
#define EVP_MD_CTRL_SET_KEY (EVP_MD_CTRL_ALG_CTRL+2)
/* Ciphers and MACs specific for GOST TLS draft */
extern EVP_CIPHER cipher_gost_vizircfb;
extern EVP_CIPHER cipher_gost_cpacnt;
extern EVP_MD imit_gost_vizir;
extern EVP_MD imit_gost_cpa;
#endif
#ifdef __cplusplus
  };
#endif
#endif
