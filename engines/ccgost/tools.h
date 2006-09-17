#ifndef GOST_TOOLS_H
#define GOST_TOOLS_H
/**********************************************************************
 *                        sign.h                                      *
 *             Copyright (c) 2006 Cryptocom LTD                       *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 *         Miscellaneous functions used in GOST engine                *
 *         OpenSSL 0.9.9 libraries required to compile and use        *
 *                              this code                             *
 **********************************************************************/ 
#include <openssl/evp.h>
#include <openssl/dsa.h>

/* from gost_sign.c */
/* Convert GOST R 34.11 hash sum to bignum according to standard */
BIGNUM *hashsum2bn(const unsigned char *dgst) ;
/* Store bignum in byte array of given length, prepending by zeros
 * if nesseccary */
int store_bignum(BIGNUM *bn, unsigned char *buf,int len);
/* Read bignum, which can have few MSB all-zeros    from buffer*/ 
BIGNUM *getbnfrombuf(const unsigned char *buf,size_t len);
/* Pack GOST R 34.10 signature according to CryptoCom rules */
int pack_sign_cc(DSA_SIG *s,int order,unsigned char *sig, unsigned int *siglen);
/* Pack GOST R 34.10 signature according to CryptoPro rules */
int pack_sign_cp(DSA_SIG *s,int order,unsigned char *sig, unsigned int *siglen); 
/* Unpack GOST R 34.10 signature according to CryptoCom rules */
DSA_SIG *unpack_cc_signature(const unsigned char *sig,size_t siglen) ;
/* Unpack GOST R 34.10 signature according to CryptoPro rules */
DSA_SIG *unpack_cp_signature(const unsigned char *sig,size_t siglen) ;
/* from ameth.c */
/* Get private key as BIGNUM from both R 34.10-94 and R 34.10-2001  keys*/
BIGNUM* gost_get_priv_key(const EVP_PKEY *pkey) ;
/* Find NID by GOST 94 parameters */
int gost94_nid_by_params(DSA *p) ;


#endif
