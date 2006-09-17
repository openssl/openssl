#ifndef GOST_SIGN_H
#define GOST_SIGN_H
/**********************************************************************
 *                        sign.h                                      *
 *             Copyright (c) 2006 Cryptocom LTD                       *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 *       Declaration of internal funtions implementing  GOST R 34.10  *
 * 	               signature and key generation                       *
 *         OpenSSL 0.9.9 libraries required to compile and use        *
 *                              this code                             *
 **********************************************************************/ 
#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
int fill_GOST94_params(DSA *dsa,int nid);
int fill_GOST2001_params(EC_KEY *eckey, int nid);
int gost_sign_keygen(DSA *dsa) ;
int gost2001_keygen(EC_KEY *ec) ;

DSA_SIG *gost_do_sign(const unsigned char *dgst,int dlen, DSA *dsa) ;
DSA_SIG *gost2001_do_sign(const unsigned char *dgst,int dlen, EC_KEY *eckey);

int gost_do_verify(const unsigned char *dgst, int dgst_len,
		DSA_SIG *sig, DSA *dsa) ;
int gost2001_do_verify(const unsigned char *dgst,int dgst_len,
			DSA_SIG *sig, EC_KEY *ec);
int gost2001_compute_public(EC_KEY *ec) ;
int gost94_compute_public(DSA *dsa) ;
#endif
