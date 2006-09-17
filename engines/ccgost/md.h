#ifndef GOST_MD_H
#define GOST_MD_H
/**********************************************************************
 *                             md.h                                   *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 *	Declaration of GOST R 34.11 bindings to OpenSSL                   *
 *																	  *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "gost89.h"
#include "gosthash.h"
#ifdef __cplusplus
 extern "C" {
#endif

	 /* Structure used as EVP_MD_CTX-md_data. 
	  * It allows to avoid storing in the md-data pointers to
	  * dynamically allocated memory.
	  *
	  * I cannot invent better way to avoid memory leaks, because
	  * openssl insist on invoking Init on Final-ed digests, and there
	  * is no reliable way to find out whether pointer in the passed
	  * md_data is valid or not.
	  * */
struct ossl_gost_digest_ctx {
	gost_hash_ctx dctx;
	gost_ctx cctx;
};	

extern EVP_MD digest_gost;


#ifdef __cplusplus
  };
#endif
#endif
