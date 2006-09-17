#ifndef GOST_PMETH_H
#define GOST_PMETH_H
/**********************************************************************
 *                             pmeth.h                                *
 *             Copyright (c) 2006 Cryptocom LTD                       *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 *	Declaration of GOST PKEY context internal data                    *
 *																	  *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <openssl/bn.h>
#include <openssl/evp.h>

/* Gost-specific control-function parameters */
#define param_ctrl_string "paramset"
#define EVP_PKEY_CTRL_GOST_PARAMSET (EVP_PKEY_ALG_CTRL+1)

	struct gost_pmeth_data {
   	    int sign_param_nid; /* Should be set whenever parameters are filled */
		int crypt_param_nid;
		EVP_PKEY *eph_seckey;
		EVP_MD *md;
	};

#endif
