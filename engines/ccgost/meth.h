#ifndef CCE_METH_H
#define CCE_METH_H
/**********************************************************************
 *                             meth.h                                 *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 *	Declaration of method registration functions                      *
 *																	  *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/

#ifdef __cplusplus
extern "C" {
#endif
	int register_ameth_gost (int nid, EVP_PKEY_ASN1_METHOD **ameth, const char* pemstr, const char* info);
	int register_pmeth_gost (int id, EVP_PKEY_METHOD **pmeth, int flags);
#ifdef __cplusplus
	  };
#endif

#endif
