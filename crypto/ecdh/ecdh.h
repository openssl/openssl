/* crypto/ecdh/ecdh.h */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * In addition, Sun covenants to all licensees who provide a reciprocal
 * covenant with respect to their own patents if any, not to sue under
 * current and future patent claims necessarily infringed by the making,
 * using, practicing, selling, offering for sale and/or otherwise
 * disposing of the ECC Code as delivered hereunder (or portions thereof),
 * provided that such covenant shall not apply:
 *  1) for code that a licensee deletes from the ECC Code;
 *  2) separates from the ECC Code; or
 *  3) for infringements caused by:
 *       i) the modification of the ECC Code or
 *      ii) the combination of the ECC Code with other software or
 *          devices where such combination causes the infringement.
 *
 * The ECDH software is originally written by Douglas Stebila of
 * Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright (c) 2000-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
#ifndef HEADER_ECDH_H
#define HEADER_ECDH_H

#ifdef OPENSSL_NO_ECDH
#error ECDH is disabled.
#endif

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ecdh_method 
{
	const char *name;
	int (*compute_key)(unsigned char *key,const EC_POINT *pub_key, EC_KEY *ecdh);
#if 0
	int (*init)(EC_KEY *eckey);
	int (*finish)(EC_KEY *eckey);
#endif
	int flags;
	char *app_data;
} ECDH_METHOD;

typedef struct ecdh_data_st {
	/* EC_KEY_METH_DATA part */
	int (*init)(EC_KEY *);
	void (*finish)(EC_KEY *);
	/* method specific part */
	ENGINE	*engine;
	int	flags;
	const ECDH_METHOD *meth;
	CRYPTO_EX_DATA ex_data;
} ECDH_DATA; 

/* ECDH_DATA functions */
ECDH_DATA *ECDH_DATA_new(void);
ECDH_DATA *ECDH_DATA_new_method(ENGINE *);
void ECDH_DATA_free(ECDH_DATA *);

ECDH_DATA *ecdh_check(EC_KEY *);


const ECDH_METHOD *ECDH_OpenSSL(void);

void	  ECDH_set_default_method(const ECDH_METHOD *);
const ECDH_METHOD *ECDH_get_default_method(void);
int 	  ECDH_set_method(EC_KEY *, const ECDH_METHOD *);

int	  ECDH_size(const EC_KEY *);
int ECDH_compute_key(unsigned char *key,const EC_POINT *pub_key, EC_KEY *ecdh);


int 	  ECDH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new 
		*new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int 	  ECDH_set_ex_data(EC_KEY *d, int idx, void *arg);
void 	  *ECDH_get_ex_data(EC_KEY *d, int idx);


/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_ECDH_strings(void);

/* Error codes for the ECDH functions. */

/* Function codes. */
#define ECDH_F_ECDH_COMPUTE_KEY				 100
#define ECDH_F_ECDH_DATA_NEW				 101

/* Reason codes. */
#define ECDH_R_NO_PRIVATE_VALUE				 100
#define ECDH_R_POINT_ARITHMETIC_FAILURE			 101
#define ECDH_R_SHA1_DIGEST_FAILED			 102

#ifdef  __cplusplus
}
#endif
#endif
