/* crypto/engine/engine_int.h */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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

#ifndef HEADER_ENGINE_INT_H
#define HEADER_ENGINE_INT_H

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Bitwise OR-able values for the "flags" variable in ENGINE. */
#define ENGINE_FLAGS_MALLOCED	0x0001

#ifndef HEADER_ENGINE_H
/* Regrettably, we need to reproduce the "BN" function types here
 * because there is no such "BIGNUM_METHOD" as there is with RSA,
 * DSA, etc. We do this so that we don't have a case where engine.h
 * and engine_int.h conflict with each other. */
typedef int (*BN_MOD_EXP)(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx);
 
/* private key operation for RSA, provided seperately in case other
 * RSA implementations wish to use it. */
typedef int (*BN_MOD_EXP_CRT)(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *q, const BIGNUM *dmp1, const BIGNUM *dmq1,
		const BIGNUM *iqmp, BN_CTX *ctx);

/* Generic function pointer */
typedef int (*ENGINE_GEN_FUNC_PTR)();
/* Generic function pointer taking no arguments */
typedef int (*ENGINE_GEN_INT_FUNC_PTR)(void);
/* Specific control function pointer */
typedef int (*ENGINE_CTRL_FUNC_PTR)(int cmd, long i, void *p, void (*f)());

#endif

/* This is a structure for storing implementations of various crypto
 * algorithms and functions. */
typedef struct engine_st
	{
	const char *id;
	const char *name;
	RSA_METHOD *rsa_meth;
	DSA_METHOD *dsa_meth;
	DH_METHOD *dh_meth;
	RAND_METHOD *rand_meth;
	BN_MOD_EXP bn_mod_exp;
	BN_MOD_EXP_CRT bn_mod_exp_crt;
	int (*init)(void);
	int (*finish)(void);
	int (*ctrl)(int cmd, long i, void *p, void (*f)());
	EVP_PKEY *(*load_privkey)(const char *key_id, const char *passphrase);
	EVP_PKEY *(*load_pubkey)(const char *key_id, const char *passphrase);
	int flags;
	/* reference count on the structure itself */
	int struct_ref;
	/* reference count on usability of the engine type. NB: This
	 * controls the loading and initialisation of any functionlity
	 * required by this engine, whereas the previous count is
	 * simply to cope with (de)allocation of this structure. Hence,
	 * running_ref <= struct_ref at all times. */
	int funct_ref;
	/* Used to maintain the linked-list of engines. */
	struct engine_st *prev;
	struct engine_st *next;
	} ENGINE;

/* BUILT-IN ENGINES. (these functions are only ever called once and
 * do not return references - they are purely for bootstrapping). */

/* Returns a structure of software only methods (the default). */
ENGINE *ENGINE_openssl();

#ifndef NO_HW

#ifndef NO_HW_CSWIFT
/* Returns a structure of cswift methods ... NB: This can exist and be
 * "used" even on non-cswift systems because the "init" will fail if the
 * card/library are not found. */
ENGINE *ENGINE_cswift();
#endif /* !NO_HW_CSWIFT */

#ifndef NO_HW_NCIPHER
ENGINE *ENGINE_ncipher();
#endif /* !NO_HW_NCIPHER */

#ifndef NO_HW_ATALLA
/* Returns a structure of atalla methods. */
ENGINE *ENGINE_atalla();
#endif /* !NO_HW_ATALLA */

#endif /* !NO_HW */

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_ENGINE_INT_H */
