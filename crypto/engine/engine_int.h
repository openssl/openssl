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

/* Take public definitions from engine.h */
#include <openssl/engine.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* NB: Bitwise OR-able values for the "flags" variable in ENGINE are now exposed
 * in engine.h. */

/* This is a structure for storing implementations of various crypto
 * algorithms and functions. */
struct engine_st
	{
	const char *id;
	const char *name;
	const RSA_METHOD *rsa_meth;
	const DSA_METHOD *dsa_meth;
	const DH_METHOD *dh_meth;
	const RAND_METHOD *rand_meth;
	BN_MOD_EXP bn_mod_exp;
	BN_MOD_EXP_CRT bn_mod_exp_crt;
	ENGINE_GEN_INT_FUNC_PTR init;
	ENGINE_GEN_INT_FUNC_PTR finish;
	ENGINE_CTRL_FUNC_PTR ctrl;
	ENGINE_LOAD_KEY_PTR load_privkey;
	ENGINE_LOAD_KEY_PTR load_pubkey;
	const ENGINE_CMD_DEFN *cmd_defns;
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
	};

/* BUILT-IN ENGINES. (these functions are only ever called once and
 * do not return references - they are purely for bootstrapping). */

/* Returns a structure of software only methods (the default). */
ENGINE *ENGINE_openssl();

#ifndef OPENSSL_NO_HW

#ifndef OPENSSL_NO_HW_CSWIFT
/* Returns a structure of cswift methods ... NB: This can exist and be
 * "used" even on non-cswift systems because the "init" will fail if the
 * card/library are not found. */
ENGINE *ENGINE_cswift();
#endif /* !OPENSSL_NO_HW_CSWIFT */

#ifndef OPENSSL_NO_HW_NCIPHER
ENGINE *ENGINE_ncipher();
#endif /* !OPENSSL_NO_HW_NCIPHER */

#ifndef OPENSSL_NO_HW_ATALLA
/* Returns a structure of atalla methods. */
ENGINE *ENGINE_atalla();
#endif /* !OPENSSL_NO_HW_ATALLA */

#ifndef OPENSSL_NO_HW_NURON
ENGINE *ENGINE_nuron();
#endif /* !OPENSSL_NO_HW_NURON */

#ifndef OPENSSL_NO_HW_UBSEC
ENGINE *ENGINE_ubsec();
#endif /* !OPENSSL_NO_HW_UBSEC */

#endif /* !OPENSSL_NO_HW */

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_ENGINE_INT_H */
