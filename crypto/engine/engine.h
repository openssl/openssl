/* openssl/engine.h */
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

#ifndef HEADER_ENGINE_H
#define HEADER_ENGINE_H

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/symhacks.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* These flags are used to control combinations of algorithm (methods)
 * by bitwise "OR"ing. */
#define ENGINE_METHOD_RSA		(unsigned int)0x0001
#define ENGINE_METHOD_DSA		(unsigned int)0x0002
#define ENGINE_METHOD_DH		(unsigned int)0x0004
#define ENGINE_METHOD_RAND		(unsigned int)0x0008
#define ENGINE_METHOD_BN_MOD_EXP	(unsigned int)0x0010
#define ENGINE_METHOD_BN_MOD_EXP_CRT	(unsigned int)0x0020
/* Obvious all-or-nothing cases. */
#define ENGINE_METHOD_ALL		(unsigned int)0xFFFF
#define ENGINE_METHOD_NONE		(unsigned int)0x0000

/* These flags are used to tell the ctrl function what should be done.
 * All command numbers are shared between all engines, even if some don't
 * make sense to some engines.  In such a case, they do nothing but return
 * the error ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED. */
#define ENGINE_CTRL_SET_LOGSTREAM		1
#define ENGINE_CTRL_SET_PASSWORD_CALLBACK	2
/* Flags specific to the nCipher "chil" engine */
#define ENGINE_CTRL_CHIL_SET_FORKCHECK		100
	/* Depending on the value of the (long)i argument, this sets or
	 * unsets the SimpleForkCheck flag in the CHIL API to enable or
	 * disable checking and workarounds for applications that fork().
	 */
#define ENGINE_CTRL_CHIL_NO_LOCKING		101
	/* This prevents the initialisation function from providing mutex
	 * callbacks to the nCipher library. */

/* As we're missing a BIGNUM_METHOD, we need a couple of locally
 * defined function types that engines can implement. */

#ifndef HEADER_ENGINE_INT_H
/* mod_exp operation, calculates; r = a ^ p mod m
 * NB: ctx can be NULL, but if supplied, the implementation may use
 * it if it wishes. */
typedef int (*BN_MOD_EXP)(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx);

/* private key operation for RSA, provided seperately in case other
 * RSA implementations wish to use it. */
typedef int (*BN_MOD_EXP_CRT)(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *q, const BIGNUM *dmp1, const BIGNUM *dmq1,
		const BIGNUM *iqmp, BN_CTX *ctx);

/* Generic function pointer */
typedef void (*ENGINE_GEN_FUNC_PTR)();
/* Generic function pointer taking no arguments */
typedef void (*ENGINE_GEN_INT_FUNC_PTR)(void);
/* Specific control function pointer */
typedef int (*ENGINE_CTRL_FUNC_PTR)(int cmd, long i, void *p, void (*f)());

/* The list of "engine" types is a static array of (const ENGINE*)
 * pointers (not dynamic because static is fine for now and we otherwise
 * have to hook an appropriate load/unload function in to initialise and
 * cleanup). */
typedef struct engine_st ENGINE;
#endif

/* STRUCTURE functions ... all of these functions deal with pointers to
 * ENGINE structures where the pointers have a "structural reference".
 * This means that their reference is to allow access to the structure
 * but it does not imply that the structure is functional. To simply
 * increment or decrement the structural reference count, use ENGINE_new
 * and ENGINE_free. NB: This is not required when iterating using
 * ENGINE_get_next as it will automatically decrement the structural
 * reference count of the "current" ENGINE and increment the structural
 * reference count of the ENGINE it returns (unless it is NULL). */

/* Get the first/last "ENGINE" type available. */
ENGINE *ENGINE_get_first(void);
ENGINE *ENGINE_get_last(void);
/* Iterate to the next/previous "ENGINE" type (NULL = end of the list). */
ENGINE *ENGINE_get_next(ENGINE *e);
ENGINE *ENGINE_get_prev(ENGINE *e);
/* Add another "ENGINE" type into the array. */
int ENGINE_add(ENGINE *e);
/* Remove an existing "ENGINE" type from the array. */
int ENGINE_remove(ENGINE *e);
/* Retrieve an engine from the list by its unique "id" value. */
ENGINE *ENGINE_by_id(const char *id);

/* These functions are useful for manufacturing new ENGINE
 * structures. They don't address reference counting at all -
 * one uses them to populate an ENGINE structure with personalised
 * implementations of things prior to using it directly or adding
 * it to the builtin ENGINE list in OpenSSL. These are also here
 * so that the ENGINE structure doesn't have to be exposed and
 * break binary compatibility!
 *
 * NB: I'm changing ENGINE_new to force the ENGINE structure to
 * be allocated from within OpenSSL. See the comment for
 * ENGINE_get_struct_size().
 */
#if 0
ENGINE *ENGINE_new(ENGINE *e);
#else
ENGINE *ENGINE_new(void);
#endif
int ENGINE_free(ENGINE *e);
int ENGINE_set_id(ENGINE *e, const char *id);
int ENGINE_set_name(ENGINE *e, const char *name);
int ENGINE_set_RSA(ENGINE *e, RSA_METHOD *rsa_meth);
int ENGINE_set_DSA(ENGINE *e, DSA_METHOD *dsa_meth);
int ENGINE_set_DH(ENGINE *e, DH_METHOD *dh_meth);
int ENGINE_set_RAND(ENGINE *e, RAND_METHOD *rand_meth);
int ENGINE_set_BN_mod_exp(ENGINE *e, BN_MOD_EXP bn_mod_exp);
int ENGINE_set_BN_mod_exp_crt(ENGINE *e, BN_MOD_EXP_CRT bn_mod_exp_crt);
int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f);
int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f);
int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f);

/* These return values from within the ENGINE structure. These can
 * be useful with functional references as well as structural
 * references - it depends which you obtained. Using the result
 * for functional purposes if you only obtained a structural
 * reference may be problematic! */
const char *ENGINE_get_id(ENGINE *e);
const char *ENGINE_get_name(ENGINE *e);
RSA_METHOD *ENGINE_get_RSA(ENGINE *e);
DSA_METHOD *ENGINE_get_DSA(ENGINE *e);
DH_METHOD *ENGINE_get_DH(ENGINE *e);
RAND_METHOD *ENGINE_get_RAND(ENGINE *e);
BN_MOD_EXP ENGINE_get_BN_mod_exp(ENGINE *e);
BN_MOD_EXP_CRT ENGINE_get_BN_mod_exp_crt(ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(ENGINE *e);
ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(ENGINE *e);

/* ENGINE_new is normally passed a NULL in the first parameter because
 * the calling code doesn't have access to the definition of the ENGINE
 * structure (for good reason). However, if the caller wishes to use
 * its own memory allocation or use a static array, the following call
 * should be used to check the amount of memory the ENGINE structure
 * will occupy. This will make the code more future-proof.
 *
 * NB: I'm "#if 0"-ing this out because it's better to force the use of
 * internally allocated memory. See similar change in ENGINE_new().
 */
#if 0
int ENGINE_get_struct_size(void);
#endif

/* FUNCTIONAL functions. These functions deal with ENGINE structures
 * that have (or will) be initialised for use. Broadly speaking, the
 * structural functions are useful for iterating the list of available
 * engine types, creating new engine types, and other "list" operations.
 * These functions actually deal with ENGINEs that are to be used. As
 * such these functions can fail (if applicable) when particular
 * engines are unavailable - eg. if a hardware accelerator is not
 * attached or not functioning correctly. Each ENGINE has 2 reference
 * counts; structural and functional. Every time a functional reference
 * is obtained or released, a corresponding structural reference is
 * automatically obtained or released too. */

/* Initialise a engine type for use (or up its reference count if it's
 * already in use). This will fail if the engine is not currently
 * operational and cannot initialise. */
int ENGINE_init(ENGINE *e);
/* Free a functional reference to a engine type. This does not require
 * a corresponding call to ENGINE_free as it also releases a structural
 * reference. */
int ENGINE_finish(ENGINE *e);
/* Send control parametrised commands to the engine.  The possibilities
 * to send down an integer, a pointer to data or a function pointer are
 * provided.  Any of the parameters may or may not be NULL, depending
 * on the command number */
/* WARNING: This is currently experimental and may change radically! */
int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)());

/* The following functions handle keys that are stored in some secondary
 * location, handled by the engine.  The storage may be on a card or
 * whatever. */
EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id,
	const char *passphrase);
EVP_PKEY *ENGINE_load_public_key(ENGINE *e, const char *key_id,
	const char *passphrase);

/* This returns a pointer for the current ENGINE structure that
 * is (by default) performing any RSA operations. The value returned
 * is an incremented reference, so it should be free'd (ENGINE_finish)
 * before it is discarded. */
ENGINE *ENGINE_get_default_RSA(void);
/* Same for the other "methods" */
ENGINE *ENGINE_get_default_DSA(void);
ENGINE *ENGINE_get_default_DH(void);
ENGINE *ENGINE_get_default_RAND(void);
ENGINE *ENGINE_get_default_BN_mod_exp(void);
ENGINE *ENGINE_get_default_BN_mod_exp_crt(void);

/* This sets a new default ENGINE structure for performing RSA
 * operations. If the result is non-zero (success) then the ENGINE
 * structure will have had its reference count up'd so the caller
 * should still free their own reference 'e'. */
int ENGINE_set_default_RSA(ENGINE *e);
/* Same for the other "methods" */
int ENGINE_set_default_DSA(ENGINE *e);
int ENGINE_set_default_DH(ENGINE *e);
int ENGINE_set_default_RAND(ENGINE *e);
int ENGINE_set_default_BN_mod_exp(ENGINE *e);
int ENGINE_set_default_BN_mod_exp_crt(ENGINE *e);

/* The combination "set" - the flags are bitwise "OR"d from the
 * ENGINE_METHOD_*** defines above. */
int ENGINE_set_default(ENGINE *e, unsigned int flags);

/* Obligatory error function. */
void ERR_load_ENGINE_strings(void);

/*
 * Error codes for all engine functions. NB: We use "generic"
 * function names instead of per-implementation ones because this
 * levels the playing field for externally implemented bootstrapped
 * support code. As the filename and line number is included, it's
 * more important to indicate the type of function, so that
 * bootstrapped code (that can't easily add its own errors in) can
 * use the same error codes too.
 */

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

/* Error codes for the ENGINE functions. */

/* Function codes. */
#define ENGINE_F_ATALLA_FINISH				 135
#define ENGINE_F_ATALLA_INIT				 136
#define ENGINE_F_ATALLA_MOD_EXP				 137
#define ENGINE_F_ATALLA_RSA_MOD_EXP			 138
#define ENGINE_F_CSWIFT_DSA_SIGN			 133
#define ENGINE_F_CSWIFT_DSA_VERIFY			 134
#define ENGINE_F_CSWIFT_FINISH				 100
#define ENGINE_F_CSWIFT_INIT				 101
#define ENGINE_F_CSWIFT_MOD_EXP				 102
#define ENGINE_F_CSWIFT_MOD_EXP_CRT			 103
#define ENGINE_F_CSWIFT_RSA_MOD_EXP			 104
#define ENGINE_F_ENGINE_ADD				 105
#define ENGINE_F_ENGINE_BY_ID				 106
#define ENGINE_F_ENGINE_CTRL				 142
#define ENGINE_F_ENGINE_FINISH				 107
#define ENGINE_F_ENGINE_FREE				 108
#define ENGINE_F_ENGINE_GET_BN_MOD_EXP			 109
#define ENGINE_F_ENGINE_GET_BN_MOD_EXP_CRT		 110
#define ENGINE_F_ENGINE_GET_CTRL_FUNCTION		 144
#define ENGINE_F_ENGINE_GET_DH				 111
#define ENGINE_F_ENGINE_GET_DSA				 112
#define ENGINE_F_ENGINE_GET_FINISH_FUNCTION		 145
#define ENGINE_F_ENGINE_GET_ID				 113
#define ENGINE_F_ENGINE_GET_INIT_FUNCTION		 146
#define ENGINE_F_ENGINE_GET_NAME			 114
#define ENGINE_F_ENGINE_GET_NEXT			 115
#define ENGINE_F_ENGINE_GET_PREV			 116
#define ENGINE_F_ENGINE_GET_RAND			 117
#define ENGINE_F_ENGINE_GET_RSA				 118
#define ENGINE_F_ENGINE_INIT				 119
#define ENGINE_F_ENGINE_LIST_ADD			 120
#define ENGINE_F_ENGINE_LIST_REMOVE			 121
#define ENGINE_F_ENGINE_LOAD_PRIVATE_KEY		 150
#define ENGINE_F_ENGINE_LOAD_PUBLIC_KEY			 151
#define ENGINE_F_ENGINE_NEW				 122
#define ENGINE_F_ENGINE_REMOVE				 123
#define ENGINE_F_ENGINE_SET_BN_MOD_EXP			 124
#define ENGINE_F_ENGINE_SET_BN_MOD_EXP_CRT		 125
#define ENGINE_F_ENGINE_SET_CTRL_FUNCTION		 147
#define ENGINE_F_ENGINE_SET_DEFAULT_TYPE		 126
#define ENGINE_F_ENGINE_SET_DH				 127
#define ENGINE_F_ENGINE_SET_DSA				 128
#define ENGINE_F_ENGINE_SET_FINISH_FUNCTION		 148
#define ENGINE_F_ENGINE_SET_ID				 129
#define ENGINE_F_ENGINE_SET_INIT_FUNCTION		 149
#define ENGINE_F_ENGINE_SET_NAME			 130
#define ENGINE_F_ENGINE_SET_RAND			 131
#define ENGINE_F_ENGINE_SET_RSA				 132
#define ENGINE_F_ENGINE_UNLOAD_KEY			 152
#define ENGINE_F_HWCRHK_CTRL				 143
#define ENGINE_F_HWCRHK_FINISH				 135
#define ENGINE_F_HWCRHK_GET_PASS			 155
#define ENGINE_F_HWCRHK_INIT				 136
#define ENGINE_F_HWCRHK_LOAD_PRIVKEY			 153
#define ENGINE_F_HWCRHK_LOAD_PUBKEY			 154
#define ENGINE_F_HWCRHK_MOD_EXP				 137
#define ENGINE_F_HWCRHK_MOD_EXP_CRT			 138
#define ENGINE_F_HWCRHK_RAND_BYTES			 139
#define ENGINE_F_HWCRHK_RSA_MOD_EXP			 140
#define ENGINE_F_LOG_MESSAGE				 141

/* Reason codes. */
#define ENGINE_R_ALREADY_LOADED				 100
#define ENGINE_R_BIO_WAS_FREED				 121
#define ENGINE_R_BN_CTX_FULL				 101
#define ENGINE_R_BN_EXPAND_FAIL				 102
#define ENGINE_R_CHIL_ERROR				 123
#define ENGINE_R_CONFLICTING_ENGINE_ID			 103
#define ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED		 119
#define ENGINE_R_DSO_FAILURE				 104
#define ENGINE_R_ENGINE_IS_NOT_IN_LIST			 105
#define ENGINE_R_FAILED_LOADING_PRIVATE_KEY		 128
#define ENGINE_R_FAILED_LOADING_PUBLIC_KEY		 129
#define ENGINE_R_FINISH_FAILED				 106
#define ENGINE_R_GET_HANDLE_FAILED			 107
#define ENGINE_R_ID_OR_NAME_MISSING			 108
#define ENGINE_R_INIT_FAILED				 109
#define ENGINE_R_INTERNAL_LIST_ERROR			 110
#define ENGINE_R_MISSING_KEY_COMPONENTS			 111
#define ENGINE_R_NOT_INITIALISED			 117
#define ENGINE_R_NOT_LOADED				 112
#define ENGINE_R_NO_CALLBACK				 127
#define ENGINE_R_NO_CONTROL_FUNCTION			 120
#define ENGINE_R_NO_KEY					 124
#define ENGINE_R_NO_LOAD_FUNCTION			 125
#define ENGINE_R_NO_REFERENCE				 130
#define ENGINE_R_NO_SUCH_ENGINE				 116
#define ENGINE_R_NO_UNLOAD_FUNCTION			 126
#define ENGINE_R_PROVIDE_PARAMETERS			 113
#define ENGINE_R_REQUEST_FAILED				 114
#define ENGINE_R_REQUEST_FALLBACK			 118
#define ENGINE_R_SIZE_TOO_LARGE_OR_TOO_SMALL		 122
#define ENGINE_R_UNIT_FAILURE				 115

#ifdef  __cplusplus
}
#endif
#endif

