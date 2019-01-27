/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include "libp11-int.h"
#include <string.h>

/*
 * Create a new context
 */
PKCS11_CTX *pkcs11_CTX_new(void)
{
	PKCS11_CTX_private *cpriv = NULL;
	PKCS11_CTX *ctx = NULL;

	/* Load error strings */
	ERR_load_PKCS11_strings();

	cpriv = OPENSSL_malloc(sizeof(PKCS11_CTX_private));
	if (cpriv == NULL)
		goto fail;
	memset(cpriv, 0, sizeof(PKCS11_CTX_private));
	ctx = OPENSSL_malloc(sizeof(PKCS11_CTX));
	if (ctx == NULL)
		goto fail;
	memset(ctx, 0, sizeof(PKCS11_CTX));
	ctx->_private = cpriv;
	cpriv->forkid = get_forkid();
	cpriv->rwlock = CRYPTO_THREAD_lock_new();
	cpriv->sign_initialized = 0;
	cpriv->decrypt_initialized = 0;

	return ctx;
fail:
	OPENSSL_free(cpriv);
	OPENSSL_free(ctx);
	return NULL;
}

/*
 * Set private init args for module
 */
void pkcs11_CTX_init_args(PKCS11_CTX *ctx, const char *init_args)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	/* Free previously duplicated string */
	if (cpriv->init_args) {
		OPENSSL_free(cpriv->init_args);
	}
	cpriv->init_args = init_args ? OPENSSL_strdup(init_args) : NULL;
}

/*
 * Load the shared library, and initialize it.
 */
int pkcs11_CTX_load(PKCS11_CTX *ctx, const char *name)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	CK_C_INITIALIZE_ARGS args;
	CK_INFO ck_info;
	int rv;

	cpriv->handle = C_LoadModule(name, &cpriv->method);
	if (cpriv->handle == NULL) {
		P11err(P11_F_PKCS11_CTX_LOAD, P11_R_LOAD_MODULE_ERROR);
		return -1;
	}

	/* Tell the PKCS11 to initialize itself */
	memset(&args, 0, sizeof(args));
	/* Unconditionally say using OS locking primitives is OK */
	args.flags |= CKF_OS_LOCKING_OK;
	args.pReserved = cpriv->init_args;
	rv = cpriv->method->C_Initialize(&args);
	if (rv && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		C_UnloadModule(cpriv->handle);
		cpriv->handle = NULL;
		CKRerr(P11_F_PKCS11_CTX_LOAD, rv);
		return -1;
	}

	/* Get info on the library */
	rv = cpriv->method->C_GetInfo(&ck_info);
	if (rv) {
		cpriv->method->C_Finalize(NULL);
		C_UnloadModule(cpriv->handle);
		cpriv->handle = NULL;
		CKRerr(P11_F_PKCS11_CTX_LOAD, rv);
		return -1;
	}

	ctx->manufacturer = PKCS11_DUP(ck_info.manufacturerID);
	ctx->description = PKCS11_DUP(ck_info.libraryDescription);

	return 0;
}

/*
 * Reinitialize (e.g., after a fork).
 */
int pkcs11_CTX_reload(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	CK_C_INITIALIZE_ARGS _args;
	CK_C_INITIALIZE_ARGS *args = NULL;
	int rv;

	if (cpriv->method == NULL) /* Module not loaded */
		return 0;

	/* Tell the PKCS11 to initialize itself */
	if (cpriv->init_args != NULL) {
		memset(&_args, 0, sizeof(_args));
		args = &_args;
		args->pReserved = cpriv->init_args;
	}
	rv = cpriv->method->C_Initialize(args);
	if (rv && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		CKRerr(P11_F_PKCS11_CTX_RELOAD, rv);
		return -1;
	}

	return 0;
}

/*
 * Unload the shared library
 */
void pkcs11_CTX_unload(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	/* Tell the PKCS11 library to shut down */
	if (cpriv->forkid == get_forkid())
		cpriv->method->C_Finalize(NULL);

	/* Unload the module */
	C_UnloadModule(cpriv->handle);
	cpriv->handle = NULL;
}

/*
 * Free a context
 */
void pkcs11_CTX_free(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	/* TODO: Move the global methods and ex_data indexes into
	 * the ctx structure, so they can be safely deallocated here:
	PKCS11_rsa_method_free(ctx);
	PKCS11_ecdsa_method_free(ctx);
	*/
	if (cpriv->init_args) {
		OPENSSL_free(cpriv->init_args);
	}
	if (cpriv->handle) {
		OPENSSL_free(cpriv->handle);
	}
	CRYPTO_THREAD_lock_free(cpriv->rwlock);
	OPENSSL_free(ctx->manufacturer);
	OPENSSL_free(ctx->description);
	OPENSSL_free(ctx->_private);
	OPENSSL_free(ctx);
}

/* vim: set noexpandtab: */
