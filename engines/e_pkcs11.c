/*
 * Copyright 1999-2001 The OpenSSL Project Authors. All Rights Reserved.
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 * Portions Copyright (c) 2003 Kevin Stefanik (kstef@mtppi.org)
 * Copied/modified by Kevin Stefanik (kstef@mtppi.org) for the OpenSC
 * project 2003.
 * Copyright (c) 2016-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_pkcs11.h"
#include <stdio.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#ifndef ENGINE_CMD_BASE
#error did not get e_pkcs11.h
#endif

#define PKCS11_ENGINE_ID "pkcs11"
#define PKCS11_ENGINE_NAME "pkcs11 engine"

static int pkcs11_idx = -1;

/* The definitions for control commands specific to this engine */

/* need to add function to pass in reader id? or user reader:key as key id string? */

static const ENGINE_CMD_DEFN engine_cmd_defns[] = {
	{CMD_SO_PATH,
		"SO_PATH",
		"Specifies the path to the 'pkcs11' engine shared library",
		ENGINE_CMD_FLAG_STRING},
	{CMD_MODULE_PATH,
		"MODULE_PATH",
		"Specifies the path to the PKCS#11 module shared library",
		ENGINE_CMD_FLAG_STRING},
	{CMD_PIN,
		"PIN",
		"Specifies the pin code",
		ENGINE_CMD_FLAG_STRING},
	{CMD_VERBOSE,
		"VERBOSE",
		"Print additional details",
		ENGINE_CMD_FLAG_NO_INPUT},
	{CMD_QUIET,
		"QUIET",
		"Remove additional details",
		ENGINE_CMD_FLAG_NO_INPUT},
	{CMD_LOAD_CERT_CTRL,
		"LOAD_CERT_CTRL",
		"Get the certificate from card",
		ENGINE_CMD_FLAG_INTERNAL},
	{CMD_INIT_ARGS,
		"INIT_ARGS",
		"Specifies additional initialization arguments to the PKCS#11 module",
		ENGINE_CMD_FLAG_STRING},
	{CMD_SET_USER_INTERFACE,
		"SET_USER_INTERFACE",
		"Set the global user interface (internal)",
		ENGINE_CMD_FLAG_INTERNAL},
	{CMD_SET_CALLBACK_DATA,
		"SET_CALLBACK_DATA",
		"Set the global user interface extra data (internal)",
		ENGINE_CMD_FLAG_INTERNAL},
	{CMD_FORCE_LOGIN,
		"FORCE_LOGIN",
		"Force login to the PKCS#11 module",
		ENGINE_CMD_FLAG_NO_INPUT},
	{0, NULL, NULL, 0}
};

static ENGINE_CTX *get_ctx(ENGINE *engine)
{
	ENGINE_CTX *ctx;

	if (pkcs11_idx < 0) {
		pkcs11_idx = ENGINE_get_ex_new_index(0, "pkcs11", NULL, NULL, 0);
		if (pkcs11_idx < 0)
			return NULL;
		ctx = NULL;
	} else {
		ctx = ENGINE_get_ex_data(engine, pkcs11_idx);
	}
	if (ctx == NULL) {
		ctx = ctx_new();
		ENGINE_set_ex_data(engine, pkcs11_idx, ctx);
	}
	return ctx;
}

/* Destroy the context allocated with ctx_new() */
static int engine_destroy(ENGINE *engine)
{
	ENGINE_CTX *ctx;
	int rv = 1;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;

	/* ENGINE_remove() invokes our engine_destroy() function with
	 * CRYPTO_LOCK_ENGINE / global_engine_lock acquired.
	 * Any attempt to re-acquire the lock either by directly
	 * invoking OpenSSL functions, or indirectly via PKCS#11 modules
	 * that use OpenSSL engines, causes a deadlock. */
	/* Our workaround is to skip ctx_finish() entirely, as a memory
	 * leak is better than a deadlock. */
#if 0
	rv &= ctx_finish(ctx);
#endif

	rv &= ctx_destroy(ctx);
	ENGINE_set_ex_data(engine, pkcs11_idx, NULL);
	ERR_unload_ENG_strings();
	return rv;
}

static int engine_init(ENGINE *engine)
{
	ENGINE_CTX *ctx;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	return ctx_init(ctx);
}

/* Finish engine operations initialized with ctx_init() */
static int engine_finish(ENGINE *engine)
{
	ENGINE_CTX *ctx;
	int rv = 1;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;

	/* ENGINE_cleanup() used by OpenSSL versions before 1.1.0 invokes
	 * our engine_finish() function with CRYPTO_LOCK_ENGINE acquired.
	 * Any attempt to re-acquire CRYPTO_LOCK_ENGINE either by directly
	 * invoking OpenSSL functions, or indirectly via PKCS#11 modules
	 * that use OpenSSL engines, causes a deadlock. */
	/* Our workaround is to skip ctx_finish() for the affected OpenSSL
	 * versions, as a memory leak is better than a deadlock. */
	/* We cannot simply temporarily release CRYPTO_LOCK_ENGINE here, as
	 * engine_finish() is also executed from ENGINE_finish() without
	 * acquired CRYPTO_LOCK_ENGINE, and there is no way with to check
	 * whether a lock is already acquired with OpenSSL < 1.1.0 API. */
#if OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER)
	rv &= ctx_finish(ctx);
#endif

	return rv;
}

static EVP_PKEY *load_pubkey(ENGINE *engine, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	ENGINE_CTX *ctx;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	return ctx_load_pubkey(ctx, s_key_id, ui_method, callback_data);
}

static EVP_PKEY *load_privkey(ENGINE *engine, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	ENGINE_CTX *ctx;
	EVP_PKEY *pkey;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	pkey = ctx_load_privkey(ctx, s_key_id, ui_method, callback_data);
#ifdef EVP_F_EVP_PKEY_SET1_ENGINE
	/* EVP_PKEY_set1_engine() is required for OpenSSL 1.1.x,
	 * but otherwise setting pkey->engine breaks OpenSSL 1.0.2 */
	if (pkey && !EVP_PKEY_set1_engine(pkey, engine)) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
#endif /* EVP_F_EVP_PKEY_SET1_ENGINE */
	return pkey;
}

static int engine_ctrl(ENGINE *engine, int cmd, long i, void *p, void (*f) ())
{
	ENGINE_CTX *ctx;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	return ctx_engine_ctrl(ctx, cmd, i, p, f);
}

/* This internal function is used by ENGINE_pkcs11() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE *e)
{
	if (!ENGINE_set_id(e, PKCS11_ENGINE_ID) ||
			!ENGINE_set_destroy_function(e, engine_destroy) ||
			!ENGINE_set_init_function(e, engine_init) ||
			!ENGINE_set_finish_function(e, engine_finish) ||
			!ENGINE_set_ctrl_function(e, engine_ctrl) ||
			!ENGINE_set_cmd_defns(e, engine_cmd_defns) ||
			!ENGINE_set_name(e, PKCS11_ENGINE_NAME) ||
#ifndef OPENSSL_NO_RSA
			!ENGINE_set_RSA(e, PKCS11_get_rsa_method()) ||
#endif
#if OPENSSL_VERSION_NUMBER  >= 0x10100002L
#ifndef OPENSSL_NO_EC
			/* PKCS11_get_ec_key_method combines ECDSA and ECDH */
			!ENGINE_set_EC(e, PKCS11_get_ec_key_method()) ||
#endif /* OPENSSL_NO_EC */
#else /* OPENSSL_VERSION_NUMBER */
#ifndef OPENSSL_NO_ECDSA
			!ENGINE_set_ECDSA(e, PKCS11_get_ecdsa_method()) ||
#endif
#ifndef OPENSSL_NO_ECDH
			!ENGINE_set_ECDH(e, PKCS11_get_ecdh_method()) ||
#endif
#endif /* OPENSSL_VERSION_NUMBER */
			!ENGINE_set_pkey_meths(e, PKCS11_pkey_meths) ||
			!ENGINE_set_load_pubkey_function(e, load_pubkey) ||
			!ENGINE_set_load_privkey_function(e, load_privkey)) {
		return 0;
	} else {
		ERR_load_ENG_strings();
		return 1;
	}
}

static int bind_fn(ENGINE *e, const char *id)
{
	if (id && (strcmp(id, PKCS11_ENGINE_ID) != 0)) {
		fprintf(stderr, "bad engine id\n");
		return 0;
	}
	if (!bind_helper(e)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)

/* vim: set noexpandtab: */
