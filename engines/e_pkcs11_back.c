/*
 * Copyright (c) 2001 Markus Friedl
 * Copyright (c) 2002 Juha Yrjölä
 * Copyright (c) 2002 Olaf Kirch
 * Copyright (c) 2003 Kevin Stefanik
 * Copyright (c) 2016-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "e_pkcs11.h"
#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#define strncasecmp _strnicmp
#endif

/* The maximum length of an internally-allocated PIN */
#define MAX_PIN_LENGTH   32
#define MAX_VALUE_LEN	200

struct st_engine_ctx {
	/* Engine configuration */
	/*
	 * The PIN used for login. Cache for the ctx_get_pin function.
	 * The memory for this PIN is always owned internally,
	 * and may be freed as necessary. Before freeing, the PIN
	 * must be whitened, to prevent security holes.
	 */
	char *pin;
	size_t pin_length;
	int verbose;
	char *module;
	char *init_args;
	UI_METHOD *ui_method;
	void *callback_data;
	int force_login;

	/* Engine initialization mutex */
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	CRYPTO_RWLOCK *rwlock;
#else
	int rwlock;
#endif

	/* Current operations */
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *slot_list;
	unsigned int slot_count;
};

/******************************************************************************/
/* Utility functions                                                          */
/******************************************************************************/

void ctx_log(ENGINE_CTX *ctx, int level, const char *format, ...)
{
	va_list ap;

	if (level > ctx->verbose)
			return;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

static void dump_hex(ENGINE_CTX *ctx, int level,
		const unsigned char *val, const size_t len)
{
	size_t n;

	for (n = 0; n < len; n++)
		ctx_log(ctx, level, "%02x", val[n]);
}

/******************************************************************************/
/* PIN handling                                                               */
/******************************************************************************/

/* Free PIN storage in secure way. */
static void ctx_destroy_pin(ENGINE_CTX *ctx)
{
	if (ctx->pin != NULL) {
		OPENSSL_cleanse(ctx->pin, ctx->pin_length);
		OPENSSL_free(ctx->pin);
		ctx->pin = NULL;
		ctx->pin_length = 0;
	}
}

/* Get the PIN via asking user interface. The supplied call-back data are
 * passed to the user interface implemented by an application. Only the
 * application knows how to interpret the call-back data.
 * A (strdup'ed) copy of the PIN code will be stored in the pin variable. */
static int ctx_get_pin(ENGINE_CTX *ctx, const char* token_label, UI_METHOD *ui_method, void *callback_data)
{
	UI *ui;
	char* prompt;

	/* call ui to ask for a pin */
	ui = UI_new_method(ui_method);
	if (ui == NULL) {
		ctx_log(ctx, 0, "UI_new failed\n");
		return 0;
	}
	if (callback_data != NULL)
		UI_add_user_data(ui, callback_data);

	ctx_destroy_pin(ctx);
	ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
	if (ctx->pin == NULL)
		return 0;
	memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
	ctx->pin_length = MAX_PIN_LENGTH;
	prompt = UI_construct_prompt(ui, "PKCS#11 token PIN", token_label);
	if (!prompt) {
		return 0;
	}
	if (!UI_dup_input_string(ui, prompt,
			UI_INPUT_FLAG_DEFAULT_PWD, ctx->pin, 4, MAX_PIN_LENGTH)) {
		ctx_log(ctx, 0, "UI_dup_input_string failed\n");
		UI_free(ui);
		OPENSSL_free(prompt);
		return 0;
	}
	OPENSSL_free(prompt);

	if (UI_process(ui)) {
		ctx_log(ctx, 0, "UI_process failed\n");
		UI_free(ui);
		return 0;
	}
	UI_free(ui);
	return 1;
}

/* Return 1 if the user has already logged in */
static int slot_logged_in(ENGINE_CTX *ctx, PKCS11_SLOT *slot) {
	int logged_in = 0;

	/* Check if already logged in to avoid resetting state */
	if (PKCS11_is_logged_in(slot, 0, &logged_in) != 0) {
		ctx_log(ctx, 0, "Unable to check if already logged in\n");
		return 0;
	}
	return logged_in;
}

/*
 * Log-into the token if necessary.
 *
 * @slot is PKCS11 slot to log in
 * @tok is PKCS11 token to log in (??? could be derived as @slot->token)
 * @ui_method is OpenSSL user interface which is used to ask for a password
 * @callback_data are application data to the user interface
 * @return 1 on success, 0 on error.
 */
static int ctx_login(ENGINE_CTX *ctx, PKCS11_SLOT *slot, PKCS11_TOKEN *tok,
		UI_METHOD *ui_method, void *callback_data)
{
	if (!(ctx->force_login || tok->loginRequired) || slot_logged_in(ctx, slot))
		return 1;

	/* If the token has a secure login (i.e., an external keypad),
	 * then use a NULL PIN. Otherwise, obtain a new PIN if needed. */
	if (tok->secureLogin) {
		/* Free the PIN if it has already been
		 * assigned (i.e, cached by ctx_get_pin) */
		ctx_destroy_pin(ctx);
	} else if (ctx->pin == NULL) {
		ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
		ctx->pin_length = MAX_PIN_LENGTH;
		if (ctx->pin == NULL) {
			ctx_log(ctx, 0, "Could not allocate memory for PIN\n");
			return 0;
		}
		memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
		if (!ctx_get_pin(ctx, tok->label, ui_method, callback_data)) {
			ctx_destroy_pin(ctx);
			ctx_log(ctx, 0, "No PIN code was entered\n");
			return 0;
		}
	}

	/* Now login in with the (possibly NULL) PIN */
	if (PKCS11_login(slot, 0, ctx->pin)) {
		/* Login failed, so free the PIN if present */
		ctx_destroy_pin(ctx);
		ctx_log(ctx, 0, "Login failed\n");
		return 0;
	}
	return 1;
}

/******************************************************************************/
/* Initialization and cleanup                                                 */
/******************************************************************************/

ENGINE_CTX *ctx_new()
{
	ENGINE_CTX *ctx;
	char *mod;

	ctx = OPENSSL_malloc(sizeof(ENGINE_CTX));
	if (ctx == NULL)
		return NULL;
	memset(ctx, 0, sizeof(ENGINE_CTX));

	mod = getenv("PKCS11_MODULE_PATH");
	if (mod) {
		ctx->module = OPENSSL_strdup(mod);
	} else {
#ifdef DEFAULT_PKCS11_MODULE
		ctx->module = OPENSSL_strdup(DEFAULT_PKCS11_MODULE);
#else
		ctx->module = NULL;
#endif
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	ctx->rwlock = CRYPTO_THREAD_lock_new();
#else
	ctx->rwlock = CRYPTO_get_dynlock_create_callback() ?
		CRYPTO_get_new_dynlockid() : 0;
#endif

	return ctx;
}

/* Destroy the context allocated with ctx_new() */
int ctx_destroy(ENGINE_CTX *ctx)
{
	if (ctx) {
		ctx_destroy_pin(ctx);
		OPENSSL_free(ctx->module);
		OPENSSL_free(ctx->init_args);
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
		CRYPTO_THREAD_lock_free(ctx->rwlock);
#else
		if (ctx->rwlock)
			CRYPTO_destroy_dynlockid(ctx->rwlock);
#endif
		OPENSSL_free(ctx);
	}
	return 1;
}

/* Initialize libp11 data: ctx->pkcs11_ctx and ctx->slot_list */
static void ctx_init_libp11_unlocked(ENGINE_CTX *ctx)
{
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *slot_list = NULL;
	unsigned int slot_count = 0;

	ctx_log(ctx, 1, "PKCS#11: Initializing the engine\n");

	pkcs11_ctx = PKCS11_CTX_new();
	PKCS11_CTX_init_args(pkcs11_ctx, ctx->init_args);
	PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);

	/* PKCS11_CTX_load() uses C_GetSlotList() via p11-kit */
	if (PKCS11_CTX_load(pkcs11_ctx, ctx->module) < 0) {
		ctx_log(ctx, 0, "Unable to load module %s\n", ctx->module);
		PKCS11_CTX_free(pkcs11_ctx);
		return;
	}

	/* PKCS11_enumerate_slots() uses C_GetSlotList() via libp11 */
	if (PKCS11_enumerate_slots(pkcs11_ctx, &slot_list, &slot_count) < 0) {
		ctx_log(ctx, 0, "Failed to enumerate slots\n");
		PKCS11_CTX_unload(pkcs11_ctx);
		PKCS11_CTX_free(pkcs11_ctx);
		return;
	}

	ctx_log(ctx, 1, "Found %u slot%s\n", slot_count,
		slot_count <= 1 ? "" : "s");

	ctx->pkcs11_ctx = pkcs11_ctx;
	ctx->slot_list = slot_list;
	ctx->slot_count = slot_count;
}

static int ctx_init_libp11(ENGINE_CTX *ctx)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	CRYPTO_THREAD_write_lock(ctx->rwlock);
#else
	if (ctx->rwlock)
		CRYPTO_w_lock(ctx->rwlock);
#endif
	if (ctx->pkcs11_ctx == NULL || ctx->slot_list == NULL)
		ctx_init_libp11_unlocked(ctx);
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	CRYPTO_THREAD_unlock(ctx->rwlock);
#else
	if (ctx->rwlock)
		CRYPTO_w_unlock(ctx->rwlock);
#endif
	return ctx->pkcs11_ctx && ctx->slot_list ? 0 : -1;
}

/* Function called from ENGINE_init() */
int ctx_init(ENGINE_CTX *ctx)
{
	/* OpenSC implicitly locks CRYPTO_LOCK_ENGINE during C_GetSlotList().
	 * OpenSSL also locks CRYPTO_LOCK_ENGINE in ENGINE_init().
	 * Double-locking a non-recursive rwlock causes the application to
	 * crash or hang, depending on the locking library implementation. */

	/* Only attempt initialization when dynamic locks are unavailable.
	 * This likely also indicates a single-threaded application,
	 * so temporarily unlocking CRYPTO_LOCK_ENGINE should be safe. */
#if OPENSSL_VERSION_NUMBER < 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	if (CRYPTO_get_dynlock_create_callback() == NULL ||
			CRYPTO_get_dynlock_lock_callback() == NULL ||
			CRYPTO_get_dynlock_destroy_callback() == NULL) {
		CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
		ctx_init_libp11_unlocked(ctx);
		CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
		return ctx->pkcs11_ctx && ctx->slot_list ? 1 : 0;
	}
#else
	(void)ctx; /* squash the unused parameter warning */
#endif
	return 1;
}

/* Finish engine operations initialized with ctx_init() */
int ctx_finish(ENGINE_CTX *ctx)
{
	if (ctx) {
		if (ctx->slot_list) {
			PKCS11_release_all_slots(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count);
			ctx->slot_list = NULL;
			ctx->slot_count = 0;
		}
		if (ctx->pkcs11_ctx) {
			PKCS11_CTX_unload(ctx->pkcs11_ctx);
			PKCS11_CTX_free(ctx->pkcs11_ctx);
			ctx->pkcs11_ctx = NULL;
		}
	}
	return 1;
}

/******************************************************************************/
/* Certificate handling                                                       */
/******************************************************************************/

/* prototype for OpenSSL ENGINE_load_cert */
/* used by load_cert_ctrl via ENGINE_ctrl for now */

static X509 *ctx_load_cert(ENGINE_CTX *ctx, const char *s_slot_cert_id,
		const int login)
{
	PKCS11_SLOT *slot;
	PKCS11_SLOT *found_slot = NULL;
	PKCS11_TOKEN *tok, *match_tok = NULL;
	PKCS11_CERT *certs, *selected_cert = NULL;
	X509 *x509;
	unsigned int cert_count, n, m;
	unsigned char cert_id[MAX_VALUE_LEN / 2];
	size_t cert_id_len = sizeof(cert_id);
	char *cert_label = NULL;
	char tmp_pin[MAX_PIN_LENGTH+1];
	size_t tmp_pin_len = MAX_PIN_LENGTH;
	int slot_nr = -1;
	char flags[64];

	if (ctx_init_libp11(ctx)) /* Delayed libp11 initialization */
		return NULL;

	if (s_slot_cert_id && *s_slot_cert_id) {
		if (!strncasecmp(s_slot_cert_id, "pkcs11:", 7)) {
			n = parse_pkcs11_uri(ctx, s_slot_cert_id, &match_tok,
				cert_id, &cert_id_len,
				tmp_pin, &tmp_pin_len, &cert_label);
			if (!n) {
				ctx_log(ctx, 0,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n");
				ENGerr(ENG_F_CTX_LOAD_CERT, ENG_R_INVALID_ID);
				return NULL;
			}
			if (tmp_pin_len > 0 && tmp_pin[0] != 0) {
				if (!login)
					return NULL; /* Process on second attempt */
				ctx_destroy_pin(ctx);
				ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
				if (ctx->pin != NULL) {
					memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
					memcpy(ctx->pin, tmp_pin, tmp_pin_len);
					ctx->pin_length = tmp_pin_len;
				}
			}
		} else {
			n = parse_slot_id_string(ctx, s_slot_cert_id, &slot_nr,
				cert_id, &cert_id_len, &cert_label);
			if (!n) {
				ctx_log(ctx, 0,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n"
					"The legacy ENGINE_pkcs11 ID format is also "
					"still accepted for now\n");
				ENGerr(ENG_F_CTX_LOAD_CERT, ENG_R_INVALID_ID);
				return NULL;
			}
		}
		ctx_log(ctx, 1, "Looking in slot %d for certificate: ",
			slot_nr);
		if (cert_id_len != 0) {
			ctx_log(ctx, 1, "id=");
			dump_hex(ctx, 1, cert_id, cert_id_len);
		}
		if (cert_id_len != 0 && cert_label != NULL)
			ctx_log(ctx, 1, " ");
		if (cert_label != NULL)
			ctx_log(ctx, 1, "label=%s", cert_label);
		ctx_log(ctx, 1, "\n");
	}

	for (n = 0; n < ctx->slot_count; n++) {
		slot = ctx->slot_list + n;
		flags[0] = '\0';
		if (slot->token) {
			if (!slot->token->initialized)
				strcat(flags, "uninitialized, ");
			else if (!slot->token->userPinSet)
				strcat(flags, "no pin, ");
			if (slot->token->loginRequired)
				strcat(flags, "login, ");
			if (slot->token->readOnly)
				strcat(flags, "ro, ");
		} else {
			strcpy(flags, "no token");
		}
		if ((m = strlen(flags)) != 0) {
			flags[m - 2] = '\0';
		}

		if (slot_nr != -1 &&
			slot_nr == (int)PKCS11_get_slotid_from_slot(slot)) {
			found_slot = slot;
		}
		if (match_tok && slot->token &&
				(match_tok->label == NULL ||
					!strcmp(match_tok->label, slot->token->label)) &&
				(match_tok->manufacturer == NULL ||
					!strcmp(match_tok->manufacturer, slot->token->manufacturer)) &&
				(match_tok->serialnr == NULL ||
					!strcmp(match_tok->serialnr, slot->token->serialnr)) &&
				(match_tok->model == NULL ||
					!strcmp(match_tok->model, slot->token->model))) {
			found_slot = slot;
		}
		ctx_log(ctx, 1, "[%lu] %-25.25s  %-16s",
			PKCS11_get_slotid_from_slot(slot),
			slot->description, flags);
		if (slot->token) {
			ctx_log(ctx, 1, "  (%s)",
				slot->token->label[0] ?
				slot->token->label : "no label");
		}
		ctx_log(ctx, 1, "\n");
	}

	if (match_tok) {
		OPENSSL_free(match_tok->model);
		OPENSSL_free(match_tok->manufacturer);
		OPENSSL_free(match_tok->serialnr);
		OPENSSL_free(match_tok->label);
		OPENSSL_free(match_tok);
	}
	if (found_slot) {
		slot = found_slot;
	} else if (match_tok) {
		ctx_log(ctx, 0, "Specified object not found\n");
		return NULL;
	} else if (slot_nr == -1) {
		if (!(slot = PKCS11_find_token(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count))) {
			ctx_log(ctx, 0, "No tokens found\n");
			return NULL;
		}
	} else {
		ctx_log(ctx, 0, "Invalid slot number: %d\n", slot_nr);
		return NULL;
	}
	tok = slot->token;

	if (tok == NULL) {
		ctx_log(ctx, 0, "Empty token found\n");
		return NULL;
	}

	ctx_log(ctx, 1, "Found slot:  %s\n", slot->description);
	ctx_log(ctx, 1, "Found token: %s\n", slot->token->label);

	/* In several tokens certificates are marked as private */
	if (login && !ctx_login(ctx, slot, tok,
			ctx->ui_method, ctx->callback_data)) {
		ctx_log(ctx, 0, "Login to token failed, returning NULL...\n");
		return NULL;
	}

	if (PKCS11_enumerate_certs(tok, &certs, &cert_count)) {
		ctx_log(ctx, 0, "Unable to enumerate certificates\n");
		return NULL;
	}

	ctx_log(ctx, 1, "Found %u cert%s:\n", cert_count,
		(cert_count <= 1) ? "" : "s");
	if ((s_slot_cert_id && *s_slot_cert_id) &&
			(cert_id_len != 0 || cert_label != NULL)) {
		for (n = 0; n < cert_count; n++) {
			PKCS11_CERT *k = certs + n;

			if (cert_label != NULL && strcmp(k->label, cert_label) == 0)
				selected_cert = k;
			if (cert_id_len != 0 && k->id_len == cert_id_len &&
					memcmp(k->id, cert_id, cert_id_len) == 0)
				selected_cert = k;
		}
	} else { 
		for (n = 0; n < cert_count; n++) {
			PKCS11_CERT *k = certs + n;
			if (k->id && *(k->id)) {
				selected_cert = k; /* Use the first certificate with nonempty id */
				break;
			}
		}
		if (!selected_cert)
			selected_cert = certs; /* Use the first certificate */
	}

	if (selected_cert != NULL) {
		x509 = X509_dup(selected_cert->x509);
	} else {
		if (login) /* Only print the error on the second attempt */
			ctx_log(ctx, 0, "Certificate not found.\n");
		x509 = NULL;
	}
	if (cert_label != NULL)
		OPENSSL_free(cert_label);
	return x509;
}

static int ctx_ctrl_load_cert(ENGINE_CTX *ctx, void *p)
{
	struct {
		const char *s_slot_cert_id;
		X509 *cert;
	} *parms = p;

	if (parms == NULL) {
		ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (parms->cert != NULL) {
		ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_INVALID_PARAMETER);
		return 0;
	}
	ERR_clear_error();
	if (!ctx->force_login)
		parms->cert = ctx_load_cert(ctx, parms->s_slot_cert_id, 0);
	if (parms->cert == NULL) { /* Try again with login */
		ERR_clear_error();
		parms->cert = ctx_load_cert(ctx, parms->s_slot_cert_id, 1);
	}
	if (parms->cert == NULL) {
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_OBJECT_NOT_FOUND);
		return 0;
	}
	return 1;
}

/******************************************************************************/
/* Private and public key handling                                            */
/******************************************************************************/

static EVP_PKEY *ctx_load_key(ENGINE_CTX *ctx, const char *s_slot_key_id,
		UI_METHOD *ui_method, void *callback_data,
		const int isPrivate, const int login)
{
	PKCS11_SLOT *slot;
	PKCS11_SLOT *found_slot = NULL;
	PKCS11_TOKEN *tok, *match_tok = NULL;
	PKCS11_KEY *keys, *selected_key = NULL;
	EVP_PKEY *pk = NULL;
	unsigned int key_count, n, m;
	unsigned char key_id[MAX_VALUE_LEN / 2];
	size_t key_id_len = sizeof(key_id);
	char *key_label = NULL;
	int slot_nr = -1;
	char tmp_pin[MAX_PIN_LENGTH+1];
	size_t tmp_pin_len = MAX_PIN_LENGTH;
	char flags[64];

	if (ctx_init_libp11(ctx)) /* Delayed libp11 initialization */
		goto error;

	ctx_log(ctx, 1, "Loading %s key \"%s\"\n",
		(char *)(isPrivate ? "private" : "public"),
		s_slot_key_id);
	if (s_slot_key_id && *s_slot_key_id) {
		if (!strncasecmp(s_slot_key_id, "pkcs11:", 7)) {
			n = parse_pkcs11_uri(ctx, s_slot_key_id, &match_tok,
				key_id, &key_id_len,
				tmp_pin, &tmp_pin_len, &key_label);
			if (!n) {
				ctx_log(ctx, 0,
					"The key ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n");
				ENGerr(ENG_F_CTX_LOAD_KEY, ENG_R_INVALID_ID);
				goto error;
			}
			if (tmp_pin_len > 0 && tmp_pin[0] != 0) {
				if (!login)
					goto error; /* Process on second attempt */
				ctx_destroy_pin(ctx);
				ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
				if (ctx->pin != NULL) {
					memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
					memcpy(ctx->pin, tmp_pin, tmp_pin_len);
					ctx->pin_length = tmp_pin_len;
				}
			}
		} else {
			n = parse_slot_id_string(ctx, s_slot_key_id, &slot_nr,
				key_id, &key_id_len, &key_label);
			if (!n) {
				ctx_log(ctx, 0,
					"The key ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n"
					"The legacy ENGINE_pkcs11 ID format is also "
					"still accepted for now\n");
				ENGerr(ENG_F_CTX_LOAD_KEY, ENG_R_INVALID_ID);
				goto error;
			}
		}
		ctx_log(ctx, 1, "Looking in slot %d for key: ",
			slot_nr);
		if (key_id_len != 0) {
			ctx_log(ctx, 1, "id=");
			dump_hex(ctx, 1, key_id, key_id_len);
		}
		if (key_id_len != 0 && key_label != NULL)
			ctx_log(ctx, 1, " ");
		if (key_label != NULL)
			ctx_log(ctx, 1, "label=%s", key_label);
		ctx_log(ctx, 1, "\n");
	}

	for (n = 0; n < ctx->slot_count; n++) {
		slot = ctx->slot_list + n;
		flags[0] = '\0';
		if (slot->token) {
			if (!slot->token->initialized)
				strcat(flags, "uninitialized, ");
			else if (!slot->token->userPinSet)
				strcat(flags, "no pin, ");
			if (slot->token->loginRequired)
				strcat(flags, "login, ");
			if (slot->token->readOnly)
				strcat(flags, "ro, ");
		} else {
			strcpy(flags, "no token");
		}
		if ((m = strlen(flags)) != 0) {
			flags[m - 2] = '\0';
		}

		if (slot_nr != -1 &&
			slot_nr == (int)PKCS11_get_slotid_from_slot(slot)) {
			found_slot = slot;
		}
		if (match_tok && slot->token &&
				(match_tok->label == NULL ||
					!strcmp(match_tok->label, slot->token->label)) &&
				(match_tok->manufacturer == NULL ||
					!strcmp(match_tok->manufacturer, slot->token->manufacturer)) &&
				(match_tok->serialnr == NULL ||
					!strcmp(match_tok->serialnr, slot->token->serialnr)) &&
				(match_tok->model == NULL ||
					!strcmp(match_tok->model, slot->token->model))) {
			found_slot = slot;
		}
		ctx_log(ctx, 1, "[%lu] %-25.25s  %-16s",
			PKCS11_get_slotid_from_slot(slot),
			slot->description, flags);
		if (slot->token) {
			ctx_log(ctx, 1, "  (%s)",
				slot->token->label[0] ?
				slot->token->label : "no label");
		}
		ctx_log(ctx, 1, "\n");
	}

	if (match_tok) {
		OPENSSL_free(match_tok->model);
		OPENSSL_free(match_tok->manufacturer);
		OPENSSL_free(match_tok->serialnr);
		OPENSSL_free(match_tok->label);
		OPENSSL_free(match_tok);
	}
	if (found_slot) {
		slot = found_slot;
	} else if (match_tok) {
		ctx_log(ctx, 0, "Specified object not found\n");
		goto error;
	} else if (slot_nr == -1) {
		if (!(slot = PKCS11_find_token(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count))) {
			ctx_log(ctx, 0, "No tokens found\n");
			goto error;
		}
	} else {
		ctx_log(ctx, 0, "Invalid slot number: %d\n", slot_nr);
		goto error;
	}
	tok = slot->token;

	if (tok == NULL) {
		ctx_log(ctx, 0, "Found empty token\n");
		goto error;
	}
	/* The following check is non-critical to ensure interoperability
	 * with some other (which ones?) PKCS#11 libraries */
	if (!tok->initialized)
		ctx_log(ctx, 0, "Found uninitialized token\n");

	ctx_log(ctx, 1, "Found slot:  %s\n", slot->description);
	ctx_log(ctx, 1, "Found token: %s\n", slot->token->label);

	/* Both private and public keys can have the CKA_PRIVATE attribute
	 * set and thus require login (even to retrieve attributes!) */
	if (login && !ctx_login(ctx, slot, tok, ui_method, callback_data)) {
		ctx_log(ctx, 0, "Login to token failed, returning NULL...\n");
		goto error;
	}

	if (isPrivate) {
		/* Make sure there is at least one private key on the token */
		if (PKCS11_enumerate_keys(tok, &keys, &key_count)) {
			ctx_log(ctx, 0, "Unable to enumerate private keys\n");
			goto error;
		}
	} else {
		/* Make sure there is at least one public key on the token */
		if (PKCS11_enumerate_public_keys(tok, &keys, &key_count)) {
			ctx_log(ctx, 0, "Unable to enumerate public keys\n");
			goto error;
		}
	}
	if (key_count == 0) {
		if (login) /* Only print the error on the second attempt */
			ctx_log(ctx, 0, "No %s keys found.\n",
				(char *)(isPrivate ? "private" : "public"));
		goto error;
	}
	ctx_log(ctx, 1, "Found %u %s key%s:\n", key_count,
		(char *)(isPrivate ? "private" : "public"),
		(key_count == 1) ? "" : "s");

	if (s_slot_key_id && *s_slot_key_id &&
			(key_id_len != 0 || key_label != NULL)) {
		for (n = 0; n < key_count; n++) {
			PKCS11_KEY *k = keys + n;

			ctx_log(ctx, 1, "  %2u %c%c id=", n + 1,
				k->isPrivate ? 'P' : ' ',
				k->needLogin ? 'L' : ' ');
			dump_hex(ctx, 1, k->id, k->id_len);
			ctx_log(ctx, 1, " label=%s\n", k->label);
			if (key_label != NULL && strcmp(k->label, key_label) == 0)
				selected_key = k;
			if (key_id_len != 0 && k->id_len == key_id_len
					&& memcmp(k->id, key_id, key_id_len) == 0)
				selected_key = k;
		}
	} else {
		selected_key = keys; /* Use the first key */
	}

	if (selected_key != NULL) {
		pk = isPrivate ?
			PKCS11_get_private_key(selected_key) :
			PKCS11_get_public_key(selected_key);
	} else {
		if (login) /* Only print the error on the second attempt */
			ctx_log(ctx, 0, "Key not found.\n");
		pk = NULL;
	}
error:
	if (key_label != NULL)
		OPENSSL_free(key_label);
	return pk;
}

EVP_PKEY *ctx_load_pubkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pk = NULL;

	ERR_clear_error();
	if (!ctx->force_login)
		pk = ctx_load_key(ctx, s_key_id, ui_method, callback_data, 0, 0);
	if (pk == NULL) { /* Try again with login */
		ERR_clear_error();
		pk = ctx_load_key(ctx, s_key_id, ui_method, callback_data, 0, 1);
	}
	if (pk == NULL) {
		ctx_log(ctx, 0, "PKCS11_load_public_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PUBKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return pk;
}

EVP_PKEY *ctx_load_privkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pk = NULL;

	ERR_clear_error();
	if (!ctx->force_login)
		pk = ctx_load_key(ctx, s_key_id, ui_method, callback_data, 1, 0);
	if (pk == NULL) { /* Try again with login */
		ERR_clear_error();
		pk = ctx_load_key(ctx, s_key_id, ui_method, callback_data, 1, 1);
	}
	if (pk == NULL) {
		ctx_log(ctx, 0, "PKCS11_get_private_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PRIVKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return pk;
}

/******************************************************************************/
/* Engine ctrl request handling                                               */
/******************************************************************************/

static int ctx_ctrl_set_module(ENGINE_CTX *ctx, const char *modulename)
{
	OPENSSL_free(ctx->module);
	ctx->module = modulename ? OPENSSL_strdup(modulename) : NULL;
	return 1;
}

/**
 * Set the PIN used for login. A copy of the PIN shall be made.
 *
 * If the PIN cannot be assigned, the value 0 shall be returned
 * and errno shall be set as follows:
 *
 *   EINVAL - a NULL PIN was supplied
 *   ENOMEM - insufficient memory to copy the PIN
 *
 * @param pin the pin to use for login. Must not be NULL.
 *
 * @return 1 on success, 0 on failure.
 */
static int ctx_ctrl_set_pin(ENGINE_CTX *ctx, const char *pin)
{
	/* Pre-condition check */
	if (pin == NULL) {
		ENGerr(ENG_F_CTX_CTRL_SET_PIN, ERR_R_PASSED_NULL_PARAMETER);
		errno = EINVAL;
		return 0;
	}

	/* Copy the PIN. If the string cannot be copied, NULL
	 * shall be returned and errno shall be set. */
	ctx_destroy_pin(ctx);
	ctx->pin = OPENSSL_strdup(pin);
	if (ctx->pin == NULL) {
		ENGerr(ENG_F_CTX_CTRL_SET_PIN, ERR_R_MALLOC_FAILURE);
		errno = ENOMEM;
		return 0;
	}
	ctx->pin_length = strlen(ctx->pin);
	return 1;
}

static int ctx_ctrl_inc_verbose(ENGINE_CTX *ctx)
{
	ctx->verbose++;
	return 1;
}

static int ctx_ctrl_set_quiet(ENGINE_CTX *ctx)
{
	ctx->verbose = -1;
	return 1;
}

static int ctx_ctrl_set_init_args(ENGINE_CTX *ctx, const char *init_args_orig)
{
	OPENSSL_free(ctx->init_args);
	ctx->init_args = init_args_orig ? OPENSSL_strdup(init_args_orig) : NULL;
	return 1;
}

static int ctx_ctrl_set_user_interface(ENGINE_CTX *ctx, UI_METHOD *ui_method)
{
	ctx->ui_method = ui_method;
	if (ctx->pkcs11_ctx != NULL) /* libp11 is already initialized */
		PKCS11_set_ui_method(ctx->pkcs11_ctx,
			ctx->ui_method, ctx->callback_data);
	return 1;
}

static int ctx_ctrl_set_callback_data(ENGINE_CTX *ctx, void *callback_data)
{
	ctx->callback_data = callback_data;
	if (ctx->pkcs11_ctx != NULL) /* libp11 is already initialized */
		PKCS11_set_ui_method(ctx->pkcs11_ctx,
			ctx->ui_method, ctx->callback_data);
	return 1;
}

static int ctx_ctrl_force_login(ENGINE_CTX *ctx)
{
	ctx->force_login = 1;
	return 1;
}

int ctx_engine_ctrl(ENGINE_CTX *ctx, int cmd, long i, void *p, void (*f)())
{
	(void)i; /* We don't currently take integer parameters */
	(void)f; /* We don't currently take callback parameters */
	/*int initialised = ((pkcs11_dso == NULL) ? 0 : 1); */
	switch (cmd) {
	case CMD_MODULE_PATH:
		return ctx_ctrl_set_module(ctx, (const char *)p);
	case CMD_PIN:
		return ctx_ctrl_set_pin(ctx, (const char *)p);
	case CMD_VERBOSE:
		return ctx_ctrl_inc_verbose(ctx);
	case CMD_QUIET:
		return ctx_ctrl_set_quiet(ctx);
	case CMD_LOAD_CERT_CTRL:
		return ctx_ctrl_load_cert(ctx, p);
	case CMD_INIT_ARGS:
		return ctx_ctrl_set_init_args(ctx, (const char *)p);
	case ENGINE_CTRL_SET_USER_INTERFACE:
	case CMD_SET_USER_INTERFACE:
		return ctx_ctrl_set_user_interface(ctx, (UI_METHOD *)p);
	case ENGINE_CTRL_SET_CALLBACK_DATA:
	case CMD_SET_CALLBACK_DATA:
		return ctx_ctrl_set_callback_data(ctx, p);
	case CMD_FORCE_LOGIN:
		return ctx_ctrl_force_login(ctx);
	default:
		ENGerr(ENG_F_CTX_ENGINE_CTRL, ENG_R_UNKNOWN_COMMAND);
		break;
	}
	return 0;
}

/* vim: set noexpandtab: */
