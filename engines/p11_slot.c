/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2015-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
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
#include <openssl/buffer.h>

static int pkcs11_init_slot(PKCS11_CTX *, PKCS11_SLOT *, CK_SLOT_ID);
static void pkcs11_release_slot(PKCS11_CTX *, PKCS11_SLOT *);
static int pkcs11_check_token(PKCS11_CTX *, PKCS11_SLOT *);
static void pkcs11_destroy_token(PKCS11_TOKEN *);

/*
 * Get slotid from private
 */
unsigned long pkcs11_get_slotid_from_slot(PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	return spriv->id;
}

/*
 * Enumerate slots
 */
int pkcs11_enumerate_slots(PKCS11_CTX *ctx, PKCS11_SLOT **slotp,
		unsigned int *countp)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	CK_SLOT_ID *slotid;
	CK_ULONG nslots, n;
	PKCS11_SLOT *slots;
	size_t alloc_size;
	int rv;

	rv = cpriv->method->C_GetSlotList(FALSE, NULL_PTR, &nslots);
	CRYPTOKI_checkerr(CKR_F_PKCS11_ENUMERATE_SLOTS, rv);

	alloc_size = nslots * sizeof(CK_SLOT_ID);
	if (alloc_size / sizeof(CK_SLOT_ID) != nslots) /* integer overflow */
		return -1;
	slotid = OPENSSL_malloc(alloc_size);
	if (slotid == NULL)
		return -1;

	rv = cpriv->method->C_GetSlotList(FALSE, slotid, &nslots);
	CRYPTOKI_checkerr(CKR_F_PKCS11_ENUMERATE_SLOTS, rv);

	alloc_size = nslots * sizeof(PKCS11_SLOT);
	if (alloc_size / sizeof(PKCS11_SLOT) != nslots) /* integer overflow */
		return -1;
	slots = OPENSSL_malloc(alloc_size);
	if (slots == NULL)
		return -1;
	memset(slots, 0, nslots * sizeof(PKCS11_SLOT));
	for (n = 0; n < nslots; n++) {
		if (pkcs11_init_slot(ctx, &slots[n], slotid[n])) {
			while (n--)
				pkcs11_release_slot(ctx, slots + n);
			OPENSSL_free(slotid);
			OPENSSL_free(slots);
			return -1;
		}
	}

	if (slotp)
		*slotp = slots;
	else
		OPENSSL_free(slots);
	if (countp)
		*countp = nslots;
	OPENSSL_free(slotid);
	return 0;
}

/*
 * Find a slot with a token that looks "valuable"
 */
PKCS11_SLOT *pkcs11_find_token(PKCS11_CTX *ctx, PKCS11_SLOT *slots,
		unsigned int nslots)
{
	PKCS11_SLOT *slot, *best;
	PKCS11_TOKEN *tok;
	unsigned int n;

	(void)ctx;

	if (slots == NULL)
		return NULL;

	best = NULL;
	for (n = 0, slot = slots; n < nslots; n++, slot++) {
		if ((tok = slot->token) != NULL) {
			if (best == NULL ||
					(tok->initialized > best->token->initialized &&
					tok->userPinSet > best->token->userPinSet &&
					tok->loginRequired > best->token->loginRequired))
				best = slot;
		}
	}
	return best;
}

/*
 * Find the next slot with a token that looks "valuable"
 */
PKCS11_SLOT *pkcs11_find_next_token(PKCS11_CTX *ctx, PKCS11_SLOT *slots,
		unsigned int nslots, PKCS11_SLOT *current)
{
	int offset;

	if (slots == NULL)
		return NULL;

	if (current) {
		offset = current + 1 - slots;
		if (offset < 1 || (unsigned int)offset >= nslots)
			return NULL;
	} else {
		offset = 0;
	}

	return pkcs11_find_token(ctx, slots + offset, nslots - offset);
}

/*
 * Open a session with this slot
 */
int pkcs11_open_session(PKCS11_SLOT *slot, int rw, int relogin)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	int rv;

	if (relogin == 0) {
		if (spriv->haveSession) {
			CRYPTOKI_call(ctx, C_CloseSession(spriv->session));
			spriv->haveSession = 0;
		}
	}
	rv = CRYPTOKI_call(ctx,
		C_OpenSession(spriv->id,
			CKF_SERIAL_SESSION | (rw ? CKF_RW_SESSION : 0),
			NULL, NULL, &spriv->session));
	CRYPTOKI_checkerr(CKR_F_PKCS11_OPEN_SESSION, rv);
	spriv->haveSession = 1;
	spriv->prev_rw = rw;

	return 0;
}

int pkcs11_reopen_session(PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	int rv;

	rv = CRYPTOKI_call(ctx,
		C_OpenSession(spriv->id,
			CKF_SERIAL_SESSION | (spriv->prev_rw ? CKF_RW_SESSION : 0),
			NULL, NULL, &spriv->session));
	CRYPTOKI_checkerr(CKR_F_PKCS11_REOPEN_SESSION, rv);
	spriv->haveSession = 1;

	return 0;
}

/*
 * Determines if user is authenticated with token
 */
int pkcs11_is_logged_in(PKCS11_SLOT *slot, int so, int *res)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_SESSION_INFO session_info;
	int rv;

	if (spriv->loggedIn) {
		*res = 1;
		return 0;
	}
	if (!spriv->haveSession) {
		/* SO gets a r/w session by default,
		 * user gets a r/o session by default. */
		if (PKCS11_open_session(slot, so))
			return -1;
	}

	rv = CRYPTOKI_call(ctx, C_GetSessionInfo(spriv->session, &session_info));
	CRYPTOKI_checkerr(CKR_F_PKCS11_IS_LOGGED_IN, rv);
	if (so) {
		*res = session_info.state == CKS_RW_SO_FUNCTIONS;
	} else {
		*res = session_info.state == CKS_RO_USER_FUNCTIONS ||
			session_info.state == CKS_RW_USER_FUNCTIONS;
	}
	return 0;
}

/*
 * Authenticate with the card. relogin should be set if we automatically
 * relogin after a fork.
 */
int pkcs11_login(PKCS11_SLOT *slot, int so, const char *pin, int relogin)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int rv;

	if (!relogin && spriv->loggedIn)
		return 0; /* Nothing to do */

	if (!spriv->haveSession) {
		/* SO gets a r/w session by default,
		 * user gets a r/o session by default. */
		if (pkcs11_open_session(slot, so, relogin))
			return -1;
	}

	rv = CRYPTOKI_call(ctx,
		C_Login(spriv->session, so ? CKU_SO : CKU_USER,
			(CK_UTF8CHAR *) pin, pin ? (unsigned long) strlen(pin) : 0));
	if (rv && rv != CKR_USER_ALREADY_LOGGED_IN) /* logged in -> OK */
		CRYPTOKI_checkerr(CKR_F_PKCS11_LOGIN, rv);
	spriv->loggedIn = 1;

	if (spriv->prev_pin != pin) {
		if (spriv->prev_pin) {
			OPENSSL_cleanse(spriv->prev_pin, strlen(spriv->prev_pin));
			OPENSSL_free(spriv->prev_pin);
		}
		spriv->prev_pin = OPENSSL_strdup(pin);
	}
	spriv->prev_so = so;
	return 0;
}

/*
 * Authenticate with the card
 */
int pkcs11_relogin(PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	return pkcs11_login(slot, spriv->prev_so, spriv->prev_pin, 1);
}

/*
 * Log out
 */
int pkcs11_logout(PKCS11_SLOT *slot)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int rv;

	/* Calling PKCS11_logout invalidates all cached
	 * keys we have */
	if (slot->token) {
		pkcs11_destroy_keys(slot->token, CKO_PRIVATE_KEY);
		pkcs11_destroy_keys(slot->token, CKO_PUBLIC_KEY);
		pkcs11_destroy_certs(slot->token);
	}
	if (!spriv->haveSession) {
		P11err(P11_F_PKCS11_LOGOUT, P11_R_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx, C_Logout(spriv->session));
	CRYPTOKI_checkerr(CKR_F_PKCS11_LOGOUT, rv);
	spriv->loggedIn = 0;
	return 0;
}

/*
 * Initialize the token
 */
int pkcs11_init_token(PKCS11_TOKEN *token, const char *pin, const char *label)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int rv;

	if (label == NULL)
		label = "PKCS#11 Token";
	rv = CRYPTOKI_call(ctx,
		C_InitToken(spriv->id,
			(CK_UTF8CHAR *) pin, (unsigned long) strlen(pin),
			(CK_UTF8CHAR *) label));
	CRYPTOKI_checkerr(CKR_F_PKCS11_INIT_TOKEN, rv);

	/* FIXME: how to update the token?
	 * PKCS11_CTX_private *cpriv;
	 * int n;
	 * cpriv = PRIVCTX(ctx);
	 * for (n = 0; n < cpriv->nslots; n++) {
	 * 	if (pkcs11_check_token(ctx, cpriv->slots + n) < 0)
	 * 		return -1;
	 * }
	 */

	return 0;
}

/*
 * Set the User PIN
 */
int pkcs11_init_pin(PKCS11_TOKEN *token, const char *pin)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int len, rv;

	if (!spriv->haveSession) {
		P11err(P11_F_PKCS11_INIT_PIN, P11_R_NO_SESSION);
		return -1;
	}

	len = pin ? (int) strlen(pin) : 0;
	rv = CRYPTOKI_call(ctx, C_InitPIN(spriv->session, (CK_UTF8CHAR *) pin, len));
	CRYPTOKI_checkerr(CKR_F_PKCS11_INIT_PIN, rv);

	return pkcs11_check_token(ctx, TOKEN2SLOT(token));
}

/*
 * Change the User PIN
 */
int pkcs11_change_pin(PKCS11_SLOT *slot, const char *old_pin,
		const char *new_pin)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int old_len, new_len, rv;

	if (!spriv->haveSession) {
		P11err(P11_F_PKCS11_CHANGE_PIN, P11_R_NO_SESSION);
		return -1;
	}

	old_len = old_pin ? (int) strlen(old_pin) : 0;
	new_len = new_pin ? (int) strlen(new_pin) : 0;
	rv = CRYPTOKI_call(ctx,
		C_SetPIN(spriv->session, (CK_UTF8CHAR *) old_pin, old_len,
			(CK_UTF8CHAR *) new_pin, new_len));
	CRYPTOKI_checkerr(CKR_F_PKCS11_CHANGE_PIN, rv);

	return pkcs11_check_token(ctx, slot);
}

/*
 * Seed the random number generator
 */
int pkcs11_seed_random(PKCS11_SLOT *slot, const unsigned char *s,
		unsigned int s_len)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int rv;

	if (!spriv->haveSession && PKCS11_open_session(slot, 0)) {
		P11err(P11_F_PKCS11_SEED_RANDOM, P11_R_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx,
		C_SeedRandom(spriv->session, (CK_BYTE_PTR) s, s_len));
	CRYPTOKI_checkerr(CKR_F_PKCS11_SEED_RANDOM, rv);

	return pkcs11_check_token(ctx, slot);
}

/*
 * Generate random numbers
 */
int pkcs11_generate_random(PKCS11_SLOT *slot, unsigned char *r,
		unsigned int r_len)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int rv;

	if (!spriv->haveSession && PKCS11_open_session(slot, 0)) {
		P11err(P11_F_PKCS11_GENERATE_RANDOM, P11_R_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx,
		C_GenerateRandom(spriv->session, (CK_BYTE_PTR) r, r_len));
	CRYPTOKI_checkerr(CKR_F_PKCS11_GENERATE_RANDOM, rv);

	return pkcs11_check_token(ctx, slot);
}

/*
 * Helper functions
 */
static int pkcs11_init_slot(PKCS11_CTX *ctx, PKCS11_SLOT *slot, CK_SLOT_ID id)
{
	PKCS11_SLOT_private *spriv;
	CK_SLOT_INFO info;
	int rv;

	rv = CRYPTOKI_call(ctx, C_GetSlotInfo(id, &info));
	CRYPTOKI_checkerr(CKR_F_PKCS11_INIT_SLOT, rv);

	spriv = OPENSSL_malloc(sizeof(PKCS11_SLOT_private));
	if (spriv == NULL)
		return -1;
	memset(spriv, 0, sizeof(PKCS11_SLOT_private));

	spriv->parent = ctx;
	spriv->id = id;
	spriv->forkid = PRIVCTX(ctx)->forkid;
	spriv->prev_rw = 0;
	spriv->prev_pin = NULL;
	spriv->prev_so = 0;

	slot->description = PKCS11_DUP(info.slotDescription);
	slot->manufacturer = PKCS11_DUP(info.manufacturerID);
	slot->removable = (info.flags & CKF_REMOVABLE_DEVICE) ? 1 : 0;
	slot->_private = spriv;

	if ((info.flags & CKF_TOKEN_PRESENT) && pkcs11_check_token(ctx, slot))
		return -1;

	return 0;
}

void pkcs11_release_all_slots(PKCS11_CTX *ctx,  PKCS11_SLOT *slots,
		unsigned int nslots)
{
	unsigned int i;

	for (i=0; i < nslots; i++)
		pkcs11_release_slot(ctx, &slots[i]);
	OPENSSL_free(slots);
}

static void pkcs11_release_slot(PKCS11_CTX *ctx, PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	if (spriv) {
		if (spriv->prev_pin) {
			OPENSSL_cleanse(spriv->prev_pin, strlen(spriv->prev_pin));
			OPENSSL_free(spriv->prev_pin);
		}
		CRYPTOKI_call(ctx, C_CloseAllSessions(spriv->id));
	}
	OPENSSL_free(slot->_private);
	OPENSSL_free(slot->description);
	OPENSSL_free(slot->manufacturer);
	if (slot->token) {
		pkcs11_destroy_token(slot->token);
		OPENSSL_free(slot->token);
	}

	memset(slot, 0, sizeof(*slot));
}

static int pkcs11_check_token(PKCS11_CTX *ctx, PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_TOKEN_private *tpriv;
	CK_TOKEN_INFO info;
	int rv;

	if (slot->token) {
		pkcs11_destroy_token(slot->token);
	} else {
		slot->token = OPENSSL_malloc(sizeof(PKCS11_TOKEN));
		if (slot->token == NULL)
			return -1;
		memset(slot->token, 0, sizeof(PKCS11_TOKEN));
	}

	rv = CRYPTOKI_call(ctx, C_GetTokenInfo(spriv->id, &info));
	if (rv == CKR_TOKEN_NOT_PRESENT || rv == CKR_TOKEN_NOT_RECOGNIZED) {
		OPENSSL_free(slot->token);
		slot->token = NULL;
		return 0;
	}
	CRYPTOKI_checkerr(CKR_F_PKCS11_CHECK_TOKEN, rv);

	/* We have a token */
	tpriv = OPENSSL_malloc(sizeof(PKCS11_TOKEN_private));
	if (tpriv == NULL)
		return -1;
	memset(tpriv, 0, sizeof(PKCS11_TOKEN_private));
	tpriv->parent = slot;
	tpriv->prv.keys = NULL;
	tpriv->prv.num = 0;
	tpriv->pub.keys = NULL;
	tpriv->pub.num = 0;
	tpriv->ncerts = 0;

	slot->token->label = PKCS11_DUP(info.label);
	slot->token->manufacturer = PKCS11_DUP(info.manufacturerID);
	slot->token->model = PKCS11_DUP(info.model);
	slot->token->serialnr = PKCS11_DUP(info.serialNumber);
	slot->token->initialized = (info.flags & CKF_TOKEN_INITIALIZED) ? 1 : 0;
	slot->token->loginRequired = (info.flags & CKF_LOGIN_REQUIRED) ? 1 : 0;
	slot->token->secureLogin = (info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ? 1 : 0;
	slot->token->userPinSet = (info.flags & CKF_USER_PIN_INITIALIZED) ? 1 : 0;
	slot->token->readOnly = (info.flags & CKF_WRITE_PROTECTED) ? 1 : 0;
	slot->token->hasRng = (info.flags & CKF_RNG) ? 1 : 0;
	slot->token->userPinCountLow = (info.flags & CKF_USER_PIN_COUNT_LOW) ? 1 : 0;
	slot->token->userPinFinalTry = (info.flags & CKF_USER_PIN_FINAL_TRY) ? 1 : 0;
	slot->token->userPinLocked = (info.flags & CKF_USER_PIN_LOCKED) ? 1 : 0;
	slot->token->userPinToBeChanged = (info.flags & CKF_USER_PIN_TO_BE_CHANGED) ? 1 : 0;
	slot->token->soPinCountLow = (info.flags & CKF_SO_PIN_COUNT_LOW) ? 1 : 0;
	slot->token->soPinFinalTry = (info.flags & CKF_SO_PIN_FINAL_TRY) ? 1 : 0;
	slot->token->soPinLocked = (info.flags & CKF_SO_PIN_LOCKED) ? 1 : 0;
	slot->token->soPinToBeChanged = (info.flags & CKF_SO_PIN_TO_BE_CHANGED) ? 1 : 0;
	slot->token->_private = tpriv;

	return 0;
}

static void pkcs11_destroy_token(PKCS11_TOKEN *token)
{
	pkcs11_destroy_keys(token, CKO_PRIVATE_KEY);
	pkcs11_destroy_keys(token, CKO_PUBLIC_KEY);
	pkcs11_destroy_certs(token);

	OPENSSL_free(token->label);
	OPENSSL_free(token->manufacturer);
	OPENSSL_free(token->model);
	OPENSSL_free(token->serialnr);
	OPENSSL_free(token->_private);
	memset(token, 0, sizeof(*token));
}

/* vim: set noexpandtab: */
