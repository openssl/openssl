/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 * Copyright (C) 2014 Red Hat
 * Copyright (C) 2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include "libp11-int.h"

#ifndef _WIN32

#include <unistd.h>

#ifndef __STDC_VERSION__
/* older than C90 */
#define inline
#endif /* __STDC_VERSION__ */

#ifdef HAVE___REGISTER_ATFORK

#ifdef __sun
#pragma fini(lib_deinit)
#pragma init(lib_init)
#define _CONSTRUCTOR
#define _DESTRUCTOR
#else /* __sun */
#define _CONSTRUCTOR __attribute__((constructor))
#define _DESTRUCTOR __attribute__((destructor))
#endif /* __sun */

static unsigned int P11_forkid = 0;

inline static unsigned int _P11_get_forkid(void)
{
	return P11_forkid;
}

inline static int _P11_detect_fork(unsigned int forkid)
{
	if (forkid == P11_forkid)
		return 0;
	return 1;
}

static void fork_handler(void)
{
	P11_forkid++;
}

extern int __register_atfork(void (*)(void), void(*)(void), void (*)(void), void *);
extern void *__dso_handle;

_CONSTRUCTOR
int _P11_register_fork_handler(void)
{
	if (__register_atfork(0, 0, fork_handler, __dso_handle) != 0)
		return -1;
	return 0;
}

#else /* HAVE___REGISTER_ATFORK */

inline static unsigned int _P11_get_forkid(void)
{
	return getpid();
}

inline static int _P11_detect_fork(unsigned int forkid)
{
	if (getpid() == forkid)
		return 0;
	return 1;
}

#endif /* HAVE___REGISTER_ATFORK */

#else /* !_WIN32 */

#define _P11_get_forkid() 0
#define _P11_detect_fork(x) 0

#endif /* !_WIN32 */

unsigned int get_forkid()
{
	return _P11_get_forkid();
}

/*
 * PKCS#11 reinitialization after fork
 * It wipes out the internal state of the PKCS#11 library
 * Any libp11 references to this state are no longer valid
 */
static int check_fork_int(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	if (_P11_detect_fork(cpriv->forkid)) {
		if (pkcs11_CTX_reload(ctx) < 0)
			return -1;
		cpriv->forkid = _P11_get_forkid();
	}
	return 0;
}

/*
 * PKCS#11 reinitialization after fork
 * Also relogins and reopens the session if needed
 */
static int check_slot_fork_int(PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	if (check_fork_int(SLOT2CTX(slot)) < 0)
		return -1;
	if (spriv->forkid != cpriv->forkid) {
		if (spriv->loggedIn) {
			int saved = spriv->haveSession;
			spriv->haveSession = 0;
			spriv->loggedIn = 0;
			if (pkcs11_relogin(slot) < 0)
				return -1;
			spriv->haveSession = saved;
		}
		if (spriv->haveSession) {
			spriv->haveSession = 0;
			if (pkcs11_reopen_session(slot) < 0)
				return -1;
		}
		spriv->forkid = cpriv->forkid;
	}
	return 0;
}

/*
 * PKCS#11 reinitialization after fork
 * Also reloads the key
 */
static int check_key_fork_int(PKCS11_KEY *key)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	if (check_slot_fork_int(slot) < 0)
		return -1;
	if (spriv->forkid != kpriv->forkid) {
		pkcs11_reload_key(key);
		kpriv->forkid = spriv->forkid;
	}
	return 0;
}

/*
 * Locking interface to check_fork_int()
 */
int check_fork(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv;
	int rv;

	if (ctx == NULL)
		return -1;
	cpriv = PRIVCTX(ctx);
	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = check_fork_int(ctx);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	return rv;
}

/*
 * Locking interface to check_slot_fork_int()
 */
int check_slot_fork(PKCS11_SLOT *slot)
{
	PKCS11_CTX_private *cpriv;
	int rv;

	if (slot == NULL)
		return -1;
	cpriv = PRIVCTX(SLOT2CTX(slot));
	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = check_slot_fork_int(slot);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	return rv;
}

/*
 * Reinitialize token (just its slot)
 */
int check_token_fork(PKCS11_TOKEN *token)
{
	if (token == NULL)
		return -1;
	return check_slot_fork(TOKEN2SLOT(token));
}

/*
 * Locking interface to check_key_fork_int()
 */
int check_key_fork(PKCS11_KEY *key)
{
	PKCS11_CTX_private *cpriv;
	int rv;

	if (key == NULL)
		return -1;
	cpriv = PRIVCTX(KEY2CTX(key));
	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = check_key_fork_int(key);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	return rv;
}

/*
 * Reinitialize cert (just its token)
 */
int check_cert_fork(PKCS11_CERT *cert)
{
	if (cert == NULL)
		return -1;
	return check_token_fork(CERT2TOKEN(cert));
}

/* vim: set noexpandtab: */
