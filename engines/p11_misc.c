/* libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2015 Michał Trojnara <Michal.Trojnara@stunnel.org>
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
#include <openssl/crypto.h>

/* PKCS11 strings are fixed size blank padded,
 * so when strduping them we must make sure
 * we stop at the end of the buffer, and while we're
 * at it it's nice to remove the padding */
char *pkcs11_strdup(char *mem, size_t size)
{
	char *res;

	while (size && mem[size - 1] == ' ')
		size--;
	res = OPENSSL_malloc(size + 1);
	if (res == NULL)
		return NULL;
	memcpy(res, mem, size);
	res[size] = '\0';
	return res;
}

/*
 * CRYPTO dynlock wrappers: 0 is an invalid dynamic lock ID
 */

#if OPENSSL_VERSION_NUMBER < 0x10100004L || defined(LIBRESSL_VERSION_NUMBER)

int CRYPTO_THREAD_lock_new()
{
	int i;

	if (CRYPTO_get_dynlock_create_callback() == NULL ||
			CRYPTO_get_dynlock_lock_callback() == NULL ||
			CRYPTO_get_dynlock_destroy_callback() == NULL)
		return 0; /* Dynamic callbacks not set */
	i = CRYPTO_get_new_dynlockid();
	if (i == 0)
		ERR_clear_error(); /* Dynamic locks are optional -> ignore */
	return i;
}

void CRYPTO_THREAD_lock_free(int i)
{
	if (i)
		CRYPTO_destroy_dynlockid(i);
}

#endif

/* vim: set noexpandtab: */
