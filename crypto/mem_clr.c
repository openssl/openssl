/* $OpenBSD: mem_clr.c,v 1.3 2014/04/15 23:04:49 tedu Exp $ */

/* Ted Unangst places this file in the public domain. */
#include <string.h>
#include <openssl/crypto.h>

void
OPENSSL_cleanse(void *ptr, size_t len)
{
	explicit_bzero(ptr, len);
}
