/* $OpenBSD: o_str.c,v 1.8 2014/06/12 15:49:27 deraadt Exp $ */
/*
 * Written by Theo de Raadt.  Public domain.
 */

#include <string.h>

int OPENSSL_strcasecmp(const char *str1, const char *str2);
int OPENSSL_strncasecmp(const char *str1, const char *str2, size_t n);

int
OPENSSL_strncasecmp(const char *str1, const char *str2, size_t n)
{
	return strncasecmp(str1, str2, n);
}

int
OPENSSL_strcasecmp(const char *str1, const char *str2)
{
	return strcasecmp(str1, str2);
}
