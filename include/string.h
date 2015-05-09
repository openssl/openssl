#include_next <string.h>

#ifndef LIBCRYPTOCOMPAT_STRING_H
#define LIBCRYPTOCOMPAT_STRING_H

#include <sys/types.h>

#ifdef __sun
/* Some functions historically defined in string.h were placed in strings.h by
 * SUS. Use the same hack as OS X and FreeBSD use to work around on Solaris.
 */
#include <strings.h>
#endif

size_t strlcpy(char *dst, const char *src, size_t siz);

size_t strlcat(char *dst, const char *src, size_t siz);

void explicit_bzero(void *, size_t);

int timingsafe_bcmp(const void *b1, const void *b2, size_t n);

int timingsafe_memcmp(const void *b1, const void *b2, size_t len);

#endif
