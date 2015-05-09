#include_next <stdlib.h>

#ifndef LIBCRYPTOCOMPAT_STDLIB_H
#define LIBCRYPTOCOMPAT_STDLIB_H

#include <sys/stat.h>
#include <sys/time.h>
#include <stdint.h>

uint32_t arc4random(void);
void arc4random_buf(void *_buf, size_t n);
void *reallocarray(void *, size_t, size_t);
long long strtonum(const char *nptr, long long minval,
		long long maxval, const char **errstr);

#endif
