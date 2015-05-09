#include_next <unistd.h>

#ifndef LIBCRYPTOCOMPAT_UNISTD_H
#define LIBCRYPTOCOMPAT_UNISTD_H

int getentropy(void *buf, size_t buflen);
int issetugid(void);

#endif
