#ifndef _COMPAT_BYTE_ORDER_H_
#define _COMPAT_BYTE_ORDER_H_

#ifdef __linux__
#include <endian.h>
#else
#ifdef __sun
#include <arpa/nameser_compat.h>
#else
#include_next <machine/endian.h>
#endif
#endif

#endif
