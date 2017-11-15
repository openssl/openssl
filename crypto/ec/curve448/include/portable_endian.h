/* Subset of Mathias Panzenböck's portable endian code, public domain */

#ifndef __PORTABLE_ENDIAN_H__
#define __PORTABLE_ENDIAN_H__

#if defined(__linux__) || defined(__CYGWIN__)
#	include <endian.h>
#elif defined(__OpenBSD__)
#	include <sys/endian.h>
#elif defined(__APPLE__)
#	include <libkern/OSByteOrder.h>
#	define htole64(x) OSSwapHostToLittleInt64(x)
#	define le64toh(x) OSSwapLittleToHostInt64(x)
#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#	include <sys/endian.h>
#	ifndef le64toh
#		define le64toh(x) letoh64(x)
#	endif
#elif defined(__sun) && defined(__SVR4)
#	include <sys/byteorder.h>
#	define htole64(x) LE_64(x)
#	define le64toh(x) LE_64(x)
#elif defined(_WIN16) || defined(_WIN32) || defined(_WIN64) || defined(__WINDOWS__)
#	include <winsock2.h>
#	include <sys/param.h>
#	if BYTE_ORDER == LITTLE_ENDIAN
#		define htole64(x) (x)
#		define le64toh(x) (x)
#	elif BYTE_ORDER == BIG_ENDIAN
#		define htole64(x) __builtin_bswap64(x)
#		define le64toh(x) __builtin_bswap64(x)
#	else
#		error byte order not supported
#	endif
#else
#	error platform not supported
#endif

#endif // __PORTABLE_ENDIAN_H__
