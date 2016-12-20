/* ecrypt-config.h */

/* *** Normally, it should not be necessary to edit this file. *** */

#ifndef ECRYPT_CONFIG
#define ECRYPT_CONFIG

/* ------------------------------------------------------------------------- */

/* Guess the endianness of the target architecture. */

/* 
 * The LITTLE endian machines:
 */
#if defined(__ultrix)           /* Older MIPS */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(__alpha)          /* Alpha */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(i386)             /* x86 (gcc) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(__i386)           /* x86 (gcc) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(_M_IX86)          /* x86 (MSC, Borland) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(_MSC_VER)         /* x86 (surely MSC) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(__INTEL_COMPILER) /* x86 (surely Intel compiler icl.exe) */
#define ECRYPT_LITTLE_ENDIAN

/* 
 * The BIG endian machines: 
 */
#elif defined(sun)              /* Newer Sparc's */
#define ECRYPT_BIG_ENDIAN
#elif defined(__ppc__)          /* PowerPC */
#define ECRYPT_BIG_ENDIAN

/* 
 * Finally machines with UNKNOWN endianness:
 */
#elif defined (_AIX)            /* RS6000 */
#define ECRYPT_UNKNOWN
#elif defined(__hpux)           /* HP-PA */
#define ECRYPT_UNKNOWN
#elif defined(__aux)            /* 68K */
#define ECRYPT_UNKNOWN
#elif defined(__dgux)           /* 88K (but P6 in latest boxes) */
#define ECRYPT_UNKNOWN
#elif defined(__sgi)            /* Newer MIPS */
#define ECRYPT_UNKNOWN
#else	                        /* Any other processor */
#define ECRYPT_UNKNOWN
#endif

/* ------------------------------------------------------------------------- */

/*
 * Find minimal-width types to store 8-bit, 16-bit, 32-bit, and 64-bit
 * integers.
 *
 * Note: to enable 64-bit types on 32-bit compilers, it might be
 * necessary to switch from ISO C90 mode to ISO C99 mode (e.g., gcc
 * -std=c99).
 */

#include <limits.h>

/* --- check char --- */

#if (UCHAR_MAX / 0xFU > 0xFU)
#ifndef I8T
#define I8T char
#define U8C(v) (v##U)

#if (UCHAR_MAX == 0xFFU)
#define ECRYPT_I8T_IS_BYTE
#endif

#endif

#if (UCHAR_MAX / 0xFFU > 0xFFU)
#ifndef I16T
#define I16T char
#define U16C(v) (v##U)
#endif

#if (UCHAR_MAX / 0xFFFFU > 0xFFFFU)
#ifndef I32T
#define I32T char
#define U32C(v) (v##U)
#endif

#if (UCHAR_MAX / 0xFFFFFFFFU > 0xFFFFFFFFU)
#ifndef I64T
#define I64T char
#define U64C(v) (v##U)
#define ECRYPT_NATIVE64
#endif

#endif
#endif
#endif
#endif

/* --- check short --- */

#if (USHRT_MAX / 0xFU > 0xFU)
#ifndef I8T
#define I8T short
#define U8C(v) (v##U)

#if (USHRT_MAX == 0xFFU)
#define ECRYPT_I8T_IS_BYTE
#endif

#endif

#if (USHRT_MAX / 0xFFU > 0xFFU)
#ifndef I16T
#define I16T short
#define U16C(v) (v##U)
#endif

#if (USHRT_MAX / 0xFFFFU > 0xFFFFU)
#ifndef I32T
#define I32T short
#define U32C(v) (v##U)
#endif

#if (USHRT_MAX / 0xFFFFFFFFU > 0xFFFFFFFFU)
#ifndef I64T
#define I64T short
#define U64C(v) (v##U)
#define ECRYPT_NATIVE64
#endif

#endif
#endif
#endif
#endif

/* --- check int --- */

#if (UINT_MAX / 0xFU > 0xFU)
#ifndef I8T
#define I8T int
#define U8C(v) (v##U)

#if (ULONG_MAX == 0xFFU)
#define ECRYPT_I8T_IS_BYTE
#endif

#endif

#if (UINT_MAX / 0xFFU > 0xFFU)
#ifndef I16T
#define I16T int
#define U16C(v) (v##U)
#endif

#if (UINT_MAX / 0xFFFFU > 0xFFFFU)
#ifndef I32T
#define I32T int
#define U32C(v) (v##U)
#endif

#if (UINT_MAX / 0xFFFFFFFFU > 0xFFFFFFFFU)
#ifndef I64T
#define I64T int
#define U64C(v) (v##U)
#define ECRYPT_NATIVE64
#endif

#endif
#endif
#endif
#endif

/* --- check long --- */

#if (ULONG_MAX / 0xFUL > 0xFUL)
#ifndef I8T
#define I8T long
#define U8C(v) (v##UL)

#if (ULONG_MAX == 0xFFUL)
#define ECRYPT_I8T_IS_BYTE
#endif

#endif

#if (ULONG_MAX / 0xFFUL > 0xFFUL)
#ifndef I16T
#define I16T long
#define U16C(v) (v##UL)
#endif

#if (ULONG_MAX / 0xFFFFUL > 0xFFFFUL)
#ifndef I32T
#define I32T long
#define U32C(v) (v##UL)
#endif

#if (ULONG_MAX / 0xFFFFFFFFUL > 0xFFFFFFFFUL)
#ifndef I64T
#define I64T long
#define U64C(v) (v##UL)
#define ECRYPT_NATIVE64
#endif

#endif
#endif
#endif
#endif

/* --- check long long --- */

#ifdef ULLONG_MAX

#if (ULLONG_MAX / 0xFULL > 0xFULL)
#ifndef I8T
#define I8T long long
#define U8C(v) (v##ULL)

#if (ULLONG_MAX == 0xFFULL)
#define ECRYPT_I8T_IS_BYTE
#endif

#endif

#if (ULLONG_MAX / 0xFFULL > 0xFFULL)
#ifndef I16T
#define I16T long long
#define U16C(v) (v##ULL)
#endif

#if (ULLONG_MAX / 0xFFFFULL > 0xFFFFULL)
#ifndef I32T
#define I32T long long
#define U32C(v) (v##ULL)
#endif

#if (ULLONG_MAX / 0xFFFFFFFFULL > 0xFFFFFFFFULL)
#ifndef I64T
#define I64T long long
#define U64C(v) (v##ULL)
#endif

#endif
#endif
#endif
#endif

#endif

/* --- check __int64 --- */

#ifdef _UI64_MAX

#if (_UI64_MAX / 0xFFFFFFFFui64 > 0xFFFFFFFFui64)
#ifndef I64T
#define I64T __int64
#define U64C(v) (v##ui64)
#endif

#endif

#endif

/* ------------------------------------------------------------------------- */

#endif
