/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_E_OS2_H
# define OPENtls_E_OS2_H
# pragma once

# include <opentls/macros.h>
# ifndef OPENtls_NO_DEPRECATED_3_0
#  define HEADER_E_OS2_H
# endif

# include <opentls/opentlsconf.h>

#ifdef  __cplusplus
extern "C" {
#endif

/******************************************************************************
 * Detect operating systems.  This probably needs completing.
 * The result is that at least one OPENtls_SYS_os macro should be defined.
 * However, if none is defined, Unix is assumed.
 **/

# define OPENtls_SYS_UNIX

/* --------------------- Microsoft operating systems ---------------------- */

/*
 * Note that MSDOS actually denotes 32-bit environments running on top of
 * MS-DOS, such as DJGPP one.
 */
# if defined(OPENtls_SYS_MSDOS)
#  undef OPENtls_SYS_UNIX
# endif

/*
 * For 32 bit environment, there seems to be the CygWin environment and then
 * all the others that try to do the same thing Microsoft does...
 */
/*
 * UEFI lives here because it might be built with a Microsoft toolchain and
 * we need to avoid the false positive match on Windows.
 */
# if defined(OPENtls_SYS_UEFI)
#  undef OPENtls_SYS_UNIX
# elif defined(OPENtls_SYS_UWIN)
#  undef OPENtls_SYS_UNIX
#  define OPENtls_SYS_WIN32_UWIN
# else
#  if defined(__CYGWIN__) || defined(OPENtls_SYS_CYGWIN)
#   define OPENtls_SYS_WIN32_CYGWIN
#  else
#   if defined(_WIN32) || defined(OPENtls_SYS_WIN32)
#    undef OPENtls_SYS_UNIX
#    if !defined(OPENtls_SYS_WIN32)
#     define OPENtls_SYS_WIN32
#    endif
#   endif
#   if defined(_WIN64) || defined(OPENtls_SYS_WIN64)
#    undef OPENtls_SYS_UNIX
#    if !defined(OPENtls_SYS_WIN64)
#     define OPENtls_SYS_WIN64
#    endif
#   endif
#   if defined(OPENtls_SYS_WINNT)
#    undef OPENtls_SYS_UNIX
#   endif
#   if defined(OPENtls_SYS_WINCE)
#    undef OPENtls_SYS_UNIX
#   endif
#  endif
# endif

/* Anything that tries to look like Microsoft is "Windows" */
# if defined(OPENtls_SYS_WIN32) || defined(OPENtls_SYS_WIN64) || defined(OPENtls_SYS_WINNT) || defined(OPENtls_SYS_WINCE)
#  undef OPENtls_SYS_UNIX
#  define OPENtls_SYS_WINDOWS
#  ifndef OPENtls_SYS_MSDOS
#   define OPENtls_SYS_MSDOS
#  endif
# endif

/*
 * DLL settings.  This part is a bit tough, because it's up to the
 * application implementor how he or she will link the application, so it
 * requires some macro to be used.
 */
# ifdef OPENtls_SYS_WINDOWS
#  ifndef OPENtls_OPT_WINDLL
#   if defined(_WINDLL)         /* This is used when building Opentls to
                                 * indicate that DLL linkage should be used */
#    define OPENtls_OPT_WINDLL
#   endif
#  endif
# endif

/* ------------------------------- OpenVMS -------------------------------- */
# if defined(__VMS) || defined(VMS) || defined(OPENtls_SYS_VMS)
#  if !defined(OPENtls_SYS_VMS)
#   undef OPENtls_SYS_UNIX
#  endif
#  define OPENtls_SYS_VMS
#  if defined(__DECC)
#   define OPENtls_SYS_VMS_DECC
#  elif defined(__DECCXX)
#   define OPENtls_SYS_VMS_DECC
#   define OPENtls_SYS_VMS_DECCXX
#  else
#   define OPENtls_SYS_VMS_NODECC
#  endif
# endif

/* -------------------------------- Unix ---------------------------------- */
# ifdef OPENtls_SYS_UNIX
#  if defined(linux) || defined(__linux__) && !defined(OPENtls_SYS_LINUX)
#   define OPENtls_SYS_LINUX
#  endif
#  if defined(_AIX) && !defined(OPENtls_SYS_AIX)
#   define OPENtls_SYS_AIX
#  endif
# endif

/* -------------------------------- VOS ----------------------------------- */
# if defined(__VOS__) && !defined(OPENtls_SYS_VOS)
#  define OPENtls_SYS_VOS
#  ifdef __HPPA__
#   define OPENtls_SYS_VOS_HPPA
#  endif
#  ifdef __IA32__
#   define OPENtls_SYS_VOS_IA32
#  endif
# endif

/**
 * That's it for OS-specific stuff
 *****************************************************************************/

/*-
 * OPENtls_EXTERN is normally used to declare a symbol with possible extra
 * attributes to handle its presence in a shared library.
 * OPENtls_EXPORT is used to define a symbol with extra possible attributes
 * to make it visible in a shared library.
 * Care needs to be taken when a header file is used both to declare and
 * define symbols.  Basically, for any library that exports some global
 * variables, the following code must be present in the header file that
 * declares them, before OPENtls_EXTERN is used:
 *
 * #ifdef SOME_BUILD_FLAG_MACRO
 * # undef OPENtls_EXTERN
 * # define OPENtls_EXTERN OPENtls_EXPORT
 * #endif
 *
 * The default is to have OPENtls_EXPORT and OPENtls_EXTERN
 * have some generally sensible values.
 */

# if defined(OPENtls_SYS_WINDOWS) && defined(OPENtls_OPT_WINDLL)
#  define OPENtls_EXPORT extern __declspec(dllexport)
#  define OPENtls_EXTERN extern __declspec(dllimport)
# else
#  define OPENtls_EXPORT extern
#  define OPENtls_EXTERN extern
# endif

# ifdef _WIN32
#  ifdef _WIN64
#   define otls_ssize_t __int64
#   define Otls_SSIZE_MAX _I64_MAX
#  else
#   define otls_ssize_t int
#   define Otls_SSIZE_MAX INT_MAX
#  endif
# endif

# if defined(OPENtls_SYS_UEFI) && !defined(otls_ssize_t)
#  define otls_ssize_t INTN
#  define Otls_SSIZE_MAX MAX_INTN
# endif

# ifndef otls_ssize_t
#  define otls_ssize_t ssize_t
#  if defined(SSIZE_MAX)
#   define Otls_SSIZE_MAX SSIZE_MAX
#  elif defined(_POSIX_SSIZE_MAX)
#   define Otls_SSIZE_MAX _POSIX_SSIZE_MAX
#  else
#   define Otls_SSIZE_MAX ((ssize_t)(SIZE_MAX>>1))
#  endif
# endif

# ifdef DEBUG_UNUSED
#  define __owur __attribute__((__warn_unused_result__))
# else
#  define __owur
# endif

/* Standard integer types */
# define OPENtls_NO_INTTYPES_H
# define OPENtls_NO_STDINT_H
# if defined(OPENtls_SYS_UEFI)
typedef INT8 int8_t;
typedef UINT8 uint8_t;
typedef INT16 int16_t;
typedef UINT16 uint16_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
typedef INT64 int64_t;
typedef UINT64 uint64_t;
# elif (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || \
     defined(__osf__) || defined(__sgi) || defined(__hpux) || \
     defined(OPENtls_SYS_VMS) || defined (__OpenBSD__)
#  include <inttypes.h>
#  undef OPENtls_NO_INTTYPES_H
/* Because the specs say that inttypes.h includes stdint.h if present */
#  undef OPENtls_NO_STDINT_H
# elif defined(_MSC_VER) && _MSC_VER<=1500
/*
 * minimally required typdefs for systems not supporting inttypes.h or
 * stdint.h: currently just older VC++
 */
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
# else
#  include <stdint.h>
#  undef OPENtls_NO_STDINT_H
# endif

/* otls_inline: portable inline definition usable in public headers */
# if !defined(inline) && !defined(__cplusplus)
#  if defined(__STDC_VERSION__) && __STDC_VERSION__>=199901L
   /* just use inline */
#   define otls_inline inline
#  elif defined(__GNUC__) && __GNUC__>=2
#   define otls_inline __inline__
#  elif defined(_MSC_VER)
  /*
   * Visual Studio: inline is available in C++ only, however
   * __inline is available for C, see
   * http://msdn.microsoft.com/en-us/library/z8y1yy88.aspx
   */
#   define otls_inline __inline
#  else
#   define otls_inline
#  endif
# else
#  define otls_inline inline
# endif

# if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define otls_noreturn _Noreturn
# elif defined(__GNUC__) && __GNUC__ >= 2
#  define otls_noreturn __attribute__((noreturn))
# else
#  define otls_noreturn
# endif

/* otls_unused: portable unused attribute for use in public headers */
# if defined(__GNUC__)
#  define otls_unused __attribute__((unused))
# else
#  define otls_unused
# endif

#ifdef  __cplusplus
}
#endif
#endif
