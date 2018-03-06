/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This file is included by e_os.h if building on a Windows platform.
 * The order of #include's and #define's here isn't completely arbitrary,
 * some tests only work properly after certain headers.
 */

#define get_last_sys_error() GetLastError()
#define clear_sys_error()    SetLastError(0)
#define EXIT(n)              exit(n)
#define LIST_SEPARATOR_CHAR  ';'

#if defined(WIN32) && !defined(WINNT)
# define WIN_CONSOLE_BUG
#endif

#ifdef OPENSSL_SYS_WINCE
# define OPENSSL_NO_POSIX_IO
#endif

#ifdef __DJGPP__
# include <unistd.h>
# include <sys/stat.h>
# define _setmode setmode
# define _O_TEXT O_TEXT
# define _O_BINARY O_BINARY
# define HAS_LFN_SUPPORT(name) (pathconf((name), _PC_NAME_MAX) > 12)
# undef DEVRANDOM_EGD
# undef DEVRANDOM
# define DEVRANDOM "/dev/urandom\x24"
#endif

#if !defined(WINNT) && !defined(__DJGPP__)
# define NO_SYSLOG
#endif

#if !defined(_WIN32_WCE) && !defined(_WIN32_WINNT)
       /*
        * Defining _WIN32_WINNT here in e_os.h implies certain "discipline."
        * Most notably we ought to check for availability of each specific
        * routine that was introduced after denoted _WIN32_WINNT with
        * GetProcAddress(). Normally newer functions are masked with higher
        * _WIN32_WINNT in SDK headers. So that if you wish to use them in
        * some module, you'd need to override _WIN32_WINNT definition in
        * the target module in order to "reach for" prototypes, but replace
        * calls to new functions with indirect calls. Alternatively it
        * might be possible to achieve the goal by /DELAYLOAD-ing .DLLs
        * and check for current OS version instead.
        */
# define _WIN32_WINNT 0x0501
#endif
#if defined(_WIN32_WINNT) || defined(_WIN32_WCE)
       /*
        * Just like defining _WIN32_WINNT including winsock2.h implies
        * certain "discipline" for maintaining [broad] binary compatibility.
        * As long as structures are invariant among Winsock versions,
        * it's sufficient to check for specific Winsock2 API availability
        * at run-time [DSO_global_lookup is recommended].  And yes, these
        * two files have to be #include'd before <windows.h>.
        */
# include <winsock2.h>
# include <ws2tcpip.h>
#endif
#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#if defined(_WIN32_WCE) && !defined(EACCES)
# define EACCES 13
#endif

#include <string.h>
#ifdef _WIN64
# define strlen(s) _strlen31(s)
/* cut strings to 2GB */
static __inline unsigned int _strlen31(const char *str)
{
    unsigned int len = 0;

    while (*str && len < 0x80000000U)
        str++, len++;
    return len & 0x7FFFFFFF;
}
#endif

#include <malloc.h>

#if defined(_MSC_VER) && !defined(_WIN32_WCE) && !defined(_DLL) && defined(stdin)
# if _MSC_VER >= 1300 && _MSC_VER < 1600
#  undef stdin
#  undef stdout
#  undef stderr
FILE *__iob_func();
#  define stdin  (&__iob_func()[0])
#  define stdout (&__iob_func()[1])
#  define stderr (&__iob_func()[2])
# elif _MSC_VER < 1300 && defined(I_CAN_LIVE_WITH_LNK4049)
#  undef stdin
#  undef stdout
#  undef stderr
         /*
          * pre-1300 has __p__iob(), but it's available only in msvcrt.lib,
          * or in other words with /MD. Declaring implicit import, i.e. with
          * _imp_ prefix, works correctly with all compiler options, but
          * without /MD results in LINK warning LNK4049: 'locally defined
          * symbol "__iob" imported'.
          */
extern FILE *_imp___iob;
#  define stdin  (&_imp___iob[0])
#  define stdout (&_imp___iob[1])
#  define stderr (&_imp___iob[2])
# endif
#endif

#include <io.h>
#include <fcntl.h>

#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#ifndef S_IFDIR
# define S_IFDIR _S_IFDIR
#endif
#ifndef S_IFMT
# define S_IFMT  _S_IFMT
#endif
#ifndef W_OK
# define W_OK 2
#endif
#ifndef R_OK
# define R_OK 4
#endif
#ifdef OPENSSL_SYS_WINCE
# define DEFAULT_HOME ""
#else
# define DEFAULT_HOME "C:"
#endif

#if _MSC_VER >= 1310
# define open _open
# define fdopen _fdopen
# define close _close
# define unlink _unlink
# define fileno _fileno
# ifndef strdup
#  define strdup _strdup
# endif
#endif

/* Avoid Visual Studio 13 GetVersion deprecated problems */
#if _MSC_VER >= 1800
# define check_winnt() (1)
#else
# define check_winnt() (GetVersion() < 0x80000000)
#endif
