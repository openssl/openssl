/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef HEADER_E_OS_H
# define HEADER_E_OS_H

# include <openssl/opensslconf.h>

# include <openssl/e_os2.h>
/*
 * <openssl/e_os2.h> contains what we can justify to make visible to the
 * outside; this file e_os.h is not part of the exported interface.
 */

#ifdef  __cplusplus
extern "C" {
#endif

/* Used to checking reference counts, most while doing perl5 stuff :-) */
# if defined(OPENSSL_NO_STDIO)
#  if defined(REF_DEBUG)
#   error "REF_DEBUG requires stdio"
#  endif
#  if defined(REF_PRINT)
#   error "REF_PRINT requires stdio"
#  endif
# endif

# if defined(REF_DEBUG)
#  define REF_ASSERT_ISNT(test) \
    (void)((test) ? (OPENSSL_die("refcount error", __FILE__, __LINE__), 1) : 0)
# else
#  define REF_ASSERT_ISNT(i)
# endif
# ifdef REF_PRINT
#  define REF_PRINT_COUNT(a, b) \
        fprintf(stderr, "%p:%4d:%s\n", b, b->references, a)
# else
#  define REF_PRINT_COUNT(a, b)
# endif

# define osslargused(x)      (void)x
# define OPENSSL_CONF        "openssl.cnf"

# ifndef DEVRANDOM
/*
 * set this to a comma-separated list of 'random' device files to try out. My
 * default, we will try to read at least one of these files
 */
#  define DEVRANDOM "/dev/urandom","/dev/random","/dev/srandom"
# endif
# if !defined(OPENSSL_NO_EGD) && !defined(DEVRANDOM_EGD)
/*
 * set this to a comma-separated list of 'egd' sockets to try out. These
 * sockets will be tried in the order listed in case accessing the device
 * files listed in DEVRANDOM did not return enough entropy.
 */
#  define DEVRANDOM_EGD "/var/run/egd-pool","/dev/egd-pool","/etc/egd-pool","/etc/entropy"
# endif

# if defined(OPENSSL_SYS_VXWORKS)
#  define NO_SYS_PARAM_H
#  define NO_CHMOD
#  define NO_SYSLOG
# endif

/********************************************************************
 The Microsoft section
 ********************************************************************/
# if defined(OPENSSL_SYS_WIN32) && !defined(WIN32)
#  define WIN32
# endif
# if defined(OPENSSL_SYS_WINDOWS) && !defined(WINDOWS)
#  define WINDOWS
# endif
# if defined(OPENSSL_SYS_MSDOS) && !defined(MSDOS)
#  define MSDOS
# endif

# if (defined(MSDOS) || defined(OPENSSL_SYS_UEFI)) && !defined(GETPID_IS_MEANINGLESS)
#  define GETPID_IS_MEANINGLESS
# endif

# ifdef WIN32
#  define NO_SYS_UN_H
#  define get_last_sys_error()    GetLastError()
#  define clear_sys_error()       SetLastError(0)
#  if !defined(WINNT)
#   define WIN_CONSOLE_BUG
#  endif
# else
#  define get_last_sys_error()    errno
#  define clear_sys_error()       errno=0
# endif

# if defined(WINDOWS)
#  define get_last_socket_error() WSAGetLastError()
#  define clear_socket_error()    WSASetLastError(0)
#  define readsocket(s,b,n)       recv((s),(b),(n),0)
#  define writesocket(s,b,n)      send((s),(b),(n),0)
# elif defined(__DJGPP__)
#  define WATT32
#  define get_last_socket_error() errno
#  define clear_socket_error()    errno=0
#  define closesocket(s)          close_s(s)
#  define readsocket(s,b,n)       read_s(s,b,n)
#  define writesocket(s,b,n)      send(s,b,n,0)
# elif defined(OPENSSL_SYS_VMS)
#  define get_last_socket_error() errno
#  define clear_socket_error()    errno=0
#  define ioctlsocket(a,b,c)      ioctl(a,b,c)
#  define closesocket(s)          close(s)
#  define readsocket(s,b,n)       recv((s),(b),(n),0)
#  define writesocket(s,b,n)      send((s),(b),(n),0)
# elif defined(OPENSSL_SYS_VXWORKS)
#  define get_last_socket_error() errno
#  define clear_socket_error()    errno=0
#  define ioctlsocket(a,b,c)          ioctl((a),(b),(int)(c))
#  define closesocket(s)              close(s)
#  define readsocket(s,b,n)           read((s),(b),(n))
#  define writesocket(s,b,n)          write((s),(char *)(b),(n))
# else
#  define get_last_socket_error() errno
#  define clear_socket_error()    errno=0
#  define ioctlsocket(a,b,c)      ioctl(a,b,c)
#  define closesocket(s)          close(s)
#  define readsocket(s,b,n)       read((s),(b),(n))
#  define writesocket(s,b,n)      write((s),(b),(n))
# endif

# if (defined(WINDOWS) || defined(MSDOS))

#  ifdef __DJGPP__
#   include <unistd.h>
#   include <sys/stat.h>
#   include <sys/socket.h>
#   include <tcp.h>
#   include <netdb.h>
#   define _setmode setmode
#   define _O_TEXT O_TEXT
#   define _O_BINARY O_BINARY
#   undef DEVRANDOM
#   define DEVRANDOM "/dev/urandom\x24"
#  endif                        /* __DJGPP__ */

#  ifndef S_IFDIR
#   define S_IFDIR     _S_IFDIR
#  endif

#  ifndef S_IFMT
#   define S_IFMT      _S_IFMT
#  endif

#  if !defined(WINNT) && !defined(__DJGPP__)
#   define NO_SYSLOG
#  endif
#  define NO_DIRENT

#  ifdef WINDOWS
#   if !defined(_WIN32_WCE) && !defined(_WIN32_WINNT)
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
#    define _WIN32_WINNT 0x0501
#   endif
#   if !defined(OPENSSL_NO_SOCK) && (defined(_WIN32_WINNT) || defined(_WIN32_WCE))
       /*
        * Just like defining _WIN32_WINNT including winsock2.h implies
        * certain "discipline" for maintaining [broad] binary compatibility.
        * As long as structures are invariant among Winsock versions,
        * it's sufficient to check for specific Winsock2 API availability
        * at run-time [DSO_global_lookup is recommended]...
        */
#    include <winsock2.h>
#    include <ws2tcpip.h>
       /* yes, they have to be #included prior to <windows.h> */
#   endif
#   include <windows.h>
#   include <stdio.h>
#   include <stddef.h>
#   include <errno.h>
#   if defined(_WIN32_WCE) && !defined(EACCES)
#    define EACCES   13
#   endif
#   include <string.h>
#   ifdef _WIN64
#    define strlen(s) _strlen31(s)
/* cut strings to 2GB */
static __inline unsigned int _strlen31(const char *str)
{
    unsigned int len = 0;
    while (*str && len < 0x80000000U)
        str++, len++;
    return len & 0x7FFFFFFF;
}
#   endif
#   include <malloc.h>
#   if defined(_MSC_VER) && _MSC_VER<=1200 && defined(_MT) && defined(isspace)
       /* compensate for bug in VC6 ctype.h */
#    undef isspace
#    undef isdigit
#    undef isalnum
#    undef isupper
#    undef isxdigit
#   endif
#   if defined(_MSC_VER) && !defined(_WIN32_WCE) && !defined(_DLL) && defined(stdin)
#    if _MSC_VER>=1300 && _MSC_VER<1600
#     undef stdin
#     undef stdout
#     undef stderr
FILE *__iob_func();
#     define stdin  (&__iob_func()[0])
#     define stdout (&__iob_func()[1])
#     define stderr (&__iob_func()[2])
#    elif _MSC_VER<1300 && defined(I_CAN_LIVE_WITH_LNK4049)
#     undef stdin
#     undef stdout
#     undef stderr
         /*
          * pre-1300 has __p__iob(), but it's available only in msvcrt.lib,
          * or in other words with /MD. Declaring implicit import, i.e. with
          * _imp_ prefix, works correctly with all compiler options, but
          * without /MD results in LINK warning LNK4049: 'locally defined
          * symbol "__iob" imported'.
          */
extern FILE *_imp___iob;
#     define stdin  (&_imp___iob[0])
#     define stdout (&_imp___iob[1])
#     define stderr (&_imp___iob[2])
#    endif
#   endif
#  endif
#  include <io.h>
#  include <fcntl.h>

#  ifdef OPENSSL_SYS_WINCE
#   define OPENSSL_NO_POSIX_IO
#  endif

#  define EXIT(n) exit(n)
#  define LIST_SEPARATOR_CHAR ';'
#  ifndef X_OK
#   define X_OK        0
#  endif
#  ifndef W_OK
#   define W_OK        2
#  endif
#  ifndef R_OK
#   define R_OK        4
#  endif
#  ifdef OPENSSL_SYS_WINCE
#   define DEFAULT_HOME  ""
#  else
#   define DEFAULT_HOME  "C:"
#  endif

/* Avoid Visual Studio 13 GetVersion deprecated problems */
#  if defined(_MSC_VER) && _MSC_VER>=1800
#   define check_winnt() (1)
#   define check_win_minplat(x) (1)
#  else
#   define check_winnt() (GetVersion() < 0x80000000)
#   define check_win_minplat(x) (LOBYTE(LOWORD(GetVersion())) >= (x))
#  endif

# else                          /* The non-microsoft world */

#  ifdef OPENSSL_SYS_VMS
#   define VMS 1
  /*
   * some programs don't include stdlib, so exit() and others give implicit
   * function warnings
   */
#   include <stdlib.h>
#   if defined(__DECC)
#    include <unistd.h>
#   else
#    include <unixlib.h>
#   endif
#   define LIST_SEPARATOR_CHAR ','
  /* We don't have any well-defined random devices on VMS, yet... */
#   undef DEVRANDOM
  /*-
     We need to do this since VMS has the following coding on status codes:

     Bits 0-2: status type: 0 = warning, 1 = success, 2 = error, 3 = info ...
               The important thing to know is that odd numbers are considered
               good, while even ones are considered errors.
     Bits 3-15: actual status number
     Bits 16-27: facility number.  0 is considered "unknown"
     Bits 28-31: control bits.  If bit 28 is set, the shell won't try to
                 output the message (which, for random codes, just looks ugly)

     So, what we do here is to change 0 to 1 to get the default success status,
     and everything else is shifted up to fit into the status number field, and
     the status is tagged as an error, which is what is wanted here.

     Finally, we add the VMS C facility code 0x35a000, because there are some
     programs, such as Perl, that will reinterpret the code back to something
     POSIXly.  'man perlvms' explains it further.

     NOTE: the perlvms manual wants to turn all codes 2 to 255 into success
     codes (status type = 1).  I couldn't disagree more.  Fortunately, the
     status type doesn't seem to bother Perl.
     -- Richard Levitte
  */
#   define EXIT(n)  exit((n) ? (((n) << 3) | 2 | 0x10000000 | 0x35a000) : 1)

#   define NO_SYS_PARAM_H
#   define NO_SYS_UN_H

#  else
     /* !defined VMS */
#   ifdef OPENSSL_UNISTD
#    include OPENSSL_UNISTD
#   else
#    include <unistd.h>
#   endif
#   ifndef NO_SYS_TYPES_H
#    include <sys/types.h>
#   endif
#   ifdef OPENSSL_SYS_WIN32_CYGWIN
#    include <io.h>
#    include <fcntl.h>
#   endif

#   define LIST_SEPARATOR_CHAR ':'
#   define EXIT(n)             exit(n)
#  endif

# endif

/*************/

# if defined(OPENSSL_NO_SOCK) && !defined(OPENSSL_NO_DGRAM)
#  define OPENSSL_NO_DGRAM
# endif

# ifdef USE_SOCKETS
#  ifdef OPENSSL_NO_SOCK
#  elif defined(WINDOWS) || defined(MSDOS)
      /* windows world */
#   if !defined(__DJGPP__)
#    if defined(_WIN32_WCE) && _WIN32_WCE<410
#     define getservbyname _masked_declaration_getservbyname
#    endif
#    if !defined(IPPROTO_IP)
         /* winsock[2].h was included already? */
#     include <winsock.h>
#    endif
#    ifdef getservbyname
#     undef getservbyname
         /* this is used to be wcecompat/include/winsock_extras.h */
struct servent *PASCAL getservbyname(const char *, const char *);
#    endif

#    ifdef _WIN64
/*
 * Even though sizeof(SOCKET) is 8, it's safe to cast it to int, because
 * the value constitutes an index in per-process table of limited size
 * and not a real pointer. And we also depend on fact that all processors
 * Windows run on happen to be two's-complement, which allows to
 * interchange INVALID_SOCKET and -1.
 */
#     define socket(d,t,p)   ((int)socket(d,t,p))
#     define accept(s,f,l)   ((int)accept(s,f,l))
#    endif
#   else
#   endif

#  else

#   ifndef NO_SYS_PARAM_H
#    include <sys/param.h>
#   endif
#   ifdef OPENSSL_SYS_VXWORKS
#    include <time.h>
#   endif

#   include <netdb.h>
#   if defined(OPENSSL_SYS_VMS_NODECC)
#    include <socket.h>
#    include <in.h>
#    include <inet.h>
#   else
#    include <sys/socket.h>
#    ifndef NO_SYS_UN_H
#     ifdef OPENSSL_SYS_VXWORKS
#      include <streams/un.h>
#     else
#      include <sys/un.h>
#     endif
#     ifndef UNIX_PATH_MAX
#      define UNIX_PATH_MAX sizeof(((struct sockaddr_un *)NULL)->sun_path)
#     endif
#    endif
#    ifdef FILIO_H
#     include <sys/filio.h> /* FIONBIO in some SVR4, e.g. unixware, solaris */
#    endif
#    include <netinet/in.h>
#    include <arpa/inet.h>
#    include <netinet/tcp.h>
#   endif

#   ifdef OPENSSL_SYS_AIX
#    include <sys/select.h>
#   endif

#   ifdef __QNX__
#    include <sys/select.h>
#   endif

#   ifndef VMS
#    include <sys/ioctl.h>
#   else
        /* ioctl is only in VMS > 7.0 and when socketshr is not used */
#    if !defined(TCPIP_TYPE_SOCKETSHR) && defined(__VMS_VER) && (__VMS_VER > 70000000)
#     include <sys/ioctl.h>
#    endif
#   endif

#   ifdef VMS
#    include <unixio.h>
#    if defined(TCPIP_TYPE_SOCKETSHR)
#     include <socketshr.h>
#    endif
#   endif

#   ifndef INVALID_SOCKET
#    define INVALID_SOCKET      (-1)
#   endif                       /* INVALID_SOCKET */
#  endif

/*
 * Some IPv6 implementations are broken, disable them in known bad versions.
 */
#  if !defined(OPENSSL_USE_IPV6)
#   if defined(AF_INET6) && !defined(NETWARE_CLIB)
#    define OPENSSL_USE_IPV6 1
#   else
#    define OPENSSL_USE_IPV6 0
#   endif
#  endif

# endif

# ifndef OPENSSL_EXIT
#  if defined(MONOLITH) && !defined(OPENSSL_C)
#   define OPENSSL_EXIT(n) return(n)
#  else
#   define OPENSSL_EXIT(n) do { EXIT(n); return(n); } while(0)
#  endif
# endif

/***********************************************/

# if defined(OPENSSL_SYS_WINDOWS)
#  define strcasecmp _stricmp
#  define strncasecmp _strnicmp
# elif defined(OPENSSL_SYS_VMS)
/* VMS below version 7.0 doesn't have strcasecmp() */
#  include "internal/o_str.h"
#  define strcasecmp OPENSSL_strcasecmp
#  define strncasecmp OPENSSL_strncasecmp
#  define OPENSSL_IMPLEMENTS_strncasecmp
# endif

/* vxworks */
# if defined(OPENSSL_SYS_VXWORKS)
#  include <ioLib.h>
#  include <tickLib.h>
#  include <sysLib.h>

#  define TTY_STRUCT int

#  define sleep(a) taskDelay((a) * sysClkRateGet())

#  include <vxWorks.h>
#  include <sockLib.h>
#  include <taskLib.h>

#  define getpid taskIdSelf

/*
 * NOTE: these are implemented by helpers in database app! if the database is
 * not linked, we need to implement them elswhere
 */
struct hostent *gethostbyname(const char *name);
struct hostent *gethostbyaddr(const char *addr, int length, int type);
struct servent *getservbyname(const char *name, const char *proto);

# endif
/* end vxworks */

#define OSSL_NELEM(x)    (sizeof(x)/sizeof(x[0]))

#ifdef  __cplusplus
}
#endif

#endif
