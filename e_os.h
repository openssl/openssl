/* e_os.h */
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
#define HEADER_E_OS_H

#include <openssl/opensslconf.h>

#include <openssl/e_os2.h>
/* <openssl/e_os2.h> contains what we can justify to make visible
 * to the outside; this file e_os.h is not part of the exported
 * interface. */

#ifdef  __cplusplus
extern "C" {
#endif

/* Used to checking reference counts, most while doing perl5 stuff :-) */
#ifdef REF_PRINT
#undef REF_PRINT
#define REF_PRINT(a,b)	fprintf(stderr,"%08X:%4d:%s\n",(int)b,b->references,a)
#endif

#ifndef DEVRANDOM
/* set this to your 'random' device if you have one.
 * My default, we will try to read this file */
#define DEVRANDOM "/dev/urandom"
#endif

/********************************************************************
 The Microsoft section
 ********************************************************************/
/* The following is used becaue of the small stack in some
 * Microsoft operating systems */
#if defined(WIN16) || defined(MSDOS)
#  define MS_STATIC	static
#else
#  define MS_STATIC
#endif

#if defined(WIN32) || defined(WIN16)
#  ifndef WINDOWS
#    define WINDOWS
#  endif
#  ifndef MSDOS
#    define MSDOS
#  endif
#endif

#ifdef WIN32
#define get_last_sys_error()	GetLastError()
#define clear_sys_error()	SetLastError(0)
#if !defined(WINNT)
#define WIN_CONSOLE_BUG
#endif
#else
#define get_last_sys_error()	errno
#define clear_sys_error()	errno=0
#endif

#ifdef WINDOWS
#define get_last_socket_error()	WSAGetLastError()
#define clear_socket_error()	WSASetLastError(0)
#define readsocket(s,b,n)	recv((s),(b),(n),0)
#define writesocket(s,b,n)	send((s),(b),(n),0)
#define EADDRINUSE		WSAEADDRINUSE
#else
#define get_last_socket_error()	errno
#define clear_socket_error()	errno=0
#define ioctlsocket(a,b,c)	ioctl(a,b,c)
#define closesocket(s)		close(s)
#define readsocket(s,b,n)	read((s),(b),(n))
#define writesocket(s,b,n)	write((s),(b),(n))
#endif

#ifdef WIN16
#  define NO_FP_API
#  define MS_CALLBACK	_far _loadds
#  define MS_FAR	_far
#else
#  define MS_CALLBACK
#  define MS_FAR
#endif

#ifdef NO_STDIO
#  define NO_FP_API
#endif

#if defined(WINDOWS) || defined(MSDOS)

#ifndef S_IFDIR
#define S_IFDIR	_S_IFDIR
#endif

#ifndef S_IFMT
#define S_IFMT	_S_IFMT

#if !defined(WINNT)
#define NO_SYSLOG
#endif
#define NO_DIRENT

#endif

#  ifdef WINDOWS
#    include <windows.h>
#    include <stddef.h>
#    include <errno.h>
#    include <string.h>
#    include <malloc.h>
#  endif
#  include <io.h>
#  include <fcntl.h>

#if defined (__BORLANDC__)
#define _setmode setmode
#define _O_TEXT O_TEXT
#define _O_BINARY O_BINARY
#define _int64 __int64
#endif

#if defined(WIN16) && !defined(MONOLITH) && defined(SSLEAY) && defined(_WINEXITNOPERSIST)
#  define EXIT(n) { if (n == 0) _wsetexit(_WINEXITNOPERSIST); return(n); }
#else
#  define EXIT(n)		return(n);
#endif
#  define LIST_SEPARATOR_CHAR ';'
#ifndef X_OK
#  define X_OK	0
#endif
#ifndef W_OK
#  define W_OK	2
#endif
#ifndef R_OK
#  define R_OK	4
#endif
#  define OPENSSL_CONF	"openssl.cnf"
#  define SSLEAY_CONF	OPENSSL_CONF
#  define NUL_DEV	"nul"
#  define RFILE		".rnd"

#else /* The non-microsoft world world */

#  if defined(__VMS) && !defined(VMS)
#  define VMS 1
#  endif

#  ifdef VMS
  /* some programs don't include stdlib, so exit() and others give implicit 
     function warnings */
#    include <stdlib.h>
#    if defined(__DECC)
#      include <unistd.h>
#    else
#      include <unixlib.h>
#    endif
#    define OPENSSL_CONF	"openssl.cnf"
#    define SSLEAY_CONF		OPENSSL_CONF
#    define RFILE		".rnd"
#    define LIST_SEPARATOR_CHAR ','
#    define NUL_DEV		"NLA0:"
  /* We need to do this, because DEC C converts exit code 0 to 1, but not 1
     to 0.  We will convert 1 to 3!  Also, add the inhibit message bit... */
#    ifndef MONOLITH
#      define EXIT(n)		do { int __VMS_EXIT = n; \
                                     if (__VMS_EXIT == 1) __VMS_EXIT = 3; \
                                     __VMS_EXIT |= 0x10000000; \
				     exit(n); return(n); } while(0)
#    else
#      define EXIT(n)		do { int __VMS_EXIT = n; \
                                     if (__VMS_EXIT == 1) __VMS_EXIT = 3; \
                                     __VMS_EXIT |= 0x10000000; \
				     return(n); } while(0)
#    endif
#  else
     /* !defined VMS */
#    include OPENSSL_UNISTD

#    define OPENSSL_CONF	"openssl.cnf"
#    define SSLEAY_CONF		OPENSSL_CONF
#    define RFILE		".rnd"
#    define LIST_SEPARATOR_CHAR ':'
#    define NUL_DEV		"/dev/null"
#    ifndef MONOLITH
#      define EXIT(n)		exit(n); return(n)
#    else
#      define EXIT(n)		return(n)
#    endif
#  endif

#  define SSLeay_getpid()	getpid()

#endif


/*************/

#ifdef USE_SOCKETS
#  if defined(WINDOWS) || defined(MSDOS)
      /* windows world */

#    ifdef NO_SOCK
#      define SSLeay_Write(a,b,c)	(-1)
#      define SSLeay_Read(a,b,c)	(-1)
#      define SHUTDOWN(fd)		close(fd)
#      define SHUTDOWN2(fd)		close(fd)
#    else
#      include <winsock.h>
extern HINSTANCE _hInstance;
#      define SSLeay_Write(a,b,c)	send((a),(b),(c),0)
#      define SSLeay_Read(a,b,c)	recv((a),(b),(c),0)
#      define SHUTDOWN(fd)		{ shutdown((fd),0); closesocket(fd); }
#      define SHUTDOWN2(fd)		{ shutdown((fd),2); closesocket(fd); }
#    endif


#  else

#    include <sys/types.h>
#    ifndef VMS
#      include <sys/param.h>
#    endif
#    include <sys/time.h> /* Needed under linux for FD_XXX */

#    include <netdb.h>
#    if defined(VMS) && !defined(__DECC)
#      include <socket.h>
#      include <in.h>
#    else
#      include <sys/socket.h>
#      ifdef FILIO_H
#        include <sys/filio.h> /* Added for FIONBIO under unixware */
#      endif
#      include <netinet/in.h>
#    endif

#    if defined(NeXT) || defined(_NEXT_SOURCE)
#      include <sys/fcntl.h>
#      include <sys/types.h>
#    endif

#    ifdef AIX
#      include <sys/select.h>
#    endif

#    if defined(sun)
#      include <sys/filio.h>
#    else
#      ifndef VMS
#        include <sys/ioctl.h>
#      else
	 /* ioctl is only in VMS > 7.0 and when socketshr is not used */
#        if !defined(TCPIP_TYPE_SOCKETSHR) && defined(__VMS_VER) && (__VMS_VER > 70000000)
#          include <sys/ioctl.h>
#        endif
#      endif
#    endif

#    ifdef VMS
#      include <unixio.h>
#      if defined(TCPIP_TYPE_SOCKETSHR)
#        include <socketshr.h>
#      endif
#    endif

#    define SSLeay_Read(a,b,c)     read((a),(b),(c))
#    define SSLeay_Write(a,b,c)    write((a),(b),(c))
#    define SHUTDOWN(fd)    { shutdown((fd),0); close((fd)); }
#    define SHUTDOWN2(fd)   { shutdown((fd),2); close((fd)); }
#    define INVALID_SOCKET	(-1)
#  endif
#endif

#if defined(THREADS) || defined(sun)
#ifndef _REENTRANT
#define _REENTRANT
#endif
#endif

/***********************************************/

/* do we need to do this for getenv.
 * Just define getenv for use under windows */

#ifdef WIN16
/* How to do this needs to be thought out a bit more.... */
/*char *GETENV(char *);
#define Getenv	GETENV*/
#define Getenv	getenv
#else
#define Getenv getenv
#endif

#define DG_GCC_BUG	/* gcc < 2.6.3 on DGUX */

#ifdef sgi
#define IRIX_CC_BUG	/* all version of IRIX I've tested (4.* 5.*) */
#endif
#ifdef SNI
#define IRIX_CC_BUG	/* CDS++ up to V2.0Bsomething suffered from the same bug.*/
#endif

#ifdef NO_MD2
#define MD2_Init MD2Init
#define MD2_Update MD2Update
#define MD2_Final MD2Final
#define MD2_DIGEST_LENGTH 16
#endif
#ifdef NO_MD5
#define MD5_Init MD5Init 
#define MD5_Update MD5Update
#define MD5_Final MD5Final
#define MD5_DIGEST_LENGTH 16
#endif

#ifdef  __cplusplus
}
#endif

#endif

