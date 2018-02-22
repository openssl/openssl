/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_E_OS_H
# define HEADER_E_OS_H

# include <limits.h>
# include <openssl/opensslconf.h>

# include <openssl/e_os2.h>
# include <openssl/crypto.h>
# include "internal/nelem.h"

/*
 * <openssl/e_os2.h> contains what we can justify to make visible to the
 * outside; this file e_os.h is not part of the exported interface.
 */

#ifdef  __cplusplus
extern "C" {
#endif

# ifndef DEVRANDOM
/*
 * set this to a comma-separated list of 'random' device files to try out. By
 * default, we will try to read at least one of these files
 */
#  if defined(__s390__)
#   define DEVRANDOM "/dev/prandom","/dev/urandom","/dev/hwrng","/dev/random"
#  else
#   define DEVRANDOM "/dev/urandom","/dev/random","/dev/srandom"
#  endif
# endif
# if !defined(OPENSSL_NO_EGD) && !defined(DEVRANDOM_EGD)
/*
 * set this to a comma-separated list of 'egd' sockets to try out. These
 * sockets will be tried in the order listed in case accessing the device
 * files listed in DEVRANDOM did not return enough randomness.
 */
#  define DEVRANDOM_EGD "/var/run/egd-pool","/dev/egd-pool","/etc/egd-pool","/etc/entropy"
# endif

# if defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_UEFI)
#  define NO_CHMOD
#  define NO_SYSLOG
# endif

# if defined(OPENSSL_SYS_WIN32) && !defined(WIN32)
#  define WIN32
# endif
# if defined(OPENSSL_SYS_WINDOWS) && !defined(WINDOWS)
#  define WINDOWS
# endif
# if defined(OPENSSL_SYS_MSDOS) && !defined(MSDOS)
#  define MSDOS
# endif

# if defined(WIN32) || defined(WINDOWS) || defined(MSDOS)
#  include "os-dep/microsoft.h"

# else

#  define get_last_sys_error()    errno
#  define clear_sys_error()       errno=0

#  if defined(OPENSSL_SYS_VXWORKS)
#   include <sys/times.h>
#  else
#   include <sys/time.h>
#  endif

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

#   define DEFAULT_HOME "SYS$LOGIN:"

#  else
     /* !defined VMS */
#   ifdef OPENSSL_UNISTD
#    include OPENSSL_UNISTD
#   else
#    include <unistd.h>
#   endif
#   include <sys/types.h>
#   ifdef OPENSSL_SYS_WIN32_CYGWIN
#    include <io.h>
#    include <fcntl.h>
#   endif

#   define LIST_SEPARATOR_CHAR ':'
#   define EXIT(n)             exit(n)
#  endif

# endif

/***********************************************/

/* vxworks */
# if defined(OPENSSL_SYS_VXWORKS)
#  include <ioLib.h>
#  include <tickLib.h>
#  include <sysLib.h>
#  include <vxWorks.h>
#  include <sockLib.h>
#  include <taskLib.h>

#  define TTY_STRUCT int
#  define sleep(a) taskDelay((a) * sysClkRateGet())

/*
 * NOTE: these are implemented by helpers in database app! if the database is
 * not linked, we need to implement them elsewhere
 */
struct hostent *gethostbyname(const char *name);
struct hostent *gethostbyaddr(const char *addr, int length, int type);
struct servent *getservbyname(const char *name, const char *proto);

# endif
/* end vxworks */

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
# define CRYPTO_memcmp memcmp
#endif

#ifdef  __cplusplus
}
#endif

#endif
