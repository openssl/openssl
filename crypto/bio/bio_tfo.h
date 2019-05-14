/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Contains defintions for simplifying the use of TCP Fast Open
 * in OpenSSL socket BIOs.
 */

#if defined(TCP_FASTOPEN)

# if defined(OPENSSL_SYS_MACOSX) || defined(__FreeBSD__)
#  include <sys/sysctl.h>
# endif

/*
 * OSSL_TFO_SYSCTL is used to determine if TFO is supported by
 * this kernel, and if supported, if it is enabled. This is more of
 * a problem on FreeBSD 10.3 ~ 12.0, where TCP_FASTOPEN was defined,
 * but not enabled by default in the kernel.
 * Linux does not have sysctlbyname(), and the closest equivalent
 * is to go into the /proc filesystem, but I'm not sure it's
 * worthwhile.
 *
 * The OSSL_TFO_xxxxxx_FLAGs can be OR'd together:
 * 0 = TFO disabled
 * 1 = client TFO enabled
 * 2 = server TFO enabled
 * 3 = server and client TFO enabled
 */

# define OSSL_TFO_CLIENT_FLAG 1
# define OSSL_TFO_SERVER_FLAG 2

/*
 * Some options are purposely NOT defined per-platform
 *
 * OSSL_TFO_SYSCTL
 *     Defined as a sysctlbyname() option to to determine if
 *     TFO is enabled in the kernel (macOS, FreeBSD)
 *
 * OSSL_TFO_SERVER_SOCKOPT
 *     Defined to indicate the socket option used to enable
 *     TFO on a server socket (all)
 *
 * OSSL_TFO_SERVER_SOCKOPT_VALUE
 *     Value to be used with OSSL_TFO_SERVER_SOCKOPT
 *
 * OSSL_TFO_CONNECTX
 *     Use the connectx() function to make a client connection
 *     (macOS)
 *
 * OSSL_TFO_CLIENT_SOCKOPT
 *     Defined to indicate the socket option used to enable
 *     TFO on a client socket (FreeBSD, Linux 4.14 and later)
 *
 * OSSL_TFO_SENDTO
 *     Defined to indicate the sendto() message type to
 *     be used to initiate a TFO connection (FreeBSD,
 *     Linux pre-4.14)
 *
 * OSSL_TFO_DO_NOT_CONNECT
 *     Defined to skip calling conect() when creating a
 *     client socket (macOS, FreeBSD, Linux pre-4.14)
 */

# if defined (OPENSSL_SYS_WINDOWS)
#  define OSSL_TFO_SERVER_SOCKOPT       TCP_FASTOPEN
#  define OSSL_TFO_SERVER_SOCKOPT_VALUE 1
/* still have to figure out client support */
# endif

# if defined (OPENSSL_SYS_MACOSX)
#  define OSSL_TFO_SYSCTL               "net.inet.tcp.fastopen"
#  define OSSL_TFO_SERVER_SOCKOPT       TCP_FASTOPEN
#  define OSSL_TFO_SERVER_SOCKOPT_VALUE 1
#  define OSSL_TFO_CONNECTX             1
#  define OSSL_TFO_DO_NOT_CONNECT       1
# endif

# if defined(__FreeBSD__)
#  define OSSL_TFO_SYSCTL               "net.inet.tcp.fastopen.enabled"
#  define OSSL_TFO_SERVER_SOCKOPT       TCP_FASTOPEN
#  define OSSL_TFO_SERVER_SOCKOPT_VALUE MAX_LISTEN
#  define OSSL_TFO_CLIENT_SOCKOPT       TCP_FASTOPEN
#  define OSSL_TFO_DO_NOT_CONNECT       1
#  define OSSL_TFO_SENDTO               0
# endif

# if defined(OPENSSL_SYS_LINUX)
/* OSSL_TFO_PROC not used, but of interest */
#  define OSSL_TFO_PROC                 "/proc/sys/net/ipv4/tcp_fastopen"
#  define OSSL_TFO_SERVER_SOCKOPT       TCP_FASTOPEN
#  define OSSL_TFO_SERVER_SOCKOPT_VALUE MAX_LISTEN
#  if defined(TCP_FASTOPEN_CONNECT)
#   define OSSL_TFO_CLIENT_SOCKOPT      TCP_FASTOPEN_CONNECT
#  else
#   define OSSL_TFO_SENDTO              MSG_FASTOPEN
#   define OSSL_TFO_DO_NOT_CONNECT      1
#  endif
# endif

#endif
