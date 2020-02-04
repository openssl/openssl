/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "bio_local.h"
#ifndef OPENSSL_NO_SOCK
# define SOCKET_PROTOCOL IPPROTO_TCP
# ifdef SO_MAXCONN
#  define MAX_LISTEN  SO_MAXCONN
# elif defined(SOMAXCONN)
#  define MAX_LISTEN  SOMAXCONN
# else
#  define MAX_LISTEN  32
# endif
# if defined(OPENSSL_SYS_WINDOWS)
static int wsa_init_done = 0;
# endif

# ifndef _WIN32
#  include <unistd.h>
#  include <sys/select.h>
# else
#  include <winsock.h> /* for type fd_set */
# endif

# ifndef OPENSSL_NO_DEPRECATED_1_1_0
int BIO_get_host_ip(const char *str, unsigned char *ip)
{
    BIO_ADDRINFO *res = NULL;
    int ret = 0;

    if (BIO_sock_init() != 1)
        return 0;               /* don't generate another error code here */

    if (BIO_lookup(str, NULL, BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, &res)) {
        size_t l;

        if (BIO_ADDRINFO_family(res) != AF_INET) {
            BIOerr(BIO_F_BIO_GET_HOST_IP,
                   BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET);
        } else if (BIO_ADDR_rawaddress(BIO_ADDRINFO_address(res), NULL, &l)) {
            /*
             * Because only AF_INET addresses will reach this far, we can assert
             * that l should be 4
             */
            if (ossl_assert(l == 4))
                ret = BIO_ADDR_rawaddress(BIO_ADDRINFO_address(res), ip, &l);
        }
        BIO_ADDRINFO_free(res);
    } else {
        ERR_add_error_data(2, "host=", str);
    }

    return ret;
}

int BIO_get_port(const char *str, unsigned short *port_ptr)
{
    BIO_ADDRINFO *res = NULL;
    int ret = 0;

    if (str == NULL) {
        BIOerr(BIO_F_BIO_GET_PORT, BIO_R_NO_PORT_DEFINED);
        return 0;
    }

    if (BIO_sock_init() != 1)
        return 0;               /* don't generate another error code here */

    if (BIO_lookup(NULL, str, BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, &res)) {
        if (BIO_ADDRINFO_family(res) != AF_INET) {
            BIOerr(BIO_F_BIO_GET_PORT,
                   BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET);
        } else {
            *port_ptr = ntohs(BIO_ADDR_rawport(BIO_ADDRINFO_address(res)));
            ret = 1;
        }
        BIO_ADDRINFO_free(res);
    } else {
        ERR_add_error_data(2, "host=", str);
    }

    return ret;
}
# endif

int BIO_sock_error(int sock)
{
    int j = 0, i;
    socklen_t size = sizeof(j);

    /*
     * Note: under Windows the third parameter is of type (char *) whereas
     * under other systems it is (void *) if you don't have a cast it will
     * choke the compiler: if you do have a cast then you can either go for
     * (char *) or (void *).
     */
    i = getsockopt(sock, SOL_SOCKET, SO_ERROR, (void *)&j, &size);
    if (i < 0)
        return get_last_socket_error();
    else
        return j;
}

# ifndef OPENSSL_NO_DEPRECATED_1_1_0
struct hostent *BIO_gethostbyname(const char *name)
{
    /*
     * Caching gethostbyname() results forever is wrong, so we have to let
     * the true gethostbyname() worry about this
     */
    return gethostbyname(name);
}
# endif

int BIO_sock_init(void)
{
# ifdef OPENSSL_SYS_WINDOWS
    static struct WSAData wsa_state;

    if (!wsa_init_done) {
        wsa_init_done = 1;
        memset(&wsa_state, 0, sizeof(wsa_state));
        /*
         * Not making wsa_state available to the rest of the code is formally
         * wrong. But the structures we use are [believed to be] invariable
         * among Winsock DLLs, while API availability is [expected to be]
         * probed at run-time with DSO_global_lookup.
         */
        if (WSAStartup(0x0202, &wsa_state) != 0) {
            ERR_raise_data(ERR_LIB_SYS, get_last_socket_error(),
                           "calling wsastartup()");
            BIOerr(BIO_F_BIO_SOCK_INIT, BIO_R_WSASTARTUP);
            return -1;
        }
    }
# endif                         /* OPENSSL_SYS_WINDOWS */
# ifdef WATT32
    extern int _watt_do_exit;
    _watt_do_exit = 0;          /* don't make sock_init() call exit() */
    if (sock_init())
        return -1;
# endif

    return 1;
}

void bio_sock_cleanup_int(void)
{
# ifdef OPENSSL_SYS_WINDOWS
    if (wsa_init_done) {
        wsa_init_done = 0;
        WSACleanup();
    }
# endif
}

int BIO_socket_ioctl(int fd, long type, void *arg)
{
    int i;

#  ifdef __DJGPP__
    i = ioctlsocket(fd, type, (char *)arg);
#  else
#   if defined(OPENSSL_SYS_VMS)
    /*-
     * 2011-02-18 SMS.
     * VMS ioctl() can't tolerate a 64-bit "void *arg", but we
     * observe that all the consumers pass in an "unsigned long *",
     * so we arrange a local copy with a short pointer, and use
     * that, instead.
     */
#    if __INITIAL_POINTER_SIZE == 64
#     define ARG arg_32p
#     pragma pointer_size save
#     pragma pointer_size 32
    unsigned long arg_32;
    unsigned long *arg_32p;
#     pragma pointer_size restore
    arg_32p = &arg_32;
    arg_32 = *((unsigned long *)arg);
#    else                       /* __INITIAL_POINTER_SIZE == 64 */
#     define ARG arg
#    endif                      /* __INITIAL_POINTER_SIZE == 64 [else] */
#   else                        /* defined(OPENSSL_SYS_VMS) */
#    define ARG arg
#   endif                       /* defined(OPENSSL_SYS_VMS) [else] */

    i = ioctlsocket(fd, type, ARG);
#  endif                        /* __DJGPP__ */
    if (i < 0)
        ERR_raise_data(ERR_LIB_SYS, get_last_socket_error(),
                       "calling ioctlsocket()");
    return i;
}

# ifndef OPENSSL_NO_DEPRECATED_1_1_0
int BIO_get_accept_socket(char *host, int bind_mode)
{
    int s = INVALID_SOCKET;
    char *h = NULL, *p = NULL;
    BIO_ADDRINFO *res = NULL;

    if (!BIO_parse_hostserv(host, &h, &p, BIO_PARSE_PRIO_SERV))
        return INVALID_SOCKET;

    if (BIO_sock_init() != 1)
        return INVALID_SOCKET;

    if (BIO_lookup(h, p, BIO_LOOKUP_SERVER, AF_UNSPEC, SOCK_STREAM, &res) != 0)
        goto err;

    if ((s = BIO_socket(BIO_ADDRINFO_family(res), BIO_ADDRINFO_socktype(res),
                        BIO_ADDRINFO_protocol(res), 0)) == INVALID_SOCKET) {
        s = INVALID_SOCKET;
        goto err;
    }

    if (!BIO_listen(s, BIO_ADDRINFO_address(res),
                    bind_mode ? BIO_SOCK_REUSEADDR : 0)) {
        BIO_closesocket(s);
        s = INVALID_SOCKET;
    }

 err:
    BIO_ADDRINFO_free(res);
    OPENSSL_free(h);
    OPENSSL_free(p);

    return s;
}

int BIO_accept(int sock, char **ip_port)
{
    BIO_ADDR res;
    int ret = -1;

    ret = BIO_accept_ex(sock, &res, 0);
    if (ret == (int)INVALID_SOCKET) {
        if (BIO_sock_should_retry(ret)) {
            ret = -2;
            goto end;
        }
        ERR_raise_data(ERR_LIB_SYS, get_last_socket_error(),
                       "calling accept()");
        BIOerr(BIO_F_BIO_ACCEPT, BIO_R_ACCEPT_ERROR);
        goto end;
    }

    if (ip_port != NULL) {
        char *host = BIO_ADDR_hostname_string(&res, 1);
        char *port = BIO_ADDR_service_string(&res, 1);
        if (host != NULL && port != NULL)
            *ip_port = OPENSSL_zalloc(strlen(host) + strlen(port) + 2);
        else
            *ip_port = NULL;

        if (*ip_port == NULL) {
            BIOerr(BIO_F_BIO_ACCEPT, ERR_R_MALLOC_FAILURE);
            BIO_closesocket(ret);
            ret = (int)INVALID_SOCKET;
        } else {
            strcpy(*ip_port, host);
            strcat(*ip_port, ":");
            strcat(*ip_port, port);
        }
        OPENSSL_free(host);
        OPENSSL_free(port);
    }

 end:
    return ret;
}
# endif

int BIO_set_tcp_ndelay(int s, int on)
{
    int ret = 0;
# if defined(TCP_NODELAY) && (defined(IPPROTO_TCP) || defined(SOL_TCP))
    int opt;

#  ifdef SOL_TCP
    opt = SOL_TCP;
#  else
#   ifdef IPPROTO_TCP
    opt = IPPROTO_TCP;
#   endif
#  endif

    ret = setsockopt(s, opt, TCP_NODELAY, (char *)&on, sizeof(on));
# endif
    return (ret == 0);
}

int BIO_socket_nbio(int s, int mode)
{
    int ret = -1;
    int l;

    l = mode;
# ifdef FIONBIO
    l = mode;

    ret = BIO_socket_ioctl(s, FIONBIO, &l);
# elif defined(F_GETFL) && defined(F_SETFL) && (defined(O_NONBLOCK) || defined(FNDELAY))
    /* make sure this call always pushes an error level; BIO_socket_ioctl() does so, so we do too. */

    l = fcntl(s, F_GETFL, 0);
    if (l == -1) {
        ERR_raise_data(ERR_LIB_SYS, get_last_sys_error(),
                       "calling fcntl()");
        ret = -1;
    } else {
#  if defined(O_NONBLOCK)
        l &= ~O_NONBLOCK;
#  else
        l &= ~FNDELAY; /* BSD4.x */
#  endif
        if (mode) {
#  if defined(O_NONBLOCK)
            l |= O_NONBLOCK;
#  else
            l |= FNDELAY; /* BSD4.x */
#  endif
        }
        ret = fcntl(s, F_SETFL, l);

        if (ret < 0) {
            ERR_raise_data(ERR_LIB_SYS, get_last_sys_error(),
                           "calling fcntl()");
        }
    }
# else
    /* make sure this call always pushes an error level; BIO_socket_ioctl() does so, so we do too. */
    BIOerr(BIO_F_BIO_SOCKET_NBIO, ERR_R_PASSED_INVALID_ARGUMENT);
# endif

    return (ret == 0);
}

int BIO_sock_info(int sock,
                  enum BIO_sock_info_type type, union BIO_sock_info_u *info)
{
    switch (type) {
    case BIO_SOCK_INFO_ADDRESS:
        {
            socklen_t addr_len;
            int ret = 0;
            addr_len = sizeof(*info->addr);
            ret = getsockname(sock, BIO_ADDR_sockaddr_noconst(info->addr),
                              &addr_len);
            if (ret == -1) {
                ERR_raise_data(ERR_LIB_SYS, get_last_socket_error(),
                               "calling getsockname()");
                BIOerr(BIO_F_BIO_SOCK_INFO, BIO_R_GETSOCKNAME_ERROR);
                return 0;
            }
            if ((size_t)addr_len > sizeof(*info->addr)) {
                BIOerr(BIO_F_BIO_SOCK_INFO, BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS);
                return 0;
            }
        }
        break;
    default:
        BIOerr(BIO_F_BIO_SOCK_INFO, BIO_R_UNKNOWN_INFO_TYPE);
        return 0;
    }
    return 1;
}

/* TODO simplify by BIO_socket_wait() further other uses of select() in apps/ */
/*
 * Wait on fd at most until max_time; succeed immediately if max_time == 0.
 * If for_read == 0 then assume to wait for writing, else wait for reading.
 * Returns -1 on error, 0 on timeout, and 1 on success.
 */
int BIO_socket_wait(int fd, int for_read, time_t max_time)
{
    fd_set confds;
    struct timeval tv;
    time_t now;

    if (max_time == 0)
        return 1;

    now = time(NULL);
    if (max_time <= now)
        return 0;

    FD_ZERO(&confds);
    openssl_fdset(fd, &confds);
    tv.tv_usec = 0;
    tv.tv_sec = (long)(max_time - now); /* this might overflow */
    return select(fd + 1, for_read ? &confds : NULL,
                  for_read ? NULL : &confds, NULL, &tv);
}

/*
 * Wait on BIO at most until max_time; succeed immediately if max_time == 0.
 * Returns -1 on error, 0 on timeout, and 1 on success.
 */
static int bio_wait(BIO *bio, time_t max_time)
{
    int fd;

    if (BIO_get_fd(bio, &fd) <= 0)
        return -1;
    return BIO_socket_wait(fd, BIO_should_read(bio), max_time);
}

/*
 * Wait on BIO at most until max_time; succeed immediately if max_time == 0.
 * Call BIOerr(...) unless success.
 * Returns -1 on error, 0 on timeout, and 1 on success.
 */
int BIO_wait(BIO *bio, time_t max_time)
{
    int rv = bio_wait(bio, max_time);

    if (rv <= 0)
        BIOerr(0, rv == 0 ? BIO_R_TRANSFER_TIMEOUT : BIO_R_TRANSFER_ERROR);
    return rv;
}

/*
 * Connect via the given BIO using BIO_do_connect() until success/timeout/error.
 * Parameter timeout == 0 means infinite, < 0 leads to immediate timeout error.
 * Returns -1 on error, 0 on timeout, and 1 on success.
 */
int BIO_connect_retry(BIO *bio, int timeout)
{
    int blocking = timeout == 0;
    time_t max_time = timeout > 0 ? time(NULL) + timeout : 0;
    int rv;

    if (bio == NULL) {
        BIOerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    if (timeout < 0) {
        BIOerr(0, BIO_R_CONNECT_TIMEOUT);
        return 0;
    }

    if (!blocking)
        BIO_set_nbio(bio, 1);

 retry: /* it does not help here to set SSL_MODE_AUTO_RETRY */
    rv = BIO_do_connect(bio); /* This indirectly calls ERR_clear_error(); */

    if (rv <= 0) {
        if (get_last_sys_error() == ETIMEDOUT) {
            /*
             * if blocking, despite blocking BIO, BIO_do_connect() timed out
             * when non-blocking, BIO_do_connect() timed out early
             * with rv == -1 and get_last_sys_error() == 0
             */
            ERR_clear_error();
            (void)BIO_reset(bio);
            /*
             * unless using BIO_reset(), blocking next connect() may crash and
             * non-blocking next BIO_do_connect() will fail
             */
            goto retry;
        } else if (BIO_should_retry(bio)) {
            /* will not actually wait if timeout == 0 (i.e., blocking BIO) */
            rv = bio_wait(bio, max_time);
            if (rv > 0)
                goto retry;
            BIOerr(0, rv == 0 ? BIO_R_CONNECT_TIMEOUT : BIO_R_CONNECT_ERROR);
        } else {
            rv = -1;
            if (ERR_peek_error() == 0) /* missing error queue entry */
                BIOerr(0, BIO_R_CONNECT_ERROR); /* workaround: general error */
        }
    }

    return rv;
}

#endif /* !defined(OPENSSL_NO_SOCK) */
