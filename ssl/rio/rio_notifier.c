#include "internal/rio_notifier.h"
#include "internal/sockets.h"
#include <openssl/bio.h>

/*
 * Sets a socket as close-on-exec, except that this is a no-op if we are certain
 * we do not need to do this or the OS does not support the concept.
 */
static int set_cloexec(int fd)
{
#if !defined(SOCK_CLOEXEC) && defined(FD_CLOEXEC)
    return fcntl(fd, F_SETFD, FD_CLOEXEC) >= 0;
#else
    return 1;
#endif
}

#if RIO_NOTIFIER_METHOD == RIO_NOTIFIER_METHOD_SOCKET

/* Create a close-on-exec socket. */
static int create_socket(int domain, int socktype, int protocol)
{
    int fd;

#if defined(OPENSSL_SYS_WINDOWS)
    static const int on = 1;

    /*
     * Use WSASocketA to create a socket which is immediately marked as
     * non-inheritable, avoiding race conditions if another thread is about to
     * call CreateProcess.
     */
    fd = (int)WSASocketA(domain, socktype, protocol, NULL, 0,
                         WSA_FLAG_NO_HANDLE_INHERIT);
    if (fd < 0)
        return -1;

    /* Prevent interference with the socket from other processes on Windows. */
    if (setsockopt(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (void *)&on, sizeof(on)) < 0) {
        BIO_closesocket(fd);
        return -1;
    }

#else
# if defined(SOCK_CLOEXEC)
    socktype |= SOCK_CLOEXEC;
# endif

    fd = BIO_socket(domain, socktype, protocol, 0);
    if (fd < 0)
        return -1;

    /*
     * Make socket close-on-exec unless this was already done above at socket
     * creation time.
     */
    if (!set_cloexec(fd)) {
        BIO_closesocket(fd);
        return -1;
    }
#endif

    return fd;
}

/*
 * The SOCKET notifier method manually creates a connected TCP socket pair by
 * temporarily creating a TCP listener on a random port and connecting back to
 * it.
 *
 * Win32 does not support socketpair(2), and Win32 pipes are not compatible with
 * Winsock select(2). This means our only means of making select(2) wakeable is
 * to artifically create a loopback TCP connection and send bytes to it.
 */
int ossl_rio_notifier_init(RIO_NOTIFIER *nfy)
{
    int rc, lfd = -1, rfd = -1, wfd = -1;
    struct sockaddr_in sa = {0}, accept_sa;
    socklen_t sa_len = sizeof(sa), accept_sa_len = sizeof(accept_sa);

    /* Create a close-on-exec socket. */
    lfd = create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lfd < 0)
        return 0;

    /* Bind the socket to a random loopback port. */
    sa.sin_family       = AF_INET;
    sa.sin_addr.s_addr  = htonl(INADDR_LOOPBACK);
    rc = bind(lfd, (const struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0)
        goto err;

    /* Determine what random port was allocated. */
    rc = getsockname(lfd, (struct sockaddr *)&sa, &sa_len);
    if (rc < 0)
        goto err;

    /* Start listening. */
    rc = listen(lfd, 1);
    if (rc < 0)
        goto err;

    /* Create another socket to connect to the listener. */
    wfd = create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (wfd < 0)
        goto err;

    /*
     * Disable Nagle's algorithm on the writer so that wakeups happen
     * immediately.
     */
    if (!BIO_set_tcp_ndelay(wfd, 1))
        goto err;

    /*
     * Connect the writer to the listener.
     */
    rc = connect(wfd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0)
        goto err;

    /*
     * The connection accepted from the listener is the read side.
     */
    rfd = accept(lfd, (struct sockaddr *)&accept_sa, &accept_sa_len);
    if (rfd < 0)
        goto err;

    rc = getsockname(wfd, (struct sockaddr *)&sa, &sa_len);
    if (rc < 0)
        goto err;

    /* Close the listener, which we don't need anymore. */
    BIO_closesocket(lfd);
    lfd = -1;

    /*
     * Sanity check - ensure someone else didn't connect to our listener during
     * the brief window of possibility above.
     */
    if (accept_sa.sin_family != AF_INET || accept_sa.sin_port != sa.sin_port)
        goto err;

    /* Make both sides of the connection non-blocking. */
    if (!BIO_socket_nbio(rfd, 1))
        goto err;

    if (!BIO_socket_nbio(wfd, 1))
        goto err;

    nfy->rfd = rfd;
    nfy->wfd = wfd;
    return 1;

err:
    if (lfd >= 0)
        BIO_closesocket(lfd);
    if (wfd >= 0)
        BIO_closesocket(wfd);
    if (rfd >= 0)
        BIO_closesocket(rfd);
    return 0;
}

#elif RIO_NOTIFIER_METHOD == RIO_NOTIFIER_METHOD_SOCKETPAIR

int ossl_rio_notifier_init(RIO_NOTIFIER *nfy)
{
    int fds[2], domain = AF_INET, type = SOCK_STREAM;

# if defined(SOCK_CLOEXEC)
    type |= SOCK_CLOEXEC;
# endif
# if defined(SOCK_NONBLOCK)
    type |= SOCK_NONBLOCK;
# endif

#if defined(OPENSSL_SYS_UNIX) && defined(AF_UNIX)
    domain = AF_UNIX;
#endif

    if (socketpair(domain, type, 0, fds) < 0)
        return 0;

    if (!set_cloexec(fds[0]) || !set_cloexec(fds[1]))
        goto err;

#if !defined(SOCK_NONBLOCK)
    if (!BIO_socket_nbio(fds[0], 1) || !BIO_socket_nbio(fds[1], 1))
        goto err;
#endif

    if (domain == AF_INET && !BIO_set_tcp_ndelay(fds[1], 1))
        goto err;

    nfy->rfd = fds[0];
    nfy->wfd = fds[1];
    return 1;

err:
    BIO_closesocket(fds[1]);
    BIO_closesocket(fds[0]);
    return 0;
}

#endif

void ossl_rio_notifier_cleanup(RIO_NOTIFIER *nfy)
{
    if (nfy->rfd < 0)
        return;

    BIO_closesocket(nfy->wfd);
    BIO_closesocket(nfy->rfd);
    nfy->rfd = nfy->wfd = -1;
}

int ossl_rio_notifier_signal(RIO_NOTIFIER *nfy)
{
    static const unsigned char ch = 0;
    ossl_ssize_t wr;

    do
        /*
         * Note: If wr returns 0 the buffer is already full so we don't need to
         * do anything.
         */
        wr = writesocket(nfy->wfd, (void *)&ch, sizeof(ch));
    while (wr < 0 && get_last_socket_error_is_eintr());

    return 1;
}

int ossl_rio_notifier_unsignal(RIO_NOTIFIER *nfy)
{
    unsigned char buf[16];
    ossl_ssize_t rd;

    /*
     * signal() might have been called multiple times. Drain the buffer until
     * it's empty.
     */
    do
        rd = readsocket(nfy->rfd, (void *)buf, sizeof(buf));
    while (rd == sizeof(buf)
           || (rd < 0 && get_last_socket_error_is_eintr()));

    if (rd < 0 && !BIO_fd_non_fatal_error(get_last_socket_error()))
        return 0;

    return 1;
}
