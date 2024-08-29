/*
 *  Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

#include <string.h>

/* Include the appropriate header file for SOCK_DGRAM */
#ifdef _WIN32 /* Windows */
# include <winsock2.h>
#else /* Linux/Unix */
# include <sys/socket.h>
# include <sys/select.h>
#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static BIO *session_bio = NULL;

/* Helper function to create a BIO connected to the server */
static BIO *create_socket_bio(const char *hostname, const char *port,
                              int family, BIO_ADDR **peer_addr)
{
    int sock = -1;
    BIO_ADDRINFO *res;
    const BIO_ADDRINFO *ai = NULL;
    BIO *bio;

    /*
     * Lookup IP address info for the server.
     */
    if (!BIO_lookup_ex(hostname, port, BIO_LOOKUP_CLIENT, family, SOCK_DGRAM, 0,
                       &res))
        return NULL;

    /*
     * Loop through all the possible addresses for the server and find one
     * we can connect to.
     */
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        /*
         * Create a UDP socket. We could equally use non-OpenSSL calls such
         * as "socket" here for this and the subsequent connect and close
         * functions. But for portability reasons and also so that we get
         * errors on the OpenSSL stack in the event of a failure we use
         * OpenSSL's versions of these functions.
         */
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_DGRAM, 0, 0);
        if (sock == -1)
            continue;

        /* Connect the socket to the server's address */
        if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), 0)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        /* Set to nonblocking mode */
        if (!BIO_socket_nbio(sock, 1)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        break;
    }

    if (sock != -1) {
        *peer_addr = BIO_ADDR_dup(BIO_ADDRINFO_address(ai));
        if (*peer_addr == NULL) {
            BIO_closesocket(sock);
            return NULL;
        }
    }

    /* Free the address information resources we allocated earlier */
    BIO_ADDRINFO_free(res);

    /* If sock is -1 then we've been unable to connect to the server */
    if (sock == -1)
        return NULL;

    /* Create a BIO to wrap the socket */
    bio = BIO_new(BIO_s_datagram());
    if (bio == NULL) {
        BIO_closesocket(sock);
        return NULL;
    }

    /*
     * Associate the newly created BIO with the underlying socket. By
     * passing BIO_CLOSE here the socket will be automatically closed when
     * the BIO is freed. Alternatively you can use BIO_NOCLOSE, in which
     * case you must close the socket explicitly when it is no longer
     * needed.
     */
    BIO_set_fd(bio, sock, BIO_CLOSE);

    return bio;
}

static void wait_for_activity(SSL *ssl)
{
    fd_set wfds, rfds;
    int width, sock, isinfinite;
    struct timeval tv;
    struct timeval *tvp = NULL;

    /* Get hold of the underlying file descriptor for the socket */
    sock = SSL_get_fd(ssl);

    FD_ZERO(&wfds);
    FD_ZERO(&rfds);

    /*
     * Find out if we would like to write to the socket, or read from it (or
     * both)
     */
    if (SSL_net_write_desired(ssl))
        FD_SET(sock, &wfds);
    if (SSL_net_read_desired(ssl))
        FD_SET(sock, &rfds);
    width = sock + 1;

    /*
     * Find out when OpenSSL would next like to be called, regardless of
     * whether the state of the underlying socket has changed or not.
     */
    if (SSL_get_event_timeout(ssl, &tv, &isinfinite) && !isinfinite)
        tvp = &tv;

    /*
     * Wait until the socket is writeable or readable. We use select here
     * for the sake of simplicity and portability, but you could equally use
     * poll/epoll or similar functions
     *
     * NOTE: For the purposes of this demonstration code this effectively
     * makes this demo block until it has something more useful to do. In a
     * real application you probably want to go and do other work here (e.g.
     * update a GUI, or service other connections).
     *
     * Let's say for example that you want to update the progress counter on
     * a GUI every 100ms. One way to do that would be to use the timeout in
     * the last parameter to "select" below. If the tvp value is greater
     * than 100ms then use 100ms instead. Then, when select returns, you
     * check if it did so because of activity on the file descriptors or
     * because of the timeout. If the 100ms GUI timeout has expired but the
     * tvp timeout has not then go and update the GUI and then restart the
     * "select" (with updated timeouts).
     */

    select(width, &rfds, &wfds, NULL, tvp);
}

static int handle_io_failure(SSL *ssl, int res)
{
    switch (SSL_get_error(ssl, res)) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        /* Temporary failure. Wait until we can read/write and try again */
        wait_for_activity(ssl);
        return 1;

    case SSL_ERROR_ZERO_RETURN:
        /* EOF */
        return 0;

    case SSL_ERROR_SYSCALL:
        return -1;

    case SSL_ERROR_SSL:
        /*
         * Some stream fatal error occurred. This could be because of a
         * stream reset - or some failure occurred on the underlying
         * connection.
         */
        switch (SSL_get_stream_read_state(ssl)) {
        case SSL_STREAM_STATE_RESET_REMOTE:
            fprintf(stderr, "Stream reset occurred\n");
            /*
             * The stream has been reset but the connection is still
             * healthy.
             */
            break;

        case SSL_STREAM_STATE_CONN_CLOSED:
            fprintf(stderr, "Connection closed\n");
            /* Connection is already closed. */
            break;

        default:
            fprintf(stderr, "Unknown stream failure\n");
            break;
        }
        /*
         * If the failure is due to a verification error we can get more
         * information about it from SSL_get_verify_result().
         */
        if (SSL_get_verify_result(ssl) != X509_V_OK)
            fprintf(stderr, "Verify error: %s\n",
                X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        return -1;

    default:
        return -1;
    }
}

static BIO *bio_keylog = NULL;

static void keylog_callback(const SSL *ssl, const char *line)
{
    if (bio_keylog == NULL) {
        fprintf(stderr, "Keylog callback is invoked without valid file!\n");
        return;
    }

    /*
     * There might be concurrent writers to the keylog file, so we must ensure
     * that the given line is written at once.
     */
    BIO_printf(bio_keylog, "%s\n", line);
    (void)BIO_flush(bio_keylog);
}

int set_keylog_file(SSL_CTX *ctx, const char *keylog_file)
{
    /* Close any open files */
    BIO_free_all(bio_keylog);
    bio_keylog = NULL;

    if (ctx == NULL || keylog_file == NULL) {
        /* Keylogging is disabled, OK. */
        return 0;
    }

    /*
     * Append rather than write in order to allow concurrent modification.
     * Furthermore, this preserves existing keylog files which is useful when
     * the tool is run multiple times.
     */
    bio_keylog = BIO_new_file(keylog_file, "a");
    if (bio_keylog == NULL) {
        printf("Error writing keylog file %s\n", keylog_file);
        return 1;
    }

    /* Write a header for seekable, empty files (this excludes pipes). */
    if (BIO_tell(bio_keylog) == 0) {
        BIO_puts(bio_keylog,
                 "# SSL/TLS secrets log file, generated by OpenSSL\n");
        (void)BIO_flush(bio_keylog);
    }
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    return 0;
}

static int session_cached = 0;
static int cache_new_session(struct ssl_st *ssl, SSL_SESSION *sess)
{

    if (session_cached == 1)
        return 0;

    /* Just write the new session to our bio */
    if (!PEM_write_bio_SSL_SESSION(session_bio, sess))
        return 0;

    fprintf(stderr, "Writing a new session to the cache\n");
    (void)BIO_flush(session_bio);
    /* only cache one session */
    session_cached = 1;
    return 1;
}

static int setup_session_cache(SSL *ssl, SSL_CTX *ctx, const char *filename)
{

    SSL_SESSION *sess = NULL;
    int rc = 0;
    int new_cache = 0;

    /* make sure caching is enabled */
    if (!SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH))
        return rc;

    /* Don't use stateless session tickets */
    if (!SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET))
        return rc;

    /* open our cache file */
    session_bio = BIO_new_file(filename, "r+");
    if (session_bio == NULL) {
        /* file might need to be created */
        session_bio = BIO_new_file(filename, "w+");
        if (session_bio == NULL)
            return rc;
        new_cache = 1;
    }

    if (new_cache == 0) {
        /* read in our cached session */
        if (PEM_read_bio_SSL_SESSION(session_bio, &sess, NULL, NULL)) {
            if (!SSL_CTX_add_session(ctx, sess))
                goto err;
            /* set our session */
            if (!SSL_set_session(ssl, sess))
                goto err;
        }
    } else {
        /* Set the callback to store new sessions */
        SSL_CTX_sess_set_new_cb(ctx, cache_new_session);
    }

    rc = 1;

err:
    if (rc == 0)
        BIO_free(session_bio);
    return rc;
}

/*
 * Simple application to send a basic HTTP/1.0 request to a server and
 * print the response on the screen. Note that HTTP/1.0 over QUIC is
 * non-standard and will not typically be supported by real world servers. This
 * is for demonstration purposes only.
 */
int main(int argc, char *argv[])
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;
    int res = EXIT_FAILURE;
    int ret;
    unsigned char alpn[] = { 10, 'h','q','-','i','n','t','e','r','o','p'};
    char req_string[1024];
    size_t written, readbytes = 0;
    char buf[160];
    BIO_ADDR *peer_addr = NULL;
    int eof = 0;
    char *hostname, *port;
    int ipv6 = 0;
    int argnext = 1;
    char *reqfile = NULL;
    char *sslkeylogfile = NULL;
    BIO *req_bio = NULL;
    char *reqnames = OPENSSL_zalloc(1025);
    size_t read_offset = 0;
    size_t bytes_read = 0;
    char *req = NULL, *saveptr = NULL;
    char outfilename[1024];
    SSL *stream_bio = NULL;

    if (argc < 4) {
        fprintf(stderr, "Usage: quic-client-non-block [-6] hostname port file\n");
        goto end;
    }

    if (!strcmp(argv[argnext], "-6")) {
        if (argc < 5) {
            fprintf(stderr, "Usage: quic-client-non-block [-6] hostname port\n");
            goto end;
        }
        ipv6 = 1;
        argnext++;
    }
    hostname = argv[argnext++];
    port = argv[argnext++];
    reqfile = argv[argnext];

    memset(req_string, 0, 1024);
#if 0
    sprintf(req_string, "GET /%s\r\n",
            reqfile);
#endif
    req_bio = BIO_new_file(reqfile, "r");
    if (req_bio == NULL) {
        fprintf(stderr, "Failed to open request file %s\n", reqfile);
        goto end;
    }

    /* Get the list of requests */
    while (!BIO_eof(req_bio)) {
        if (!BIO_read_ex(req_bio, &reqnames[read_offset], 1024, &bytes_read)) {
            fprintf(stderr, "Failed to read some data from request file\n");
            goto end;
        }
        read_offset += bytes_read;
        reqnames = OPENSSL_realloc(reqnames, read_offset+1024);
        if (reqnames == NULL) {
            fprintf(stderr, "Realloc failure\n");
            goto end;
        }
    }
    BIO_free(req_bio);
    req_bio = NULL;
    reqnames[read_offset+1] = '\0';
    
    /*
     * Create an SSL_CTX which we can use to create SSL objects from. We
     * want an SSL_CTX for creating clients so we use
     * OSSL_QUIC_client_method() here.
     */
    ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create the SSL_CTX\n");
        goto end;
    }

    /*
     * Configure the client to abort the handshake if certificate
     * verification fails. Virtually all clients should do this unless you
     * really know what you are doing.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* Use the default trusted certificate store */
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        fprintf(stderr, "Failed to set the default trusted certificate store\n");
        goto end;
    }

    sslkeylogfile = getenv("SSLKEYLOGFILE");
    if (sslkeylogfile != NULL)
        if (set_keylog_file(ctx, sslkeylogfile))
            goto end;

    /* Create an SSL object to represent the TLS connection */
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "Failed to create the SSL object\n");
        goto end;
    }

    if (getenv("SSL_SESSION_FILE") != NULL) {
        if (!setup_session_cache(ssl, ctx, getenv("SSL_SESSION_FILE"))) {
            fprintf(stderr, "Unable to setup session cache\n");
            goto end;
        }
    }

    /*
     * Create the underlying transport socket/BIO and associate it with the
     * connection.
     */
    bio = create_socket_bio(hostname, port, ipv6 ? AF_INET6 : AF_INET,
                            &peer_addr);
    if (bio == NULL) {
        fprintf(stderr, "Failed to crete the BIO\n");
        goto end;
    }
    SSL_set_bio(ssl, bio, bio);

    /*
     * Tell the server during the handshake which hostname we are attempting
     * to connect to in case the server supports multiple hosts.
     */
    if (!SSL_set_tlsext_host_name(ssl, hostname)) {
        fprintf(stderr, "Failed to set the SNI hostname\n");
        goto end;
    }

    /*
     * Ensure we check during certificate verification that the server has
     * supplied a certificate for the hostname that we were expecting.
     * Virtually all clients should do this unless you really know what you
     * are doing.
     */
    if (!SSL_set1_host(ssl, hostname)) {
        fprintf(stderr, "Failed to set the certificate verification hostname");
        goto end;
    }

    /* SSL_set_alpn_protos returns 0 for success! */
    if (SSL_set_alpn_protos(ssl, alpn, sizeof(alpn)) != 0) {
        fprintf(stderr, "Failed to set the ALPN for the connection\n");
        goto end;
    }

    /* Set the IP address of the remote peer */
    if (!SSL_set1_initial_peer_addr(ssl, peer_addr)) {
        fprintf(stderr, "Failed to set the initial peer address\n");
        goto end;
    }

    /*
     * The underlying socket is always nonblocking with QUIC, but the default
     * behaviour of the SSL object is still to block. We set it for nonblocking
     * mode in this demo.
     {*/
    if (!SSL_set_blocking_mode(ssl, 0)) {
        fprintf(stderr, "Failed to turn off blocking mode\n");
        goto end;
    }

    /* Do the handshake with the server */
    while ((ret = SSL_connect(ssl)) != 1) {
        if (handle_io_failure(ssl, ret) == 1)
            continue; /* Retry */
        fprintf(stderr, "Failed to connect to server\n");
        goto end; /* Cannot retry: error */
    }


    /* Send an http1.0 request for each item in reqnames */
    req = strtok_r(reqnames, " ", &saveptr);
    while (req != NULL) {

        eof = 0;

        /* Format the http request */
        sprintf(req_string, "GET /%s\r\n", req);

        /* build the outfile request path */
        memset(outfilename, 0, 1024);
        sprintf(outfilename, "/downloads/%s", req);

        /* open a bio to write the file */
        req_bio = BIO_new_file(outfilename, "w+");
        if (req_bio == NULL) {
            fprintf(stderr, "Failed to open outfile %s\n", outfilename);
            goto end;
        }

        /* create a request stream */
        stream_bio = SSL_new_stream(ssl, 0);
        if (stream_bio == NULL) {
            fprintf(stderr, "Failed to create stream request bio\n");
            goto end;
        }

        /* Write an HTTP GET request to the peer */
        while (!SSL_write_ex2(stream_bio, req_string, strlen(req_string),
                              SSL_WRITE_FLAG_CONCLUDE, &written)) {
            fprintf(stderr, "Write failed\n");
            if (handle_io_failure(stream_bio, 0) == 1)
                continue; /* Retry */
            fprintf(stderr, "Failed to write start of HTTP request\n");
            goto end; /* Cannot retry: error */
        }

        do {
            /*
             * Get up to sizeof(buf) bytes of the response. We keep reading until
             * the server closes the connection.
             */
            while (!eof && !SSL_read_ex(stream_bio, buf, sizeof(buf), &readbytes)) {
                switch (handle_io_failure(stream_bio, 0)) {
                case 1:
                    continue; /* Retry */
                case 0:
                    eof = 1;
                    continue;
                case -1:
                default:
                    fprintf(stderr, "Failed reading remaining data\n");
                    goto end; /* Cannot retry: error */
                }
            }
            /*
             * OpenSSL does not guarantee that the returned data is a string or
             * that it is NUL terminated so we use fwrite() to write the exact
             * number of bytes that we read. The data could be non-printable or
             * have NUL characters in the middle of it. For this simple example
             * we're going to print it to stdout anyway.
             */
            if (!eof)
                BIO_write(req_bio, buf, readbytes);
            else
                fprintf(stderr, "Wrote %s\n", outfilename);
        } while (!eof);
        /* In case the response didn't finish with a newline we add one now */
        BIO_free(req_bio);
        req_bio = NULL;
        req = strtok_r(NULL, " ", &saveptr);
        SSL_free(stream_bio);
        stream_bio = NULL;
    }

    /*
     * Repeatedly call SSL_shutdown() until the connection is fully
     * closed.
     */
    while ((ret = SSL_shutdown(ssl)) != 1) {
        if (ret < 0 && handle_io_failure(ssl, ret) == 1)
            continue; /* Retry */
    }

    /* Success! */
    res = EXIT_SUCCESS;
 end:
    /*
     * If something bad happened then we will dump the contents of the
     * OpenSSL error stack to stderr. There might be some useful diagnostic
     * information there.
     */
    if (res == EXIT_FAILURE)
        ERR_print_errors_fp(stderr);

    /*
     * Free the resources we allocated. We do not free the BIO object here
     * because ownership of it was immediately transferred to the SSL object
     * via SSL_set_bio(). The BIO will be freed when we free the SSL object.
     */
    SSL_free(stream_bio);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_ADDR_free(peer_addr);
    OPENSSL_free(reqnames);
    BIO_free(req_bio);
    BIO_free(session_bio);
    return res;
}
