/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is a temporary test server for QUIC. It will eventually be replaced
 * by s_server and removed once we have full QUIC server support.
 */

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "internal/e_os.h"
#include "internal/sockets.h"
#include "internal/quic_tserver.h"
#include "internal/time.h"

static void wait_for_activity(QUIC_TSERVER *qtserv)
{
    fd_set readfds, writefds;
    fd_set *readfdsp = NULL, *writefdsp = NULL;
    struct timeval timeout, *timeoutp = NULL;
    int width;
    int sock;
    BIO *bio = ossl_quic_tserver_get0_rbio(qtserv);
    OSSL_TIME deadline;

    BIO_get_fd(bio, &sock);

    if (ossl_quic_tserver_get_net_read_desired(qtserv)) {
        readfdsp = &readfds;
        FD_ZERO(readfdsp);
        openssl_fdset(sock, readfdsp);
    }

    if (ossl_quic_tserver_get_net_write_desired(qtserv)) {
        writefdsp = &writefds;
        FD_ZERO(writefdsp);
        openssl_fdset(sock, writefdsp);
    }

    deadline = ossl_quic_tserver_get_deadline(qtserv);

    if (!ossl_time_is_infinite(deadline)) {
        timeout = ossl_time_to_timeval(ossl_time_subtract(deadline,
                                                          ossl_time_now()));
        timeoutp = &timeout;
    }

    width = sock + 1;

    if (readfdsp == NULL && writefdsp == NULL && timeoutp == NULL)
        return;

    select(width, readfdsp, writefdsp, NULL, timeoutp);
}

/* Helper function to create a BIO connected to the server */
static BIO *create_dgram_bio(int family, const char *hostname, const char *port)
{
    int sock = -1;
    BIO_ADDRINFO *res;
    const BIO_ADDRINFO *ai = NULL;
    BIO *bio;

    if (BIO_sock_init() != 1)
        return NULL;

    /*
     * Lookup IP address info for the server.
     */
    if (!BIO_lookup_ex(hostname, port, BIO_LOOKUP_SERVER, family, SOCK_DGRAM,
                       0, &res))
        return NULL;

    /*
     * Loop through all the possible addresses for the server and find one
     * we can create and start listening on
     */
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        /* Create the UDP socket */
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_DGRAM, 0, 0);
        if (sock == -1)
            continue;

        /* Start listening on the socket */
        if (!BIO_listen(sock, BIO_ADDRINFO_address(ai), 0)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        /* Set to non-blocking mode */
        if (!BIO_socket_nbio(sock, 1)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }
    }

    /* Free the address information resources we allocated earlier */
    BIO_ADDRINFO_free(res);

    /* If sock is -1 then we've been unable to connect to the server */
    if (sock == -1)
        return NULL;

    /* Create a BIO to wrap the socket*/
    bio = BIO_new(BIO_s_datagram());
    if (bio == NULL)
        BIO_closesocket(sock);

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

static void usage(void)
{
    printf("quicserver [-6] hostname port certfile keyfile\n");
}

int main(int argc, char *argv[])
{
    QUIC_TSERVER_ARGS tserver_args = {0};
    QUIC_TSERVER *qtserv = NULL;
    int ipv6 = 0;
    int argnext = 1;
    BIO *bio = NULL;
    char *hostname, *port, *certfile, *keyfile;
    int ret = EXIT_FAILURE;
    unsigned char reqbuf[1024];
    size_t numbytes, reqbytes = 0;
    const char reqterm[] = {
        '\r', '\n', '\r', '\n'
    };
    const char *msg = "Hello world\n";
    unsigned char alpn[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '0' };
    int first = 1;

    if (argc == 0)
        return EXIT_FAILURE;

    while (argnext < argc) {
        if (argv[argnext][0] != '-')
            break;
        if (strcmp(argv[argnext], "-6") == 0) {
            ipv6 = 1;
        } else {
            printf("Unrecognised argument %s\n", argv[argnext]);
            usage();
            return EXIT_FAILURE;
        }
        argnext++;
    }

    if (argc - argnext != 4) {
        usage();
        return EXIT_FAILURE;
    }
    hostname = argv[argnext++];
    port = argv[argnext++];
    certfile = argv[argnext++];
    keyfile = argv[argnext++];

    bio = create_dgram_bio(ipv6 ? AF_INET6 : AF_INET, hostname, port);
    if (bio == NULL || !BIO_up_ref(bio)) {
        BIO_free(bio);
        printf("Unable to create server socket\n");
        return EXIT_FAILURE;
    }

    tserver_args.libctx = NULL;
    tserver_args.net_rbio = bio;
    tserver_args.net_wbio = bio;
    tserver_args.alpn = alpn;
    tserver_args.alpnlen = sizeof(alpn);

    qtserv = ossl_quic_tserver_new(&tserver_args, certfile, keyfile);
    if (qtserv == NULL) {
        printf("Failed to create the QUIC_TSERVER\n");
        goto end;
    }

    printf("Starting quicserver\n");
    printf("Note that this utility will be removed in a future OpenSSL version\n");
    printf("For test purposes only. Not for use in a production environment\n");

    /* Ownership of the BIO is passed to qtserv */
    bio = NULL;

    /* Read the request */
    do {
        if (first)
            first = 0;
        else
            wait_for_activity(qtserv);

        ossl_quic_tserver_tick(qtserv);

        if (ossl_quic_tserver_read(qtserv, 0, reqbuf, sizeof(reqbuf),
                                    &numbytes)) {
            if (numbytes > 0) {
                fwrite(reqbuf, 1, numbytes, stdout);
            }
            reqbytes += numbytes;
        }
    } while (reqbytes < sizeof(reqterm)
             || memcmp(reqbuf + reqbytes - sizeof(reqterm), reqterm,
                       sizeof(reqterm)) != 0);

    /* Send the response */

    ossl_quic_tserver_tick(qtserv);
    if (!ossl_quic_tserver_write(qtserv, 0, (unsigned char *)msg, strlen(msg),
                                 &numbytes))
        goto end;

    if (!ossl_quic_tserver_conclude(qtserv, 0))
        goto end;

    /* Wait until all data we have sent has been acked */
    while (!ossl_quic_tserver_is_terminated(qtserv)
           && !ossl_quic_tserver_is_stream_totally_acked(qtserv, 0)) {
        ossl_quic_tserver_tick(qtserv);
        wait_for_activity(qtserv);
    }

    while (!ossl_quic_tserver_shutdown(qtserv))
        wait_for_activity(qtserv);

    /* Close down here */

    ret = EXIT_SUCCESS;
 end:
    /* Free twice because we did an up-ref */
    BIO_free(bio);
    BIO_free(bio);
    ossl_quic_tserver_free(qtserv);
    return ret;
}
