/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "internal/nelem.h"
#include "testutil/output.h"
#include "testutil.h"

#ifndef OPENSSL_NO_SOCK

# define COOKIE_LEN  20

static int cookie_gen(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    unsigned int i;

    for (i = 0; i < COOKIE_LEN; i++, cookie++)
        *cookie = i;
    *cookie_len = COOKIE_LEN;

    return 1;
}

static int cookie_verify(SSL *ssl, const unsigned char *cookie,
                         unsigned int cookie_len)
{
    unsigned int i;

    if (cookie_len != COOKIE_LEN)
        return 0;

    for (i = 0; i < COOKIE_LEN; i++, cookie++) {
        if (*cookie != i)
            return 0;
    }

    return 1;
}

static int dtls_accept_test(int unused)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL *connection = NULL;
    BIO *outbio = NULL;
    BIO *inbio = NULL;
    BIO_ADDR *peer = NULL;
    const char *stage = NULL;
    //char *data;
    //long datalen;
    int ret, success = 0;
    int socket_type = SOCK_DGRAM;
    int family      = AF_INET6;
    int protocol    = 0;  /* UDP has nothing here */
    int portnum;
    struct sockaddr_in6 loopback;
    socklen_t           loopback_len;
    int listen_fd   = -1;

    /* initialize loopback socket addr */
    memset(&loopback, 0, sizeof(loopback));
    loopback.sin6_addr = in6addr_loopback;
    loopback.sin6_family= AF_INET6;

    stage = "ctx_new";
    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
            || !TEST_ptr(peer = BIO_ADDR_new()))
        goto err;
    SSL_CTX_set_cookie_generate_cb(ctx, cookie_gen);
    SSL_CTX_set_cookie_verify_cb(ctx, cookie_verify);

    /*
     * create a socket on loopback with a random (kernel allocated)
     * port number, extract port number to use with test client
     * process.
     */
    stage = "socket";
    listen_fd = socket(family, socket_type, protocol);
    if(listen_fd < 0) goto err;

    stage = "ssl";
    if (!TEST_ptr(ssl = SSL_new(ctx)))
      goto err;

    stage = "connection-ssl";
    if (!TEST_ptr(connection = SSL_new(ctx)))
      goto err;

    inbio  = BIO_new(BIO_s_datagram());
    BIO_set_fd(inbio, listen_fd, BIO_NOCLOSE);
    outbio = inbio;
    SSL_set_bio(ssl, inbio, outbio);

    stage = "bind";
    /* bind it to ::1 */
    if(bind(listen_fd,
            (struct sockaddr *)&loopback, sizeof(struct sockaddr_in6)) != 0) {
      goto err;
    }

    stage = "getsockname";
    /* dig out the port number with getsockname */
    loopback_len = sizeof(loopback);
    if(getsockname(listen_fd, (struct sockaddr *)&loopback,
                   &loopback_len) < 0) {
      goto err;
    }
    portnum = loopback.sin6_port;
    test_printf_stdout("listening on port: %u\n", ntohs(portnum));

    while((ret = DTLSv1_accept(ssl, connection, peer)) != -1) {
      pid_t          pid;
      int            i;
      unsigned short port;
      const char *host;

      if(ret == 0) continue;  /* no new connection ready */

      /* new connection found! */
      host = BIO_ADDR_hostname_string(peer, 0);
      port = BIO_ADDR_rawport(peer);
      test_printf_stdout("connection from %s:%u\n", host, port);

      /* process this connection in a sub-process */
      pid = fork();
      switch(pid) {
      case 0:
        /* child process */
        {
          char buf[256];
          unsigned int bufsize = sizeof(buf);

          BIO *rbio = SSL_get_rbio(connection);
          BIO *wbio = SSL_get_wbio(connection);

          i = 1;
          while(i > 0) {
            i = BIO_read(rbio, buf, bufsize - 1);
            test_printf_stdout("read: %s[%d]", buf, i);
            BIO_write(wbio, buf, i);
          }
        }

        exit(0);
        break;

      case -1:
        perror("fork");
        break;

      default:
        test_printf_stderr("created child pid=%d\n", pid);
        /* parent process */
      }

      /* create a fresh connection for next connection */
      SSL_free(connection);

      if (!TEST_ptr(connection = SSL_new(ctx)))
        goto err;
    }


    success = 1;

 err:
    if(success == 0) perror(stage);
    if(listen_fd >=0) close(listen_fd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    if(peer) OPENSSL_free(peer);
    return success;
}
#endif

int setup_tests()
{
  ADD_ALL_TESTS(dtls_accept_test, 1);
  return 1;
}
