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
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include "internal/nelem.h"
#include "testutil/output.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

#ifndef OPENSSL_NO_SOCK

# define COOKIE_LEN  20

#define CLIENT_TEST_COUNT 5

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

static void do_clients(int portnum)
{
  int i, pid;
  char b[512];
  /* apps/openssl s_client -dtls -connect localhost:40000  */

  snprintf(b, 512, "echo hello | apps/openssl s_client -dtls -connect localhost:%u >/dev/null 2>&1", portnum);

  for(i=0; i<CLIENT_TEST_COUNT; i++) {
    pid = fork();
    switch(pid) {
    case 0:
      /* child process */
      {
        sleep(3+(i*2));
        test_printf_stdout("starting client %u: %s\n", getpid(), b);
        system(b);
        exit(0);
      }
    default:
      test_printf_stdout("client pid=%d\n", pid);
      break;
    }
  }
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
    int one         = 1;
    struct sockaddr_in6 loopback;
    socklen_t           loopback_len;
    int listen_fd   = -1;
    int client_count = 0;

    /* initialize loopback socket addr */
    memset(&loopback, 0, sizeof(loopback));
    loopback.sin6_addr = in6addr_loopback;
    loopback.sin6_family= AF_INET6;
    loopback.sin6_port  = htons(40000);

    stage = "ctx_new";
    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
            || !TEST_ptr(peer = BIO_ADDR_new()))
        goto err;

    if (!TEST_int_eq(SSL_CTX_use_certificate_file(ctx, cert,
                                                  SSL_FILETYPE_PEM), 1)
            || !TEST_int_eq(SSL_CTX_use_PrivateKey_file(ctx, privkey,
                                                        SSL_FILETYPE_PEM), 1)
            || !TEST_int_eq(SSL_CTX_check_private_key(ctx), 1))
        goto err;

    if (!TEST_true(SSL_CTX_set_cipher_list(ctx, "AES128-SHA")))
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

    if(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) goto err;

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

    /* spawn off some clients to connect to us */
    do_clients(ntohs(portnum));

    /* kill self in 60s */
    alarm(60);

    while(client_count < CLIENT_TEST_COUNT &&
          (ret = DTLSv1_accept(ssl, connection, peer)) != -1) {
      pid_t          pid;
      int            i;
      unsigned short port;
      const char *host;

      if(ret == 0) continue;  /* no new connection ready */

      /* new connection found! */
      host = BIO_ADDR_hostname_string(peer, 0);
      port = BIO_ADDR_rawport(peer);
      test_printf_stdout("\n%u: connection from %s:%u\n",
                         client_count, host, ntohs(port));

      /* process this connection in a sub-process */
      pid = fork();
      switch(pid) {
      case 0:
        /* child process */
        {
          int need_accept = 1;

          char buf[256];
          unsigned int bufsize = sizeof(buf);
          int count = 0;
          fd_set fds;
          struct timeval timeout;

          i = 1;
          while(i > 0) {
            if(need_accept) {
              i = SSL_accept(connection);
              if(i == 1) {
                need_accept = 0;
                continue;
              }
            } else {
              i = SSL_read(connection, buf, bufsize - 1);
              if (i > 0) {
                  test_printf_stdout("packet len: %d", i);
                  BIO_dump_fp(stdout, (char *)buf, i);
                  SSL_write(connection, buf, i);
                }
            }

            if(i == -1) {
                count++;
                int err = SSL_get_error(connection, i);
                test_printf_stdout("get_error %i:%i\n", i, err);
                switch (err)
                {
                    case SSL_ERROR_NONE:
                    {
                        // no real error, just try again...
                        test_printf_stdout("SSL_ERROR_NONE %i\n", count);
                        continue;
                    }

                    case SSL_ERROR_ZERO_RETURN:
                    {
                        // peer disconnected...
                        test_printf_stdout("SSL_ERROR_ZERO_RETURN %i\n", count);
                        break;
                    }

                    case SSL_ERROR_WANT_READ:
                    {
                        // no data available right now, wait a few seconds in case new data arrives...
                        test_printf_stdout("SSL_ERROR_WANT_READ %i\n", count);

                        int sock = SSL_get_rfd(connection);
                        FD_ZERO(&fds);
                        FD_SET(sock, &fds);

                        timeout.tv_sec = 5;
                        timeout.tv_usec = 0;

                        err = select(sock+1, &fds, NULL, NULL, &timeout);
                        if (err > 0)
                            continue; // more data to read...

                        if (err == 0) {
                            // timeout...
                        } else {
                            // error...
                        }

                        break;
                    }

                    case SSL_ERROR_WANT_WRITE:
                    {
                        // socket not writable right now, wait a few seconds and try again...
                        test_printf_stdout("SSL_ERROR_WANT_WRITE %i\n", count);

                        int sock = SSL_get_wfd(connection);
                        FD_ZERO(&fds);
                        FD_SET(sock, &fds);

                        timeout.tv_sec = 5;
                        timeout.tv_usec = 0;

                        err = select(sock+1, NULL, &fds, NULL, &timeout);
                        if (err > 0)
                            continue; // can write more data now...

                        if (err == 0) {
                            // timeout...
                        } else {
                            // error...
                        }

                        break;
                    }

                case SSL_ERROR_WANT_CONNECT:
                  test_printf_stdout("want_connect %i:%i\n", i, err);
                  break;
                case SSL_ERROR_WANT_ACCEPT:
                  test_printf_stdout("want_accept %i:%i\n", i, err);
                  break;
                case SSL_ERROR_WANT_X509_LOOKUP:
                  test_printf_stdout("want_x509_lookup %i:%i\n", i, err);
                  break;
                case SSL_ERROR_SYSCALL:
                  test_printf_stdout("syscall %i:%i\n", i, err);
                  exit(12);
                case SSL_ERROR_SSL:
                  test_printf_stdout("ssl error %i:%i\n", i, err);
                  exit(11);
                default:
                  test_printf_stdout("error %i:%i\n", i, err);
                  exit(10);
                }
            }
          }
        }
        test_printf_stdout("\nterminated connection from %s:%u\n", host, port);

        exit(0);
        break;

      case -1:
        perror("fork");
        break;

      default:
        test_printf_stderr("created child pid=%d\n", pid);
        client_count++;
        /* parent process */
      }

      /* create a fresh connection for next connection */
      SSL_free(connection);

      if (!TEST_ptr(connection = SSL_new(ctx)))
        goto err;
    }

    {
      int i;
      for(i=0; i<CLIENT_TEST_COUNT; i++) {
        int wstatus;
        pid_t pid;
        pid = wait(&wstatus);
        test_printf_stdout("pid: %u finished: %d\n", pid, wstatus);
      }
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
  if (!TEST_ptr(cert = test_get_argument(0))
      || !TEST_ptr(privkey = test_get_argument(1)))
    return 0;

  ADD_ALL_TESTS(dtls_accept_test, 1);
  return 1;
}
