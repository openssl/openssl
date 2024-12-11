/*
 *  Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */


#include <string.h>

#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/quic.h>

#include "testutil.h"

#define BUF_SIZE 4096
#define FILE_MAX_SZ (8 * BUF_SIZE)

#define LOCALHOST_IP 0x7f000001

/*
 * hq-interop application protocol
 */
static const unsigned char alpn_ossltest[] = {
    10, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p',
};
static const char *whoami = "Server";
static unsigned long port;
static int quit, error;

static int select_alpn(SSL *ssl, const unsigned char **out,
                       unsigned char *out_len, const unsigned char *in,
                       unsigned int in_len, void *arg)
{
    if (SSL_select_next_proto((unsigned char **)out, out_len, alpn_ossltest,
                              sizeof(alpn_ossltest), in,
                              in_len) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static SSL_CTX *create_ctx(const char *cert_path, const char *key_path)
{
    SSL_CTX *ssl_ctx;
    int chk;

    if (cert_path == NULL && key_path == NULL) {
        ssl_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
        if (ssl_ctx == NULL) {
            TEST_error("[ %s ] %s SSL_CTX_new %s\n", whoami, __func__,
                       ERR_reason_error_string(ERR_get_error()));
            goto err;
        }

    } else {
        ssl_ctx = SSL_CTX_new(OSSL_QUIC_server_method());
        if (ssl_ctx == NULL) {
            TEST_error("[ %s ] %s SSL_CTX_new %s\n", whoami, __func__,
                       ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        SSL_CTX_set_alpn_select_cb(ssl_ctx, select_alpn, NULL);
    }

    if (cert_path != NULL) {
        chk =  SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_path);
        if (chk != 1) {
            TEST_error("[ %s ] %s SSL_CTX_use_certificate_chain_file(%s) %s\n",
                       whoami, __func__, cert_path,
                       ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
    }

    if (key_path != NULL) {
        chk = SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM);
        if (chk != 1) {
            TEST_error("[ %s ] %s SSL_CTX_use_PrivateKey(%s)  %s\n",
                       whoami, __func__, key_path,
                       ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    return ssl_ctx;

err:
    SSL_CTX_free(ssl_ctx);
    return NULL;
}

static BIO *create_socket(uint16_t port, struct in_addr *ina)
{
    int fd = -1;
    struct sockaddr_in sa;
    BIO *bio_sock = NULL;
    int chk;

    fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (fd < 0) {
        TEST_error("[ %s ] %s cannot BIO_socket %s", whoami, __func__,
                   ERR_reason_error_string(ERR_get_error()));
        goto err;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr = *ina;
    chk = bind(fd, (const struct sockaddr *)&sa, sizeof(sa));
    if (chk < 0) {
        TEST_error("[ %s ] %s bind(%d) %s\n", whoami, __func__, port,
                   strerror(errno));
        goto err;
    }

    bio_sock = BIO_new(BIO_s_datagram());
    if (bio_sock == NULL) {
        TEST_error("[ %s ] %s BIO_new %s\n", whoami, __func__,
                   ERR_reason_error_string(ERR_get_error()));
        goto err;
    }

    chk = BIO_set_fd(bio_sock, fd, BIO_CLOSE);
    if (chk != 1) {
        TEST_error("[ %s ] %s BIO_set_fd %s\n", whoami, __func__,
                   ERR_reason_error_string(ERR_get_error()));
        goto err;
    }

    return bio_sock;

err:
    BIO_free(bio_sock);
    BIO_closesocket(fd);
    return NULL;
}

static BIO *open_fake_file(const char *filename)
{
    size_t fsize, i;
    char *tmp_buf = strdup(filename);
    char *p;
    char *fsize_str;
    BIO *bio_fakef = NULL;

    if (tmp_buf == NULL)
        goto done;

    fsize_str = strchr(tmp_buf, '_');
    if (fsize_str == NULL)
        goto done;
    fsize_str++;

    p = strchr(fsize_str, '.');
    if (p == NULL)
        goto done;
    *p = '\0';

    fsize = atoi(fsize_str);
    if (fsize > FILE_MAX_SZ || fsize <= 0)
        goto done;

    free(tmp_buf);
    tmp_buf = (char *)malloc(fsize);
    if (tmp_buf == NULL)
        goto done;

    bio_fakef = BIO_new_mem_buf(tmp_buf, fsize);
    if (bio_fakef == NULL)
        goto done;

    /*
     * fill buffer with 'OpenSSLOpenSSLOpenS...' pattern
     */
    for (i = 0; i < fsize; i++)
        tmp_buf[i] = "OpenSSL"[i % (sizeof ("OpenSSL") - 1)]; 

done:
    free(tmp_buf);

    return bio_fakef;
}

static void send_file(SSL *ssl_qstream, const char *filename)
{
    unsigned char buf[BUF_SIZE];
    BIO *bio_fakef;
    size_t bytes_read = 0;
    size_t bytes_written = 0;
    size_t offset = 0;
    int chk;

    TEST_info("( Server ) Serving %s\n", filename);
    bio_fakef = open_fake_file(filename);
    if (bio_fakef == NULL) {
        TEST_error("[ Server ] Unable to open %s\n", filename);
        ERR_print_errors_fp(stderr);
        goto done;
    }

    while (BIO_eof(bio_fakef) <= 0) {
        bytes_read = 0;
        chk = BIO_read_ex(bio_fakef, buf, BUF_SIZE, &bytes_read);
        if (chk == 0) {
            chk = BIO_eof(bio_fakef);
            if (chk != 1) {
                TEST_error("[ Server ] Failed to read from %s\n", filename);
                ERR_print_errors_fp(stderr);
                goto done;
            } else {
                break;
            }
        }

        offset = 0;
        for (;;) {
            bytes_written = 0;
            chk = SSL_write_ex(ssl_qstream, &buf[offset], bytes_read, &bytes_written);
            if (chk == 0) {
                chk = SSL_get_error(ssl_qstream, chk);
                switch (chk) {
                case SSL_ERROR_WANT_WRITE:
                    TEST_error("[ Server ] %s Send buffer full, retrying\n", 
                               __func__);
                    continue;
                default:
                    TEST_error("[ Server ] %s Unhandled error cause %s\n",
                               __func__, ERR_reason_error_string(chk));
                    goto done;
                }
            }
            bytes_read -= bytes_written;
            offset += bytes_written;
            bytes_written = 0;
            if (bytes_read == 0)
                break;
        }
    }

done:
    BIO_free(bio_fakef);

    return;
}

static void process_new_stream(SSL *ssl_qlistener, SSL *ssl_qstream)
{
    unsigned char buf[BUF_SIZE];
    char path[BUF_SIZE];
    char *req = (char *)buf;
    char *reqname;
    char *dst_host;
    char *dst_port_str;
    size_t nread;
    char *creturn;
    BIO_ADDRINFO *bio_addr = NULL;
    SSL *ssl_qconn = NULL;
    int chk;

    memset(buf, 0, BUF_SIZE);
    chk = SSL_read_ex(ssl_qstream, buf, sizeof(buf) - 1, &nread);
    if (chk == 0) {
        quit = 1;
        return;
    }

    TEST_info("(Server) Request is %s\n", req);

    reqname = strrchr(req, '/');
    if (reqname == NULL) {
        quit = 1;
        return;
    }
    *reqname = '\0';
    reqname++;
    creturn = strchr(reqname, '\r');
    if (creturn != NULL)
        *creturn = '\0';

    snprintf(path, BUF_SIZE, "%s", reqname);

    /*
     * in case request is something like:
     *    /hostname:port/file.txt
     * the server connects back to client to
     * transfer file.txt (think of active FTP),
     */
    dst_host = strrchr(req, '/');
    if (dst_host != NULL) {

        dst_host++;
        dst_port_str = strchr(dst_host, ':');
        if (dst_port_str == NULL) {
            dst_host = NULL;
        } else {
            *dst_port_str = '\0';
            dst_port_str++;
            chk = BIO_lookup_ex(dst_host, dst_port_str, BIO_LOOKUP_CLIENT,
                                AF_INET, SOCK_DGRAM, 0, &bio_addr);
            if (chk == 0) {
                TEST_error("[ Server ] %s BIO_lookup_ex(%s, %s) error (%s)\n",
                           __func__, dst_host, dst_port_str,
                           ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto done;
            }

            ssl_qconn = SSL_new_from_listener(ssl_qlistener, 0);
            if (ssl_qconn == NULL) {
                TEST_error("[ Server ] %s SSL_new_from_listener error (%s)\n",
                           __func__, ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto done;
            }

            chk = SSL_set1_initial_peer_addr(ssl_qconn,
                                             BIO_ADDRINFO_address(bio_addr));
            if (chk == 0) {
                TEST_error("[ Server ] %s SSL_new_from_listener error (%s)\n",
                           __func__, ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto done;
            }

            chk = SSL_set_alpn_protos(ssl_qconn, alpn_ossltest, sizeof(alpn_ossltest));
            if (chk != 0) {
                TEST_error("[ Client ] %s SSL_set_alpn_protos failed %s\n",
                           __func__, ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto done;
            }

            chk = SSL_connect(ssl_qconn);
            if (chk != 1) {
                TEST_error("[ Server ] %s SSL_connect() to %s:%s failed (%s)\n",
                           __func__, dst_host, dst_port_str,
                           ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto done;
            }

            SSL_free(ssl_qstream);
            /*
             * We connect back to client, but still expect client to initiate
             * a QUIC stream for transfer.
             */
            chk = SSL_set_incoming_stream_policy(ssl_qconn,
                                                 SSL_INCOMING_STREAM_POLICY_ACCEPT,
                                                 0);
            if (chk == 0) {
                TEST_error("[ Server ] %s SSL_set_incoming_stream_policy %s\n",
                           __func__, ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto shutdown;
            }

            TEST_info("( Server ) waiting for stream\n");

            ssl_qstream = SSL_new_stream(ssl_qconn, 0);
            if (ssl_qstream == NULL) {
                TEST_error("[ Server ] %s SSL_new_stream() to %s:%s failed (%s)\n",
                           __func__, dst_host, dst_port_str,
                           ERR_reason_error_string(ERR_get_error()));
                quit = 1;
                goto shutdown;
            }
            TEST_info("( Server ) got stream\n");
        }
    }

    send_file(ssl_qstream, path);
    SSL_stream_conclude(ssl_qstream, 0);

shutdown:
    SSL_shutdown(ssl_qconn);

done:
    SSL_free(ssl_qstream);
    SSL_free(ssl_qconn);
    BIO_ADDRINFO_free(bio_addr);
}

static int run_quic_server(SSL_CTX *ssl_ctx, BIO *bio_sock)
{
    int err = 1;
    int chk;
    SSL *ssl_qlistener, *ssl_qconn, *ssl_qstream;
    unsigned long errcode;

    ssl_qlistener = SSL_new_listener(ssl_ctx, 0);
    if (ssl_qlistener == NULL)
        goto err;

    SSL_set_bio(ssl_qlistener, bio_sock, bio_sock);

    chk = SSL_listen(ssl_qlistener);
    if (chk == 0)
        goto err;

    while (quit == 0) {
        ERR_clear_error();

        TEST_info("( Server ) Waiting for connection\n");
        ssl_qconn = SSL_accept_connection(ssl_qlistener, 0);
        if (ssl_qconn == NULL) {
            TEST_error("[ Server ] %s SSL_accept_connection %s\n",
                       __func__, ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        TEST_info("( Server ) Accepted new connection\n");

        chk = SSL_set_incoming_stream_policy(ssl_qconn,
                                             SSL_INCOMING_STREAM_POLICY_ACCEPT,
                                             0);
        if (chk == 0) {
            TEST_error("[ Server ] %s SSL_set_incoming_stream_policy %s\n",
                       __func__, ERR_reason_error_string(ERR_get_error()));
            goto close_conn;
        }

        while (quit == 0) {
            ssl_qstream = SSL_accept_stream(ssl_qconn, 0);
            if (ssl_qstream == NULL) {
                errcode = ERR_get_error();
                if (ERR_GET_REASON(errcode) != SSL_R_PROTOCOL_IS_SHUTDOWN)
                    TEST_error("[ Server ] %s SSL_accept_stream %s\n",
                               __func__, ERR_reason_error_string(errcode));
                break;
            }
            process_new_stream(ssl_qlistener, ssl_qstream);
        }

close_conn:
        while (SSL_shutdown(ssl_qconn) != 1)
            continue;

        SSL_free(ssl_qconn);
    }

    err = error;

err:
    SSL_free(ssl_qlistener);

    return err;
}

static int client_stream_transfer(SSL *ssl_qstream, size_t expected,
                                  const char *filename)
{
    char buf[1024];
    size_t transfered, x;
    int chk;

    transfered = 0;
    while (transfered < expected) {
        TEST_info("( Client ) reading from stream ... \n");
        chk = SSL_read_ex(ssl_qstream, buf, sizeof(buf), &x);
        if (chk == 0) {
            TEST_error("[ Client ] %s SSL_read_ex(%s) { %lu } %s\n",
                       __func__, filename, transfered,
                       ERR_reason_error_string(ERR_get_error()));
            return 1;
        }
        TEST_info("( Client ) got %lu bytes\n", x);
        transfered += x;
    }

    if (transfered != expected) {
        TEST_error("[ Client ] %s transfer %s incomplete, missing %ld\n",
                   __func__, filename, expected - transfered);
        return 1;
    }

    chk = SSL_read_ex(ssl_qstream, buf, sizeof(buf), &x);
    if (chk == 1) {
        TEST_error("[ Client ] %s there is more than %lu to receive in %s\n",
                   __func__, expected, filename);
        return 1;
    }

    return 0;
}

int client_passive_transfer(SSL *ssl_qstream, const char *filename)
{
    char buf[1024];
    char *fsize_str, *p;
    size_t fsize, transfered;
    int err = 1;
    int chk;

    strlcpy(buf, filename, sizeof(buf) - 1);
    fsize_str = strchr(buf, '_');
    if (fsize_str == NULL) {
        TEST_error("[ Client ] %s no '_' found in %s\n",
                   __func__, filename);
        goto done;
    }

    fsize_str++;
    p = strchr(fsize_str, '.');
    if (p == NULL) {
        TEST_error("[ Client ] %s no '.' found in %s\n",
                   __func__, filename);
        goto done;
    }
    *p = '\0';

    fsize = (size_t)atoi(fsize_str);
    if (fsize == 0 || fsize > FILE_MAX_SZ) {
        TEST_error("[ Client ] %s unexpected length in %s\n",
                   __func__, filename);
        goto done;
    }

    snprintf(buf, sizeof(buf), "GET /%s\r\n", filename);
    chk = SSL_write_ex(ssl_qstream, buf, strlen(buf), &transfered);
    if (chk == 0) {
        TEST_error("[ Client ] %s SSL_write_ex('GET /%s') failed %s\n",
                   __func__, filename,
                   ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    err = client_stream_transfer(ssl_qstream, fsize, filename);

done:
    return err;
}

int client_active_transfer(SSL *ssl_stream_cmd, SSL *ssl_qconn_listener,
                           const char *filename)
{
    char buf[1024];
    char *fsize_str, *p;
    size_t fsize, transfered;
    SSL *ssl_qconn_data = NULL;
    SSL *ssl_qstream_data = NULL;
    int err = 1;
    int chk;

    strlcpy(buf, filename, sizeof(buf) - 1);
    fsize_str = strchr(buf, '_');
    if (fsize_str == NULL) {
        TEST_error("[ Client ] no '_' found in %s\n", filename);
        goto done;
    }

    fsize_str++;
    p = strchr(fsize_str, '.');
    if (p == NULL) {
        TEST_error("[ Client ] no '.' found in %s\n", filename);
        goto done;
    }
    *p = '\0';

    fsize = (size_t)atoi(fsize_str);
    if (fsize == 0) {
        TEST_error("[ Client ] %s unexpected length in %s\n",
                   __func__, filename);
        goto done;
    }

    /*
     * Active transfer request, server connects back, note the
     * first path component is localhost:port. We use port + 1 where
     * we expect server to connect back.
     */
    snprintf(buf, sizeof(buf), "GET /%s:%u/%s\r\n", "localhost",
             (unsigned short)port + 1, filename);
    chk = SSL_write_ex(ssl_stream_cmd, buf, strlen(buf), &transfered);
    if (chk == 0) {
        TEST_error("[ Client ] %s SSL_write_ex() failed %s\n",
                   __func__, ERR_reason_error_string(ERR_get_error()));
        goto done;
    }
    /*
     * we are done with transfer command, we must accept stream
     * on data connection to receive file.
     */
    SSL_stream_conclude(ssl_stream_cmd, 0);

    /*
     * accept QUIC connection for data first.
     */
    ssl_qconn_data = SSL_accept_connection(ssl_qconn_listener, 0);
    if (ssl_qconn_data == NULL) {
        TEST_error("[ Client ] %s SSL_accept_connectio failed %s\n",
                   __func__, ERR_reason_error_string(ERR_get_error()));
        goto done;
    }
    /*
     * create data stream to receive data from server.
     */
    ssl_qstream_data = SSL_accept_stream(ssl_qconn_data, 0);
    if (ssl_qstream_data == NULL) {
        TEST_error("[ Client ] %s SSL_new_stream failed %s\n",
                   __func__, ERR_reason_error_string(ERR_get_error()));
        ERR_print_errors_fp(stderr);
        goto done;
    }

    err = client_stream_transfer(ssl_qstream_data, fsize, filename);

    SSL_stream_conclude(ssl_qstream_data, 0);
done:
    SSL_shutdown(ssl_qconn_data);
    SSL_free(ssl_qstream_data);
    SSL_free(ssl_qconn_data);

    return err;
}

void client_send_quit(SSL *ssl_qconn)
{
    SSL *ssl_stream;

    ssl_stream = SSL_new_stream(ssl_qconn, SSL_STREAM_FLAG_UNI);
    if (ssl_stream != NULL) {
        SSL_write(ssl_stream, "QUIT\r\n", sizeof("QUIT\r\n") - 1);
        SSL_stream_conclude(ssl_stream, 0);
        SSL_free(ssl_stream);
    } else {
        TEST_error("[ Client ] %s can not create stream %s\n",
                   __func__, ERR_reason_error_string(ERR_get_error()));
    }
}

int client_run(SSL *ssl_qconn, SSL *ssl_qconn_listener)
{
    SSL *ssl_stream_cmd;
    const char *filenames[] = {
        "file_1024.txt",
        "file_2048.txt",
        "file_3076.txt",
        "file_4096.txt",
        "file_1234.txt",
        NULL
    };
    const char **filename = filenames;
    int err = 0;

    while (err == 0 && *filename != NULL) {
        ssl_stream_cmd = SSL_new_stream(ssl_qconn, 0);
        if (ssl_stream_cmd == NULL) {
            TEST_error("[ Client ] %s SSL_new_stream failed (%s)\n",
                       __func__, ERR_reason_error_string(ERR_get_error()));
            err = 1;
            continue;
        }

        TEST_info("( Client ) %s getting %s\n", __func__, *filename);
        if (ssl_qconn_listener == NULL)
            err = client_passive_transfer(ssl_stream_cmd, *filename);
        else
            err = client_active_transfer(ssl_stream_cmd, ssl_qconn_listener,
                                         *filename);
        if (err == 0)
            filename++;

        SSL_free(ssl_stream_cmd);
    }

    if (err != 0)
        TEST_error("[ Client ] %s could not get %s\n",
                   __func__, *filename);

    return err;
}

int client_main(int argc, char *argv[])
{
    SSL_CTX *ssl_ctx = NULL;
    SSL_CTX *ssl_ctx_data = NULL;
    BIO *bio_sock = NULL;
    BIO *bio_sock_data = NULL;
    SSL *ssl_qconn = NULL;
    SSL *ssl_qconn_listener = NULL;
    int err = 1;
    int chk;
    struct in_addr ina = { 0 };
    BIO_ADDR *bio_addr = NULL;

    whoami = "Client";

    /*
     * We are creating two QUIC SSL objects here:
     *    - SSL QUIC connection client object
     *    - SSL QUIC listener (server if you want) where remote
     *      QUIC server connects to perform active-FTP like data
     *      transfer
     *
     * create quic connection SSL client object. This involves steps as
     * follows:
     *    - create context for client (no servercert, serverkey are needed)
     *    - create UDP socket for client, although create_socket() calls
     *      bind(2) we let system to bind socket to any addr (ina = { 0 }).
     *    - we create ssl_qconn a quic client connection object
     *    - the ssl_qconn needs to be further initialized:
     *        o Assign a dstIP:dstPort of remote QUIC server where client
     *          connects to
     *        o set application layer protocol negotiation, we use hq-interop
     *        o use SSL_connect() to connect to server.
     */

    /*
     * we create a QUIC client, hence servercert and serverkey are NULL.
     */
    ssl_ctx = create_ctx(NULL, NULL);
    if (ssl_ctx == NULL) {
        TEST_error("[ Client ]: Failed to create context (%s)\n",
                   ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    bio_sock = create_socket(0, &ina);
    if (bio_sock == NULL) {
        TEST_error("[ Client ]: could not create socket (%s)\n",
                   ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    ssl_qconn = SSL_new(ssl_ctx);
    if (ssl_qconn == NULL) {
        TEST_error("[ Client ]: could not create socket (%s)\n",
                   ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    /*
     * pass socket to ssl_qconn object, ssl_qconn uses the socket
     * for reading and writing,
     */
    SSL_set_bio(ssl_qconn, bio_sock, bio_sock);
    bio_sock = NULL;

    /*
     * Set up a destination address where client connects to.
     */
    ina.s_addr = htonl(LOCALHOST_IP);
    bio_addr = BIO_ADDR_new();
    if (bio_addr == NULL) {
        TEST_error("[ Client ]: failed to allocate BIO_ADDR\n");
        goto done;
    }
    chk = BIO_ADDR_rawmake(bio_addr, AF_INET, &ina, sizeof(ina),
                           htons((uint16_t)port));
    if (chk == 0) {
        TEST_error("[ Client ]: BIO_ADDR_rawmake %s\n",
                    ERR_reason_error_string(ERR_get_error()));
        goto done;
    }
    chk = SSL_set1_initial_peer_addr(ssl_qconn, bio_addr);
    if (chk == 0) {
        TEST_error("[ Client ]:  SSL_set1_initial_peer_addr (%s)\n",
                   ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    /*
     * we are hq-interop client.
     */
    chk = SSL_set_alpn_protos(ssl_qconn, alpn_ossltest, sizeof(alpn_ossltest));
    if (chk != 0) {
        TEST_error("[ Client ] ]: SSL_set_alpn_protos failed %s\n",
                   ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    chk = SSL_connect(ssl_qconn);
    if (chk != 1) {
        TEST_error("[ Client ]:  SSL_connect (%s)\n",
                   ERR_reason_error_string(ERR_get_error()));
        ERR_print_errors_fp(stderr);
        goto done;
    }

    /*
     * Here we create QUIC listener for data received in active-FTP like
     * fashion.
     */
    ssl_ctx_data = create_ctx(argv[2], argv[3]);
    if (ssl_ctx_data == NULL) {
        TEST_error("[ Client ]: Failed to create data context\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    /* Create and bind a UDP socket. Note: we use port number port + 1 for
     * client's listener
     */
    bio_sock_data = create_socket((uint16_t)port + 1, &ina);
    if (bio_sock_data == NULL) {
        TEST_error("[ Client ] Failed to create socket\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    ssl_qconn_listener = SSL_new_listener(ssl_ctx_data, 0);
    if (ssl_qconn_listener == NULL) {
        TEST_error("[ Client ] Failed to create listener %s\n",
                   ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    SSL_set_bio(ssl_qconn_listener, bio_sock_data, bio_sock_data);
    bio_sock_data = NULL;

    chk = SSL_listen(ssl_qconn_listener);
    if (chk == 0) {
        TEST_error("[ Client ] Failed to start listener %s\n",
                   ERR_reason_error_string(ERR_get_error()));
        goto done;
    }

    /*
     * passing NULL as a listener makes client to run like
     * http/1.0 client, request and response use bi-directional
     * QUIC-stream.
     * passing a listener makes client to run in active-FTP-like
     * mode. Client sends request over stream to server.
     * Then client waits for server to send response back
     * over yet another QUIC connection. Client accepts the connection
     * from server on `ssl_qcon_listener` QUIC object.
     */
    err = client_run(ssl_qconn, NULL);
    if (err == 0)
        err = client_run(ssl_qconn, ssl_qconn_listener);

    /*
     * Tell server to stop and finish.
     */
    client_send_quit(ssl_qconn);

    SSL_shutdown(ssl_qconn);
    SSL_shutdown(ssl_qconn_listener);
done:
    SSL_free(ssl_qconn_listener);
    BIO_free(bio_sock_data);
    SSL_CTX_free(ssl_ctx_data);
    SSL_free(ssl_qconn);
    BIO_free(bio_sock);
    SSL_CTX_free(ssl_ctx);
    BIO_ADDR_free(bio_addr);

    return err;
}

int main(int argc, char *argv[])
{
    int res = EXIT_FAILURE;
    SSL_CTX *ssl_ctx = NULL;
    BIO *bio_sock = NULL;
    struct in_addr ina;

    ina.s_addr = INADDR_ANY;

    if (argc != 4) {
        TEST_error("usage: %s <port> <server.crt> <server.key>\n", argv[0]);
        goto out;
    }

    /* Create SSL_CTX that supports QUIC. */
    ssl_ctx = create_ctx(argv[2], argv[3]);
    if (ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        TEST_error("[ Server ]: Failed to create context\n");
        goto out;
    }

    /* Parse port number from command line arguments. */
    port = strtoul(argv[1], NULL, 0);
    if (port == 0 || port > UINT16_MAX) {
        TEST_error("[ Server ] Failed to parse port number\n");
        goto out;
    }
    TEST_info("( Server ) Binding to port %lu\n", port);

    /* Create and bind a UDP socket. */
    bio_sock = create_socket((uint16_t)port, &ina);
    if (bio_sock == NULL) {
        TEST_error("[ Server ] Failed to create socket\n");
        ERR_print_errors_fp(stderr);
        goto out;
    }

    if (fork() == 0) {
        SSL_CTX_free(ssl_ctx);
        BIO_free(bio_sock);
        return (client_main(argc, argv));
    }

    /* QUIC server connection acceptance loop. */
    if (run_quic_server(ssl_ctx, bio_sock) != 0) {
        ERR_print_errors_fp(stderr);
        TEST_error("[ Server ] Failed to run quic server\n");
        goto out;
    }

    wait(NULL);

    if (error == 0)
    	res = EXIT_SUCCESS;

out:
    /* Free resources. */
    SSL_CTX_free(ssl_ctx);
    BIO_free(bio_sock);

    return res;
}

