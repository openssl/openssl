/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef OSSL_NGHTTP3_H
# define OSSL_NGHTTP3_H

# include <openssl/bio.h>
# include <openssl/ssl.h>
# include <nghttp3/nghttp3.h>

/*
 * ossl-nghttp3: Demo binding of nghttp3 to OpenSSL QUIC
 * =====================================================
 *
 * This is a simple library which provides an example binding of the nghttp3
 * HTTP/3 library to OpenSSL's QUIC API.
 */

/* Represents an HTTP/3 connection to a server. */
typedef struct h3_conn_st H3_CONN;

/* Represents an HTTP/3 request, control or QPACK stream. */
typedef struct h3_stream_st H3_STREAM;

/*
 * Creates a HTTP/3 connection using the given QUIC client connection BIO. The
 * BIO must be able to provide an SSL object pointer using BIO_get_ssl. Takes
 * ownership of the reference. If the QUIC connection SSL object has not already
 * been connected, HTTP/3 ALPN is set automatically. If it has already been
 * connected, HTTP/3 ALPN ("h3") must have been configured and no streams must
 * have been created yet.
 *
 * If settings is NULL, use default settings only. Settings unsupported by
 * this QUIC binding are ignored.
 *
 * user_data is an application-provided opaque value which can be retrieved
 * using H3_CONN_get_user_data. Note that the user data value passed to the
 * callback functions specified in callbacks is a pointer to the H3_CONN, not
 * user_data.
 *
 * Returns NULL on failure.
 */
H3_CONN *H3_CONN_new_for_conn(BIO *qconn_bio,
                              const nghttp3_callbacks *callbacks,
                              const nghttp3_settings *settings,
                              void *user_data);

/*
 * Works identically to H3_CONN_new_for_conn except that it manages the creation
 * of a QUIC connection SSL object automatically using an address string. addr
 * should be a string such as "www.example.com:443". The created underlying QUIC
 * connection SSL object is owned by the H3_CONN and can be subsequently
 * retrieved using H3_CONN_get0_connection.
 *
 * Returns NULL on failure. ctx must be a SSL_CTX using a QUIC client
 * SSL_METHOD.
 */
H3_CONN *H3_CONN_new_for_addr(SSL_CTX *ctx, const char *addr,
                              const nghttp3_callbacks *callbacks,
                              const nghttp3_settings *settings,
                              void *user_data);

/* Equivalent to SSL_connect(H3_CONN_get0_connection(conn)). */
int H3_CONN_connect(H3_CONN *conn);

/*
 * Free the H3_CONN and any underlying QUIC connection SSL object and associated
 * streams.
 */
void H3_CONN_free(H3_CONN *conn);

/* Returns the user data value which was specified in H3_CONN_new_for_conn. */
void *H3_CONN_get_user_data(const H3_CONN *conn);

/* Returns the underlying QUIC connection SSL object. */
SSL *H3_CONN_get0_connection(const H3_CONN *conn);

/*
 * Handle any pending events on a given HTTP/3 connection. Returns 0 on error.
 */
int H3_CONN_handle_events(H3_CONN *conn);

/*
 * Submits a new HTTP/3 request on the given connection. Returns 0 on error.
 *
 * This works analogously to nghttp3_conn_submit_request(). The stream user data
 * pointer passed to the callbacks is a H3_STREAM object pointer; to retrieve
 * the stream user data pointer passed to this function, use
 * H3_STREAM_get_user_data.
 */
int H3_CONN_submit_request(H3_CONN *conn,
                           const nghttp3_nv *hdr, size_t hdrlen,
                           const nghttp3_data_reader *dr,
                           void *stream_user_data);

/* Returns the user data value which was specified in H3_CONN_submit_request. */
void *H3_STREAM_get_user_data(const H3_STREAM *stream);

#endif
