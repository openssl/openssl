/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include "ossl-nghttp3.h"
#include <openssl/err.h>

#include <sys/socket.h>
#include <netinet/in.h>

static int done;

/**
 * @brief variable to record output basename path
 */
static char *dlpath = NULL;

/**
 * @brief struct to hold user data for async http3 writes
 */
struct stream_user_data {
    char *outpath;
    FILE *fp;
};

static void make_nv(nghttp3_nv *nv, const char *name, const char *value)
{
    nv->name = (uint8_t *)name;
    nv->value = (uint8_t *)value;
    nv->namelen = strlen(name);
    nv->valuelen = strlen(value);
    nv->flags = NGHTTP3_NV_FLAG_NONE;
}

static int on_recv_header(nghttp3_conn *h3conn, int64_t stream_id,
    int32_t token,
    nghttp3_rcbuf *name, nghttp3_rcbuf *value,
    uint8_t flags,
    void *conn_user_data,
    void *stream_user_data)
{
    nghttp3_vec vname, vvalue;

    /* Received a single HTTP header. */
    vname = nghttp3_rcbuf_get_buf(name);
    vvalue = nghttp3_rcbuf_get_buf(value);

    fwrite(vname.base, vname.len, 1, stderr);
    fprintf(stderr, ": ");
    fwrite(vvalue.base, vvalue.len, 1, stderr);
    fprintf(stderr, "\n");

    return 0;
}

static int on_end_headers(nghttp3_conn *h3conn, int64_t stream_id,
    int fin,
    void *conn_user_data, void *stream_user_data)
{
    fprintf(stderr, "\n");
    return 0;
}

static int on_recv_data(nghttp3_conn *h3conn, int64_t stream_id,
    const uint8_t *data, size_t datalen,
    void *conn_user_data, void *user_data)
{
    FILE *outfp;
    size_t wr;
    struct stream_user_data *sdata = OSSL_DEMO_H3_STREAM_get_user_data((const OSSL_DEMO_H3_STREAM *)user_data);

    if (dlpath == NULL) {
        outfp = stdout;
    } else {
        if (sdata->fp == NULL) {
            sdata->fp = fopen(sdata->outpath, "w+");
        }
        if (sdata->fp == NULL) {
            fprintf(stderr, "Failed to open %s for writing\n", sdata->outpath);
            return 1;
        }
        outfp = sdata->fp;
    }
    /* HTTP response body data - write it. */
    while (datalen > 0) {
        fprintf(stderr, "writing %lu bytes to %s\n", datalen, sdata->outpath);
        wr = fwrite(data, 1, datalen, outfp);
        if (ferror(outfp))
            return 1;

        data += wr;
        datalen -= wr;
    }
    return 0;
}

static int on_end_stream(nghttp3_conn *h3conn, int64_t stream_id,
    void *conn_user_data, void *user_data)
{
    /* HTTP transaction is done - set done flag so that we stop looping. */
    done = 1;
    return 0;
}

static int try_conn(OSSL_DEMO_H3_CONN *conn, const char *bare_hostname, const char *path)
{
    nghttp3_nv nva[16];
    size_t num_nv = 0;
    struct stream_user_data *sdata;
    size_t needed_size;
    int pathsize;

    /* Build HTTP headers. */
    make_nv(&nva[num_nv++], ":method", "GET");
    make_nv(&nva[num_nv++], ":scheme", "https");
    make_nv(&nva[num_nv++], ":authority", bare_hostname);
    make_nv(&nva[num_nv++], ":path", path);
    make_nv(&nva[num_nv++], "user-agent", "OpenSSL-Demo/nghttp3");

    needed_size = sizeof(struct stream_user_data);
    pathsize = snprintf(NULL, 0, "%s/%s", dlpath, path);
    if (pathsize < 0) {
        fprintf(stderr, "Unable to format path string\n");
        return 0;
    }
    needed_size += pathsize;

    sdata = malloc(needed_size + 1);
    if (sdata == NULL)
        return 0;
    sdata->outpath = (char *)(sdata + 1);
    sprintf(sdata->outpath, "%s/%s", dlpath, path);
    sdata->fp = NULL;
    fprintf(stderr, "Requesting %s\n", sdata->outpath);
    /* Submit request. */
    if (!OSSL_DEMO_H3_CONN_submit_request(conn, nva, num_nv, NULL, sdata)) {
        fprintf(stderr, "Cannot submit HTTP/3 request\n");
        return 0;
    }

    /* Wait for request to complete. */
    done = 0;
    while (!done) {
        if (!OSSL_DEMO_H3_CONN_handle_events(conn)) {
            fprintf(stderr, "Cannot handle events\n");
            return 0;
        }
    }
    if (sdata->fp != NULL) {
        fclose(sdata->fp);
        fprintf(stderr, "Closing local FILE pointer for %s\n", sdata->outpath);
    }
    free(sdata);
    return 1;
}

int main(int argc, char **argv)
{
    int ret = 1;
    int ok;
    SSL_CTX *ctx = NULL;
    OSSL_DEMO_H3_CONN *conn = NULL;
    nghttp3_callbacks callbacks = { 0 };
    const char *addr;
    char *hostname, *service;
    BIO_ADDRINFO *bai = NULL;
    const BIO_ADDRINFO *bai_walk;
    FILE *req_fp = NULL;
    size_t req_count = 0;
    char **req_array = NULL;
    size_t i;
    char buffer[PATH_MAX];

    /* Check arguments. */
    if (argc < 2) {
        fprintf(stderr, "usage: %s <host:port> [requestfile.txt <download_dir>]\n", argv[0]);
        goto err;
    }

    /*
     * If we have more than two arguments, then we are accepting both a request file
     * which is a newline separated list of paths to request from the server
     * as well as a download location relative to the current working directory
     */
    if (argc >= 4) {
        dlpath = argv[3];
        fprintf(stderr, "setting download path to %s, and reading %s\n", dlpath, argv[2]);

        /*
         * Read in our request file, one path per line
         */
        req_fp = fopen(argv[2], "r");
        if (req_fp == NULL) {
            fprintf(stderr, "Unable to open request file\n");
            goto err;
        }
        while (!feof(req_fp)) {
            req_count++;
            req_array = realloc(req_array, sizeof(char *) * req_count);
            req_array[req_count - 1] = NULL;
            if (fscanf(req_fp, "%s", buffer) != 1) {
                req_count--;
                if (feof(req_fp))
                    break;
                fprintf(stderr, "Failed to read request file at index %lu\n", req_count);
                fclose(req_fp);
                goto err;
            }
            req_array[req_count - 1] = calloc(1, strlen(buffer) + 1);
            memcpy(req_array[req_count - 1], buffer, strlen(buffer));
        }
        fclose(req_fp);
    }

    addr = argv[1];

    hostname = NULL;
    service = NULL;
    if (BIO_parse_hostserv(addr, &hostname, &service, 0) != 1) {
        fprintf(stderr, "usage: %s <host:port>\n", argv[0]);
        goto err;
    }

    if (hostname == NULL || service == NULL) {
        fprintf(stderr, "usage: %s <host:port>\n", argv[0]);
        goto err;
    }

    /*
     * Remember DNS may return more IP addresses (and it typically does these
     * dual-stack days).
     */
    ok = BIO_lookup_ex(hostname, service, BIO_LOOKUP_CLIENT,
        0, SOCK_DGRAM, IPPROTO_UDP, &bai);
    if (ok == 0) {
        fprintf(stderr, "host %s not found\n", hostname);
        goto err;
    }

    /* Setup SSL_CTX. */
    if ((ctx = SSL_CTX_new(OSSL_QUIC_client_method())) == NULL)
        goto err;

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    if (SSL_CTX_set_default_verify_paths(ctx) == 0)
        goto err;

    /* Setup callbacks. */
    callbacks.recv_header = on_recv_header;
    callbacks.end_headers = on_end_headers;
    callbacks.recv_data = on_recv_data;
    callbacks.end_stream = on_end_stream;

    /*
     * Unlike TCP there is no handshake on UDP protocol.
     * The BIO subsystem uses connect(2) to establish
     * connection. However connect(2) for UDP does not
     * perform handshake, so BIO just assumes the remote
     * service is reachable on the first address returned
     * by DNS. It's the SSL-handshake itself when QUIC stack
     * realizes the service is not reachable, so the application
     * needs to initiate a QUIC connection on the next address
     * returned by DNS.
     */
    for (bai_walk = bai; bai_walk != NULL;
        bai_walk = BIO_ADDRINFO_next(bai_walk)) {
        conn = OSSL_DEMO_H3_CONN_new_for_addr(ctx, bai_walk, hostname,
            &callbacks, NULL, NULL);
        if (conn != NULL) {
            for (i = 0; i < req_count; i++) {
                if (try_conn(conn, addr, req_array[i]) == 0) {
                    /*
                     * Failure, bail out.
                     */
                    OSSL_DEMO_H3_CONN_free(conn);
                    conn = NULL;
                    ret = 1;
                    goto err;
                }
            }
            fprintf(stderr, "all requests complete\n");
            ret = 0;
        }
    }
err:
    for (i = 0; i < req_count; i++)
        free(req_array[i]);
    free(req_array);

    if (ret != 0)
        ERR_print_errors_fp(stderr);

    OSSL_DEMO_H3_CONN_free(conn);
    SSL_CTX_free(ctx);
    BIO_ADDRINFO_free(bai);
    return ret;
}
