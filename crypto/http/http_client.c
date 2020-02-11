/*
 * Copyright 2001-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Siemens AG 2018-2020
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <stdio.h>
#include <stdlib.h>
#include "crypto/ctype.h"
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/httperr.h>
#include <openssl/cmperr.h>
#include <openssl/buffer.h>
#include <openssl/http.h>
#include "internal/sockets.h"
#include "internal/cryptlib.h"

#include "http_local.h"

#define HTTP_PREFIX "HTTP/"
#define HTTP_VERSION_PATT "1." /* allow 1.x */
#define HTTP_VERSION_STR_LEN 3
#define HTTP_LINE1_MINLEN ((int)strlen(HTTP_PREFIX HTTP_VERSION_PATT "x 200\n"))
#define HTTP_VERSION_MAX_REDIRECTIONS 50

#define HTTP_STATUS_CODE_OK                200
#define HTTP_STATUS_CODE_MOVED_PERMANENTLY 301
#define HTTP_STATUS_CODE_FOUND             302


/* Stateful HTTP request code, supporting blocking and non-blocking I/O */

/* Opaque HTTP request status structure */

struct ossl_http_req_ctx_st {
    int state;                  /* Current I/O state */
    unsigned char *iobuf;       /* Line buffer */
    int iobuflen;               /* Line buffer length */
    BIO *wbio;                  /* BIO to send request to */
    BIO *rbio;                  /* BIO to read response from */
    BIO *mem;                   /* Memory BIO response is built into */
    int method_GET;             /* HTTP method "GET" or "POST" */
    const char *expected_ct;    /* expected Content-Type, or NULL */
    int expect_asn1;            /* response must be ASN.1-encoded */
    unsigned long resp_len;     /* length of response */
    unsigned long max_resp_len; /* Maximum length of response */
    time_t max_time;            /* Maximum end time of the transfer, or 0 */
    char *redirection_url;      /* Location given with HTTP status 301/302 */
};

#define HTTP_DEFAULT_MAX_LINE_LENGTH (4 * 1024)
#define HTTP_DEFAULT_MAX_RESP_LEN (100 * 1024)

/* HTTP states */

#define OHS_NOREAD          0x1000 /* If set no reading should be performed */
#define OHS_ERROR           (0 | OHS_NOREAD) /* Error condition */
#define OHS_FIRSTLINE       1 /* First line being read */
#define OHS_REDIRECT        0xa /* Looking for redirection location */
#define OHS_HEADERS         2 /* MIME headers being read */
#define OHS_ASN1_HEADER     3 /* HTTP initial header (tag+length) being read */
#define OHS_CONTENT         4 /* HTTP content octets being read */
#define OHS_WRITE_INIT     (5 | OHS_NOREAD) /* 1st call: ready to start I/O */
#define OHS_WRITE          (6 | OHS_NOREAD) /* Request being sent */
#define OHS_FLUSH          (7 | OHS_NOREAD) /* Request being flushed */
#define OHS_DONE           (8 | OHS_NOREAD) /* Completed */
#define OHS_HTTP_HEADER    (9 | OHS_NOREAD) /* Headers set, w/o final \r\n */

OSSL_HTTP_REQ_CTX *OSSL_HTTP_REQ_CTX_new(BIO *wbio, BIO *rbio,
                                         int method_GET, int maxline,
                                         unsigned long max_resp_len,
                                         int timeout,
                                         const char *expected_content_type,
                                         int expect_asn1)
{
    OSSL_HTTP_REQ_CTX *rctx;

    if (wbio == NULL || rbio == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if ((rctx = OPENSSL_zalloc(sizeof(*rctx))) == NULL)
        return NULL;
    rctx->state = OHS_ERROR;
    rctx->iobuflen = maxline > 0 ? maxline : HTTP_DEFAULT_MAX_LINE_LENGTH;
    rctx->iobuf = OPENSSL_malloc(rctx->iobuflen);
    rctx->wbio = wbio;
    rctx->rbio = rbio;
    rctx->mem = BIO_new(BIO_s_mem());
    if (rctx->iobuf == NULL || rctx->mem == NULL) {
        OSSL_HTTP_REQ_CTX_free(rctx);
        return NULL;
    }
    rctx->method_GET = method_GET;
    rctx->expected_ct = expected_content_type;
    rctx->expect_asn1 = expect_asn1;
    rctx->resp_len = 0;
    OSSL_HTTP_REQ_CTX_set_max_response_length(rctx, max_resp_len);
    rctx->max_time = timeout > 0 ? time(NULL) + timeout : 0;
    return rctx;
}

void OSSL_HTTP_REQ_CTX_free(OSSL_HTTP_REQ_CTX *rctx)
{
    if (rctx == NULL)
        return;
    BIO_free(rctx->mem); /* this may indirectly call ERR_clear_error() */
    OPENSSL_free(rctx->iobuf);
    OPENSSL_free(rctx);
}

BIO *OSSL_HTTP_REQ_CTX_get0_mem_bio(OSSL_HTTP_REQ_CTX *rctx)
{
    if (rctx == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    return rctx->mem;
}

void OSSL_HTTP_REQ_CTX_set_max_response_length(OSSL_HTTP_REQ_CTX *rctx,
                                               unsigned long len)
{
    if (rctx == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return;
    }
    rctx->max_resp_len = len != 0 ? len : HTTP_DEFAULT_MAX_RESP_LEN;
}

/*
 * Create HTTP header using given op and path (or "/" in case path is NULL).
 * Server name (and port) must be given if and only if plain HTTP proxy is used.
 */
int OSSL_HTTP_REQ_CTX_header(OSSL_HTTP_REQ_CTX *rctx, const char *server,
                             const char *port, const char *path)
{
    if (rctx == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (BIO_printf(rctx->mem, "%s ", rctx->method_GET ? "GET" : "POST") <= 0)
        return 0;

    if (server != NULL) { /* HTTP (but not HTTPS) proxy is used */
        /*
         * Section 5.1.2 of RFC 1945 states that the absoluteURI form is only
         * allowed when using a proxy
         */
        if (BIO_printf(rctx->mem, "http://%s", server) <= 0)
            return 0;
        if (port != NULL && BIO_printf(rctx->mem, ":%s", port) <= 0)
            return 0;
    }

    /* Make sure path includes a forward slash */
    if (path == NULL)
        path = "/";
    if (path[0] != '/' && BIO_printf(rctx->mem, "/") <= 0)
        return 0;

    if (BIO_printf(rctx->mem, "%s "HTTP_PREFIX"1.0\r\n", path) <= 0)
        return 0;
    rctx->state = OHS_HTTP_HEADER;
    return 1;
}

int OSSL_HTTP_REQ_CTX_add1_header(OSSL_HTTP_REQ_CTX *rctx,
                                  const char *name, const char *value)
{
    if (rctx == NULL || name == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (BIO_puts(rctx->mem, name) <= 0)
        return 0;
    if (value != NULL) {
        if (BIO_write(rctx->mem, ": ", 2) != 2)
            return 0;
        if (BIO_puts(rctx->mem, value) <= 0)
            return 0;
    }
    if (BIO_write(rctx->mem, "\r\n", 2) != 2)
        return 0;
    rctx->state = OHS_HTTP_HEADER;
    return 1;
}

static int OSSL_HTTP_REQ_CTX_content(OSSL_HTTP_REQ_CTX *rctx,
                                     const char *content_type, BIO *req_mem)
{
    const unsigned char *req;
    long req_len;

    if (rctx == NULL || req_mem == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (content_type != NULL
            && BIO_printf(rctx->mem, "Content-Type: %s\r\n", content_type) <= 0)
        return 0;

    if ((req_len = BIO_get_mem_data(req_mem, &req)) <= 0)
        return 0;
    rctx->state = OHS_WRITE_INIT;

    return BIO_printf(rctx->mem, "Content-Length: %ld\r\n\r\n", req_len) > 0
        && BIO_write(rctx->mem, req, req_len) == (int)req_len;
}

BIO *HTTP_asn1_item2bio(const ASN1_ITEM *it, ASN1_VALUE *val)
{
    BIO *res;

    if (it == NULL || val == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if ((res = BIO_new(BIO_s_mem())) == NULL)
        return NULL;
    if (ASN1_item_i2d_bio(it, res, val) <= 0) {
        BIO_free(res);
        res = NULL;
    }
    return res;
}

int OSSL_HTTP_REQ_CTX_i2d(OSSL_HTTP_REQ_CTX *rctx, const char *content_type,
                          const ASN1_ITEM *it, ASN1_VALUE *req)
{
    BIO *mem;
    int res;

    if (rctx == NULL || it == NULL || req == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    res = (mem = HTTP_asn1_item2bio(it, req)) != NULL
        && OSSL_HTTP_REQ_CTX_content(rctx, content_type, mem);
    BIO_free(mem);
    return res;
}

static int OSSL_HTTP_REQ_CTX_add1_headers(OSSL_HTTP_REQ_CTX *rctx,
                                          const STACK_OF(CONF_VALUE) *headers,
                                          const char *host)
{
    int i;
    int add_host = 1;
    CONF_VALUE *hdr;

    for (i = 0; i < sk_CONF_VALUE_num(headers); i++) {
        hdr = sk_CONF_VALUE_value(headers, i);
        if (add_host && strcasecmp("host", hdr->name) == 0)
            add_host = 0;
        if (!OSSL_HTTP_REQ_CTX_add1_header(rctx, hdr->name, hdr->value))
            return 0;
    }

    if (add_host && !OSSL_HTTP_REQ_CTX_add1_header(rctx, "Host", host))
        return 0;
    return 1;
}

/*-
 * Create OSSL_HTTP_REQ_CTX structure using the values provided.
 * If !use_http_proxy then the 'server' and 'port' parameters are ignored.
 * If req_mem == NULL then use GET and ignore content_type, else POST.
 */
OSSL_HTTP_REQ_CTX *HTTP_REQ_CTX_new(BIO *wbio, BIO *rbio, int use_http_proxy,
                                    const char *server, const char *port,
                                    const char *path,
                                    const STACK_OF(CONF_VALUE) *headers,
                                    const char *content_type, BIO *req_mem,
                                    int maxline, unsigned long max_resp_len,
                                    int timeout,
                                    const char *expected_content_type,
                                    int expect_asn1)
{
    OSSL_HTTP_REQ_CTX *rctx;

    if (use_http_proxy && (server == NULL || port == NULL)) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    /* remaining parameters are checked indirectly by the functions called */

    if ((rctx = OSSL_HTTP_REQ_CTX_new(wbio, rbio, req_mem == NULL, maxline,
                                      max_resp_len, timeout,
                                      expected_content_type, expect_asn1))
        == NULL)
        return NULL;

    if (OSSL_HTTP_REQ_CTX_header(rctx, use_http_proxy ? server : NULL,
                                 port, path)
        && OSSL_HTTP_REQ_CTX_add1_headers(rctx, headers, server)
        && (req_mem == NULL
            || OSSL_HTTP_REQ_CTX_content(rctx, content_type, req_mem)))
        return rctx;

    OSSL_HTTP_REQ_CTX_free(rctx);
    return NULL;
}

/*
 * Parse first HTTP response line. This should be like this: "HTTP/1.0 200 OK".
 * We need to obtain the numeric code and (optional) informational message.
 */

static int parse_http_line1(char *line)
{
    int retcode;
    char *code, *reason, *end;

    /* Skip to first whitespace (past protocol info) */
    for (code = line; *code != '\0' && !ossl_isspace(*code); code++)
        continue;
    if (*code == '\0') {
        HTTPerr(0, HTTP_R_SERVER_RESPONSE_PARSE_ERROR);
        return 0;
    }

    /* Skip past whitespace to start of response code */
    while (*code != '\0' && ossl_isspace(*code))
        code++;

    if (*code == '\0') {
        HTTPerr(0, HTTP_R_SERVER_RESPONSE_PARSE_ERROR);
        return 0;
    }

    /* Find end of response code: first whitespace after start of code */
    for (reason = code; *reason != '\0' && !ossl_isspace(*reason); reason++)
        continue;

    if (*reason == '\0') {
        HTTPerr(0, HTTP_R_SERVER_RESPONSE_PARSE_ERROR);
        return 0;
    }

    /* Set end of response code and start of message */
    *reason++ = '\0';

    /* Attempt to parse numeric code */
    retcode = strtoul(code, &end, 10);

    if (*end != '\0')
        return 0;

    /* Skip over any leading whitespace in message */
    while (*reason != '\0' && ossl_isspace(*reason))
        reason++;

    if (*reason != '\0') {
        /*
         * Finally zap any trailing whitespace in message (include CRLF)
         */

        /* chop any trailing whitespace from reason */
        /* We know reason has a non-whitespace character so this is OK */
        for (end = reason + strlen(reason) - 1; ossl_isspace(*end); end--)
            *end = '\0';
    }

    switch (retcode) {
    case HTTP_STATUS_CODE_OK:
    case HTTP_STATUS_CODE_MOVED_PERMANENTLY:
    case HTTP_STATUS_CODE_FOUND:
        return retcode;
    default:
        if (retcode < 400)
            HTTPerr(0, HTTP_R_STATUS_CODE_UNSUPPORTED);
        else
            HTTPerr(0, HTTP_R_SERVER_SENT_ERROR);
        if (*reason == '\0')
            ERR_add_error_data(2, "Code=", code);
        else
            ERR_add_error_data(4, "Code=", code, ",Reason=", reason);
        return 0;
    }
}

static int check_set_resp_len(OSSL_HTTP_REQ_CTX *rctx, unsigned long len)
{
    const char *tag = NULL;
    unsigned long val = 0;

    if (len > rctx->max_resp_len) {
        HTTPerr(0, HTTP_R_MAX_RESP_LEN_EXCEEDED);
        tag = ",max=";
        val = rctx->max_resp_len;
    }
    if (rctx->resp_len != 0 && rctx->resp_len != len) {
        HTTPerr(0, HTTP_R_INCONSISTENT_CONTENT_LENGTH);
        tag = ",before=";
        val = rctx->resp_len;
    }
    if (tag != NULL) {
        char len_str[32];
        char str[32];

        BIO_snprintf(len_str, sizeof(len_str), "%lu", len);
        BIO_snprintf(str, sizeof(str), "%lu", val);
        ERR_add_error_data(4, "length=", len_str, tag, str);
        return 0;
    }
    rctx->resp_len = len;
    return 1;
}

/*
 * Try exchanging request and response via HTTP on (non-)blocking BIO in rctx.
 * Returns 1 on success, 0 on error or redirection, -1 on BIO_should_retry.
 */
int OSSL_HTTP_REQ_CTX_nbio(OSSL_HTTP_REQ_CTX *rctx)
{
    int i;
    long n, n_to_send = 0;
    unsigned long resp_len;
    const unsigned char *p;
    char *key, *value, *line_end = NULL;

    if (rctx == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    rctx->redirection_url = NULL;
 next_io:
    if ((rctx->state & OHS_NOREAD) == 0) {
        n = BIO_read(rctx->rbio, rctx->iobuf, rctx->iobuflen);
        if (n <= 0) {
            if (BIO_should_retry(rctx->rbio))
                return -1;
            return 0;
        }

        /* Write data to memory BIO */
        if (BIO_write(rctx->mem, rctx->iobuf, n) != n)
            return 0;
    }

    switch (rctx->state) {
    case OHS_HTTP_HEADER:
        /* Last operation was adding headers: need a final \r\n */
        if (BIO_write(rctx->mem, "\r\n", 2) != 2) {
            rctx->state = OHS_ERROR;
            return 0;
        }
        rctx->state = OHS_WRITE_INIT;

        /* fall thru */
    case OHS_WRITE_INIT:
        n_to_send = BIO_get_mem_data(rctx->mem, NULL);
        rctx->state = OHS_WRITE;

        /* fall thru */
    case OHS_WRITE:
        n = BIO_get_mem_data(rctx->mem, &p);

        i = BIO_write(rctx->wbio, p + (n - n_to_send), n_to_send);

        if (i <= 0) {
            if (BIO_should_retry(rctx->wbio))
                return -1;
            rctx->state = OHS_ERROR;
            return 0;
        }

        n_to_send -= i;

        if (n_to_send > 0)
            goto next_io;

        rctx->state = OHS_FLUSH;

        (void)BIO_reset(rctx->mem);

        /* fall thru */
    case OHS_FLUSH:

        i = BIO_flush(rctx->wbio);

        if (i > 0) {
            rctx->state = OHS_FIRSTLINE;
            goto next_io;
        }

        if (BIO_should_retry(rctx->wbio))
            return -1;

        rctx->state = OHS_ERROR;
        return 0;

    case OHS_ERROR:
        return 0;

    case OHS_FIRSTLINE:
    case OHS_HEADERS:
    case OHS_REDIRECT:

        /* Attempt to read a line in */
 next_line:
        /*
         * Due to strange memory BIO behavior with BIO_gets we have to check
         * there's a complete line in there before calling BIO_gets or we'll
         * just get a partial read.
         */
        n = BIO_get_mem_data(rctx->mem, &p);
        if (n <= 0 || memchr(p, '\n', n) == 0) {
            if (n >= rctx->iobuflen) {
                rctx->state = OHS_ERROR;
                return 0;
            }
            goto next_io;
        }
        n = BIO_gets(rctx->mem, (char *)rctx->iobuf, rctx->iobuflen);

        if (n <= 0) {
            if (BIO_should_retry(rctx->mem))
                goto next_io;
            rctx->state = OHS_ERROR;
            return 0;
        }

        /* Don't allow excessive lines */
        if (n == rctx->iobuflen) {
            HTTPerr(0, HTTP_R_RESPONSE_LINE_TOO_LONG);
            rctx->state = OHS_ERROR;
            return 0;
        }

        /* First line */
        if (rctx->state == OHS_FIRSTLINE) {
            switch (parse_http_line1((char *)rctx->iobuf)) {
            case HTTP_STATUS_CODE_OK:
                rctx->state = OHS_HEADERS;
                goto next_line;
            case HTTP_STATUS_CODE_MOVED_PERMANENTLY:
            case HTTP_STATUS_CODE_FOUND: /* i.e., moved temporarily */
                if (rctx->method_GET) {
                    rctx->state = OHS_REDIRECT;
                    goto next_line;
                }
                HTTPerr(0, HTTP_R_REDIRECTION_NOT_ENABLED);
                /* redirection is not supported/recommended for POST */
                /* fall through */
            default:
                rctx->state = OHS_ERROR;
                return 0;
            }
        }
        key = (char *)rctx->iobuf;
        value = strchr(key, ':');
        if (value != NULL) {
            *(value++) = '\0';
            while (ossl_isspace(*value))
                value++;
            line_end = strchr(value, '\r');
            if (line_end == NULL)
                line_end = strchr(value, '\n');
            if (line_end != NULL)
                *line_end = '\0';
        }
        if (value != NULL && line_end != NULL) {
            if (rctx->state == OHS_REDIRECT && strcmp(key, "Location") == 0) {
                rctx->redirection_url = value;
                return 0;
            }
            if (rctx->expected_ct != NULL && strcmp(key, "Content-Type") == 0) {
                if (strcmp(rctx->expected_ct, value) != 0) {
                    HTTPerr(0, HTTP_R_UNEXPECTED_CONTENT_TYPE);
                    ERR_add_error_data(4, "expected=", rctx->expected_ct,
                                       ",actual=", value);
                    return 0;
                }
                rctx->expected_ct = NULL; /* content-type has been found */
            }
            if (strcmp(key, "Content-Length") == 0) {
                resp_len = strtoul(value, &line_end, 10);
                if (line_end == value || *line_end != '\0') {
                    HTTPerr(0, HTTP_R_ERROR_PARSING_CONTENT_LENGTH);
                    ERR_add_error_data(2, "input=", value);
                    return 0;
                }
                if (!check_set_resp_len(rctx, resp_len))
                    return 0;
            }
        }

        /* Look for blank line: end of headers */
        for (p = rctx->iobuf; *p != '\0' ; p++) {
            if (*p != '\r' && *p != '\n')
                break;
        }
        if (*p != '\0') /* not end of headers */
            goto next_line;

        if (rctx->expected_ct != NULL) {
            HTTPerr(0, HTTP_R_MISSING_CONTENT_TYPE);
            ERR_add_error_data(2, "expected=", rctx->expected_ct);
            return 0;
        }
        if (rctx->state == OHS_REDIRECT) {
            /* http status code indicated redirect but there was no Location */
            HTTPerr(0, HTTP_R_MISSING_REDIRECT_LOCATION);
            return 0;
        }

        if (!rctx->expect_asn1) {
            rctx->state = OHS_CONTENT;
            goto content;
        }

        rctx->state = OHS_ASN1_HEADER;

        /* Fall thru */
    case OHS_ASN1_HEADER:
        /*
         * Now reading ASN1 header: can read at least 2 bytes which is enough
         * for ASN1 SEQUENCE header and either length field or at least the
         * length of the length field.
         */
        n = BIO_get_mem_data(rctx->mem, &p);
        if (n < 2)
            goto next_io;

        /* Check it is an ASN1 SEQUENCE */
        if (*p++ != (V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED)) {
            HTTPerr(0, HTTP_R_MISSING_ASN1_ENCODING);
            return 0;
        }

        /* Check out length field */
        if ((*p & 0x80) != 0) {
            /*
             * If MSB set on initial length octet we can now always read 6
             * octets: make sure we have them.
             */
            if (n < 6)
                goto next_io;
            n = *p & 0x7F;
            /* Not NDEF or excessive length */
            if (n == 0 || (n > 4)) {
                HTTPerr(0, HTTP_R_ERROR_PARSING_ASN1_LENGTH);
                return 0;
            }
            p++;
            resp_len = 0;
            for (i = 0; i < n; i++) {
                resp_len <<= 8;
                resp_len |= *p++;
            }
            resp_len += n + 2;
        } else {
            resp_len = *p + 2;
        }
        if (!check_set_resp_len(rctx, resp_len))
            return 0;

 content:
        rctx->state = OHS_CONTENT;

        /* Fall thru */
    case OHS_CONTENT:
    default:
        n = BIO_get_mem_data(rctx->mem, NULL);
        if (n < (long)rctx->resp_len /* may be 0 if no Content-Type or ASN.1 */)
            goto next_io;

        rctx->state = OHS_DONE;
        return 1;
    }
}

#ifndef OPENSSL_NO_SOCK

/* set up a new connection BIO, to HTTP server or to HTTP(S) proxy if given */
static BIO *HTTP_new_bio(const char *server, const char *server_port,
                         const char *proxy, const char *proxy_port)
{
    const char *host = server;
    const char *port = server_port;
    BIO *cbio;

    if (server == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (proxy != NULL) {
        host = proxy;
        port = proxy_port;
    }
    cbio = BIO_new_connect(host);
    if (cbio == NULL)
        goto end;
    if (port != NULL)
        (void)BIO_set_conn_port(cbio, port);

 end:
    return cbio;
}

static ASN1_VALUE *BIO_mem_d2i(BIO *mem, const ASN1_ITEM *it)
{
    const unsigned char *p;
    long len = BIO_get_mem_data(mem, &p);
    ASN1_VALUE *resp = ASN1_item_d2i(NULL, &p, len, it);

    if (resp == NULL)
        HTTPerr(0, HTTP_R_SERVER_RESPONSE_PARSE_ERROR);
    return resp;
}

static BIO *OSSL_HTTP_REQ_CTX_transfer(OSSL_HTTP_REQ_CTX *rctx)
{
    int sending = 1;
    int rv;

    if (rctx == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    for (;;) {
        rv = OSSL_HTTP_REQ_CTX_nbio(rctx);
        if (rv != -1)
            break;
        /* BIO_should_retry was true */
        sending = 0;
        /* will not actually wait if rctx->max_time == 0 */
        if (BIO_wait(rctx->rbio, rctx->max_time) <= 0)
            return NULL;
    }

    if (rv == 0) {
        if (rctx->redirection_url == NULL) { /* an error occurred */
            if (sending && (rctx->state & OHS_NOREAD) != 0)
                HTTPerr(0, HTTP_R_ERROR_SENDING);
            else
                HTTPerr(0, HTTP_R_ERROR_RECEIVING);
        }
        return NULL;
    }
    if (!BIO_up_ref(rctx->mem))
        return NULL;
    return rctx->mem;
}

/* Exchange ASN.1-encoded request and response via HTTP on (non-)blocking BIO */
ASN1_VALUE *OSSL_HTTP_REQ_CTX_sendreq_d2i(OSSL_HTTP_REQ_CTX *rctx,
                                          const ASN1_ITEM *it)
{
    if (rctx == NULL || it == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    return BIO_mem_d2i(OSSL_HTTP_REQ_CTX_transfer(rctx), it);
}

static int update_timeout(int timeout, time_t start_time)
{
    long elapsed_time;

    if (timeout == 0)
        return 0;
    elapsed_time = (long)(time(NULL) - start_time); /* this might overflow */
    return timeout <= elapsed_time ? -1 : timeout - elapsed_time;
}

/*-
 * Exchange HTTP request and response with the given server.
 * If req_mem == NULL then use GET and ignore content_type, else POST.
 * The redirection_url output (freed by caller) parameter is used only for GET.
 *
 * Typically the bio and rbio parameters are NULL and a network BIO is created
 * internally for connecting to the given server and port, optionally via a
 * proxy and its port, and is then used for exchanging the request and response.
 * If bio is given and rbio is NULL then this BIO is used instead.
 * If both bio and rbio are given (which may be memory BIOs for instance)
 * then no explicit connection is attempted,
 * bio is used for writing the request, and rbio for reading the response.
 *
 * bio_update_fn is an optional BIO connect/disconnect callback function,
 * which has the prototype
 *   BIO *(*OSSL_HTTP_bio_cb_t) (BIO *bio, void *arg, int conn, int detail);
 * The callback may modify the HTTP BIO provided in the bio argument,
 * whereby it may make use of any custom defined argument 'arg'.
 * During connection establishment, just after BIO_connect_retry(),
 * the callback function is invoked with the 'conn' argument being 1
 * 'detail' indicating whether a HTTPS (i.e., TLS) connection is requested.
 * On disconnect 'conn' is 0 and 'detail' indicates that no error occurred.
 * For instance, on connect the funct may prepend a TLS BIO to implement HTTPS;
 * after disconnect it may do some error diagnostics and/or specific cleanup.
 * The function should return NULL to indicate failure.
 * After disconnect the modified BIO will be deallocated using BIO_free_all().
 */
BIO *OSSL_HTTP_transfer(const char *server, const char *port, const char *path,
                        int use_ssl, const char *proxy, const char *proxy_port,
                        BIO *bio, BIO *rbio,
                        OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                        const STACK_OF(CONF_VALUE) *headers,
                        const char *content_type, BIO *req_mem,
                        int maxline, unsigned long max_resp_len, int timeout,
                        const char *expected_ct, int expect_asn1,
                        char **redirection_url)
{
    time_t start_time = timeout > 0 ? time(NULL) : 0;
    BIO *cbio; /* = bio if present, used as connection BIO if rbio is NULL */
    OSSL_HTTP_REQ_CTX *rctx;
    BIO *resp = NULL;

    if (redirection_url != NULL)
        *redirection_url = NULL; /* do this beforehand to prevent dbl free */

    if (use_ssl && bio_update_fn == NULL) {
        HTTPerr(0, HTTP_R_TLS_NOT_ENABLED);
        return NULL;
    }
    if (rbio != NULL && (bio == NULL || bio_update_fn != NULL)) {
        HTTPerr(0, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }
    /* remaining parameters are checked indirectly by the functions called */

    if (bio != NULL)
        cbio = bio;
    else if ((cbio = HTTP_new_bio(server, port, proxy, proxy_port)) == NULL)
        return NULL;

    (void)ERR_set_mark(); /* prepare removing any spurious libssl errors */
    if (rbio == NULL && BIO_connect_retry(cbio, timeout) <= 0)
        goto end;
    /* now timeout is guaranteed to be >= 0 */

    /* callback can be used to wrap or prepend TLS session */
    if (bio_update_fn != NULL) {
        BIO *orig_bio = cbio;
        cbio = (*bio_update_fn)(cbio, arg, 1 /* connect */, use_ssl);
        if (cbio == NULL) {
            cbio = orig_bio;
            goto end;
        }
    }

    rctx = HTTP_REQ_CTX_new(cbio, rbio != NULL ? rbio : cbio,
                            !use_ssl && proxy != NULL, server, port, path,
                            headers, content_type, req_mem, maxline,
                            max_resp_len, update_timeout(timeout, start_time),
                            expected_ct, expect_asn1);
    if (rctx == NULL)
        goto end;

    resp = OSSL_HTTP_REQ_CTX_transfer(rctx);
    if (resp == NULL) {
        if (rctx->redirection_url != NULL) {
            if (redirection_url == NULL)
                HTTPerr(0, HTTP_R_REDIRECTION_NOT_ENABLED);
            else
                /* may be NULL if out of memory: */
                *redirection_url = OPENSSL_strdup(rctx->redirection_url);
        } else {
            char buf[200];
            unsigned long err = ERR_peek_error();
            int lib = ERR_GET_LIB(err);
            int reason = ERR_GET_REASON(err);

            if (lib == ERR_LIB_SSL || lib == ERR_LIB_HTTP
                    || (lib == ERR_LIB_BIO && reason == BIO_R_CONNECT_TIMEOUT)
                    || (lib == ERR_LIB_BIO && reason == BIO_R_CONNECT_ERROR)
# ifndef OPENSSL_NO_CMP
                    || (lib == ERR_LIB_CMP
                        && reason == CMP_R_POTENTIALLY_INVALID_CERTIFICATE)
# endif
                ) {
                BIO_snprintf(buf, 200, "server=%s:%s", server, port);
                ERR_add_error_data(1, buf);
                if (err == 0) {
                    BIO_snprintf(buf, 200, "server has disconnected%s",
                                 use_ssl ? " violating the protocol" :
                                 ", likely because it requires the use of TLS");
                    ERR_add_error_data(1, buf);
                }
            }
        }
    }
    OSSL_HTTP_REQ_CTX_free(rctx);

    /* callback can be used to clean up TLS session */
    if (bio_update_fn != NULL
            && (*bio_update_fn)(cbio, arg, 0, resp != NULL) == NULL) {
        BIO_free(resp);
        resp = NULL;
    }

 end:
    /*
     * Use BIO_free_all() because bio_update_fn may prepend or append to cbio.
     * This also frees any (e.g., SSL/TLS) BIOs linked with bio and,
     * like BIO_reset(bio), calls SSL_shutdown() to notify/alert the peer.
     */
    if (bio == NULL) /* cbio was not provided by caller */
        BIO_free_all(cbio);

    if (resp != NULL)
        /* remove any spurious error queue entries by ssl_add_cert_chain() */
        (void)ERR_pop_to_mark();
    else
        (void)ERR_clear_last_mark();

    return resp;
}

static int redirection_ok(int n_redir, const char *old_url, const char *new_url)
{
    static const char https[] = "https:";
    int https_len = 6; /* strlen(https) */

    if (n_redir >= HTTP_VERSION_MAX_REDIRECTIONS) {
        HTTPerr(0, HTTP_R_TOO_MANY_REDIRECTIONS);
        return 0;
    }
    if (*new_url == '/') /* redirection to same server => same protocol */
        return 1;
    if (strncmp(old_url, https, https_len) == 0 &&
        strncmp(new_url, https, https_len) != 0) {
        HTTPerr(0, HTTP_R_REDIRECTION_FROM_HTTPS_TO_HTTP);
        return 0;
    }
    return 1;
}

/* Get data via HTTP from server at given URL, potentially with redirection */
BIO *OSSL_HTTP_get(const char *url, const char *proxy, const char *proxy_port,
                   BIO *bio, BIO *rbio,
                   OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                   const STACK_OF(CONF_VALUE) *headers,
                   int maxline, unsigned long max_resp_len, int timeout,
                   const char *expected_content_type, int expect_asn1)
{
    time_t start_time = timeout > 0 ? time(NULL) : 0;
    char *current_url, *redirection_url;
    int n_redirs = 0;
    char *host;
    char *port;
    char *path;
    int use_ssl;
    BIO *resp = NULL;

    if (url == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if ((current_url = OPENSSL_strdup(url)) == NULL)
        return NULL;

    for (;;) {
        if (!OSSL_HTTP_parse_url(current_url, &host, &port, &path, &use_ssl))
            break;

     new_rpath:
        resp = OSSL_HTTP_transfer(host, port, path, use_ssl, proxy, proxy_port,
                                  bio, rbio,
                                  bio_update_fn, arg, headers, NULL, NULL,
                                  maxline, max_resp_len,
                                  update_timeout(timeout, start_time),
                                  expected_content_type, expect_asn1,
                                  &redirection_url);
        OPENSSL_free(path);
        if (resp == NULL && redirection_url != NULL) {
            if (redirection_ok(++n_redirs, current_url, redirection_url)) {
                (void)BIO_reset(bio);
                OPENSSL_free(current_url);
                current_url = redirection_url;
                if (*redirection_url == '/') { /* redirection to same server */
                    path = OPENSSL_strdup(redirection_url);
                    goto new_rpath;
                }
                OPENSSL_free(host);
                OPENSSL_free(port);
                continue;
            }
            OPENSSL_free(redirection_url);
        }
        OPENSSL_free(host);
        OPENSSL_free(port);
        break;
    }
    OPENSSL_free(current_url);
    return resp;
}

/* Get ASN.1-encoded data via HTTP from server at given URL */
ASN1_VALUE *OSSL_HTTP_get_asn1(const char *url,
                               const char *proxy, const char *proxy_port,
                               BIO *bio, BIO *rbio,
                               OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                               const STACK_OF(CONF_VALUE) *headers,
                               int maxline, unsigned long max_resp_len,
                               int timeout, const char *expected_content_type,
                               const ASN1_ITEM *it)
{
    BIO *mem;
    ASN1_VALUE *resp = NULL;

    if (url == NULL || it == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if ((mem = OSSL_HTTP_get(url, proxy, proxy_port, bio, rbio, bio_update_fn,
                             arg, headers, maxline, max_resp_len, timeout,
                             expected_content_type, 1 /* expect_asn1 */))
        != NULL)
        resp = BIO_mem_d2i(mem, it);
    BIO_free(mem);
    return resp;
}

/* Post ASN.1-encoded request via HTTP to server return ASN.1 response */
ASN1_VALUE *OSSL_HTTP_post_asn1(const char *server, const char *port,
                                const char *path, int use_ssl,
                                const char *proxy, const char *proxy_port,
                                BIO *bio, BIO *rbio,
                                OSSL_HTTP_bio_cb_t bio_update_fn, void *arg,
                                const STACK_OF(CONF_VALUE) *headers,
                                const char *content_type,
                                ASN1_VALUE *req, const ASN1_ITEM *req_it,
                                int maxline, unsigned long max_resp_len,
                                int timeout, const char *expected_ct,
                                const ASN1_ITEM *rsp_it)
{
    BIO *req_mem;
    BIO *res_mem;
    ASN1_VALUE *resp = NULL;

    if (req == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    /* remaining parameters are checked indirectly */

    req_mem = HTTP_asn1_item2bio(req_it, req);
    res_mem = OSSL_HTTP_transfer(server, port, path, use_ssl, proxy, proxy_port,
                                 bio, rbio,
                                 bio_update_fn, arg, headers, content_type,
                                 req_mem /* may be NULL */, maxline,
                                 max_resp_len, timeout,
                                 expected_ct, 1 /* expect_asn1 */, NULL);
    BIO_free(req_mem);
    if (res_mem != NULL)
        resp = BIO_mem_d2i(res_mem, rsp_it);
    BIO_free(res_mem);
    return resp;
}

/* BASE64 encoder used for encoding basic proxy authentication credentials */
static char *base64encode(const void *buf, size_t len)
{
    int i;
    size_t outl;
    char *out;

    /* Calculate size of encoded data */
    outl = (len / 3);
    if (len % 3 > 0)
        outl++;
    outl <<= 2;
    out = OPENSSL_malloc(outl + 1);
    if (out == NULL)
        return 0;

    i = EVP_EncodeBlock((unsigned char *)out, buf, len);
    if (!ossl_assert(0 <= i && (size_t)i <= outl)) {
        OPENSSL_free(out);
        return NULL;
    }
    return out;
}

/*
 * Promote the given connection BIO using the CONNECT method for a TLS proxy.
 * This is typically called by an app, so bio_err and prog are used unless NULL
 * to print additional diagnostic information in a user-oriented way.
 */
int OSSL_HTTP_proxy_connect(BIO *bio, const char *server, const char *port,
                            const char *proxyuser, const char *proxypass,
                            int timeout, BIO *bio_err, const char *prog)
{
# undef BUF_SIZE
# define BUF_SIZE (8 * 1024)
    char *mbuf = OPENSSL_malloc(BUF_SIZE);
    char *mbufp;
    int read_len = 0;
    int rv;
    int ret = 0;
    BIO *fbio = BIO_new(BIO_f_buffer());
    time_t max_time = timeout > 0 ? time(NULL) + timeout : 0;

    if (bio == NULL || server == NULL || port == NULL
            || (bio_err != NULL && prog == NULL)) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        goto end;
    }

    if (mbuf == NULL || fbio == NULL) {
        BIO_printf(bio_err /* may be NULL */, "%s: out of memory", prog);
        goto end;
    }
    BIO_push(fbio, bio);

    BIO_printf(fbio, "CONNECT %s:%s "HTTP_PREFIX"1.0\r\n", server, port);

    /*
     * Workaround for broken proxies which would otherwise close
     * the connection when entering tunnel mode (e.g., Squid 2.6)
     */
    BIO_printf(fbio, "Proxy-Connection: Keep-Alive\r\n");

    /* Support for basic (base64) proxy authentication */
    if (proxyuser != NULL) {
        size_t len = strlen(proxyuser) + 1;
        char *proxyauth, *proxyauthenc = NULL;

        if (proxypass != NULL)
            len += strlen(proxypass);
        proxyauth = OPENSSL_malloc(len + 1);
        if (proxyauth == NULL)
            goto end;
        if (BIO_snprintf(proxyauth, len + 1, "%s:%s", proxyuser,
                         proxypass != NULL ? proxypass : "") != (int)len)
            goto proxy_end;
        proxyauthenc = base64encode(proxyauth, len);
        if (proxyauthenc != NULL) {
            BIO_printf(fbio, "Proxy-Authorization: Basic %s\r\n", proxyauthenc);
            OPENSSL_clear_free(proxyauthenc, strlen(proxyauthenc));
        }
     proxy_end:
        OPENSSL_clear_free(proxyauth, len);
        if (proxyauthenc == NULL)
            goto end;
    }

    /* Terminate the HTTP CONNECT request */
    BIO_printf(fbio, "\r\n");

    for (;;) {
        if (BIO_flush(fbio) != 0)
            break;
        /* potentially needs to be retried if BIO is non-blocking */
        if (!BIO_should_retry(fbio))
            break;
    }

    for (;;) {
        /* will not actually wait if timeout == 0 */
        rv = BIO_wait(fbio, max_time);
        if (rv <= 0) {
            BIO_printf(bio_err, "%s: HTTP CONNECT %s\n", prog,
                       rv == 0 ? "timed out" : "failed waiting for data");
            goto end;
        }

        /*-
         * The first line is the HTTP response.
         * According to RFC 7230, it is formatted exactly like this:
         * HTTP/d.d ddd Reason text\r\n
         */
        read_len = BIO_gets(fbio, mbuf, BUF_SIZE);
        /* the BIO may not block, so we must wait for the 1st line to come in */
        if (read_len < HTTP_LINE1_MINLEN)
            continue;

        /* RFC 7231 4.3.6: any 2xx status code is valid */
        if (strncmp(mbuf, HTTP_PREFIX, strlen(HTTP_PREFIX)) != 0) {
            HTTPerr(0, HTTP_R_SERVER_RESPONSE_PARSE_ERROR);
            BIO_printf(bio_err, "%s: HTTP CONNECT failed, non-HTTP response\n",
                       prog);
            /* Wrong protocol, not even HTTP, so stop reading headers */
            goto end;
        }
        mbufp = mbuf + strlen(HTTP_PREFIX);
        if (strncmp(mbufp, HTTP_VERSION_PATT, strlen(HTTP_VERSION_PATT)) != 0) {
            HTTPerr(0, HTTP_R_SERVER_SENT_WRONG_HTTP_VERSION);
            BIO_printf(bio_err,
                       "%s: HTTP CONNECT failed, bad HTTP version %.*s\n",
                       prog, HTTP_VERSION_STR_LEN, mbufp);
            goto end;
        }
        mbufp += HTTP_VERSION_STR_LEN;
        if (strncmp(mbufp, " 2", strlen(" 2")) != 0) {
            mbufp += 1;
            /* chop any trailing whitespace */
            while (read_len > 0 && ossl_isspace(mbuf[read_len - 1]))
                read_len--;
            mbuf[read_len] = '\0';
            HTTPerr(0, HTTP_R_CONNECT_FAILURE);
            ERR_add_error_data(2, "Reason=", mbufp);
            BIO_printf(bio_err, "%s: HTTP CONNECT failed, Reason=%s\n",
                       prog, mbufp);
            goto end;
        }
        ret = 1;
        break;
    }

    /* Read past all following headers */
    do {
        /*
         * TODO: This does not necessarily catch the case when the full
         * HTTP response came in in more than a single TCP message.
         */
        read_len = BIO_gets(fbio, mbuf, BUF_SIZE);
    } while (read_len > 2);

 end:
    if (fbio != NULL) {
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
    }
    OPENSSL_free(mbuf);
    return ret;
# undef BUF_SIZE
}

#endif /* !defined(OPENSSL_NO_SOCK) */
