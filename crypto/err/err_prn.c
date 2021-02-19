/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* TODO: When ERR_STATE becomes opaque, this musts be removed */
#define OSSL_FORCE_ERR_STATE

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <crypto/err.h>

int ERR_location_string_n(int lib, const char *func, const char *file, int line,
                          char *buf, size_t len)
{
    int n = 0;
    int ret = 0;
    const char *ls = ERR_lib_error_string(ERR_PACK(lib, 0, 0));

    if (len == 0)
        return -1;
    buf[0] = '\0';

    if (ls == NULL)
        n = BIO_snprintf(buf, len, "lib(%d):", lib);
    else
        n = BIO_snprintf(buf, len, "%s:", ls);
    if (n < 0)
        return -1;

#ifdef NDEBUG
    func = NULL;
    file = NULL;
#endif
    if (func != NULL && strcmp(func, OSSL_unknown_func) == 0)
        func = NULL; /* suppress pseudo information "(unknown function)" */
    if (func != NULL) {
        ret = BIO_snprintf(buf + n, len - n, "%s()", func);
        if (ret < 0)
            return -1;
        n += ret;
    }

    if (file != NULL) {
        ret = BIO_snprintf(buf + n, len - n, ":%s:%d", file, line);
        if (ret < 0)
            return -1;
        n += ret;
    }

    return n;
}

static int reason_string_n(unsigned long e, char *buf, size_t len)
{
    int r = ERR_GET_REASON(e);
    const char *rs = NULL;

    if (len == 0)
        return -1;
    buf[0] = '\0';

    /*
     * ERR_reason_error_string() can't safely return system error strings,
     * since it would call openssl_strerror_r(), which needs a buffer for
     * thread safety.  So for system errors, we call openssl_strerror_r()
     * directly instead.
     */
#ifndef OPENSSL_NO_ERR
    if (ERR_SYSTEM_ERROR(e)) {
        if (openssl_strerror_r(r, buf, len))
            rs = buf;
    } else {
        rs = ERR_reason_error_string(e);
        if (rs != NULL && BIO_snprintf(buf, len, "%s", rs) < 0)
            rs = NULL;
    }
#endif
    return
        rs == NULL ? BIO_snprintf(buf, len, "reason(%d)", r) : (int)strlen(buf);
}

int ossl_err_string_int(char *buf, size_t len, int with_tid, int with_osslv,
                        const char *func, const char *file, int line,
                        unsigned long err, const char *data, const char *nl)
{
    char lsbuf[256], rsbuf[256];
    int l, ret = 0;

#ifdef NDEBUG
    with_tid = 0;
#endif
    if (with_tid) {
        CRYPTO_THREAD_ID tid = CRYPTO_THREAD_get_current_id();
        char *hex = ossl_buf2hexstr_sep((const unsigned char *)&tid,
                                        sizeof(tid), '\0');

        ret = BIO_snprintf(buf, len, "%s:",
                           hex == NULL ? "(unknown tid)" : hex);
        if (ret < 0)
            return -1;
        OPENSSL_free(hex);
    }
    buf += ret;
    len -= ret;

    if (with_osslv) {
        if ((ret = BIO_snprintf(buf, len, "OpenSSL %s ",
                                OPENSSL_FULL_VERSION_STR)) < 0)
            return -1;
        buf += ret;
        len -= ret;
    }
    if ((ret = BIO_snprintf(buf, len, "error:%08lX:", err)) < 0)
        return -1;
    buf += ret;
    len -= ret;

    l = ERR_GET_LIB(err);
    /* Deliberately ignore any errors here; in error strings are truncated. */
    (void)ERR_location_string_n(l, func, file, line, lsbuf, sizeof(lsbuf));
    (void)reason_string_n(err, rsbuf, sizeof(rsbuf));

    ret = BIO_snprintf(buf, len, "%s:%s%s%s%s", lsbuf, rsbuf,
                       data == NULL ? "" : ":", data == NULL ? "" : data, nl);
    if (ret >= 0)
        return len - ret;
    /* Didn't fit; use a minimal format. */
    ret = BIO_snprintf(buf, len, "%d:%d:%s", l, ERR_GET_REASON(err), nl);
    return ret >= 0 ? (int)(len - ret) : -1;
}


int ERR_error_string_n(unsigned long err, char *buf, size_t len)
{
    return ossl_err_string_int(buf, len, 0, 0, NULL, NULL, 0, err, NULL, "");
}

/*
 * ERR_error_string_n() should be used instead for ret != NULL as
 * ERR_error_string() cannot know how large the buffer is
 */
char *ERR_error_string(unsigned long e, char *ret)
{
    static char buf[256];

    if (ret == NULL)
        ret = buf;
    ERR_error_string_n(e, ret, sizeof(buf));
    return ret;
}

#define ERR_PRINT_BUF_SIZE 4096
void ERR_print_errors_cb(int (*cb) (const char *str, size_t len, void *u),
                         void *u)
{
    unsigned long l;
    const char *file, *data, *func;
    int line, flags;

    while ((l = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        char buf[ERR_PRINT_BUF_SIZE] = "";

        if ((flags & ERR_TXT_STRING) == 0)
            data = "";
        ossl_err_string_int(buf, sizeof(buf),
                            1, 1, func, file, line, l, data, "");
        if (cb(buf, strlen(buf), u) <= 0)
            break;              /* abort outputting the error report */
    }
}

/* auxiliary function for incrementally reporting texts via the error queue */
static void put_error(int lib, const char *func, int reason,
                      const char *file, int line)
{
    ERR_new();
    ERR_set_debug(file, line, func);
    ERR_set_error(lib, reason, NULL /* no data here, so fmt is NULL */);
}

#define TYPICAL_MAX_OUTPUT_BEFORE_DATA 100
#define MAX_DATA_LEN (ERR_PRINT_BUF_SIZE - TYPICAL_MAX_OUTPUT_BEFORE_DATA)
void ERR_add_error_txt(const char *separator, const char *txt)
{
    const char *file = NULL;
    int line;
    const char *func = NULL;
    const char *data = NULL;
    int flags;
    unsigned long err = ERR_peek_last_error();

    if (separator == NULL)
        separator = "";
    if (err == 0)
        put_error(ERR_LIB_NONE, NULL, 0, "", 0);

    do {
        size_t available_len, data_len;
        const char *curr = txt, *next = txt;
        const char *leading_separator = separator;
        int trailing_separator = 0;
        char *tmp;

        ERR_peek_last_error_all(&file, &line, &func, &data, &flags);
        if ((flags & ERR_TXT_STRING) == 0) {
            data = "";
            leading_separator = "";
        }
        data_len = strlen(data);

        /* workaround for limit of ERR_print_errors_cb() */
        if (data_len >= MAX_DATA_LEN
                || strlen(separator) >= (size_t)(MAX_DATA_LEN - data_len))
            available_len = 0;
        else
            available_len = MAX_DATA_LEN - data_len - strlen(separator) - 1;
        /* MAX_DATA_LEN > available_len >= 0 */

        if (*separator == '\0') {
            const size_t len_next = strlen(next);

            if (len_next <= available_len) {
                next += len_next;
                curr = NULL; /* no need to split */
            } else {
                next += available_len;
                curr = next; /* will split at this point */
            }
        } else {
            while (*next != '\0' && (size_t)(next - txt) <= available_len) {
                curr = next;
                next = strstr(curr, separator);
                if (next != NULL) {
                    next += strlen(separator);
                    trailing_separator = *next == '\0';
                } else {
                    next = curr + strlen(curr);
                }
            }
            if ((size_t)(next - txt) <= available_len)
                curr = NULL; /* the above loop implies *next == '\0' */
        }
        if (curr != NULL) {
            /* split error msg at curr since error data would get too long */
            if (curr != txt) {
                tmp = OPENSSL_strndup(txt, curr - txt);
                if (tmp == NULL)
                    return;
                ERR_add_error_data(2, separator, tmp);
                OPENSSL_free(tmp);
            }
            put_error(ERR_GET_LIB(err), func, err, file, line);
            txt = curr;
        } else {
            if (trailing_separator) {
                tmp = OPENSSL_strndup(txt, next - strlen(separator) - txt);
                if (tmp == NULL)
                    return;
                /* output txt without the trailing separator */
                ERR_add_error_data(2, leading_separator, tmp);
                OPENSSL_free(tmp);
            } else {
                ERR_add_error_data(2, leading_separator, txt);
            }
            txt = next; /* finished */
        }
    } while (*txt != '\0');
}

void ERR_add_error_mem_bio(const char *separator, BIO *bio)
{
    if (bio != NULL) {
        char *str;
        long len = BIO_get_mem_data(bio, &str);

        if (len > 0) {
            if (str[len - 1] != '\0') {
                if (BIO_write(bio, "", 1) <= 0)
                    return;

                len = BIO_get_mem_data(bio, &str);
            }
            if (len > 1)
                ERR_add_error_txt(separator, str);
        }
    }
}

static int print_bio(const char *str, size_t len, void *bp)
{
    return BIO_printf((BIO *)bp, "%s\n", str) >= 0;
}

void ERR_print_errors(BIO *bp)
{
    ERR_print_errors_cb(print_bio, bp);
}

#ifndef OPENSSL_NO_STDIO
void ERR_print_errors_fp(FILE *fp)
{
    BIO *bio = BIO_new_fp(fp, BIO_NOCLOSE);
    if (bio == NULL)
        return;

    ERR_print_errors_cb(print_bio, bio);
    BIO_free(bio);
}
#endif
