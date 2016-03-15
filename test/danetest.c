/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "../e_os.h"

#define _UC(c) ((unsigned char)(c))

static const char *progname;

/*
 * Forward declaration, of function that uses internal interfaces, from headers
 * included at the end of this module.
 */
static void store_ctx_dane_init(X509_STORE_CTX *, SSL *);

static int saved_errno;

static void save_errno(void)
{
    saved_errno = errno;
}

static int restore_errno(void)
{
    int ret = errno;
    errno = saved_errno;
    return ret;
}

static void test_usage(void)
{
    fprintf(stderr, "usage: %s: danetest basedomain CAfile tlsafile\n", progname);
}

static void print_errors(void)
{
    unsigned long err;
    char buffer[1024];
    const char *file;
    const char *data;
    int line;
    int flags;

    while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        ERR_error_string_n(err, buffer, sizeof(buffer));
        if (flags & ERR_TXT_STRING)
            fprintf(stderr, "Error: %s:%s:%d:%s\n", buffer, file, line, data);
        else
            fprintf(stderr, "Error: %s:%s:%d\n", buffer, file, line);
    }
}

static int verify_chain(SSL *ssl, STACK_OF(X509) *chain)
{
    int ret;
    X509_STORE_CTX *store_ctx;
    SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);
    int store_ctx_idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    X509 *cert = sk_X509_value(chain, 0);

    if ((store_ctx = X509_STORE_CTX_new()) == NULL)
        return -1;

    if (!X509_STORE_CTX_init(store_ctx, store, cert, chain))
	return 0;
    X509_STORE_CTX_set_ex_data(store_ctx, store_ctx_idx, ssl);

    X509_STORE_CTX_set_default(store_ctx,
            SSL_is_server(ssl) ? "ssl_client" : "ssl_server");
    X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(store_ctx),
            SSL_get0_param(ssl));
    store_ctx_dane_init(store_ctx, ssl);

    if (SSL_get_verify_callback(ssl))
	X509_STORE_CTX_set_verify_cb(store_ctx, SSL_get_verify_callback(ssl));

    ret = X509_verify_cert(store_ctx);

    SSL_set_verify_result(ssl, X509_STORE_CTX_get_error(store_ctx));
    X509_STORE_CTX_cleanup(store_ctx);
    X509_STORE_CTX_free(store_ctx);

    return (ret);
}

static STACK_OF(X509) *load_chain(BIO *fp, int nelem)
{
    int count;
    char *name = 0;
    char *header = 0;
    unsigned char *data = 0;
    long len;
    char *errtype = 0;		/* if error: cert or pkey? */
    STACK_OF(X509) *chain;
    typedef X509 *(*d2i_X509_t)(X509 **, const unsigned char **, long);

    if ((chain = sk_X509_new_null()) == 0) {
	perror("malloc");
	exit(1);
    }

    for (count = 0;
	 count < nelem && errtype == 0
         && PEM_read_bio(fp, &name, &header, &data, &len);
	 ++count) {
	const unsigned char *p = data;

	if (strcmp(name, PEM_STRING_X509) == 0
	    || strcmp(name, PEM_STRING_X509_TRUSTED) == 0
	    || strcmp(name, PEM_STRING_X509_OLD) == 0) {
	    d2i_X509_t d = strcmp(name, PEM_STRING_X509_TRUSTED) ?
		d2i_X509_AUX : d2i_X509;
	    X509 *cert = d(0, &p, len);

	    if (cert == 0 || (p - data) != len)
		errtype = "certificate";
	    else if (sk_X509_push(chain, cert) == 0) {
		perror("malloc");
		goto err;
	    }
	} else {
	    fprintf(stderr, "unexpected chain file object: %s\n", name);
	    goto err;
	}

	/*
	 * If any of these were null, PEM_read() would have failed.
	 */
	OPENSSL_free(name);
	OPENSSL_free(header);
	OPENSSL_free(data);
    }

    if (errtype) {
	fprintf(stderr, "error reading: malformed %s\n", errtype);
        goto err;
    }
    
    if (count == nelem) {
        ERR_clear_error();
        return chain;
    }

err:
    /* Some other PEM read error */
    sk_X509_pop_free(chain, X509_free);
    print_errors();
    return NULL;
}

static char *read_to_eol(BIO *f)
{
    static char buf[1024];
    int n;

    if (!BIO_gets(f, buf, sizeof(buf)))
        return NULL;

    n = strlen(buf);

    if (buf[n-1] != '\n') {
        if (n+1 == sizeof(buf)) {
            fprintf(stderr, "%s: warning: input too long\n", progname);
        } else {
            fprintf(stderr, "%s: warning: EOF before newline\n", progname);
        }
        return NULL;
    }

    /* Trim trailing whitespace */
    while (n > 0 && isspace(_UC(buf[n-1])))
        buf[--n] = '\0';

    return buf;
}

/*
 * Hex decoder that tolerates optional whitespace
 */
static ossl_ssize_t hexdecode(const char *in, void *result)
{
    unsigned char **out = (unsigned char **)result;
    unsigned char *ret = OPENSSL_malloc(strlen(in)/2);
    unsigned char *cp = ret;
    uint8_t byte;
    int nibble = 0;

    if (ret == NULL)
        return -1;

    for (byte = 0; *in; ++in) {
        char c;

        if (isspace(_UC(*in)))
            continue;
        c = tolower(_UC(*in));
        if ('0' <= c && c <= '9') {
            byte |= c - '0';
        } else if ('a' <= c && c <= 'f') {
            byte |= c - 'a' + 10;
        } else {
            OPENSSL_free(ret);
            return 0;
        }
        if ((nibble ^= 1) == 0) {
            *cp++ = byte;
            byte = 0;
        } else {
            byte <<= 4;
        }
    }
    if (nibble != 0) {
        OPENSSL_free(ret);
        return 0;
    }

    return cp - (*out = ret);
}

static ossl_ssize_t checked_uint8(const char *in, void *out)
{
    uint8_t *result = (uint8_t *)out;
    const char *cp = in;
    char *endp;
    long v;
    int e;

    save_errno();
    v = strtol(cp, &endp, 10);
    e = restore_errno();

    if (((v == LONG_MIN || v == LONG_MAX) && e == ERANGE) ||
        endp == cp || !isspace(_UC(*endp)) ||
        v != (*(uint8_t *)result = (uint8_t) v)) {
        return -1;
    }
    for (cp = endp; isspace(_UC(*cp)); ++cp)
        continue;
    return cp - in;
}

struct tlsa_field {
    void *var;
    const char *name;
    ossl_ssize_t (*parser)(const char *, void *);
};

static int tlsa_import_rr(SSL *ssl, const char *rrdata)
{
    static uint8_t usage;
    static uint8_t selector;
    static uint8_t mtype;
    static unsigned char *data = NULL;
    static struct tlsa_field tlsa_fields[] = {
        { &usage, "usage", checked_uint8 },
        { &selector, "selector", checked_uint8 },
        { &mtype, "mtype", checked_uint8 },
        { &data, "data", hexdecode },
        { NULL, }
    };
    int ret;
    struct tlsa_field *f;
    const char *cp = rrdata;
    ossl_ssize_t len = 0;

    for (f = tlsa_fields; f->var; ++f) {
        if ((len = f->parser(cp += len, f->var)) <= 0) {
            fprintf(stderr, "%s: warning: bad TLSA %s field in: %s\n",
                    progname, f->name, rrdata);
            return 0;
        }
    }
    ret = SSL_dane_tlsa_add(ssl, usage, selector, mtype, data, len);
    OPENSSL_free(data);

    if (ret == 0) {
        print_errors();
        fprintf(stderr, "%s: warning: unusable TLSA rrdata: %s\n",
                progname, rrdata);
        return 0;
    }
    if (ret < 0) {
        fprintf(stderr, "%s: warning: error loading TLSA rrdata: %s\n",
                progname, rrdata);
        return 0;
    }
    return ret;
}

static int allws(const char *cp)
{
    while (*cp)
        if (!isspace(_UC(*cp++)))
            return 0;
    return 1;
}

static int test_tlsafile(SSL_CTX *ctx, const char *basename,
                         BIO *f, const char *path)
{
    char *line;
    int testno = 0;
    int ret = 1;
    SSL *ssl;

    while (ret > 0 && (line = read_to_eol(f)) != NULL) {
        STACK_OF(X509) *chain;
        int ntlsa;
        int ncert;
        int want;
        int want_depth;
        int off;
        int i;
        int ok;
        int err;
        int mdpth;

        if (*line == '\0' || *line == '#')
            continue;

        ++testno;
        if (sscanf(line, "%d %d %d %d%n", &ntlsa, &ncert, &want, &want_depth, &off) != 4
            || !allws(line + off)) {
            fprintf(stderr, "Expected tlsa count, cert count and result"
                    " at test %d of %s\n", testno, path);
            return 0;
        }

        if ((ssl = SSL_new(ctx)) == NULL)
            return -1;
        SSL_set_connect_state(ssl);
        if (SSL_dane_enable(ssl, basename) <= 0) {
            SSL_free(ssl);
            return -1;
        }

        for (i = 0; i < ntlsa; ++i) {
            if ((line = read_to_eol(f)) == NULL || !tlsa_import_rr(ssl, line)) {
                SSL_free(ssl);
                return 0;
            }
        }

        /* Don't report old news */
        ERR_clear_error();
        chain = load_chain(f, ncert);
        if (chain == NULL) {
            SSL_free(ssl);
            return -1;
        }

        ok = verify_chain(ssl, chain);
        sk_X509_pop_free(chain, X509_free);
        err = SSL_get_verify_result(ssl);
        /*
         * Peek under the hood, normally TLSA match data is hidden when
         * verification fails, we can obtain any suppressed data by setting the
         * verification result to X509_V_OK before looking.
         */
        SSL_set_verify_result(ssl, X509_V_OK);
        mdpth = SSL_get0_dane_authority(ssl, NULL, NULL);
        /* Not needed any more, but lead by example and put the error back. */
        SSL_set_verify_result(ssl, err);
        SSL_free(ssl);

        if (ok < 0) {
            ret = 0;
            fprintf(stderr, "verify_chain internal error in %s test %d\n",
                    path, testno);
            print_errors();
            continue;
        }
        if (err != want || (want == 0 && !ok)) {
            ret = 0;
            if (err != want) {
                if (want == X509_V_OK)
                    fprintf(stderr, "Verification failure in %s test %d: %d: %s\n",
                            path, testno, err, X509_verify_cert_error_string(err));
                else
                    fprintf(stderr, "Unexpected error in %s test %d: %d: wanted %d\n",
                            path, testno, err, want);
            } else {
                fprintf(stderr, "Verification failure in %s test %d: ok=0\n",
                        path, testno);
            }
            print_errors();
            continue;
        }
        if (mdpth != want_depth) {
            ret = 0;
            fprintf(stderr, "Wrong match depth, in %s test %d: wanted %d, got: %d\n",
                    path, testno, want_depth, mdpth);
        }
        fprintf(stderr, "%s: test %d successful\n", path, testno);
    }
    ERR_clear_error();

    return ret;
}

int main(int argc, char *argv[])
{
    BIO *f;
    BIO *bio_err;
    SSL_CTX *ctx = NULL;
    const char *basedomain;
    const char *CAfile;
    const char *tlsafile;
    const char *p;
    int ret = 1;

    progname = argv[0];
    if (argc != 4) {
        test_usage();
        EXIT(1);
    }
    basedomain = argv[1];
    CAfile = argv[2];
    tlsafile = argv[3];

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    p = getenv("OPENSSL_DEBUG_MEMORY");
    if (p != NULL && strcmp(p, "on") == 0)
        CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    f = BIO_new_file(tlsafile, "r");
    if (f == NULL) {
        fprintf(stderr, "%s: Error opening tlsa record file: '%s': %s\n",
                progname, tlsafile, strerror(errno));
        return 0;
    }


    ctx = SSL_CTX_new(TLS_client_method());
    if (SSL_CTX_dane_enable(ctx) <= 0) {
        print_errors();
        goto end;
    }
    if (!SSL_CTX_load_verify_locations(ctx, CAfile, NULL)) {
        print_errors();
        goto end;
    }
    if ((SSL_CTX_dane_mtype_set(ctx, EVP_sha512(), 2, 1)) <= 0) {
        print_errors();
        goto end;
    }
    if ((SSL_CTX_dane_mtype_set(ctx, EVP_sha256(), 1, 2)) <= 0) {
        print_errors();
        goto end;
    }

    if (test_tlsafile(ctx, basedomain, f, tlsafile) <= 0) {
        print_errors();
        goto end;
    }

    ret = 0;

end:

    BIO_free(f);
    SSL_CTX_free(ctx);

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks(bio_err) <= 0)
        ret = 1;
#endif
    BIO_free(bio_err);
    EXIT(ret);
}

#include <internal/dane.h>

static void store_ctx_dane_init(X509_STORE_CTX *store_ctx, SSL *ssl)
{
    X509_STORE_CTX_set0_dane(store_ctx, SSL_get0_dane(ssl));
}
