/*
 * C implementation based on the original Perl and shell versions
 *
 * Copyright (c) 2013-2014 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 */
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "apps.h"

#ifdef unix
# include <unistd.h>
# include <stdio.h>
# include <limits.h>
# include <errno.h>
# include <string.h>
# include <ctype.h>
# include <sys/stat.h>

# include "internal/o_dir.h"
# include <openssl/evp.h>
# include <openssl/pem.h>
# include <openssl/x509.h>


# define MAX_COLLISIONS  256

typedef struct hentry_st {
    struct hentry_st *next;
    char *filename;
    unsigned short old_id;
    unsigned char need_symlink;
    unsigned char digest[EVP_MAX_MD_SIZE];
} HENTRY;

typedef struct bucket_st {
    struct bucket_st *next;
    HENTRY *first_entry, *last_entry;
    unsigned int hash;
    unsigned short type;
    unsigned short num_needed;
} BUCKET;

enum Type {
    /* Keep in sync with |suffixes|, below. */
    TYPE_CERT=0, TYPE_CRL=1
};

enum Hash {
    HASH_OLD, HASH_NEW, HASH_BOTH
};


static int evpmdsize;
static const EVP_MD *evpmd;
static int remove_links = 1;
static int verbose = 0;
static BUCKET *hash_table[257];

static const char *suffixes[] = { "", "r" };
static const char *extensions[] = { "pem", "crt", "cer", "crl" };


static void bit_set(unsigned char *set, unsigned int bit)
{
    set[bit >> 3] |= 1 << (bit & 0x7);
}

static int bit_isset(unsigned char *set, unsigned int bit)
{
    return set[bit >> 3] & (1 << (bit & 0x7));
}


static void add_entry(enum Type type, unsigned int hash, const char *filename,
                      const unsigned char *digest, int need_symlink,
                      unsigned short old_id)
{
    static BUCKET nilbucket;
    static HENTRY nilhentry;
    BUCKET *bp;
    HENTRY *ep, *found = NULL;
    unsigned int ndx = (type + hash) % OSSL_NELEM(hash_table);

    for (bp = hash_table[ndx]; bp; bp = bp->next)
        if (bp->type == type && bp->hash == hash)
            break;
    if (bp == NULL) {
        bp = app_malloc(sizeof(*bp), "hash bucket");
        *bp = nilbucket;
        bp->next = hash_table[ndx];
        bp->type = type;
        bp->hash = hash;
        hash_table[ndx] = bp;
    }

    for (ep = bp->first_entry; ep; ep = ep->next) {
        if (digest && memcmp(digest, ep->digest, evpmdsize) == 0) {
            BIO_printf(bio_err,
                       "%s: skipping duplicate certificate in %s\n",
                       opt_getprog(), filename);
            return;
        }
        if (strcmp(filename, ep->filename) == 0) {
            found = ep;
            if (digest == NULL)
                break;
        }
    }
    ep = found;
    if (ep == NULL) {
        if (bp->num_needed >= MAX_COLLISIONS)
            return;
        ep = app_malloc(sizeof(*ep), "collision bucket");
        *ep = nilhentry;
        ep->old_id = ~0;
        ep->filename = BUF_strdup(filename);
        if (bp->last_entry)
            bp->last_entry->next = ep;
        if (bp->first_entry == NULL)
            bp->first_entry = ep;
        bp->last_entry = ep;
    }

    if (old_id < ep->old_id)
        ep->old_id = old_id;
    if (need_symlink && !ep->need_symlink) {
        ep->need_symlink = 1;
        bp->num_needed++;
        memcpy(ep->digest, digest, evpmdsize);
    }
}

static int handle_symlink(const char *filename, const char *fullpath)
{
    unsigned int hash = 0;
    int i, type, id;
    unsigned char ch;
    char linktarget[NAME_MAX], *endptr;
    ssize_t n;

    for (i = 0; i < 8; i++) {
        ch = filename[i];
        if (!isxdigit(ch))
            return -1;
        hash <<= 4;
        hash += app_hex(ch);
    }
    if (filename[i++] != '.')
        return -1;
    for (type = OSSL_NELEM(suffixes) - 1; type > 0; type--)
        if (strcasecmp(suffixes[type], &filename[i]) == 0)
            break;
    i += strlen(suffixes[type]);

    id = strtoul(&filename[i], &endptr, 10);
    if (*endptr != '\0')
        return -1;

    n = readlink(fullpath, linktarget, sizeof(linktarget));
    if (n < 0 || n >= (int)sizeof(linktarget))
        return -1;
    linktarget[n] = 0;

    add_entry(type, hash, linktarget, NULL, 0, id);
    return 0;
}

static int do_file(const char *filename, const char *fullpath, enum Hash h)
{
    STACK_OF (X509_INFO) *inf;
    X509_INFO *x;
    X509_NAME *name = NULL;
    BIO *b;
    const char *ext;
    unsigned char digest[EVP_MAX_MD_SIZE];
    int i, type, ret = -1;

    if ((ext = strrchr(filename, '.')) == NULL)
        return 0;
    for (i = 0; i < (int)OSSL_NELEM(extensions); i++) {
        if (strcasecmp(extensions[i], ext + 1) == 0)
            break;
    }
    if (i >= (int)OSSL_NELEM(extensions))
        return -1;

    if ((b = BIO_new_file(fullpath, "r")) == NULL)
        return -1;
    inf = PEM_X509_INFO_read_bio(b, NULL, NULL, NULL);
    BIO_free(b);
    if (inf == NULL)
        return -1;

    if (sk_X509_INFO_num(inf) != 1) {
        BIO_printf(bio_err,
                   "%s: skipping %s,"
                   "it does not contain exactly one certificate or CRL\n",
                   opt_getprog(), filename);
        goto end;
    }
    x = sk_X509_INFO_value(inf, 0);
    if (x->x509) {
        type = TYPE_CERT;
        name = X509_get_subject_name(x->x509);
        X509_digest(x->x509, evpmd, digest, NULL);
    } else if (x->crl) {
        type = TYPE_CRL;
        name = X509_CRL_get_issuer(x->crl);
        X509_CRL_digest(x->crl, evpmd, digest, NULL);
    }
    if (name) {
        if ((h == HASH_NEW) || (h == HASH_BOTH))
            add_entry(type, X509_NAME_hash(name), filename, digest, 1, ~0);
        if ((h == HASH_OLD) || (h == HASH_BOTH))
            add_entry(type, X509_NAME_hash_old(name), filename, digest, 1, ~0);
    }

end:
    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    return ret;
}

static int do_dir(const char *dirname, enum Hash h)
{
    BUCKET *bp, *nextbp;
    HENTRY *ep, *nextep;
    OPENSSL_DIR_CTX *d = NULL;
    struct stat st;
    unsigned char idmask[MAX_COLLISIONS / 8];
    int i, n, nextid, buflen, ret = -1;
    const char *pathsep;
    const char *filename;
    char *buf;

    buflen = strlen(dirname);
    pathsep = (buflen && dirname[buflen - 1] == '/') ? "" : "/";
    buflen += NAME_MAX + 2;
    buf = app_malloc(buflen, "filename buffer");

    if (verbose)
        BIO_printf(bio_out, "Doing %s\n", dirname);

    while ((filename = OPENSSL_DIR_read(&d, dirname)) != NULL) {
        if (snprintf(buf, buflen, "%s%s%s",
                    dirname, pathsep, filename) >= buflen)
            continue;
        if (lstat(buf, &st) < 0)
            continue;
        if (S_ISLNK(st.st_mode) && handle_symlink(filename, buf) == 0)
            continue;
        do_file(filename, buf, h);
    }
    OPENSSL_DIR_end(&d);

    for (i = 0; i < (int)OSSL_NELEM(hash_table); i++) {
        for (bp = hash_table[i]; bp; bp = nextbp) {
            nextbp = bp->next;
            nextid = 0;
            memset(idmask, 0, (bp->num_needed + 7) / 8);
            for (ep = bp->first_entry; ep; ep = ep->next)
                if (ep->old_id < bp->num_needed)
                    bit_set(idmask, ep->old_id);

            for (ep = bp->first_entry; ep; ep = nextep) {
                nextep = ep->next;
                if (ep->old_id < bp->num_needed) {
                    /* Link exists, and is used as-is */
                    snprintf(buf, buflen, "%08x.%s%d", bp->hash,
                             suffixes[bp->type], ep->old_id);
                    if (verbose)
                        BIO_printf(bio_out, "link %s -> %s\n",
                                   ep->filename, buf);
                } else if (ep->need_symlink) {
                    /* New link needed (it may replace something) */
                    while (bit_isset(idmask, nextid))
                        nextid++;

                    snprintf(buf, buflen, "%s%s%n%08x.%s%d",
                             dirname, pathsep, &n, bp->hash,
                             suffixes[bp->type], nextid);
                    if (verbose)
                        BIO_printf(bio_out, "link %s -> %s\n",
                                   ep->filename, &buf[n]);
                    if (unlink(buf) < 0 && errno != ENOENT)
                        BIO_printf(bio_err,
                                   "%s: Can't unlink %s, %s\n",
                                   opt_getprog(), buf, strerror(errno));
                    if (symlink(ep->filename, buf) < 0)
                        BIO_printf(bio_err,
                                   "%s: Can't symlink %s, %s\n",
                                   opt_getprog(), ep->filename,
                                   strerror(errno));
                } else if (remove_links) {
                    /* Link to be deleted */
                    snprintf(buf, buflen, "%s%s%n%08x.%s%d",
                             dirname, pathsep, &n, bp->hash,
                             suffixes[bp->type], ep->old_id);
                    if (verbose)
                        BIO_printf(bio_out, "unlink %s\n",
                                   &buf[n]);
                    if (unlink(buf) < 0 && errno != ENOENT)
                        BIO_printf(bio_err,
                                   "%s: Can't unlink %s, %s\n",
                                   opt_getprog(), buf, strerror(errno));
                }
                OPENSSL_free(ep->filename);
                OPENSSL_free(ep);
            }
            OPENSSL_free(bp);
        }
        hash_table[i] = NULL;
    }
    ret = 0;

    OPENSSL_free(buf);
    return ret;
}

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_COMPAT, OPT_OLD, OPT_N, OPT_VERBOSE
} OPTION_CHOICE;

OPTIONS rehash_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] [cert-directory...]\n"},
    {OPT_HELP_STR, 1, '-', "Valid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"compat", OPT_COMPAT, '-', "Create both new- and old-style hash links"},
    {"old", OPT_OLD, '-', "Use old-style hash to generate links"},
    {"n", OPT_N, '-', "Do not remove existing links"},
    {"v", OPT_VERBOSE, '-', "Verbose output"},
    {NULL}
};


int rehash_main(int argc, char **argv)
{
    const char *env, *prog;
    char *e, *m;
    int ret = 0;
    OPTION_CHOICE o;
    enum Hash h = HASH_NEW;

    prog = opt_init(argc, argv, rehash_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(rehash_options);
            goto end;
        case OPT_COMPAT:
            h = HASH_BOTH;
            break;
        case OPT_OLD:
            h = HASH_OLD;
            break;
        case OPT_N:
            remove_links = 0;
            break;
        case OPT_VERBOSE:
            verbose = 1;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    evpmd = EVP_sha1();
    evpmdsize = EVP_MD_size(evpmd);

    if (*argv) {
        while (*argv)
            ret |= do_dir(*argv++, h);
    } else if ((env = getenv("SSL_CERT_DIR")) != NULL) {
        m = BUF_strdup(env);
        for (e = strtok(m, ":"); e != NULL; e = strtok(NULL, ":"))
            ret |= do_dir(e, h);
        OPENSSL_free(m);
    } else {
        ret |= do_dir("/etc/ssl/certs", h);
    }

 end:
    return ret ? 2 : 0;
}

#else
OPTIONS rehash_options[] = {
    {NULL}
};

int rehash_main(int argc, char **argv)
{
    BIO_printf(bio_err, "Not available; use c_rehash script\n");
    return (1);
}

#endif
