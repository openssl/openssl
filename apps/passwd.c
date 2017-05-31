/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if defined OPENSSL_NO_MD5 || defined CHARSET_EBCDIC
# define NO_MD5CRYPT_1
#endif

#if defined OPENSSL_NO_SHA || defined CHARSET_EBCDIC
# define NO_SHACRYPT
#endif

#if !defined(OPENSSL_NO_DES) || !defined(NO_MD5CRYPT_1) || !defined(NO_SHACRYPT)

# include <string.h>

# include "apps.h"

# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# ifndef OPENSSL_NO_DES
#  include <openssl/des.h>
# endif
# ifndef NO_MD5CRYPT_1
#  include <openssl/md5.h>
# endif
# ifndef NO_SHACRYPT
#  include <openssl/sha.h>
# endif

static unsigned const char cov_2char[64] = {
    /* from crypto/des/fcrypt.c */
    0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44,
    0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
    0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54,
    0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
    0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
    0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A
};

typedef enum {
    passwd_unset = 0,
    passwd_crypt,
    passwd_md5,
    passwd_apr1,
    passwd_sha256,
    passwd_sha512,
    passwd_aixmd5
} passwd_modes;

static int do_passwd(int passed_salt, char **salt_p, char **salt_malloc_p,
                     char *passwd, BIO *out, int quiet, int table,
                     int reverse, size_t pw_maxlen, passwd_modes mode);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_IN,
    OPT_NOVERIFY, OPT_QUIET, OPT_TABLE, OPT_REVERSE, OPT_APR1,
    OPT_1, OPT_5, OPT_6, OPT_CRYPT, OPT_AIXMD5, OPT_SALT, OPT_STDIN
} OPTION_CHOICE;

const OPTIONS passwd_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Read passwords from file"},
    {"noverify", OPT_NOVERIFY, '-',
     "Never verify when reading password from terminal"},
    {"quiet", OPT_QUIET, '-', "No warnings"},
    {"table", OPT_TABLE, '-', "Format output as table"},
    {"reverse", OPT_REVERSE, '-', "Switch table columns"},
    {"salt", OPT_SALT, 's', "Use provided salt"},
    {"stdin", OPT_STDIN, '-', "Read passwords from stdin"},
# ifndef NO_SHACRYPT
    {"6", OPT_6, '-', "SHA512-based password algorithm"},
    {"5", OPT_5, '-', "SHA256-based password algorithm"},
# endif
# ifndef NO_MD5CRYPT_1
    {"apr1", OPT_APR1, '-', "MD5-based password algorithm, Apache variant"},
    {"1", OPT_1, '-', "MD5-based password algorithm"},
    {"aixmd5", OPT_AIXMD5, '-', "AIX MD5-based password algorithm"},
# endif
# ifndef OPENSSL_NO_DES
    {"crypt", OPT_CRYPT, '-', "Standard Unix password algorithm (default)"},
# endif
    {NULL}
};

int passwd_main(int argc, char **argv)
{
    BIO *in = NULL;
    char *infile = NULL, *salt = NULL, *passwd = NULL, **passwds = NULL;
    char *salt_malloc = NULL, *passwd_malloc = NULL, *prog;
    OPTION_CHOICE o;
    int in_stdin = 0, pw_source_defined = 0;
# ifndef OPENSSL_NO_UI
    int in_noverify = 0;
# endif
    int passed_salt = 0, quiet = 0, table = 0, reverse = 0;
    int ret = 1;
    passwd_modes mode = passwd_unset;
    size_t passwd_malloc_size = 0;
    size_t pw_maxlen = 256; /* arbitrary limit, should be enough for most
                             * passwords */

    prog = opt_init(argc, argv, passwd_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(passwd_options);
            ret = 0;
            goto end;
        case OPT_IN:
            if (pw_source_defined)
                goto opthelp;
            infile = opt_arg();
            pw_source_defined = 1;
            break;
        case OPT_NOVERIFY:
# ifndef OPENSSL_NO_UI
            in_noverify = 1;
# endif
            break;
        case OPT_QUIET:
            quiet = 1;
            break;
        case OPT_TABLE:
            table = 1;
            break;
        case OPT_REVERSE:
            reverse = 1;
            break;
        case OPT_1:
            if (mode != passwd_unset)
                goto opthelp;
            mode = passwd_md5;
            break;
        case OPT_5:
            if (mode != passwd_unset)
                goto opthelp;
            mode = passwd_sha256;
            break;
        case OPT_6:
            if (mode != passwd_unset)
                goto opthelp;
            mode = passwd_sha512;
            break;
        case OPT_APR1:
            if (mode != passwd_unset)
                goto opthelp;
            mode = passwd_apr1;
            break;
        case OPT_AIXMD5:
            if (mode != passwd_unset)
                goto opthelp;
            mode = passwd_aixmd5;
            break;
        case OPT_CRYPT:
            if (mode != passwd_unset)
                goto opthelp;
            mode = passwd_crypt;
            break;
        case OPT_SALT:
            passed_salt = 1;
            salt = opt_arg();
            break;
        case OPT_STDIN:
            if (pw_source_defined)
                goto opthelp;
            in_stdin = 1;
            pw_source_defined = 1;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (*argv) {
        if (pw_source_defined)
            goto opthelp;
        pw_source_defined = 1;
        passwds = argv;
    }

    if (mode == passwd_unset) {
        /* use default */
        mode = passwd_crypt;
    }

# ifdef OPENSSL_NO_DES
    if (mode == passwd_crypt)
        goto opthelp;
# endif
# ifdef NO_MD5CRYPT_1
    if (mode == passwd_md5 || mode == passwd_apr1 || mode == passwd_aixmd5)
        goto opthelp;
# endif
# ifdef NO_SHACRYPT
    if (mode == passwd_sha256 || mode == passwd_sha512)
        goto opthelp;
# endif

    if (infile != NULL && in_stdin) {
        BIO_printf(bio_err, "%s: Can't combine -in and -stdin\n", prog);
        goto end;
    }

    if (infile != NULL || in_stdin) {
        /*
         * If in_stdin is true, we know that infile is NULL, and that
         * bio_open_default() will give us back an alias for stdin.
         */
        in = bio_open_default(infile, 'r', FORMAT_TEXT);
        if (in == NULL)
            goto end;
    }

    if (mode == passwd_crypt)
        pw_maxlen = 8;

    if (passwds == NULL) {
        /* no passwords on the command line */

        passwd_malloc_size = pw_maxlen + 2;
        /* longer than necessary so that we can warn about truncation */
        passwd = passwd_malloc =
            app_malloc(passwd_malloc_size, "password buffer");
    }

    if ((in == NULL) && (passwds == NULL)) {
        /*
         * we use the following method to make sure what
         * in the 'else' section is always compiled, to
         * avoid rot of not-frequently-used code.
         */
        if (1) {
# ifndef OPENSSL_NO_UI
            /* build a null-terminated list */
            static char *passwds_static[2] = { NULL, NULL };

            passwds = passwds_static;
            if (in == NULL) {
                if (EVP_read_pw_string
                    (passwd_malloc, passwd_malloc_size, "Password: ",
                     !(passed_salt || in_noverify)) != 0)
                    goto end;
            }
            passwds[0] = passwd_malloc;
        } else {
# endif
            BIO_printf(bio_err, "password required\n");
            goto end;
        }
    }

    if (in == NULL) {
        assert(passwds != NULL);
        assert(*passwds != NULL);

        do {                    /* loop over list of passwords */
            passwd = *passwds++;
            if (!do_passwd(passed_salt, &salt, &salt_malloc, passwd, bio_out,
                           quiet, table, reverse, pw_maxlen, mode))
                goto end;
        } while (*passwds != NULL);
    } else {
        /* in != NULL */
        int done;

        assert(passwd != NULL);
        do {
            int r = BIO_gets(in, passwd, pw_maxlen + 1);
            if (r > 0) {
                char *c = (strchr(passwd, '\n'));
                if (c != NULL) {
                    *c = 0;     /* truncate at newline */
                } else {
                    /* ignore rest of line */
                    char trash[BUFSIZ];
                    do
                        r = BIO_gets(in, trash, sizeof trash);
                    while ((r > 0) && (!strchr(trash, '\n')));
                }

                if (!do_passwd
                    (passed_salt, &salt, &salt_malloc, passwd, bio_out, quiet,
                     table, reverse, pw_maxlen, mode))
                    goto end;
            }
            done = (r <= 0);
        } while (!done);
    }
    ret = 0;

 end:
    ERR_print_errors(bio_err);
    OPENSSL_free(salt_malloc);
    OPENSSL_free(passwd_malloc);
    BIO_free(in);
    return (ret);
}

# ifndef NO_MD5CRYPT_1
/*
 * MD5-based password algorithm (should probably be available as a library
 * function; then the static buffer would not be acceptable). For magic
 * string "1", this should be compatible to the MD5-based BSD password
 * algorithm. For 'magic' string "apr1", this is compatible to the MD5-based
 * Apache password algorithm. (Apparently, the Apache password algorithm is
 * identical except that the 'magic' string was changed -- the laziest
 * application of the NIH principle I've ever encountered.)
 */
static char *md5crypt(const char *passwd, const char *magic, const char *salt)
{
    /* "$apr1$..salt..$.......md5hash..........\0" */
    static char out_buf[6 + 9 + 24 + 2];
    unsigned char buf[MD5_DIGEST_LENGTH];
    char *salt_out;
    int n;
    unsigned int i;
    EVP_MD_CTX *md = NULL, *md2 = NULL;
    size_t passwd_len, salt_len, magic_len;

    passwd_len = strlen(passwd);

    out_buf[0] = 0;
    magic_len = strlen(magic);

    if (magic_len > 0) {
        out_buf[0] = '$';
        out_buf[1] = 0;

        if (magic_len > 4)    /* assert it's  "1" or "apr1" */
            return NULL;

        OPENSSL_strlcat(out_buf, magic, sizeof out_buf);
        OPENSSL_strlcat(out_buf, "$", sizeof out_buf);
    }

    OPENSSL_strlcat(out_buf, salt, sizeof out_buf);

    if (strlen(out_buf) > 6 + 8) /* assert "$apr1$..salt.." */
        return NULL;

    salt_out = out_buf;
    if (magic_len > 0)
        salt_out += 2 + magic_len;
    salt_len = strlen(salt_out);

    if (salt_len > 8)
        return NULL;

    md = EVP_MD_CTX_new();
    if (md == NULL
        || !EVP_DigestInit_ex(md, EVP_md5(), NULL)
        || !EVP_DigestUpdate(md, passwd, passwd_len))
        goto err;

    if (magic_len > 0)
        if (!EVP_DigestUpdate(md, "$", 1)
            || !EVP_DigestUpdate(md, magic, magic_len)
            || !EVP_DigestUpdate(md, "$", 1))
          goto err;

    if (!EVP_DigestUpdate(md, salt_out, salt_len))
        goto err;

    md2 = EVP_MD_CTX_new();
    if (md2 == NULL
        || !EVP_DigestInit_ex(md2, EVP_md5(), NULL)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestUpdate(md2, salt_out, salt_len)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestFinal_ex(md2, buf, NULL))
        goto err;

    for (i = passwd_len; i > sizeof buf; i -= sizeof buf) {
        if (!EVP_DigestUpdate(md, buf, sizeof buf))
            goto err;
    }
    if (!EVP_DigestUpdate(md, buf, i))
        goto err;

    n = passwd_len;
    while (n) {
        if (!EVP_DigestUpdate(md, (n & 1) ? "\0" : passwd, 1))
            goto err;
        n >>= 1;
    }
    if (!EVP_DigestFinal_ex(md, buf, NULL))
        return NULL;

    for (i = 0; i < 1000; i++) {
        if (!EVP_DigestInit_ex(md2, EVP_md5(), NULL))
            goto err;
        if (!EVP_DigestUpdate(md2,
                              (i & 1) ? (unsigned const char *)passwd : buf,
                              (i & 1) ? passwd_len : sizeof buf))
            goto err;
        if (i % 3) {
            if (!EVP_DigestUpdate(md2, salt_out, salt_len))
                goto err;
        }
        if (i % 7) {
            if (!EVP_DigestUpdate(md2, passwd, passwd_len))
                goto err;
        }
        if (!EVP_DigestUpdate(md2,
                              (i & 1) ? buf : (unsigned const char *)passwd,
                              (i & 1) ? sizeof buf : passwd_len))
                goto err;
        if (!EVP_DigestFinal_ex(md2, buf, NULL))
                goto err;
    }
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    md2 = NULL;
    md = NULL;

    {
        /* transform buf into output string */
        unsigned char buf_perm[sizeof buf];
        int dest, source;
        char *output;

        /* silly output permutation */
        for (dest = 0, source = 0; dest < 14;
             dest++, source = (source + 6) % 17)
            buf_perm[dest] = buf[source];
        buf_perm[14] = buf[5];
        buf_perm[15] = buf[11];
#  ifndef PEDANTIC              /* Unfortunately, this generates a "no
                                 * effect" warning */
        assert(16 == sizeof buf_perm);
#  endif

        output = salt_out + salt_len;
        assert(output == out_buf + strlen(out_buf));

        *output++ = '$';

        for (i = 0; i < 15; i += 3) {
            *output++ = cov_2char[buf_perm[i + 2] & 0x3f];
            *output++ = cov_2char[((buf_perm[i + 1] & 0xf) << 2) |
                                  (buf_perm[i + 2] >> 6)];
            *output++ = cov_2char[((buf_perm[i] & 3) << 4) |
                                  (buf_perm[i + 1] >> 4)];
            *output++ = cov_2char[buf_perm[i] >> 2];
        }
        assert(i == 15);
        *output++ = cov_2char[buf_perm[i] & 0x3f];
        *output++ = cov_2char[buf_perm[i] >> 6];
        *output = 0;
        assert(strlen(out_buf) < sizeof(out_buf));
    }

    return out_buf;

 err:
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    return NULL;
}
# endif

# ifndef NO_SHACRYPT
/*
 * SHA based password algorithm, describe by Ulrich Drepper here:
 * https://www.akkadia.org/drepper/SHA-crypt.txt
 * (note that it's in the public domain)
 */
static char *shacrypt(const char *passwd, const char *magic, const char *salt)
{
    /* Prefix for optional rounds specification.  */
    static const char rounds_prefix[] = "rounds=";
    /* Maximum salt string length.  */
#  define SALT_LEN_MAX 16
    /* Default number of rounds if not explicitly specified.  */
#  define ROUNDS_DEFAULT 5000
    /* Minimum number of rounds.  */
#  define ROUNDS_MIN 1000
    /* Maximum number of rounds.  */
#  define ROUNDS_MAX 999999999

    /* "$6$rounds=<N>$......salt......$...shahash(up to 86 chars)...\0" */
    static char out_buf[3 + 17 + 17 + 86 + 1];
    unsigned char buf[SHA512_DIGEST_LENGTH];
    unsigned char temp_buf[SHA512_DIGEST_LENGTH];
    size_t buf_size = 0;
    char salt_copy[17];          /* Max 16 chars plus '\0' */
    size_t n;
    EVP_MD_CTX *md = NULL, *md2 = NULL;
    const EVP_MD *sha = NULL;
    size_t passwd_len, salt_len, magic_len;
    unsigned int rounds = 5000;        /* Default */
    char rounds_custom = 0;
    char *p_bytes = NULL;
    char *s_bytes = NULL;
    char *cp = NULL;

    passwd_len = strlen(passwd);
    magic_len = strlen(magic);

    /* assert it's "5" or "6" */
    if (magic_len != 1)
        return NULL;

    switch (magic[0]) {
    case '5':
        sha = EVP_sha256();
        buf_size = 32;
        break;
    case '6':
        sha = EVP_sha512();
        buf_size = 64;
        break;
    default:
        return NULL;
    }

    if (strncmp(salt, rounds_prefix, sizeof(rounds_prefix) - 1) == 0) {
        const char *num = salt + sizeof(rounds_prefix) - 1;
        char *endp;
        unsigned long int srounds = strtoul (num, &endp, 10);
        if (*endp == '$') {
            salt = endp + 1;
            if (srounds > ROUNDS_MAX)
                rounds = ROUNDS_MAX;
            else if (srounds < ROUNDS_MIN)
                rounds = ROUNDS_MIN;
            else
                rounds = (unsigned int)srounds;
            rounds_custom = 1;
        } else {
            return NULL;
        }
    }

    /* The salt gets truncated to 16 chars */
    OPENSSL_strlcpy(salt_copy, salt, sizeof salt_copy);
    salt_len = strlen(salt_copy);

    out_buf[0] = 0;
    OPENSSL_strlcat(out_buf, "$", sizeof out_buf);
    OPENSSL_strlcat(out_buf, magic, sizeof out_buf);
    OPENSSL_strlcat(out_buf, "$", sizeof out_buf);
    if (rounds_custom) {
        char tmp_buf[80]; /* "rounds=999999999" */
        sprintf(tmp_buf, "rounds=%u", rounds);
        OPENSSL_strlcat(out_buf, tmp_buf, sizeof out_buf);
        OPENSSL_strlcat(out_buf, "$", sizeof out_buf);
    }
    OPENSSL_strlcat(out_buf, salt_copy, sizeof out_buf);

    /* assert "$5$rounds=999999999$......salt......" */
    if (strlen(out_buf) > 3 + 17 * rounds_custom + salt_len )
        return NULL;

    md = EVP_MD_CTX_new();
    if (md == NULL
        || !EVP_DigestInit_ex(md, sha, NULL)
        || !EVP_DigestUpdate(md, passwd, passwd_len)
        || !EVP_DigestUpdate(md, salt_copy, salt_len))
        goto err;

    md2 = EVP_MD_CTX_new();
    if (md2 == NULL
        || !EVP_DigestInit_ex(md2, sha, NULL)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestUpdate(md2, salt_copy, salt_len)
        || !EVP_DigestUpdate(md2, passwd, passwd_len)
        || !EVP_DigestFinal_ex(md2, buf, NULL))
        goto err;

    for (n = passwd_len; n > buf_size; n -= buf_size) {
        if (!EVP_DigestUpdate(md, buf, buf_size))
            goto err;
    }
    if (!EVP_DigestUpdate(md, buf, n))
        goto err;

    n = passwd_len;
    while (n) {
        if (!EVP_DigestUpdate(md,
                              (n & 1) ? buf : (unsigned const char *)passwd,
                              (n & 1) ? buf_size : passwd_len))
            goto err;
        n >>= 1;
    }
    if (!EVP_DigestFinal_ex(md, buf, NULL))
        return NULL;

    /* P sequence */
    if (!EVP_DigestInit_ex(md2, sha, NULL))
        goto err;

    for (n = passwd_len; n > 0; n--)
        if (!EVP_DigestUpdate(md2, passwd, passwd_len))
            goto err;

    if (!EVP_DigestFinal_ex(md2, temp_buf, NULL))
        return NULL;

    if ((p_bytes = OPENSSL_zalloc(passwd_len)) == NULL)
        goto err;
    for (cp = p_bytes, n = passwd_len; n > buf_size; n -= buf_size, cp += buf_size)
        memcpy(cp, temp_buf, buf_size);
    memcpy(cp, temp_buf, n);

    /* S sequence */
    if (!EVP_DigestInit_ex(md2, sha, NULL))
        goto err;

    for (n = 16 + buf[0]; n > 0; n--)
        if (!EVP_DigestUpdate(md2, salt, salt_len))
            goto err;

    if (!EVP_DigestFinal_ex(md2, temp_buf, NULL))
        return NULL;

    if ((s_bytes = OPENSSL_zalloc(salt_len)) == NULL)
        goto err;
    for (cp = s_bytes, n = salt_len; n > buf_size; n -= buf_size, cp += buf_size)
        memcpy(cp, temp_buf, buf_size);
    memcpy(cp, temp_buf, n);

    for (n = 0; n < rounds; n++) {
        if (!EVP_DigestInit_ex(md2, sha, NULL))
            goto err;
        if (!EVP_DigestUpdate(md2,
                              (n & 1) ? (unsigned const char *)p_bytes : buf,
                              (n & 1) ? passwd_len : buf_size))
            goto err;
        if (n % 3) {
            if (!EVP_DigestUpdate(md2, s_bytes, salt_len))
                goto err;
        }
        if (n % 7) {
            if (!EVP_DigestUpdate(md2, p_bytes, passwd_len))
                goto err;
        }
        if (!EVP_DigestUpdate(md2,
                              (n & 1) ? buf : (unsigned const char *)p_bytes,
                              (n & 1) ? buf_size : passwd_len))
                goto err;
        if (!EVP_DigestFinal_ex(md2, buf, NULL))
                goto err;
    }
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    md2 = NULL;
    md = NULL;
    OPENSSL_free(p_bytes);
    OPENSSL_free(s_bytes);
    p_bytes = NULL;
    s_bytes = NULL;

    cp = out_buf + strlen(out_buf);
    *cp++ = '$';

#  define b64_from_24bit(B2, B1, B0, N)                                   \
    do {                                                                \
        unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);             \
        int i = (N);                                                    \
        while (i-- > 0)                                                 \
            {                                                           \
                *cp++ = cov_2char[w & 0x3f];                            \
                w >>= 6;                                                \
            }                                                           \
    } while (0)

    switch (*magic) {
    case '5':
        b64_from_24bit (buf[0], buf[10], buf[20], 4);
        b64_from_24bit (buf[21], buf[1], buf[11], 4);
        b64_from_24bit (buf[12], buf[22], buf[2], 4);
        b64_from_24bit (buf[3], buf[13], buf[23], 4);
        b64_from_24bit (buf[24], buf[4], buf[14], 4);
        b64_from_24bit (buf[15], buf[25], buf[5], 4);
        b64_from_24bit (buf[6], buf[16], buf[26], 4);
        b64_from_24bit (buf[27], buf[7], buf[17], 4);
        b64_from_24bit (buf[18], buf[28], buf[8], 4);
        b64_from_24bit (buf[9], buf[19], buf[29], 4);
        b64_from_24bit (0, buf[31], buf[30], 3);
        break;
    case '6':
        b64_from_24bit (buf[0], buf[21], buf[42], 4);
        b64_from_24bit (buf[22], buf[43], buf[1], 4);
        b64_from_24bit (buf[44], buf[2], buf[23], 4);
        b64_from_24bit (buf[3], buf[24], buf[45], 4);
        b64_from_24bit (buf[25], buf[46], buf[4], 4);
        b64_from_24bit (buf[47], buf[5], buf[26], 4);
        b64_from_24bit (buf[6], buf[27], buf[48], 4);
        b64_from_24bit (buf[28], buf[49], buf[7], 4);
        b64_from_24bit (buf[50], buf[8], buf[29], 4);
        b64_from_24bit (buf[9], buf[30], buf[51], 4);
        b64_from_24bit (buf[31], buf[52], buf[10], 4);
        b64_from_24bit (buf[53], buf[11], buf[32], 4);
        b64_from_24bit (buf[12], buf[33], buf[54], 4);
        b64_from_24bit (buf[34], buf[55], buf[13], 4);
        b64_from_24bit (buf[56], buf[14], buf[35], 4);
        b64_from_24bit (buf[15], buf[36], buf[57], 4);
        b64_from_24bit (buf[37], buf[58], buf[16], 4);
        b64_from_24bit (buf[59], buf[17], buf[38], 4);
        b64_from_24bit (buf[18], buf[39], buf[60], 4);
        b64_from_24bit (buf[40], buf[61], buf[19], 4);
        b64_from_24bit (buf[62], buf[20], buf[41], 4);
        b64_from_24bit (0, 0, buf[63], 2);
        break;
    default:
        goto err;
    }
    *cp = '\0';

    return out_buf;

 err:
    EVP_MD_CTX_free(md2);
    EVP_MD_CTX_free(md);
    OPENSSL_free(p_bytes);
    OPENSSL_free(s_bytes);
    return NULL;
}
# endif

static int do_passwd(int passed_salt, char **salt_p, char **salt_malloc_p,
                     char *passwd, BIO *out, int quiet, int table,
                     int reverse, size_t pw_maxlen, passwd_modes mode)
{
    char *hash = NULL;

    assert(salt_p != NULL);
    assert(salt_malloc_p != NULL);

    /* first make sure we have a salt */
    if (!passed_salt) {
# ifndef OPENSSL_NO_DES
        if (mode == passwd_crypt) {
            if (*salt_malloc_p == NULL)
                *salt_p = *salt_malloc_p = app_malloc(3, "salt buffer");
            if (RAND_bytes((unsigned char *)*salt_p, 2) <= 0)
                goto end;
            (*salt_p)[0] = cov_2char[(*salt_p)[0] & 0x3f]; /* 6 bits */
            (*salt_p)[1] = cov_2char[(*salt_p)[1] & 0x3f]; /* 6 bits */
            (*salt_p)[2] = 0;
#  ifdef CHARSET_EBCDIC
            ascii2ebcdic(*salt_p, *salt_p, 2); /* des_crypt will convert back
                                                * to ASCII */
#  endif
        }
# endif                         /* !OPENSSL_NO_DES */

# ifndef NO_MD5CRYPT_1
        if (mode == passwd_md5 || mode == passwd_apr1 || mode == passwd_aixmd5) {
            int i;

            if (*salt_malloc_p == NULL)
                *salt_p = *salt_malloc_p = app_malloc(9, "salt buffer");
            if (RAND_bytes((unsigned char *)*salt_p, 8) <= 0)
                goto end;

            for (i = 0; i < 8; i++)
                (*salt_p)[i] = cov_2char[(*salt_p)[i] & 0x3f]; /* 6 bits */
            (*salt_p)[8] = 0;
        }
# endif                         /* !NO_MD5CRYPT_1 */

# ifndef NO_SHACRYPT
        if (mode == passwd_sha256 || mode == passwd_sha512) {
            int i;

            if (*salt_malloc_p == NULL)
                *salt_p = *salt_malloc_p = app_malloc(17, "salt buffer");
            if (RAND_bytes((unsigned char *)*salt_p, 16) <= 0)
                goto end;

            for (i = 0; i < 16; i++)
                (*salt_p)[i] = cov_2char[(*salt_p)[i] & 0x3f]; /* 6 bits */
            (*salt_p)[16] = 0;
        }
# endif                         /* !NO_SHACRYPT */
    }

    assert(*salt_p != NULL);

    /* truncate password if necessary */
    if ((strlen(passwd) > pw_maxlen)) {
        if (!quiet)
            /*
             * XXX: really we should know how to print a size_t, not cast it
             */
            BIO_printf(bio_err,
                       "Warning: truncating password to %u characters\n",
                       (unsigned)pw_maxlen);
        passwd[pw_maxlen] = 0;
    }
    assert(strlen(passwd) <= pw_maxlen);

    /* now compute password hash */
# ifndef OPENSSL_NO_DES
    if (mode == passwd_crypt)
        hash = DES_crypt(passwd, *salt_p);
# endif
# ifndef NO_MD5CRYPT_1
    if (mode == passwd_md5 || mode == passwd_apr1)
        hash = md5crypt(passwd, (mode == passwd_md5 ? "1" : "apr1"), *salt_p);
    if (mode == passwd_aixmd5)
        hash = md5crypt(passwd, "", *salt_p);
# endif
# ifndef NO_SHACRYPT
    if (mode == passwd_sha256 || mode == passwd_sha512)
        hash = shacrypt(passwd, (mode == passwd_sha256 ? "5" : "6"), *salt_p);
# endif
    assert(hash != NULL);

    if (table && !reverse)
        BIO_printf(out, "%s\t%s\n", passwd, hash);
    else if (table && reverse)
        BIO_printf(out, "%s\t%s\n", hash, passwd);
    else
        BIO_printf(out, "%s\n", hash);
    return 1;

 end:
    return 0;
}
#else

int passwd_main(int argc, char **argv)
{
    BIO_printf(bio_err, "Program not available.\n");
    return (1);
}
#endif
