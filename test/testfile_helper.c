/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <ctype.h>
#include <openssl/crypto.h>
#include "testfile_helper.h"


const char *stanza_find_attr(const STANZA *s, const char *key)
{
    const PAIR *pp = s->pairs;
    int i = s->numpairs;

    for ( ; --i >= 0; pp++)
        if (strcasecmp(pp->key, key) == 0)
            return pp->value;
    return NULL;
}

int stanza_type(const STANZA *sp, const char **list)
{
    int i;

    for (i = 0; list[i]; ++i) {
        if (stanza_find_attr(sp, list[i]) != NULL)
            return i;
    }
    return -1;
}

#if 0
static int parsedecbn(BIGNUM **out, const char *in)
{
    *out = NULL;
    return BN_dec2bn(out, in);
}
#endif

BIGNUM *stanza_get_bignum(STANZA *s, const char *attribute)
{
    const char *hex;
    BIGNUM *ret = NULL;

    if ((hex = stanza_find_attr(s, attribute)) == NULL) {
        fprintf(stderr, "Can't find %s in test at line %d\n",
                attribute, s->start);
        return NULL;
    }

    if (BN_hex2bn(&ret, hex) != (int)strlen(hex)) {
        fprintf(stderr, "Could not decode '%s'.\n", hex);
        return NULL;
    }
    return ret;
}

int stanza_get_bin(const STANZA *sp, const char *attribute,
                   unsigned char **buf, size_t *buflen)
{
    return 0;
}

int stanza_get_int(STANZA *s, const char *attribute, int *out)
{
    BIGNUM *ret = stanza_get_bignum(s, attribute);
    BN_ULONG word;
    int st = 0;

    if (ret == NULL)
        goto err;

    if ((word = BN_get_word(ret)) > INT_MAX)
        goto err;

    *out = (int)word;
    st = 1;
err:
    BN_free(ret);
    return st;
}

/* Skip leading whitespace. */
static char *skip_spaces(char *p)
{
    while (*p && isspace(*p))
        p++;
    return p;
}

/* Delete leading and trailing spaces from a string */
static char *trim_spaces(char *p)
{
    char *q;

    /* Skip over leading spaces */
    p = skip_spaces(p);
    if (*p == '\0')
        return NULL;

    /* Back up over trailing spaces. */
    for (q = p + strlen(p) - 1; q != p && isspace(*q); )
        *q-- = '\0';
    return *p ? p : NULL;
}


/* Free list of stanza's. */
void stanza_free_all(STANZA *sp)
{

    while (sp != NULL) {
        PAIR *pp = sp->pairs;
        int i = sp->numpairs;
        STANZA *next = sp->next;

        for ( ; --i >= 0; pp++) {
            OPENSSL_free(pp->key);
            OPENSSL_free(pp->value);
        }
        OPENSSL_free(sp->name);
        OPENSSL_free(sp);
        sp = next;
    }
}

STANZA *stanza_parse_file(const char *file)
{
    FILE *fp = fopen(file, "r");
    STANZA *sz;

    if (fp == NULL) {
        perror(file);
        fprintf(stderr, "Can't open for input\n");
        exit(EXIT_FAILURE);
    }
    sz = stanza_parse_fp(fp);
    fclose(fp);
    return sz;
}

/*
 * Return a copy of next logical line. If line ends with \ it is continued
 * on the next line.  Returns an allocated copy, or NULL on error.
 */
static char *read_line(FILE *fp, int *lineno)
{
    char buff[1024];
    char *line = NULL, *p, *copy;
    size_t linelen = 0;
    size_t frag;

    for ( ; ; ) {
        if (fgets(buff, sizeof(buff), fp) == NULL || feof(fp))
            break;
        (*lineno)++;
        if ((p = strchr(buff, '\n')) == NULL) {
            fprintf(stderr, "Line %d too long.\n", *lineno);
            break;
        }
        *p = '\0';
        frag = p - buff;

        /* Append the physical line. */
        copy = OPENSSL_realloc(line, linelen + frag + 1);
        if (copy == NULL) {
            fprintf(stderr, "Out of memory at line %d\n", *lineno);
            break;
        }
        line = copy;
        strcpy(&line[linelen], buff);
        linelen += strlen(buff);

        if (p == buff || p[-1] != '\\')
            return line;
        line[--linelen] = '\0';
    }

    /* Failed; clean up and return. */
    free(line);
    return NULL;
}

/* Decode %xx URL-decoding in-place; return 0 on failure. */
static int urldecode(char *p)
{
    char *out = p;

    for (; *p; p++) {
        if (*p != '%')
            *out++ = *p;
        else if (isxdigit(p[1]) && isxdigit(p[2])) {
            /* Don't check, can't fail because of ixdigit() call. */
            *out++ = (OPENSSL_hexchar2int(p[1]) << 4)
                   | OPENSSL_hexchar2int(p[2]);
            p += 2;
        }
        else
            return 0;
    }
    *out = '\0';
    return 1;
}

STANZA *stanza_parse_fp(FILE *fp)
{
    STANZA *sp = NULL, *save = NULL;
    PAIR *pp;
    char *line, *equals, *key, *value;
    int encoded, comment, lineno = 0;
    size_t len;

    /* Skip any prolog. */
    for ( ; ; ) {
        line = read_line(fp, &lineno);
        if (line == NULL) {
            fprintf(stderr, "Empty file.\n");
            return NULL;
        }
        if (line[0] == '#' || line[0] == '\0') {
            OPENSSL_free(line);
            continue;
        }
        break;
    }

    save = sp = (STANZA *)OPENSSL_zalloc(sizeof(*sp));
    sp->start = lineno;
    for ( ; ; ) {
        /* Name? */
        if (line[0] == '[') {
            OPENSSL_free(sp->name);
            sp->name = OPENSSL_strdup(line + 1);
            if ((equals = strrchr(sp->name, ']')) != NULL)
                *equals = '\0';
        } else {
            /* Add a key/value pair line. */
            encoded = 0;
            if ((equals = strchr(line, '~')) != NULL)
                encoded++;
            else if ((equals = strchr(line, '=')) == NULL) {
                fprintf(stderr, "Line %d missing equals.\n", sp->start);
                return save;
            }
            *equals++ = '\0';

            key = trim_spaces(line);
            value = skip_spaces(equals);
            if (*value == '"') {
                value++;
                len = strlen(value);
                if (len < 2 || value[--len] != '"') {
                    fprintf(stderr, "Line %d missing close quote.\n", sp->start);
                    return save;
                }
                value[len] = '\0';
            }

            if (key == NULL || value == NULL) {
                fprintf(stderr, "Line %d missing field.\n", sp->start);
                return save;
            }
            pp = &sp->pairs[sp->numpairs++];
            if (sp->numpairs >= MAXPAIRS) {
                fprintf(stderr, "Line %d too many lines\n", sp->start);
                return save;
            }
            pp->key = OPENSSL_strdup(key);
            pp->value = OPENSSL_strdup(value);
            OPENSSL_free(line);
            if (encoded && !urldecode(pp->value)) {
                fprintf(stderr, "Line %d bad URL encoding\n", lineno);
                return save;
            }
        }

        /* Blank or comment? Mark end of stanza, eat all such lines. */
        for (comment = 0; ; ) {
            line = read_line(fp, &lineno);
            if (line == NULL)
                break;
            if (line[0] == '#' || line[0] == '\0') {
                OPENSSL_free(line);
                comment++;
                continue;
            }
            break;
        }
        if (line == NULL)
            break;
        if (comment) {
            /*  If we had a comment/blank, start new stanza. */
            sp->next = (STANZA *)OPENSSL_zalloc(sizeof(*sp));
            sp = sp->next;
            sp->start = lineno;
        }
    }

    /* If we read anything, return ok. */
    return save;
}
