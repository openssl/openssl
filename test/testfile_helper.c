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

#define KWOTE(c)        (c == '"' || c == '\'')

char *stanza_get_string(STANZA *s, const char *attribute)
{
    const char *value = stanza_find_attr(s, attribute);
    char *ret;
    size_t len;
    char first;

    if (value == NULL) {
        fprintf(stderr, "Can't find %s in test at line %d\n",
                attribute, s->start);
        return NULL;
    }
    first = value[0];
    ret = KWOTE(first) ? OPENSSL_strdup(value + 1) : OPENSSL_strdup(value);
    if (ret == NULL)
        return NULL;
    if (KWOTE(first)) {
        len = strlen(ret);
        if (len < 2 || ret[--len] != first) {
            fprintf(stderr, "Line %d missing close quote.\n", s->start);
            OPENSSL_free(ret);
            return NULL;
        }
        ret[len] = '\0';
    }
    return ret;
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

char *stanza_get_urlstring(STANZA *s, const char *attribute)
{
    char *value = stanza_get_string(s, attribute);

    if (value == NULL) {
        fprintf(stderr, "Can't find %s in test at line %d\n",
                attribute, s->start);
        return NULL;
    }
    if (!urldecode(value)) {
        fprintf(stderr, "Bad url decode for %s int est at line %d\n",
                attribute, s->start);
        OPENSSL_free(value);
        return NULL;
    }
    return value;
}

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

/*
 * Delete leading and trailing spaces from a string; return NULL for a
 * blank line.
 */
static char *trim_spaces(char *p)
{
    char *q;

    /* Skip over leading spaces */
    while (*p && isspace(*p))
        p++;
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
    char buff[1024], *line = NULL, *p, *copy;
    size_t linelen = 0, frag;
    int more;

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

        /* Continuation line? */
        more = p > buff && p[-1] == '\\';
        if (more) {
            /* See if it ends with \\ and turn first \ into a newline. */
            *--p = '\0';
            if (p > buff && p[-1] == '\\')
                p[-1] = '\n';
        }

        /* Append the physical line. */
        copy = OPENSSL_realloc(line, linelen + frag + 1);
        if (copy == NULL) {
            fprintf(stderr, "Out of memory at line %d\n", *lineno);
            break;
        }
        line = copy;
        strcpy(&line[linelen], buff);
        linelen += strlen(buff);

        /* Continuation line? */
        if (!more)
            return line;
    }

    /* Failed; clean up and return. */
    free(line);
    return NULL;
}

STANZA *stanza_parse_fp(FILE *fp)
{
    STANZA *sp = NULL, *save = NULL;
    PAIR *pp;
    char *line, *equals, *key, *value;
    int comment, lineno = 0;

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
            if ((equals = strchr(line, '=')) == NULL) {
                fprintf(stderr, "Line %d missing equals.\n", sp->start);
                return save;
            }
            *equals++ = '\0';

            key = trim_spaces(line);
            value = trim_spaces(equals);

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
