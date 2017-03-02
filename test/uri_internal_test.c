/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/safestack.h>

#include "internal/uri.h"

#include "e_os.h"

struct test_data_st {
    int good;
    char *uri;
    struct {
        char *scheme;
        int decoded_scheme;
        char *authority;
        int decoded_authority;
        char *path;
        int decoded_path;
        char *query;
        int decoded_query;
        char *fragment;
        int decoded_fragment;
        char *user;
        int decoded_user;
        char *password;
        int decoded_password;
        char *host;
        int decoded_host;
        char *service;
        int decoded_service;
    } expected;
};
typedef struct test_data_st TEST_DATA;

static void free_test_data(TEST_DATA *test_data)
{
    if (test_data == NULL)
        return;
    OPENSSL_free(test_data->uri);
    OPENSSL_free(test_data->expected.scheme);
    OPENSSL_free(test_data->expected.authority);
    OPENSSL_free(test_data->expected.path);
    OPENSSL_free(test_data->expected.query);
    OPENSSL_free(test_data->expected.fragment);
    OPENSSL_free(test_data->expected.user);
    OPENSSL_free(test_data->expected.password);
    OPENSSL_free(test_data->expected.host);
    OPENSSL_free(test_data->expected.service);
    OPENSSL_free(test_data);
}

static int parse_key_value(const char *line, char **key, char **value)
{
    size_t off = 0;

    while(*line != '\n' && isspace(*line))
        line++;

    off = 0;
    while(line[off] != '\n' && !isspace(line[off]) && line[off] != '=')
        off++;

    if ((*key = OPENSSL_strndup(line, off)) == NULL)
        return 0;

    line += off;
    while(*line != '\n' && isspace(*line))
        line++;

    if (line[0] != '=') {
        OPENSSL_free(*key);
        return 0;
    }
    line++;
    while(*line != '\n' && isspace(*line))
        line++;

    off = strlen(line);
    while(off > 0 && isspace(line[off - 1]))
        off--;

    if ((*value = OPENSSL_strndup(line, off)) == NULL) {
        OPENSSL_free(*key);
        return 0;
    }

    return 1;
}

/*
 * read_test_data() reads exactly one valid stanza and returns the parsed data
 */
static int linecounter = 0;
static TEST_DATA *read_test_data(FILE *f)
{
    TEST_DATA *test_data = NULL;
    int errcount = 0;
    int skip_stanza = 0;

    while (1) {
        char line[2048], *p = NULL, *key = NULL, *value = NULL;

        if (fgets(line, sizeof(line), f) == NULL) {
            if (ferror(f)) {
                perror("reading tests");
                free_test_data(test_data);
                test_data = NULL;
            }
            break;
        }

        linecounter++;

        for (p = line; *p != '\n' && isspace(*p); p++)
            continue;

        if (*p == '\n') {
            /*
             * If test_data is non-NULL, it means we're done reading a stanza,
             * time to return to caller.
             */
            if (test_data != NULL)
                break;
            skip_stanza = 0;
            continue;
        }
        if (*p == '#')
            continue;

        if (!parse_key_value(p, &key, &value)) {
            fprintf(stderr, "Invalid line %d: %s\n", linecounter, line);
            errcount++;
            skip_stanza = 1;
            free_test_data(test_data);
            test_data = NULL;
        }

        if (skip_stanza)
            continue;

#define PROCESS_URI(__good)                                             \
        do {                                                            \
            if (test_data == NULL) {                                    \
                test_data = OPENSSL_zalloc(sizeof(*test_data));         \
                test_data->uri = value;                                 \
                test_data->good = (__good);                             \
            } else {                                                    \
                fprintf(stderr, "Duplicate URI at line %d\n", linecounter); \
                errcount++;                                             \
                skip_stanza = 1;                                        \
                free_test_data(test_data);                              \
                test_data = NULL;                                       \
                OPENSSL_free(value);                                    \
            }                                                           \
        } while (0)
#define CHECK_KEY(__key)                                 \
        (strcasecmp(key, #__key) == 0                    \
         || strcasecmp(key, "decoded_" #__key) == 0)
#define PROCESS_KEY(__key,__key_uc)                                     \
        do {                                                            \
            if (test_data != NULL && test_data->expected.__key == NULL) { \
                test_data->expected.__key = value;                      \
                test_data->expected.decoded_ ## __key = *key == 'd';    \
            } else {                                                    \
                if (test_data == NULL) {                                \
                    fprintf(stderr,                                     \
                            "Stanza didn't start with URI at line %d\n", \
                            linecounter);                               \
                } else {                                                \
                    fprintf(stderr, "Duplicate " #__key_uc " at line %d\n", \
                            linecounter);                               \
                }                                                       \
                errcount++;                                             \
                skip_stanza = 1;                                        \
                free_test_data(test_data);                              \
                test_data = NULL;                                       \
                OPENSSL_free(value);                                    \
            }                                                           \
        } while (0)

        if (strcasecmp(key, "uri") == 0) {
            PROCESS_URI(1);
        } else if (strcasecmp(key, "baduri") == 0) {
            PROCESS_URI(0);
        } else if (CHECK_KEY(scheme)) {
            PROCESS_KEY(scheme,SCHEME);
        } else if (CHECK_KEY(authority)) {
            PROCESS_KEY(authority,AUTHORITY);
        } else if (CHECK_KEY(path)) {
            PROCESS_KEY(path,PATH);
        } else if (CHECK_KEY(query)) {
            PROCESS_KEY(query,QUERY);
        } else if (CHECK_KEY(fragment)) {
            PROCESS_KEY(fragment,FRAGMENT);
        } else if (CHECK_KEY(user)) {
            PROCESS_KEY(user,USER);
        } else if (CHECK_KEY(password)) {
            PROCESS_KEY(password,PASSWORD);
        } else if (CHECK_KEY(host)) {
            PROCESS_KEY(host,HOST);
        } else if (CHECK_KEY(service)) {
            PROCESS_KEY(service,SERVICE);
        } else {
            fprintf(stderr, "Invalid line %d: %s\n", linecounter, line);
            errcount++;
            skip_stanza = 1;
            free_test_data(test_data);
            test_data = NULL;
            OPENSSL_free(value);
        }
        OPENSSL_free(key);
    }

    return test_data;
}

static int cmp(const char *a, const char *b)
{
    if (a != NULL && b != NULL)
        return strcmp(a, b);
    if (a == NULL && b == NULL)
        return 0;
    if (a == NULL)
        return -1;
    return 1;
}
static int testnum = 0;
static int run_test(TEST_DATA *test_data)
{
    int errcount = 0;
    char *scheme = NULL, *authority = NULL, *path = NULL, *query = NULL,
        *fragment = NULL;
    char *user = NULL, *password = NULL, *host = NULL, *service = NULL;
    int rv = OPENSSL_decode_uri(test_data->uri, &scheme, &authority, &path,
                                &query, &fragment)
        && (authority == NULL
            || OPENSSL_decode_authority(authority, &user, &password, &host,
                                        &service));

    testnum++;
    if ((test_data->good && !rv) || (!test_data->good && rv)) {
        errcount++;
        fprintf(stderr, "Failed test %d (expected %s, got %s)\n",
                testnum, test_data->good ? "good" : "bad",
                rv ? "good" : "bad");
        if (!rv) {
            ERR_print_errors_fp(stderr);
            goto err;
        }
    }
    ERR_clear_error();
    rv = (!test_data->expected.decoded_scheme
          || OPENSSL_percent_decode_inline(scheme))
        && (!test_data->expected.decoded_authority
            || OPENSSL_percent_decode_inline(authority))
        && (!test_data->expected.decoded_path
            || OPENSSL_percent_decode_inline(path))
        && (!test_data->expected.decoded_query
            || OPENSSL_percent_decode_inline(query))
        && (!test_data->expected.decoded_fragment
            || OPENSSL_percent_decode_inline(fragment))
        && (!test_data->expected.decoded_user
            || OPENSSL_percent_decode_inline(user))
        && (!test_data->expected.decoded_password
            || OPENSSL_percent_decode_inline(password))
        && (!test_data->expected.decoded_host
            || OPENSSL_percent_decode_inline(host))
        && (!test_data->expected.decoded_service
            || OPENSSL_percent_decode_inline(service));
    if (!rv) {
        ERR_print_errors_fp(stderr);
        errcount++;
        goto err;
    }
    rv = (cmp(scheme, test_data->expected.scheme) == 0
          && cmp(authority, test_data->expected.authority) == 0
          && cmp(path, test_data->expected.path) == 0
          && cmp(query, test_data->expected.query) == 0
          && cmp(fragment, test_data->expected.fragment) == 0
          && cmp(user, test_data->expected.user) == 0
          && cmp(password, test_data->expected.password) == 0
          && cmp(host, test_data->expected.host) == 0
          && cmp(service, test_data->expected.service) == 0);
    if (!rv) {
        errcount++;
        fprintf(stderr, "Test %d got unexpected result:\n", testnum);
        fprintf(stderr, "  %s    = '%s'\n",
                test_data->good ? "uri   " : "baduri", test_data->uri);
        fprintf(stderr, "  scheme    = '%s' (expected '%s')\n", scheme,
                test_data->expected.scheme);
        fprintf(stderr, "  authority = '%s' (expected '%s')\n", authority,
                test_data->expected.authority);
        fprintf(stderr, "  path      = '%s' (expected '%s')\n", path,
                test_data->expected.path);
        fprintf(stderr, "  query     = '%s' (expected '%s')\n", query,
                test_data->expected.query);
        fprintf(stderr, "  fragment  = '%s' (expected '%s')\n", fragment,
                test_data->expected.fragment);
        fprintf(stderr, "  user      = '%s' (expected '%s')\n", user,
                test_data->expected.user);
        fprintf(stderr, "  password  = '%s' (expected '%s')\n", password,
                test_data->expected.password);
        fprintf(stderr, "  host      = '%s' (expected '%s')\n", host,
                test_data->expected.host);
        fprintf(stderr, "  service   = '%s' (expected '%s')\n", service,
                test_data->expected.service);
    } else {
        fprintf(stderr, "Test %d OK\n", testnum);
        fprintf(stderr, "  %s    = '%s'\n",
                test_data->good ? "uri   " : "baduri", test_data->uri);
        if (scheme || test_data->expected.scheme)
            fprintf(stderr, "  scheme    = '%s' (expected '%s')\n", scheme,
                    test_data->expected.scheme);
        if (authority || test_data->expected.authority)
            fprintf(stderr, "  authority = '%s' (expected '%s')\n",
                    authority, test_data->expected.authority);
        if (path || test_data->expected.path)
            fprintf(stderr, "  path      = '%s' (expected '%s')\n", path,
                    test_data->expected.path);
        if (query || test_data->expected.query)
            fprintf(stderr, "  query     = '%s' (expected '%s')\n", query,
                    test_data->expected.query);
        if (fragment || test_data->expected.fragment)
            fprintf(stderr, "  fragment  = '%s' (expected '%s')\n",
                    fragment, test_data->expected.fragment);
        if (user || test_data->expected.user)
            fprintf(stderr, "  user      = '%s' (expected '%s')\n",
                    user, test_data->expected.user);
        if (password || test_data->expected.password)
            fprintf(stderr, "  password  = '%s' (expected '%s')\n",
                    password, test_data->expected.password);
        if (host || test_data->expected.host)
            fprintf(stderr, "  host      = '%s' (expected '%s')\n",
                    host, test_data->expected.host);
        if (service || test_data->expected.service)
            fprintf(stderr, "  service   = '%s' (expected '%s')\n",
                    service, test_data->expected.service);
    }
 err:
    ERR_clear_error();
    OPENSSL_free(scheme);
    OPENSSL_free(authority);
    OPENSSL_free(path);
    OPENSSL_free(query);
    OPENSSL_free(fragment);
    OPENSSL_free(user);
    OPENSSL_free(password);
    OPENSSL_free(host);
    OPENSSL_free(service);

    return errcount;
}

int main(int argc, char *argv[])
{
    FILE *f;
    TEST_DATA *test_data = NULL;
    int errs = 0;

    if (argc != 2) {
        fprintf(stderr, "%s TESTFILE\n", argv[0]);
        exit(1);
    }

    f = fopen(argv[1], "r");
    if (f == NULL) {
        perror(argv[0]);
        exit(1);
    }

    while (!feof(f) && (test_data = read_test_data(f)) != NULL) {
        errs += run_test(test_data);
        free_test_data(test_data);
    }

    fclose(f);

    exit(errs);
}
