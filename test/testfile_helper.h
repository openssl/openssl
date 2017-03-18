/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef TESTFILE_HELPER_H
#define TESTFILE_HELPER_H

# include <stdio.h>
# include <openssl/bn.h>

/*
 * Utilities to parse a test file.  Tests inputs are grouped into stanza's,
 * which are sets of lines separated by a blank line or comment (starts
 * with a #).  Except for dividing tests, comments and blank lines are
 * ignored.
 *
 * A line ending with a backslash means the next line is joined to it; the
 * backslask and newline charactesr are removed.
 *
 * A stanze may start with a test name in square brackets.
 * Lines look like this:
 *      key = value
 * where value (after any line-joining) may be surrounded by
 * double-quotes.
 *
 * The following four entries are equivalent:
 *      pem =          asdf
 *      pem = "asdf"
 *      pem = a\
 *      sdf
 *      pem = "asd\
 *      f"
 *
 * Leading and trailing whitespace is stripped from value. To preserve them,
 * put quotes around it.  Leading and trailing whitespace is also stripped
 * from the key.
 *
 * To use URL-encoded values (%% for % and %xx for hex value), use a
 * tilde instead of the equal sign.
 */

/*
 * A key->value mapping.
 */
typedef struct pair_st {
    char *key;
    char *value;
} PAIR;

/*
 * A stanza has a starting linenumber and a set of key/value pairs.
 */
# define MAXPAIRS        20
typedef struct stanza_st STANZA;
struct stanza_st {
    char *name;
    int start;
    int numpairs;
    PAIR pairs[MAXPAIRS];
    STANZA *next;
};

/*
 * Parse a test file, return NULL terminated list of stanzas or NULL on
 * error (with error message on stderr).
 */
STANZA *stanza_parse_fp(FILE *fp);

/*
 * Like stanza_parse_fp() but exits on error.
 */
STANZA *stanza_parse_file(const char *file);

/*
 * Free all stanza's in a list
 */
void stanza_free_all(STANZA *sp);

/*
 * Look for one of a set of attributes in a stanza and return its
 * index into |list| if found, or -1 if not found. This is useful
 * when the type of test to run is implied by what attributes are
 * in the stanza.  |list| is a NULL terminated.
 */
int stanza_type(const STANZA *sp, const char **list);

/*
 * Look for |key| in the stanza and return its value or NULL if not found.
 */
const char *stanza_find_attr(const STANZA *sp, const char *key);

/*
 * Parse named |attribute| as a BIGNUM, return it or NULL on error
 * (and error message to stderr).
 */
BIGNUM *stanza_get_bignum(STANZA *s, const char *attribute);

/*
 * Parse named |attribute| as an int, and put value in |out|. Return 1
 * if okay, or 0 (and error message to stderr) on error.
 */
int stanza_get_int(STANZA *s, const char *attribute, int *out);

#endif
