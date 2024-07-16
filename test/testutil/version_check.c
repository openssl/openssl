/*
 * Copyright 20243 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../testutil.h"
#include <ctype.h>
#include <openssl/opensslv.h>

int version_match(const char *versions)
{
    const char *p;
    int major, minor, patch, r;
    enum {
        MODE_EQ, MODE_NE, MODE_LE, MODE_LT, MODE_GT, MODE_GE
    } mode;

    while (*versions != '\0') {
        for (; isspace((unsigned char)(*versions)); versions++)
            continue;
        if (*versions == '\0')
            break;
        for (p = versions; *versions != '\0' && !isspace((unsigned char)(*versions)); versions++)
            continue;
        if (*p == '!') {
            mode = MODE_NE;
            p++;
        } else if (*p == '=') {
            mode = MODE_EQ;
            p++;
        } else if (*p == '<' && p[1] == '=') {
            mode = MODE_LE;
            p += 2;
        } else if (*p == '>' && p[1] == '=') {
            mode = MODE_GE;
            p += 2;
        } else if (*p == '<') {
            mode = MODE_LT;
            p++;
        } else if (*p == '>') {
            mode = MODE_GT;
            p++;
        } else if (isdigit((unsigned char)*p)) {
            mode = MODE_EQ;
        } else {
            TEST_info("Error matching OpenSSL version: mode %s\n", p);
            return -1;
        }
        if (sscanf(p, "%d.%d.%d", &major, &minor, &patch) != 3) {
            TEST_info("Error matching OpenSSL version: version %s\n", p);
            return -1;
        }
        switch (mode) {
        case MODE_EQ:
            r = OPENSSL_VERSION_MAJOR == major
                && OPENSSL_VERSION_MINOR == minor
                && OPENSSL_VERSION_PATCH == patch;
            break;
        case MODE_NE:
            r = OPENSSL_VERSION_MAJOR != major
                || OPENSSL_VERSION_MINOR != minor
                || OPENSSL_VERSION_PATCH != patch;
            break;
        case MODE_LE:
            r = OPENSSL_VERSION_MAJOR < major
                || (OPENSSL_VERSION_MAJOR == major
                    && (OPENSSL_VERSION_MINOR < minor
                        || (OPENSSL_VERSION_MINOR == minor
                            && OPENSSL_VERSION_PATCH <= patch)));
            break;
        case MODE_LT:
            r = OPENSSL_VERSION_MAJOR < major
                || (OPENSSL_VERSION_MAJOR == major
                    && (OPENSSL_VERSION_MINOR < minor
                        || (OPENSSL_VERSION_MINOR == minor
                            && OPENSSL_VERSION_PATCH < patch)));
            break;
        case MODE_GT:
            r = OPENSSL_VERSION_MAJOR > major
                || (OPENSSL_VERSION_MAJOR == major
                    && (OPENSSL_VERSION_MINOR > minor
                        || (OPENSSL_VERSION_MINOR == minor
                            && OPENSSL_VERSION_PATCH > patch)));
            break;
        case MODE_GE:
            r = OPENSSL_VERSION_MAJOR > major
                || (OPENSSL_VERSION_MAJOR == major
                    && (OPENSSL_VERSION_MINOR > minor
                        || (OPENSSL_VERSION_MINOR == minor
                            && OPENSSL_VERSION_PATCH >= patch)));
            break;
        }
        if (r == 0)
            return 0;
    }
    return 1;
}
