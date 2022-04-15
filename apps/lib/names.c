/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <locale.h>
#include <openssl/bio.h>
#include <openssl/safestack.h>
#include "names.h"

#ifdef _WIN32
# define strcasecmp_l(a,b,c) _stricmp(a,b)
#endif

int name_cmp(const char * const *a, const char * const *b)
{
    static locale_t c_locale = LC_GLOBAL_LOCALE;
    if (c_locale == LC_GLOBAL_LOCALE)
        c_locale = newlocale(LC_CTYPE_MASK, "C", 0);

    return strcasecmp_l(*a, *b, c_locale);
}

void collect_names(const char *name, void *vdata)
{
    STACK_OF(OPENSSL_CSTRING) *names = vdata;

    sk_OPENSSL_CSTRING_push(names, name);
}

void print_names(BIO *out, STACK_OF(OPENSSL_CSTRING) *names)
{
    int i = sk_OPENSSL_CSTRING_num(names);
    int j;

    sk_OPENSSL_CSTRING_sort(names);
    if (i > 1)
        BIO_printf(out, "{ ");
    for (j = 0; j < i; j++) {
        const char *name = sk_OPENSSL_CSTRING_value(names, j);

        if (j > 0)
            BIO_printf(out, ", ");
        BIO_printf(out, "%s", name);
    }
    if (i > 1)
        BIO_printf(out, " }");
}
