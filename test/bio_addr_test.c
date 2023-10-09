/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include "internal/e_os.h"
#include "internal/sockets.h"
#include "testutil.h"

static int families[] = {
    AF_INET,
#if OPENSSL_USE_IPV6
    AF_INET6,
#endif
#ifndef OPENSSL_NO_UNIX_SOCK
    AF_UNIX
#endif
};

static BIO_ADDR *make_dummy_addr(int family)
{
    BIO_ADDR *addr;
    union {
        struct sockaddr_in sin;
#if OPENSSL_USE_IPV6
        struct sockaddr_in6 sin6;
#endif
#ifndef OPENSSL_NO_UNIX_SOCK
        struct sockaddr_un sunaddr;
#endif
    } sa;
    void *where;
    size_t wherelen;

    /* Fill with a dummy address */
    switch(family) {
    case AF_INET:
        where = &(sa.sin.sin_addr);
        wherelen = sizeof(sa.sin.sin_addr);
        break;
#if OPENSSL_USE_IPV6
    case AF_INET6:
        where = &(sa.sin6.sin6_addr);
        wherelen = sizeof(sa.sin6.sin6_addr);
        break;
#endif
#ifndef OPENSSL_NO_UNIX_SOCK
    case AF_UNIX:
        where = &(sa.sunaddr.sun_path);
        /* BIO_ADDR_rawmake needs an extra byte for a NUL-terminator*/
        wherelen = sizeof(sa.sunaddr.sun_path) - 1;
        break;
#endif
    default:
        TEST_error("Unsupported address family");
        return 0;
    }
    /*
     * Could be any data, but we make it printable because BIO_ADDR_rawmake
     * expects the AF_UNIX address to be a string.
     */
    memset(where, 'a', wherelen);

    addr = BIO_ADDR_new();
    if (!TEST_ptr(addr))
        return NULL;

    if (!TEST_true(BIO_ADDR_rawmake(addr, family, where, wherelen, 1000))) {
        BIO_ADDR_free(addr);
        return NULL;
    }

    return addr;
}

static int bio_addr_is_eq(const BIO_ADDR *a, const BIO_ADDR *b)
{
    void *adata = NULL, *bdata = NULL;
    size_t alen, blen;
    int ret;

    /* True even if a and b are NULL */
    if (a == b)
        return 1;

    /* If one is NULL the other cannot be due to the test above */
    if (a == NULL || b == NULL)
        return 0;

    if (BIO_ADDR_family(a) != BIO_ADDR_family(b))
        return 0;

    /* Works even with AF_UNIX/AF_UNSPEC which just returns 0 */
    if (BIO_ADDR_rawport(a) != BIO_ADDR_rawport(b))
        return 0;

    /*
     * BIO_ADDR_sockaddr_size() reliable returns the size of the underlying
     * socket structure, or if the AF family is unspecified, the size of the
     * BIO_ADDR structure.  Either way, it's an appropriate buffer size to
     * use with BIO_ADDR_rawaddress().
     */
    alen = BIO_ADDR_sockaddr_size(a);
    blen = BIO_ADDR_sockaddr_size(b);

    if (alen != blen)
        return 0;

    adata = OPENSSL_zalloc(alen);
    bdata = OPENSSL_zalloc(blen);

    ret = 0;
    if (adata == NULL || bdata == NULL)
        goto end;

    if (!BIO_ADDR_rawaddress(a, adata, &alen))
        goto end;

    if (!BIO_ADDR_rawaddress(a, bdata, &blen))
        goto end;

    if (alen != blen)
        goto end;

    if (alen == 0)
        ret = 1;
    else
        ret = memcmp(adata, bdata, alen) == 0;
 end:
    OPENSSL_free(adata);
    OPENSSL_free(bdata);
    return ret;
}

static int test_bio_addr_copy_dup(int idx)
{
    BIO_ADDR *src = NULL, *dst = NULL;
    int ret = 0;
    int docopy = idx & 1;

    idx >>= 1;

    src = make_dummy_addr(families[idx]);
    if (!TEST_ptr(src))
        return 0;

    if (docopy) {
        dst = BIO_ADDR_new();
        if (!TEST_ptr(dst))
            goto err;

        if (!TEST_true(BIO_ADDR_copy(dst, src)))
            goto err;
    } else {
        dst = BIO_ADDR_dup(src);
        if (!TEST_ptr(dst))
            goto err;
    }

    if (!TEST_true(bio_addr_is_eq(src, dst)))
        goto err;

    ret = 1;
 err:
    BIO_ADDR_free(src);
    BIO_ADDR_free(dst);
    return ret;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    ADD_ALL_TESTS(test_bio_addr_copy_dup, OSSL_NELEM(families) * 2);
    return 1;
}
