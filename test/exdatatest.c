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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/crypto.h>

static long sargl;
static void *sargp;
static int sidx;

static void exnew(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
          int idx, long argl, void *argp)
{
    assert(idx == sidx);
    assert(argl == sargl);
    assert(argp == sargp);
}

static int exdup(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from,
          void *from_d, int idx, long argl, void *argp)
{
    assert(idx == sidx);
    assert(argl == sargl);
    assert(argp == sargp);
    return 0;
}

static void exfree(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
            int idx, long argl, void *argp)
{
    assert(idx == sidx);
    assert(argl == sargl);
    assert(argp == sargp);
}

typedef struct myobj_st {
    CRYPTO_EX_DATA ex_data;
    int id;
} MYOBJ;

static MYOBJ *MYOBJ_new()
{
    static int count = 0;
    MYOBJ *obj = OPENSSL_malloc(sizeof(*obj));
    int st;

    obj->id = ++count;
    st = CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, obj, &obj->ex_data);
    assert(st != 0);
    return obj;
}

static void MYOBJ_sethello(MYOBJ *obj, char *cp)
{
    int st;

    st = CRYPTO_set_ex_data(&obj->ex_data, sidx, cp);
    assert(st != 0);
}

static char *MYOBJ_gethello(MYOBJ *obj)
{
    return CRYPTO_get_ex_data(&obj->ex_data, sidx);
}

static void MYOBJ_free(MYOBJ *obj)
{
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, obj, &obj->ex_data);
    OPENSSL_free(obj);
}

int main()
{
    MYOBJ *t1, *t2;
    const char *cp;
    char *p;

    p = strdup("hello world");
    sargl = 21;
    sargp = malloc(1);
    sidx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, sargl, sargp,
                                   exnew, exdup, exfree);
    t1 = MYOBJ_new();
    t2 = MYOBJ_new();
    MYOBJ_sethello(t1, p);
    cp = MYOBJ_gethello(t1);
    assert(cp == p);
    cp = MYOBJ_gethello(t2);
    assert(cp == NULL);
    MYOBJ_free(t1);
    MYOBJ_free(t2);
    free(sargp);
    free(p);
    return 0;
}
