/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
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
 *    openssl-core@OpenSSL.org.
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

#include "bio_lcl.h"

BIO_METHOD *BIO_meth_new(int type, const char *name)
{
    BIO_METHOD *biom = OPENSSL_zalloc(sizeof(BIO_METHOD));

    if (biom != NULL) {
        biom->type = type;
        biom->name = name;
    }
    return biom;
}

void BIO_meth_free(BIO_METHOD *biom)
{
    OPENSSL_free(biom);
}

int (*BIO_meth_get_write(BIO_METHOD *biom)) (BIO *, const char *, int)
{
    return biom->bwrite;
}

int BIO_meth_set_write(BIO_METHOD *biom,
                       int (*bwrite) (BIO *, const char *, int))
{
    biom->bwrite = bwrite;
    return 1;
}

int (*BIO_meth_get_read(BIO_METHOD *biom)) (BIO *, char *, int)
{
    return biom->bread;
}

int BIO_meth_set_read(BIO_METHOD *biom,
                      int (*bread) (BIO *, char *, int))
{
    biom->bread = bread;
    return 1;
}

int (*BIO_meth_get_puts(BIO_METHOD *biom)) (BIO *, const char *)
{
    return biom->bputs;
}

int BIO_meth_set_puts(BIO_METHOD *biom,
                      int (*bputs) (BIO *, const char *))
{
    biom->bputs = bputs;
    return 1;
}

int (*BIO_meth_get_gets(BIO_METHOD *biom)) (BIO *, char *, int)
{
    return biom->bgets;
}

int BIO_meth_set_gets(BIO_METHOD *biom,
                      int (*bgets) (BIO *, char *, int))
{
    biom->bgets = bgets;
    return 1;
}

long (*BIO_meth_get_ctrl(BIO_METHOD *biom)) (BIO *, int, long, void *)
{
    return biom->ctrl;
}

int BIO_meth_set_ctrl(BIO_METHOD *biom,
                      long (*ctrl) (BIO *, int, long, void *))
{
    biom->ctrl = ctrl;
    return 1;
}

int (*BIO_meth_get_create(BIO_METHOD *biom)) (BIO *)
{
    return biom->create;
}

int BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *))
{
    biom->create = create;
    return 1;
}

int (*BIO_meth_get_destroy(BIO_METHOD *biom)) (BIO *)
{
    return biom->destroy;
}

int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *))
{
    biom->destroy = destroy;
    return 1;
}

long (*BIO_meth_get_callback_ctrl(BIO_METHOD *biom)) (BIO *, int, bio_info_cb *)
{
    return biom->callback_ctrl;
}

int BIO_meth_set_callback_ctrl(BIO_METHOD *biom,
                               long (*callback_ctrl) (BIO *, int,
                                                      bio_info_cb *))
{
    biom->callback_ctrl = callback_ctrl;
    return 1;
}
