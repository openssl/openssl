/* Written by Ben Laurie <ben@algroup.co.uk> August 2001 */
/* ====================================================================
 * Copyright (c) 2000-2001 The OpenSSL Project.  All rights reserved.
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
 *    licensing@OpenSSL.org.
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

#include <openssl/engine.h>
#include <openssl/evp.h>
#include "eng_int.h"
#include <string.h>

int ENGINE_add_cipher(ENGINE *e,const EVP_CIPHER *c)
    {
    ENGINE_EVP_CIPHER *p;

    p=OPENSSL_malloc(sizeof *p);
    p->cipher=c;

    if(!e->ciphers)
	e->ciphers=sk_ENGINE_EVP_CIPHER_new_null();
    sk_ENGINE_EVP_CIPHER_push(e->ciphers,p);

    return 1;
    }

void ENGINE_free_engine_cipher(ENGINE_EVP_CIPHER *p)
    { OPENSSL_free(p); }

int ENGINE_cipher_num(const ENGINE *e)
    { return sk_ENGINE_EVP_CIPHER_num(e->ciphers); }

const EVP_CIPHER *ENGINE_get_cipher(const ENGINE *e, int n)
    { return sk_ENGINE_EVP_CIPHER_value(e->ciphers, n)->cipher; }

void ENGINE_load_ciphers()
    {
    ENGINE *e;

    for(e=ENGINE_get_first() ; e ; e=ENGINE_get_next(e))
	ENGINE_load_engine_ciphers(e);
    }
	
void ENGINE_load_engine_ciphers(ENGINE *e)
    {
    int n;

    for(n=0 ; n < sk_ENGINE_EVP_CIPHER_num(e->ciphers) ; ++n)
	EVP_add_cipher(sk_ENGINE_EVP_CIPHER_value(e->ciphers,n)->cipher);
    }

const EVP_CIPHER *ENGINE_get_cipher_by_name(ENGINE *e,const char *name)
    {
    int n;

    for(n=0 ; n < ENGINE_cipher_num(e) ; ++n)
	{
	const EVP_CIPHER *c=ENGINE_get_cipher(e,n);

	if(!strcmp(EVP_CIPHER_name(c),name))
	    return c;
	}
    return NULL;
    }
