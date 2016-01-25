/*
 * Written by Matt Caswell (matt@openssl.org) for the OpenSSL project.
 */
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
 */

/* This must be the first #include file */
#include "../async_locl.h"

#ifdef ASYNC_POSIX

# include <stddef.h>
# include <unistd.h>

pthread_key_t posixctx;
pthread_key_t posixpool;

#define STACKSIZE       32768

int async_global_init(void)
{
    if (pthread_key_create(&posixctx, NULL) != 0
            || pthread_key_create(&posixpool, NULL) != 0)
        return 0;

    return 1;
}

void async_local_cleanup(void)
{
}

void async_global_cleanup(void)
{
}

int async_fibre_makecontext(async_fibre *fibre)
{
    fibre->env_init = 0;
    if (getcontext(&fibre->fibre) == 0) {
        fibre->fibre.uc_stack.ss_sp = OPENSSL_malloc(STACKSIZE);
        if (fibre->fibre.uc_stack.ss_sp != NULL) {
            fibre->fibre.uc_stack.ss_size = STACKSIZE;
            fibre->fibre.uc_link = NULL;
            makecontext(&fibre->fibre, async_start_func, 0);
            return 1;
        }
    } else {
        fibre->fibre.uc_stack.ss_sp = NULL;
    }
    return 0;
}

void async_fibre_free(async_fibre *fibre)
{
    OPENSSL_free(fibre->fibre.uc_stack.ss_sp);
    fibre->fibre.uc_stack.ss_sp = NULL;
}

#endif
