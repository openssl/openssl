/* crypto/async/arch/async_posix.h */
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
#include <openssl/e_os2.h>

#ifdef OPENSSL_SYS_UNIX

# include <unistd.h>

# if _POSIX_VERSION >= 200112L

#  define ASYNC_POSIX
#  define ASYNC_ARCH

/*
 * Some platforms complain (e.g. OS-X) that setcontext/getcontext/makecontext
 * are deprecated without the following defined. We know its deprecated but
 * there is no alternative.
 */
#  define _XOPEN_SOURCE
#  pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#  include <ucontext.h>
#  include <setjmp.h>
#  include "e_os.h"

extern __thread async_ctx *posixctx;
extern __thread async_pool *posixpool;

typedef struct async_fibre_st {
    ucontext_t fibre;
    jmp_buf env;
    int env_init;
} async_fibre;

#  define async_set_ctx(nctx)             (posixctx = (nctx))
#  define async_get_ctx()                 (posixctx)
#  define async_set_pool(p)               (posixpool = (p))
#  define async_get_pool()                (posixpool)

static inline int async_fibre_swapcontext(async_fibre *o, async_fibre *n, int r)
{
    o->env_init = 1;

    if (!r || !_setjmp(o->env)) {
        if (n->env_init)
            _longjmp(n->env, 1);
        else
            setcontext(&n->fibre);
    }

    return 1;
}

#  define async_fibre_makecontext(c) \
            (!getcontext(&(c)->fibre) \
            && async_fibre_init(c) \
            && (makecontext(&(c)->fibre, async_start_func, 0), 1))
#  define async_fibre_init_dispatcher(d)

int async_fibre_init(async_fibre *fibre);
void async_fibre_free(async_fibre *fibre);

# endif
#endif
