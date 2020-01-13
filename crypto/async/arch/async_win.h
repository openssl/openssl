/*
 * Copyright 2015-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*
 * This is the same detection used in cryptlib to set up the thread local
 * storage that we depend on, so just copy that
 */
#if defined(_WIN32) && !defined(OPENtls_NO_ASYNC)
#include <opentls/async.h>
# define ASYNC_WIN
# define ASYNC_ARCH

# include <windows.h>
# include "internal/cryptlib.h"

typedef struct async_fibre_st {
    LPVOID fibre;
    int converted;
} async_fibre;

# define async_fibre_swapcontext(o,n,r) \
        (SwitchToFiber((n)->fibre), 1)
# define async_fibre_makecontext(c) \
        ((c)->fibre = CreateFiber(0, async_start_func_win, 0))
# define async_fibre_free(f)             (DeleteFiber((f)->fibre))

int async_fibre_init_dispatcher(async_fibre *fibre);
VOID CALLBACK async_start_func_win(PVOID unused);

#endif
