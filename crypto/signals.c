/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <string.h>

#include <openssl/crypto.h>
#include <internal/list.h>

struct sigentry {
    CRYPTO_SIGNAL p;
    struct list list;
};

static struct list siglist;

static ossl_inline int siglist_sigeq(struct list *l, void *data);

static ossl_inline int siglist_sigeq(struct list *l, void *data)
{
    return container_of(l, struct sigentry, list)->p.signal == *(long*)data;
}

#if defined(OPENSSL_SYS_WINDOWS) || defined(_WIN32) || defined(__CYGWIN__)

# include <windows.h>

volatile PHANDLER_ROUTINE callback_handler = NULL;

static BOOL WINAPI CRYPTO_SIGNAL_handler(DWORD dwType)
{
    if (list_empty(&siglist))
        return FALSE;

    struct list *l;
    if ((l = list_find(&siglist, siglist_sigeq, (void*)&dwType)) == NULL)
        return FALSE;

    container_of(l, struct sigentry, list)->p.callback(dwType);
    return TRUE;
}

static int CRYPTO_SIGNAL_arch_enable()
{
    callback_handler = (PHANDLER_ROUTINE) CRYPTO_SIGNAL_handler;
    if (SetConsoleCtrlHandler(callback_handler, TRUE) == 0)
        return 0;
    return 1;
}

static int CRYPTO_SIGNAL_arch_disable()
{
    if (SetConsoleCtrlHandler(callback_handler, FALSE) == 0) {
        callback_handler = NULL;
        return 0;
    }
    return 1;
}

static int CRYPTO_SIGNAL_block_arch(CRYPTO_SIGNAL *p)
{
    return 1;
}

#elif defined(OPENSSL_SYS_UNIX) || defined (__unix__) || \
      (defined (__APPLE__) && defined (__MACH__))

# include <sys/types.h>
# include <unistd.h>
# include <signal.h>

static int CRYPTO_SIGNAL_arch_enable(void)
{
    return 1;
}

static int CRYPTO_SIGNAL_arch_disable(void)
{
    return 1;
}

/**
 * signal specifies which signal to (un)block/(un)mask
 * callback is one of:
 *     NULL, SIG_DFL   restores default signal handling
 *     SIG_IGN         blocks signal (if possible)
 *     void (*)(int)   masks signal and calls a callback upon receive
 */
static int CRYPTO_SIGNAL_block_arch(CRYPTO_SIGNAL *p)
{
    int how;
    sigset_t sigs;
    struct sigaction sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = p->callback;

    if (sigemptyset (&sa.sa_mask) != 0)
        goto fail;

    if (sigaction((int)p->signal, &sa, NULL) != 0)
        goto fail;

    if (p->callback == NULL || p->callback == SIG_DFL)
        how = SIG_UNBLOCK;
    else if (p->callback == SIG_IGN)
        how = SIG_BLOCK;
    else
        how = SIG_SETMASK;

    if (p->callback == SIG_IGN) {
        if (sigemptyset(&sigs) != 0 || sigaddset(&sigs, (int)p->signal) != 0)
            goto fail;
        if (sigprocmask(how, &sigs, NULL) != 0)
            goto fail;
    }

    return 1;

fail:
    if (p->callback != NULL) {
        p->callback = SIG_DFL;
        CRYPTO_SIGNAL_block(p);
    }
    return 0;
}

#else

static int CRYPTO_SIGNAL_arch_enable()
{
    return 0;
}

static int CRYPTO_SIGNAL_arch_disable()
{
    return 0;
}

static int CRYPTO_SIGNAL_block_arch(CRYPTO_SIGNAL *p)
{
    return 0;
}

#endif

int CRYPTO_SIGNAL_block(CRYPTO_SIGNAL *p)
{
    struct sigentry *s = NULL;

    if (siglist.prev == NULL || siglist.next == NULL)
        list_init(&siglist);

    if (list_empty(&siglist)) {
        if (p->callback == NULL)
            return 1;
        else if (CRYPTO_SIGNAL_arch_enable() == 0)
            return 0;
    } else {
        struct list *l;
        if ((l = list_find(&siglist, siglist_sigeq, (void*)&p->signal)) != NULL)
            s = container_of(l, struct sigentry, list);
    }

    if (s && p->callback == NULL) {
        list_del(&s->list);
        OPENSSL_free(s);
        if (list_empty(&siglist) && CRYPTO_SIGNAL_arch_disable() == 0)
            return 0;
        return 1;
    }

    s = (struct sigentry*) OPENSSL_malloc(sizeof(*s));
    list_add_tail(&s->list, &siglist);

    s->p.callback = p->callback;
    s->p.signal = p->signal;
    if (CRYPTO_SIGNAL_block_arch(p) == 0)
        return 0;

    return 1;
}

int CRYPTO_SIGNAL_block_set(CRYPTO_SIGNAL** props)
{
    int r;
    CRYPTO_SIGNAL** props_iter;
    for (props_iter = props; *props_iter != NULL; ++props_iter) {
        r = CRYPTO_SIGNAL_block(*props_iter);
        if (r != 1)
            goto fail;
    }

    return 1;

fail:
    for (; props_iter != props; --props_iter) {
        CRYPTO_SIGNAL tmp;

        tmp.signal = (*props_iter)->signal;
        tmp.callback = NULL;

        if (CRYPTO_SIGNAL_block(&tmp) != 1)
            goto fail;
    }
    return 0;
}

int CRYPTO_SIGNAL_unblock_all()
{
    struct list *iter;
    struct sigentry * e;
    if (siglist.prev == NULL || siglist.next == NULL)
        return 0;
    list_for_each(iter, &siglist) {
        e = container_of(iter, struct sigentry, list);
        e->p.callback = NULL;
        if (CRYPTO_SIGNAL_block(&e->p) == 0)
            return 0;
    }
    return 1;
}
