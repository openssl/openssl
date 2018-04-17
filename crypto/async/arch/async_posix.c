/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This must be the first #include file */
#include "../async_locl.h"

#ifdef ASYNC_POSIX

# include <stddef.h>
# include <string.h>
# include <unistd.h>
# include <sys/mman.h>

# define STACKSIZE     32768
# ifndef PAGE_SIZE
#  define PAGE_SIZE    4096
# endif

int ASYNC_is_capable(void)
{
    ucontext_t ctx;

    /*
     * Some platforms provide getcontext() but it does not work (notably
     * MacOSX PPC64). Check for a working getcontext();
     */
    return getcontext(&ctx) == 0;
}

void async_local_cleanup(void)
{
}

int async_fibre_makecontext(async_fibre *fibre)
{
    size_t pagesize;
    size_t stackallocsize;
    size_t stacksize = STACKSIZE;
    char *stackallocaddr = NULL;

# if defined(_SC_PAGE_SIZE) || defined (_SC_PAGESIZE)
    {
#  if defined(_SC_PAGE_SIZE)
        long tmppgsize = sysconf(_SC_PAGE_SIZE);
#  else
        long tmppgsize = sysconf(_SC_PAGESIZE);
#  endif
        if (tmppgsize < 1)
            pagesize = PAGE_SIZE;
        else
            pagesize = (size_t)tmppgsize;
    }
# else
    pagesize = PAGE_SIZE;
# endif
    if (pagesize > stacksize)
        stacksize = pagesize;

    stackallocsize = stacksize + 2 * pagesize;

    fibre->env_init = 0;
    if (getcontext(&fibre->fibre) == 0) {
        if (posix_memalign((void **)&stackallocaddr,
                           pagesize,
                           stackallocsize) == 0) {
            fibre->fibre.uc_stack.ss_sp = stackallocaddr + pagesize;
            fibre->fibre.uc_stack.ss_size = stacksize;
            fibre->fibre.uc_link = NULL;
            /* Make a best effort to create guard pages, lock the
               stack into memory and prevent it getting dumped
               on a core dump. */
            mprotect(stackallocaddr,
                     pagesize,
                     PROT_NONE);
            mprotect(stackallocaddr + pagesize + stacksize,
                     pagesize,
                     PROT_NONE);
            mlock(fibre->fibre.uc_stack.ss_sp, stacksize);
# ifdef MADV_DONTDUMP
            madvise(fibre->fibre.uc_stack.ss_sp, stacksize, MADV_DONTDUMP);
# endif
            makecontext(&fibre->fibre, async_start_func, 0);
            return 1;
        }
    }
    fibre->fibre.uc_stack.ss_sp = NULL;
    return 0;
}

void async_fibre_free(async_fibre *fibre)
{
    size_t pagesize;
    size_t stacksize = fibre->fibre.uc_stack.ss_size;
    char *stackallocaddr = NULL;

# if defined(_SC_PAGE_SIZE) || defined (_SC_PAGESIZE)
    {
#  if defined(_SC_PAGE_SIZE)
        long tmppgsize = sysconf(_SC_PAGE_SIZE);
#  else
        long tmppgsize = sysconf(_SC_PAGESIZE);
#  endif
        if (tmppgsize < 1)
            pagesize = PAGE_SIZE;
        else
            pagesize = (size_t)tmppgsize;
    }
# else
    pagesize = PAGE_SIZE;
# endif

    if (fibre->fibre.uc_stack.ss_sp) {
        stackallocaddr = (char *)fibre->fibre.uc_stack.ss_sp - pagesize;
        /* Make a best effort to reverse the stack setup and guard pages.
           Purposely not checking return values as there is nothing we
           can do if they fail. */
        madvise(fibre->fibre.uc_stack.ss_sp, stacksize, MADV_NORMAL);
        munlock(fibre->fibre.uc_stack.ss_sp, stacksize);
        mprotect(stackallocaddr,
                 pagesize,
                 PROT_READ|PROT_WRITE);
        mprotect(stackallocaddr + pagesize + stacksize,
                 pagesize,
                 PROT_READ|PROT_WRITE);
        free(stackallocaddr);
        fibre->fibre.uc_stack.ss_sp = NULL;
    }
}

#endif
