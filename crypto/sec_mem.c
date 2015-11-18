/*
 * Copyright 2004-2014, Akamai Technologies. All Rights Reserved.
 * This file is distributed under the terms of the OpenSSL license.
 */

/*
 * This file is in two halves. The first half implements the public API
 * to be used by external consumers, and to be used by OpenSSL to store
 * data in a "secure arena." The second half implements the secure arena.
 * For details on that implementation, see below (look for uppercase
 * "SECURE HEAP IMPLEMENTATION").
 */
#include <openssl/crypto.h>
#include <e_os.h>

#if defined(OPENSSL_SYS_LINUX) || defined(OPENSSL_SYS_UNIX)
# define IMPLEMENTED
# include <stdlib.h>
# include <string.h>
# include <assert.h>
# include <unistd.h>
# include <sys/types.h>
# include <sys/mman.h>
# include <sys/param.h>
# include <sys/stat.h>
# include <fcntl.h>
#endif

#define LOCK()      CRYPTO_w_lock(CRYPTO_LOCK_MALLOC)
#define UNLOCK()    CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC)
#define CLEAR(p, s) OPENSSL_cleanse(p, s)
#ifndef PAGE_SIZE
# define PAGE_SIZE    4096
#endif

#ifdef IMPLEMENTED
static size_t secure_mem_used;

static int secure_mem_initialized;
static int too_late;

/*
 * These are the functions that must be implemented by a secure heap (sh).
 */
static int sh_init(size_t size, int minsize);
static char *sh_malloc(size_t size);
static void sh_free(char *ptr);
static void sh_done(void);
static int sh_actual_size(char *ptr);
static int sh_allocated(const char *ptr);
#endif

int CRYPTO_secure_malloc_init(size_t size, int minsize)
{
#ifdef IMPLEMENTED
    int ret = 0;

    if (too_late)
        return ret;
    LOCK();
    OPENSSL_assert(!secure_mem_initialized);
    if (!secure_mem_initialized) {
        ret = sh_init(size, minsize);
        secure_mem_initialized = 1;
    }
    UNLOCK();
    return ret;
#else
    return 0;
#endif /* IMPLEMENTED */
}

void CRYPTO_secure_malloc_done()
{
#ifdef IMPLEMENTED
    LOCK();
    sh_done();
    secure_mem_initialized = 0;
    UNLOCK();
#endif /* IMPLEMENTED */
}

int CRYPTO_secure_malloc_initialized()
{
#ifdef IMPLEMENTED
    return secure_mem_initialized;
#else
    return 0;
#endif /* IMPLEMENTED */
}

void *CRYPTO_secure_malloc(int num, const char *file, int line)
{
#ifdef IMPLEMENTED
    void *ret;
    size_t actual_size;

    if (!secure_mem_initialized) {
        too_late = 1;
        return CRYPTO_malloc(num, file, line);
    }
    LOCK();
    ret = sh_malloc(num);
    actual_size = ret ? sh_actual_size(ret) : 0;
    secure_mem_used += actual_size;
    UNLOCK();
    return ret;
#else
    return CRYPTO_malloc(num, file, line);
#endif /* IMPLEMENTED */
}

void CRYPTO_secure_free(void *ptr)
{
#ifdef IMPLEMENTED
    size_t actual_size;

    if (ptr == NULL)
        return;
    if (!secure_mem_initialized) {
        CRYPTO_free(ptr);
        return;
    }
    LOCK();
    actual_size = sh_actual_size(ptr);
    CLEAR(ptr, actual_size);
    secure_mem_used -= actual_size;
    sh_free(ptr);
    UNLOCK();
#else
    CRYPTO_free(ptr);
#endif /* IMPLEMENTED */
}

int CRYPTO_secure_allocated(const void *ptr)
{
#ifdef IMPLEMENTED
    int ret;

    if (!secure_mem_initialized)
        return 0;
    LOCK();
    ret = sh_allocated(ptr);
    UNLOCK();
    return ret;
#else
    return 0;
#endif /* IMPLEMENTED */
}

/* END OF PAGE ...

   ... START OF PAGE */

/*
 * SECURE HEAP IMPLEMENTATION
 */
#ifdef IMPLEMENTED


/*
 * The implementation provided here uses a fixed-sized mmap() heap,
 * which is locked into memory, not written to core files, and protected
 * on either side by an unmapped page, which will catch pointer overruns
 * (or underruns) and an attempt to read data out of the secure heap.
 * Free'd memory is zero'd or otherwise cleansed.
 *
 * This is a pretty standard buddy allocator.  We keep areas in a multiple
 * of "sh.minsize" units.  The freelist and bitmaps are kept separately,
 * so all (and only) data is kept in the mmap'd heap.
 *
 * This code assumes eight-bit bytes.  The numbers 3 and 7 are all over the
 * place.
 */

# define TESTBIT(t, b)  (t[(b) >> 3] &  (1 << ((b) & 7)))
# define SETBIT(t, b)   (t[(b) >> 3] |= (1 << ((b) & 7)))
# define CLEARBIT(t, b) (t[(b) >> 3] &= (0xFF & ~(1 << ((b) & 7))))

#define WITHIN_ARENA(p) \
    ((char*)(p) >= sh.arena && (char*)(p) < &sh.arena[sh.arena_size])
#define WITHIN_FREELIST(p) \
    ((char*)(p) >= (char*)sh.freelist && (char*)(p) < (char*)&sh.freelist[sh.freelist_size])


typedef struct sh_list_st
{
    struct sh_list_st *next;
    struct sh_list_st **p_next;
} SH_LIST;

typedef struct sh_st
{
    char* map_result;
    size_t map_size;
    char *arena;
    int arena_size;
    char **freelist;
    int freelist_size;
    int minsize;
    unsigned char *bittable;
    unsigned char *bitmalloc;
    int bittable_size; /* size in bits */
} SH;

static SH sh;

static int sh_getlist(char *ptr)
{
    int list = sh.freelist_size - 1;
    int bit = (sh.arena_size + ptr - sh.arena) / sh.minsize;

    for (; bit; bit >>= 1, list--) {
        if (TESTBIT(sh.bittable, bit))
            break;
        OPENSSL_assert((bit & 1) == 0);
    }

    return list;
}


static int sh_testbit(char *ptr, int list, unsigned char *table)
{
    int bit;

    OPENSSL_assert(list >= 0 && list < sh.freelist_size);
    OPENSSL_assert(((ptr - sh.arena) & ((sh.arena_size >> list) - 1)) == 0);
    bit = (1 << list) + ((ptr - sh.arena) / (sh.arena_size >> list));
    OPENSSL_assert(bit > 0 && bit < sh.bittable_size);
    return TESTBIT(table, bit);
}

static void sh_clearbit(char *ptr, int list, unsigned char *table)
{
    int bit;

    OPENSSL_assert(list >= 0 && list < sh.freelist_size);
    OPENSSL_assert(((ptr - sh.arena) & ((sh.arena_size >> list) - 1)) == 0);
    bit = (1 << list) + ((ptr - sh.arena) / (sh.arena_size >> list));
    OPENSSL_assert(bit > 0 && bit < sh.bittable_size);
    OPENSSL_assert(TESTBIT(table, bit));
    CLEARBIT(table, bit);
}

static void sh_setbit(char *ptr, int list, unsigned char *table)
{
    int bit;

    OPENSSL_assert(list >= 0 && list < sh.freelist_size);
    OPENSSL_assert(((ptr - sh.arena) & ((sh.arena_size >> list) - 1)) == 0);
    bit = (1 << list) + ((ptr - sh.arena) / (sh.arena_size >> list));
    OPENSSL_assert(bit > 0 && bit < sh.bittable_size);
    OPENSSL_assert(!TESTBIT(table, bit));
    SETBIT(table, bit);
}

static void sh_add_to_list(char **list, char *ptr)
{
    SH_LIST *temp;

    OPENSSL_assert(WITHIN_FREELIST(list));
    OPENSSL_assert(WITHIN_ARENA(ptr));

    temp = (SH_LIST *)ptr;
    temp->next = *(SH_LIST **)list;
    OPENSSL_assert(temp->next == NULL || WITHIN_ARENA(temp->next));
    temp->p_next = (SH_LIST **)list;

    if (temp->next != NULL) {
        OPENSSL_assert((char **)temp->next->p_next == list);
        temp->next->p_next = &(temp->next);
    }

    *list = ptr;
}

static void sh_remove_from_list(char *ptr, char *list)
{
    SH_LIST *temp, *temp2;

    temp = (SH_LIST *)ptr;
    if (temp->next != NULL)
        temp->next->p_next = temp->p_next;
    *temp->p_next = temp->next;
    if (temp->next == NULL)
        return;

    temp2 = temp->next;
    OPENSSL_assert(WITHIN_FREELIST(temp2->p_next) || WITHIN_ARENA(temp2->p_next));
}


static int sh_init(size_t size, int minsize)
{
    int i, ret;
    size_t pgsize;
    size_t aligned;

    memset(&sh, 0, sizeof sh);

    /* make sure size and minsize are powers of 2 */
    OPENSSL_assert(size > 0);
    OPENSSL_assert((size & (size - 1)) == 0);
    OPENSSL_assert(minsize > 0);
    OPENSSL_assert((minsize & (minsize - 1)) == 0);
    if (size <= 0 || (size & (size - 1)) != 0)
        goto err;
    if (minsize <= 0 || (minsize & (minsize - 1)) != 0)
        goto err;

    sh.arena_size = size;
    sh.minsize = minsize;
    sh.bittable_size = (sh.arena_size / sh.minsize) * 2;

    sh.freelist_size = -1;
    for (i = sh.bittable_size; i; i >>= 1)
        sh.freelist_size++;

    sh.freelist = OPENSSL_zalloc(sh.freelist_size * sizeof (char *));
    OPENSSL_assert(sh.freelist != NULL);
    if (sh.freelist == NULL)
        goto err;

    sh.bittable = OPENSSL_zalloc(sh.bittable_size >> 3);
    OPENSSL_assert(sh.bittable != NULL);
    if (sh.bittable == NULL)
        goto err;

    sh.bitmalloc = OPENSSL_zalloc(sh.bittable_size >> 3);
    OPENSSL_assert(sh.bitmalloc != NULL);
    if (sh.bitmalloc == NULL)
        goto err;

    /* Allocate space for heap, and two extra pages as guards */
#if defined(_SC_PAGE_SIZE) || defined (_SC_PAGESIZE)
    {
# if defined(_SC_PAGE_SIZE)
        long tmppgsize = sysconf(_SC_PAGE_SIZE);
# else
        long tmppgsize = sysconf(_SC_PAGESIZE);
# endif
        if (tmppgsize < 1)
            pgsize = PAGE_SIZE;
        else
            pgsize = (size_t)tmppgsize;
    }
#else
    pgsize = PAGE_SIZE;
#endif
    sh.map_size = pgsize + sh.arena_size + pgsize;
    if (1) {
#ifdef MAP_ANON
        sh.map_result = mmap(NULL, sh.map_size,
                             PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    } else {
#endif
        int fd;

        sh.map_result = MAP_FAILED;
        if ((fd = open("/dev/zero", O_RDWR)) >= 0) {
            sh.map_result = mmap(NULL, sh.map_size,
                                 PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
            close(fd);
        }
    }
    OPENSSL_assert(sh.map_result != MAP_FAILED);
    if (sh.map_result == MAP_FAILED)
        goto err;
    sh.arena = (char *)(sh.map_result + pgsize);
    sh_setbit(sh.arena, 0, sh.bittable);
    sh_add_to_list(&sh.freelist[0], sh.arena);

    /* Now try to add guard pages and lock into memory. */
    ret = 1;

    /* Starting guard is already aligned from mmap. */
    if (mprotect(sh.map_result, pgsize, PROT_NONE) < 0)
        ret = 2;

    /* Ending guard page - need to round up to page boundary */
    aligned = (pgsize + sh.arena_size + (pgsize - 1)) & ~(pgsize - 1);
    if (mprotect(sh.map_result + aligned, pgsize, PROT_NONE) < 0)
        ret = 2;

    if (mlock(sh.arena, sh.arena_size) < 0)
        ret = 2;
#ifdef MADV_DONTDUMP
    if (madvise(sh.arena, sh.arena_size, MADV_DONTDUMP) < 0)
        ret = 2;
#endif

    return ret;

 err:
    sh_done();
    return 0;
}

static void sh_done()
{
    OPENSSL_free(sh.freelist);
    OPENSSL_free(sh.bittable);
    OPENSSL_free(sh.bitmalloc);
    if (sh.map_result != NULL && sh.map_size)
        munmap(sh.map_result, sh.map_size);
    memset(&sh, 0, sizeof sh);
}

static int sh_allocated(const char *ptr)
{
    return WITHIN_ARENA(ptr) ? 1 : 0;
}

static char *sh_find_my_buddy(char *ptr, int list)
{
    int bit;
    char *chunk = NULL;

    bit = (1 << list) + (ptr - sh.arena) / (sh.arena_size >> list);
    bit ^= 1;

    if (TESTBIT(sh.bittable, bit) && !TESTBIT(sh.bitmalloc, bit))
        chunk = sh.arena + ((bit & ((1 << list) - 1)) * (sh.arena_size >> list));

    return chunk;
}

static char *sh_malloc(size_t size)
{
    int list, slist;
    size_t i;
    char *chunk;

    list = sh.freelist_size - 1;
    for (i = sh.minsize; i < size; i <<= 1)
        list--;
    if (list < 0)
        return NULL;

    /* try to find a larger entry to split */
    for (slist = list; slist >= 0; slist--)
        if (sh.freelist[slist] != NULL)
            break;
    if (slist < 0)
        return NULL;

    /* split larger entry */
    while (slist != list) {
        char *temp = sh.freelist[slist];

        /* remove from bigger list */
        OPENSSL_assert(!sh_testbit(temp, slist, sh.bitmalloc));
        sh_clearbit(temp, slist, sh.bittable);
        sh_remove_from_list(temp, sh.freelist[slist]);
        OPENSSL_assert(temp != sh.freelist[slist]);

        /* done with bigger list */
        slist++;

        /* add to smaller list */
        OPENSSL_assert(!sh_testbit(temp, slist, sh.bitmalloc));
        sh_setbit(temp, slist, sh.bittable);
        sh_add_to_list(&sh.freelist[slist], temp);
        OPENSSL_assert(sh.freelist[slist] == temp);

        /* split in 2 */
        temp += sh.arena_size >> slist;
        OPENSSL_assert(!sh_testbit(temp, slist, sh.bitmalloc));
        sh_setbit(temp, slist, sh.bittable);
        sh_add_to_list(&sh.freelist[slist], temp);
        OPENSSL_assert(sh.freelist[slist] == temp);

        OPENSSL_assert(temp-(sh.arena_size >> slist) == sh_find_my_buddy(temp, slist));
    }

    /* peel off memory to hand back */
    chunk = sh.freelist[list];
    OPENSSL_assert(sh_testbit(chunk, list, sh.bittable));
    sh_setbit(chunk, list, sh.bitmalloc);
    sh_remove_from_list(chunk, sh.freelist[list]);

    OPENSSL_assert(WITHIN_ARENA(chunk));

    return chunk;
}

static void sh_free(char *ptr)
{
    int list;
    char *buddy;

    if (ptr == NULL)
        return;
    OPENSSL_assert(WITHIN_ARENA(ptr));
    if (!WITHIN_ARENA(ptr))
        return;

    list = sh_getlist(ptr);
    OPENSSL_assert(sh_testbit(ptr, list, sh.bittable));
    sh_clearbit(ptr, list, sh.bitmalloc);
    sh_add_to_list(&sh.freelist[list], ptr);

    /* Try to coalesce two adjacent free areas. */
    while ((buddy = sh_find_my_buddy(ptr, list)) != NULL) {
        OPENSSL_assert(ptr == sh_find_my_buddy(buddy, list));
        OPENSSL_assert(ptr != NULL);
        OPENSSL_assert(!sh_testbit(ptr, list, sh.bitmalloc));
        sh_clearbit(ptr, list, sh.bittable);
        sh_remove_from_list(ptr, sh.freelist[list]);
        OPENSSL_assert(!sh_testbit(ptr, list, sh.bitmalloc));
        sh_clearbit(buddy, list, sh.bittable);
        sh_remove_from_list(buddy, sh.freelist[list]);

        list--;

        if (ptr > buddy)
            ptr = buddy;

        OPENSSL_assert(!sh_testbit(ptr, list, sh.bitmalloc));
        sh_setbit(ptr, list, sh.bittable);
        sh_add_to_list(&sh.freelist[list], ptr);
        OPENSSL_assert(sh.freelist[list] == ptr);
    }
}

static int sh_actual_size(char *ptr)
{
    int list;

    OPENSSL_assert(WITHIN_ARENA(ptr));
    if (!WITHIN_ARENA(ptr))
        return 0;
    list = sh_getlist(ptr);
    OPENSSL_assert(sh_testbit(ptr, list, sh.bittable));
    return sh.arena_size / (1 << list);
}
#endif /* IMPLEMENTED */
