/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file
 * A collection of lockless data structures for high performance 
 * data paths
 */
#include <assert.h>
#include <openssl/crypto.h>
#include "internal/common.h"
#include "internal/lockless.h"

/**
 * @brief
 * a linked list node
 */
typedef struct lll_node {
    void *data;                /* the data this node points to */
    struct lll_node *next;     /* the next node in the list */
    struct lll_node *del_next; /* next pointer for pending delete list */
} LLL_NODE;

/**
 * @brief this is the core of our linked list.
 */
struct lll_st {
    uint64_t readers;      /* The number of readers in the list */
    LLL_NODE *head;        /* The head node in the list */
    LLL_NODE *tail;        /* The tail node in the list */
    LLL_NODE *pending_del; /* the list of nodes to delete */
    lll_cmp cmpfn;         /* The comparison function for this list */
    lll_free freefn;       /* The free function for nodes on this list */
    int allow_del;         /* do we allow deletes from this list */
    CRYPTO_RWLOCK *lck;    /* The lock that we have to have for atomic ops */
};

typedef struct lll_idx_st {
    LLL_NODE *pred;
    LLL_NODE *succ;
    LLL_NODE *curr;
    LLL_NODE *next;
} LLL_IDX;

static int notify_read_start(LLL *list)
{
    uint64_t readers;

    return list->allow_del == 0 ? 1 : CRYPTO_atomic_add64(&list->readers, 1, &readers, list->lck);
}

static void notify_read_end(LLL *list)
{
    uint64_t readers;
    LLL_NODE *del_list;
    LLL_NODE *null_ptr = NULL;

    if (list->allow_del == 0)
        return;

    if (!CRYPTO_atomic_add64(&list->readers, -1, &readers, list->lck))
        return;
    
    del_list = list->pending_del;

    if (readers == 0) {
        /*
         * we're out of readers, quick!  Grab the delete list
         */
        if (!CRYPTO_atomic_cmp_exch((void **)&list->pending_del, (void **)&del_list,
                                    (void **)&null_ptr, list->lck))
            return;
        /*
         * check to see if got a list of pointers
         * if so, iterate and delete them
         */
        while (del_list != NULL) {
            null_ptr = del_list->del_next;
            list->freefn(del_list->data);
            OPENSSL_free(del_list);
            del_list = null_ptr;
        }
    }

    return;
}

/**
 * @brief
 * Allocate a new linked list
 * parameters
 * cmpfn - The comparison function for nodes on the list
 * freefn - The free function for nodes on the list
 * allow_delete - Flag to indicate if we allow deletions
 *
 * Returns a pointer to a linked list or NULL on failure
 */
LLL* LLL_new(lll_cmp cmpfn, lll_free freefn, int allow_delete)
{
    LLL *new = OPENSSL_zalloc(sizeof(LLL) + (sizeof(LLL_NODE) * 2));

    if (new == NULL)
        return NULL;
    new->lck = CRYPTO_THREAD_lock_new();
    if (new->lck == NULL) {
        OPENSSL_free(new);
        return NULL;
    }
    new->head = (LLL_NODE *)(new + 1);
    new->tail = (LLL_NODE *)(new->head + 1);
    new->head->data = (void *)0xdeadbeee;
    new->head->next = new->tail;

    new->tail->data = (void *)0xdeadbeee;
    new->tail->next = NULL;
    
    new->cmpfn = cmpfn;
    new->freefn = freefn;
    new->allow_del = allow_delete;

    return new;
}

/**
 * @brief
 * Frees all nodes on a list in preparation for deleting the
 * list entirely
 * parameters
 * list - the list to traverse and free all the nodes of
 *
 * Note: This is not strictly multiuser safe, but we
 * assume that when the list is getting freed there is only
 * a single user remaining for it, so we don't need to delete
 * nodes and wait for any readers to finish up.  We still use
 * atomics here though because we're shutting down the list (so
 * speed isn't super relevant), and we want to avoid any
 * thread sanitizer complaints.
 */
static void lll_free_all_nodes(LLL *list)
{
    LLL_NODE *head, *next;

    /*
     * Need to free the pending_list too
     * handle it with a notify_read_start/notify_read_end
     */
    notify_read_start(list);
    notify_read_end(list);

    head = list->head;

    /*
     * Free all list items.
     * NOTE: head and tail are allocated as part of a contiguous
     * block in LLL_new, so those get freed via the OPENSSL_free()
     * call in LLL_delete, we don't touch them here
     */
    while (head != list->tail) {
        next = head->next;
        if (head != list->head) {
            list->freefn(head->data);
            OPENSSL_free(head);
        }
        head = next;
    }
    return;
}

/**
 * @brief
 * Free a linked list
 * parameters
 * list - the list to free
 */
void LLL_free(LLL *list)
{
    uint64_t readers;

    if (list == NULL)
        return;
    /*
     * If we're freeing, traverse the list and free every item on
     * it.
     * Assume that we are the only remaining user, so we can
     * traverse the list without worrying about other readers
     * but lets do a sanity check to be safe
     */
    if (!CRYPTO_atomic_add64(&list->readers, 0, &readers, list->lck)) {
        /*
         * can't do any atomic ops?  We're done
         */
        return;
    }
    if (!ossl_assert(readers == 0)) {
        /*
         * Still have readers?  No good, get out
         */
        return;
    }

    lll_free_all_nodes(list);

    /*
     * We've freed all the nodes, now we just need to clean
     * up the top level struct
     */
    CRYPTO_THREAD_lock_free(list->lck);
    OPENSSL_free(list);
    return;
}

#define UNMARK_MASK ~1
#define MARK_BIT (uintptr_t)0x1
#define getpointer(_markedpointer) ((LLL_NODE *)(((uintptr_t)_markedpointer) & UNMARK_MASK))
#define ismarked(_markedpointer) ((((uintptr_t)_markedpointer) & MARK_BIT) != 0x0)
#define setmark(_markedpointer) ((LLL_NODE *)(((uintptr_t)_markedpointer) | MARK_BIT))

static void lll_pos(LLL *list, LLL_NODE *key, lll_cmp cmpfn, LLL_IDX *idx, void *arg)
{
    LLL_NODE *pred, *curr, *succ;
    int restarted = 1;
retry:
    pred = list->head;    

    if (!ossl_assert(CRYPTO_atomic_load_ptr((void **)&pred->next,
                                            (void **)&curr, list->lck) == 1))
        return;
    assert(curr != NULL);
    curr = getpointer(curr);

    do {
        if(!ossl_assert(CRYPTO_atomic_load_ptr((void **)&curr->next,
                                               (void **)&succ, list->lck) == 1))
            return;
        while (ossl_unlikely(ismarked(succ))) {
            succ = getpointer(succ);
            if (!CRYPTO_atomic_cmp_exch((void **)&pred->next,
                                        (void **)&curr, (void **)&succ,
                                        list->lck)) {
                restarted = 1;
                goto retry;
            }
            curr = getpointer(succ);
            if (!ossl_assert(CRYPTO_atomic_load_ptr((void **)&succ->next,
                                                    (void **)&succ, list->lck) == 1))
                return;
        }
   
        /*
         * If we hit the tail node, we should return immediately
         */
        if (curr == list->tail || cmpfn(curr->data, key->data, arg, restarted) >= 0) {
            idx->pred = pred;
            idx->curr = curr;
            return;
        }
        restarted = 0;

        pred = curr;
        if (!ossl_assert(CRYPTO_atomic_load_ptr((void **)&curr->next,
                                                (void **)&curr, list->lck) == 1))
            return;
        curr = getpointer(curr);
    } while (1);
}

/**
 * @brief
 * Insert to a linked list
 * parameters
 * list - the list to insert to
 * data - the data to insert
 * arg - data to pass to cmp method during lookup
 *
 * returns 1 on success or 0 on failure
 */
int LLL_insert(LLL *list, void *data, void *arg)
{
    LLL_IDX idx = { NULL, NULL, NULL, NULL };
    LLL_NODE *new = OPENSSL_zalloc(sizeof(LLL_NODE));
    int ret = 0;
    if (new == NULL)
        return 0;

    new->data = data;

    notify_read_start(list);
    do {
        lll_pos(list, new, list->cmpfn, &idx, arg);
        if (idx.curr != list->head && idx.curr != list->tail) {    
            if (list->cmpfn(idx.curr->data, new->data, arg, 0) == 0) {
                free(new);
                break;
            }
        }
        new->next = idx.curr;
        if (CRYPTO_atomic_cmp_exch((void **)&idx.pred->next, (void **)&idx.curr,
                                   (void **)&new, list->lck)) {
            if(list->head->next == (LLL_NODE *)0xdeadbeee)
                abort();
            ret = 1;
            break;
        }
    } while (1);

    notify_read_end(list);
    return ret;
}

/**
 * @brief
 * Delete from a linked list
 * Parameters
 * list - The list to delete from
 * data - A comparison data node to locate the node to delete
 * arg - Arbitrary data to pass to cmpfn for list
 * returns 1 on success or 0 on failure
 */
int LLL_delete(LLL *list, void *data, void *arg)
{
    LLL_IDX idx = { NULL, NULL, NULL, NULL };
    LLL_NODE key;
    LLL_NODE *node, *pred, *succ;
    LLL_NODE *markedsucc;
    int ret = 0;

    if (list->allow_del == 0)
        return 0;

    key.data = data;

    notify_read_start(list);

    do {
        lll_pos(list, &key, list->cmpfn, &idx, arg);
        pred = idx.pred;
        node = idx.curr;

        /*
         * If we got to the end of the list, we didn't match on 
         * anything, delete is a fail
         */
        if (idx.curr == list->tail)
            break;

        if (list->cmpfn(idx.curr->data, data, arg, 0) != 0)
            break;

        if (!CRYPTO_atomic_load_ptr((void **)&node->next, (void **)&succ, list->lck))
            break;
        succ = getpointer(succ);
        markedsucc = setmark(succ);

        if (!CRYPTO_atomic_cmp_exch((void **)&node->next, (void **)&succ,
                                    (void **)&markedsucc, list->lck))
            continue;

        if (!CRYPTO_atomic_cmp_exch((void **)&pred->next, (void **)&node,
                                (void **)&succ, list->lck))
            node = idx.curr;

        node->del_next = list->pending_del;
        do {
            ret = CRYPTO_atomic_cmp_exch((void **)&list->pending_del, (void **)&node->del_next,
                                         (void **)&node, list->lck);
        } while (ret != 1);
        break;
    } while (1);

    notify_read_end(list);
    return ret;
}


/**
 * @brief
 * Find a node in a linked list
 * parameters
 * list - The list to do the lookup in
 * data - temporary data used for comparison in comparing nodes
 * arg - arbitrary data to pass to cmpfn for list
 * returns 1 on success, 0 on failure
 * NOTE, on a successful lookup, data needed from the node should be
 * copied to stable storage from within the compare function, so as to ensure
 * that its not deleted while in use.  Doing so from the cmpfn ensures that
 * the node will not be deleted by another thread while being accessed.
 */
int LLL_find(LLL *list, void *data, void *arg)
{
    LLL_IDX idx = { NULL, NULL, NULL, NULL };
    LLL_NODE key;
    key.data = data;
    int ret = 0;

    notify_read_start(list);
    lll_pos(list, &key, list->cmpfn, &idx, arg);
   
    if (idx.curr == list->head || idx.curr == list->tail)
        ret = 0;
    else if (list->cmpfn(idx.curr->data, data, arg, 0) == 0)
        ret = 1;
    notify_read_end(list);
    return ret;
}

int LLL_iterate(LLL *list, lll_cmp fn, void *arg)
{
    LLL_IDX idx = {NULL, NULL, NULL, NULL };
    LLL_NODE key;

    key.data = NULL;
    notify_read_start(list);
    lll_pos(list, &key, fn, &idx, arg);
    notify_read_end(list);
    return 1;
}
