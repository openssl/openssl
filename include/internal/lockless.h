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

#ifndef OPENSSL_LOCKLESS_H
# define OPENSSL_LOCKLESS_H
# pragma once


/*
 * A lockless linked list, relying on atomic compare and exchange to
 * remain consistent.  The list is always maintained as sorted
 * based on the results of the cmp function passed to the list creator
 * objects that evaulate as equivalent may appear in any order.
 *
 * Based on Harris' algorithm:
 * https://timharris.uk/papers/2001-disc.pdf
 */

/**
 * @brief the top level data struct for a lockless linked list
 */
typedef struct lll_st LLL;

/**
 * @brief
 * A free callback handler for nodes on the associated linked list
 * parameters
 * data - The data held in the node to be freed
 */
typedef void (*lll_free)(void *data);

/**
 * @brief
 * A compare function to do ordinal comparisons of nodes in a list
 * returns 0 if a and b are equivalent, > 0 if a > b, and < 0 if
 * a < b
 * parameters
 * a - a list node for comparison
 * b - a list node for comparison
 * arg - arbitrary data to pass via delete/find/insert methods
 * restarted - indicator to announce we are begining at list head
 */
typedef int (*lll_cmp)(void *a, void *b, void *arg, int restarted);


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
LLL* LLL_new(lll_cmp cmpfn, lll_free freefn, int allow_delete);

/**
 * @brief
 * Free a linked list
 * parameters
 * list - the list to free
 */
void LLL_free(LLL *list);

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
int LLL_insert(LLL *list, void *data, void *arg);

/**
 * @brief
 * Delete from a linked list
 * Parameters
 * list - The list to delete from
 * data - A comparison data node to locate the node to delete
 * arg - Arbitrary data to pass to cmpfn for list
 * returns 1 on success or 0 on failure
 */
int LLL_delete(LLL *list, void *data, void *arg);

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
int LLL_find(LLL *list, void *data, void *arg);

/**
 * @brief
 * Iterate over an entire list
 */
int LLL_iterate(LLL *list, lll_cmp fn, void *arg);

#endif
