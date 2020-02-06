/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_LIST_H
# define HEADER_LIST_H

# include <stddef.h>
# include <openssl/e_os2.h>

#define container_of(ptr, type, member) \
    ((type *)((char *)ptr - offsetof(type, member)))

#define list_for_each(iter, head) \
    for (iter = (head)->next; iter != (head); iter = iter->next)

#define list_for_each_r(iter, head) \
    for (iter = (head)->prev; iter != (head); iter = iter->prev)

struct list {
    struct list *next, *prev;
};

static ossl_inline int list_empty(const struct list *head)
{
    return head->next == head;
}

static ossl_inline size_t list_size(const struct list *head)
{
    size_t sz = 0;
    struct list *iter;
    for (iter = (head)->next; iter != (head); iter = iter->next)
        ++sz;
    return sz;
}

static ossl_inline void list_init(struct list *list)
{
    list->next = list;
    list->prev = list;
}

static ossl_inline void list_add(struct list *n, struct list *head)
{
    struct list *prev = head, *next = head->next;
    next->prev = n;
    n->next = next;
    n->prev = prev;
    prev->next = n;
}

static ossl_inline void list_add_tail(struct list *n, struct list *head)
{
    struct list *prev = head->prev, *next = head;
    next->prev = n;
    n->next = next;
    n->prev = prev;
    prev->next = n;
}

static ossl_inline void list_del(struct list *entry)
{
    struct list *prev = entry->prev, *next = entry->next;
    next->prev = prev;
    prev->next = next;
}

static ossl_inline struct list* list_find(struct list *entry,
                                     int (*eq)(struct list*, void*),
                                     void *data)
{
    struct list *iter;
    list_for_each(iter, entry)
        if (eq(iter, data))
            return iter;
    return NULL;
}

static ossl_inline struct list* list_rfind(struct list *entry,
                                      int (*eq)(struct list*, void*),
                                      void *data)
{
    struct list *iter;
    list_for_each_r(iter, entry)
        if (eq(iter, data))
            return iter;
    return NULL;
}

#endif
