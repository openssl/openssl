/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/uint_set.h"
#include "internal/common.h"
#include <assert.h>

/*
 * uint64_t Integer Sets
 * =====================
 *
 * This data structure supports the following operations:
 *
 *   Insert Range: Adds an inclusive range of integers [start, end]
 *                 to the set. Equivalent to Insert for each number
 *                 in the range.
 *
 *   Remove Range: Removes an inclusive range of integers [start, end]
 *                 from the set. Not all of the range need already be in
 *                 the set, but any part of the range in the set is removed.
 *
 *   Query:        Is an integer in the data structure?
 *
 * The data structure can be iterated.
 *
 * For greater efficiency in tracking large numbers of contiguous integers, we
 * track integer ranges rather than individual integers. The data structure
 * manages a list of integer ranges [[start, end]...]. Internally this is
 * implemented as a doubly linked sorted list of range structures, which are
 * automatically split and merged as necessary.
 *
 * This data structure requires O(n) traversal of the list for insertion,
 * removal and query when we are not adding/removing ranges which are near the
 * beginning or end of the set of ranges. For the applications for which this
 * data structure is used (e.g. QUIC PN tracking for ACK generation), it is
 * expected that the number of integer ranges needed at any given time will
 * generally be small and that most operations will be close to the beginning or
 * end of the range.
 *
 * Invariant: The data structure is always sorted in ascending order by value.
 *
 * Invariant: No two adjacent ranges ever 'border' one another (have no
 *            numerical gap between them) as the data structure always ensures
 *            such ranges are merged.
 *
 * Invariant: No two ranges ever overlap.
 *
 * Invariant: No range [a, b] ever has a > b.
 *
 * Invariant: Since ranges are represented using inclusive bounds, no range
 *            item inside the data structure can represent a span of zero
 *            integers.
 */
void ossl_uint_set_init(UINT_SET *s)
{
    s->head = s->tail = NULL;
    s->num_ranges = 0;
}

void ossl_uint_set_destroy(UINT_SET *s)
{
    UINT_SET_ITEM *x, *xnext;

    for (x = s->head; x != NULL; x = xnext) {
        xnext = x->next;
        OPENSSL_free(x);
    }
}

/* Possible merge of x, x->prev */
static void uint_set_merge_adjacent(UINT_SET *s, UINT_SET_ITEM *x)
{
    UINT_SET_ITEM *xprev = x->prev;

    if (xprev == NULL)
        return;

    if (x->range.start - 1 != xprev->range.end)
        return;

    x->range.start = xprev->range.start;
    x->prev = xprev->prev;
    if (x->prev != NULL)
        x->prev->next = x;

    if (s->head == xprev)
        s->head = x;

    OPENSSL_free(xprev);
    --s->num_ranges;
}

static uint64_t u64_min(uint64_t x, uint64_t y)
{
    return x < y ? x : y;
}

static uint64_t u64_max(uint64_t x, uint64_t y)
{
    return x > y ? x : y;
}

/*
 * Returns 1 if there exists an integer x which falls within both ranges a and
 * b.
 */
static int uint_range_overlaps(const UINT_RANGE *a,
                               const UINT_RANGE *b)
{
    return u64_min(a->end, b->end)
        >= u64_max(a->start, b->start);
}

int ossl_uint_set_insert(UINT_SET *s, const UINT_RANGE *range)
{
    UINT_SET_ITEM *x, *z, *xnext, *f, *fnext;
    uint64_t start = range->start, end = range->end;

    if (!ossl_assert(start <= end))
        return 0;

    if (s->head == NULL) {
        /* Nothing in the set yet, so just add this range. */
        x = OPENSSL_zalloc(sizeof(UINT_SET_ITEM));
        if (x == NULL)
            return 0;

        x->range.start = start;
        x->range.end   = end;
        s->head = s->tail = x;
        ++s->num_ranges;
        return 1;
    }

    if (start > s->tail->range.end) {
        /*
         * Range is after the latest range in the set, so append.
         *
         * Note: The case where the range is before the earliest range in the
         * set is handled as a degenerate case of the final case below. See
         * optimization note (*) below.
         */
        if (s->tail->range.end + 1 == start) {
            s->tail->range.end = end;
            return 1;
        }

        x = OPENSSL_zalloc(sizeof(UINT_SET_ITEM));
        if (x == NULL)
            return 0;

        x->range.start = start;
        x->range.end   = end;
        x->prev        = s->tail;
        if (s->tail != NULL)
            s->tail->next = x;
        s->tail = x;
        ++s->num_ranges;
        return 1;
    }

    if (start <= s->head->range.start && end >= s->tail->range.end) {
        /*
         * New range dwarfs all ranges in our set.
         *
         * Free everything except the first range in the set, which we scavenge
         * and reuse.
         */
        for (x = s->head->next; x != NULL; x = xnext) {
            xnext = x->next;
            OPENSSL_free(x);
        }

        s->head->range.start = start;
        s->head->range.end   = end;
        s->head->next = s->head->prev = NULL;
        s->tail = s->head;
        s->num_ranges = 1;
        return 1;
    }

    /*
     * Walk backwards since we will most often be inserting at the end. As an
     * optimization, test the head node first and skip iterating over the
     * entire list if we are inserting at the start. The assumption is that
     * insertion at the start and end of the space will be the most common
     * operations. (*)
     */
    z = end < s->head->range.start ? s->head : s->tail;

    for (; z != NULL; z = z->prev) {
        /* An existing range dwarfs our new range (optimisation). */
        if (z->range.start <= start && z->range.end >= end)
            return 1;

        if (uint_range_overlaps(&z->range, range)) {
            /*
             * Our new range overlaps an existing range, or possibly several
             * existing ranges.
             */
            UINT_SET_ITEM *ovend = z;
            UINT_RANGE t;
            size_t n = 0;

            t.end = u64_max(end, z->range.end);

            /* Get earliest overlapping range. */
            for (; z->prev != NULL && uint_range_overlaps(&z->prev->range, range);
                   z = z->prev);

            t.start = u64_min(start, z->range.start);

            /* Replace sequence of nodes z..ovend with ovend only. */
            ovend->range = t;
            ovend->prev = z->prev;
            if (z->prev != NULL)
                z->prev->next = ovend;
            if (s->head == z)
                s->head = ovend;

            /* Free now unused nodes. */
            for (f = z; f != ovend; f = fnext, ++n) {
                fnext = f->next;
                OPENSSL_free(f);
            }

            s->num_ranges -= n;
            break;
        } else if (end < z->range.start
                    && (z->prev == NULL || start > z->prev->range.end)) {
            if (z->range.start == end + 1) {
                /* We can extend the following range backwards. */
                z->range.start = start;

                /*
                 * If this closes a gap we now need to merge
                 * consecutive nodes.
                 */
                uint_set_merge_adjacent(s, z);
            } else if (z->prev != NULL && z->prev->range.end + 1 == start) {
                /* We can extend the preceding range forwards. */
                z->prev->range.end = end;

                /*
                 * If this closes a gap we now need to merge
                 * consecutive nodes.
                 */
                uint_set_merge_adjacent(s, z);
            } else {
                /*
                 * The new interval is between intervals without overlapping or
                 * touching them, so insert between, preserving sort.
                 */
                x = OPENSSL_zalloc(sizeof(UINT_SET_ITEM));
                if (x == NULL)
                    return 0;

                x->range.start = start;
                x->range.end   = end;

                x->next = z;
                x->prev = z->prev;
                if (x->prev != NULL)
                    x->prev->next = x;
                z->prev = x;
                if (s->head == z)
                    s->head = x;

                ++s->num_ranges;
            }
            break;
        }
    }

    return 1;
}

int ossl_uint_set_remove(UINT_SET *s, const UINT_RANGE *range)
{
    UINT_SET_ITEM *z, *zprev, *y;
    uint64_t start = range->start, end = range->end;

    if (!ossl_assert(start <= end))
        return 0;

    /* Walk backwards since we will most often be removing at the end. */
    for (z = s->tail; z != NULL; z = zprev) {
        zprev = z->prev;

        if (start > z->range.end)
            /* No overlapping ranges can exist beyond this point, so stop. */
            break;

        if (start <= z->range.start && end >= z->range.end) {
            /*
             * The range being removed dwarfs this range, so it should be
             * removed.
             */
            if (z->next != NULL)
                z->next->prev = z->prev;
            if (z->prev != NULL)
                z->prev->next = z->next;
            if (s->head == z)
                s->head = z->next;
            if (s->tail == z)
                s->tail = z->prev;

            OPENSSL_free(z);
            --s->num_ranges;
        } else if (start <= z->range.start) {
            /*
             * The range being removed includes start of this range, but does
             * not cover the entire range (as this would be caught by the case
             * above). Shorten the range.
             */
            assert(end < z->range.end);
            z->range.start = end + 1;
        } else if (end >= z->range.end) {
            /*
             * The range being removed includes the end of this range, but does
             * not cover the entire range (as this would be caught by the case
             * above). Shorten the range. We can also stop iterating.
             */
            assert(start > z->range.start);
            assert(start > 0);
            z->range.end = start - 1;
            break;
        } else if (start > z->range.start && end < z->range.end) {
            /*
             * The range being removed falls entirely in this range, so cut it
             * into two. Cases where a zero-length range would be created are
             * handled by the above cases.
             */
            y = OPENSSL_zalloc(sizeof(UINT_SET_ITEM));
            if (y == NULL)
                return 0;

            y->range.end   = z->range.end;
            y->range.start = end + 1;
            y->next = z->next;
            y->prev = z;
            if (y->next != NULL)
                y->next->prev = y;

            z->range.end = start - 1;
            z->next = y;

            if (s->tail == z)
                s->tail = y;

            ++s->num_ranges;
            break;
        } else {
            /* Assert no partial overlap; all cases should be covered above. */
            assert(!uint_range_overlaps(&z->range, range));
        }
    }

     return 1;
}

int ossl_uint_set_query(const UINT_SET *s, uint64_t v)
{
    UINT_SET_ITEM *x;

    if (s->head == NULL)
        return 0;

    for (x = s->tail; x != NULL; x = x->prev)
        if (x->range.start <= v && x->range.end >= v)
            return 1;
        else if (x->range.end < v)
            return 0;

    return 0;
}
