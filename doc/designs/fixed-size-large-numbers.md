Fixed size large numbers
========================

*`BIGNUM` redesign for better constant time calculations*
---------------------------------------------------------

<center>
<p><h3>Abstract</h3></p>

<p>
In this design, we explore and define how OpenSSL's `BIGNUM` library can
be remodelled for constant-size calculations. Furthermore, we explore and
define a fixed size large number library, which never changes the in-memory
size of a number once it has been allocated. Finally, we define how `BIGNUM`
functions with corresponding fixed size large number functions can be remade
into wrappers around the latter.
</p>

</center>

### Table of contents:

- [Background][]
- [Goals][]
- [Challenges][]
- [Design][]
  - [The `OSSL_FN` type][]
  - [The `OSSL_FN_CTX` type][]
    - [The `OSSL_FN_CTX` type, with frames][]
    - [The `OSSL_FN_CTX` type, without frames][]
  - [The `BIGNUM` type][]
  - [Mutability][]
  - [Dropping `top` from `BIGNUM`][]
  - [Memory functionality for `OSSL_FN`][]
  - [Memory functionality for `OSSL_FN_CTX`][]
  - [Wrapping an `OSSL_FN` function with a `BIGNUM` function][]
  - [Failures][]
- [Repurposing existing code][]
- [How to apply `OSSL_FN`][]
- [Where to apply `OSSL_FN`][]
- [How to apply `OSSL_FN_CTX`][]
  - [The variant with frames][]
  - [The variant without frames][]
- [Testing][]
- [Appendix][]
  - [Using the C99 flexible array member feature][]

Background
==========

[Background]: #background

The current internal definition of OpenSSL's `BIGNUM` looks like this:

```c
struct bignum_st {
    BN_ULONG *d;    /*
                     * Pointer to an array of 'BN_BITS2' bit
                     * chunks. These chunks are organised in
                     * a least significant chunk first order.
                     */
    int top;        /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;       /* Size of the d array. */
    int neg;        /* one if the number is negative */
    int flags;
};
```

The fields `d`, `top` and `dmax` allow the numbers to be quite dynamic in
terms of its memory footprint, as it can both increase in size[^1] and
decrease in size.[^2]

Furthermore, the result of any `BIGNUM` operation may be the same `BIGNUM`
instance as any of the operands, which means that any `BIGNUM` may have its
memory footprint adjusted at any time.

While this is very flexible, it leaves uncertainties about the time any
calculation may take, following any earlier calculation, which is a security
vulnerability.

[^1]: the array `d` is reallocated to a larger size and `dmax` as well as top
      are updated
[^2]: `top` is diminished

Goals
=====

[Goals]: #goals

Overall goal: Introduce a new type and API that are inherently constant size
to replace the existing `BIGNUM` usage.

The intention is to enhance this one aspect of constant time calculations.
Other aspects are considered out of scope for this design.

The included sub-goals are:

* To define a new large number type and accompanying API, that doesn't allow
  size adjustments of the large numbers once their individual size has been
  established
* To define that large number type and API in such a way it's compatible
  with and can be used by the `BIGNUM` API through easy transition to the
  new type.
* To ensure that the new large number API is constant-size
* To repurpose as much as possible of our current `BIGNUM` code for the new
  large number API, especially our assembler code (with the assumption that
  everything that doesn't change the `BIGNUM` sizes can be repurposed as is)
* To replace the public `BIGNUM` API that has been repurposed as wrappers
  around the new large number API
* To replace all security critical large number calculations so that they
  are not just constant-size in themselves, but that the whole set of
  calculations remains constant-size, within OpenSSL code

Challenges
==========

[Challenges]: #challenges

The challenges we have are:

- **`BIGNUM` usage**

  Because `BIGNUM` is a public facing API, it's likely to be used by OpenSSL
  users.  This existing API needs to be backward compatible, but performance
  isn't necessarily critical.

- **constant-time through constant-size**

  To make calculation time predictable on a broader scale than on a
  per-operation basis, there's a need to ensure that each large number being
  used in the calculations involved has a fixed size, i.e. to avoid the sort
  of dynamic sizing that the `BIGNUM` functionality does.

Design
======

[Design]: #design

The overall design defines a new type, `OSSL_FN` (where FN is short for
"FIXNUM"), which can somehow be made compatible with `BIGNUM`, but yet be
distinct.  Early thoughts on this was to make them essentially the same type
internally, and cast between them, but unfortunately, a compliant C compiler
is very likely to auto-cast between them, making it difficult to keep them
separate yet castable back and forth.

To allow a stricter or more explicit way to remedy the flexibility of the C
language, this design therefore defines a `OSSL_FN` which is separate from
the `BIGNUM`, yet compatible with BIGNUM insofar that the `BIGNUM` type
wraps around the `OSSL_FN` type, and `BIGNUM` functions wrap around
corresponding `OSSL_FN` functions when there are any.

The idea is that a `BIGNUM` (`BN_`) function may call an `OSSL_FN` function,
but not the other way around, i.e. when an `OSSL_FN` function is called, an
"`OSSL_FN` only" bubble is entered, and such a function must therefore only
in turn call other `OSSL_FN` functions for large number operations, rather
than `BIGNUM` functions.

The overall design also defines new associated types to replace their
`BIGNUM` counterparts: `OSSL_FN_CTX`, `OSSL_FN_BLINDING`, `OSSL_FN_MONT_CTX`,
and `OSSL_FN_RECP_CTX`.  Notably, however, the callback type `BN_GENCB`
isn't replaced, as it contains nothing `BIGNUM`, and can therefore be reused
unchanged with an `OSSL_FN` API.

The `OSSL_FN` type and API will be designed in such a way to enable it to
become public at some point in the future.  *The initial version will not be
public and will only be used internally within OpenSSL.*

Let's go over the details

The `OSSL_FN` type
------------------

[The `OSSL_FN` type]: #the-ossl_fn-type

The `OSSL_FN` type would be a structure derived from the existing `BIGNUM`
type, retaining a minimum amount of data.  Just as was previously with
`BIGNUM`, the absolute value of the number is stored in a `BN_ULONG` array,
and a flag indicates if the number is positive or negative.

```c
typedef struct ossl_fn_st OSSL_FN;

struct ossl_fn_st {
    /* Flag: alloced with OSSL_FN_new() or  OSSL_FN_secure_new() */
    unsigned int is_dynamically_allocated : 1;
    /* Flag: alloced with OSSL_FN_secure_new() */
    unsigned int is_securely_allocated : 1;
    /* Flag: the caller holds a pointer to this OSSL_FN as well as the BIGNUM that wraps it */
    unsigned int is_acquired : 1;
    /* Flag: the number is negative */
    unsigned int is_negative : 1;

    /*
     * The d array, with its size in number of BN_ULONG.
     * This stores the number itself
     */
    size_t dsize;
    BN_ULONG d[];
};
```

To be noted is that current cryptosystems never use negative numbers, so
it's possible that the `is_negative` flag will never be used.  Therefore, it
is possible that it will never exist in actual implementation.  It is
retained in this design, though, to keep that option open.

The `OSSL_FN_CTX` type
----------------------

[The `OSSL_FN_CTX` type]: #the-ossl_fn_ctx-type

The `OSSL_FN_CTX` type is made to replace the `BN_CTX` type where `OSSL_FN`
type is used instead of `BIGNUM`.

The `OSSL_FN_CTX` type is to be implemented as an arena (a large enough chunk
of memory) in which `OSSL_FN` instances are allocated.  More in detail, there
are two possibilities.

### The `OSSL_FN_CTX` type, with frames

[The `OSSL_FN_CTX` type, with frames]: #the-ossl_fn_ctx-type-with-frames

This variant is intended to mimic all `BN_CTX` functionality.  The idea is to
create a large `OSSL_FN_CTX` at the top function of a complex calculation, and
pass it around to all sub-function calls.

Each sub-function would begin with starting a frame (using `OSSL_FN_CTX_begin()`,
similar in spirit to `BN_CTX_start()`) in the passed `OSSL_FN_CTX` arena,
obtain what temporary `OSSL_FN`s it needs from it (using `OSSL_FN_CTX_get()`,
similar in spirit to `BN_CTX_get()`), perform what calculations it needs, and
finish with ending the frame (using `OSSL_FN_CTX_end()`, similar in spirit to
`BN_CTX_end()`), which relinquishing that frame's space in the `OSSL_FN_CTX`
arena, and thereby making that same space available for the next sub-function.

```c
typedef struct ossl_fn_ctx_st OSSL_FN_CTX;

struct ossl_fn_ctx_frame_st; /* forwarding, see below */
struct ossl_fn_ctx_st {
    /*
     * Pointer to the last OSSL_FN_CTX_start() location (a simple pointer into
     * the memory area).  See the struct ossl_fn_ctx_frame_st definition below
     * for details.
     */
    struct ossl_fn_ctx_frame_st *last_frame;
    /*
     * The arena itself.
     */
    size_t msize; /* bytes */
    unsigned char memory[];
};

struct ossl_fn_ctx_frame_st {
    /*
     * Pointer back to the whole arena where the frame is located, to access
     * |msize| and |memory| from it.
     */
    struct ossl_fn_ctx_st *arena;
    /*
     * Pointer to the previous frame in the arena, allowing OSSL_FN_CTX_end()
     * to do its job.
     */
    struct ossl_fn_ctx_frame_st *previous_frame;
    /*
     * Pointer to the free area of the frame.  Every time OSSL_FN_CTX_get() is
     * called, the current value of this pointer is returned, and it's updated
     * by incrementing it by the number of bytes given by OSSL_FN_CTX_get().
     * The available number of bytes is limited by what's left in the arena.
     */
    unsigned char *free_memory;
    unsigned char memory[];
};
```

The arena design requires that the total use of the arena can be predicted
at the point of allocating the arena.  There is an inherent uncertainty how
large an arena should be to accommodate the needs of a large tree of
function calls using it.  A possible solution is to allocate a very large
arena (could 32kB be considered enough?), but it may require some
investigation to find out what's reasonable.

Looking at the current use of `BN_CTX_new`, it can be noted that they are
allocated all over current OpenSSL code, so it's easy to assume that each is
used in a fairly limited fashion.  Furthermore, the `BN_CTX` internals allow
for a maximum of 16 `BIGNUM`s.  A corresponding arena could the reasonably
have the size 16 \* *size of largest fixed number* plus a little extra for
bookkeeping purposes.

### The `OSSL_FN_CTX` type, without frames

[The `OSSL_FN_CTX` type, without frames]: #the-ossl_fn_ctx-type-without-frames

Compared to the variant with frames, this `OSSL_FN_CTX` variant is much
simpler, but also more heap allocation intense.

The idea with this one is that each function that needs to obtain temporary
`OSSL_FN`s would also create their own `OSSL_FN_CTX`, independently from any
other function.

```c
typedef struct ossl_fn_ctx_st OSSL_FN_CTX;

struct ossl_fn_ctx_st {
    /*
     * Pointer to the free area of the arena.  Every time OSSL_FN_CTX_get() is
     * called, the current value of this pointer is returned, and it's updated
     * by incrementing it by the number of bytes given by OSSL_FN_CTX_get().
     * The available number of bytes is limited by what's left in the arena.
     */
    unsigned char *free_memory;
    /*
     * The arena itself.
     */
    size_t msize; /* bytes */
    unsigned char memory[];
};
```

Other associated types
----------------------

[Other associated types]: #other-associated-types

There are a few types that, like `BN_CTX` / `OSSL_FN_CTX`, are used to hold
a context around some more complicated calculations.  Just like `OSSL_FN_CTX`,
The `OSSL_FN` variants of these types are made into strictly separate types,
not compatible with their `BIGNUM` counterparts.

| `BIGNUM` types | `OSSL_FN` types    |
|----------------|--------------------|
| `BN_BLINDING`  | `OSSL_FN_BLINDING` |
| `BN_MONT_CTX`  | `OSSL_FN_MONT_CTX` |
| `BN_RECP_CTX`  | `OSSL_FN_RECP_CTX` |

Their `OSSL_FN` APIs for these types should be possible to create by
repurposing the corresponding `BIGNUM` APIs, with adjustments for the
constant-size requirements of all `OSSL_FN` functions.

The `BIGNUM` type
-----------------

[The `BIGNUM` type]: #the-bignum-type

The `BIGNUM` type is changed to include a `OSSL_FN` for its data, and other
fields that are only of interest for `BIGNUM`s:

```c
struct bignum_st {
    OSSL_FN *data;
    /* Some of these flags are replicated in OSSL_FN, some are not */
    int flags;
};
```

When structured this way, it's easy to get an `OSSL_FN` out of a `BIGNUM`,
as well as to wrap an `OSSL_FN` in a `BIGNUM`:

```c
/*
 * BN_acquire_fn() and BN_release_fn() function together.  It is done this
 * way as a safety measure, to make sure that a BIGNUM doesn't expand an OSSL_FN
 * that the caller currently has a handle on.  However, it's possible to
 * adjust the size of the OSSL_FN while acquiring it.
 */
OSSL_FN *BN_acquire_fn(BIGNUM *a, size_t bits)
{
    if (a->data->is_acquired)
        return NULL; /* only one acquisition at a time */
    if ((bn_expand(a, bits)) <= 0)
        return NULL;
    a->data->is_acquired = 1;
    return a->data;
}
void BN_release_fn(BIGNUM *a)
{
    a->data->is_acquired = 0;
}
```

Note that these functions are not designed to be thread-safe, nor do they
support multiple suímultaneous acquisitions.  By design, holding pointers to
a `BIGNUM` and its wrapped `OSSL_FN` at the same time should only happen in
a very short term.

If there's a need, it would also be possible to wrap an `OSSL_FN` with a
`BIGNUM`:

``` C
/*
 * When wrapping an OSSL_FN in a BIGNUM, the OSSL_FN is considered acquired
 * until the caller decides to release it.
 */
BIGNUM *BN_wrap_fn(OSSL_FN *a)
{
    BIGNUM *r = OPENSSL_zalloc(sizeof(BIGNUM));

    if (r != NULL) {
        r->data = a;
        r->flags |= (a->is_dynamically_allocated ? BN_FLG_MALLOCED);
        r->flags |= (a->is_securely_allocated ? BN_FLG_SECURE);
        a->is_acquired = 1;
    }

    return r;
}
```

This should be avoided, but we retain this possibility just in case its use
is unavoidable.

Mutability
----------

[Mutability]: #mutability

The understanding is that within a `OSSL_FN` API, `dsize` is immutable as
soon as a `OSSL_FN` has been allocated to its target size, except for when
the `OSSL_FN` instance is freed. However, when accessed through the `BIGNUM`
type (i.e. by the `BIGNUM` API), the `OSSL_FN` size may be reallocated to
allow a larger size than initially allocated, and `dsize` may be modified
accordingly.

The `OSSL_FN_CTX`  API is much more strict.  The size of an `OSSL_FN_CTX`
instance is immutable after it has been allocated, except when it is freed.

In the case where an `OSSL_FN` is "acquired" (i.e. the calling code holds a
pointer to a `OSSL_FN` and to a `BIGNUM` that wraps it), `BIGNUM` must
consider the `OSSL_FN` size as immutable.

Dropping `top` from `BIGNUM`
----------------------------

[Dropping `top` from `BIGNUM`]: #dropping-top-from-bignum

With this design, the `top` field is dropped, meaning that a `BIGNUM` will
no longer be able to diminish its memory footprint. The reason is that the
`OSSL_FN` functionality would need to update it, but that runs counter to
the ideas behind the `OSSL_FN` functionality in terms of mutability.

This may come at a performance cost for users calling the `BIGNUM`
API. However, it's our judgement that this is acceptable to get better
overall safety.

Memory functionality for `OSSL_FN`
----------------------------------

[Memory functionality for `OSSL_FN`]: #memory-functionality-for-ossl_fn

We anticipate that we will need the following functions to allocate and
deallocate `OSSL_FN`s:

```c
OSSL_FN *OSSL_FN_new(size_t size);
void OSSL_FN_free(OSSL_FN *f);
```

Memory functionality for `OSSL_FN_CTX`
--------------------------------------

[Memory functionality for `OSSL_FN_CTX`]: #memory-functionality-for-ossl_fn_ctx

We anticipate that the `OSSL_FN_CTX` API will look very much like the
`BN_CTX` API, except for the allocation functionality:

```c
OSSL_FN_CTX *OSSL_FN_CTX_new(OSSL_LIB_CTX *libctx, size_t arena_size);
OSSL_FN_CTX *OSSL_FN_CTX_secure_new(OSSL_LIB_CTX *libctx, size_t arena_size);
void OSSL_FN_CTX_free(OSSL_FN_CTX *ctx);

OSSL_FN *OSSL_FN_CTX_get(OSSL_FN_CTX *ctx, size_t size);
```

*Something to be noted is that `OSSL_FN_CTX_secure_new()` allocates the
whole arena in secure memory.  The impact compared to allocating individual
`OSSL_FN` instances in secure memory is considered minimal.*

If the variant of `OSSL_FN_CTX` *with frames* is chosen, the following
functions will also have to be defined:

```c
int OSSL_FN_CTX_start(OSSL_FN_CTX *ctx);
int OSSL_FN_CTX_end(OSSL_FN_CTX *ctx);
```

Wrapping an `OSSL_FN` function with a `BIGNUM` function
-------------------------------------------------------

[Wrapping an `OSSL_FN` function with a `BIGNUM` function]: #wrapping-an-ossl_fn-function-with-a-bignum-function

This is one example of what that would look like. This assumes that there is
a function `OSSL_FN_add()`:

```c
int OSSL_FN_add(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b)
{
    /*
     * Code from the current BN_add() goes here, without the part that touches
     * top and dmax (top doesn't exist in this design, but it does exist in
     * current OpenSSL code)
     */
}

int BN_add(BIGNUM *r, BIGNUM *a, BIGNUM *b)
{
    int ret;

    if (!r->data.is_acquired) {
        size_t max_size = a->data.dsize; /* number of sizeof(BN_ULONG) limbs */
        BN_ULONG n = a->data->d[max_size-1];

        if (b->data.dsize > max_size) {
            max_size = b->data->dsize;
            n = b->data->d[max_size-1];
        }

        /*
         * If the highest limb in the biggest number is non-zero and they are
         * both positive or both negative, it's assumed that the resulting
         * bignum may grow by one limb.
         */
        if (n != 0 && a->data->is_negative == b->data->is_negative)
            max_size++;

        if ((ret = bn_expand(r, max_size * BN_BITS2)) <= 0)
            return ret;
    }

    /*
     * It's not necessary to "acquire" the OSSL_FNs here, because it's
     * assumed that the call of OSSL_FN_add() enters a "OSSL_FN only" bubble.
     */
    ret = OSSL_FN_add(r->data, a->data, b->data);

    return ret;
}
```

*(This is not perfect and tested code, it's just an example.  Actual code
should be more perfect, and of course, tested)*

Failures
--------

[Failures]: #failures

A fixed size large number introduces new problems, which introduces new ways
that the `OSSL_FN` API can fail:

* Overflow: this will happen when the caller has allocated an improperly
  sized `OSSL_FN` to store future calculation results in.  *This is akin to
  memory allocation failures in so far that there isn't enough memory space*

Repurposing existing code
=========================

[Repurposing existing code]: #repurposing-existing-code

A majority of existing internal `BIGNUM` code operates directly on the `d`
array of the existing `BIGNUM` structure, with the size of that array given
separately, and are already essentially operating on fixed size numbers.
This design assumes that such functions can be repurposed for `OSSL_FN`
functionality with zero change, apart from function name changes.

Furthermore, this design assumes that the remaining functions, which do
manipulate the size of the `BIGNUM`, or are public facing `BIGNUM`
functions, can be rewritten in the same way as [the `BN_add()` example
above](#wrapping-an-ossl_fn-function-with-a-bignum-function), thereby
functionally separating the dynamic properties of `BIGNUM`s from the less
dynamic properties of  `OSSL_FN`s.

How to apply `OSSL_FN`
======================

[How to apply `OSSL_FN`]: #how-to-apply-ossl_fn

The purpose of `OSSL_FN` is to make the number constant size (implying
enhanced constant time) for a crypto system.  To guarantee this with high
confidence, any function that performs some sort of numeric operation on a
set of input `OSSL_FN`s must only use other functions that only affect the
contents of their `d` array, but not its size.  Those are typically other
`OSSL_FN` functions, or reused bignum functions that receive the `d` array
and its size directly.

Where to apply `OSSL_FN`
========================

[Where to apply `OSSL_FN`]: #where-to-apply-ossl_fn

`OSSL_FN` should primarily be used instead of `BIGNUM` in internal
calculations throughout OpenSSLs libraries.  Exceptions can be made where
calculations aren't security critical.

In this, "calculations" is meant in a mathematical sense, i.e. whatever what
would be expressed as a mathematical formula is considered a "calculation".

However, `BIGNUM` has other uses than mere calculations.  For example,
`BIGNUM` is used as storage of numbers that were originally ASN.1 INTEGERs,
and while individual ASN.1 INTEGERs always have a known size, they are
usually just one number in a set, and it's often only known at a later time
what are the size requirements of the cryptosystem that use them.
For example, the size of an RSA key can only be determined when a known
number in that key - usually *n* - has been seen by code, and this affects
what size all numbers in an RSA key should be adjusted to before doing
calculations on them.

How to apply `OSSL_FN_CTX`
==========================

[How to apply `OSSL_FN_CTX`]: #how-to-apply-ossl_fn_ctx

The variant with frames
-----------------------

[The variant with frames]: #the-variant-with-frames

All internal uses of `BN_CTX_new()` and `BN_CTX_new_ex()` are to be replaced
with calls of `OSSL_FN_CTX_new()`.

All internal uses of `BN_CTX_secure_new()` and `BN_CTX_secure_new_ex()` are to
be replaced with calls of `OSSL_FN_CTX_secure_new()`.

All internal uses of `BN_CTX_free()` are to be replaced with calls of
`OSSL_FN_CTX_free()`.

All internal uses of `BN_CTX_start()` are to be replaced with calls of
`OSSL_FN_CTX_start()`.

All internal uses of `BN_CTX_get()` are to be replaced with calls of
`OSSL_FN_CTX_get()`.

All internal uses of `BN_CTX_end()` are to be replaced with calls of
`OSSL_FN_CTX_end()`.

The variant without frames
--------------------------

[The variant without frames]: #the-variant-without-frames

All internal uses of `BN_CTX_new()`, `BN_CTX_new_ex()`, `BN_CTX_secure_new()`,
`BN_CTX_secure_new_ex()`, and `BN_CTX_free()` are to be dropped.

All internal uses of `BN_CTX_start()` are to be replaced with calls of
`OSSL_FN_CTX_new()`.

All internal uses of `BN_CTX_get()` are to be replaced with calls of
`OSSL_FN_CTX_get()`.

All internal uses of `BN_CTX_end()` are to be replaced with calls of
`OSSL_FN_CTX_free()`.

Testing
=======

[Testing]: #testing

Functional tests similar to `test/recipes/10-test_bn.t` must be added.

Timing tests to compare operations on a variety of inputs of different sizes
must also be added.  These tests should perform operations based on a given
fixed number size.

It should also prove interesting to collect timing statistics for a set of
operations using `BIGNUM` in previous OpenSSL versions and compare them with
similar timing statistics using `BIGNUM` when reimplemented according to this
design.  It is *assumed* that the new statistics will show a higher degree
of constant time, [due to `top` being dropped](#dropping-top-from-bignum),
even though not as much as pure `OSSL_FN` operations.

Appendix
========

[Appendix]: #appendix

Using the C99 flexible array member feature
-------------------------------------------

[Using the C99 flexible array member feature]: #using-the-c99-flexible-array-member-feature

In this design, the C99 feature that's dubbed "flexible array member" is used
extensively.  This a `struct` member that's an array, that must come last in
the struct, and that is incomplete in so far that no array size is given.  It
can look like this:

``` C
struct t {
    size_t a;
    char b;
    char c[]; /**< flexible array member */
};
```

Some attention must be payed to how it's arranged in memory.  It's debated
whether the offset of a flexible array member's offset from the start of the
`struct` is set to be before or after the `struct`'s end padding, i.e. whether
`sizeof(struct t) == offsetof(struct t, c)` is true or not in all circumstances.

Here's how that would differ on a 64-bit system:

| location of `c` | `offsetof(struct t, a)` | `offsetof(struct t, b)` | `offsetof(struct t, c)` | `sizeof(struct t)` |
|-----------------|:-----------------------:|:-----------------------:|:-----------------------:|:------------------:|
| before padding  | 0                       | 8                       | 9                       | 16                 |
| after padding   | 0                       | 8                       | 16                      | 16                 |

To be noted, `gcc` and `clang` favor "before padding".

For consistent placement of the flexible array member, one therefore needs to
pay attention to possible `struct` padding.  Among other methods, one chosen
here is to precede the flexible array member with a member whose type is
assumed to be large enough that no padding is needed after it, such as
`size_t` or a pointer.
