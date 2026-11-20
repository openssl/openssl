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
size of a number once it has been allocated.
</p>

</center>

### Table of contents:

- [Background][]
- [Goals][]
- [Challenges][]
- [Design][]
  - [The `OSSL_FSN` type][]
  - [The `OSSL_FSN_CTX` type][]
    - [The `OSSL_FSN_CTX` type, with frames][]
    - [The `OSSL_FSN_CTX` type, without frames][]
  - [The `BIGNUM` type][]
  - [Mutability][]
  - [Memory functionality for `OSSL_FSN`][]
  - [Memory functionality for `OSSL_FSN_CTX`][]
  - [Failures][]
- [Repurposing existing code][]
- [How to apply `OSSL_FSN`][]
- [Where to apply `OSSL_FSN`][]
- [How to apply `OSSL_FSN_CTX`][]
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
  with the `BIGNUM` type, so that a `BIGNUM` may use an `OSSL_FSN` as its
  backing storage and selected call sites may acquire an `OSSL_FSN` view of
  a `BIGNUM`.
* To ensure that the new large number API is constant-size
* To repurpose as much as possible of our current `BIGNUM` code for the new
  large number API, especially our assembler code (with the assumption that
  everything that doesn't change the `BIGNUM` sizes can be repurposed as is)
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

The overall design defines a new type, `OSSL_FSN` (where FSN is short for
"fixed size numbers"), which can somehow be made compatible with `BIGNUM`,
but yet be distinct.  Early thoughts on this was to make them essentially the same type
internally, and cast between them, but unfortunately, a compliant C compiler
is very likely to auto-cast between them, making it difficult to keep them
separate yet castable back and forth.

To allow a stricter or more explicit way to remedy the flexibility of the C
language, this design therefore defines a `OSSL_FSN` which is separate from
the `BIGNUM`, yet compatible with BIGNUM insofar that the `BIGNUM` type
wraps around the `OSSL_FSN` type.

The compatibility is primarily at the storage and acquisition boundary.  A
`BIGNUM` may use an `OSSL_FSN` as its backing storage, and selected internal
crypto call sites that already receive `BIGNUM` values may acquire the
embedded `OSSL_FSN` and perform security-critical calculations with `OSSL_FSN`
functions.

This does not mean that ordinary `BIGNUM` (`BN_`) operation functions are
wrappers around corresponding `OSSL_FSN` operation functions.  `BN_`
functions retain their dynamic `BIGNUM` semantics.  Conversely, once
execution has entered an `OSSL_FSN` operation, that operation must remain
inside the "`OSSL_FSN` only" bubble and must not call functions that take
`BIGNUM` arguments.

This restriction does not apply to low-level helpers that operate only on
`BN_ULONG` arrays or primitive limb values, such as existing `bn_` word
functions.  `BN_ULONG` and `OSSL_FSN_ULONG` are compatible, so such helpers
may be reused by `OSSL_FSN` code as long as they do not allocate, resize, or
otherwise operate on `BIGNUM` objects.

The overall design also defines new associated types to replace their
`BIGNUM` counterparts: `OSSL_FSN_CTX`, `OSSL_FSN_BLINDING`, `OSSL_FSN_MONT_CTX`,
and `OSSL_FSN_RECP_CTX`.  Notably, however, the callback type `BN_GENCB`
isn't replaced, as it contains nothing `BIGNUM`, and can therefore be reused
unchanged with an `OSSL_FSN` API.

The `OSSL_FSN` type and API will be designed in such a way to enable it to
become public at some point in the future.  *The initial version will not be
public and will only be used internally within OpenSSL.*

Let's go over the details

The `OSSL_FSN` type
------------------

[The `OSSL_FSN` type]: #the-ossl_fsn-type

The `OSSL_FSN` type would be a structure derived from the existing `BIGNUM`
type, retaining a minimum amount of data.  Just as was previously with
`BIGNUM`, the absolute value of the number is stored in a `BN_ULONG` array.
`OSSL_FSN` itself is unsigned; sign handling remains with `BIGNUM` when
`BIGNUM` values are used as carriers.

```c
typedef struct ossl_fsn_st OSSL_FSN;

struct ossl_fsn_st {
    /* Flag: alloced with OSSL_FSN_new() or  OSSL_FSN_secure_new() */
    unsigned int is_dynamically_allocated : 1;
    /* Flag: alloced with OSSL_FSN_secure_new() */
    unsigned int is_securely_allocated : 1;

    /*
     * The d array, with its size in number of BN_ULONG.
     * This stores the number itself
     */
    size_t dsize;
    BN_ULONG d[];
};
```

The `OSSL_FSN_CTX` type
----------------------

[The `OSSL_FSN_CTX` type]: #the-ossl_fsn_ctx-type

The `OSSL_FSN_CTX` type is made to replace the `BN_CTX` type where `OSSL_FSN`
type is used instead of `BIGNUM`.

The `OSSL_FSN_CTX` type is to be implemented as an arena (a large enough chunk
of memory) in which `OSSL_FSN` instances are allocated.  More in detail, there
are two possibilities.

### The `OSSL_FSN_CTX` type, with frames

[The `OSSL_FSN_CTX` type, with frames]: #the-ossl_fsn_ctx-type-with-frames

This variant is intended to mimic all `BN_CTX` functionality.  The idea is to
create a large `OSSL_FSN_CTX` at the top function of a complex calculation, and
pass it around to all sub-function calls.

Each sub-function would begin with starting a frame (using `OSSL_FSN_CTX_begin()`,
similar in spirit to `BN_CTX_start()`) in the passed `OSSL_FSN_CTX` arena,
obtain what temporary `OSSL_FSN`s it needs from it (using `OSSL_FSN_CTX_get()`,
similar in spirit to `BN_CTX_get()`), perform what calculations it needs, and
finish with ending the frame (using `OSSL_FSN_CTX_end()`, similar in spirit to
`BN_CTX_end()`), which relinquishing that frame's space in the `OSSL_FSN_CTX`
arena, and thereby making that same space available for the next sub-function.

```c
typedef struct ossl_fsn_ctx_st OSSL_FSN_CTX;

struct ossl_fsn_ctx_frame_st; /* forwarding, see below */
struct ossl_fsn_ctx_st {
    /*
     * Pointer to the last OSSL_FSN_CTX_start() location (a simple pointer into
     * the memory area).  See the struct ossl_fsn_ctx_frame_st definition below
     * for details.
     */
    struct ossl_fsn_ctx_frame_st *last_frame;
    /*
     * The arena itself.
     */
    size_t msize; /* bytes */
    unsigned char memory[];
};

struct ossl_fsn_ctx_frame_st {
    /*
     * Pointer back to the whole arena where the frame is located, to access
     * |msize| and |memory| from it.
     */
    struct ossl_fsn_ctx_st *arena;
    /*
     * Pointer to the previous frame in the arena, allowing OSSL_FSN_CTX_end()
     * to do its job.
     */
    struct ossl_fsn_ctx_frame_st *previous_frame;
    /*
     * Pointer to the free area of the frame.  Every time OSSL_FSN_CTX_get() is
     * called, the current value of this pointer is returned, and it's updated
     * by incrementing it by the number of bytes given by OSSL_FSN_CTX_get().
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

### The `OSSL_FSN_CTX` type, without frames

[The `OSSL_FSN_CTX` type, without frames]: #the-ossl_fsn_ctx-type-without-frames

Compared to the variant with frames, this `OSSL_FSN_CTX` variant is much
simpler, but also more heap allocation intense.

The idea with this one is that each function that needs to obtain temporary
`OSSL_FSN`s would also create their own `OSSL_FSN_CTX`, independently from any
other function.

```c
typedef struct ossl_fsn_ctx_st OSSL_FSN_CTX;

struct ossl_fsn_ctx_st {
    /*
     * Pointer to the free area of the arena.  Every time OSSL_FSN_CTX_get() is
     * called, the current value of this pointer is returned, and it's updated
     * by incrementing it by the number of bytes given by OSSL_FSN_CTX_get().
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

There are a few types that, like `BN_CTX` / `OSSL_FSN_CTX`, are used to hold
a context around some more complicated calculations.  Just like `OSSL_FSN_CTX`,
The `OSSL_FSN` variants of these types are made into strictly separate types,
not compatible with their `BIGNUM` counterparts.

| `BIGNUM` types | `OSSL_FSN` types    |
|----------------|--------------------|
| `BN_BLINDING`  | `OSSL_FSN_BLINDING` |
| `BN_MONT_CTX`  | `OSSL_FSN_MONT_CTX` |
| `BN_RECP_CTX`  | `OSSL_FSN_RECP_CTX` |

Their `OSSL_FSN` APIs for these types should be possible to create by
repurposing the corresponding `BIGNUM` APIs, with adjustments for the
constant-size requirements of all `OSSL_FSN` functions.

The `BIGNUM` type
-----------------

[The `BIGNUM` type]: #the-bignum-type

The `BIGNUM` type is changed to include a `OSSL_FSN` for its data, while
retaining the fields that support the dynamic `BIGNUM` semantics:

```c
struct bignum_st {
    OSSL_FSN *data;
    /* Some of these flags are replicated in OSSL_FSN, some are not */
    int flags;

    BN_ULONG *d; /* Pointer to |data->d| */
    int top; /* Index of last used d +1. */
    int dmax; /* Copy of |data->dsize| */
    int neg; /* One if the number is negative */
};
```

In normal public use, `data` is non-NULL and `d` points at `data->d`.
Certain internal or otherwise special `BIGNUM`s may still have `data` set to
NULL, in which case `d` points directly at a `BN_ULONG` array.  Such cases
must not be forced to grow an `OSSL_FSN` backing object solely to fit this
structure.  How `OSSL_FSN` code should use the `BN_ULONG` data from such
`BIGNUM`s remains an implementation detail.

When structured this way, it's easy to get an `OSSL_FSN` out of a `BIGNUM`:

```c
/*
 * BN_acquire_fsn() and BN_release_fsn() function together.  It is done this
 * way as a safety measure, to make sure that a BIGNUM doesn't expand an OSSL_FSN
 * that the caller currently has a handle on.  However, it's possible to
 * adjust the size of the OSSL_FSN while acquiring it.
 */
OSSL_FSN *BN_acquire_fsn(BIGNUM *a, size_t bits)
{
    if ((bn_expand(a, bits)) <= 0)
        return NULL;
    /* Implementation may do further acquisition bookkeeping here. */
    return a->data;
}
void BN_release_fsn(BIGNUM *a)
{
    /* Implementation may do further release bookkeeping here. */
}
```

Note that these functions are not designed to be thread-safe.  By design,
holding pointers to a `BIGNUM` and its wrapped `OSSL_FSN` at the same time
should only happen in a very short term.

Mutability
----------

[Mutability]: #mutability

The understanding is that within a `OSSL_FSN` API, `dsize` is immutable as
soon as a `OSSL_FSN` has been allocated to its target size, except for when
the `OSSL_FSN` instance is freed.

When accessed through the `BIGNUM` type (i.e. by the `BIGNUM` API), the
`OSSL_FSN` size may be reallocated to allow a larger size than initially
allocated, and `dsize` may be modified accordingly.  The exception is an
acquired `OSSL_FSN` view.  Once a caller has acquired the backing `OSSL_FSN`
from a `BIGNUM`, that backing size must be treated as immutable until
release.  The owning `BIGNUM` must not simultaneously be used through `BN_`
operations that could resize or otherwise reinterpret the same storage.

The `OSSL_FSN_CTX`  API is much more strict.  The size of an `OSSL_FSN_CTX`
instance is immutable after it has been allocated, except when it is freed.

Memory functionality for `OSSL_FSN`
----------------------------------

[Memory functionality for `OSSL_FSN`]: #memory-functionality-for-ossl_fsn

We anticipate that we will need the following functions to allocate and
deallocate `OSSL_FSN`s:

```c
OSSL_FSN *OSSL_FSN_new(size_t size);
void OSSL_FSN_free(OSSL_FSN *f);
```

Memory functionality for `OSSL_FSN_CTX`
--------------------------------------

[Memory functionality for `OSSL_FSN_CTX`]: #memory-functionality-for-ossl_fsn_ctx

We anticipate that the `OSSL_FSN_CTX` API will look very much like the
`BN_CTX` API, except for the allocation functionality:

```c
OSSL_FSN_CTX *OSSL_FSN_CTX_new(OSSL_LIB_CTX *libctx, size_t arena_size);
OSSL_FSN_CTX *OSSL_FSN_CTX_secure_new(OSSL_LIB_CTX *libctx, size_t arena_size);
void OSSL_FSN_CTX_free(OSSL_FSN_CTX *ctx);

OSSL_FSN *OSSL_FSN_CTX_get(OSSL_FSN_CTX *ctx, size_t size);
```

*Something to be noted is that `OSSL_FSN_CTX_secure_new()` allocates the
whole arena in secure memory.  The impact compared to allocating individual
`OSSL_FSN` instances in secure memory is considered minimal.*

If the variant of `OSSL_FSN_CTX` *with frames* is chosen, the following
functions will also have to be defined:

```c
int OSSL_FSN_CTX_start(OSSL_FSN_CTX *ctx);
int OSSL_FSN_CTX_end(OSSL_FSN_CTX *ctx);
```

Failures
--------

[Failures]: #failures

A fixed size large number introduces new problems, which introduces new ways
that the `OSSL_FSN` API can fail:

* Overflow: this will happen when the caller has allocated an improperly
  sized `OSSL_FSN` to store future calculation results in.  *This is akin to
  memory allocation failures in so far that there isn't enough memory space*

Repurposing existing code
=========================

[Repurposing existing code]: #repurposing-existing-code

A majority of existing internal `BIGNUM` code operates directly on the `d`
array of the existing `BIGNUM` structure, with the size of that array given
separately, and are already essentially operating on fixed size numbers.
This design assumes that such functions can be repurposed for `OSSL_FSN`
functionality with zero change, apart from function name changes.

Furthermore, the remaining functions, which do manipulate the size of the
`BIGNUM`, or are public facing `BIGNUM` functions, retain their current
`BIGNUM` functionality, including size manipulation within the `BIGNUM`
"bubble".  They are not wrapped around `OSSL_FSN` functions; conversion
between `BIGNUM` and `OSSL_FSN` happens at top-level crypto call sites,
where the embedded `OSSL_FSN` is acquired and passed to `OSSL_FSN`
functions, during whose execution the `OSSL_FSN` size is immutable (see
[Mutability][]).

How to apply `OSSL_FSN`
======================

[How to apply `OSSL_FSN`]: #how-to-apply-ossl_fsn

The purpose of `OSSL_FSN` is to make the number constant size (implying
enhanced constant time) for a crypto system.  To guarantee this with high
confidence, any function that performs some sort of numeric operation on a
set of input `OSSL_FSN`s must only use other functions that only affect the
contents of their `d` array, but not its size.  Those are typically other
`OSSL_FSN` functions, or reused bignum functions that receive the `d` array
and its size directly.

Where to apply `OSSL_FSN`
========================

[Where to apply `OSSL_FSN`]: #where-to-apply-ossl_fsn

`OSSL_FSN` should primarily be used instead of `BIGNUM` in internal
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

How to apply `OSSL_FSN_CTX`
==========================

[How to apply `OSSL_FSN_CTX`]: #how-to-apply-ossl_fsn_ctx

The variant with frames
-----------------------

[The variant with frames]: #the-variant-with-frames

All internal uses of `BN_CTX_new()` and `BN_CTX_new_ex()` are to be replaced
with calls of `OSSL_FSN_CTX_new()`.

All internal uses of `BN_CTX_secure_new()` and `BN_CTX_secure_new_ex()` are to
be replaced with calls of `OSSL_FSN_CTX_secure_new()`.

All internal uses of `BN_CTX_free()` are to be replaced with calls of
`OSSL_FSN_CTX_free()`.

All internal uses of `BN_CTX_start()` are to be replaced with calls of
`OSSL_FSN_CTX_start()`.

All internal uses of `BN_CTX_get()` are to be replaced with calls of
`OSSL_FSN_CTX_get()`.

All internal uses of `BN_CTX_end()` are to be replaced with calls of
`OSSL_FSN_CTX_end()`.

The variant without frames
--------------------------

[The variant without frames]: #the-variant-without-frames

All internal uses of `BN_CTX_new()`, `BN_CTX_new_ex()`, `BN_CTX_secure_new()`,
`BN_CTX_secure_new_ex()`, and `BN_CTX_free()` are to be dropped.

All internal uses of `BN_CTX_start()` are to be replaced with calls of
`OSSL_FSN_CTX_new()`.

All internal uses of `BN_CTX_get()` are to be replaced with calls of
`OSSL_FSN_CTX_get()`.

All internal uses of `BN_CTX_end()` are to be replaced with calls of
`OSSL_FSN_CTX_free()`.

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
design.

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

Some attention must be paid to how it's arranged in memory.  It's debated
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
