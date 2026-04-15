EVP refcounting minimization design
===================================

Currently, EVP_* objects (MD/CIPHER/etc), potentially experience significant
refcount mutation (that is to say, applications may fetch an EVP object once and
share that object with multiple other threads.  This necessitates the atomic
mutation of the objects reference count using an `__ATOMIC_ACQ_REL` ordering
constraint, which can have significant performance impact.  This proposal seeks
to minimize the amount of reference counting needed on any fetched EVP objects,
improving performance.

Proposal Overview
-----------------

Currently, EVP objects are allocated and cached when they don't yet exist (with
a reference count of 1).  And freed when their reference count reaches 0.  A
zero reference count event may occur if:

a) The method store cache culls that cached EVP method
b) All threads which have fetched that EVP object call `EVP_<method>_free` on
the object.

During that time, calling threads may share that object with other threads by
using the `EVP_<method>_up_ref` API call, which introduces significant cache
line contention.  This proposal seeks to transform all `EVP_<method>_up_ref` and
`EVP_<method>_free` calls into no-ops, eliminating the identified cache
contention in the CPU.


To achieve this, the following is proposed:

1) Ensure that, while providers may be deactivated with a call to
`OSSL_PROVIDER_unload`, the provider DSO will remain memory resident until any
libctx objects which have loaded the provider are themselves freed.

2) Ensure that any EVP objects that are allocated and placed in the method store
cache are not freed until such time as the libctx which allocated the method
store is itself freed.

3) Convert all `EVP_<method>_up_ref` and `EVP_<method_free` to be no-ops.
Refcounting will only be preformed on insertion to and removal from the method
store cache associated with the libctx that preformed the lookup. 

Notes on provider lifetime
--------------------------

Currently it is possible to unload and free a provider from a libctx via a
single call to `OSSL_PROVIDER_unload`.  This creates a problem in that (a)
Preforming an unload (which can happen at any time), necessitates a method store
cache flush, removing any EVP objects which were allocated.  This operation is
what seems to have driven the need for EVP object reference counting initially
(as outstanding EVP objects still needed access to the provider).  By
instructing the loading of a provider to a libctx to claim an extra refcount on
the provider (on behalf of the libctx), we can ensure that, when a provider is
unloaded it becomes deactivated (preventing any future look ups from taking place
against it), while still allowing outstanding EVP objects to make use of the
provider.

Notes on EVP object free deferral
--------------------------------

With the goal of not having to refcount EVP objects outside of the method store,
we need to ensure that, on provider unload/deactivation, we no longer allow
look ups to that provider, while still ensuring that exiting issued EVP objects
remain usable (i.e. we need to avoid use after free conditions on these EVP
objects).  To do so, the method store cache can be modified such that, where
methods were previously freed, they are now instead, removed from the cache, and
placed in an 'attic'.  This attic is simply a linked list of objects that have
been removed from the cache, and are awaiting a call to `ossl_method_store_free`
to be guaranteed that there are no more users of this object, at which point
they can finally be cleaned up.

Notes on EVP object usage after libctx free
-------------------------------------------

It was mentioned during the development of this proposal, that there may be a
use case in which:

1) Thread A fetches an EVP object
2) Increments the ref count of that object
3) Passes that EVP object to Thread B for further use
4) Frees the libctx from which the object was allocated.

It was asserted that, in the above use case, under the current implementation
this might be allowed, as the EVP object would ensure that that the provider
remained resident, and that under this proposal the same use case would result
in a use after free error, as the freeing of the libctx object would drive the
freeing of the EVP object.

I assert that the above use case is however a programming error.  This is due to
the provider use of the `PROV_LIBCTX_OF` macro.  Providers, as part of their
initialization, may (and often do) store a handle to the libctx that they are
being created against, and any use of that libctx in the above use case would
result in a similar use after free segfault.  Not all providers store this
handle, and as such, the use case may work, but some providers do, so in short,
if the above use case works, it is by good fortune rather than design.
