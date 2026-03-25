OpenSSL Method Store Freezing
=============================

This engineering design document explains our investigation into the
performance of the method store. The investigation results confirmed
our initial hypothesis: to resolve significant performance
bottlenecks, we propose a **freeze function** for the method store to
create a lockless cache.

The investigation found that the primary bottleneck in isolated,
uncached algorithm lookups was not only lock contention, but rather
the overhead of:

- Read locks
- Object copying
- Freeing

These operations consumed up to **80% of execution time**, making
these lookups up to **10 times slower** than legacy methods.
A proof of concept that bypassed this overhead improved performance
from **10× slower** to approximately the same performance as legacy
methods.

The proposed solution involves:

- Creating a **frozen cache** (a lockless dictionary) for method store objects.
- The **freeze function** must be called once in a non-threaded environment.
- The cache eliminates the need for read locks, object copying, and
  freeing during subsequent lookups.
- The system supports optional query strings (e.g., `"?fips=true"`),
  creating a separate frozen cache if needed.
- After freezing, providers cannot be added, modified, or removed.
- Functionality remains otherwise identical.

The next steps include implementing the cache, adding unit tests for
stability and correct behavior, validating the performance gain, and
updating documentation.

Investigating Hashing Performance Using EVP API
-----------------------------------------------

We investigated the performance of hashing using the modern EVP
interface versus the deprecated/legacy interfaces
(https://github.com/openssl/project/issues/1681). A new perftool,
evp_hash, was created to compute hashes using a specified algorithm
(https://github.com/openssl/perftools/pull/58).

Three environments were tested:

1. `deprecated` Worker threads use legacy APIs (e.g., `SHA1_Init`) for
   computation.
2. `evp_isolated` Uses the EVP API. No initial work is done by the
   main thread, and worker threads have no access to shared data. Each
   worker is expected to completely compute a hash using a previously
   unknown algorithm, requiring a full lookup process.
3. `evp_shared` Uses the EVP API. The main thread pre-initializes data
   and shares it with the worker threads, allowing them to use this
   shared data to compute hashes.

Performance Results
-------------------

### SHA256, 1000 Threads

```bash
$ ./evp_hash -o deprecated -a SHA256 1000
Average time per hash: 48.245043us
```

```bash
$ ./evp_hash -o evp_shared -a SHA256 1000
Average time per hash: 53.653964us
```

```bash
$ ./evp_hash -o evp_isolated -a SHA256 1000
Average time per hash: 485.848308us
```

The performance comparison showed a clear hierarchy:

- `deprecated` — fastest
- `evp_shared` — ~10% slower than deprecated
- `evp_isolated` — **~10×** slower than deprecated

Virtually no lock contention was observed (except briefly at program
startup), confirmed using lock contention monitoring.

Deep Dive with Linux perf & Flamegraph
--------------------------------------

Given the significant performance gap in the `evp_isolated` case, we
aimed to analyze the runtime breakdown
(https://github.com/openssl/project/issues/1698). We decided to use
the Linux perf tool with a flamegraph visualization
(https://github.com/brendangregg/FlameGraph).

The perf analysis immediately identified a new primary issue: read
locks and reference-counted copying were taking up to 80% of the total
execution time. This is divided into about 70% for read locks and 30%
for copying. This indicated that the overhead of acquiring and
releasing read locks, as well as copying & managing reference counts
during the method fetching process, was the dominant bottleneck, not
lock contention itself.


Proof of Concept
----------------
Based on the finding that lock/reference-counting overhead was the
main bottleneck, we investigated methods to remove the need for read
locks and reference counting in the evp_isolated case
(https://github.com/openssl/project/issues/1705).

We created a proof of concept implementation for `EVP_DigestInit_ex`
when called with the SHA1 algorithm. The PoC was designed to skip the
general method lookup process and immediately return the corresponding
SHA1 function pointer.

PoC Results:

```bash
$ ./evp_hash -o deprecated -a SHA1 14
Average time per hash: 0.752904us
```

```bash
$ ./evp_hash -o evp_shared -a SHA1 14
Average time per hash: 0.772852us
```

```bash
$ ./evp_hash -o evp_isolated -a SHA1 14
Average time per hash: 0.973133us
```

The performance increase for evp_isolated was dramatic. Its speed
improved from 10x slower than deprecated to only about 1.3x the speed
of deprecated. This confirms that eliminating the overhead of general
lookup that used read locks and reference counting is a highly
effective strategy for improving performance in isolation scenarios.

Solution Goals / Non-Goals
--------------------------

* Primary Objective: Significantly enhance method store performance for isolated scenarios.
* Out-of-Scope: Improving deprecated or shared method performance.
* API Constraints: New API calls or functions are permissible if
  executed before or after the core isolated retrieval process.
* Consistency Constraint: No solution may alter the specific method
  returned for any given query. Correctness and consistency of method
  resolution must be preserved.
* Freezing Mechanism (Permitted Trade-off): The solution may include
  mechanisms that prevent further modifications or changes to the
  method store once a certain state (e.g., "frozen" or "finalized") is
  reached, as a potential trade-off for performance gains.

Method Store Freezing
---------------------

From this investigation, we determined that our initial idea for a
method store freeze could be very beneficial in the `evp_isolated`
case. We continue with our proposal to create a frozen cache for
objects in the method store that is only enabled when a program
manually opts into it.

This frozen cache will likely only be helpful in a situation similar
to `evp_isolated` (i.e., worker threads doing isolated computations),
which might be the case for some high-throughput applications that
can't/don't want to restructure their code to pass data to threads.

Functionality from an application standpoint should be identical both
before and after freezing. The only difference should be in
performance, plus providers can't be added/modified/removed after the
freeze.

Implementation Details
----------------------
* Cache Structure:
  Essentially, it's just a dictionary of strings to function pointers.
* Implementation:
  The frozen cache will be implemented using lockless HT cache.
* Caches for Each Type:
  Most likely need different caches for different types of objects in
  the method store (e.g., digests, algorithms). There should only be
  about 5 types. However, we may be able to use just one cache for all
  types if we’re able to use `ossl_method_store_cache_get`.
  * To effectively manage memory allocations/deallocations, it is
    preferable to maintain type awareness for each object. Performing this
    allocation at the `EVP_<type>_fetch` level ensures the necessary type
    context is available, removing the need for extensive low-level
    modifications.
* Freeze Function Usage:
  * The freeze function must be called from the main thread and in
    non-threaded mode. There’s no reason to call it in threaded
    mode/from a worker thread. We will make sure to mention this in the
    documentation, and that any other implementation may lead to
    undefined behavior.
  * We can spend as much time as needed to create the cache from
    within the main thread.
* Handling Query Strings:
 * The freeze function can receive an optional query string to account
   for the method store's optional query string capability.
 * By default, if the query string is NULL, we will only have 1 frozen
   cache (for the default case).
 * However, if a non-NULL query string is passed, we'll have 2 frozen
   caches (first for the NULL query string, second for the passed query
   string).
 * Other query strings will go through the old internal methods and
   require the current read locks (i.e., be slow).
 * This is primarily to maximize performance for common use cases like
   for applications that want only FIPS algorithms
   (i.e.,"?fips=true"). All other query strings will fall back to the
   standard lookup path.
 * Cache Creation:
   When freezing, we look up all algorithms with the given query
   string (or `NULL` if none) and save everything that's returned into
   the cache.
 * Cache Lifetime:
   The frozen caches will be dynamically allocated inside `OSSL_LIB_CTX` when the freeze
   function is called. When `OSSL_LIB_CTX` is freed, so does frozen cache.
 * Object Flagging:
   When the EVP objects are returned to applications and later freed,
   they will have a special flag set on them (`EVP_ORIG_FROZEN`
   instead of `EVP_ORIG_METH`) so that we know later we don't need to
   free it (i.e., it comes from the long-lived cache).

Implementation V2
=================

This version of freezing will address all outstanding issues.

Note: Maybe the freezing name itself was not chosen right. In a
nutshell, the API call will create immutable store with pre-fetched
algorithms for any `propq` that is bound to a lifetime of
`OSSL_LIB_CTX`.

API change
----------
```c
  int OSSL_LIB_CTX_freeze(OSSL_LIB_CTX *ctx, const char *const *propq, size_t count)
```
or 
```
  int OSSL_LIB_CTX_create_imm_mstore(OSSL_LIB_CTX *ctx, const char *const *propq, size_t count)
```

Any propq can be pre-fetched and stored into frozen/immutable store, not
just one with extra addition to ""/NULL.

```c
const char *propq[] = { "fips=true", "fips=false" };
OSSL_LIB_CTX_freeze(ctx, propq, sizeof(propq), OSSL_NELEM(propq));
```

Retrieval from frozen/immutable method store
--------------------------------------------
```
   EVP_xxx_fetch(...)
     ossl_method_store_get_frozen(store, propq, &method))
        /* nothing has been frozen, fallback  */
        if (store->propq_trie == NULL)
            return;
        HT *frozen_mstore = ossl_trie_get(store->propq_trie, propq);
        /* propq is not frozen, fallback */
        if (frozen_mstore == NULL)
            return;

        /* return method from frozen/imm_mstore if any */
```

How the freeze/immutable store is created
-----------------------------------------

Originally, the freeze method store calls a bunch of `evp_*_fetch_all` to force
load algorithm to the sparse array (SA), and then iterate over the SA to find the
best match for `<nid, propq>`. If method is found, method was duplicated with updated
`->origin` to `EVP_ORIG_FROZEN`, and provider was `up_ref()`-ed.

The requirement for force algo load to method store can be lifted by implementing
`evp_method_data_st` and `ossl_method_construct` that will use
directly `HT<operation_id, algo_name>`.

With that:

* callbacks `dup_method`, and `dup_free_method` could removed from fetch and store_cache
  code path entirely
* remove all restrictions on `OSSL_METHOD_STORE`
