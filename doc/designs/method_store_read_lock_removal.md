Removing the method store read lock
===================================

Currently the method store relies heavily on serialization using a rwlock, to
facilitate cache look ups while other threads may be modifying the contents of
the cache.  From https://github.com/openssl/openssl/issues/30659:
```
STARTING!!
rdlockctr: 776798
CRYPTO_EX_READ_LOCK: 242880 (31%)
OSSL_OBJ_READ_LOCK: 30360 (3%)
OSSL_PROPERTY_READ_LOCK: 389620 (50%)
DECODER_CACHE_READ_LOCK: 2530 (0%)
RAND_GET_METHOD_READ_LOCK: 38038 (4%)
DOALL_NAMES_READ_LOCK: 25300 (3%)
X509_STORE_READ_LOCK: 7590 (0%)
BN_MONT_CTX_READ_LOCK: 12650 (1%)
RSA_READ_LOCK: 2530 (0%)
X509_READ_LOCK: 2530 (0%)
OBJ_READ_LOCK: 2530 (0%)
SSL_CONNECTION_READ_LOCK: 5060 (0%)
SSL_SESSION_READ_LOCK: 5060 (0%)
SSL_SESSION_READ_LOCK2: 10120 (1%)
Average time per handshake: 1975.503753us
Handshakes per second: 506.200000
Total handshakes: 2531
```

The property read lock is responsible for 50% of the locks taken in our TLS
handshake test.  While a read lock is fast relative to a mutex (in that it need
not block with respect to other readers), it is still inefficient, in that every
read lock (and corresponding unlock) requires an atomic write to a shared memory
location, which becomes heavily serialized when many readers are attempting to
access shared data, even for read purposes.

Proposal Overview
-----------------

This proposal seeks to eliminate the need to take a read lock during look ups to
the ossl method store.  In doing so, we can avoid the serialization of writes to
the read lock, and improve performance.

To do this, we need to convert the current cache storage (currently a set of
hash tables) to a form that can be accessed using only relaxed atomic reads, and
is only updated using atomic store and atomic compare and exchange operations.
While updating the cache still requires the use of a write lock (to prevent
concurrent updates and the complexities that entails), the read side can safely
traverse any such list without concern for accessing a corrupted pointer in the
list.

Notes on data structure changes
-------------------------------

This proposal seeks to convert the hash tables stored in each `STORED_ALGORITHM`
structure to an array of QUERY * structures.  The array length is arbitrarily
sized to be large enough to allow sharding based on nid value, such that the
length of any given list remains relatively short, so as to prevent long
look ups, while still being small enough to not impact memory usage
significantly.


Notes on QUERY object list traversal/modification
-------------------------------------------------

To ensure that the list pointers remain valid at all times, look ups are
preformed using the following pattern:

```
QUERY *idx;
CRYPTO_atomic_load_ptr(&list_head, &idx, lock);
while (idx != NULL) {
    /* preform read operations on idx */
    CRYPTO_atomic_load_ptr(&idx->next, &idx, lock);
}
```

List inserts and removals (done under traditional write lock to avoid parallel
updates), are preformed using the following (general) pattern:

```
QUERY *new = &newval;
CRYPTO_atomic_load(&list_head, &new->next, lock);
CRYPTO_atomic_cmp_exch(&list_head, &list_head, new, lock);
```

Noting that all inserts to the list occur at the head of the list, for
simplicity.  Given the fact that all look ups to the method store are definitive
(i.e. requiring an exact match on all relevant fields of the method <nid,
provider, propquery>, ordering is not relevant to this data structure.

Removal from the list generally follows this pattern:

```
QUERY *old = &toremove;
QUERY *prev = &previousentry;

CRYPTO_atomic_cmp_exch(&prev->next, &old, old->next, lock);
```
