Deferred FIPS Self-Tests
========================

Introduction
------------

This document outlines a design to change how and when FIPS Known Answer
Tests (KATs) and other algorithm self-tests are executed within the OpenSSL
FIPS provider. The goal is to move from the current model, where all
self-tests are run unconditionally at provider load time, to a deferred
model where each test is run conditionally, the first time a specific
cryptographic algorithm is requested for use.

Background
----------

Currently, when the FIPS provider is loaded into the library, it executes
all of the self-tests for all approved algorithms it implements. The
power-on self-tests ensure the module is in a valid state before any
cryptographic operations are performed.

While robust, this approach has a significant drawback: it can introduce a
noticeable latency at application startup, even if the application only
intends to use a small subset of the available FIPS algorithms. For many
applications, this startup cost is undesirable.

The proposed design shifts to a "deferred" self-test execution model. Each
algorithm's self-test will be run only when that algorithm is first requested.
Once a test passes, it will not be run again. This approach aims to minimize
startup latency while maintaining FIPS compliance. FIPS 140-3 IG 10.3.A
"Cryptographic Algorithm Self-Test Requirements" allows for deferring KATs
until the first invocation of the algorithm.

The core module integrity check and certain essential startup tests will
still be performed when the provider is loaded.

Requirements
------------

1. **Conditional Execution**: Each algorithm-specific KAT must be executed
   before the first cryptographic use of that algorithm.
2. **Idempotency**: Once a self-test has been successfully executed for an
   algorithm, it must not be run again. A successful result will be cached.
3. **Failure Handling**: If a self-test fails, the module is put into an
   error state and no other operation will be allowed.
4. **Dependency Management**: The system must handle dependencies between
   algorithms. If a high-level algorithm's self-test depends on a
   lower-level one, the lower-level test must be executed first.
5. **Implicit Dependencies**: Dependency resolution should be implicit. For
   example, when an implementation for a higher-level algorithm (e.g., HMAC)
   initializes a lower-level one it depends on (e.g., SHA-512), the self-test
   for the lower-level algorithm should be triggered automatically if it has
   not already been run.
6. **Thread Safety**: The mechanism for checking test status and running
   tests must be thread-safe.
7. **Equivalency**: If running a KAT for one algorithm also satisfies the
   testing requirements for other algorithms, a mechanism must exist to mark
   all equivalent tests as passed. This is used for example to mark a
   lower-level algorithm test as satisfied where FIPS 140-3 IG 10.3.A Note33
   allows higher-level algorithm tests to implicitly affirm lower-level
   algorithms are good.

Self-Test State Management
--------------------------

A basic mechanism to mark individual tests for deferral and track their state
has been introduced with PR #28725 and will be used as a basis for
implementing a more complete deferral and dependency tracking mechanism as
described in the requirements.

In particular, the state management will be expanded to include equivalency
and explicit dependency requirements.

The FIPS_kat_deferred() function will handle recursing into executing explicit
dependencies if needed, and marking all equivalent tests as passed at once.

This function operates on the basis of locking execution of tests to a single
thread and therefore can safely manipulate the data required to maintain
state across all threads as well as handling ordering of test execution.

Triggering Self-Tests
---------------------

Each algorithm implementation will be modified to trigger its corresponding
self-test at initialization similar to how SLH-DSA tests have already been
changed. This will typically be within the algorithm's `newctx()` or `init()`
function, as this is the earliest point at which an application signals its
intent to use the algorithm.

The self-test state is maintained in a structure of type `FIPS_DEFERRED_TEST`,
this structure will be augmented with an array of pointers to other state
structures of the same type that this test depends on for certification
reasons but would not be otherwise implicitly exercised by test (or perhaps
ordering is important).

Note that recursions are cut short by the fact that calling into a "parent"
test results only in that test being recorded as seen but not processed.

Dependency Handling
-------------------

"Implicit" dependencies will are handled transparently. When calling a high
level algorithm any subordinate algorithm that needs to be used will have
its initialization function called at some point before the originating
algorithm is executed. If those algorithms have not been tested yet this will
trigger their sefl-test.

Note that if there is a need (dictated by certification) to forcibly run a
"dependent" algorithm self-test before the high level algorithm self-test, this
needs to be an explicit dependency in the `depends_on` list of the algorithm's
test definition. During a self-test no other self-tests are executed implicitly
as the machinery that checks for the need to execute self-tests is disabled to
avoid deadlocks (See how `FIPS_kat_deferred()` behaves when it detects that the
current thread is already running a self-test).

OpenSSL functional tests may need to be changed to account for test nesting,
especially when fault injection is implemented.

When `FIPS_kat_deferred()` is executed, the `depends_on` array is checked,
and any test listed in the list is executed in order, while the triggering
test awaits in FIPS_DEFERRED_TEST_IN_PROGRESS state.

Initial Startup Self-Tests
--------------------------

Not all self-tests can be deferred. The FIPS provider will still perform
a minimal set of tests upon loading:

1. **Module Integrity Check**: A HMAC-SHA256 check of the provider module
   itself.
2. **DRBG Tests**: These tests currently depend on temporarily installing
   an alternative TEST random generator, and can't be (in this form)
   executed while other threads may try to access the random generator.

The existing `OSSL_SELF_TEST_onbegin()` callback will be modified to run
only these mandatory startup tests, while the individual algorithm KATs
will be removed from this initial sequence.

Even though these tests will be forcibly executed at module initialization
they will use the same execution architecture via FIPS_DEFERRED_TEST state,
so that they can be depended on by other tests and can mark other tests
passed via equivalency.

Error Handling
--------------

Ideally on a test failure, a FAILED state is recorded in the state structure
for the algorithm, and any dependent failure will propagate upwards through
the dependency chain. An algorithm that is marked failed will immediately
return an error on any subsequent invocation until the operator attempts
error recovery by running all tests again.

However, for simplicity of implementation if an algorithm test fails the
module will be put into an error state, and any further operation will be
denied until the process is restarted.

Examples
--------

The following examples explain how some of the tests interact and can be
ordered to achieve higher efficiency.

### Example 1: simple self-test

For example an application that just uses the SHA-256 digest will not need to
execute any of the HMAC, key derivation or Signature tests, etc...  At
instantiation of the digest (basically when the application calls
EVP_DigestInit[\_ex|\_ex2]) if a SHA-256 specific test has not been run yet,
the init function itself (sha256_internal_init() inside the FIPS module) will
trigger the self-test.

### Example 2: composite algorithms

For composite algorithms, i.e., algorithms that use other internal algorithms
it is possible that a higher level test is considered by the FIPS standard as
satisfying KAT requirements also for the inner algorithm used.

For example the self-test for HMAC is considered sufficient also for testing
the underlying digest. Therefore the current HMAC test (which uses SHA-256)
will invoke the SHA-256 algorithm which will call into the test machinery and
will be recorded as an algorithm invoked by the test.

When the application invokes EVP_MAC_init() it internally causes the FIPS
module hmac_init() function to execute. If the HMAC test has not been run yet
it will be executed.

Once the HMAC test is complete the FIPS_KAT_deferred code will check the
list of additional algorithms invoked as part of the test and will mark each
of them as passed.

### Example 3: simple tests and dependencies behavior

Another example is the use of `depends_on` to run equivalent but broader tests
when that makes sense. For example if we consider the HMAC test as low impact,
we could decide to avoid writing two tests, one for HMAC+SHA-256 and one for
SHA-256 standalone and mark the HMAC test as a dependency for the SHA-256 test.

In this case when the application calls EVP_DigestInit with SHA-256 the internal
sha256_internal_init() will call the machinery to execute the self-test.

This self-test will be an empty function that just returns an error if executed
directly (this is a safety measure to avoid mistakes the function will never be
invoked in normal conditions).  However the actual FIPS_DEFERRED_TEST for
SHA-256 lists the HMAC test as "dependency" in the `depends_on` list.

When FIPS_KAT_deferred is invoked it checks whether there are tests listed in
the depends_on list before executing the actual self-test, and if there are
tests, it executes those first (recursively). It will find the HMAC test and
execute it.  The HMAC test invokes the SHA-256 test and records it, therefore at
the end of the test, the SHA-256 test will be marked as passed and control
returned back up to the calling test. FIPS_KAT_deferred will now check if the
SHA-256 test is already passed. Finding it already passed just returns and never
actually executes the SHA-256 test directly.

Note that this is a special case of using dependencies to satisfy a test via
indirection, in some cases dependencies will just be necessary tests that have
to be run before the current test can be run but do not otherwise necessarily
affect the subsequent running of the depending test.

For example, all tests could mark the integrity test as a depends_on if it were
optional, therefore forcing the integrity test before any other cryptographic
operation could be executed.

Implementation Details
----------------------

### Current Implementation

The current implementation provides the foundational mechanism for deferred
self-tests through two key functions: `FIPS_deferred_self_tests()` and
`FIPS_kat_deferred()`. Together, they ensure that conditional self-tests are
executed in a thread-safe manner.

When a cryptographic algorithm is initialized for the first time, its
implementation calls `FIPS_deferred_self_tests()` with a list of required
tests. This function iterates through the list and, for any test that has
not already passed, calls `FIPS_kat_deferred()` to run it.

The `FIPS_kat_deferred()` function is responsible for the core execution and
synchronization logic. It employs a locking mechanism to handle concurrent
requests from multiple threads. A single, global `CRYPTO_RWLOCK` is used,
and any thread that needs to run a test must acquire an exclusive write lock.
This serializes all self-test executions, guaranteeing that only one test
can run at any given time across the entire FIPS provider.

To handle nested test calls (e.g., an algorithm's test depending on another
primitive) and prevent deadlocks, the mechanism uses thread-local storage.
Before attempting to acquire the global lock, `FIPS_kat_deferred()` checks a
thread-local flag. If the flag is set, it indicates the current thread is
already executing a test, and the function returns immediately with a
`FIPS_DEFERRED_TEST_IN_PROGRESS` status to avoid a recursive lock attempt.

Furthermore, `FIPS_kat_deferred()` uses a double-checked locking pattern to
avoid redundant work. It checks a test's status before acquiring the lock
and checks it again after acquiring it. This efficiently handles the race
condition where another thread completes the test while the current thread
was waiting for the lock. The final test status (`PASSED` or `FAILED`) is
updated within the critical section protected by the lock, ensuring the
result is safely published and visible to all threads.

### Data Structures

The `fips_deferred_test_st` structure will be changed to look like this:

```c
struct fips_deferred_test_st {
    const char *algorithm;
    int category;
    int state;
    struct fips_deferred_test_st *depends_on;
};

```
