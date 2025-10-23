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
3. **Failure Handling**: If a self-test fails, the corresponding algorithm
   must be immediately disabled and put into an error state. Any attempt
   to use it must fail. This error state should be permanent.
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

In particular the state management will be expanded to include equivalency
and explicit dependency requirements.

The FIPS_kat_deferred() function will handle recursing into executing explicit
dependencies if needed, and marking all equivalent tests as passed at once.

This function operates on the basis of locking execution of tests to a single
thread and therefore can safely manipulate the data required to maintain
state across all threads as well as handling ordering of tests execution.

Triggering Self-Tests
---------------------

Each algorithm implementation will be modified to trigger its corresponding
self-test at initialization similar to how SLH-DSA test have already been
changed. This will typically be within the algorithm's `newctx()` or `init()`
function, as this is the earliest point at which an application signals its
intent to use the algorithm.

The self-test state is maintained in a structure of type `FIPS_DEFERRED_TEST`,
this structure will be augmented with two arrays of pointers to other state
structures of the same type.

One will handle test equivalency and will be named 'also_satisfies', the other
will handle explicit dependencies that are not implicitly handled by
initialization functions.

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

OpenSSL functional test may need to be changed to account for test nesting,
especially when fault injection is implemented.

When `FIPS_kat_deferred()` is executed, the `depends_on` array is checked,
and any test listed in the list is executed in order, while the triggering
test is awaits in FIPS_DEFERRED_TEST_IN_PROGRESS state.

Initial Startup Self-Tests
-------------------------

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
passed via equivalency (`also_satisfies` lists).

Error Handling
--------------

On test failure, a FAILED state is recorded in the state structure for the
algorithm, and any dependent failure will propagate upwards through the
dependency chain. An algorithm that is marked failed will immediately return
an error on any subsequent invocation.

Implementation Details
----------------------

Data Structures
---------------

The  fips_deferred_test_st structure will be changed to look like this:

```c
struct fips_deferred_test_st {
    const char *algorithm;
    int category;
    int state;
    struct fips_deferred_test_st *also_satisfies;
    struct fips_deferred_test_st *depends_on;
};

```
