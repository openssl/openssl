OpenSSL Unit Tests
==================

This directory holds the OpenSSL *unit* tests. Their purpose is to test a
single function, or a small group of related functions, in isolation by
replacing the other functions it calls with mocks. This makes it possible to
test logic that is otherwise hard to reach: error and failure paths of
dependencies, branches that depend on the exact arguments passed to a
collaborator, or code whose real dependencies would require network access,
specific hardware, or elaborate setup. Each test can then drive the function
under test through a precise, fully controlled sequence of calls and return
values, and assert on exactly how it interacts with its surroundings.

Unit tests are not meant to replace the broader, integration-style testing that
makes up most of `test/`, and they are not the right tool for everything. They
are used for selected, self-contained pieces of the library where the mocking
boundary is clean and the payoff is high, the BIO layer being the main example.
Most code continues to be tested through the ordinary recipes (typically built
on `testutil`, and generally without mocking).

Requirements
------------

The tests are built on [cmocka], a lightweight C unit-testing framework, and
rely on the GNU/BSD linker's `--wrap` option to intercept calls into the
function under test's dependencies. Because `--wrap` is required, unit tests
are only built on platforms that support it (Linux and BSD only at present),
and only when the build is configured with `enable-unit-tests`.

[cmocka]: https://cmocka.org/

Tests must build and run against cmocka 1.1.5, as that is still the version
shipped by some currently supported enterprise and LTS distributions. Do not
rely on APIs introduced in cmocka 2.x, since a test that needs them cannot be
built on those systems; when in doubt, check against the 1.1.5 headers rather
than the latest online documentation.

Building and Running
--------------------

Unit tests are disabled by default. To build them, configure with
`enable-unit-tests` and make sure the cmocka development files are installed
on the system:

```console
$ sudo apt-get install libcmocka-dev          # Debian/Ubuntu
$ ./config enable-unit-tests
$ make
```

If cmocka is installed in a non-standard location, point the build at it with:

```console
$ ./config enable-unit-tests \
      --with-cmocka-include=/path/to/include \
      --with-cmocka-lib=/path/to/lib
```

On a platform without `--wrap` support, `enable-unit-tests` is silently turned
off during configuration; the rest of the build proceeds normally.

The whole unit-test suite runs as part of the normal test target:

```console
$ make test
```

It is gathered under a single recipe, so it can also be run on its own:

```console
$ make test TESTS=test_unit
```

The recipe discovers every executable named `test_*` under the build's
`test/unit` tree and runs each one, so a newly added test binary is picked up
automatically once it builds. Each binary reports its results in TAP, which the
harness consumes directly.

Because each test is an ordinary standalone executable, it can also be run
directly, which is convenient when debugging a single failure under a debugger:

```console
$ gdb test/unit/crypto/foo/test_bar
```

Running the binary on its own prints its TAP output to the terminal and makes
it straightforward to set breakpoints in a specific test, mock, or in the
function under test.

For debugging it is worth configuring the build with `--debug` as well, e.g.
`./config enable-unit-tests --debug`. A normal build is optimized, which makes
stepping through code and inspecting variables awkward; `--debug` lowers the
optimization level and adds debug information, giving a much more predictable
experience under gdb.

Anatomy of a Unit Test
----------------------

A unit test is a single C source file laid out under `test/unit/` in a path
that mirrors the location of the code it exercises. For example, code that
lives in `crypto/foo/bar.c` is tested by `test/unit/crypto/foo/test_bar.c`. The
file is self-contained: it provides its own `main()`, registers a list of test
cases, and runs them as a cmocka group.

The body of a test file is organised into a few clearly separated sections,
conventionally introduced by short comments, in this order:

  * the `__wrap_*` mock implementations (`/* wraps */`),
  * thin `expect_*` helpers that program each mock (`/* expectations */`),
  * any shared helpers (fake methods, accessors, reset routines),
  * the `setup`/`teardown` fixtures,
  * the test functions themselves, and
  * `main()`, which builds the `CMUnitTest` array and runs it.

Keeping these sections in this order and clearly labelled makes a test file
predictable to read and easy to extend.

### main() and the test list

`main()` declares a `struct CMUnitTest` array, selects TAP output, and runs the
group:

```c
int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_something_simple),
        cmocka_unit_test_setup_teardown(test_with_fixture, setup, teardown),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
```

Always select `CM_OUTPUT_TAP` so the harness can parse the results. Use
`cmocka_unit_test()` for tests that need no per-test fixture, and
`cmocka_unit_test_setup_teardown()` when a test needs a fresh object built
before it and cleaned up after. The last two arguments to
`cmocka_run_group_tests()` are an optional group-level setup and teardown, run
once before and after the whole group; pass `NULL` when they are not needed.

It is common to wrap the registration macros in a short local macro when most
tests share the same fixture, e.g.

```c
#define MY_TEST(name) \
    cmocka_unit_test_setup_teardown(name, setup, teardown)
```

### A test function

Each test is a function with the signature `void (void **state)`. The `state`
argument carries whatever a `setup` fixture stored there; tests that do not use
it should cast it to `void` to silence warnings:

```c
static void test_addr_family(void **state)
{
    BIO_ADDR ap;

    (void)state;
    memset(&ap, 0, sizeof(ap));
    ap.sa.sa_family = AF_INET;
    assert_int_equal(BIO_ADDR_family(&ap), AF_INET);
}
```

Assertions come from cmocka: `assert_int_equal`, `assert_ptr_equal`,
`assert_true`, `assert_false`, `assert_null`, `assert_non_null`,
`assert_string_equal`, `assert_memory_equal`, and friends. A failing assertion
aborts the current test and marks it failed without disturbing the others.

How the Expectation Mechanism Works
-----------------------------------

Before writing mocks it helps to understand what cmocka is actually doing,
because the model is simple once stated plainly and it makes the rest of the
API obvious.

For each `(function, parameter)` pair cmocka keeps an internal queue. The
`expect_*()` macros, called from the test, push values onto these queues. The
`check_expected()` macro, called from inside the mock, pops the next value and
compares it against the argument the mock actually received; a mismatch fails
the test. Return values work the same way: `will_return()` pushes a value from
the test, and `mock_type()`/`mock_ptr_type()` pops it inside the mock to use as
the return value. Call accounting is analogous: `expect_function_call()` pushes
an expected call and `function_called()` consumes one.

So a test programs, in order, the calls it expects the function under test to
make, and the mocks consume those programmed entries as the calls actually
happen. Entries are consumed in the order they were queued, which is why the
`expect_*`/`will_return` calls in a test must be written in the same order the
function under test will call its dependencies. At the end of the test cmocka
fails if any queued entry was never consumed, or if a mock is called with
nothing queued for it. This is what turns the expected interaction sequence
into a checked specification rather than a loose suggestion.

Because each entry covers a single call, a function that is expected to be
called more than once is programmed by pushing the entries that many times, in
the order the calls will occur:

```c
/* the SUT is expected to call BIO_socket twice */
expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, INVALID_SOCKET);
expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, FAKE_SOCKET);
```

cmocka also offers `_count` variants (such as `will_return_count()`,
`expect_value_count()` and `expect_function_calls()`) that program one entry
for a given number of calls in a single statement. These are not just a
shorthand for repeating the macro: they carry a different ordering semantics.
Repeating `expect_function_call()` pins each call's position in the overall
sequence, so any other expected call programmed between two of them must
actually occur between them. `expect_function_calls(f, 2)`, by contrast, only
requires that `f` is called twice somewhere; other calls may fall before,
after, or in between without failing the test. Prefer repeating the plain
macros when the interleaving matters (which is the common case), and reach for
the count variants only when a function is genuinely called many times and its
position relative to the others is not what the test is checking.

Two consequences are worth keeping in mind:

  * **cmocka has nothing to do with `--wrap`.** The expectation machinery is
    just these queues plus the `check_expected`/`mock`/`function_called`
    macros. It works in any function whose body calls them. `--wrap` is merely
    the linker trick OpenSSL uses to *substitute* a dependency with a mock; the
    two are independent. The same `expect_*` style is used below for purpose-
    built fake objects that are never wrapped at all (see Fixtures).

  * Because matching is per parameter and in order, a mock must call
    `check_expected()` for exactly the parameters the test programs with
    `expect_*()`, and the `will_return`/`mock_type` counts must balance.

Mocking Dependencies with --wrap
--------------------------------

The core technique is link-time function interception. When a binary is linked
with `-Wl,--wrap=foo`, every call to `foo` is redirected to a function named
`__wrap_foo`, and the original is still reachable as `__real_foo`. This lets a
test replace the function under test's dependencies with mocks that record how
they were called and return whatever the test dictates.

### Declaring the wraps

The set of wrapped symbols for a test binary is declared in the `build.info`
file (see below). For each wrapped symbol the test file provides a
`__wrap_<name>` function with exactly the same signature as the real one. A
prototype is also needed to satisfy `-Wmissing-prototypes`:

```c
int __wrap_BIO_socket(int domain, int socktype, int protocol, int options);

int __wrap_BIO_socket(int domain, int socktype, int protocol, int options)
{
    function_called();
    check_expected(domain);
    check_expected(socktype);
    check_expected(protocol);
    check_expected(options);
    return mock_type(int);
}
```

A typical mock does three things:

  * `function_called()` records that the function was invoked, balanced against
    the test's `expect_function_call()`.
  * `check_expected(param)` (or `check_expected_ptr(param)` for pointers)
    verifies the argument against the value the test queued. Use the `_ptr`
    variant for pointer parameters.
  * `mock_type(T)` (or `mock_ptr_type(T)` for pointers) returns the value the
    test queued for this call. A `void` mock omits this.

Mocks may also have deliberate side effects when the real function would
produce one that the code under test depends on. For example, a function that
fills a caller-supplied buffer should have its mock write into that buffer, and
a fatal-error reporter that the code expects to flip a state flag should do so:

```c
int __wrap_ssl_fill_hello_random(SSL_CONNECTION *s, int server,
    unsigned char *field, size_t len, DOWNGRADE dgrd)
{
    function_called();
    check_expected_ptr(s);
    check_expected(server);
    check_expected_ptr(field);
    check_expected(len);
    check_expected(dgrd);

    if (field != NULL)
        memset(field, 0xAB, len);

    return mock_type(int);
}
```

Keep these side effects minimal and confined to what the function under test
genuinely observes; the goal is to reproduce the contract of the real function,
not to re-implement it.

### Programming the mocks: expectations

Rather than scatter `expect_function_call`/`expect_value`/`will_return` calls
through every test, wrap each mock in a small `expect_<name>` helper that takes
the expected arguments and the return value. This keeps the tests readable and,
crucially, gives a single place to update when a function's signature or call
contract changes:

```c
static void expect_BIO_socket(int domain, int socktype, int protocol,
    int options, int rc)
{
    expect_function_call(__wrap_BIO_socket);
    expect_value(__wrap_BIO_socket, domain, domain);
    expect_value(__wrap_BIO_socket, socktype, socktype);
    expect_value(__wrap_BIO_socket, protocol, protocol);
    expect_value(__wrap_BIO_socket, options, options);
    will_return(__wrap_BIO_socket, rc);
}
```

The most useful cmocka primitives here are:

  * `expect_function_call(f)`: expect one call to `f`. Pair every
    `function_called()` in a mock with one of these.
  * `expect_value(f, param, value)`: the argument must equal `value`. This is
    consumed by `check_expected(param)`.
  * `expect_any(f, param)`: the argument may be anything; still consumed by
    `check_expected(param)`, so it must be present whenever the mock checks
    that parameter.
  * `will_return(f, value)`: queue a return value for the next call,
    retrieved by `mock_type`/`mock_ptr_type`. Queue several in order if the
    mock pulls more than one value (e.g. a return code followed by an
    out-parameter payload).

When a mock conditionally retrieves a second value, the matching expectation
must queue it under the same condition, so the queues stay aligned:

```c
static void expect_BIO_lookup(BIO_ADDRINFO *res, int rc)
{
    expect_function_call(__wrap_BIO_lookup);
    expect_any(__wrap_BIO_lookup, host);
    expect_any(__wrap_BIO_lookup, service);
    expect_value(__wrap_BIO_lookup, lookup_type, BIO_LOOKUP_SERVER);
    expect_any(__wrap_BIO_lookup, family);
    expect_any(__wrap_BIO_lookup, socktype);
    will_return(__wrap_BIO_lookup, rc);
    if (rc == 1)
        will_return(__wrap_BIO_lookup, res);
}
```

### Writing a test against the mocks

With the helpers in place, a test reads as: arrange the object, declare the
expected sequence of calls, invoke the function under test, and assert on the
result and any observable state.

```c
static void test_socket_then_listen_fails(void **state)
{
    BIO *bio = *state;

    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, FAKE_SOCKET);
    expect_BIO_listen(FAKE_SOCKET, &expected_addr, 0, 0);
    expect_BIO_closesocket(FAKE_SOCKET, 0);

    assert_true(BIO_do_accept(bio) <= 0);
}
```

If the function under test makes a call that was not programmed, or fails to
make one that was, or passes an argument that does not match, cmocka fails the
test and reports the mismatch.

Fixtures and Real Fake Objects
------------------------------

A `setup` function allocates or initialises whatever object the test needs and
stores it through `*state`; the matching `teardown` releases it. Returning
non-zero from either aborts the test as an error.

```c
static int setup(void **state)
{
    BIO *bio = BIO_new(BIO_s_accept());

    assert_non_null(bio);
    *state = bio;
    return 0;
}

static int teardown(void **state)
{
    if (*state != NULL)
        BIO_free(*state);
    return 0;
}
```

A group-level setup/teardown (the last two arguments to
`cmocka_run_group_tests`) is the place for one-time work shared by every test,
such as initialising static fixtures used across the file.

Two practical cautions apply when fixtures interact with wrapped functions:

  * Teardown can itself trigger wrapped calls. If freeing the object under test
    would invoke a wrapped function (for instance, closing a socket), reset the
    relevant fields to safe sentinels before the free so no *unexpected* mock
    call is made, or program the expectation for it. A common pattern is a
    small `reset_for_teardown()` helper called at the end of any test that left
    such state behind.

  * It is often cleaner to drive an object through its public interface with a
    *real* minimal fake than to mock everything. For example, building a small
    fake `BIO_METHOD` whose read/write callbacks are themselves cmocka mocks
    (using the same `function_called`/`check_expected`/`mock_type` machinery,
    even though nothing is wrapped) lets a test exercise the forwarding logic
    of the object under test without wrapping low-level syscalls. Choose
    whichever boundary keeps the test focused on the function actually under
    examination.

Conditional Compilation
------------------------

Mirror the `#ifdef`/`#ifndef` guards of the code under test. If a function only
exists under a build option, guard both the test function and its registration
in `main()` with the same condition, so the suite still builds in every
configuration:

```c
#ifndef OPENSSL_NO_UNIX_SOCK
static void test_addr_make_unix(void **state)
{
    ...
}
#endif

int main(void)
{
    const struct CMUnitTest tests[] = {
#ifndef OPENSSL_NO_UNIX_SOCK
        cmocka_unit_test(test_addr_make_unix),
#endif
        ...
    };
    ...
}
```

When an entire test file only makes sense under some option, guard the whole
body and provide a trivial `main()` for the disabled case so the binary still
links and the recipe still finds something to run:

```c
#ifndef OPENSSL_NO_SOCK

/* ... the tests ... */

#else

int main(void)
{
    return 0;
}

#endif
```

Wiring a New Test into the Build
--------------------------------

Test binaries are declared in `test/unit/build.info`. A unit test that wraps no
symbols would not be linked against cmocka, so **every** unit test must declare
at least one `WRAP[]` entry: this is what causes both the `--wrap` link flags
and `-lcmocka` to be added for that binary. The directives needed per test are
`PROGRAMS`, `SOURCE`, `INCLUDE`, `DEPEND`, and `WRAP`:

```text
PROGRAMS{noinst}=crypto/foo/test_bar
SOURCE[crypto/foo/test_bar]=crypto/foo/test_bar.c
INCLUDE[crypto/foo/test_bar]=../../include ../../include/internal \
                             ../../crypto/foo
DEPEND[crypto/foo/test_bar]=../../libcrypto.a
WRAP[crypto/foo/test_bar]=BIO_socket BIO_listen BIO_closesocket
```

Notes:

  * `PROGRAMS{noinst}` marks the binary as not installed.
  * `INCLUDE[]` lists the directories needed to reach the headers the test
    uses, including any internal directory that declares the types or the
    function under test. The cmocka include path is added automatically to
    every target that has a `WRAP[]` entry, so it need not be listed.
  * `DEPEND[]` links the appropriate static libraries: `../../libcrypto.a`,
    and `../../libssl.a` as well for libssl code.
  * `WRAP[]` is the whitespace-separated list of symbols to intercept; it may
    be split over several lines with trailing backslashes. List exactly the
    dependencies the test mocks.

Because the recipe discovers binaries by name, no change to the Perl recipe is
needed; building the new `test_*` binary is enough for it to run under
`test_unit`.

Generating Mock Stubs with mkwraps.pl
-------------------------------------

Writing the `__wrap_*` and `expect_*` boilerplate by hand for a long `WRAP[]`
list is tedious and error-prone, so the helper script `util/mkwraps.pl`
generates a first draft from the `build.info` declaration. It reads the
`WRAP[<target>]` list, searches the headers under the target's `INCLUDE[]`
directories for each function's prototype, and emits matching wrap functions
and expectation helpers. Functions not found there (typically libc/POSIX
functions such as `read` or `socket`) are looked up under the compiler's
default system include paths, and emitted with angle-bracket includes.

```console
$ ./util/mkwraps.pl --build-info test/unit/build.info \
                    --target crypto/foo/test_bar
```

Useful options:

  * `--mode wraps|expects|both`: emit only the `__wrap_*` functions, only the
    `expect_*` helpers, or both (the default).
  * `--include DIR`: add an extra header search directory beyond those in
    `INCLUDE[]`. Cumulative.
  * `--cc NAME`: C compiler queried for the system include paths (default
    `$CC` or `cc`).
  * `--no-system`: do not fall back to the compiler's system include
    directories for functions missing from the project headers.
  * `--output FILE`: write to a file instead of standard output.
  * `--verbose`: report progress and where each prototype was found.

The output is a *starting point*, not a finished test. The generated mocks call
`function_called()`, check every parameter, and return a `mock_type` value, but
any real behaviour still has to be added by hand: side effects on
out-parameters, variadic forwarding, conditional `will_return` payloads, and
the use of internal headers for opaque types. Generated `#include` lines and
parameter checks frequently need adjusting. Treat the script as a way to skip
the mechanical typing, then review and edit every generated function.

Conventions
-----------

Unit tests follow the usual OpenSSL C coding style (enforced via
clang-format), so it is not repeated here. A few conventions specific to unit
tests keep them consistent and maintainable:

  * Order the file as wraps, expectations, helpers, fixtures, tests, then
    `main()`, with the short section-header comments shown above.
  * Name test functions `test_<area>_<behaviour>` so the suite reads as a list
    of behaviours, and add a brief comment on any test whose setup or expected
    sequence is not obvious from the name.
  * Give every mock a matching `expect_<name>` helper and route all programming
    of that mock through it rather than inlining `expect_value`/`will_return`
    in the tests, so a change to a function's contract is fixed in one place.
  * Keep each test focused on one behaviour, and prefer several small tests
    over one test with many branches.
  * Always emit TAP output, and always reset fixture state that would otherwise
    cause an unexpected wrapped call during teardown.
