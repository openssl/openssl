ClientHello Extension Ordering
==============================

This document proposes an opt-in, application-controlled callback that changes
the order in which TLS extensions are emitted. It allows fixed and
per-connection orders without OpenSSL shipping browser profiles or fingerprint
databases. With no callback the wire output must stay byte-for-byte unchanged.
The design covers built-in and custom extensions, `pre_shared_key`, GREASE, ECH
and HelloRetryRequest.

Problem statement
-----------------

### TLS fingerprinting

The ClientHello is clear text unless ECH is used, so its extension set and
order are visible to the server and any on-path observer. Extension order feeds
JA3-style fingerprinting, used for bot detection, censorship and differential
treatment of non-browser clients.

The request came from [issue #19220][issue19220], after Node.js discussion of
rewriting the ClientHello after construction. Rewriting changes the transcript
hash, breaks the Finished MAC and is especially dangerous with ECH.

### Current OpenSSL behaviour

OpenSSL builds extensions from the fixed `ext_defs[]` table in
`ssl/statem/extensions.c`; order matters because constructors, parsers and
finalisers can depend on earlier extensions. Custom extensions registered with
`SSL_CTX_add_custom_ext()` are emitted first, before the `ext_defs[]` loop.

There is no public API to change this: applications can add custom extensions
but cannot move them relative to built-ins or reorder built-ins. BoringSSL's
`SSL_set_permute_extensions()` randomises only a fixed subset and ignores
custom extensions.

Requirements
------------

### Goals

- Provide a generic, opt-in API for built-in and custom extensions, with fixed
  and random permutations.
- Leave the default wire output byte-for-byte unchanged when no callback is set.
- Preserve protocol constraints: `pre_shared_key` last in the ClientHello,
  ECH compression contiguity, GREASE and HelloRetryRequest behaviour.
- Validate the result and fail safely on an invalid permutation.
- Allow configuration per `SSL_CTX` and per `SSL`, with clear ownership and
  lifetime rules.
- Be usable by TLS 1.2, TLS 1.3, DTLS and QUIC clients.

### Non-goals

- This is not security: it is obfuscation, not a defence against a determined
  fingerprinter.
- OpenSSL will not ship browser fingerprints, profiles or a ClientHello layout
  database, and will not track browser changes.
- The API does not change extension values, cipher suites, groups, signature
  algorithms, ALPN, GREASE policy or ECH configuration. It only changes order.
- There is no guarantee that a given order defeats fingerprinting or stays
  stable across OpenSSL versions; server-side order is out of scope for v1.

Proposal
--------

### API

```c
typedef int (*SSL_ext_reorder_cb)(SSL *s, unsigned int context,
    const uint16_t *exts, const unsigned char *present,
    uint16_t *order, size_t len, X509 *x, size_t chainidx, void *arg);

void SSL_CTX_set_ext_reorder_cb(SSL_CTX *ctx, SSL_ext_reorder_cb cb, void *arg);
void SSL_set_ext_reorder_cb(SSL *s, SSL_ext_reorder_cb cb, void *arg);
```

The prototype uses `const BIGNUM *present`; this document proposes a byte-array
bitset (see [Representation of present](#representation-of-present)).
`SSL_set_ext_reorder_cb()` overrides the `SSL_CTX` value; `NULL` disables it
for that object, and `arg` is borrowed and must outlive every handshake.

### Callback contract

On entry, `exts` holds `len` wire types, `present` is a bitset and `order` is
the identity permutation. Rearrange `order` in place; return 1 on success.

Custom extensions come first, then built-ins in `ext_defs[]` order; disabled
built-ins may appear as type 0 with a clear bit.

Bit `n` is set when extension `n` is a candidate:

```c
present[n / 8] & (1u << (n % 8))
```

A set bit means "may be sent", not "will be sent": constructors can return
`EXT_RETURN_NOT_SENT` and some relevant extensions have no constructor. A
clear bit means it will not be sent.

`order` is a full permutation. OpenSSL walks it and emits only present entries;
the callback cannot add or remove extensions. It may inspect `context`, `x`
and `chainidx` (always `NULL`/0 in v1).

### Validation and errors

OpenSSL validates that `order` is a permutation of `0..len-1`: every index in
range, each exactly once, plus the `pre_shared_key` rule. Returning 0 raises
`SSL_R_CALLBACK_FAILED`; an invalid permutation raises
`ERR_R_PASSED_INVALID_ARGUMENT` or a new `SSL_R_EXT_ORDER_INVALID`. Both abort
with `internal_error`; there is no silent fallback. The callback gets no
`int *al`, so it cannot choose the alert.

### Invocation points and v1 scope

All extension construction uses `tls_construct_extensions()` for ClientHello,
ServerHello, EncryptedExtensions, CertificateRequest, Certificate and
NewSessionTicket; the prototype invokes the callback for all.

This document recommends v1 for `SSL_EXT_CLIENT_HELLO` only, including the
second ClientHello after HelloRetryRequest; `context` remains for future
messages. The feature targets client fingerprinting, so server order has no
privacy benefit, and other messages have different rules (`pre_shared_key` may
appear anywhere in ServerHello, Certificate extensions are per-certificate).
The prototype implements the generic form, but each context needs its own
tests; on a server `SSL_CTX` it has no effect in v1.

### Protocol constraints

#### pre_shared_key must be last

RFC 8446 section 4.2.11 and RFC 9846 section 4.3.11 require `pre_shared_key`
last; a server rejects otherwise with `illegal_parameter`. After the callback,
if the candidate bit is set it must be the last present extension in `order`;
if clear there is no constraint.

Candidate presence is conservative: a later `EXT_RETURN_NOT_SENT` still had to
be last. The check applies only when TLS 1.3 PSK is possible; TLS 1.2 has no
such extension. The prototype wrongly requires it when PSK is not sent.

#### Padding

RFC 7685 defines the legacy padding extension. In OpenSSL 3.4 and earlier it is
generated after the others because its length depends on bytes already written,
so it must be last or immediately before `pre_shared_key`; a callback cannot
compute that length.

OpenSSL 4.1 and later no longer emit it and `SSL_OP_TLSEXT_PADDING` is a no-op,
so there is no built-in slot. If padding returns or is a custom extension,
OpenSSL-generated padding is appended after the ordered extensions;
application padding is the application's responsibility.

#### GREASE

RFC 8701 GREASE stops peers assuming a fixed set or order. OpenSSL has two
GREASE slots with per-handshake wire types; the callback sees the concrete
types and may place them anywhere, but OpenSSL must not regenerate a type
afterwards. Intersperse GREASE; GREASE in cipher suites, groups, signature
algorithms and versions is independent.

#### ECH

ECH (RFC 9849) has an outer and an encoded inner ClientHello. Extensions
compressed from the outer are listed in `outer_extensions`; that extension and
the referenced extensions must be contiguous in the inner ClientHello, in outer
order.

For v1, invoke the callback for the inner ClientHello and cache the type order,
then apply the same type order to the outer without reusing indices (the arrays
and `len` can differ). Construct compressed extensions first so
`outer_extensions` stays contiguous. The inner order is the `outer_extensions`
list first, in the callback's relative order, then the remaining types. The
fallback is to reject real ECH when ordering is set, while still allowing ECH
GREASE, which has no inner ClientHello.

#### HelloRetryRequest

The second ClientHello is new: `cookie` appears and `key_share` may change. The
callback runs again and the `pre_shared_key` rule applies. Derive randomness
from per-connection state for a stable order; a different second order is legal
but changes the fingerprint.

#### Custom extensions

Custom extensions are slots at the front of `exts[]` and can move anywhere.
OpenSSL must call each add callback exactly once per handshake, in emission
order, and not for a skipped extension; this requires refactoring
`custom_ext_add()` into a per-extension helper (`custom_ext_add_one()`). Add
callbacks may have side effects, so their order changes the order of those
effects; this is inherent and must be documented.

### Thread safety and reentrancy

The callback runs synchronously on the handshake thread. No per-`SSL` lock is
held, and the application must not use the same `SSL` or `SSL_CTX`
concurrently. It must not call mutating APIs (`SSL_set_*`, `SSL_CTX_set_*`,
`SSL_clear()`, `SSL_free()`, another handshake); read-only queries are
acceptable. Do not retain `exts`, `present` or `order` pointers beyond the
call. `arg` is shared across connections if installed on an `SSL_CTX`;
synchronise or keep per-connection state in `SSL` ex-data. It may run more than
once per connection (HelloRetryRequest, ECH inner, DTLS retransmission), so it
must be reentrant.

### Compatibility

With no callback the path must be unchanged: same order, GREASE, padding and
ECH output. Add a regression test capturing ClientHello bytes across a
configuration matrix with no callback and with an identity callback.

The only ABI changes are the typedef and two setters. Symbols need
`util/libssl.num` and `make update`. Check the prototype's ECH loop refactor:
it changes two passes to one for the outer ClientHello. If the default outer
order changes, the no-callback path must keep the original two-pass behaviour.

Alternatives considered
-----------------------

### BoringSSL-style permutation option

BoringSSL's `SSL_CTX_set_permute_extensions()` and
`SSL_set_permute_extensions()` randomise a fixed subset and ignore custom
extensions. They cannot express a fixed order or place custom extensions, so
they are insufficient; a compatible convenience option could be added later.

### Post-construction reordering

Construct all extensions canonically, parse the type-length-value records and
re-emit them in the requested order. This knows exact presence, runs
constructors in order, sizes padding correctly and places `pre_shared_key` last
trivially. But parsing, re-encoding, fixing lengths, preserving ECH references
and keeping the transcript consistent is larger and riskier than permuting
construction order. A fallback, not the first choice.

### Allow-list versus permutation-only

An allow-list (types in the desired order, unspecified types appended or
rejected) is easier to configure but cannot express every order, silently
changes meaning when OpenSSL adds an extension, and needs a rule for
present-but-unlisted extensions. A full permutation is explicit, validates
cleanly and supports fixed and random strategies; the example helper keeps the
ergonomic advantage.

### String, array and fixed-seed options

A string such as `"0x44cd:0x000a:0x000b"` or an array of types is easy to
configure from a file, but needs parsing in OpenSSL, has no place for
per-connection randomness or `context`, and makes error reporting awkward. A
library-level seed still needs a strategy and would impose policy. The
callback's `arg` lets an application implement a deterministic seed, a random
stream or a fixed order without new state.

API maintenance considerations
-----------------------------

### New extensions and version drift

Adding a built-in extension changes `len`, the `exts[]` layout and the
`present` bits, so a callback assuming a fixed set or length will break.
Applications needing a precise fingerprint must detect the OpenSSL version and
configuration and test against it; no stability is promised. Write callbacks
defensively: iterate over `len`, use `exts[n]`, and append unknown types in
default relative order.

### Representation of present

Three representations are plausible:

- `BIGNUM` (the prototype): convenient internally, but heavyweight in a public
  callback (dependency, allocation, ownership, awkward bindings, implicit bit
  order).
- Byte-array bitset: `const unsigned char *present`, `(len + 7) / 8` bytes,
  bit `n` at `present[n / 8] >> (n % 8)`. Compact, allocation-free, ABI-stable
  and easy to bind. Recommended.
- Array of structures: `struct { uint16_t type; unsigned int present; }`.
  Most ergonomic, but changes the callback shape and makes future extension an
  ABI question.

Replace the prototype's `BIGNUM` with the byte-array bitset before merge, or
confirm the choice.

### Naming

`SSL_ext_reorder_cb`, `SSL_CTX_set_ext_reorder_cb` and
`SSL_set_ext_reorder_cb` are consistent with the prototype and describe fixed
ordering and permutation. `SSL_ext_order_cb` is shorter but can be confused
with a getter; `SSL_extension_order_cb` is verbose. Keeping `ext_reorder` is
reasonable unless reviewers prefer a rename before the API is frozen.

### Documentation and tests

The implementation needs a man page (`doc/man3/SSL_CTX_set_ext_reorder_cb.pod`),
SSL documentation, `CHANGES.md` and `NEWS.md` entries, and this design
document. Tests should cover default output with no callback and an identity
callback; fixed and shuffled orders, custom extensions and add-callback counts;
`pre_shared_key` last with and without a PSK and in TLS 1.2; GREASE and real
ECH inner/outer; HelloRetryRequest, TLS 1.2/1.3, DTLS and QUIC; invalid
permutations; and callback and allocation failures.

Examples
--------

This callback puts chosen types first, leaves the rest in default order, and
moves `pre_shared_key` last when present; it is not a browser profile.

```c
static int fixed_order_cb(SSL *s, unsigned int context, const uint16_t *exts,
                          const unsigned char *present, uint16_t *order,
                          size_t len, X509 *x, size_t chainidx, void *arg)
{
    static const uint16_t wanted[] = {
        0x0000, /* server_name */
        0x000d, /* signature_algorithms */
        0x0033, /* key_share */
        0xff01, /* renegotiation_info */
    };
    size_t i, j, n = 0, psk = len;

    (void)s; (void)x; (void)chainidx; (void)arg;
    if ((context & SSL_EXT_CLIENT_HELLO) == 0)
        return 1;
    for (i = 0; i < sizeof(wanted) / sizeof(wanted[0]); i++)
        for (j = 0; j < len; j++)
            if (exts[j] == wanted[i])
                order[n++] = (uint16_t)j;
    for (i = 0; i < len; i++) {
        if (exts[i] == 0x0029) /* pre_shared_key */
            psk = i;
        for (j = 0; j < n; j++)
            if (order[j] == i)
                break;
        if (j == n)
            order[n++] = (uint16_t)i;
    }
    if (psk < len && (present[psk / 8] & (1u << (psk % 8))) != 0) {
        for (i = 0; i < len; i++) {
            if (order[i] == psk) {
                order[i] = order[len - 1];
                order[len - 1] = (uint16_t)psk;
                break;
            }
        }
    }
    return 1;
}
```

Install it with `SSL_CTX_set_ext_reorder_cb(ctx, fixed_order_cb, NULL)`.

### Deterministic shuffle

The application owns the state and can seed it per connection or per process.
Build the identity permutation, walk `order` from `len` down to 2 swapping
`order[i - 1]` with `order[next_random(state) % i]`, then move `pre_shared_key`
last. The state must outlive the handshake and not be shared across threads
without synchronisation.

### Custom extension placement

Custom extensions are at the front of `exts[]`. Put one first by placing its
type first in `wanted`, for example `{ 0x44cd }`; the rest is unchanged. The
callback sees only wire types, not values.

Security considerations
-----------------------

Shuffling extensions is obscurity, not security. A determined fingerprinter can
ignore order, as JA4 does, and can use cipher suites, groups, signature
algorithms, ALPN, certificates, timing and traffic patterns. It may frustrate
naive JA3-based blocking but is not a privacy guarantee.

Randomising per connection can itself be a signal; a deterministic seed may be
unique. Choose a strategy deliberately and test it.

Servers and middleboxes must accept any order except the `pre_shared_key` rule,
but old or non-compliant implementations may assume one, and unusual orders can
trigger bot-detection or WAF heuristics.

The callback runs in the handshake path: a slow callback delays it and a buggy
one aborts it. OpenSSL validates the permutation and fails safely, but cannot
stop a callback that blocks or corrupts state. ECH only helps if deployed and
if TLS is not terminated before the fingerprint is taken.

Open questions
--------------

**Exact presence versus candidate presence.** Exact presence needs two-phase
construction or a post-construction callback; candidate presence is simpler
for v1.

**ECH in v1.** Supporting real ECH uses one type order for inner and outer and
preserves compression contiguity; the fallback rejects real ECH, which cannot
match a browser using ECH.

**Server-side support.** The proposal says v1 is ClientHello-only. A generic
version needs per-context rules and tests, and `pre_shared_key` need not be
last in ServerHello.

**Padding sizing.** OpenSSL-generated padding is excluded and appended last.
Since 4.1 no longer emits the legacy extension, this is future-proofing.

**Error reporting.** No `int *al` in v1: failures use `internal_error`, and
applications can call `ERR_raise()`. It could be added later, but lets
application code send arbitrary alerts.

**Helpers and extension set.** OpenSSL will not ship Fisher-Yates helpers,
fixed-order builders or named profiles; those are policy. The callback also
cannot add or remove extensions.

**Stability and naming.** The order is cached for ECH inner/outer and
recomputed after HelloRetryRequest; DTLS retransmission needs tests. Naming and
the `present` representation are the details most likely to change.

Implementation status
---------------------

A prototype exists: grqz posted a patch in [issue #19220][issue19220] on
5 September 2026. It adds the callback and setters, handles ECH inner/outer
ordering, refactors `custom_ext_add()` into a per-extension helper, and adds
tests in `test/sslapitest.c`, `test/ech_test.c` and `test/ext_reorder_util.h`
(about 830 insertions across 12 files).

It is rebased onto master and passes `make test`, but issues remain: the TLS
1.2 `pre_shared_key` check is wrong when PSK is not sent; ECH with custom
extensions breaks with no callback; some test callbacks read out of bounds; the
`BIGNUM` representation should become the byte-array bitset; the ECH loop
refactor needs a default-output check; man pages, `CHANGES.md` and `NEWS.md`
are missing; and tests for invalid permutations, HRR, DTLS, QUIC and real ECH
are needed. Design review and committer approval are required before merge.

This document does not claim the code is merged.

References
----------

- [OpenSSL issue #19220: ClientHello extension shuffling][issue19220]
- [RFC 8446: TLS 1.3, section 4.2.11][rfc8446]
- [RFC 9846: TLS 1.3, section 4.3.11][rfc9846]
- [RFC 8701: GREASE][rfc8701]
- [RFC 7685: TLS ClientHello Padding Extension][rfc7685]
- [RFC 9849: TLS Encrypted Client Hello][rfc9849]
- [OpenSSL design process policy][design-process]
- [OpenSSL ECH design notes][ech-design]

[issue19220]: https://github.com/openssl/openssl/issues/19220
[rfc8446]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11
[rfc9846]: https://www.rfc-editor.org/rfc/rfc9846#section-4.3.11
[rfc8701]: https://www.rfc-editor.org/rfc/rfc8701
[rfc7685]: https://www.rfc-editor.org/rfc/rfc7685
[rfc9849]: https://www.rfc-editor.org/rfc/rfc9849
[design-process]: https://github.com/openssl/technical-policies/blob/master/policies/design-process.md
[ech-design]: https://github.com/openssl/openssl/blob/master/doc/designs/ech-api.md
