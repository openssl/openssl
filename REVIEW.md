# Review instructions

Every review covers, in this order of priority:

1. Bugs that a tool cannot find, above all those that can lead to a
   vulnerability.
2. Changes to documented or long-standing behaviour.
3. Conformance with `STYLE.md` and `DOCUMENTATION.md` at the repository
   root.

The checks below come from the CVEs, post-merge regression fixes and
maintainer reviews between October 2023 and October 2026. Most security
bugs and regressions in that period were visible in the diff that
introduced them.

## Evidence

Each finding states the inputs or state that trigger it and what goes
wrong, with a `file:line` citation for every claim about code outside the
diff. Read the callee before claiming what it returns or who owns its
result. A finding that cannot name a trigger is not reported.

## Error paths and ownership

- For every new allocation, find the free on every exit after it. A new
  `return` in a function that otherwise uses `goto err` usually leaks.
- Code after a shared `err:` or `end:` label only touches objects that
  are initialised on every path reaching it.
- `sk_*_push()`, `*_set0_*()` and `*_add*()` take ownership only on
  success; `set1` copies. State who frees the object on success and on
  failure, and check the pointer is set to `NULL` after a transfer.
- A pointer freed inside a loop or retry path is not freed again at the
  common exit.
- Each type is released with its own free function, not
  `OPENSSL_free()`. `dup` and `free` functions cover every new owned
  field; a struct-copying `dupctx` must not alias owned pointers.
- Free functions accept `NULL`; do not guard calls to them.

## Untrusted input

- Every access to an `ASN1_TYPE`, CHOICE or union member is preceded by
  a check of the discriminant on the same object (`->type`, the `ptype`
  from `X509_ALGOR_get0()`). Never select the member by what the caller
  expects.
- Every OPTIONAL field is checked for `NULL` before use, including
  `X509_ALGOR->parameter`. Use the ASN.1 template (`ASN1_OPT`,
  `ASN1_EXP_OPT`), not the RFC text, to find which fields are optional.
- Before reading N bytes of peer data, `remaining >= N` holds. Prefer
  `PACKET` and `WPACKET` helpers to hand-written length handling.
- A length returned by a size query bounds the later write on success
  and on failure.
- Sizes computed from caller or peer input are checked for overflow,
  including the `+ 1` for a terminator, and `size_t` to `int`
  conversions are checked against `INT_MAX`.
- `int`-returning sizes such as `EVP_MD_get_size()` are checked for
  `<= 0` before use as `size_t`. Such a check must not reject inputs the
  manual page allows, such as a `NULL` digest.
- Allocations, queues and work driven by peer input have an explicit
  bound that does not depend on the peer acknowledging or the
  application draining. Watch for quadratic work in peer-chosen sizes.

## Return values and errors

- For every changed condition on a call's result, check the callee's
  documented convention: 0, -1 or `<= 0` for failure.
- Trace `ret` through every new label. A function that raises an error
  returns failure, and a success path does not fall into error
  reporting.
- Errors are raised once, where they occur, with the most specific
  reason code.
- A check that exists only as `assert()` disappears in release builds.

## Security semantics

- Attacker-supplied data is not stored in a shared or cached object,
  such as an `SSL_SESSION`, before it is verified. Verification results
  are reset on every failure path.
- Trust flags such as `*_TRUSTOTHER` are not applied to peer-supplied
  certificate sets.
- Parameters an attacker chooses (key and tag lengths, whether a cipher
  is AEAD, domain parameters) have security minimums as well as
  memory-safety maximums. Peer domain parameters are checked against
  local ones.
- A change that disables or weakens a countermeasure, such as implicit
  rejection, is a finding.
- Secret data is not used in branches, memory indexing or early exits.
  BIGNUMs holding keys or nonces stay constant-time through every
  operation, including platform-specific EC code and assembly.
- Secrets are cleansed on every path. Zeroisation does not depend on
  `OPENSSL_PEDANTIC_ZEROIZATION`.

## Parallel paths and new modes

- A new entry point or constructor that duplicates an existing one sets
  up the same state. Compare it with its sibling.
- Paths that must agree do the same security work: `EVP_Cipher()`
  one-shot and update/final; assembly and generic code; check, generate
  and verify entry points. Zero-length input does not skip
  finalisation.
- A new check is not bypassed by a platform fast path or early return
  above it.
- A new mode or flag (RPK, `PARTIAL_CHAIN`, QUIC without address
  validation) keeps every invariant that consumers of the default path
  rely on, such as a certificate being present.
- A fix or check applied to one function is applied to its siblings:
  the same structure in CMS, PKCS#7, PKCS#12, TS, CMP and CRMF; other
  RecipientInfo types; other functions in the file.

## Refactors

Treat "mechanical" changes as semantic ones.

- When a condition is split, moved or rewritten, every term of the old
  condition survives.
- After a rename, no reader of the old name is left, including `#if`
  lines.
- After a lock is dropped and retaken, values computed under the earlier
  lock are stale. Shared state is read and written under the lock that
  guards it elsewhere.
- A refactor or optimisation does not change results through the public
  API, including inputs that used to fail.

## Compatibility

- Changes to a public function's return values, error-queue behaviour,
  flag semantics or `const` qualifiers are compared against its manual
  page. Say which existing callers break.
- A restriction added to a generic helper applies to all its callers.
- Behaviour changes and large refactors are not suitable for stable
  branches.

## Providers and the FIPS module

- Fetches use the caller's library context and property query; no
  fallback to legacy global lookups such as `EVP_get_digestbyname()`.
- Provider operations can be reached with no key or cipher set; check
  that `update`, `final` and `get_params` handle that.
- `ossl_prov_is_running()` is checked at operation entry points, not on
  per-update paths.
- Files added to or removed from the FIPS provider are reflected in the
  FIPS source lists and checksums.

## Build configurations and platforms

- Code and tests are guarded by exactly the `OPENSSL_NO_*` or platform
  conditions they need, and build with `no-deprecated`.
- Assembly dispatch checks every capability it uses. Constant tables go
  in `.rodata`.
- New public headers have `extern "C"` guards and use `ossl_inline`.

## Tests

- A regression test fails without the fix and passes with it.
- Each `TEST_*` result is acted on, assertions check expected values,
  and negative tests fail for the reason they claim.
- Tests of behaviour that differs between FIPS provider versions are
  gated on the provider version.

## Performance

Report per-call allocation, locking or repeated lookups added to hot
paths, such as per-record or per-update code.

## Project standards

Read `STYLE.md` and `DOCUMENTATION.md` and report violations in lines the
pull request adds or changes. Each finding cites the section it
violates.

- Documentation and comments state what the code does now. A change
  that makes a manual page, `CHANGES.md` entry or comment inaccurate
  updates it.
- New public symbols have a POD page in `doc/man3` with a `HISTORY`
  entry naming the release, and are removed from
  `util/missingcrypto*.txt` if listed. Public manual pages do not
  describe internal functions.
- New commands and options are documented in `doc/man1`, and new
  Configure options in `INSTALL.md`.
- User-visible changes have a `CHANGES.md` entry written for users.
- Internal and file-local items are documented as `DOCUMENTATION.md`
  requires, unless trivial.
- Pointers are compared explicitly with `NULL`. Magic numbers are named
  or explained.

## Severity

- Important: bugs and security issues with a stated trigger, behaviour
  changes to public APIs, and missing documentation for a new public
  symbol, command, option or Configure option.
- Nit: other `STYLE.md` and `DOCUMENTATION.md` violations, naming, and
  dead code left by the change. Report at most ten Nits; Important
  findings are not limited.

## Do not report

- What CI already reports: compiler warnings, clang-format, codespell,
  `make doc-nits`, `make md-nits`.
- Commit messages, CLA status, rebasing and target branches; maintainers
  and bots handle these.
- Questions about intent with no defect behind them.
- `STYLE.md` and `DOCUMENTATION.md` non-conformance in code the pull
  request does not touch.
- Files regenerated by `make update`.
