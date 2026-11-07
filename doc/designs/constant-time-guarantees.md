Constant-time guarantees for private-key operations
===================================================

This document states what OpenSSL guarantees about the constant-time
behaviour of its private-key operations.  For each operation it gives what
the guarantee covers, what it requires of the caller, what it deliberately
leaves out, and how it is checked.  It currently covers DH; see
[Known gaps][].

The guarantees apply to the implementations in libcrypto, as used by the
default provider.

What "constant time" means here
-------------------------------

An operation is constant time when its control flow, and the memory
addresses it accesses, do not depend on secret values.  Its running time, and
which cache lines it uses, then depend only on public values.

The guarantee addresses an attacker who measures timing or cache behaviour,
locally or remotely.  It does not address:

- power, electromagnetic or acoustic side channels
- fault injection
- speculative-execution attacks
- instructions whose latency depends on their operands, such as integer
  division or, on some processors, multiplication.  The validation described
  below cannot see these; the arithmetic is written to avoid division on
  secrets, but this is checked by review only.

Secret and public values
------------------------

Unless an operation's section says otherwise:

**Secret:**

- the private key value
- every value drawn from the private DRBG (`RAND_priv_bytes_ex()`)
- every intermediate value derived from these
- the shared secret produced by key agreement

**Public:**

- domain parameters: the group, the curve, the moduli and the group order
- all public keys, including the peer's
- the bit length of the private key, as stored.  This is a precondition, not
  something the implementation protects; see [Preconditions][].
- whether the operation succeeds
- how many times a rejection loop runs.  This depends only on values that
  were discarded, never on the value finally used.

### Declassification

Some values derived from secrets are public by construction, and the
implementation branches on them after marking them public
(`CONSTTIME_DECLASSIFY` or `constant_time_declassify_u32()`).  Each such
point is listed in the operation's section with the reason it is safe.
Declassification is checked by review, not by the tooling.

Preconditions
-------------

These apply to every operation below:

- **The key's length is public.**  Private keys are held as `BIGNUM`s, and a
  `BIGNUM`'s length (its `top`) is visible to code that reads it.  For a key
  drawn uniformly below the group order, a short key occurs with
  negligible probability.  Where a key is deliberately short (a DH private
  exponent sized from the security strength), its length is a public
  parameter.
- **Default provider only.**  The FIPS provider is built from the same
  sources but is not validated: it has its own DRBG and key objects, which
  the tests cannot mark secret, and a FIPS module in use may come from a
  different release than the rest of the library.
- **Default methods only.**  Custom methods such as a `DH_METHOD`, including
  a replacement `bn_mod_exp`, are outside the guarantee.
- **Validated configurations.**  The guarantee is checked for the compilers
  and targets listed in [Validation][].  Other compilers, flags and targets
  are expected to behave alike but are not checked; compilers can and do
  turn branch-free C into branches.

Validation
----------

A build with `enable-ct-validation` turns `CONSTTIME_SECRET` and
`CONSTTIME_DECLASSIFY` into Valgrind client requests that mark memory
undefined or defined.  Running a test under Valgrind's memcheck then reports
every conditional branch, memory index or system call argument that depends
on a secret.  `make test OSSL_VALGRIND_CT=yes` runs tests that way and fails
on any report.

The tests are:

- `test_pkey_ct`: the private-key operations end to end, through
  `EVP_PKEY_derive()`, on provider keys.  The private key's limbs and all
  private DRBG output are marked secret, so everything from the
  exponentiation to the output encoding is covered.
- `test_fn_ct`: individual `OSSL_FN` building blocks, with chosen inputs
  that the end-to-end test cannot force.

The daily `ct-validation` CI job runs these on x86-64 and AArch64, each with
and without assembly.

Limits of the method:

- Only executed paths are checked.  A path the tests do not reach is not
  validated, however similar it looks.
- memcheck follows data flow, not control flow.  A value computed by
  branching on a secret (for example `bn_correct_top()` on secret limbs)
  is reported once, at the branch, and then looks public.  Absence of later
  reports does not mean the value was not derived from a secret.
- Assembly is checked as executed, so a secret branch in assembly is
  reported like any other.

DH
--

**In scope:** `ossl_dh_compute_key()` with the default method, for DH and
DHX keys, as reached by `DH_compute_key_padded()` and by `EVP_PKEY_derive()`
with `OSSL_EXCHANGE_PARAM_PAD` set or with the X9.42 KDF: the exponentiation
Z = y^x mod p, the SP 800-56A step 2 check on Z, and the output, either Z
padded to the length of p or the KDF applied to it.

**Postconditions:** the output buffer holds the padded shared secret, which
remains secret.  The return value (the length of p, or an error) is public.

**Declassified:**

- whether Z is 0, 1 or p - 1 (step 2).  Such a Z only arises from an invalid
  peer key or a broken group, and the operation fails.
- whether Z fits in the output length.  Z < p, so it always does.

**Out of scope:**

- **Unpadded output** (`DH_compute_key()`, and `EVP_PKEY_derive()` without
  the pad parameter) strips leading zero bytes, so its length reveals them.
  TLS 1.2 and earlier require this format; see CVE-2020-1968 (Raccoon).
- Key and parameter generation, key validation, and import and export.
- s390x, where the default method first tries the hardware
  exponentiation and Z returns as a `BIGNUM`.

Known gaps
----------

- DSA, ECDH, ECDSA, SM2 and RSA
- key generation for every algorithm
- the FIPS provider
- a variant of `test_pkey_ct` that also marks the private key's length
  secret, to check [Preconditions][] mechanically
