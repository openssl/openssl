ML-KEM Design
=============

This document covers OpenSSL specific ML-KEM implementation details.
[FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
clearly states most of the requirements of ML-KEM and has comprehensive
pseudo code for all its algorithms.

ML-KEM Parameters & Functions
-----------------------------

There are 3 different parameter sets in FIPS 203 (see Section 8).
There are constants related to these, as well as there being a group of
functions associated with each set.

To support these variants, OpenSSL will have 3 different key managers and 3
corresponding KEM function sets. The names used are of the form "ML-KEM-768".

The key problem implementing the different variants lies in the significant
differences in (dimensions of) vectors and matrics required. For this reason,
[boringssl](https://boringssl.googlesource.com/boringssl/+/HEAD/crypto/mlkem)
chose to use C++ templates to represent the different parameter sets.
As C++ cannot be used in OpenSSL, (object) code duplication by way of use
of macros to minimize source code duplication is used. Note that C++ templates are also specialised at compile time to the specific types at which they are instantiated, so there's not in fact much difference in the resulting code size. Templates are in this regard just a cleaner, more expressive "macro" system.

ML-KEM makes extensive use of SHA3 primitives, SHA3-256, SHA3-512, SHAKE256 and SHAKE128.
To improve ML-KEM execution performance the EVP handles for these are pre-fetched during ML-KEM
key initialisation and stored in an ossl_ml_kem_ctx object.
These are then used in key generation, encapsulation and decapsulation.
The context is also duplicated (EVP_MD handles uprefed) when the ML-KEM key is duplicated.

This ossl_ml_kem_ctx is then passed to all functions.
As already noted, it is presently allocated on a per-key basis in the providers'
ML-KEM key context, but if there's some way to do this just once during provider
initialisation, or once per thread, ... performance might noticeably improve.

ML-KEM keys
-----------

As expected, ML-KEM  has both public and private keys.
Since the public key is exchanged between the two parties as part of key
agreement, the encoding (wire-form) of the public key is clearly defined and
there are unambiguous choices for its encoding and decoding functions.

It may be noted that the wire-form public key is "compressed".
Instead of the bulky "A" ("m" in the code) matrix, which represents the majority
of the storage required for ML-KEM public and private keys, the wire-form public
key, holds a 32-byte seed from which one can regenerate the matrix.
The full matrix is in memory in the internal form (needed for computations) of
the public key (which in our implementation is simply a reference into the internal
form of the private key when both are known).
It is possible to save space and compute the matrix elements just-in-time, as-needed,
which would not have a performance impact on the encapsulation step (typically server)
where each matrix element is used exactly once!

However, the same matrix is used both during key generation and decapsulation and
computing it twice would have a noticeable performance impact (typically on the client).
If we wanted to do just-in-time matrix computation for decapsulation, we'd need to have
a different memory layout for public keys when only the public key is known, and to change
the algorithm code to generate matrix elements on demand during encapsulation. This can
be considered later, if it is determined that the space savings (9*512 bytes in memory for
ML-KEM-768, for the full matrix, instead of 512 bytes for a just-in-time element) this could
be considered later, but the server will generally destroy the client public key soon after the
shared secret is computed, so these don't stay in memory long, so briefly saving ~2KB may
not to be of much benefit).

The private key format is somewhat ad hoc, though (to be able to fully describe the algorithms)
FIPS 203 documents a format that is commonly referred to as the "extended"
format and also exportable/importable via encoding functions in well-defined
sizes. The IETF voices interest in using the "seed-based" format (the (d,z) seed
pair from which the key is generated and can be recovered). This is supported by the
FIPS 203 internal deterministic key generation functions, which are "testing only".
We naturally use this for running the Known Answer Tests, but our private key encoding
format is the full expanded key, not the 64 byte (d,z) seed pair.

The design therefore caters to both options: The default key generation and
KEM encapsulation/decapsulation functions operate on/with "extended keys".
It is also possible to use the "seed-based" format by way of providing
specific OSSL_PARAMs made available for that purpose -- but again, as per
NIST guidance, only for testing. If the seed version is retrieved from a
normal key generation operation, it shall be subject to the same level of
protection given to private key material.

Key generation API
------------------

Keys can therefore be generated as "usual" by way of the EVP functions
EVP_PKEY_generate() and EVP_PKEY_Q_keygen().

An explicit seed can be specified by setting the OSSL_PARAM value
"OSSL_PKEY_PARAM_ML_KEM_SEED" to a 64-byte octet-string before key generation.
The octet-string value must be the concatenation of the B<d> and B<z> strings in that
order.

KEM API
-------

ML-KEM is meant to be a simple replacement for existing KEM algorithms.
Therefore, simple use should be

EVP_PKEY_encapsulate_init(), EVP_PKEY_encapsulate(),
EVP_PKEY_decapsulate_init(), EVP_PKEY_decapsulate().

For the encapsulation operation, a test-only option exists to avoid the
otherwise mandatory use of a random number generator for passing in a
known "entropy" by way of the OSSL_PARAM "OSSL_KEM_PARAM_IKME".

Buffers
-------

There are many functions passing buffers of sizes dependent on algorithm
(version). It therefore is required to properly check/allocate buffers of
suitable sizes as defined in the core "mlkem.h" header file. These size
checks are performed within the provider logic. The core crypto APIs for
any ML-KEM algorithm are not to be exposed and called by external users.

Constant Time Considerations
----------------------------

The usual constant time methods are used in the implementation. All possible
error conditions that can be detected are passed up the call stack to provide
the usual OK/NOK status for all required functions.
