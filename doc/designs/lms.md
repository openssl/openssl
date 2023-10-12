Leighton-Micali Signature (LMS)
===============================

Introduction
------------

Existing OpenSSL digital signature algorithms such as ECDSA and EDDSA
have the potential to be broken using large scale quantum computers.

The NSA have listed LMS as a quantum-resistant scheme for software and
firmware signing for National Security Systems [3].
LMS is a Stateful Hash-Based Signature (HBS) scheme that depends only on the
security of its underlying hash functions, and approved secure hash functions
are believed to be quantum resistant.
Stateful HBS schemes are not suitable for general use because they require
careful state management that is often difficult to ensure.

Overview
---------

A signature is used to validate the authenticity of a message by associating a
secret private key with a shared public key. Leighton-Micali One Time Signatures
(LM-OTS) require a unique private key to sign any given message. This means that
a LMS private key must contain state information so that it changes the LM-OTS
private key each time a message is signed. The system is not secure if the same
private key is used more than once.

The LMS scheme uses a Merkle hash tree, where the leaves of the tree are LM-OTS
public keys, and each non leaf node is a hash of its 2 children. The root node
is the shared public key of the tree. For a h height tree there are 2^h OTS
public keys.

A LM-OTS signature uses Hash functions that use a OTS private key and message.
A LMS signature consists of a leaf index q combined with a LM-OTS signature and
a path of adjacent hashes going from the leaf node up to the root. The signature
can then be verified by comparing the supplied public key to a calculated
public key.

Since all leaf nodes are required to obtain a public key for a single
LMS tree, a very large tree can take a long time to generate.
LMS has a multi-tree variant called the Hierarchical Signature System (HSS)
which allows smaller subtrees to be built as required.
In HSS the public key for the first LMS tree is the public key of the HSS system.
Each LMS private key signs the next levels LMS public key, and a bottom level
LMS tree signs the actual message using a leaf LM-OTS private key.

Refer to [1] & [4] for further information.

What is supported
-----------------

- HSS public keys and HSS signatures. LMS and HSS public keys may share the
same object, there is only one additional field L for HSS public keys.
- HSS signature verification
- Support for modes and digests specified in [2].

What is not supported
---------------------

- LMS key pair generation, signature generation and private key support.
  Due to the problematic nature of managing the stateful OTS private keys,
  [2] requires that key and signature generation be performed in
  hardware cryptographic modules that do not allow secret keying material to be
  exported, even in encrypted form.
- LMS and LM_OTS signatures.
  The code will be written in a way that would allow LMS signatures to be added
  if required, but a HSS signature with only a single level tree should be
  sufficient for this use case. A separate LMS signature dispatch table could be
  added if this is ever required.
- CMS and X509 support - this may be added at a later date.
- Implementing Extended Merkle signature scheme (XMSS) is a separate effort.

HSS Signature and Key formats
-----------------------------

The LMS/HSS signature and public key formats use XDR (not ASN1 data).
The reference code in RFC 8554 checks sizes of the binary data before loading
the known fields. Rather than do this the OpenSSL PACKET interface is used.
When the end of the data is expected PACKET_remaining() is tested.
NOTE that the size of signatures depends on the modes which are embedded in the
loaded data.
Byte array data such as encoded public keys are just kept as pointers into the
data. The entire signature blob is duplicated if the pointers are required
across API calls.

HSS message streaming API
-------------------------

In order to handle HSS message streaming the signature data must be decoded
first, since the message is only used in the last part of the verify.
This means that the existing sequence of calls for streaming (i.e.
DigestVerifyInit/DigestVerifyUpdate/DigestFinal) is not sufficient for this
purpose unless the message is buffered during the update, and then only
processed during the final.

So we should:

- Support one shot operations:
  Using existing EVP_DigestVerifyInit_ex + EVP_DigestVerify calls
- Dont support streaming via existing interface:
  EVP_DigestVerifyInit_ex + EVP_DigestVerifyUpdate + EVP_DigestVerifyFinal.
  It could be done, but requires buffering of the message during updates.
- EVP_VerifyInit etc should not be supported.
- In order to set the signature early one of the following methods should be
  used:

Proposal 1:

Add streaming via a new API that is similar to the existing DigestVerify API's,
but moves the signature |sig| from the final to the init. i.e.

```c
__owur int EVP_DigestVerifyHBSInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                   const char *mdname,
                                   OSSL_LIB_CTX *libctx,
                                   const char *props, EVP_PKEY *pkey,
                                   const OSSL_PARAM params[],
                                   const unsigned char *sig,
                                   size_t siglen);   
/* Alias: since the function signature is identical */
#define EVP_DigestVerifyHBSUpdate(a,b,c) EVP_DigestVerifyUpdate(a,b,c)

__owur int EVP_DigestVerifyHBSFinal(EVP_MD_CTX *ctx);
```

Proposal 2:

Add a Init_ex function and leave the Final the same.

i.e.
EVP_DigestVerifyInit_ex3(..., const unsigned char *sig, size_t siglen);

For the EVP_DigestVerifyFinal pass a NULL signature.
The signature length must be zero in this case or an error will occur.
If a signature is passed should it just ignore the value?

Proposal 3:

Pass the signature after the init via an OSSL_PARAM.


Hash Function Selection
-----------------------

- During the DigestVerifyInit()the passed in digest name is not required
since the LMS/HSS public key and HSS signature contain the digest to use.
If specified, the digest name must match the one used by the HSS public key and
signature, otherwise an error will occur.
- Section 4 of [2] states that the same hash function MUST be used everywhere
for OTS and LMS at all HSS levels (this means the terms 'm' and 'n' are the
same)). ([1] only states that the hashes SHOULD be the same).
This requires error checking when the HSS signature data is decoded.
- Hash Functions for SHAKE and truncated SHA256 are not specified in [1],
but are part of [2] so they should be supported.
For truncated SHAKE256/192 support this will require the OSSL_DIGEST_PARAM_XOFLEN
parameter to be set.

Threading
---------

For HSS, multi-level trees are used for verification,
and there is a verify process involving many hashes for each of the (1..8)
levels, with only the final level using the input message (and the message is
possibly streamed).
All the other levels are one shot verify operations that must all return true in
order to pass verification. These one-shot operations may be done in parallel
using the new internal thread API calls (introduced for ARGON).
When streaming only the final part of the validation involves the message,
and this is done using a init, update and final in the main thread.
After this the other threads must finish before verification can end.
If threads are not supported, then a single threaded call is used instead.
By default the thread count will be one.
A parameter to set the threads can be done via a OSSL_PARAM.
For one shot verification threading can still be used for the top levels.

Provider Support
----------------

dupctx should not be supported by the provider since this would not apply to LMS.

In order to support the new API calls there should be 2 additional dispatch
functions..

OSSL_CORE_MAKE_FUNC(int, signature_digest_verify_pbs_init,
                    (void *ctx, const char *mdname, void *provkey,
                     const OSSL_PARAM params[],
                     const unsigned char *sig, size_t siglen))
OSSL_CORE_MAKE_FUNC(int, signature_digest_verify_pbs_final,
                    (void *ctx))


A new HSS keymanager should support:

OSSL_FUNC_KEYMGMT_NEW
OSSL_FUNC_KEYMGMT_FREE
OSSL_FUNC_KEYMGMT_SET_PARAMS
OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS
OSSL_FUNC_KEYMGMT_HAS
OSSL_FUNC_KEYMGMT_MATCH
OSSL_FUNC_KEYMGMT_VALIDATE
OSSL_FUNC_KEYMGMT_IMPORT
OSSL_FUNC_KEYMGMT_IMPORT_TYPES
OSSL_FUNC_KEYMGMT_EXPORT
OSSL_FUNC_KEYMGMT_EXPORT_TYPES
OSSL_FUNC_KEYMGMT_LOAD

A HSS public key requires 2 OSSL_PARAM fields:
OSSL_PKEY_PARAM_HSS_L int 
OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY octet_string

FIPS Requirements
------------------

See [FIPS 140-3 IG] "10.3.A Cryptographic Algorithm Self-Test Requirements"
If the module implements signature verification for HSS, it shall have a CAST
for it.

Testing
-------

As well as using the test vectors supplied in [1] and [6], additional interop tests
should be performed by generating data using other toolkits
(such as Ciso or Bouncy Castle).
Signature data will also be corrupted to perform negative tests, which are
determined by manually running code coverage reports.

References
----------

The LMS/HSS implementation uses the following references.

- [1]: [RFC 8554 "Leighton-Micali Hash-Based Signatures"]
    <https://www.rfc-editor.org/rfc/rfc8708.pdf>
- [2]: [NIST SP 800-208 "Recommendation for Stateful Hash-Based Signature Schemes"]
    <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf>
- [3]: [Commercial National Security Algorithm Suite (CNSA 2.0)]
    <https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF>
- [4]: [RFC 8708 "Use of the HSS/LMS Hash-Based Signature Algorithm in CMS)"]
    <https://www.rfc-editor.org/rfc/rfc8708.pdf>
- [5]: [FIPS 140-3 IG]
    <https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf>
- [6]: [Additional Parameter sets for HSS/LMS Hash-Based Signatures]
    <https://datatracker.ietf.org/doc/html/draft-fluhrer-lms-more-parm-sets-11>
