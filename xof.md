XOF Design
==========

XOF Definition
--------------

An extendable output function (XOF) is defined as a variable-length hash
function on a message in which the output can be extended to any desired length.

At a minimum an XOF needs to support the following pseudo-code
```
xof = xof.new();
xof.absorb(bytes1);
xof.absorb(bytes2);
xof.finalize();
out1 = xof.squeeze(10);
out2 = xof.squeeze(1000);
xof.reset();
xof.assorb(bytes);
```
### Rules

- absorb can be called multiple times
- finalize ends the absorb process (by adding padding bytes and doing a final absorb).
  absorb must not be called once the finalize is done unless a reset happens.
- finalize may be done as part of the first squeeze operation
- squeeze can be called multiple times.

OpenSSL XOF Requirements
------------------------

The current OpenSSL implementation of XOF only supports a single call to squeeze.
The assumption exists in both the high level call to EVP_DigestFinalXOF() as well
as in the lower level SHA3_squeeze() operation (Of which there is a generic c version,
as well as assembler code for different platforms).

A decision has to be made as to whether a new API is required, as well as considering
how the change may affect existing applications.
The changes introduced should have a minimal affect on other related functions that
share the same code (e.g SHAKE and SHA3 share functionality).

API Discussion of Squeeze
-------------------------

### Squeeze

Currently EVP_DigestFinalXOF() uses a flag to check that it is only invoked once.
It returns an error if called more than once. When initially written it also did a 
reset, but that code was removed as it was deemed to be incorrect.

#### Proposal 1

Change EVP_DigestFinalXOF(ctx, out, outlen) to handle multiple calls.
Possibly have EVP_DigestSqueeze() just as an alias method?
Changing the code at this level should be a simple matter of removing the flag check.

##### Pros

  - New API is not required

##### Cons

  - Final seems like a strange name to call multiple times.

#### Proposal 2

Keep EVP_DigestFinalXOF() as a one shot function and create a new API to handle the
multi squeeze case e.g.
```
EVP_DigestSqueeze(ctx, out, outlen).
```

##### Pros

  - Seems like a better name.

##### Cons

  - Adds an extra API.
  - The interaction between the 2 API's needs to be clearly documented.
     - A call to EVP_DigestSqueeze() after EVP_DigestFinalXOF() would fail.
     - A call to EVP_DigestFinalXOF() after the EVP_DigestSqueeze() would fail? Is this confusing.

API Discussion of other XOF API'S
---------------------------------

### Init

The digest can be initialized as normal using:
```
md = EVP_MD_fetch(libctx, "SHAKE256", propq);
ctx = EVP_MD_CTX_new();
EVP_DigestInit_ex2(ctx, md, NULL);
```

### Absorb

Absorb can be done by multiple calls to:
```
EVP_DigestUpdate(ctx, in, inlen);
```

#### Proposal:

Do we want to have an Alias function?
```
EVP_DigestAbsorb(ctx, in, inlen);
```

### Finalize

The finalize is just done as part of the squeeze operation.

### Reset

A reset can be done by calling:
```
EVP_DigestInit_ex2(ctx, NULL, NULL);
```

Low Level squeeze changes
--------------------------

### Description

The existing one shot squeeze method is:
```
SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t outlen, size_t r)
```
It contains an opaque object for storing the state B<A>,
which can be used B<r> times to output squeezed values to B<out>,
before it needs to update the state B<A> by internally calling KeccakF1600().
Unless you are using a multiple of B<r> as the B<outlen>, the function no way
of knowing where to start from if another call to SHA_squeeze() was attempted.
The method also avoids doing a final call to KeccakF1600() currently since it was
assumed that it was not required for a one shot operation.

### Solution 1

Modify the SHA3_squeeze code to accept a input/output parameter to track the position
within the state B<A>.
See https://github.com/openssl/openssl/pull/13470.

#### Pros

  - Change in C code is minimal. it just needs to pass this additional parameter.
  - There are no additional memory copies of buffered results.

#### Cons

  - The logic in the c reference has many if clauses.
  - It needs to be written in assembler, the logic would also be different in different assembler routines
    due to the internal format of the state A being different.
  - The general SHA3 case would be slower unless code was duplicated?

### Solution 2

Leave SHA3_squeeze() as it is and buffer calls to the SHA3_squeeze() function inside the final.
See https://github.com/openssl/openssl/pull/7921.

#### Pros

  - Change is mainly in C code.

#### Cons

  - Because of the one shot nature of the SHA3_squeeze() it still needs to call the KeccakF1600() function directly.
  - The Assembler function for KeccakF1600() needs to be exposed. This function was not intended to be exposed
    since the internal format of the state B<A> can be different on different platform architectures.
  - When should this internal buffer state be cleared?

### Solution 3

Perform a one-shot squeeze on the original absorbed data and throw away the first part of the output buffer,

#### Pros

  - Very simple.

#### Cons

  - Incredibly slow.
  - More of a hack than a real solution.

### Proposed Solution

An alternative approach to solution 2 is to modify the SHA3_squeeze() slightly so that it can pass in a boolean that handles
the call to KeccakF1600() correctly for multiple calls.

#### Pros

  - C code is fairly simple to implement.
  - The state data remains as an opaque blob.
  - For larger values of outlen SHA3_squeeze() may use the out buffer directly.

#### Cons

  - Requires small assembler change to pass the boolean and handle the call to KeccakF1600().
  - Uses memcpy to store partial results for a single blob of squeezed data of size 'r' bytes.
