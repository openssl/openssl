Algorithm data sheet: `kex_sidh_msr`
======================================

Algorithm
---------

**Name:** SIDH/SIKE MSR

**Description:**
The ephemeral Diffie-Hellman key exchange scheme "SIDH" [1,2], and the CCA-secure key encapsulation mechanism "SIKE" [3] are schemes based on the supersingular isogeny Diffie-Hellman problem.

The following KEM schemes are supported:
- SIKEp503: matching the post-quantum security of AES128.
- SIKEp751: matching the post-quantum security of AES192.

The following ephemeral key exchange schemes are supported:
- SIDHp503: matching the post-quantum security of AES128.
- SIDHp751: matching the post-quantum security of AES192.

The library was developed by Microsoft Research for experimentation purposes.

**Supporting research:**
- [1] Craig Costello, Patrick Longa, and Michael Naehrig, "Efficient algorithms for supersingular isogeny Diffie-Hellman". Advances in Cryptology - CRYPTO 2016, LNCS 9814, pp. 572-601, 2016.
- [2] David Jao and Luca DeFeo, "Towards quantum-resistant cryptosystems from supersingular elliptic curve isogenies". PQCrypto 2011, LNCS 7071, pp. 19-34, 2011.
- [3] Reza Azarderakhsh, Matthew Campagna, Craig Costello, Luca De Feo, Basil Hess, Amir Jalali, David Jao, Brian Koziel, Brian LaMacchia, Patrick Longa, Michael Naehrig, Joost Renes, Vladimir Soukharev, and David Urbanik, "Supersingular Isogeny Key Encapsulation". Submission to the NIST Post-Quantum Standardization project, 2017.

Security
--------

**Security model:** Unauthenticated key exchange / IND-CPA and CCA secure key encapsulation mechanism

**Underlying hard problem(s):** hardness of computing large-degree isogenies between two given elliptic curves

Parameter set 1
---------------

SIDH P503 parameter set from [1]. Same security as AES128.

**Claimed classical security:** 

- 2^126

**Claimed quantum security:** 

- 2^84

**Communication size:** 

- Alice → Bob: 378 bytes
- Bob → Alice: 378 bytes
- total: 756 bytes

Parameter set 2
---------------

SIDH P751 parameter set from [1]. Same security as AES192.

**Claimed classical security:** 

- 2^188

**Claimed quantum security:** 

- 2^125

**Communication size:** 

- Alice → Bob: 564 bytes
- Bob → Alice: 564 bytes
- total: 1128 bytes

Parameter set 3
---------------

SIKE P503 parameter set from [3]. Same security as AES128.

**Claimed classical security:** 

- 2^126

**Claimed quantum security:** 

- 2^84

**Communication size:** 

- Alice → Bob: 378 bytes
- Bob → Alice: 378 bytes
- total: 756 bytes

Parameter set 4
---------------

SIKE P751 parameter set from [3]. Same security as AES192.

**Claimed classical security:** 

- 2^188

**Claimed quantum security:** 

- 2^125

**Communication size:** 

- Alice → Bob: 564 bytes
- Bob → Alice: 564 bytes
- total: 1128 bytes

Implementation
--------------

**Source of implementation:** Original research paper ([https://github.com/Microsoft/PQCrypto-SIDH](https://github.com/Microsoft/PQCrypto-SIDH))

**License:** MIT License

**Language:** C

**Constant-time:** Yes

**Testing:**

- Correctness: covered by test harness `test_kex`
- Statistics of shared secrets: covered by test harness `test_kex`
- Static analysis:
	- `scan_build`

