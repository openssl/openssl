Algorithm data sheet: `kex_sidh_cln16`
======================================

Algorithm
---------

**Name:** SIDH CLN16

**Description:**
The Supersingular Isogeny Diffie-Hellman (SIDH) key exchange protocol was proposed by Jao and DeFeo in [JD11]. The mathematical structures that provide the key exchange operations are supersingular elliptic curves and isogeny maps between them. Despite the use of elliptic curves, its security is not based on the hardness of the elliptic curve discrete logarithm problem, but instead on the hardness of computing large-degree isogenies between two given elliptic curves, believed to be resistant to quantum computers.

The library, provided by Microsoft Research, implements the algorithms of Costello, Longa, and Naehrig [CLN16], including public key compression algorithms of [CJLNRU17]. It is fully protected against timing and cache attacks: all operations on secret data run in constant time. More details at [https://www.microsoft.com/en-us/research/project/sidh-library/#].

The chosen parameters aim to provide 128 bits of security against attackers running a large-scale quantum computer, and 192 bits of security against classical algorithms. SIDH has the option of a hybrid key exchange that combines supersingular isogeny Diffie-Hellman with a high-security classical elliptic curve Diffie-Hellman key exchange at a small overhead.

SIDH is the first supersingular isogeny Diffie-Hellman software that is fully protected against timing and cache attacks: all operations on secret data run in constant time. The library is also significantly faster than previous implementations, e.g., it is about 3 times faster than the previously best (non-constant-time) supersingular isogeny Diffie-Hellman software.


**Supporting research:**
- [CLN16] Craig Costello, Patrick Longa, and Michael Naehrig. Efficient algorithms for supersingular isogeny Diffie-Hellman, available at [http://eprint.iacr.org/2016/413].
- [JD11] David Jao and Luca DeFeo. Towards quantum-resistant cryptosystems from supersingular elliptic curve isogenies, in PQCrypto 2011, LNCS 7071, pp. 19-34, 2011.
- [CJLNRU17] Craig Costello, David Jao, Patrick Longa, Michael Naehrig, Joost Renes, and David Urbanik. Efficient compression of SIDH public keys. Advances in Cryptology  EUROCRYPT 2017, LNCS 10210, pp. 679-706, 2017. The preprint version is available at [http://eprint.iacr.org/2016/963].

Security
--------

**Security model:** Unauthenticated key exchange / passive (IND-CPA) key encapsulation mechanism

**Underlying hard problem(s):** hardness of computing large-degree isogenies between two given elliptic curves

Parameter set 1
---------------

"Recommended" parameter set from [CLN16]

**Claimed classical security:** 

- 2^192 (original paper)

**Claimed quantum security:** 

- 2^128 (original paper)

**Communication size:** 

- Alice → Bob: 564 bytes (uncompressed), 330 bytes (compressed)
- Bob → Alice: 564 bytes (uncompressed), 330 bytes (compressed) 
- total: 1128 bytes (uncompressed), 660 bytes (compressed) 


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

