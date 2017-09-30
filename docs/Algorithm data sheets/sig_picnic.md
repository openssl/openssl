Algorithm data sheet: `sig_picnic`
==================================

Algorithm
---------

**Name:** Picnic

**Description:**
Picnic is a post-quantum digital signature scheme that: (a) derives its security from the security of symmetric-key primitives, believed to be quantum-secure, and (b) has extremely small keypairs, and, (c) is highly parametrizable.

The public key is an image y=f(x) of a one-way function f (the block cipher LowMC) and the secret key is x. A signature is a non-interactive zero-knowledge proof of x, that incorporates a message to be signed. For this proof, improvements to the recent progress of Giacomelli et al. (USENIX'16) in constructing an efficient sigma protocol for statements over general circuits are leveraged, resulting in smaller signature sizes.

Two mechanisms for making the proof non-interactive can be used: the Fiat-Shamir transform, and Unruh's transform (EUROCRYPT'12,'15,'16). The former has smaller signatures, while the latter has a security analysis in the quantum-accessible random oracle model. By customizing Unruh's transform, the overhead is reduced to 1.6x when compared to the Fiat-Shamir transform. 

**Supporting research:**
- [CDGORRSZ] Melissa Chase, David Derler, Steven Goldfeder, Claudio Orlandi, Sebastian Ramacher, Christian Rechberger, Daniel Slamanig, and Greg Zaverucha. Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives, Proceedings of ACM CCS 2017, and available at [http://eprint.iacr.org/2017/279].

Security
--------

**Security model:** existential unforgeability in the random oracle model (ROM), or quantum
random oracle model (QROM).

**Underlying hard problem(s):** hash function security (ROM/QROM), key recovery attacks on the lowMC
block cipher

Parameter set 1
---------------

"Picnic_1_316_FS" parameter set from [CDGORRSZ]

**Claimed classical security:** 

- 2^256 (original paper)

**Claimed quantum security:** 

- 2^128 (original paper)

**Data sizes:** 

- Private key: 130 bytes
- Public key: 65 bytes
- Signature: 103464 bytes

Parameter set 2
---------------

"Picnic_1_316_UR" parameter set from [CDGORRSZ]

**Claimed classical security:** 

- 2^256 (original paper)

**Claimed quantum security:** 

- 2^128 (original paper)

**Data sizes:** 

- Private key: 130 bytes
- Public key: 65 bytes
- Signature: 174434 bytes

Parameter set 3
---------------

"Picnic_10_38_FS" parameter set from [CDGORRSZ]

**Claimed classical security:** 

- 2^256 (original paper)

**Claimed quantum security:** 

- 2^128 (original paper)

**Data sizes:** 

- Private key: 130 bytes
- Public key: 65 bytes
- Signature: 114264 bytes

Parameter set 4
---------------

"Picnic_10_38_UR" parameter set from [CDGORRSZ]

**Claimed classical security:** 

- 2^256 (original paper)

**Claimed quantum security:** 

- 2^128 (original paper)

**Data sizes:** 

- Private key: 130 bytes
- Public key: 65 bytes
- Signature: 195458 bytes

Parameter set 5
---------------

"Picnic_42_14_FS" parameter set from [CDGORRSZ]

**Claimed classical security:** 

- 2^256 (original paper)

**Claimed quantum security:** 

- 2^128 (original paper)

**Data sizes:** 

- Private key: 130 bytes
- Public key: 65 bytes
- Signature: 148236 bytes

Parameter set 6
---------------

"Picnic_42_14_UR" parameter set from [CDGORRSZ]

**Claimed classical security:** 

- 2^256 (original paper)

**Claimed quantum security:** 

- 2^128 (original paper)

**Data sizes:** 

- Private key: 130 bytes
- Public key: 65 bytes
- Signature: 263786 bytes

Implementation
--------------

**Source of implementation:** Original research paper ([https://github.com/Microsoft/Picnic](https://github.com/Microsoft/Picnic))

**License:** MIT License

**Language:** C

**Constant-time:** Yes

**Testing:**

- Correctness: covered by test harness `test_sig`
- Statistics of signatures: covered by test harness `test_sig`
- Static analysis:
	- `scan_build`

