Algorithm data sheet: `kex_lwe_frodo`
=======================================

Algorithm
---------

**Name:** Frodo

**Description:** Key exchange protocol proposed by Bos et al. [BCDMNNRS16] based on the ring learning with errors problem.  Instantiation of the Lindner–Peikert approximate LWE key agreement scheme [LP10], which was an adaptation of the LWE public key encryption scheme of in public key encryption scheme of Regev [Reg05], using reconciliation mechanism of Peikert [Pei14].

**Supporting research:**

- [BCDMNNRS16] Joppe Bos, Craig Costello, Léo Ducas, Ilya Mironov, Michael Naehrig, Valeria Nikolaenko, Ananth Raghunathan, Douglas Stebila. Frodo: Take off the ring! Practical, quantum-secure key exchange from LWE. In *Proc. 23rd ACM Conference on Computer and Communications Security (CCS) 2016*, pp. 1006-1018. ACM, October 2016. [https://eprint.iacr.org/2016/659](https://eprint.iacr.org/2016/659)
- [Pei14] Chris Peikert. Lattice cryptography for the Internet. In *PQCrypto 2014*, volume 8772 of LNCS, pages 197–219. Springer, 2014. [https://eprint.iacr.org/2014/070](https://eprint.iacr.org/2014/070)
- [LP10] Richard Lindner and Chris Peikert. Better key sizes (and attacks) for LWE-based encryption. In *Proc. CT-RSA 2011*, *LNCS*, vol. 6558, pp. 319–339. Springer, February 2011. [https://eprint.iacr.org/2010/613](https://eprint.iacr.org/2010/613)
- [Reg05] Oded Regev. On lattices, learning with errors, random linear codes, and cryptography. In *Proc. 37th ACM STOC*, pp. 84–93. ACM Press, May 2005.

Security
--------

**Security model:** Unauthenticated key exchange / passive (IND-CPA) key encapsulation mechanism

**Underlying hard problem(s):** Decision learning with errors problem

Parameter set 1
---------------

"Recommended" parameter set from [BCDMNNRS16]

**Claimed classical security:** 

- 2^144 (original paper)

**Claimed quantum security:** 

- 2^130 (original paper)

**Communication size:** 

- Alice → Bob: 11,377 bytes
- Bob → Alice: 11,296 bytes
- total: 22,673 bytes

Implementation
--------------

**Source of implementation:** Original research paper ([https://github.com/lwe-frodo/lwe-frodo](https://github.com/lwe-frodo/lwe-frodo))

**License:** MIT License

**Language:** C

**Constant-time:** Yes

**Testing:**

- Correctness: covered by test harness `test_kex`
- Statistics of shared secrets: covered by test harness `test_kex`
- Static analysis:
	- `scan_build`
