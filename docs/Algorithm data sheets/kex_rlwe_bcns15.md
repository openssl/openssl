Algorithm data sheet: `kex_rlwe_bcns15`
=======================================

Algorithm
---------

**Name:** BCNS15

**Description:** Key exchange protocol proposed by Bos et al. [BCNS15] based on the ring learning with errors problem.  Instantiation of the approximate KEM in public key encryption scheme of Lyubashevsky, Peikert, Regev [LPR10], using reconciliation mechanism of Peikert [Pei14].

**Supporting research:**

- [BCNS15] Joppe W. Bos, Craig Costello, Michael Naehrig, Douglas Stebila. Post-quantum key exchange for the TLS protocol from the ring learning with errors problem. In *IEEE Symposium on Security and Privacy (S&P) 2015*, pp. 553-570. IEEE, May 2015. [https://eprint.iacr.org/2014/599](https://eprint.iacr.org/2014/599)
- [Pei14] Chris Peikert. Lattice cryptography for the Internet. In *PQCrypto 2014*, volume 8772 of LNCS, pages 197–219. Springer, 2014. [https://eprint.iacr.org/2014/070](https://eprint.iacr.org/2014/070)
- [LPR10] Vadim Lyubashevsky, Chris Peikert, and Oded Regev. On ideal lattices and learning with errors over rings. In *EUROCRYPT 2010*, volume 6110 of LNCS, pages 1–23. Springer, May 2010. [https://eprint.iacr.org/2012/230](https://eprint.iacr.org/2012/230)

Security
--------

**Security model:** Unauthenticated key exchange / passive (IND-CPA) key encapsulation mechanism

**Underlying hard problem(s):** Decision ring learning with errors problem

Parameter set 1
---------------

**Claimed classical security:** 

- 2^163.8 (original paper)
- 2^86 ([https://eprint.iacr.org/2015/1092](https://eprint.iacr.org/2015/1092))

**Claimed quantum security:** 

- ≥ 2^81.9 (original paper)
- 2^78 ([https://eprint.iacr.org/2015/1092](https://eprint.iacr.org/2015/1092))

**Communication size:** 

- Alice → Bob: 4,096 bytes
- Bob → Alice: 4,224 bytes
- total: 8,320 bytes

Implementation
--------------

**Source of implementation:** Original research paper ([https://github.com/dstebila/rlwekex](https://github.com/dstebila/rlwekex))

**License:** Public domain ("Unlicense", [http://unlicense.org](http://unlicense.org))

**Language:** C

**Constant-time:** When preprocessor macro `CONSTANT_TIME` is defined

**Options:**

- preprocessor macro `CONSTANT_TIME` to enable constant-time code

**Testing:**

- Correctness: covered by test harness `test_kex`
- Statistics of shared secrets: covered by test harness `test_kex`
	- statistical distance from uniform over 100 iterations: 0.0561185025
- Static analysis:
	- `scan_build`

**Runtime:**

Operation                      | Iterations | Total time (s) | Time (us): mean | pop. stdev | CPU cycles: mean | pop. stdev
------------------------------ | ----------:| --------------:| ---------------:| ----------:| ----------------:| ----------:
alice 0                        |      17664 |         10.000 |         566.145 |     24.189 |          2269004 |      96901
bob                            |      10923 |         10.001 |         915.562 |     53.806 |          3669454 |     215632
alice 1                        |      86154 |         10.000 |         116.071 |     13.987 |           465102 |      56014

Runtime measurement configuration:

- CPU: Intel Core i7 (6700K "Skylake") with 4 cores each running at 4.0 GHz; single-threaded runtime measurements
- TurboBoost and hyperthreading (hardware multithreading): disabled
- liboqs version: commit [c5382941aecc85df90b9179458c9fba7a9f45611](https://github.com/open-quantum-safe/liboqs/commit/c5382941aecc85df90b9179458c9fba7a9f45611)
- compiler: gcc-6 (Homebrew gcc 6.2.0) 6.2.0
- build command: make CC=gcc-6
