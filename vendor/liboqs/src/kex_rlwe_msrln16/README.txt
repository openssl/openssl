                                 LatticeCrypto v1.0 (C Edition)
                                 ==============================

LatticeCrypto is a post-quantum secure cryptography library based on the Ring-Learning with Errors (R-LWE) 
problem. The version 1.0 of the library implements the instantiation of Peikert's key exchange [1] due to 
Alkim, Ducas, Pöppelmann and Schwabe [2], and incorporates novel techniques to provide higher performance.

The library [3] was developed by Microsoft Research for experimentation purposes. 

*** THE ORIGINAL README HAS BEEN TRIMMED LEAVING ONLY THE INFO RELEVANT FOR THE OQS INTEGRATION ***

1. CONTENTS:
   --------

/                                              - Library C and header files                                     
AMD64/                                         - Optimized implementation of the NTT for x64 platforms
generic/                                       - Implementation of the NTT in portable C
README.txt                                     - This readme file


2. MAIN FEATURES:
   -------------
   
- Support arithmetic functions for computations in power-of-2 cyclotomic rings that are the basis for 
  implementing Ring-LWE-based cryptographic algorithms.
- Support key exchange providing at least 128 bits of quantum and classical security.
- All functions evaluating secret data have regular, constant-time execution, which provides protection 
  against timing and cache attacks.
- Basic implementation of the underlying arithmetic functions using portable C to enable support on
  a wide range of platforms including x64, x86 and ARM.  
- Optional high-performance implementation of the underlying arithmetic functions for x64 platforms on
  Linux using assembly and AVX2 vector instructions.


REFERENCES
----------

[1] C. Peikert, "Lattice cryptography for the internet", in Post-Quantum Cryptography - 6th International 
    Workshop (PQCrypto 2014), LNCS 8772, pp. 197-219. Springer, 2014.
[2] E. Alkim, L. Ducas, T. Pöppelmann and P. Schwabe, "Post-quantum key exchange - a new hope", IACR Cryp-
    tology ePrint Archive, Report 2015/1092, 2015.
[3] https://www.microsoft.com/en-us/research/project/lattice-cryptography-library/
