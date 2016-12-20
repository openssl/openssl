                                        SIDH v1.1 (C Edition)
                                       =======================

The SIDH v1.1 library (C Edition) is a supersingular isogeny-based cryptography library that implements a
new suite of algorithms for a post-quantum resistant Diffie-Hellman key exchange scheme [2]. This scheme 
provides approximately 128 bits of quantum security and 192 bits of classical security. 

The library was developed by Microsoft Research for experimentation purposes. 

*** THE ORIGINAL README HAS BEEN TRIMMED LEAVING ONLY THE INFO RELEVANT FOR THE OQS INTEGRATION ***

1. CONTENTS:
   --------

/                              - Library C and header files                                     
AMD64/                         - Optimized implementation of the field arithmetic for x64 platforms
generic/                       - Implementation of the field arithmetic in portable C
README.txt                     - This readme file


2. MAIN FEATURES:
   -------------
   
- Support key exchange providing 128 bits of quantum security and 192 bits of classical security.
- Support a peace-of-mind hybrid key exchange mode that adds a classical elliptic curve Diffie-Hellman 
  key exchange on a high-security Montgomery curve providing 384 bits of classical ECDH security.
- Protected against timing and cache-timing attacks through regular, constant-time implementation of 
  all operations on secret key material.
- Support for public key validation in static key exchange when private keys are used more than once.
- Basic implementation of the underlying arithmetic functions using portable C to enable support on
  a wide range of platforms including x64, x86 and ARM. 
- Optimized implementation of the underlying arithmetic functions for x64 platforms with optional, 
  high-performance x64 assembly for Linux.


REFERENCES:
----------

[1]   Craig Costello, Patrick Longa, and Michael Naehrig.
      Efficient algorithms for supersingular isogeny Diffie-Hellman.      
      Advances in Cryptology - CRYPTO 2016 (to appear), 2016. 
      Extended version available at: http://eprint.iacr.org/2016/413. 

[2]   David Jao and Luca DeFeo. 
      Towards quantum-resistant cryptosystems from supersingular elliptic curve isogenies.
      PQCrypto 2011, LNCS 7071, pp. 19-34, 2011. 