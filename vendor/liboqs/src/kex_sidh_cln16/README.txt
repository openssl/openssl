                                        SIDH v2.0 (C Edition)
                                       =======================

The SIDH v2.0 library (C Edition) is a supersingular isogeny-based cryptography library that implements a
new suite of algorithms for a post-quantum, ephemeral Diffie-Hellman key exchange scheme [2]. 

The library was developed by Microsoft Research for experimentation purposes. 

SECURITY NOTE: the scheme is NOT secure when using static keys.

*** THE ORIGINAL README HAS BEEN TRIMMED LEAVING ONLY THE INFO RELEVANT FOR THE OQS INTEGRATION ***

1. CONTENTS:
   --------

/                              - Library C and header files.                                     
AMD64/                         - Optimized implementation of the field arithmetic for x64 platforms                                    
ARM64/                         - Optimized implementation of the field arithmetic for ARMv8 platforms
generic/                       - Implementation of the field arithmetic in portable C
README.txt                     - This readme file


2. CONTRIBUTIONS:
   -------------

   The field arithmetic implementation for 64-bit ARM processors (ARM64 folder) was contributed by 
   David Urbanik (dburbani@uwaterloo.ca).


3. MAIN FEATURES:
   -------------
   
- Support ephemeral Diffie-Hellman key exchange.
- Support a peace-of-mind hybrid key exchange mode that adds a classical elliptic curve Diffie-Hellman 
  key exchange on a high-security Montgomery curve providing 384 bits of classical ECDH security.
- Protected against timing and cache-timing attacks through regular, constant-time implementation of 
  all operations on secret key material.
- Basic implementation of the underlying arithmetic functions using portable C to enable support on
  a wide range of platforms including x64, x86 and ARM. 
- Optimized implementation of the underlying arithmetic functions for x64 platforms with optional, 
  high-performance x64 assembly for Linux. 
- Optimized implementation of the underlying arithmetic functions for 64-bit ARM platforms using assembly
  for Linux.


4. NEW IN VERSION 2.0:
   ------------------
   
- A new variant of the isogeny-based key exchange that includes a new suite of algorithms for efficient
  public key compression [3]. In this variant, public keys are only 330 bytes (compare to 564 bytes
  required by the original SIDH key exchange variant without compression).  
- An optimized implementation of the underlying arithmetic functions for 64-bit ARM (ARMv8) platforms.


5. SUPPORTED PLATFORMS:
   -------------------

SIDH v2.0 is supported on a wide range of platforms including x64, x86 and ARM devices running Windows 
or Linux OS. We have tested the library with Microsoft Visual Studio 2015, GNU GCC v4.9, and clang v3.8.
See instructions below to choose an implementation option and compile on one of the supported platforms.



REFERENCES:
----------

[1]   Craig Costello, Patrick Longa, and Michael Naehrig.
      Efficient algorithms for supersingular isogeny Diffie-Hellman.      
      Advances in Cryptology - CRYPTO 2016, LNCS 9814, pp. 572-601, 2016. 
      Extended version available at: http://eprint.iacr.org/2016/413. 

[2]   David Jao and Luca DeFeo. 
      Towards quantum-resistant cryptosystems from supersingular elliptic curve isogenies.
      PQCrypto 2011, LNCS 7071, pp. 19-34, 2011. 

[3]   Craig Costello, David Jao, Patrick Longa, Michael Naehrig, Joost Renes, and David Urbanik.
      Efficient compression of SIDH public keys.      
      Advances in Cryptology - EUROCRYPT 2017, 2017. 
      Preprint version available at: http://eprint.iacr.org/2016/963. 