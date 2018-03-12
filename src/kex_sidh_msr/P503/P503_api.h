/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: API header file for P503
*********************************************************************************************/

#ifndef __P503_API_H__
#define __P503_API_H__

#include <oqs/rand.h>

#if defined(_WIN32)
#include "../windows_undef.h"
#endif

/*********************** Key encapsulation mechanism API ***********************/

#define OQS_SIDH_MSR_CRYPTO_SECRETKEYBYTES 434 // MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes
#define OQS_SIDH_MSR_CRYPTO_PUBLICKEYBYTES 378
#define OQS_SIDH_MSR_CRYPTO_BYTES 16
#define OQS_SIDH_MSR_CRYPTO_CIPHERTEXTBYTES 402 // CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes

// Algorithm name
#define OQS_SIDH_MSR_CRYPTO_ALGNAME "SIKEp503"

// SIKE's key generation
// It produces a private key sk and computes the public key pk.
// Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = 434 bytes)
//          public key pk (CRYPTO_PUBLICKEYBYTES = 378 bytes)
int crypto_kem_keypair_SIKEp503(unsigned char *pk, unsigned char *sk, OQS_RAND *rand);

// SIKE's encapsulation
// Input:   public key pk         (CRYPTO_PUBLICKEYBYTES = 378 bytes)
// Outputs: shared secret ss      (CRYPTO_BYTES = 16 bytes)
//          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = 402 bytes)
int crypto_kem_enc_SIKEp503(unsigned char *ct, unsigned char *ss, const unsigned char *pk, OQS_RAND *rand);

// SIKE's decapsulation
// Input:   secret key sk         (CRYPTO_SECRETKEYBYTES = 434 bytes)
//          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = 402 bytes)
// Outputs: shared secret ss      (CRYPTO_BYTES = 16 bytes)
int crypto_kem_dec_SIKEp503(unsigned char *ss, const unsigned char *ct, const unsigned char *sk, OQS_RAND *rand);

// Encoding of keys for KEM-based isogeny system "SIKEp503" (wire format):
// ----------------------------------------------------------------------
// Elements over GF(p503) are encoded in 63 octets in little endian format (i.e., the least significant octet is located in the lowest memory address).
// Elements (a+b*i) over GF(p503^2), where a and b are defined over GF(p503), are encoded as {a, b}, with a in the lowest memory portion.
//
// Private keys sk consist of the concatenation of a 24-byte random value, a value in the range [0, 2^252-1] and the public key pk. In the SIKE API,
// private keys are encoded in 434 octets in little endian format.
// Public keys pk consist of 3 elements in GF(p503^2). In the SIKE API, pk is encoded in 378 octets.
// Ciphertexts ct consist of the concatenation of a public key value and a 24-byte value. In the SIKE API, ct is encoded in 378 + 24 = 402 octets.
// Shared keys ss consist of a value of 16 octets.

/*********************** Ephemeral key exchange API ***********************/

#define SIDH_SECRETKEYBYTES 32
#define SIDH_PUBLICKEYBYTES 378
#define SIDH_BYTES 126

// SECURITY NOTE: SIDH supports ephemeral Diffie-Hellman key exchange. It is NOT secure to use it with static keys.
// See "On the Security of Supersingular Isogeny Cryptosystems", S.D. Galbraith, C. Petit, B. Shani and Y.B. Ti, in ASIACRYPT 2016, 2016.
// Extended version available at: http://eprint.iacr.org/2016/859

// Generation of Alice's secret key
// Outputs random value in [0, 2^250 - 1] to be used as Alice's private key
void random_mod_order_A_SIDHp503(unsigned char *random_digits, OQS_RAND *rand);

// Generation of Bob's secret key
// Outputs random value in [0, 2^Floor(Log(2,3^159)) - 1] to be used as Bob's private key
void random_mod_order_B_SIDHp503(unsigned char *random_digits, OQS_RAND *rand);

// Alice's ephemeral public key generation
// Input:  a private key PrivateKeyA in the range [0, 2^250 - 1], stored in 32 bytes.
// Output: the public key PublicKeyA consisting of 3 GF(p503^2) elements encoded in 378 bytes.
int EphemeralKeyGeneration_A_SIDHp503(const unsigned char *PrivateKeyA, unsigned char *PublicKeyA, OQS_RAND *rand);

// Bob's ephemeral key-pair generation
// It produces a private key PrivateKeyB and computes the public key PublicKeyB.
// The private key is an integer in the range [0, 2^Floor(Log(2,3^159)) - 1], stored in 32 bytes.
// The public key consists of 3 GF(p503^2) elements encoded in 378 bytes.
int EphemeralKeyGeneration_B_SIDHp503(const unsigned char *PrivateKeyB, unsigned char *PublicKeyB, OQS_RAND *rand);

// Alice's ephemeral shared secret computation
// It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's public key PublicKeyB
// Inputs: Alice's PrivateKeyA is an integer in the range [0, 2^250 - 1], stored in 32 bytes.
//         Bob's PublicKeyB consists of 3 GF(p503^2) elements encoded in 378 bytes.
// Output: a shared secret SharedSecretA that consists of one element in GF(p503^2) encoded in 126 bytes.
int EphemeralSecretAgreement_A_SIDHp503(const unsigned char *PrivateKeyA, const unsigned char *PublicKeyB, unsigned char *SharedSecretA);

// Bob's ephemeral shared secret computation
// It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's public key PublicKeyA
// Inputs: Bob's PrivateKeyB is an integer in the range [0, 2^Floor(Log(2,3^159)) - 1], stored in 32 bytes.
//         Alice's PublicKeyA consists of 3 GF(p503^2) elements encoded in 378 bytes.
// Output: a shared secret SharedSecretB that consists of one element in GF(p503^2) encoded in 126 bytes.
int EphemeralSecretAgreement_B_SIDHp503(const unsigned char *PrivateKeyB, const unsigned char *PublicKeyA, unsigned char *SharedSecretB);

// Encoding of keys for KEX-based isogeny system "SIDHp503" (wire format):
// ----------------------------------------------------------------------
// Elements over GF(p503) are encoded in 63 octets in little endian format (i.e., the least significant octet is located in the lowest memory address).
// Elements (a+b*i) over GF(p503^2), where a and b are defined over GF(p503), are encoded as {a, b}, with a in the lowest memory portion.
//
// Private keys PrivateKeyA and PrivateKeyB can have values in the range [0, 2^250-1] and [0, 2^252-1], resp. In the SIDH API, private keys are encoded
// in 32 octets in little endian format.
// Public keys PublicKeyA and PublicKeyB consist of 3 elements in GF(p503^2). In the SIDH API, they are encoded in 378 octets.
// Shared keys SharedSecretA and SharedSecretB consist of one element in GF(p503^2). In the SIDH API, they are encoded in 126 octets.

#endif
