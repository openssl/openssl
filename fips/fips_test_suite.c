/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
 *
 *
 * This command is intended as a test driver for the FIPS-140 testing
 * lab performing FIPS-140 validation.  It demonstrates the use of the
 * OpenSSL library ito perform a variety of common cryptographic
 * functions.  A power-up self test is demonstrated by deliberately
 * pointing to an invalid executable hash
 *
 * Contributed by Steve Marquess.
 *
 */
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/fips.h>

#ifndef OPENSSL_FIPS
int main(int argc, char *argv[])
    {
    printf("No FIPS support\n");
    return(0);
    }
#else

/* AES: encrypt and decrypt known plaintext, verify result matches original plaintext
*/
static int FIPS_aes_test()
    {
    unsigned char userkey[16] = { 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xf0, 0x0d };
    unsigned char plaintext[16] = "etaonrishdlcu";
    unsigned char ciphertext[16];
    unsigned char buf[16];
    AES_KEY key;
    AES_KEY dkey;

    if (AES_set_encrypt_key( userkey, 128, &key ))
	return 0;
    AES_encrypt( plaintext, ciphertext, &key);
    AES_set_decrypt_key( userkey, 128, &dkey );
    AES_decrypt( ciphertext, buf, &dkey);
    if (memcmp(buf, plaintext, sizeof(buf)))
        return 0;
    return 1;

    }

/* DES: encrypt and decrypt known plaintext, verify result matches original plaintext
*/
static int FIPS_des_test()
    {
    DES_cblock userkey = { 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xf0, 0x0d };
    DES_cblock plaintext = { 'e', 't', 'a', 'o', 'n', 'r', 'i', 's' };

    DES_key_schedule key;
    DES_cblock ciphertext;
    DES_cblock buf;

    DES_set_key(&userkey, &key);
    DES_ecb_encrypt( &plaintext, &ciphertext, &key, 1);
    DES_ecb_encrypt( &ciphertext, &buf, &key, 0);
    if (memcmp(buf, plaintext, sizeof(buf)))
        return 0;
    return 1;
    }

/* DSA: generate key and sign a known digest, then verify the signature
 * against the digest
*/
static int FIPS_dsa_test()
    {
    DSA *dsa = NULL;
    unsigned char dgst[] = "etaonrishdlc";
    unsigned char sig[256];
    unsigned int siglen;

    dsa = DSA_generate_parameters(512,NULL,0,NULL,NULL,NULL,NULL);
    if (!dsa)
	return 0;
    DSA_generate_key(dsa);
    if ( DSA_sign(0,dgst,strlen(dgst),sig,&siglen,dsa) != 1 )
	return 0;
    if ( DSA_verify(0,dgst,strlen(dgst),sig,siglen,dsa) != 1 )
	return 0;
    DSA_free(dsa);
    return 1;
    }

/* RSA: generate keys and encrypt and decrypt known plaintext, verify result
 * matches the original plaintext
*/
static int FIPS_rsa_test()
    {
    RSA *key;
    unsigned char input_ptext[] = "etaonrishdlc";
    unsigned char ctext[256];
    unsigned char ptext[256];
    int n;

    key = RSA_generate_key(1024,65537,NULL,NULL);
    if (!key)
	return 0;
    n = RSA_size(key);
    n = RSA_public_encrypt(strlen(input_ptext),input_ptext,ctext,key,RSA_PKCS1_PADDING);
    if (n < 0)
	return 0;
    n = RSA_private_decrypt(n,ctext,ptext,key,RSA_PKCS1_PADDING);
    if (n < 0)
	return 0;
    RSA_free(key);
    if (memcmp(input_ptext,ptext,strlen(input_ptext)))
        return 0;
    return 1;
    }

/* SHA1: generate hash of known digest value and compate to known precomputed correct hash
*/
static int FIPS_sha1_test()
    {
    unsigned char digest[SHA_DIGEST_LENGTH] =
        { 0x11, 0xf1, 0x9a, 0x3a, 0xec, 0x1a, 0x1e, 0x8e, 0x65, 0xd4, 0x9a, 0x38, 0x0c, 0x8b, 0x1e, 0x2c, 0xe8, 0xb3, 0xc5, 0x18 };
    char str[] = "etaonrishd";

    unsigned char md[SHA_DIGEST_LENGTH];

    if (!SHA1(str,strlen(str),md)) return 0;
    if (memcmp(md,digest,sizeof(md)))
        return 0;
    return 1;
    }

static int Error;
const char * Fail(const char *msg)
    {
    Error++;
    return msg; 
    }

int main(int argc,char **argv)
    {

    printf("\tFIPS-mode test application\n\n");

    /* Power-up self test failure
    */
    printf("1. Automatic power-up self test...");
    printf( FIPS_mode_set(1,"/dev/null") ? Fail("passed INCORRECTLY!\n") : "failed as expected\n" );

    /* Algorithm call when uninitialized failure
    */
    printf("\ta. AES API failure on failed power-up self test...");
    printf( FIPS_aes_test() ? Fail("passed INCORRECTLY!\n") :"failed as expected\n" );
    printf("\tb. RSA API failure on failed power-up self test...");
    printf( FIPS_rsa_test() ? Fail("passed INCORRECTLY!\n") :  "failed as expected\n" );
    printf("\tc. DES API failure on failed power-up self test...");
    printf( FIPS_des_test() ? Fail("passed INCORRECTLY!\n") : "failed as expected\n" );
    printf("\td. DSA API failure on failed power-up self test...");
    printf( FIPS_dsa_test() ? Fail("passed INCORRECTLY!\n") :  "failed as expected\n" );
    printf("\te. SHA1 API failure on failed power-up self test...");
    printf( FIPS_sha1_test() ? Fail("passed INCORRECTLY!\n") : "failed as expected\n" );

    /* Power-up self test retry
    */
    printf("2. Automatic power-up self test retry...");
    if(!FIPS_mode_set(1,argv[0]))
	{
	ERR_load_crypto_strings();
	ERR_print_errors(BIO_new_fp(stderr,BIO_NOCLOSE));
        printf(Fail("FAILED!\n"));
	exit(1);
	}
    printf("successful\n");

    /* AES encryption/decryption
    */
    printf("3. AES encryption/decryption...");
    printf( FIPS_aes_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* RSA key generation and encryption/decryption
    */
    printf("4. RSA key generation and encryption/decryption...");
    printf( FIPS_rsa_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* DES-CBC encryption/decryption
    */
    printf("5. DES-ECB encryption/decryption...");
    printf( FIPS_des_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* DSA key generation and signature validation
    */
    printf("6. DSA key generation and signature validation...");
    printf( FIPS_dsa_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* SHA-1 hash
    */
    printf("7. SHA-1 hash...");
    printf( FIPS_sha1_test() ? "successful\n" :  Fail("FAILED!\n") );

    printf("\nAll tests completed with %d errors\n", Error);
    return 0;
    }
#endif
