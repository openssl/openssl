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
#include <openssl/hmac.h>
#include <openssl/fips_sha.h>
#include <openssl/md5.h>
#include <openssl/err.h>
#include <openssl/fips.h>
#include <openssl/bn.h>                                                                                          
#include <openssl/rand.h>                                                                                          
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

    ERR_clear_error();
    if (AES_set_encrypt_key( userkey, 128, &key ))
	return 0;
    AES_encrypt( plaintext, ciphertext, &key);
    if (AES_set_decrypt_key( userkey, 128, &dkey ))
        return 0;
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

    ERR_clear_error();
    if (DES_set_key(&userkey, &key) < 0)
        return 0;
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

    ERR_clear_error();
    dsa = DSA_generate_parameters(512,NULL,0,NULL,NULL,NULL,NULL);
    if (!dsa)
	return 0;
    if (!DSA_generate_key(dsa))
	return 0;
    if ( DSA_sign(0,dgst,sizeof(dgst) - 1,sig,&siglen,dsa) != 1 )
	return 0;
    if ( DSA_verify(0,dgst,sizeof(dgst) - 1,sig,siglen,dsa) != 1 )
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

    ERR_clear_error();
    key = RSA_generate_key(1024,65537,NULL,NULL);
    if (!key)
	return 0;
    n = RSA_size(key);
    n = RSA_public_encrypt(sizeof(input_ptext) - 1,input_ptext,ctext,key,RSA_PKCS1_PADDING);
    if (n < 0)
	return 0;
    n = RSA_private_decrypt(n,ctext,ptext,key,RSA_PKCS1_PADDING);
    if (n < 0)
	return 0;
    RSA_free(key);
    if (memcmp(input_ptext,ptext,sizeof(input_ptext) - 1))
        return 0;
    return 1;
    }

/* SHA1: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_sha1_test()
    {
    unsigned char digest[SHA_DIGEST_LENGTH] =
        { 0x11, 0xf1, 0x9a, 0x3a, 0xec, 0x1a, 0x1e, 0x8e, 0x65, 0xd4, 0x9a, 0x38, 0x0c, 0x8b, 0x1e, 0x2c, 0xe8, 0xb3, 0xc5, 0x18 };
    unsigned char str[] = "etaonrishd";

    unsigned char md[SHA_DIGEST_LENGTH];

    ERR_clear_error();
    if (!SHA1(str,sizeof(str) - 1,md)) return 0;
    if (memcmp(md,digest,sizeof(md)))
        return 0;
    return 1;
    }

/* SHA256: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_sha256_test()
    {
    unsigned char digest[SHA256_DIGEST_LENGTH] =
	{0xf5, 0x53, 0xcd, 0xb8, 0xcf, 0x1, 0xee, 0x17, 0x9b, 0x93, 0xc9, 0x68, 0xc0, 0xea, 0x40, 0x91,
	 0x6, 0xec, 0x8e, 0x11, 0x96, 0xc8, 0x5d, 0x1c, 0xaf, 0x64, 0x22, 0xe6, 0x50, 0x4f, 0x47, 0x57};
    unsigned char str[] = "etaonrishd";

    unsigned char md[SHA256_DIGEST_LENGTH];

    ERR_clear_error();
    if (!SHA256(str,sizeof(str) - 1,md)) return 0;
    if (memcmp(md,digest,sizeof(md)))
        return 0;
    return 1;
    }

/* SHA512: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_sha512_test()
    {
    unsigned char digest[SHA512_DIGEST_LENGTH] =
	{0x99, 0xc9, 0xe9, 0x5b, 0x88, 0xd4, 0x78, 0x88, 0xdf, 0x88, 0x5f, 0x94, 0x71, 0x64, 0x28, 0xca,
	 0x16, 0x1f, 0x3d, 0xf4, 0x1f, 0xf3, 0x0f, 0xc5, 0x03, 0x99, 0xb2, 0xd0, 0xe7, 0x0b, 0x94, 0x4a,
	 0x45, 0xd2, 0x6c, 0x4f, 0x20, 0x06, 0xef, 0x71, 0xa9, 0x25, 0x7f, 0x24, 0xb1, 0xd9, 0x40, 0x22,
	 0x49, 0x54, 0x10, 0xc2, 0x22, 0x9d, 0x27, 0xfe, 0xbd, 0xd6, 0xd6, 0xeb, 0x2d, 0x42, 0x1d, 0xa3};
    unsigned char str[] = "etaonrishd";

    unsigned char md[SHA512_DIGEST_LENGTH];

    ERR_clear_error();
    if (!SHA512(str,sizeof(str) - 1,md)) return 0;
    if (memcmp(md,digest,sizeof(md)))
        return 0;
    return 1;
    }

/* HMAC-SHA1: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha1_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0x73, 0xf7, 0xa0, 0x48, 0xf8, 0x94, 0xed, 0xdd, 0x0a, 0xea, 0xea, 0x56, 0x1b, 0x61, 0x2e, 0x70,
	 0xb2, 0xfb, 0xec, 0xc6};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha1(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA224: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha224_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0x75, 0x58, 0xd5, 0xbd, 0x55, 0x6d, 0x87, 0x0f, 0x75, 0xff, 0xbe, 0x1c, 0xb2, 0xf0, 0x20, 0x35,
	 0xe5, 0x62, 0x49, 0xb6, 0x94, 0xb9, 0xfc, 0x65, 0x34, 0x33, 0x3a, 0x19};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha224(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA256: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha256_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0xe9, 0x17, 0xc1, 0x7b, 0x4c, 0x6b, 0x77, 0xda, 0xd2, 0x30, 0x36, 0x02, 0xf5, 0x72, 0x33, 0x87,
	 0x9f, 0xc6, 0x6e, 0x7b, 0x7e, 0xa8, 0xea, 0xaa, 0x9f, 0xba, 0xee, 0x51, 0xff, 0xda, 0x24, 0xf4};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha256(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA384: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha384_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0xb2, 0x9d, 0x40, 0x58, 0x32, 0xc4, 0xe3, 0x31, 0xb6, 0x63, 0x08, 0x26, 0x99, 0xef, 0x3b, 0x10,
	 0xe2, 0xdf, 0xf8, 0xff, 0xc6, 0xe1, 0x03, 0x29, 0x81, 0x2a, 0x1b, 0xac, 0xb0, 0x07, 0x39, 0x08,
	 0xf3, 0x91, 0x35, 0x11, 0x76, 0xd6, 0x4c, 0x20, 0xfb, 0x4d, 0xc3, 0xf3, 0xb8, 0x9b, 0x88, 0x1c};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha384(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA512: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha512_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0xcd, 0x3e, 0xb9, 0x51, 0xb8, 0xbc, 0x7f, 0x9a, 0x23, 0xaf, 0xf3, 0x77, 0x59, 0x85, 0xa9, 0xe6,
	 0xf7, 0xd1, 0x51, 0x96, 0x17, 0xe0, 0x92, 0xd8, 0xa6, 0x3b, 0xc1, 0xad, 0x7e, 0x24, 0xca, 0xb1,
	 0xd7, 0x79, 0x0a, 0xa5, 0xea, 0x2c, 0x02, 0x58, 0x0b, 0xa6, 0x52, 0x6b, 0x61, 0x7f, 0xeb, 0x9c,
	 0x47, 0x86, 0x5d, 0x74, 0x2b, 0x88, 0xdf, 0xee, 0x46, 0x69, 0x96, 0x3d, 0xa6, 0xd9, 0x2a, 0x53};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha512(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* MD5: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int md5_test()
    {
    unsigned char digest[MD5_DIGEST_LENGTH] =
	{ 0x48, 0x50, 0xf0, 0xa3, 0x3a, 0xed, 0xd3, 0xaf, 0x6e, 0x47, 0x7f, 0x83, 0x02, 0xb1, 0x09, 0x68 };
    unsigned char str[] = "etaonrishd";

    unsigned char md[MD5_DIGEST_LENGTH];

    ERR_clear_error();
    if (!MD5(str,sizeof(str) - 1,md))
	return 0;
    if (memcmp(md,digest,sizeof(md)))
	return 0;
    return 1;
    }

/* DH: generate shared parameters
*/
static int dh_test()
    {
    DH *dh;

    ERR_clear_error();
    dh = DH_generate_parameters(256, 2, NULL, NULL);
    if (dh)
        return 1;
    return 0;
    }

/* Zeroize
*/
static int Zeroize()
    {
    RSA *key;
    unsigned char userkey[16] = 
	{ 0x48, 0x50, 0xf0, 0xa3, 0x3a, 0xed, 0xd3, 0xaf, 0x6e, 0x47, 0x7f, 0x83, 0x02, 0xb1, 0x09, 0x68 };
    int i, n;
    
    key = RSA_generate_key(1024,65537,NULL,NULL);
    if (!key)
	return 0;
    n = BN_num_bytes(key->d);
    printf(" Generated %d byte RSA private key\n", n);
    printf("\tBN key before overwriting:\n%s\n", BN_bn2hex(key->d));
    BN_rand(key->d,n*8,-1,0);
    printf("\tBN key after overwriting:\n%s\n", BN_bn2hex(key->d));

    printf("\tchar buffer key before overwriting: \n\t\t");
    for(i = 0; i < sizeof(userkey); i++) printf("%02x", userkey[i]);
        printf("\n");
    RAND_bytes(userkey, sizeof userkey);
    printf("\tchar buffer key after overwriting: \n\t\t");
    for(i = 0; i < sizeof(userkey); i++) printf("%02x", userkey[i]);
        printf("\n");

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

    /* Load entropy from external file, if any */
    RAND_load_file(".rnd", 1024);

    if (argv[1]) {
        /* Corrupted KAT tests */
        if (!strcmp(argv[1], "aes")) {
            FIPS_corrupt_aes();
            printf("AES encryption/decryption with corrupted KAT...\n");
        } else if (!strcmp(argv[1], "des")) {
            FIPS_corrupt_des();
            printf("DES-ECB encryption/decryption with corrupted KAT...\n");
        } else if (!strcmp(argv[1], "dsa")) {
            FIPS_corrupt_dsa();
            printf("DSA key generation and signature validation with corrupted KAT...\n");
        } else if (!strcmp(argv[1], "rsa")) {
            FIPS_corrupt_rsa();
            printf("RSA key generation and encryption/decryption with corrupted KAT...\n");
        } else if (!strcmp(argv[1], "sha1")) {
            FIPS_corrupt_sha1();
            printf("SHA-1 hash with corrupted KAT...\n");
	} else if (!strcmp(argv[1], "rng")) {
	    FIPS_corrupt_rng();
	    printf("RNG test with corrupted KAT...\n");
        } else {
            printf("Bad argument \"%s\"\n", argv[1]);
            exit(1);
        }
        if (!FIPS_mode_set(1))
   	    {
	    ERR_load_crypto_strings();
	    ERR_print_errors(BIO_new_fp(stderr,BIO_NOCLOSE));
            printf("Power-up self test failed\n");
	    exit(1);
	}
        printf("Power-up self test successful\n");
        exit(0);
    }

    /* Non-Approved cryptographic operation
    */
    printf("1. Non-Approved cryptographic operation test...\n");
    printf("\ta. Excluded algorithm (MD5)...");
    printf( md5_test() ? "successful\n" :  Fail("FAILED!\n") );
    printf("\tb. Included algorithm (D-H)...");
    printf( dh_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* Power-up self test
    */
    ERR_clear_error();
    printf("2. Automatic power-up self test...");
    if (!FIPS_mode_set(1))
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
    printf("7a. SHA-1 hash...");
    printf( FIPS_sha1_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* SHA-256 hash
    */
    printf("7b. SHA-256 hash...");
    printf( FIPS_sha256_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* SHA-512 hash
    */
    printf("7c. SHA-512 hash...");
    printf( FIPS_sha512_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* HMAC-SHA-1 hash
    */
    printf("7d. SHA-1 hash...");
    printf( FIPS_hmac_sha1_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* HMAC-SHA-224 hash
    */
    printf("7e. SHA-224 hash...");
    printf( FIPS_hmac_sha224_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* HMAC-SHA-256 hash
    */
    printf("7f. SHA-256 hash...");
    printf( FIPS_hmac_sha256_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* HMAC-SHA-384 hash
    */
    printf("7g. SHA-384 hash...");
    printf( FIPS_hmac_sha384_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* HMAC-SHA-512 hash
    */
    printf("7h. SHA-512 hash...");
    printf( FIPS_hmac_sha512_test() ? "successful\n" :  Fail("FAILED!\n") );

    /* Non-Approved cryptographic operation
    */
    printf("8. Non-Approved cryptographic operation test...\n");
    printf("\ta. Excluded algorithm (MD5)...");
    printf( md5_test() ? Fail("passed INCORRECTLY!\n")
	    : "failed as expected\n" );
    printf("\tb. Included algorithm (D-H)...");
    printf( dh_test() ? "successful as expected\n"
	    : Fail("failed INCORRECTLY!\n") );

    /* Zeroization
    */
    printf("9. Zero-ization...\n");
    Zeroize();

    printf("\nAll tests completed with %d errors\n", Error);
    return 0;
    }
#endif
