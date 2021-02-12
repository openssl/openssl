/*-
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Example of using EVP_MD_fetch and EVP_Digest* methods to calculate
 * a digest of static buffers
 * You can find SHA3 test vectors from NIST here:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
 * Use xxd convert a hex input:
 * echo "1ca984dcc913344370cf" | xxd -r -p | ./EVP_MD_stdin
 */

#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

/*-
 * This demonstration will show how to digest data using
 * a BIO configured with a message digest
 * A message digest name may be passed as an argument.
 * The default digest is sha3-512
 */

int main(int argc, char * argv[])
{
    int result = 1;
    OSSL_LIB_CTX *library_context = NULL;
    BIO *input = NULL;
    BIO *bio_digest = NULL;
    const char *digest_name;
    EVP_MD *md = NULL;
    unsigned char buffer[512];
    size_t readct, writect;
    unsigned char *digest_value=NULL;
    int j;

    if (argc > 1)
        digest_name = argv[1];
    else 
        digest_name = "sha3-512";
    
    input = BIO_new_fd( fileno(stdin), 1 );
    if (input == NULL) {
        fprintf(stderr, "BIO_new_fd() for stdin returned NULL\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    library_context = OSSL_LIB_CTX_new();
    if (library_context == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    md = EVP_MD_fetch( library_context, digest_name, NULL );
    if (md == NULL) {
        fprintf(stderr, "EVP_MD_fetch did not find %s.\n", digest_name);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    size_t digest_size = EVP_MD_size(md);
    digest_value = OPENSSL_malloc(digest_size);
    if (digest_value == NULL) {
        fprintf(stderr, "Can't allocate %lu bytes for the digest value.\n", (unsigned long)digest_size);
        goto cleanup;
    }
/* Make a bio that uses the digest */
    bio_digest = BIO_new(BIO_f_md());
    if (bio_digest == NULL) {
        fprintf(stderr, "BIO_new(BIO_f_md()) returned NULL\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
/* set our bio_digest BIO to digest data */
    if (BIO_set_md(bio_digest,md) != 1) {
           fprintf(stderr, "BIO_set_md failed.\n");
           ERR_print_errors_fp(stderr);
           goto cleanup;
    }
/*
 * We will use BIO chaining so that as we read, the digest gets updated
 * See the man page for BIO_push
 */
    BIO *reading = BIO_push( bio_digest, input );
    
    while( BIO_read(reading, buffer, sizeof(buffer)) > 0 )
        ;

/* Read the digest from bio_digest */
/*
 * BIO_gets must be used to calculate the final
 * digest value.
 */
    if (BIO_gets(bio_digest, digest_value, digest_size) != digest_size) {
        fprintf(stderr, "BIO_gets(bio_digest) failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    for( j=0; j<digest_size; j++ ) {
        fprintf(stdout, "%02x", digest_value[j]);
    }
    fprintf(stdout, "\n");
    result = 0;
    
cleanup:
    OPENSSL_free(digest_value);
    BIO_free(input);
    BIO_free(bio_digest);
    EVP_MD_free(md);
    OSSL_LIB_CTX_free(library_context);

    return result;
}
