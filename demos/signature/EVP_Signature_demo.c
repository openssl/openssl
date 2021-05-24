/*-
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Example of using EVP_MD*, EVP_DigestSign* and EVP_DigestVerify* methods
 * to calculate and verify a signature of static buffers.
 * Another way of signature is to use EVP_PKEY_sign(), it uses a digest
 * of message, does not hash the data to be signed, and therefore is
 * normally used to sign digests.
 */

#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "EVP_Signature_demo.h"
#include <openssl/decoder.h>

/*
 * This demonstration will show calculate and verify a signature of data using
 * the soliloqy from Hamlet scene 1 act 3
 */

static const char *hamlet_1 =
    "To be, or not to be, that is the question,\n"
    "Whether tis nobler in the minde to suffer\n"
    "The ?lings and arrowes of outragious fortune,\n"
    "Or to take Armes again in a sea of troubles,\n"
    "And by opposing, end them, to die to sleep;\n"
    "No more, and by a sleep, to say we end\n"
    "The heart-ache, and the thousand natural shocks\n"
    "That flesh is heir to? tis a consumation\n"
;

static const char *hamlet_2 =
    "Devoutly to be wished. To die to sleep,\n"
    "To sleepe, perchance to dreame, Aye, there's the rub,\n"
    "For in that sleep of death what dreams may come\n"
    "When we haue shuffled off this mortal coil\n"
    "Must give us pause. There's the respect\n"
    "That makes calamity of so long life:\n"
    "For who would bear the Ships and Scorns of time,\n"
    "The oppressor's wrong, the proud man's Contumely,\n"
    "The pangs of dispised love, the Law's delay,\n"
;

/*
 * For demo_sign, load EC private key priv_key from priv_key_der[].
 * For demo_verify, load EC public key pub_key from pub_key_der[].
 */
static EVP_PKEY *get_key(OSSL_LIB_CTX *libctx, const char *propq, int public)
{
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY  *pkey = NULL;
    int selection;
    const unsigned char *data;
    size_t data_len;

    if (public) {
        selection = EVP_PKEY_PUBLIC_KEY;
        data =  pub_key_der;
        data_len = sizeof(pub_key_der);
    } else {
        selection =  EVP_PKEY_KEYPAIR;
        data = priv_key_der;
        data_len = sizeof(priv_key_der);
    }
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, "EC",
                                         selection, libctx, propq);
    (void)OSSL_DECODER_from_data(dctx, &data, &data_len);
    OSSL_DECODER_CTX_free(dctx);
    if (pkey == NULL)
        fprintf(stderr, "Failed to load %s key.\n", public ? "Public" : "Private");
    return pkey;
}

static int demo_sign(OSSL_LIB_CTX *libctx,  const char *sig_name,
                     size_t *sig_out_len, unsigned char **sig_out_value)
{
    int i = 0, j = 0, result = 0, public = 0;
    size_t sig_len;
    unsigned char *sig_value = NULL;
    const char *propq = NULL;
    EVP_MD_CTX *sign_context = NULL;
    const EVP_MD *sig_alg = NULL;
    EVP_PKEY *priv_key = NULL;
    
    /* Get private key */
    priv_key = get_key(libctx, propq, public);
    if (priv_key == NULL) {
        fprintf(stderr, "Get private key failed.\n");
        goto cleanup;
    }
    /*
     * Make a message signature context to hold temporary state
     * during signature creation
     */
    sign_context = EVP_MD_CTX_new();
    if (sign_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }
    /*
     * Initialize the sign context to use the fetched
     * sign provider.
     */
    if (EVP_DigestSignInit_ex(sign_context, NULL, sig_name,
                              libctx, NULL, priv_key, NULL) != 1) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed.\n");
        goto cleanup;
    }
    /*
     * EVP_MD_CTX_get1_md returns the EVP_MD structure corresponding
     * to the passed EVP_MD_CTX.
     */
    sig_alg = EVP_MD_CTX_get0_md(sign_context);
    if (sig_alg == NULL) {
        fprintf(stderr, "EVP_MD_CTX_get1_md returned NULL.");
        goto cleanup;
    }
    /*
     * EVP_DigestSignUpdate() can be called several times on the same context
     * to include additional data.
     */
    if (EVP_DigestSignUpdate(sign_context, hamlet_1, strlen(hamlet_1)) != 1) {
        fprintf(stderr, "EVP_DigestSignUpdate(hamlet_1) failed.\n");
        goto cleanup;
    }
    if (EVP_DigestSignUpdate(sign_context, hamlet_2, strlen(hamlet_2)) != 1) {
        fprintf(stderr, "EVP_DigestSignUpdate(hamlet_2) failed.\n");
        goto cleanup;
    }
    /* Call EVP_DigestSignFinal to get signature length sig_len */
    if (EVP_DigestSignFinal(sign_context, NULL, &sig_len) != 1) {
        fprintf(stderr, "EVP_DigestSignFinal failed.\n");
        goto cleanup;
    }
    if (sig_len <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal returned invalid signature length.\n");
        goto cleanup;
    }
    sig_value = OPENSSL_malloc(sig_len);
    if (sig_value == NULL) {
        fprintf(stderr, "No memory.\n");
        goto cleanup;
    }
    if (EVP_DigestSignFinal(sign_context, sig_value, &sig_len) != 1) {
        fprintf(stderr, "EVP_DigestSignFinal failed.\n");
        goto cleanup;
    }
    *sig_out_len = sig_len;
    *sig_out_value = sig_value;
    for (j = 0; j < sig_len; j++)
        fprintf(stdout, "%02x", sig_value[j]);
    fprintf(stdout, "\n");
    fprintf(stdout, "Signature calculated properly.\n");
    result = 1;

cleanup:
    /* OpenSSL free functions will ignore NULL arguments */
    if (!result)
        OPENSSL_free(sig_value);
    EVP_PKEY_free(priv_key);
    EVP_MD_CTX_free(sign_context);
    return result;
}

static int demo_verify(OSSL_LIB_CTX *libctx, const char *sig_name,
                       size_t sig_len, unsigned char *sig_value)
{
    int result = 0, i = 0, public = 1;
    const char *propq = NULL;
    EVP_MD_CTX *verify_context = NULL;
    EVP_PKEY *pub_key = NULL;

    /*
     * Make a verify signature context to hold temporary state
     * during signature verification
     */    
    verify_context = EVP_MD_CTX_new();
    if (verify_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }
    /*Get public key*/
    pub_key = get_key(libctx, propq, public);
    if (pub_key == NULL) {
        fprintf(stderr, "Get public key failed.\n");
        goto cleanup;
    }
    /* Verify */
    if (EVP_DigestVerifyInit_ex(verify_context, NULL, sig_name,
                                libctx, NULL, pub_key, NULL) != 1) {
        fprintf(stderr, "EVP_DigestVerifyInit failed.\n");
        goto cleanup;
    }
    /*
     * EVP_DigestVerifyUpdate() can be called several times on the same context
     * to include additional data.
     */
    if (EVP_DigestVerifyUpdate(verify_context, hamlet_1, strlen(hamlet_1)) != 1) {
        fprintf(stderr, "EVP_DigestVerifyUpdate(hamlet_1) failed.\n");
        goto cleanup;
    }
    if (EVP_DigestVerifyUpdate(verify_context, hamlet_2, strlen(hamlet_2)) != 1) {
        fprintf(stderr, "EVP_DigestVerifyUpdate(hamlet_2) failed.\n");
        goto cleanup;
    }
    
    if (EVP_DigestVerifyFinal(verify_context, sig_value, sig_len) != 1) {
        fprintf(stderr, "EVP_DigestVerifyFinal failed.\n");
        goto cleanup;
    } else {
        fprintf(stdout, "Signature verified properly.\n");
        result = 1;
    }

cleanup:
    /* OpenSSL free functions will ignore NULL arguments */
    EVP_PKEY_free(pub_key);
    EVP_MD_CTX_free(verify_context);
    return result;
}

int main(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    const char *sig_name = "SHA3-512";
    size_t sig_len = 0;
    unsigned char *sig_value = NULL;
    int result = 0;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
        goto cleanup;
    }
    if (demo_sign(libctx, sig_name, &sig_len, &sig_value) != 1) {
        fprintf(stderr, "demo_sign failed.\n");
        goto cleanup;
    }
    if (demo_verify(libctx, sig_name, sig_len, sig_value) != 1) {
        fprintf(stderr, "demo_verify failed.\n");
        goto cleanup;
    }
    result = 1;

cleanup:
    if (result != 1)
        ERR_print_errors_fp(stderr);
    /* OpenSSL free functions will ignore NULL arguments */
    OSSL_LIB_CTX_free(libctx);
    OPENSSL_free(sig_value);
    return result == 0;
}
