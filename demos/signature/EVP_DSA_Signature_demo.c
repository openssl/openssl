/*-
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * An example that uses the EVP_PKEY*, EVP_DigestSign* and EVP_DigestVerify*
 * methods to calculate public/private DSA keypair and to sign and verify
 * two static buffers.
 */

#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <openssl/dsa.h>

/*
 * This demonstration will calculate and verify a signature of data using
 * the soliloquy from Hamlet scene 1 act 3
 */

static const char *hamlet_1 =
    "To be, or not to be, that is the question,\n"
    "Whether tis nobler in the minde to suffer\n"
    "The slings and arrowes of outragious fortune,\n"
    "Or to take Armes again in a sea of troubles,\n"
;
static const char *hamlet_2 =
    "And by opposing, end them, to die to sleep;\n"
    "No more, and by a sleep, to say we end\n"
    "The heart-ache, and the thousand natural shocks\n"
    "That flesh is heir to? tis a consumation\n"
;

static const char ALG[] = "DSA";
static const char DIGEST[] = "SHA256";
static const int NUMBITS = 1024;
static const char * const PROPQUERY = NULL;

static int generate_dsa_params(OSSL_LIB_CTX *libctx,
                               EVP_PKEY **p_params)
{
    int result = 0;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *params = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(libctx, ALG, PROPQUERY);
    if (ctx == NULL)
        goto end;

    if (EVP_PKEY_paramgen_init(ctx) <= 0)
        goto end;

    if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, NUMBITS) <= 0)
        goto end;
    if (EVP_PKEY_paramgen(ctx, &params) <= 0)
        goto end;
    if (params == NULL)
        goto end;

    result = 1;
end:
    if(!result) {
        EVP_PKEY_free(params);
        params = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    *p_params = params;
    fprintf(stdout, "Params:\n");
    EVP_PKEY_print_params_fp(stdout, params, 4, NULL);
    fprintf(stdout, "\n");

    return result;
}

static int generate_dsa_key(OSSL_LIB_CTX *libctx,
                            EVP_PKEY *params,
                            EVP_PKEY **p_pkey)
{
    int result = 0;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, params,
                                     NULL);
    if (ctx == NULL)
        goto end;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto end;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto end;
    if (pkey == NULL)
        goto end;

    result = 1;
end:
    if(!result) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    *p_pkey = pkey;
    fprintf(stdout, "Generating public/private key pair:\n");
    EVP_PKEY_print_public_fp(stdout, pkey, 4, NULL);
    fprintf(stdout, "\n");
    EVP_PKEY_print_private_fp(stdout, pkey, 4, NULL);
    fprintf(stdout, "\n");
    EVP_PKEY_print_params_fp(stdout, pkey, 4, NULL);
    fprintf(stdout, "\n");

    return result;
}

static int demo_sign(OSSL_LIB_CTX *libctx,
                     size_t *p_sig_len, unsigned char **p_sig_value,
                     EVP_PKEY *pkey)
{
    int result = 0;
    size_t sig_len = 0;
    unsigned char *sig_value = NULL;
    EVP_MD_CTX *ctx = NULL;

    ctx = EVP_MD_CTX_create();
    if (ctx == NULL)
        goto end;

    if (EVP_DigestSignInit_ex(ctx, NULL, DIGEST, libctx, NULL, pkey, NULL) != 1)
        goto end;

   if (EVP_DigestSignUpdate(ctx, hamlet_1, sizeof(hamlet_1)) != 1)
        goto end;

   if (EVP_DigestSignUpdate(ctx, hamlet_2, sizeof(hamlet_2)) != 1)
        goto end;

    if (EVP_DigestSignFinal(ctx, NULL, &sig_len) != 1)
        goto end;
    if (sig_len <= 0)
        goto end;

    sig_value = OPENSSL_malloc(sig_len);
    if (sig_value == NULL)
        goto end;

    if (EVP_DigestSignFinal(ctx, sig_value, &sig_len) != 1)
        goto end;

    result = 1;
end:
    EVP_MD_CTX_destroy(ctx);
    if (!result) {
        OPENSSL_free(sig_value);
        sig_len = 0;
        sig_value = NULL;
    }
    *p_sig_len = sig_len;
    *p_sig_value = sig_value;
    fprintf(stdout, "Generating signature:\n");
    BIO_dump_indent_fp(stdout, sig_value, sig_len, 2);
    fprintf(stdout, "\n");
    return result;
}

static int demo_verify(OSSL_LIB_CTX *libctx,
                       size_t sig_len, unsigned char *sig_value,
                       EVP_PKEY *pkey)
{
    int result = 0;
    EVP_MD_CTX *ctx = NULL;

    ctx = EVP_MD_CTX_create();
    if(ctx == NULL)
        goto end;

    if (EVP_DigestVerifyInit_ex(ctx, NULL, DIGEST, libctx, NULL, pkey, NULL) != 1)
        goto end;

    if (EVP_DigestVerifyUpdate(ctx, hamlet_1, sizeof(hamlet_1)) != 1)
        goto end;

    if (EVP_DigestVerifyUpdate(ctx, hamlet_2, sizeof(hamlet_2)) != 1)
        goto end;

    /* Clear any errors for the call below */
    ERR_clear_error();

    if (EVP_DigestVerifyFinal(ctx, sig_value, sig_len) != 1)
        goto end;

    result = 1;
end:
    EVP_MD_CTX_destroy(ctx);
    return result;
}

int main(void)
{
    int result = 0;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY *pkey = NULL;
    size_t sig_len = 0;
    unsigned char *sig_value = NULL;

    libctx = OSSL_LIB_CTX_new();

    if (!generate_dsa_params(libctx, &params))
        goto end;

    if (!generate_dsa_key(libctx, params, &pkey))
        goto end;

    if (!demo_sign(libctx, &sig_len, &sig_value, pkey))
        goto end;

    if (!demo_verify(libctx, sig_len, sig_value, pkey))
        goto end;

    result = 1;
end:
    if (!result)
        ERR_print_errors_fp(stderr);

    OPENSSL_free(sig_value);
    EVP_PKEY_free(params);
    EVP_PKEY_free(pkey);
    OSSL_LIB_CTX_free(libctx);

    return result ? 0 : 1;
}
