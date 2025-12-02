This guide provides a direct, hands-on approach to performing the most common Cryptographic Message Syntax (CMS) operations using the OpenSSL API. By following these steps, you will learn to sign, verify, encrypt, and decrypt data programmatically, forming a practical foundation for building secure messaging applications.

## Prerequisites

Before proceeding, ensure the following components are prepared. These examples assume all files are in the current working directory.

1.  **A C Compiler and OpenSSL Development Libraries:** Your system must be able to compile C code and link against the OpenSSL libraries (`libcrypto`).
2.  **CA Certificate (`cacert.pem`):** A root certificate used to establish a trust anchor.
3.  **Signer's Certificate and Private Key (`signer.pem`):** A single file containing both the end-entity certificate (issued by the CA) and its corresponding private key. This will be used for both signing and decryption.
4.  **Content Files:**
    *   `sign.txt`: Plaintext content for the signing/verification example.
    *   `encr.txt`: Plaintext content for the encryption/decryption example.

You can generate the necessary certificates and keys using the `openssl req` and `openssl ca` commands. For this guide, we assume they have already been created.

## Signing Data (Detached)

A detached signature is created separately from the content it signs. This is useful when you need to distribute the content in its original form, with the signature provided as a separate file or message part.

The process involves loading a signer's private key and certificate, reading the content, and using `CMS_sign()` to generate a `SignedData` structure.

### Signing Example Code

The following code reads content from `sign.txt`, signs it using the credentials in `signer.pem`, and writes the detached signature to `smout.txt`.

```c cms_sign.c icon=lucide:file-code
/* Simple S/MIME signing example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *scert = NULL;
    EVP_PKEY *skey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    /* Use detached signatures and streaming for efficiency */
    int flags = CMS_DETACHED | CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in signer certificate and private key from one file */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;

    scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    BIO_reset(tbio);
    skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (!scert || !skey)
        goto err;

    /* Open content to be signed */
    in = BIO_new_file("sign.txt", "r");
    if (!in)
        goto err;

    /* Sign content */
    cms = CMS_sign(scert, skey, NULL, in, flags);
    if (!cms)
        goto err;

    /* Open file to write S/MIME message to */
    out = BIO_new_file("smout.txt", "w");
    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;

    ret = EXIT_SUCCESS;

err:
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Error Signing Data\n");
        ERR_print_errors_fp(stderr);
    }
    CMS_ContentInfo_free(cms);
    X509_free(scert);
    EVP_PKEY_free(skey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}
```

### Command-Line Equivalent

The same operation can be performed using the `openssl cms` command-line tool. This is useful for scripting and quick tests.

```sh Signing with OpenSSL CLI icon=lucide:terminal
openssl cms -sign -in sign.txt -out smout.txt -signer signer.pem -nodetach
```

:::info
The C example uses `CMS_DETACHED`, while the CLI example uses `-nodetach` to create an opaque signature for simplicity. To create a detached signature with the CLI, use the `-detach` flag and specify the original content during verification with `-content sign.txt`.
:::

## Verifying Data

Verification confirms the authenticity and integrity of the original data. It requires the detached signature, the original (unmodified) content, and a trusted CA certificate to validate the signer's certificate.

The process uses `CMS_verify()` to check the signature's validity against the provided content and certificate store.

### Verification Example Code

This code verifies the signature in `smout.txt` against the original content (`sign.txt`, which is referenced inside `smout.txt`). It uses `cacert.pem` to build a trusted certificate chain. The verified content is written to `smver.txt`.

```c cms_ver.c icon=lucide:file-code
/* Simple S/MIME verification example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Create a new certificate store */
    st = X509_STORE_new();
    if (st == NULL)
        goto err;

    /* Read in the trusted CA certificate */
    tbio = BIO_new_file("cacert.pem", "r");
    if (!tbio)
        goto err;

    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!cacert)
        goto err;

    if (!X509_STORE_add_cert(st, cacert))
        goto err;

    /* Open the S/MIME message to verify */
    in = BIO_new_file("smout.txt", "r");
    if (!in)
        goto err;

    /* Parse the S/MIME message */
    cms = SMIME_read_CMS(in, &cont);
    if (!cms)
        goto err;

    /* Open file to output the verified content to */
    out = BIO_new_file("smver.txt", "w");
    if (!out)
        goto err;

    /* Verify the signature */
    if (!CMS_verify(cms, NULL, st, cont, out, 0)) {
        fprintf(stderr, "Verification Failure\n");
        goto err;
    }

    printf("Verification Successful\n");
    ret = EXIT_SUCCESS;

err:
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Error Verifying Data\n");
        ERR_print_errors_fp(stderr);
    }
    X509_STORE_free(st);
    CMS_ContentInfo_free(cms);
    X509_free(cacert);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}
```

### Command-Line Equivalent

```sh Verifying with OpenSSL CLI icon=lucide:terminal
openssl cms -verify -in smout.txt -CAfile cacert.pem -out smver.txt
```

## Encrypting Data

CMS encryption, which creates an `EnvelopedData` structure, secures data for one or more recipients. Each recipient's public key (from their certificate) is used to encrypt a unique copy of the content encryption key.

The process involves loading recipient certificates, reading the content, and calling `CMS_encrypt()`.

### Encryption Example Code

The following code encrypts the content of `encr.txt` for a single recipient whose certificate is in `signer.pem`. The resulting S/MIME message is written to `smencr.txt`.

```c cms_enc.c icon=lucide:file-code
/* Simple S/MIME encrypt example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    /* Use streaming for efficiency */
    int flags = CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!rcert)
        goto err;

    /* Create recipient STACK and add the certificate to it */
    recips = sk_X509_new_null();
    if (!recips || !sk_X509_push(recips, rcert))
        goto err;
    rcert = NULL; /* Ownership is transferred to the STACK */

    /* Open content to be encrypted */
    in = BIO_new_file("encr.txt", "r");
    if (!in)
        goto err;

    /* Encrypt the content */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);
    if (!cms)
        goto err;

    out = BIO_new_file("smencr.txt", "w");
    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;

    printf("Encryption Successful\n");
    ret = EXIT_SUCCESS;

err:
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }
    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    OSSL_STACK_OF_X509_free(recips);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}
```

### Command-Line Equivalent

```sh Encrypting with OpenSSL CLI icon=lucide:terminal
openssl cms -encrypt -in encr.txt -out smencr.txt -outform SMIME signer.pem
```

## Decrypting Data

Decryption requires the recipient's private key and their corresponding certificate. The private key is used to decrypt the content encryption key, which in turn is used to decrypt the message content.

The main function for this operation is `CMS_decrypt()`.

### Decryption Example Code

This code decrypts the message in `smencr.txt` using the private key and certificate from `signer.pem`. The recovered plaintext is written to `decout.txt`.

```c cms_dec.c icon=lucide:file-code
/* Simple S/MIME decryption example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    EVP_PKEY *rkey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate and private key */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    BIO_reset(tbio);
    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (!rcert || !rkey)
        goto err;

    /* Open S/MIME message to decrypt */
    in = BIO_new_file("smencr.txt", "r");
    if (!in)
        goto err;

    /* Parse the S/MIME message */
    cms = SMIME_read_CMS(in, NULL);
    if (!cms)
        goto err;

    out = BIO_new_file("decout.txt", "w");
    if (!out)
        goto err;

    /* Decrypt S/MIME message */
    if (!CMS_decrypt(cms, rkey, rcert, NULL, out, 0))
        goto err;

    printf("Decryption Successful\n");
    ret = EXIT_SUCCESS;

err:
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Error Decrypting Data\n");
        ERR_print_errors_fp(stderr);
    }
    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    EVP_PKEY_free(rkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}
```

### Command-Line Equivalent

```sh Decrypting with OpenSSL CLI icon=lucide:terminal
openssl cms -decrypt -in smencr.txt -inkey signer.pem -recip signer.pem -out decout.txt
```

## Summary

This guide has demonstrated the fundamental operations of the OpenSSL CMS API. You have successfully signed, verified, encrypted, and decrypted data using both programmatic C examples and their command-line equivalents. These foundational workflows can be adapted and expanded to build more complex security protocols.

For more advanced scenarios, refer to the [How-To Guides](./guides.md) and the detailed [API Reference](./api.md).