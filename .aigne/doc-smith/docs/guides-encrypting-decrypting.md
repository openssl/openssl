# Encryption & Decryption

Securely transmitting sensitive information requires robust encryption, ensuring that only authorized recipients can access the content. This guide provides systematic, step-by-step workflows for encrypting and decrypting data using the OpenSSL implementation of the CMS `EnvelopedData` content type. You will learn the standard process for handling encrypted messages and the less common workflow for detached data.

The procedures outlined here primarily involve the `EnvelopedData` content type, which encapsulates encrypted content and one or more recipient identifiers. Each recipient entry contains a content-encryption key that has been individually encrypted for that specific recipient, typically using their public key. The following diagram illustrates this general concept.

<!-- DIAGRAM_IMAGE_START:flowchart:4:3 -->
![Encryption & Decryption](./assets/diagram/guides-encrypting-decrypting-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

For a more detailed explanation of the underlying structures, refer to the [Content Types](./concepts-content-types.md) and [Recipient Info Types](./concepts-recipient-info-types.md) documentation.

## Standard Workflow: Attached Data

The most common use case involves creating a single S/MIME message where the encrypted content is included within the CMS structure. The following sections detail the process for creating and decrypting these messages.

### Encryption Process

The encryption workflow generates a `CMS_ContentInfo` structure of the `EnvelopedData` type. This structure contains the encrypted data along with the necessary information for each recipient to decrypt it.

The primary function for this operation is `CMS_encrypt()`. It orchestrates the entire process: generating a symmetric content-encryption key (CEK), encrypting the data with the CEK, encrypting the CEK for each recipient using their public key, and assembling these components into the final structure.

The logical steps are as follows:
1.  Initialize OpenSSL libraries.
2.  Load the public certificate for each intended recipient.
3.  Create a `STACK_OF(X509)` and add each recipient's certificate to it.
4.  Open the input data to be encrypted using a `BIO`.
5.  Invoke `CMS_encrypt()`, providing the recipient stack, input `BIO`, a symmetric cipher (e.g., `EVP_des_ede3_cbc()`), and any necessary flags.
6.  Open an output `BIO` for writing the result.
7.  Write the complete S/MIME message using `SMIME_write_CMS()`.
8.  Clean up all allocated resources.

The following example demonstrates a complete encryption operation.

```c cms_enc.c
/* Simple S/MIME encrypt example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    /*
     * On OpenSSL 1.0.0 and later only:
     * for streaming set CMS_STREAM
     */
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

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_X509_new_null();
    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /* rcert is now part of recips and will be freed with it */
    rcert = NULL;

    /* Open content being encrypted */
    in = BIO_new_file("encr.txt", "r");
    if (!in)
        goto err;

    /* Encrypt content */
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

### Decryption Process

Decryption is the reverse operation. A recipient uses their private key to decrypt the content-encryption key (CEK) from their corresponding `RecipientInfo` structure. Once the CEK is recovered, it is used to decrypt the message content.

The `CMS_decrypt()` function handles this process. It requires the recipient's private key and their matching certificate to locate the correct `RecipientInfo` structure and perform the decryption.

The logical steps are:
1.  Initialize OpenSSL libraries.
2.  Load the recipient's private key (`EVP_PKEY`) and public certificate (`X509`).
3.  Open the encrypted S/MIME message using a `BIO`.
4.  Parse the message into a `CMS_ContentInfo` structure with `SMIME_read_CMS()`.
5.  Open an output `BIO` for the decrypted plaintext.
6.  Call `CMS_decrypt()`, providing the `CMS_ContentInfo` structure, the recipient's private key, the certificate, and the output `BIO`.
7.  Clean up all allocated resources.

The following example demonstrates a complete decryption operation.

```c cms_dec.c
/* Simple S/MIME decryption example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

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
    if (BIO_reset(tbio) < 0)
        goto err;
    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (!rcert || !rkey)
        goto err;

    /* Open S/MIME message to decrypt */
    in = BIO_new_file("smencr.txt", "r");
    if (!in)
        goto err;

    /* Parse message */
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

## Advanced Workflow: Detached Data

In some scenarios, the encrypted content may be handled separately from the CMS metadata structure. This is known as detached data. When encrypting, the `CMS_DETACHED` flag is used to create a `CMS_ContentInfo` structure that omits the encrypted content, which must be stored elsewhere. This is an infrequent use case.

### Encryption with Detached Data

When using the `CMS_DETACHED` flag with `CMS_encrypt()`, the function still performs the encryption but writes the resulting ciphertext to a separate `BIO`. The returned `CMS_ContentInfo` structure contains all the necessary recipient information but not the data itself.

The process is similar to standard encryption, with these key differences:
-   The `CMS_DETACHED` flag must be included.
-   A separate `BIO` (`dout` in the example) is required to capture the encrypted output.
-   The `CMS_final()` function is used to finalize the streaming encryption operation.
-   The resulting `CMS_ContentInfo` structure (without content) is written to one file, and the encrypted data is written to another.

```c cms_denc.c
/* S/MIME detached data encrypt example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *dout = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    int flags = CMS_STREAM | CMS_DETACHED;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;
    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!rcert)
        goto err;

    /* Create recipient STACK */
    recips = sk_X509_new_null();
    if (!recips || !sk_X509_push(recips, rcert))
        goto err;
    rcert = NULL;

    /* Open content being encrypted and detached output */
    in = BIO_new_file("encr.txt", "r");
    dout = BIO_new_file("smencr.out", "wb");
    if (in == NULL || dout == NULL)
        goto err;

    /* Encrypt content */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);
    if (!cms)
        goto err;

    out = BIO_new_file("smencr.pem", "w");
    if (!out)
        goto err;

    /* Finalize the streaming encryption, writing ciphertext to dout */
    if (!CMS_final(cms, in, dout, flags))
        goto err;

    /* Write out CMS structure without content */
    if (!PEM_write_bio_CMS(out, cms))
        goto err;

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
    BIO_free(dout);
    BIO_free(tbio);
    return ret;
}
```

### Decryption with Detached Data

To decrypt a message with detached data, you must provide both the `CMS_ContentInfo` structure and the separate file containing the encrypted content. The `CMS_decrypt()` function accepts an additional `BIO` argument (`dcont`) for this purpose.

The key differences from the standard decryption process are:
-   The `CMS_ContentInfo` structure is read from its file (e.g., a `.pem` file).
-   A separate `BIO` is opened for the detached encrypted content.
-   This content `BIO` is passed as the `dcont` argument to `CMS_decrypt()`.

```c cms_ddec.c
/* S/MIME detached data decrypt example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *dcont = NULL;
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
    if (BIO_reset(tbio) < 0)
        goto err;
    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (!rcert || !rkey)
        goto err;

    /* Open PEM file containing enveloped data structure */
    in = BIO_new_file("smencr.pem", "r");
    if (!in)
        goto err;

    /* Parse PEM content */
    cms = PEM_read_bio_CMS(in, NULL, 0, NULL);
    if (!cms)
        goto err;

    /* Open file containing detached content */
    dcont = BIO_new_file("smencr.out", "rb");
    if (dcont == NULL)
        goto err;

    out = BIO_new_file("encrout.txt", "w");
    if (!out)
        goto err;

    /* Decrypt S/MIME message using detached content */
    if (!CMS_decrypt(cms, rkey, rcert, dcont, out, 0))
        goto err;

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
    BIO_free(dcont);
    return ret;
}
```

## Summary

This guide has provided a complete, methodical overview of encryption and decryption workflows using the OpenSSL CMS API. You have seen how to handle both standard attached data and less common detached data scenarios. By following these structured examples, you can reliably implement secure data exchange in your applications.

For more detailed information on the functions used, please consult the relevant entries in the [API Reference](./api.md) section. Additional guides on related topics are also available:

<x-cards data-columns="2">
  <x-card data-title="Signing and Verifying" data-icon="lucide:pen-square" data-href="/guides/signing-verifying">
    Learn how to create and validate digital signatures on CMS messages.
  </x-card>
  <x-card data-title="API Reference" data-icon="lucide:book-text" data-href="/api">
    Explore the full OpenSSL CMS API for advanced operations.
  </x-card>
</x-cards>