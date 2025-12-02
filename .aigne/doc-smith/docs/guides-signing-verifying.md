# Signing and Verifying

Master the creation and verification of CMS digital signatures, from simple single-signer messages to complex multi-layered scenarios. This guide provides systematic procedures and code examples to ensure message integrity and authenticity using the OpenSSL CMS API, covering both straightforward and advanced workflows like multi-signer and detached signatures.

Digital signatures are a cornerstone of secure communication, providing authentication, integrity, and non-repudiation. In the Cryptographic Message Syntax (CMS), this is primarily handled by the `SignedData` content type. This guide details the procedures for creating and verifying these signatures using the core functions provided by the OpenSSL library. For a deeper dive into the underlying API functions, refer to the [Main Functions API Reference](./api-main.md).

## Basic Signing Process

Creating a digital signature involves combining the content to be signed with the signer's private key and certificate. The `CMS_sign()` function is the primary high-level entry point for this operation.

### Key Parameters for `CMS_sign()`

The behavior of the signing process is controlled through a set of flags. Understanding these is crucial for generating the correct CMS structure for your use case.

| Flag | Description |
| :--- | :--- |
| `CMS_TEXT` | Prepends standard `text/plain` MIME headers to the content before signing. |
| `CMS_NOCERTS` | Excludes the signer's certificate from the `SignedData` structure. This reduces message size but requires the recipient to have another way to obtain the certificate. |
| `CMS_DETACHED` | Creates a detached signature where the content is not included in the final CMS structure. The signature and content are handled separately. |
| `CMS_BINARY` | Suppresses the default MIME canonicalization of the content. This is essential for signing binary data to prevent corruption. |
| `CMS_NOATTR` | Omits all signed attributes, including signing time and SMIMECapabilities. |
| `CMS_NOSMIMECAP` | Excludes the `SMIMECapabilities` attribute, which lists the cryptographic algorithms supported by the sender. |
| `CMS_STREAM` | Initializes the structure for streaming operations but does not perform the final signing. The data is processed in a single pass when the structure is finalized by a function like `SMIME_write_CMS()`. |
| `CMS_PARTIAL` | Creates a partial `CMS_ContentInfo` structure, allowing for advanced operations like adding multiple signers before finalization. |

### Example: Creating a Detached Signature

This example demonstrates a common use case: creating a detached S/MIME signature for a text file. The process involves loading a signer's certificate and private key, then using `CMS_sign()` with the `CMS_DETACHED` flag.

```c cms_sign.c icon=lucide:file-code
/* Simple S/MIME signing example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *scert = NULL;
    EVP_PKEY *skey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    /* For simple S/MIME signing use CMS_DETACHED. */
    int flags = CMS_DETACHED | CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in signer certificate and private key */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;

    scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    BIO_reset(tbio);
    skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!scert || !skey)
        goto err;

    /* Open content being signed */
    in = BIO_new_file("sign.txt", "r");
    if (!in)
        goto err;

    /* Sign content */
    cms = CMS_sign(scert, skey, NULL, in, flags);
    if (!cms)
        goto err;

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

This code reads the content from `sign.txt`, signs it using `signer.pem`, and writes the resulting detached signature to `smout.txt`. The original content is not included in `smout.txt`.

## Basic Verification Process

Verifying a signature confirms the identity of the signer and ensures the content has not been altered. The `CMS_verify()` function handles this by checking the signature against the provided content and validating the signer's certificate against a trusted store.

### Key Parameters for `CMS_verify()`

The verification process can be customized with the following flags.

| Flag | Description |
| :--- | :--- |
| `CMS_NOINTERN` | Prevents searching for the signer's certificate within the CMS message itself. The certificate must be provided in the `certs` parameter. |
| `CMS_TEXT` | Instructs the function to handle `text/plain` MIME content by stripping the headers before verification. |
| `CMS_NO_SIGNER_CERT_VERIFY` | Skips the certificate chain verification for the signer. The signature on the attributes is still checked. |
| `CMS_NO_ATTR_VERIFY` | Skips the verification of the signed attributes' signature. The content digest is still checked. |
| `CMS_NO_CONTENT_VERIFY` | Skips the final content verification. This is useful for extracting content without validating its integrity. |
| `CMS_CADES` | Enables CAdES (CMS Advanced Electronic Signatures) compliance checks, which imposes stricter rules on certificate verification and signed attributes. |

### Example: Verifying a Signature

This example demonstrates how to verify the signature created previously. It requires a trust store containing the CA certificate (`cacert.pem`) that issued the signer's certificate.

```c cms_ver.c icon=lucide:file-code
/* Simple S/MIME verification example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up trusted CA certificate store */
    st = X509_STORE_new();
    tbio = BIO_new_file("cacert.pem", "r");
    if (!st || !tbio)
        goto err;

    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!cacert)
        goto err;

    if (!X509_STORE_add_cert(st, cacert))
        goto err;

    /* Open message being verified */
    in = BIO_new_file("smout.txt", "r");
    if (!in)
        goto err;

    /* The original content is required for a detached signature */
    cont = BIO_new_file("sign.txt", "r");
    if (!cont)
        goto err;

    /* Parse message */
    cms = SMIME_read_CMS(in, NULL);
    if (!cms)
        goto err;

    /* File to output verified content to */
    out = BIO_new_file("smver.txt", "w");
    if (!out)
        goto err;

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
    BIO_free(cont);
    return ret;
}
```

In this workflow, `CMS_verify` uses the `cont` BIO (containing the original `sign.txt` data) to validate the detached signature from `smout.txt`. The verified content is then written to `smver.txt`.

## Multi-Signer Scenarios

CMS supports messages with multiple signers. This is achieved by first creating a partial `SignedData` structure and then adding each signer individually using `CMS_add1_signer()`.

The process is as follows:
1.  Call `CMS_sign()` with `NULL` for the signer certificate and key, and set the `CMS_PARTIAL` flag. This initializes an empty `SignedData` structure.
2.  For each signer, call `CMS_add1_signer()`, providing their certificate and private key. This function adds a `SignerInfo` structure to the message.
3.  Finalize the structure by writing it out, for example with `SMIME_write_CMS()`. This function computes all the required digests and signatures.

### Example: Creating a Multi-Signer Message

This example creates a message signed by two different entities.

```c cms_sign2.c icon=lucide:file-code
/* S/MIME signing example: 2 signers */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *scert = NULL, *scert2 = NULL;
    EVP_PKEY *skey = NULL, *skey2 = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Load first signer's certificate and key */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio) goto err;
    scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    BIO_reset(tbio);
    skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    BIO_free(tbio);

    /* Load second signer's certificate and key */
    tbio = BIO_new_file("signer2.pem", "r");
    if (!tbio) goto err;
    scert2 = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    BIO_reset(tbio);
    skey2 = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!scert || !skey || !scert2 || !skey2)
        goto err;

    in = BIO_new_file("sign.txt", "r");
    if (!in)
        goto err;

    /* Create a partial CMS structure with no initial signer */
    cms = CMS_sign(NULL, NULL, NULL, in, CMS_STREAM | CMS_PARTIAL);
    if (!cms)
        goto err;

    /* Add each signer in turn */
    if (!CMS_add1_signer(cms, scert, skey, NULL, 0))
        goto err;
    if (!CMS_add1_signer(cms, scert2, skey2, NULL, 0))
        goto err;

    out = BIO_new_file("smout.txt", "w");
    if (!out)
        goto err;

    /* Finalize the structure and write it out */
    if (!SMIME_write_CMS(out, cms, in, CMS_STREAM))
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
    X509_free(scert2);
    EVP_PKEY_free(skey2);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}
```

The verification of a multi-signer message is identical to a single-signer message. `CMS_verify()` will automatically process and check every `SignerInfo` structure present.

## Summary

This guide has provided a structured overview of the fundamental signing and verification workflows in OpenSSL's CMS implementation. By using functions like `CMS_sign()`, `CMS_verify()`, and `CMS_add1_signer()`, you can implement robust solutions for ensuring data integrity and authenticity.

For more advanced topics, see the related guides:
- [Encryption & Decryption](./guides-encrypting-decrypting.md)
- [Signed Receipts](./guides-receipts.md)