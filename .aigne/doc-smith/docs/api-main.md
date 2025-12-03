# Main Functions

This section provides a detailed reference for the high-level functions used to create, parse, finalize, and manage core Cryptographic Message Syntax (CMS) structures. These functions serve as the primary entry points for common operations such as signing, verifying, encrypting, and decrypting data.

The following diagram illustrates the relationship between the main CMS functions for signing/verifying and encrypting/decrypting data flows.

<!-- DIAGRAM_IMAGE_START:flowchart:16:9 -->
![Main Functions](./assets/diagram/api-main-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## Signing and Verification

These functions handle the creation and verification of CMS `SignedData` structures, which are fundamental for ensuring data integrity and authenticity.

### CMS_sign

The `CMS_sign()` and `CMS_sign_ex()` functions create a `CMS_ContentInfo` structure of the `SignedData` type. This operation involves signing data with a private key and including the corresponding certificate, along with any additional certificates, to form a complete, verifiable message.

#### Synopsis

```c
#include <openssl/cms.h>

CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
                          BIO *data, unsigned int flags);

CMS_ContentInfo *CMS_sign_ex(X509 *signcert, EVP_PKEY *pkey,
                             STACK_OF(X509) *certs, BIO *data,
                             unsigned int flags, OSSL_LIB_CTX *libctx,
                             const char *propq);
```

#### Parameters

<x-field-group>
  <x-field data-name="signcert" data-type="X509*" data-required="false" data-desc="The certificate of the signer. Can be NULL for a certificate-only structure."></x-field>
  <x-field data-name="pkey" data-type="EVP_PKEY*" data-required="false" data-desc="The private key corresponding to signcert. Can be NULL for a certificate-only structure."></x-field>
  <x-field data-name="certs" data-type="STACK_OF(X509)*" data-required="false" data-desc="An optional stack of additional certificates to include in the structure, such as intermediate CAs."></x-field>
  <x-field data-name="data" data-type="BIO*" data-required="true" data-desc="A BIO containing the data to be signed."></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="A bitmask of flags to control the signing operation."></x-field>
  <x-field data-name="libctx" data-type="OSSL_LIB_CTX*" data-required="false" data-desc="An OpenSSL library context (for CMS_sign_ex). If NULL, the default context is used."></x-field>
  <x-field data-name="propq" data-type="const char*" data-required="false" data-desc="A property query string for algorithm fetching (for CMS_sign_ex)."></x-field>
</x-field-group>

#### Flags

The `flags` parameter modifies the behavior of the signing operation. Multiple flags can be combined using a bitwise OR.

| Flag | Description |
| --- | --- |
| `CMS_TEXT` | Prepends standard `text/plain` MIME headers to the content. |
| `CMS_NOCERTS` | Excludes the signer's certificate from the `SignedData` structure. The certificate is still required in the `signcert` parameter for signing. |
| `CMS_DETACHED` | Creates a detached signature where the content is not included in the final `CMS_ContentInfo` structure. |
| `CMS_BINARY` | Prevents MIME canonicalization of the content. This is essential for binary data to avoid corruption. |
| `CMS_NOATTR` | Excludes all signed attributes, including signing time and SMIMECapabilities. |
| `CMS_NOSMIMECAP` | Omits the `SMIMECapabilities` signed attribute. |
| `CMS_NO_SIGNING_TIME` | Omits the signing time attribute. |
| `CMS_USE_KEYID` | Identifies the signer's certificate by its subject key identifier instead of the default issuer and serial number. |
| `CMS_STREAM` | Initializes the `CMS_ContentInfo` structure for streaming but defers the actual signing. The data is read and processed during finalization. |
| `CMS_PARTIAL` | Creates a partial `CMS_ContentInfo` structure, allowing for the addition of more signers or attributes before calling `CMS_final()`. |

#### Return Value

Returns a valid `CMS_ContentInfo` structure on success or `NULL` on failure. The error can be retrieved from the OpenSSL error queue.

### CMS_verify

The `CMS_verify()` function validates a CMS `SignedData` structure. It checks the integrity of the signed content, verifies the signer's signature, and optionally validates the signer's certificate chain against a trusted store.

#### Synopsis

```c
#include <openssl/cms.h>

int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs, X509_STORE *store,
               BIO *detached_data, BIO *out, unsigned int flags);
```

#### Parameters

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="The CMS_ContentInfo structure to verify."></x-field>
  <x-field data-name="certs" data-type="STACK_OF(X509)*" data-required="false" data-desc="An optional stack of untrusted certificates used to search for the signer's certificate and to aid in chain building."></x-field>
  <x-field data-name="store" data-type="X509_STORE*" data-required="false" data-desc="A trusted certificate store for path validation."></x-field>
  <x-field data-name="detached_data" data-type="BIO*" data-required="false" data-desc="A BIO containing the content if the signature is detached. Should be NULL for enveloped signatures."></x-field>
  <x-field data-name="out" data-type="BIO*" data-required="false" data-desc="A BIO to write the verified content to. If NULL, the content is read and verified but not written."></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="A bitmask of flags to control the verification operation."></x-field>
</x-field-group>

#### Flags

| Flag | Description |
| --- | --- |
| `CMS_NOINTERN` | Prevents searching for the signer's certificate within the CMS structure itself. The certificate must be provided in the `certs` parameter. |
| `CMS_TEXT` | Strips `text/plain` MIME headers from the content. An error occurs if the content type is not `text/plain`. |
| `CMS_NO_SIGNER_CERT_VERIFY` | Skips the certificate chain verification of the signer's certificate. |
| `CMS_NO_ATTR_VERIFY` | Skips verification of the signed attributes' signature. |
| `CMS_NO_CONTENT_VERIFY` | Skips verification of the content digest. This means the signature is checked, but the content itself is not validated against it. |
| `CMS_NOCRL` | Ignores any CRLs present in the CMS structure during certificate validation. |
| `CMS_CADES` | Enables CAdES-specific checks, such as verifying the `signingCertificate` or `signingCertificateV2` attribute. |

#### Return Value

Returns `1` for a successful verification and `0` for failure. Detailed error information can be retrieved from the OpenSSL error queue.

### CMS_get0_signers

This utility function retrieves the certificates of all signers from a `CMS_ContentInfo` structure. It should only be called after a successful verification, as the verification process is responsible for locating and associating the certificates with each `SignerInfo`.

#### Synopsis

```c
#include <openssl/cms.h>

STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);
```

#### Parameters

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="The successfully verified CMS structure."></x-field>
</x-field-group>

#### Return Value

Returns a pointer to an internal `STACK_OF(X509)` containing the signers' certificates. This pointer should not be freed by the application. Returns `NULL` if an error occurs or if no signers are found.

## Encryption and Decryption

These functions are used to create and parse `EnvelopedData` structures for encrypting and decrypting data for one or more recipients.

### CMS_encrypt

The `CMS_encrypt()` and `CMS_encrypt_ex()` functions create a `CMS_ContentInfo` structure of type `EnvelopedData` or `AuthEnvelopedData`. The content is encrypted with a randomly generated symmetric key, which is then securely distributed to each recipient by encrypting it with their respective public keys.

#### Synopsis

```c
#include <openssl/cms.h>

CMS_ContentInfo *CMS_encrypt(STACK_OF(X509) *certs, BIO *in,
                             const EVP_CIPHER *cipher, unsigned int flags);

CMS_ContentInfo *CMS_encrypt_ex(STACK_OF(X509) *certs, BIO *in,
                                const EVP_CIPHER *cipher, unsigned int flags,
                                OSSL_LIB_CTX *libctx, const char *propq);
```

#### Parameters

<x-field-group>
  <x-field data-name="certs" data-type="STACK_OF(X509)*" data-required="true" data-desc="A stack of recipient certificates."></x-field>
  <x-field data-name="in" data-type="BIO*" data-required="true" data-desc="A BIO containing the data to be encrypted."></x-field>
  <x-field data-name="cipher" data-type="const EVP_CIPHER*" data-required="true" data-desc="The symmetric cipher to use for content encryption (e.g., EVP_aes_256_cbc())."></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="A bitmask of flags to control the encryption operation."></x-field>
  <x-field data-name="libctx" data-type="OSSL_LIB_CTX*" data-required="false" data-desc="An OpenSSL library context (for CMS_encrypt_ex). If NULL, the default context is used."></x-field>
  <x-field data-name="propq" data-type="const char*" data-required="false" data-desc="A property query string for algorithm fetching (for CMS_encrypt_ex)."></x-field>
</x-field-group>

#### Flags

| Flag | Description |
| --- | --- |
| `CMS_TEXT` | Prepends standard `text/plain` MIME headers to the content before encryption. |
| `CMS_BINARY` | Prevents MIME canonicalization of the content, which is necessary for binary data. |
| `CMS_USE_KEYID` | Identifies recipients by their subject key identifier. An error occurs if a recipient certificate lacks this extension. |
| `CMS_STREAM` | Initializes the `CMS_ContentInfo` structure for streaming I/O but defers reading data from the input BIO. |
| `CMS_PARTIAL` | Creates a partial `CMS_ContentInfo` structure, allowing for the addition of more recipients before finalization. |
| `CMS_DETACHED` | Omits the encrypted content from the final structure. This is rarely used. |

#### Return Value

Returns a valid `CMS_ContentInfo` structure on success or `NULL` on failure.

### CMS_decrypt

The `CMS_decrypt()` function decrypts a `CMS_ContentInfo` structure of type `EnvelopedData` or `AuthEnvelopedData`. It uses the recipient's private key to decrypt the content encryption key, which is then used to decrypt the actual content.

#### Synopsis

```c
#include <openssl/cms.h>

int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert,
                BIO *dcont, BIO *out, unsigned int flags);
```

#### Parameters

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="The CMS structure to decrypt."></x-field>
  <x-field data-name="pkey" data-type="EVP_PKEY*" data-required="true" data-desc="The recipient's private key."></x-field>
  <x-field data-name="cert" data-type="X509*" data-required="false" data-desc="The recipient's certificate. While not strictly required for decryption, it is highly recommended to locate the correct RecipientInfo and prevent potential attacks."></x-field>
  <x-field data-name="dcont" data-type="BIO*" data-required="false" data-desc="A BIO containing the encrypted content if it is detached. Usually NULL."></x-field>
  <x-field data-name="out" data-type="BIO*" data-required="true" data-desc="A BIO to write the decrypted content to."></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="A bitmask of flags to control the decryption."></x-field>
</x-field-group>

#### Flags

| Flag | Description |
| --- | --- |
| `CMS_TEXT` | Strips `text/plain` MIME headers from the decrypted content. An error occurs if the content type is not `text/plain`. |
| `CMS_DEBUG_DECRYPT` | Disables MMA (Bleichenbacher's attack) countermeasures. If no recipient key decrypts successfully, an error is returned immediately instead of decrypting with a random key. Use with extreme caution. |

#### Return Value

Returns `1` on success or `0` on failure.

### Helper Decryption Functions

For more granular control, you can set the decryption key in advance using the following functions, and then call `CMS_decrypt()` with `pkey` and `cert` set to `NULL`.

#### Synopsis

```c
#include <openssl/cms.h>

int CMS_decrypt_set1_pkey(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert);

int CMS_decrypt_set1_pkey_and_peer(CMS_ContentInfo *cms, EVP_PKEY *pk,
                                   X509 *cert, X509 *peer);

int CMS_decrypt_set1_password(CMS_ContentInfo *cms,
                              unsigned char *pass, ossl_ssize_t passlen);
```

#### Description

-   `CMS_decrypt_set1_pkey()` and `CMS_decrypt_set1_pkey_and_peer()` decrypt the content encryption key using a private key `pk`. The certificate `cert` helps identify the correct `RecipientInfo`. The `peer` certificate is for key agreement schemes.
-   `CMS_decrypt_set1_password()` decrypts using a password for `PWRI` (Password Recipient Info) types.

These functions return `1` on success and `0` on failure.

## Finalization Functions

When creating a CMS structure with the `CMS_STREAM` or `CMS_PARTIAL` flags, a finalization step is required to complete the structure after all data has been processed.

### CMS_final

The `CMS_final()` function finalizes a `CMS_ContentInfo` structure. This typically involves calculating and encoding digests and signatures after all the content has been written through the streaming BIO. This function is essential when using the `CMS_PARTIAL` flag without streaming I/O.

#### Synopsis

```c
#include <openssl/cms.h>

int CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont, unsigned int flags);
```

#### Parameters

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="The partial CMS structure to finalize."></x-field>
  <x-field data-name="data" data-type="BIO*" data-required="true" data-desc="A BIO containing the content to be processed."></x-field>
  <x-field data-name="dcont" data-type="BIO*" data-required="false" data-desc="A BIO to write the content to after processing (for detached signatures). Usually NULL."></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="Flags to control processing, such as MIME canonicalization."></x-field>
</x-field-group>

#### Return Value

Returns `1` on success or `0` on failure.

### CMS_dataFinal

The `CMS_dataFinal()` and `CMS_dataFinal_ex()` functions are used to finalize a CMS structure when streaming is enabled. They are called internally by functions like `i2d_CMS_bio_stream()` but can be used directly for fine-grained control. `CMS_dataFinal_ex` is required for hash-less signature schemes like EdDSA.

#### Synopsis

```c
#include <openssl/cms.h>

int CMS_dataFinal(CMS_ContentInfo *cms, BIO *cmsbio);

int CMS_dataFinal_ex(CMS_ContentInfo *cms, BIO *cmsbio, BIO *data);
```

#### Parameters

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="The streaming CMS structure to finalize."></x-field>
  <x-field data-name="cmsbio" data-type="BIO*" data-required="true" data-desc="The BIO chain returned from CMS_dataInit() through which data was written."></x-field>
  <x-field data-name="data" data-type="BIO*" data-required="false" data-desc="The original data BIO, required for hash-less signature schemes that need to re-read the raw data (for CMS_dataFinal_ex)."></x-field>
</x-field-group>

#### Return Value

Returns `1` on success or `0` on failure.

## Summary

This section covered the main entry points for creating and processing CMS messages. For more detailed control over message components, refer to the functions in the [SignerInfo Functions](./api-signerinfo.md) and [RecipientInfo Functions](./api-recipientinfo.md) sections. The how-to guides for [Signing and Verifying](./guides-signing-verifying.md) and [Encryption & Decryption](./guides-encrypting-decrypting.md) provide practical examples using these functions.
