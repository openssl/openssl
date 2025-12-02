This section provides a complete reference for functions that create, manage, and verify `CMS_SignerInfo` structures. A `SignerInfo` structure contains all the necessary information about a single signer, including their certificate identifier, digest and signature algorithms, signed and unsigned attributes, and the encrypted signature itself. These functions offer granular control, making them ideal for advanced scenarios such as creating messages with multiple signers or customizing attributes.

For higher-level operations, see the [Main Functions](./api-main.md) documentation, which covers simplified APIs like `CMS_sign()` and `CMS_verify()`.

# SignerInfo Functions

## Adding and Finalizing Signers

These functions are used to add one or more signers to a `CMS_SignedData` structure and finalize their respective signatures.

### CMS_add1_signer

Adds a signer to a `CMS_ContentInfo` structure that must contain `SignedData`. This function is typically used after an initial call to `CMS_sign()` with the `CMS_PARTIAL` flag.

```c
CMS_SignerInfo *CMS_add1_signer(CMS_ContentInfo *cms, X509 *signcert,
                                EVP_PKEY *pkey, const EVP_MD *md,
                                unsigned int flags);
```

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="A pointer to the CMS_ContentInfo structure to add the signer to."></x-field>
  <x-field data-name="signcert" data-type="X509 *" data-required="true" data-desc="The signer's certificate."></x-field>
  <x-field data-name="pkey" data-type="EVP_PKEY *" data-required="true" data-desc="The signer's private key."></x-field>
  <x-field data-name="md" data-type="const EVP_MD *" data-required="false">
    <x-field-desc markdown>The message digest algorithm to use. If `NULL`, the default digest for the public key algorithm is used.</x-field-desc>
  </x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="false" data-desc="A bitmask of flags to control the signing operation. See table below."></x-field>
</x-field-group>

**Flags for `CMS_add1_signer`**

| Flag                  | Description                                                                                                                                                                                          |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CMS_REUSE_DIGEST`    | Attempts to copy the content digest from an existing `SignerInfo` structure. This is used when adding a new signer to an existing message. The structure is finalized upon return.                      |
| `CMS_PARTIAL`         | When used with `CMS_REUSE_DIGEST`, the `SignerInfo` structure is not finalized, allowing for the addition of more attributes. `CMS_SignerInfo_sign()` must be called explicitly later.                   |
| `CMS_NOCERTS`         | Prevents the signer's certificate from being included in the `SignedData` structure. This reduces message size if the certificate is available to the recipient through other means.                     |
| `CMS_NOATTR`          | Excludes all signed attributes. This creates a simpler signature but omits contextual information like signing time and S/MIME capabilities.                                                        |
| `CMS_NOSMIMECAP`      | Omits the `SMIMECapabilities` signed attribute, which lists the cryptographic algorithms supported by the sender.                                                                                    |
| `CMS_NO_SIGNING_TIME` | Omits the `signingTime` signed attribute.                                                                                                                                                            |
| `CMS_USE_KEYID`       | Identifies the signer's certificate by its Subject Key Identifier instead of the default Issuer Name and Serial Number. An error occurs if the certificate lacks a subject key identifier extension. |
| `CMS_CADES`           | Adds CAdES-specific attributes (`signingCertificateV2`) for advanced electronic signatures.                                                                                                            |

**Return Value**

Returns an internal pointer to the newly created `CMS_SignerInfo` structure on success, or `NULL` on failure.

### CMS_SignerInfo_sign

Explicitly generates the signature for a `CMS_SignerInfo` structure. This function is primarily used to finalize a `SignerInfo` structure that was created using `CMS_add1_signer()` with both the `CMS_REUSE_DIGEST` and `CMS_PARTIAL` flags set.

```c
int CMS_SignerInfo_sign(CMS_SignerInfo *si);
```

<x-field-group>
  <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="A pointer to the SignerInfo structure to sign."></x-field>
</x-field-group>

**Return Value**

Returns `1` on success and `0` on failure.

## Retrieving Signer Information

These functions provide access to the data within `CMS_SignerInfo` structures.

| Function                            | Description                                                                                                                                                           |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CMS_get0_SignerInfos()`            | Returns a `STACK_OF(CMS_SignerInfo)` containing all signers in a `SignedData` structure.                                                                                |
| `CMS_get0_signers()`                | Returns a `STACK_OF(X509)` containing the certificates of all signers, if they are present in the `SignerInfo` structures.                                              |
| `CMS_SignerInfo_get0_signer_id()`   | Retrieves the signer's identifier. It populates either the `keyid` (Subject Key Identifier) or both `issuer` and `sno` (Issuer Name and Serial Number).                  |
| `CMS_SignerInfo_get0_algs()`        | Retrieves pointers to the signer's public key (`EVP_PKEY`), certificate (`X509`), digest algorithm (`X509_ALGOR`), and signature algorithm (`X509_ALGOR`).                |
| `CMS_SignerInfo_get0_signature()`   | Returns a pointer to an `ASN1_OCTET_STRING` containing the raw signature value.                                                                                         |
| `CMS_SignerInfo_get0_pkey_ctx()`    | Returns the `EVP_PKEY_CTX` associated with the signer, which may be `NULL` if not set.                                                                                    |
| `CMS_SignerInfo_get0_md_ctx()`      | Returns the `EVP_MD_CTX` associated with the signer.                                                                                                                    |
| `CMS_set1_signers_certs()`          | Iterates through a stack of certificates (`scerts`) and associates them with matching `SignerInfo` structures in the `CMS_ContentInfo` message.                          |
| `CMS_SignerInfo_set1_signer_cert()` | Sets the certificate and public key for a given `SignerInfo` structure. This is useful when certificates are not included in the CMS message and must be supplied externally. |
| `CMS_SignerInfo_cert_cmp()`         | Compares a certificate (`cert`) against a `SignerInfo` structure (`si`) to determine if it is the signer's certificate. Returns `0` on a match.                            |

## Verifying Signatures

These functions are used for low-level verification of a single `SignerInfo` structure. For most use cases, `CMS_verify()` is recommended.

| Function                       | Description                                                                                                                                                                                                    |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CMS_SignerInfo_verify()`      | Verifies the signature within the `SignerInfo` structure against its signed attributes. This confirms the integrity of the attributes but not the message content itself.                                       |
| `CMS_SignerInfo_verify_content()` | Verifies the content digest. It calculates the digest of the message content and compares it to the `messageDigest` signed attribute. This confirms that the message content has not been altered.               |
| `CMS_SignerInfo_verify_ex()`   | A more flexible version of `verify_content` that allows specifying a separate data source `BIO`, which is necessary for hash-less signature schemes like EdDSA.                                                 |
| `CMS_SignedData_verify()`      | Verifies a standalone `CMS_SignedData` structure. This is a helper function that wraps the full `CMS_verify` process for cases where you only have the `SignedData` part of a `CMS_ContentInfo` message.         |

## Attribute Management

A `SignerInfo` structure can contain two types of attributes: **signed** and **unsigned**.

-   **Signed Attributes**: These are cryptographically protected by the digital signature. Any modification to a signed attribute will invalidate the signature. Common signed attributes include `contentType`, `signingTime`, and `messageDigest`.
-   **Unsigned Attributes**: These are not protected by the signature and can be added or modified without invalidating it. A common example is a `counterSignature`.

OpenSSL provides a parallel set of functions for managing both types of attributes. The `CMS_signed_*` functions operate on signed attributes, while the `CMS_unsigned_*` functions operate on unsigned attributes.

### Common Attribute Functions

The following table lists the available functions. Replace `*` with `signed` or `unsigned` as needed.

| Function Name                     | Description                                                                                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CMS_*_get_attr_count()`          | Returns the number of attributes.                                                                                                                 |
| `CMS_*_get_attr()`                | Retrieves an attribute at a specific index (`loc`).                                                                                               |
| `CMS_*_get_attr_by_NID()`         | Finds the index of an attribute by its NID (e.g., `NID_pkcs9_signingTime`).                                                                         |
| `CMS_*_get_attr_by_OBJ()`         | Finds the index of an attribute by its `ASN1_OBJECT`.                                                                                             |
| `CMS_*_add1_attr()`               | Adds a pre-constructed `X509_ATTRIBUTE` structure.                                                                                                |
| `CMS_*_add1_attr_by_NID()`        | Creates and adds an attribute by its NID.                                                                                                         |
| `CMS_*_add1_attr_by_OBJ()`        | Creates and adds an attribute by its `ASN1_OBJECT`.                                                                                               |
| `CMS_*_add1_attr_by_txt()`        | Creates and adds an attribute by its text representation (e.g., "signingTime").                                                                   |
| `CMS_*_delete_attr()`             | Deletes an attribute at a specific index (`loc`).                                                                                                 |
| `CMS_*_get0_data_by_OBJ()`        | Retrieves the raw data of an attribute value, specified by `ASN1_OBJECT`. This is a convenient way to extract values like the `messageDigest`. |

---

### Further Reading

-   [Main Functions](./api-main.md): For high-level signing and verification.
-   [Attribute & Cert API](./api-attributes-certs.md): For general functions to manage certificates, CRLs, and attributes in a `CMS_ContentInfo` structure.
-   [RFC 5652: Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652): The core specification defining the `SignerInfo` structure.