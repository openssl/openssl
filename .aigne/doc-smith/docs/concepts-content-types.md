This section breaks down the six fundamental building blocks of the Cryptographic Message Syntax (CMS). By the end of this guide, you will be able to distinguish between each of the core CMS content types and understand the specific cryptographic purpose each one is designed to fulfill.

# Content Types

At the core of the Cryptographic Message Syntax is the `ContentInfo` structure, a generic container for all protected data. The `ContentInfo` object includes a content type identifier and the corresponding content itself. CMS defines six primary content types, each serving a distinct cryptographic function. These types can be nested to combine operations, such as creating a signed-then-encrypted message.

The following diagram illustrates how these content types relate to one another, often with the `Data` type as the innermost content.

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![This section breaks down the six fundamental building blocks of the Cryptographic Message Syntax ...](./assets/diagram/content-types-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

Understanding these six types is essential for effectively using the OpenSSL CMS library, as they form the foundation for all signing and encryption operations.

| Content Type | ASN.1 Object Identifier | Purpose |
| :--- | :--- | :--- |
| **Data** | `pkcs7-data` | Encapsulates arbitrary octet string data without cryptographic protection. It serves as the innermost content for other types. |
| **SignedData** | `pkcs7-signedData` | Applies a digital signature to content, providing authentication, integrity, and non-repudiation. |
| **EnvelopedData** | `pkcs7-envelopedData` | Encrypts content for one or more recipients, providing confidentiality. |
| **DigestedData** | `pkcs7-digestData` | Provides content integrity by encapsulating the content and a message digest of that content. |
| **EncryptedData** | `pkcs7-encryptedData` | Encrypts content using a symmetric key. Unlike `EnvelopedData`, it does not include recipient information for key management. |
| **AuthEnvelopedData** | `id-smime-ct-authEnvelopedData` | Provides authenticated encryption with associated data (AEAD), combining confidentiality and integrity in a single operation. |

---

## Data

The `Data` content type is the most basic. It simply contains an octet string of data and provides no cryptographic protection. It is most often used as the encapsulated content within other CMS types, such as `SignedData` or `EnvelopedData`.

-   **Purpose**: To hold the raw message content.
-   **Structure**: Consists of a single field, an `OCTET STRING`, which contains the message data.

```sh ASN.1 Definition
ContentInfo ::= SEQUENCE {
  contentType                OBJECT IDENTIFIER (pkcs7-data),
  content               [0]  EXPLICIT ANY DEFINED BY contentType OPTIONAL
                               -- Contains an OCTET STRING
}
```

---

## SignedData

The `SignedData` content type is used to apply one or more digital signatures to content. It provides data integrity, authentication of the signer(s), and non-repudiation. The content itself may be detached or encapsulated within the structure.

-   **Purpose**: To create and verify digital signatures.
-   **Key Features**: Supports multiple signers, detached signatures, and inclusion of certificates and CRLs to aid in verification.

### Structure

The `SignedData` structure is a collection of information about the signers, digest algorithms, and the content being signed.

| Field | Description |
| :--- | :--- |
| `version` | The syntax version number. It is automatically set based on the components used (e.g., version 3 if a `subjectKeyIdentifier` is used). |
| `digestAlgorithms` | A set of message digest algorithm identifiers used by the signers. |
| `encapContentInfo` | The encapsulated content, including its type and the content itself (which may be omitted for detached signatures). |
| `certificates` | An optional set of certificates useful for validating the signatures. |
| `crls` | An optional set of certificate revocation lists (CRLs) for path validation. |
| `signerInfos` | A set of `SignerInfo` structures, one for each signer. Each `SignerInfo` contains the signer's identity, digest and signature algorithms, signed attributes, and the signature itself. |

For more details on managing signer information, see the [SignerInfo Functions](./api-signerinfo.md) API reference.

---

## EnvelopedData

The `EnvelopedData` content type is used to encrypt content for one or more recipients, ensuring confidentiality. It works by generating a random symmetric content-encryption key (CEK), encrypting the data with the CEK, and then encrypting the CEK for each recipient using their respective public keys.

-   **Purpose**: To encrypt data for specific recipients.
-   **Key Features**: Supports multiple recipients using various key management techniques.

### Structure

The `EnvelopedData` structure contains the encrypted content and all necessary information for recipients to decrypt it.

| Field | Description |
| :--- | :--- |
| `version` | The syntax version number, determined by the types of recipient information and other fields present. |
| `originatorInfo` | An optional field containing certificates and CRLs to help the recipient establish a key agreement key. |
| `recipientInfos` | A set of `RecipientInfo` structures, one for each recipient. Each structure contains the recipient's identifier and the encrypted CEK. |
| `encryptedContentInfo` | Contains the encrypted content, the content-encryption algorithm, and the encrypted content itself. |
| `unprotectedAttrs` | An optional set of attributes that are not cryptographically protected. |

To understand how keys are managed for different recipients, refer to the [Recipient Info Types](./concepts-recipient-info-types.md) documentation.

---

## DigestedData

The `DigestedData` content type provides a straightforward way to ensure content integrity. It consists of the content and a message digest (hash) of that content, calculated with a specified algorithm. It does not provide authentication or confidentiality.

-   **Purpose**: To verify that content has not been modified in transit.
-   **Key Features**: Simpler than `SignedData` when only integrity is required.

### Structure

| Field | Description |
| :--- | :--- |
| `version` | The syntax version number. |
| `digestAlgorithm` | The identifier for the message digest algorithm used. |
| `encapContentInfo` | The encapsulated content that was digested. |
| `digest` | The calculated message digest of the content. |

---

## EncryptedData

The `EncryptedData` content type is used for encrypting data using a symmetric key. Unlike `EnvelopedData`, it does not provide a mechanism for securely distributing the symmetric key to recipients. The key must be managed through an external, out-of-band channel.

-   **Purpose**: Symmetric encryption of content when key management is handled separately.
-   **Key Features**: Useful for scenarios where the sender and receiver already share a secret key.

### Structure

| Field | Description |
| :--- | :--- |
| `version` | The syntax version number. |
| `encryptedContentInfo` | Contains the encrypted content, the content-encryption algorithm, and the encrypted content itself. |
| `unprotectedAttrs` | An optional set of attributes that are not cryptographically protected. |

---

## AuthEnvelopedData

The `AuthEnvelopedData` content type provides authenticated encryption, a mode that combines confidentiality and integrity into a single cryptographic operation. It is typically used with AEAD (Authenticated Encryption with Associated Data) ciphers like AES-GCM.

-   **Purpose**: To encrypt content while simultaneously providing integrity and authenticity protection.
-   **Key Features**: More efficient and secure than applying encryption and a MAC separately (e.g., Encrypt-then-MAC).

### Structure

| Field | Description |
| :--- | :--- |
| `version` | The syntax version number. |
| `originatorInfo` | Optional information about the originator, similar to `EnvelopedData`. |
| `recipientInfos` | A set of `RecipientInfo` structures for managing the content-encryption key. |
| `authEncryptedContentInfo` | Contains the encrypted content and encryption algorithm. |
| `authAttrs` | An optional set of authenticated attributes that are included in the MAC calculation. |
| `mac` | The message authentication code (tag) that ensures data integrity and authenticity. |
| `unauthAttrs` | An optional set of unauthenticated attributes. |

## Summary

The six CMS content types provide a flexible toolkit for securing data. `Data` is the baseline, while `SignedData` and `EnvelopedData` are the workhorses for signing and encryption, respectively. `DigestedData`, `EncryptedData`, and `AuthEnvelopedData` offer specialized solutions for integrity, simple symmetric encryption, and authenticated encryption.

For a deeper understanding of how keys are managed for recipients in `EnvelopedData` and `AuthEnvelopedData`, proceed to the [Recipient Info Types](./concepts-recipient-info-types.md) section.