# Core Concepts

To effectively use the OpenSSL Cryptographic Message Syntax (CMS) library, it is essential to first understand its architectural blueprint. This document provides a foundational overview of the primary components of a CMS message, how they interact, and the purpose each serves in creating secure digital messages. This conceptual framework will prepare you for practical application in subsequent guides.

## The CMS Architectural Blueprint

Cryptographic Message Syntax (CMS), specified in [RFC 5652](https://tools.ietf.org/html/rfc5652), is a standard for protecting data. It provides a syntax for a wide range of cryptographic operations, including digital signatures, message digests, authentication, and encryption. Its most prominent application is in the **S/MIME** (Secure/Multipurpose Internet Mail Extensions) protocol, which secures email communication.

At its core, every CMS message is a `ContentInfo` structure. This structure acts as a universal wrapper, containing two key pieces of information:

1.  **Content Type**: An object identifier (OID) that specifies what kind of data is enclosed.
2.  **Content**: The actual data, structured according to the specified content type.

This layered design allows for nesting, where one CMS structure can be wrapped inside another. For example, a signed message (`SignedData`) can itself be encrypted, with the entire `SignedData` structure becoming the content of an `EnvelopedData` structure. The following diagram illustrates this hierarchical structure:

<!-- DIAGRAM_IMAGE_START:architecture:3:4 -->
![Core Concepts](assets/diagram/concepts-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## CMS Content Types

The OpenSSL CMS implementation supports several standard content types, each designed for a specific cryptographic purpose. Understanding these types is the first step to building and parsing CMS messages.

For in-depth details on each type, refer to the [Content Types](./concepts-content-types.md) documentation.

<x-cards data-columns="3">
  <x-card data-title="Data" data-icon="lucide:file-text">
    The simplest type, representing arbitrary octet string data. It serves as the plaintext content for other types.
  </x-card>
  <x-card data-title="SignedData" data-icon="lucide:pen-square">
    Provides digital signatures. It contains the original content, information about the signers (SignerInfo), and the digital signatures.
  </x-card>
  <x-card data-title="EnvelopedData" data-icon="lucide:mail">
    Provides confidentiality through encryption. It contains the encrypted content and recipient-specific information (RecipientInfo) needed to decrypt it.
  </x-card>
  <x-card data-title="DigestedData" data-icon="lucide:hash">
    Provides content integrity by storing a message digest (hash) of the content.
  </x-card>
  <x-card data-title="EncryptedData" data-icon="lucide:lock">
    Contains symmetrically encrypted content, but unlike EnvelopedData, does not include recipient key management information. The key must be managed out-of-band.
  </x-card>
  <x-card data-title="AuthEnvelopedData" data-icon="lucide:shield-check">
    Provides authenticated encryption with associated data (AEAD), combining confidentiality and integrity in a single operation.
  </x-card>
</x-cards>

## Key Components within Content Types

Two critical structures, `SignerInfo` and `RecipientInfo`, are the operational heart of the `SignedData` and `EnvelopedData` types, respectively.

### SignerInfo: The Signature Block

The `SignerInfo` structure is central to the `SignedData` content type. Each signer of a message contributes one `SignerInfo` block. This block contains all necessary information to verify a signature, including:

*   **Signer Identifier**: Uniquely identifies the signer's certificate, typically by issuer and serial number or by subject key identifier.
*   **Digest Algorithm**: The algorithm used to hash the message content before signing (e.g., SHA-256).
*   **Signature Algorithm**: The algorithm used to create the digital signature (e.g., RSA).
*   **Signed Attributes**: A set of authenticated attributes that are signed along with the content digest. This typically includes the content type and signing time.
*   **Signature Value**: The actual digital signature octet string.
*   **Unsigned Attributes**: Optional attributes that are not part of the signature calculation, such as countersignatures.

### RecipientInfo: The Key to Decryption

The `RecipientInfo` structure is central to `EnvelopedData` and `AuthEnvelopedData`. It provides the necessary information for a specific recipient to decrypt the message. A message can contain multiple `RecipientInfo` structures, one for each recipient.

CMS defines several methods for delivering the content encryption key (CEK) to recipients, each corresponding to a different `RecipientInfo` type. The choice of type depends on the kind of credential the recipient uses.

For a complete explanation of each type, please see the [Recipient Info Types](./concepts-recipient-info-types.md) documentation.

| Type  | Constant                | Description                                                                                             | Common Credential         |
| :---- | :---------------------- | :------------------------------------------------------------------------------------------------------ | :------------------------ |
| KTRI  | `CMS_RECIPINFO_TRANS`   | **Key Transport**: The CEK is encrypted with the recipient's public key (e.g., RSA).                      | X.509 Certificate (RSA)   |
| KARI  | `CMS_RECIPINFO_AGREE`   | **Key Agreement**: A shared secret is derived using the recipient's and originator's keys (e.g., DH/ECDH). | X.509 Certificate (DH/EC) |
| KEKRI | `CMS_RECIPINFO_KEK`     | **Key Encryption Key**: The CEK is wrapped with a pre-shared symmetric key.                               | Symmetric Key             |
| PWRI  | `CMS_RECIPINFO_PASS`    | **Password**: The CEK is derived from a password.                                                         | Password / Passphrase     |
| KEMRI | `CMS_RECIPINFO_KEM`     | **Key Encapsulation Mechanism**: Quantum-resistant mechanism for key exchange.                            | Post-Quantum Keys         |
| ORI   | `CMS_RECIPINFO_OTHER`   | **Other**: A placeholder for custom or future recipient types.                                            | Custom                    |

## Relationship to the `openssl cms` Command

The `openssl cms` command-line tool is a high-level interface to the CMS library functions. Each of its primary operations corresponds directly to the creation or processing of a specific CMS content type. Understanding this mapping provides context for how command-line actions translate to the underlying API.

| `openssl cms` Command         | Corresponding CMS Content Type | Core API Functions                                 |
| :---------------------------- | :----------------------------- | :------------------------------------------------- |
| `-sign`, `-verify`, `-resign` | `SignedData`                   | `CMS_sign()`, `CMS_verify()`                       |
| `-encrypt`, `-decrypt`        | `EnvelopedData`                | `CMS_encrypt()`, `CMS_decrypt()`                   |
| `-digest_create`, `-digest_verify` | `DigestedData`                 | `CMS_digest_create()`, `CMS_digest_verify()`       |
| `-EncryptedData_encrypt`, `-EncryptedData_decrypt` | `EncryptedData`                | `CMS_EncryptedData_encrypt()`, `CMS_EncryptedData_decrypt()` |
| `-compress`, `-uncompress`    | `CompressedData`               | `CMS_compress()`, `CMS_uncompress()`               |
| `-data_create`                | `Data`                         | `CMS_data_create()`                                |

## Summary

The Cryptographic Message Syntax provides a structured, layered framework for applying cryptographic protections to data. Its core is the `ContentInfo` structure, which wraps various content types like `SignedData` and `EnvelopedData`. These, in turn, rely on `SignerInfo` and `RecipientInfo` to manage signatures and encryption keys.

With this conceptual foundation, you are now prepared to explore more specific topics:

<x-cards data-columns="2">
  <x-card data-title="Quick Start" data-icon="lucide:rocket" data-href="/quick-start">
    A hands-on guide to performing common CMS operations with minimal theory.
  </x-card>
  <x-card data-title="Content Types" data-icon="lucide:box" data-href="/concepts/content-types">
    A detailed examination of each of the primary CMS content types.
  </x-card>
  <x-card data-title="Recipient Info Types" data-icon="lucide:key-round" data-href="/concepts/recipient-info-types">
    An in-depth look at the different methods for recipient key management.
  </x-card>
  <x-card data-title="CLI Tool (openssl cms)" data-icon="lucide:terminal" data-href="/command-line">
    A comprehensive reference for the command-line interface.
  </x-card>
</x-cards>