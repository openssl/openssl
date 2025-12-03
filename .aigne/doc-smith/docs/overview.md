This document explains the purpose of the Cryptographic Message Syntax (CMS), its role in secure messaging applications like S/MIME, and the high-level architecture of the OpenSSL CMS library. By the end, you will understand the fundamental components of a CMS message and how they fit together.

# Overview

Cryptographic Message Syntax (CMS), specified in [RFC 5652](https://tools.ietf.org/html/rfc5652), is a standard for protecting data using cryptography. It defines a syntax for a variety of cryptographic operations, including digital signatures, message digests, authentication, and encryption. CMS is a cornerstone of secure messaging standards like Secure/Multipurpose Internet Mail Extensions (S/MIME), which is used to sign and encrypt email.

The OpenSSL CMS module provides a comprehensive and flexible implementation of this standard, accessible through both a C-language API and a powerful command-line interface (`openssl cms`).

## The Purpose of CMS

CMS provides a "wrapper" format that encapsulates data and associated cryptographic information. This allows for the creation of self-contained, secure messages that can be transmitted over insecure networks. The core capabilities of CMS include:

*   **Data Integrity:** Ensuring that data has not been modified in transit, typically using digital signatures.
*   **Authentication:** Verifying the identity of the sender.
*   **Confidentiality:** Encrypting data so that only authorized recipients can view it.
*   **Non-repudiation:** Providing proof that a specific sender created a message, preventing them from denying it later.

## High-Level Architecture

At its core, a CMS structure is a `ContentInfo` object. This object acts as a container that holds two key pieces of information:

1.  **Content Type:** An identifier that specifies the type of cryptographic protection applied (e.g., signed data, enveloped data).
2.  **Content:** The actual data, structured according to the specified content type.

The power of CMS lies in its modular design, where different content types can be nested to combine cryptographic operations, such as creating a message that is both signed and then encrypted.

The following diagram illustrates the relationship between the `ContentInfo` container and its various content types:

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![This document explains the purpose of the Cryptographic Message Syntax (CMS), its role in secure ...](./assets/diagram/overview-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

### Core Content Types

OpenSSL's CMS implementation supports several standard content types, each serving a distinct purpose. Understanding these types is fundamental to using the library effectively.

| Content Type | Description | Common Use Case |
| :--- | :--- | :--- |
| **Data** | A simple wrapper for arbitrary data, with no cryptographic protection. It is often used as the innermost content in a nested structure. | Encapsulating the original message before signing or encrypting. |
| **SignedData** | Contains data and one or more digital signatures from signers. It provides authentication, integrity, and non-repudiation. | Verifying the author of a document or email. |
| **EnvelopedData** | Contains encrypted data and information for one or more recipients to decrypt it. It provides confidentiality. | Sending a confidential message to multiple recipients. |
| **DigestedData** | Contains data and a message digest (hash) of that data. It provides a basic form of integrity checking. | Verifying that a file has not been corrupted during download. |
| **EncryptedData** | Contains data encrypted with a symmetric key. Unlike `EnvelopedData`, it does not include recipient information for key management. | Simple symmetric encryption where key distribution is handled separately. |
| **AuthEnvelopedData** | Provides authenticated encryption (AEAD), combining confidentiality and integrity in a single, efficient operation. | Securing data where both confidentiality and authenticity are critical. |
| **CompressedData** | Contains compressed data. This type is often used before encryption to reduce the size of the message. | Compressing a large attachment before encrypting and sending it. |

For a more detailed explanation of each type, refer to the [Core Concepts](./concepts-content-types.md) section.

### Signers and Recipients

Within the main content types, two other structures play a critical role:

*   `SignerInfo`: Used within a `SignedData` structure. Each `SignerInfo` object contains the signature and related information for a single signer, including their certificate identifier and the hash of the signed attributes. A message can have multiple signers, each represented by a separate `SignerInfo` structure.

*   `RecipientInfo`: Used within an `EnvelopedData` structure. Each `RecipientInfo` object contains the encrypted content-encryption key for a single recipient. This design allows a message to be encrypted once but be decryptable by multiple recipients, each using their own private key. CMS supports various methods for key management, covered in [Recipient Info Types](./concepts-recipient-info-types.md).

## Library vs. Command-Line Tool

OpenSSL provides two primary ways to interact with the CMS module:

1.  **The `openssl cms` Command-Line Tool:** A versatile utility for performing common CMS operations like signing, verifying, encrypting, and decrypting files directly from the shell. It is ideal for scripting and manual tasks.

2.  **The C Library (`libcrypto`):** A rich API that exposes the full power of the CMS implementation. This is the path for developers who need to integrate secure messaging capabilities directly into their C/C++ applications, offering granular control over every aspect of the CMS structure.

The command-line tool is built directly on top of the C library, and its options often map directly to API functions and flags. For example, running `openssl cms -sign` invokes the underlying `CMS_sign()` function. This documentation aims to bridge the gap between the two, allowing users familiar with the command line to transition to the API and vice-versa.

## Navigating This Documentation

This documentation is structured to guide you from high-level concepts to practical implementation details.

<x-cards data-columns="2">
  <x-card data-title="Quick Start" data-icon="lucide:rocket" data-href="/quick-start">
    For a hands-on introduction, this guide provides immediate, practical examples for the most common operations.
  </x-card>
  <x-card data-title="Core Concepts" data-icon="lucide:book-open" data-href="/concepts">
    For a deeper theoretical understanding, this section details the architectural components of CMS.
  </x-card>
  <x-card data-title="How-To Guides" data-icon="lucide:wrench" data-href="/guides">
    For task-oriented instructions, these guides provide step-by-step workflows for specific use cases.
  </x-card>
  <x-card data-title="API Reference" data-icon="lucide:library" data-href="/api">
    For detailed technical information, this section provides a comprehensive reference for every function in the API.
  </x-card>
</x-cards>

---

### Summary

*   **CMS is a Standard:** It provides a versatile syntax (RFC 5652) for applying cryptographic protections like signatures and encryption to data.
*   **It's a Wrapper System:** The core `ContentInfo` structure wraps data with different `Content Types` (e.g., `SignedData`, `EnvelopedData`) to secure it.
*   **OpenSSL Provides Full Support:** Functionality is available through the flexible `openssl cms` command-line tool and the comprehensive C library API.
*   **Key Structures:** `SignerInfo` and `RecipientInfo` enable multi-signer and multi-recipient capabilities, respectively.