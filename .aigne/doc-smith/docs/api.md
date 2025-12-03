# API Reference

This section provides a complete and searchable reference for the entire public OpenSSL Cryptographic Message Syntax (CMS) API. It offers detailed documentation for all functions, including those previously undocumented, making it the definitive guide for developers working with the library.

The API is organized into logical groups to help you quickly locate the functions you need. Whether you are performing high-level operations or require fine-grained control over CMS structures, this reference contains the necessary details.

For conceptual explanations of CMS, see the [Core Concepts](./concepts.md) section. For task-oriented workflows, refer to the [How-To Guides](./guides.md).

## Function Categories

The OpenSSL CMS API is organized into several categories based on functionality. Below is an overview of each category and a link to its detailed documentation.

<x-cards data-columns="2">
  <x-card data-title="Main Functions" data-icon="lucide:function-square" data-href="/api/main">
    High-level functions for common operations like signing, verifying, encrypting, and decrypting CMS messages. These are the most frequently used functions.
  </x-card>
  <x-card data-title="SignerInfo Functions" data-icon="lucide:pen-tool" data-href="/api/signerinfo">
    Functions for managing SignerInfo structures, including adding signers, managing signed and unsigned attributes, and performing low-level signature verification.
  </x-card>
  <x-card data-title="RecipientInfo Functions" data-icon="lucide:users" data-href="/api/recipientinfo">
    Functions for managing RecipientInfo structures. This includes adding recipients for various key management types (KTRI, KARI, etc.) and handling decryption keys.
  </x-card>
  <x-card data-title="Attribute & Cert API" data-icon="lucide:files" data-href="/api/attributes-certs">
    A collection of functions for managing certificates, Certificate Revocation Lists (CRLs), and attributes within a CMS structure.
  </x-card>
  <x-card data-title="I/O and Data Functions" data-icon="lucide:binary" data-href="/api/io-data">
    Covers functions for data streaming, I/O operations, and direct management of content types such as Data, DigestedData, and CompressedData.
  </x-card>
</x-cards>

## Key Data Structures

The entire CMS functionality revolves around a few central data structures. Understanding these is key to using the API effectively. The following diagram illustrates the relationship between these key structures.

<!-- DIAGRAM_IMAGE_START:intro:1:1 -->
![API Reference](assets/diagram/api-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

*   **`CMS_ContentInfo`**: The top-level structure in CMS. It encapsulates the content type and the content itself. All CMS messages are parsed into or generated from this structure.
*   **`CMS_SignerInfo`**: Contains all information related to a single signer, including their certificate identifier, signature algorithm, signature value, and any signed or unsigned attributes.
*   **`CMS_RecipientInfo`**: Contains the necessary information for a single recipient to decrypt the content encryption key. There are different types of `RecipientInfo` structures depending on the key management technique used.

## Common Flags

Many CMS functions accept a `flags` argument that modifies their behavior. These flags can be combined using a bitwise OR operator (`|`). The table below lists the most common flags and their purpose.

| Flag | Value | Description |
| :--- | :--- | :--- |
| `CMS_TEXT` | `0x1` | Adds MIME headers for `text/plain` content type. |
| `CMS_NOCERTS` | `0x2` | When signing, do not include the signer's certificate in the message. |
| `CMS_NO_CONTENT_VERIFY` | `0x4` | When verifying, do not verify the content signature. |
| `CMS_NO_ATTR_VERIFY` | `0x8` | When verifying, do not verify the signature on the signed attributes. |
| `CMS_NOINTERN` | `0x10` | When verifying, do not search for the signer's certificate in the message itself. |
| `CMS_NO_SIGNER_CERT_VERIFY` | `0x20` | Do not verify the signer's certificate chain. |
| `CMS_DETACHED` | `0x40` | Create a detached signature where the content is not included in the `SignedData` structure. |
| `CMS_BINARY` | `0x80` | Do not perform MIME canonicalization on the content. Use this for binary data. |
| `CMS_NOATTR` | `0x100` | Do not include any signed attributes. This creates a simpler signature but lacks context like signing time. |
| `CMS_NOSMIMECAP` | `0x200` | Omit the S/MIME capabilities signed attribute. |
| `CMS_CRLFEOL` | `0x800` | Use CRLF as the line ending for text-based MIME content. |
| `CMS_STREAM` | `0x1000` | Indicates that the data is being streamed and enables streaming I/O operations. |
| `CMS_NOCRL` | `0x2000` | Do not include any CRLs in the `SignedData` structure. |
| `CMS_USE_KEYID` | `0x10000` | Use the Subject Key Identifier to identify certificates instead of the issuer and serial number. |
| `CMS_DEBUG_DECRYPT` | `0x20000` | Enables debugging output during decryption operations to help diagnose errors. |
| `CMS_CADES` | `0x100000` | Enables CAdES (CMS Advanced Electronic Signatures) compliance for signatures. |

## Summary

This API reference is designed to be a comprehensive resource for developers using the OpenSSL CMS library. Each sub-section provides detailed function prototypes, parameter descriptions, return values, and usage notes. Use the navigation to explore the different function categories and find the specific tools you need for your implementation.