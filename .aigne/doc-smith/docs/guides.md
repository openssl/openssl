# How-To Guides

Moving from conceptual understanding to practical implementation is a critical step in mastering any technology. This section provides a series of task-oriented guides that demonstrate how to use the OpenSSL CMS library for common, real-world scenarios. Each guide presents a complete, step-by-step workflow.

The following guides offer practical instructions for both the C API and the `openssl cms` command-line tool, ensuring you can apply the concepts discussed in earlier sections to build secure messaging solutions.

<x-cards data-columns="2">
  <x-card data-title="Signing and Verifying" data-icon="lucide:pen-tool" data-href="/guides/signing-verifying">
    Learn how to create and verify digital signatures. This guide covers single-signer, multi-signer, and detached signature scenarios, providing a foundation for message integrity and authentication.
  </x-card>
  <x-card data-title="Encryption and Decryption" data-icon="lucide:lock" data-href="/guides/encrypting-decrypting">
    Follow procedures for encrypting data for various recipient types, including certificate-based (KTRI) and symmetric-key-based (KEKRI) methods, to ensure message confidentiality.
  </x-card>
  <x-card data-title="Signed Receipts" data-icon="lucide:mail-check" data-href="/guides/receipts">
    Walk through the process of requesting, generating, and verifying signed receipts. This workflow is essential for implementing non-repudiation of message delivery.
  </x-card>
  <x-card data-title="Compression" data-icon="lucide:file-archive" data-href="/guides/compression">
    Discover how to use the CompressedData content type to reduce message size before signing or encrypting, which can be useful for optimizing bandwidth and storage.
  </x-card>
</x-cards>

## Summary

These guides are designed to be practical, self-contained resources for developers. By following the step-by-step instructions, you can effectively implement core CMS functionalities. For a deeper dive into the functions used in these guides, consult the [API Reference](./api.md) section.