This section provides a clear, methodical reference for the I/O and data management functions within the OpenSSL CMS API. You will learn how to handle streaming operations using `BIO` chains and manage the simpler CMS content types—`Data`, `DigestedData`, `EncryptedData`, and `CompressedData`—which are foundational for more complex structures.

# I/O and Data Functions

The OpenSSL CMS library provides a suite of functions for handling data streams and managing specific content types. These functions are essential for both streaming large messages without holding them entirely in memory and for creating and processing the simpler CMS structures. This section details the functions related to I/O operations and the `Data`, `DigestedData`, `EncryptedData`, and `CompressedData` content types.

For functions related to more complex structures, see the corresponding sections:
- [Main Functions](./api-main.md) for `CMS_sign()`, `CMS_encrypt()`, etc.
- [SignerInfo Functions](./api-signerinfo.md) for managing digital signatures.
- [RecipientInfo Functions](./api-recipientinfo.md) for managing encryption recipients.

## Streaming Operations with BIO

Streaming is a critical feature for processing large messages efficiently. Instead of reading an entire file into memory, you can process it in chunks using OpenSSL's I/O abstraction, `BIO`. The following functions are central to streaming operations in CMS.

### CMS_data
This function processes content for a streaming-based `CMS_ContentInfo` structure. Data is read from the input `BIO` (`in`), processed according to the CMS content type (e.g., encrypted, signed), and written to the output `BIO` (`out`).

The `flags` parameter modifies the operation, with `CMS_STREAM` being a common choice to indicate a streaming operation. The function should be called repeatedly until it returns 0, indicating that all data from `in` has been processed.

```c
int CMS_data(CMS_ContentInfo *cms, BIO *in, BIO *out, unsigned int flags);
```

### CMS_final
For streaming operations, `CMS_final()` finalizes the `CMS_ContentInfo` structure. This includes tasks like computing the final signature, writing padding for encryption, and appending any footers. It must be called after all data has been processed by `CMS_data()`.

```c
int CMS_final(CMS_ContentInfo *cms, BIO *in, BIO *out, unsigned int flags);
```

### d2i_CMS_bio and i2d_CMS_bio
These functions are used to read (decode) or write (encode) a `CMS_ContentInfo` structure from or to a `BIO` in DER format. They are essential for parsing incoming CMS messages from a stream or serializing a created message to a stream.

- `d2i_CMS_bio()`: Parses a DER-encoded CMS structure from a `BIO`.
- `i2d_CMS_bio()`: Writes a `CMS_ContentInfo` structure to a `BIO` in DER format.

```c
CMS_ContentInfo *d2i_CMS_bio(BIO *bp, CMS_ContentInfo **cms);
int i2d_CMS_bio(BIO *bp, CMS_ContentInfo *cms);
```

## Data Content Type
The `Data` content type is the simplest, representing arbitrary binary data.

### CMS_Data_create
This function creates a `CMS_ContentInfo` structure of the type `Data`.

```c
CMS_ContentInfo *CMS_Data_create(void);
```

**Returns**
- A pointer to a new `CMS_ContentInfo` structure on success.
- `NULL` on error.

## DigestedData Content Type
The `DigestedData` content type contains a message digest of the content.

### CMS_DigestedData_create
Creates a `CMS_ContentInfo` structure of type `DigestedData`. The `md` parameter specifies the message digest algorithm to use (e.g., `EVP_sha256()`).

```c
CMS_ContentInfo *CMS_DigestedData_create(const EVP_MD *md);
```

**Parameters**
<x-field-group>
  <x-field data-name="md" data-type="const EVP_MD *" data-required="true" data-desc="A pointer to the message digest algorithm structure."></x-field>
</x-field-group>

**Returns**
- A pointer to a new `CMS_ContentInfo` structure on success.
- `NULL` on error.

### CMS_DigestedData_do_final
This function is used in streaming operations to finalize the digest calculation. It must be called after all content has been processed through `CMS_data()`. It computes the digest and stores it in the `DigestedData` structure.

```c
int CMS_DigestedData_do_final(CMS_ContentInfo *cms, BIO *chain, int verify);
```

**Parameters**
<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="The DigestedData CMS structure."></x-field>
  <x-field data-name="chain" data-type="BIO *" data-required="true" data-desc="The BIO chain containing the digest context."></x-field>
  <x-field data-name="verify" data-type="int" data-required="true" data-desc="If non-zero, it verifies the existing digest against the computed one. If zero, it computes and sets the digest."></x-field>
</x-field-group>

**Returns**
- `1` for success.
- `0` for failure.

## EncryptedData Content Type
The `EncryptedData` content type contains content encrypted with a symmetric key. Unlike `EnvelopedData`, it does not include recipient information for key management. The key must be shared out-of-band.

### CMS_EncryptedData_encrypt
Encrypts content using a symmetric cipher.

```c
CMS_ContentInfo *CMS_EncryptedData_encrypt(BIO *in, const EVP_CIPHER *cipher,
                                           const unsigned char *key,
                                           size_t keylen, unsigned int flags);
```

**Parameters**
<x-field-group>
  <x-field data-name="in" data-type="BIO *" data-required="true" data-desc="The BIO containing the data to be encrypted."></x-field>
  <x-field data-name="cipher" data-type="const EVP_CIPHER *" data-required="true" data-desc="The symmetric cipher to use (e.g., EVP_aes_256_cbc())."></x-field>
  <x-field data-name="key" data-type="const unsigned char *" data-required="true" data-desc="The symmetric key."></x-field>
  <x-field data-name="keylen" data-type="size_t" data-required="true" data-desc="The length of the symmetric key in bytes."></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="false" data-desc="Flags to modify the operation. Use 0 for default behavior."></x-field>
</x-field-group>

**Returns**
- A pointer to a new `CMS_ContentInfo` structure containing the encrypted data.
- `NULL` on error.

### CMS_EncryptedData_decrypt
Decrypts content within a `CMS_EncryptedData` structure.

```c
int CMS_EncryptedData_decrypt(CMS_ContentInfo *cms, const unsigned char *key,
                              size_t keylen, BIO *dcont, BIO *out,
                              unsigned int flags);
```

**Parameters**
<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="The EncryptedData CMS structure to decrypt."></x-field>
  <x-field data-name="key" data-type="const unsigned char *" data-required="true" data-desc="The symmetric key for decryption."></x-field>
  <x-field data-name="keylen" data-type="size_t" data-required="true" data-desc="The length of the symmetric key."></x-field>
  <x-field data-name="dcont" data-type="BIO *" data-required="false" data-desc="If the content is detached, this BIO provides the encrypted data. Can be NULL if content is attached."></x-field>
  <x-field data-name="out" data-type="BIO *" data-required="true" data-desc="The BIO where the decrypted content will be written."></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="false" data-desc="Flags to modify behavior. Use 0 for default."></x-field>
</x-field-group>

**Returns**
- `1` for success.
- `0` for failure.

### CMS_EncryptedData_set1_key
Sets the key, key length, IV, and cipher for a `CMS_EncryptedData` structure. This is typically used when creating the structure piece by piece rather than with the one-shot `CMS_EncryptedData_encrypt` function.

```c
int CMS_EncryptedData_set1_key(CMS_ContentInfo *cms, const EVP_CIPHER *c,
                               const unsigned char *key, size_t keylen);
```

**Returns**
- `1` for success.
- `0` for failure.

## CompressedData Content Type
The `CompressedData` content type holds compressed data. OpenSSL must be compiled with `zlib` support for these functions to be available.

:::info
To use compression functions, ensure your OpenSSL build includes zlib support. If not, these functions will return an error indicating that the feature is unsupported.
:::

### CMS_compress
Compresses the data from an input `BIO` and wraps it in a `CMS_ContentInfo` structure of type `CompressedData`.

```c
CMS_ContentInfo *CMS_compress(BIO *in, int comp_nid, unsigned int flags);
```

**Parameters**
<x-field-group>
  <x-field data-name="in" data-type="BIO *" data-required="true" data-desc="The BIO containing the data to compress."></x-field>
  <x-field data-name="comp_nid" data-type="int" data-required="true" data-desc="The NID of the compression algorithm. Typically NID_zlib_compression."></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="false" data-desc="Flags to modify behavior. Use 0 for default."></x-field>
</x-field-group>

**Returns**
- A pointer to a `CMS_ContentInfo` structure containing the compressed data.
- `NULL` on error or if zlib is not enabled.

### CMS_uncompress
Uncompresses the content of a `CMS_ContentInfo` structure.

```c
int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
                   unsigned int flags);
```

**Parameters**
<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="The CompressedData CMS structure."></x-field>
  <x-field data-name="dcont" data-type="BIO *" data-required="false" data-desc="If the content is detached, this BIO provides the compressed data. Can be NULL if content is attached."></x-field>
  <x-field data-name="out" data-type="BIO *" data-required="true" data-desc="The BIO where the uncompressed content will be written."></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="false" data-desc="Flags to modify behavior. Use 0 for default."></x-field>
</x-field-group>

**Returns**
- `1` for success.
- `0` for failure.

### CMS_CompressedData_create
Creates a `CMS_ContentInfo` structure of type `CompressedData`. The `comp_nid` specifies the compression algorithm.

```c
CMS_ContentInfo *CMS_CompressedData_create(int comp_nid);
```

**Returns**
- A pointer to a new `CMS_ContentInfo` structure.
- `NULL` on error.

## Summary

The I/O and data functions provide the necessary tools for managing data streams and handling the less complex CMS content types. A solid understanding of `BIO` chains is crucial for using the streaming functions (`CMS_data`, `CMS_final`) effectively, which is the recommended approach for large messages. The functions for `DigestedData`, `EncryptedData`, and `CompressedData` offer straightforward, high-level interfaces for these specific use cases.