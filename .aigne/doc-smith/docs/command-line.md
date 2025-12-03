This document provides a detailed reference for the `openssl cms` command-line tool, mapping its operations and flags to the underlying OpenSSL library functions. By understanding these connections, you can transition from command-line usage to programmatic API implementation more effectively.

# CLI Tool (`openssl cms`)

The `openssl cms` command provides a command-line interface for handling Cryptographic Message Syntax (CMS) data. It allows users to perform a wide range of cryptographic operations, such as creating digital signatures, verifying signatures, and encrypting or decrypting message content, aligning with standards like S/MIME for secure email.

This tool serves as a practical wrapper around the core functions of the OpenSSL CMS library. Understanding its usage can provide insight into the programmatic application of the API for more complex workflows.

The diagram below illustrates the relationship between the `openssl cms` command-line tool, its main operations, and the core OpenSSL library functions they utilize.

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![This document provides a detailed reference for the `openssl cms` command-line tool, mapping its ...](./assets/diagram/command-line-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## Operations

The primary function of the `openssl cms` tool is determined by a single operation option. Each operation corresponds to a high-level workflow that combines several steps, from reading input data to formatting the final output. The following table maps the most common operations to their principal library functions and CMS content types.

| Operation Option | CMS Content Type | Core API Function(s) | Description |
| :--- | :--- | :--- | :--- |
| `-sign` | `SignedData` | `CMS_sign()` | Creates a digital signature over the input data. |
| `-verify` | `SignedData` | `CMS_verify()` | Verifies the integrity and authenticity of a signed message. |
| `-encrypt` | `EnvelopedData` | `CMS_encrypt()` | Encrypts content for one or more recipients. |
| `-decrypt` | `EnvelopedData` | `CMS_decrypt()` | Decrypts content using a recipient's private key. |
| `-compress` | `CompressedData` | `CMS_compress()` | Compresses the input data using zlib. |
| `-uncompress` | `CompressedData` | `CMS_uncompress()` | Decompresses a `CompressedData` object. |
| `-resign` | `SignedData` | `CMS_sign()` with `CMS_REUSE_DIGEST` | Adds a new signature to an existing `SignedData` structure. |
| `-digest_create`| `DigestedData` | `CMS_digest_create()` | Creates a structure containing a message digest. |
| `-EncryptedData_encrypt` | `EncryptedData` | `CMS_EncryptedData_encrypt()` | Encrypts data using a symmetric key without recipient info. |

## Option Reference

The behavior of each operation is controlled by a set of flags. These flags often correspond directly to parameters or flags in the underlying C API functions.

### General and I/O Options

These options control the input and output sources and formats.

| Flag | Parameter | Description |
| :--- | :--- | :--- |
| `-in` | `<filename>` | Specifies the input file. |
| `-out` | `<filename>` | Specifies the output file. |
| `-inform` | `SMIME` \| `PEM` \| `DER` | Sets the input format. The default is `SMIME`. |
| `-outform`| `SMIME` \| `PEM` \| `DER` | Sets the output format. The default is `SMIME`. |
| `-binary` | (none) | Prevents canonical text conversion (CRLF translation). Use for binary data. Corresponds to the `CMS_BINARY` flag. |
| `-stream`, `-indef` | (none) | Enables streaming I/O, which uses BER indefinite-length encoding. Corresponds to the `CMS_STREAM` flag. |
| `-content`| `<filename>` | Specifies the detached content file for verification. |
| `-text` | (none) | Adds `text/plain` MIME headers when signing/encrypting or strips them when verifying/decrypting. Corresponds to the `CMS_TEXT` flag. |

### Signing and Verification Options

These flags modify the behavior of the `-sign` and `-verify` operations.

| Flag | Parameter | Operation | Description |
| :--- | :--- | :--- | :--- |
| `-signer` | `<certfile>` | Sign, Verify | Specifies the signer's certificate. Can be used multiple times for multi-signer messages. |
| `-inkey` | `<keyfile>` | Sign, Decrypt | Specifies the private key corresponding to the `-signer` or `-recip` certificate. |
| `-md` | `<digest>` | Sign | Sets the digest algorithm (e.g., `sha256`). |
| `-nodetach`| (none) | Sign | Creates an opaque signature where the content is embedded within the `SignedData` structure. Clears the `CMS_DETACHED` flag. |
| `-nocerts` | (none) | Sign | Excludes the signer's certificate from the `SignedData` structure. Corresponds to the `CMS_NOCERTS` flag. |
| `-noattr` | (none) | Sign | Excludes all signed attributes, including signing time and S/MIME capabilities. Corresponds to the `CMS_NOATTR` flag. |
| `-noverify`| (none) | Verify | Skips the verification of the signer's certificate chain. Corresponds to the `CMS_NO_SIGNER_CERT_VERIFY` flag. |
| `-nosigs` | (none) | Verify | Skips the verification of the digital signature itself. Corresponds to the `CMS_NOSIGS` flag. |
| `-certfile`| `<certs.pem>` | Sign, Verify | Provides additional certificates to include in the message or use for chain building during verification. |
| `-CAfile` | `<ca.pem>` | Verify | Specifies a file of trusted CA certificates for chain validation. |

### Encryption and Decryption Options

These flags modify the behavior of the `-encrypt` and `-decrypt` operations.

| Flag | Parameter | Operation | Description |
| :--- | :--- | :--- | :--- |
| `-recip` | `<cert.pem>` | Encrypt, Decrypt | Specifies a recipient's certificate for encryption or decryption. |
| `-<cipher>` | (none) | Encrypt | Specifies the content encryption algorithm (e.g., `-aes256`, `-des3`). |
| `-keyid` | (none) | Encrypt, Sign | Identifies recipients or signers by Subject Key Identifier instead of Issuer and Serial Number. Corresponds to the `CMS_USE_KEYID` flag. |
| `-secretkey`| `<key>` | Encrypt, Decrypt | A hex-encoded symmetric key for `KEKRecipientInfo` (encryption) or `EncryptedData` operations. |
| `-secretkeyid`| `<id>` | Encrypt, Decrypt | A hex-encoded key identifier for a KEK recipient. |
| `-pwri_password`| `<password>` | Encrypt, Decrypt | A password for `PasswordRecipientInfo` (PWRI). |
| `-originator` | `<cert.pem>` | Decrypt | Specifies the originator's certificate for key agreement schemes (e.g., ECDH). |

## Practical Examples

The following examples demonstrate common use cases of the `openssl cms` tool.

### Creating a Detached Signature

This command signs a message and outputs the signature in a separate file, keeping the original content unmodified. This is the default signing behavior.

```sh Creating a detached signature icon=lucide:terminal
openssl cms -sign -in message.txt -text -out signature.pem \
  -signer signer_cert.pem -inkey signer_key.pem
```

### Verifying a Detached Signature

To verify the signature, you must provide the original content, the signature file, and the signer's certificate.

```sh Verifying a detached signature icon=lucide:terminal
openssl cms -verify -in signature.pem -inform PEM \
  -content message.txt -CAfile trusted_ca.pem -out verified_message.txt
```

### Creating an Opaque (Attached) Signature

An opaque signature embeds the original content within the CMS structure. The resulting file is not human-readable without being parsed.

```sh Creating an opaque signature icon=lucide:terminal
openssl cms -sign -in message.txt -text -nodetach \
  -out signed_opaque.pem -signer signer_cert.pem
```

### Encrypting a Message for Multiple Recipients

This command encrypts a file for two different recipients. Either recipient can decrypt the message with their corresponding private key.

```sh Encrypting for multiple recipients icon=lucide:terminal
openssl cms -encrypt -in confidential.txt -out encrypted.pem \
  -recip recip1_cert.pem -recip recip2_cert.pem
```

### Decrypting a Message

The recipient uses their certificate and private key to decrypt the message.

```sh Decrypting a message icon=lucide:terminal
openssl cms -decrypt -in encrypted.pem -out confidential.txt \
  -recip recip1_cert.pem -inkey recip1_key.pem
```

### Signing and Then Encrypting a Message

To create a message that is both signed and encrypted, the operations are chained together. The output of the `-sign` command is piped to the input of the `-encrypt` command.

```sh Signing and then encrypting a message icon=lucide:terminal
openssl cms -sign -in message.txt -signer signer.pem -text \
  | openssl cms -encrypt -recip recipient.pem -out signed_and_encrypted.pem
```

## Summary

The `openssl cms` command-line tool is a versatile utility for managing CMS structures. Its options and operations provide a direct analogue to the functions available in the OpenSSL library. For developers, analyzing its source code and behavior is an effective way to learn how to implement these features programmatically.

For more detailed information on the underlying API, refer to the following sections:
- [Main Functions](./api-main.md)
- [Signing and Verifying](./guides-signing-verifying.md)
- [Encryption & Decryption](./guides-encrypting-decrypting.md)