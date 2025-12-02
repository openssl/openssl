# Troubleshooting

Encountering an error during a Cryptographic Message Syntax (CMS) operation can halt progress. This section provides a comprehensive reference to the error codes defined in the OpenSSL CMS library, enabling you to diagnose and resolve issues with precision. Understanding these codes is the first step toward a successful resolution.

## Understanding CMS Error Codes

When an error occurs within the OpenSSL CMS library, a specific reason code is pushed onto the OpenSSL error stack. These codes are defined in the header file `cmserr.h`. By retrieving and identifying these codes, you can pinpoint the exact cause of a failure, whether it's a missing certificate, an unsupported algorithm, or a malformed message.

The following table lists the symbolic names for each error, the corresponding reason string that describes the issue, and a brief explanation of the likely cause.

## CMS Reason Codes

| Symbolic Name                                  | Description                             | Common Cause                                                                                                                               |
| :--------------------------------------------- | :-------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------- |
| `CMS_R_ADD_SIGNER_ERROR`                       | add signer error                        | An issue occurred while adding a `SignerInfo` structure, possibly due to an invalid certificate or key.                                    |
| `CMS_R_ATTRIBUTE_ERROR`                        | attribute error                         | A problem was found with a signed or unsigned attribute, such as incorrect formatting or a missing required attribute.                   |
| `CMS_R_CERTIFICATE_ALREADY_PRESENT`            | certificate already present             | An attempt was made to add a certificate that is already included in the CMS structure's certificate store.                                |
| `CMS_R_CERTIFICATE_HAS_NO_KEYID`               | certificate has no keyid                | An operation required a subject key identifier (e.g., using the `-keyid` flag), but the certificate lacks this extension.                |
| `CMS_R_CERTIFICATE_VERIFY_ERROR`               | certificate verify error                | The verification of a signer's certificate failed. This could be due to an untrusted CA, expired certificate, or a broken chain.         |
| `CMS_R_CIPHER_INITIALISATION_ERROR`            | cipher initialisation error             | The encryption or decryption context could not be initialized, often due to an unsupported cipher or invalid parameters.                 |
| `CMS_R_CONTENT_NOT_FOUND`                      | content not found                       | The encapsulated content is missing, which is common when verifying a detached signature without providing the content file.             |
| `CMS_R_CONTENT_TYPE_MISMATCH`                  | content type mismatch                   | The `eContentType` attribute inside a `SignedData` structure does not match the actual content type being processed.                     |
| `CMS_R_DECRYPT_ERROR`                          | decrypt error                           | Decryption of the content failed. This is typically caused by using the wrong private key, a corrupted message, or incorrect padding.    |
| `CMS_R_ERROR_GETTING_PUBLIC_KEY`               | error getting public key                | The public key could not be extracted from a recipient's or originator's certificate.                                                      |
| `CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE`  | error reading messagedigest attribute   | The `messageDigest` signed attribute could not be read or parsed correctly during verification.                                            |
| `CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH`   | messagedigest attribute wrong length    | The length of the `messageDigest` attribute does not match the expected length for the given digest algorithm.                           |
| `CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE`      | msgsigdigest verification failure       | The calculated `msgSigDigest` value did not match the one present in the signed attributes, indicating a CAdES signature validation fail. |
| `CMS_R_NEED_ONE_SIGNER`                        | need one signer                         | A CAdES verification operation was attempted, but the `SignerInfo` structure did not contain the required `signingCertificate` attribute.  |
| `CMS_R_NOT_A_SIGNED_RECEIPT`                   | not a signed receipt                    | `CMS_verify_receipt()` was called on a CMS structure that is not a valid signed receipt.                                                   |
| `CMS_R_NOT_KEY_TRANSPORT`                      | not key transport                       | A decryption operation expected a Key Transport Recipient Info (`KTRI`) but found a different type.                                        |
| `CMS_R_NO_CIPHER`                              | no cipher                               | An encryption operation was attempted without specifying a cipher algorithm.                                                               |
| `CMS_R_NO_CONTENT`                             | no content                              | The CMS structure does not contain any encapsulated content.                                                                               |
| `CMS_R_NO_DEFAULT_DIGEST`                      | no default digest                       | A signing operation was initiated, but no message digest algorithm was specified and a default could not be determined from the key.     |
| `CMS_R_NO_MATCHING_RECIPIENT`                  | no matching recipient                   | During decryption, no `RecipientInfo` structure could be found that corresponds to the provided private key and certificate.             |
| `CMS_R_NO_MATCHING_SIGNATURE`                  | no matching signature                   | The calculated signature digest does not match the signature value in the `SignerInfo`, indicating the message was altered or the wrong key was used. |
| `CMS_R_NO_PRIVATE_KEY`                         | no private key                          | A decryption or signing operation was attempted without providing a private key.                                                           |
| `CMS_R_NO_PUBLIC_KEY`                          | no public key                           | An encryption or verification operation was attempted without a valid public key.                                                          |
| `CMS_R_NO_SIGNERS`                             | no signers                              | A verification operation was attempted on a `SignedData` structure that contains no `SignerInfo` entries.                                |
| `CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE` | private key does not match certificate  | The provided private key does not correspond to the public key in the associated certificate.                                              |
| `CMS_R_SIGNER_CERTIFICATE_NOT_FOUND`           | signer certificate not found            | The certificate for a signer could not be located, either within the CMS message or in the provided certificate store.                 |
| `CMS_R_UNABLE_TO_FINALIZE_CONTEXT`             | unable to finalize context              | An error occurred during the finalization step of a signing or encryption operation, often preventing the output from being written.     |
| `CMS_R_UNKNOWN_DIGEST_ALGORITHM`               | unknown digest algorithm                | The specified message digest algorithm is not recognized or supported by the current OpenSSL library.                                      |
| `CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM`      | unsupported compression algorithm       | The compression algorithm used is not supported. This typically happens if OpenSSL was not compiled with zlib support.                     |
| `CMS_R_UNSUPPORTED_CONTENT_TYPE`               | unsupported content type                | The operation cannot be performed on the given CMS content type. For example, trying to verify a `EnvelopedData` structure.            |
| `CMS_R_UNSUPPORTED_KEK_ALGORITHM`              | unsupported kek algorithm               | The Key Encryption Key (KEK) algorithm specified in a `KEKRecipientInfo` is not supported.                                                 |
| `CMS_R_UNSUPPORTED_RECIPIENT_TYPE`             | unsupported recipient type              | The type of `RecipientInfo` encountered is not supported by the function being called.                                                     |
| `CMS_R_VERIFICATION_FAILURE`                   | verification failure                    | A general failure occurred during the signature verification process. This is often accompanied by more specific errors on the stack.    |
| `CMS_R_WRAP_ERROR`                             | wrap error                              | An error occurred while wrapping (encrypting) the content encryption key.                                                                  |
| `CMS_R_UNWRAP_ERROR`                           | unwrap error                            | An error occurred while unwrapping (decrypting) the content encryption key.                                                                |

## Summary

This section detailed the various error codes you may encounter while using the OpenSSL CMS functionality. By referencing this list, you can efficiently identify the root cause of operational failures and take corrective action. For more hands-on guidance, refer to the [How-To Guides](./guides.md) for step-by-step examples of common CMS operations.