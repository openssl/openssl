# RecipientInfo Functions

This section provides a detailed reference for the functions used to manage `CMS_RecipientInfo` structures within a CMS `EnvelopedData` or `AuthEnvelopedData` object. You will learn how to add recipients of various types, associate the necessary keys for decryption, and perform the decryption of the content encryption key.

A `RecipientInfo` structure contains the information required for a specific recipient to decrypt the shared content encryption key (CEK). The OpenSSL CMS implementation supports several types of recipients, each with its own key management mechanism. For a conceptual overview of these types, please see the [Recipient Info Types](./concepts-recipient-info-types.md) documentation.

## General Management Functions

These functions are used to access, identify, and process `RecipientInfo` structures within a `CMS_ContentInfo` object.

### CMS_get0_RecipientInfos

Retrieves all `CMS_RecipientInfo` structures from a CMS `EnvelopedData` or `AuthEnvelopedData` structure.

```c
#include <openssl/cms.h>

STACK_OF(CMS_RecipientInfo) *CMS_get0_RecipientInfos(CMS_ContentInfo *cms);
```

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo *" data-desc="A pointer to the CMS_ContentInfo structure."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="STACK_OF(CMS_RecipientInfo) *" data-desc="A pointer to the stack of CMS_RecipientInfo structures, or NULL on error. The returned pointer is internal and should not be freed by the application."></x-field>
</x-field-group>

### CMS_RecipientInfo_type

Returns the type of a given `CMS_RecipientInfo` structure. This is essential for determining which functions to use for processing the structure.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_type(CMS_RecipientInfo *ri);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="A pointer to the CMS_RecipientInfo structure."></x-field>
</x-field-group>

**Return Value**

An integer representing the recipient type. The value will be one of the following constants:
*   `CMS_RECIPINFO_TRANS` (Key Transport)
*   `CMS_RECIPINFO_AGREE` (Key Agreement)
*   `CMS_RECIPINFO_KEK` (Key Encryption Key)
*   `CMS_RECIPINFO_PASS` (Password-Based)
*   `CMS_RECIPINFO_KEM` (Key Encapsulation Mechanism)
*   `CMS_RECIPINFO_OTHER` (Other type)

### CMS_RecipientInfo_decrypt

Attempts to decrypt the content encryption key (CEK) using the private or symmetric key associated with a specific `CMS_RecipientInfo` structure. A key must be associated with the `ri` structure *before* calling this function (e.g., using `CMS_RecipientInfo_set0_pkey()`).

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_decrypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri);
```

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo *" data-desc="A pointer to the parent CMS_ContentInfo structure."></x-field>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The specific recipient info structure to use for decryption."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 1 for success or 0 on failure."></x-field>
</x-field-group>

### CMS_RecipientInfo_encrypt

Encrypts the content encryption key for a specific recipient. This is typically used when adding a new recipient to an existing `EnvelopedData` structure after the CEK has already been generated (e.g., by decrypting another `RecipientInfo` in the same message).

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_encrypt(const CMS_ContentInfo *cms, CMS_RecipientInfo *ri);
```

<x-field-group>
  <x-field data-name="cms" data-type="const CMS_ContentInfo *" data-desc="A pointer to the parent CMS_ContentInfo structure, which contains the CEK."></x-field>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The recipient info structure to encrypt."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 1 for success or 0 on failure."></x-field>
</x-field-group>

## Adding Recipients

These functions are used to create and add new `RecipientInfo` structures to an `EnvelopedData` structure, typically after it has been created with `CMS_encrypt()` using the `CMS_PARTIAL` flag.

### CMS_add1_recipient_cert

Adds a recipient using their X.509 certificate. This function automatically determines the correct recipient type (KTRI, KARI, or KEMRI) based on the public key algorithm in the certificate.

```c
#include <openssl/cms.h>

CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms,
                                           X509 *recip, unsigned int flags);
```

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo *" data-desc="The CMS_ContentInfo structure to add the recipient to."></x-field>
  <x-field data-name="recip" data-type="X509 *" data-desc="The recipient's certificate."></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-desc="Flags to control the operation. Use CMS_USE_KEYID to identify the recipient by Subject Key Identifier instead of Issuer and Serial Number."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="CMS_RecipientInfo *" data-desc="An internal pointer to the newly added CMS_RecipientInfo structure, or NULL on error."></x-field>
</x-field-group>

### CMS_add0_recipient_key

Adds a Key Encryption Key (KEK) recipient. This method is used when the CEK is to be encrypted with a pre-shared symmetric key.

```c
#include <openssl/cms.h>

CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid,
                                          unsigned char *key, size_t keylen,
                                          unsigned char *id, size_t idlen,
                                          ASN1_GENERALIZEDTIME *date,
                                          ASN1_OBJECT *otherTypeId,
                                          ASN1_TYPE *otherType);
```

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo *" data-desc="The CMS_ContentInfo structure."></x-field>
  <x-field data-name="nid" data-type="int" data-desc="The NID of the symmetric key wrapping algorithm (e.g., NID_id_aes128_wrap). If NID_undef, an AES wrap algorithm is chosen based on keylen."></x-field>
  <x-field data-name="key" data-type="unsigned char *" data-desc="The symmetric key."></x-field>
  <x-field data-name="keylen" data-type="size_t" data-desc="The length of the symmetric key."></x-field>
  <x-field data-name="id" data-type="unsigned char *" data-desc="The key identifier for the symmetric key."></x-field>
  <x-field data-name="idlen" data-type="size_t" data-desc="The length of the key identifier."></x-field>
  <x-field data-name="date" data-type="ASN1_GENERALIZEDTIME *" data-desc="An optional date for the key identifier."></x-field>
  <x-field data-name="otherTypeId" data-type="ASN1_OBJECT *" data-desc="An optional object identifier for other key attributes."></x-field>
  <x-field data-name="otherType" data-type="ASN1_TYPE *" data-desc="An optional type for other key attributes."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="CMS_RecipientInfo *" data-desc="An internal pointer to the newly added CMS_RecipientInfo structure, or NULL on error."></x-field>
</x-field-group>

### CMS_add0_recipient_password

Adds a password-based recipient. The CEK is encrypted using a key derived from a password.

```c
#include <openssl/cms.h>

CMS_RecipientInfo *CMS_add0_recipient_password(CMS_ContentInfo *cms,
                                               int iter, int wrap_nid,
                                               int pbe_nid,
                                               unsigned char *pass,
                                               ossl_ssize_t passlen,
                                               const EVP_CIPHER *kekciph);
```

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo *" data-desc="The CMS_ContentInfo structure."></x-field>
  <x-field data-name="iter" data-type="int" data-desc="The PBKDF2 iteration count. If -1, a default value is used."></x-field>
  <x-field data-name="wrap_nid" data-type="int" data-desc="The NID of the key wrapping algorithm. Currently, only NID_id_alg_PWRI_KEK is supported."></x-field>
  <x-field data-name="pbe_nid" data-type="int" data-desc="The NID of the PBE algorithm. If -1, a default is chosen."></x-field>
  <x-field data-name="pass" data-type="unsigned char *" data-desc="The password."></x-field>
  <x-field data-name="passlen" data-type="ossl_ssize_t" data-desc="The length of the password. If -1, the password is assumed to be a null-terminated string."></x-field>
  <x-field data-name="kekciph" data-type="const EVP_CIPHER *" data-desc="The cipher for the key encryption key. If NULL, the content encryption cipher is used."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="CMS_RecipientInfo *" data-desc="An internal pointer to the newly added CMS_RecipientInfo structure, or NULL on error."></x-field>
</x-field-group>

## Key Transport (KTRI) Functions

These functions apply to `RecipientInfo` structures of type `CMS_RECIPINFO_TRANS`, where the CEK is encrypted directly with the recipient's public key (e.g., RSA).

### CMS_RecipientInfo_ktri_get0_signer_id

Retrieves the recipient's identifier, which can be either an issuer/serial number pair or a subject key identifier.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_ktri_get0_signer_id(CMS_RecipientInfo *ri,
                                          ASN1_OCTET_STRING **keyid,
                                          X509_NAME **issuer,
                                          ASN1_INTEGER **sno);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KTRI recipient info structure."></x-field>
  <x-field data-name="keyid" data-type="ASN1_OCTET_STRING **" data-desc="A pointer to be populated with the subject key identifier, if present."></x-field>
  <x-field data-name="issuer" data-type="X509_NAME **" data-desc="A pointer to be populated with the issuer name, if present."></x-field>
  <x-field data-name="sno" data-type="ASN1_INTEGER **" data-desc="A pointer to be populated with the serial number, if present."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 1 for success or 0 on failure."></x-field>
</x-field-group>

### CMS_RecipientInfo_ktri_cert_cmp

Compares a certificate with the identifier in a KTRI structure to see if they match.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KTRI recipient info structure."></x-field>
  <x-field data-name="cert" data-type="X509 *" data-desc="The certificate to compare against."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 0 on a successful match, and non-zero otherwise."></x-field>
</x-field-group>

### CMS_RecipientInfo_set0_pkey

Associates a private key with a KTRI structure, enabling decryption.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pkey);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KTRI recipient info structure."></x-field>
  <x-field data-name="pkey" data-type="EVP_PKEY *" data-desc="The recipient's private key. The structure takes ownership of this pointer."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 1 for success or 0 on failure."></x-field>
</x-field-group>

## Key Agreement (KARI) Functions

These functions apply to `RecipientInfo` structures of type `CMS_RECIPINFO_AGREE`, where a shared secret is derived (e.g., using DH or ECDH) to create a key encryption key, which in turn wraps the CEK.

### CMS_RecipientInfo_kari_set0_pkey_and_peer

Associates a private key and an optional peer public key (from a certificate) with a KARI structure to enable decryption. The peer's public key is needed to derive the shared secret.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_kari_set0_pkey_and_peer(CMS_RecipientInfo *ri,
                                              EVP_PKEY *pk, X509 *peer);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KARI recipient info structure."></x-field>
  <x-field data-name="pk" data-type="EVP_PKEY *" data-desc="The recipient's private key."></x-field>
  <x-field data-name="peer" data-type="X509 *" data-desc="The peer's (originator's) certificate containing the public key for key derivation."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 1 for success or 0 on failure."></x-field>
</x-field-group>

### CMS_RecipientInfo_kari_get0_ctx

Returns the `EVP_CIPHER_CTX` for the key encryption key, allowing the caller to specify the key wrap cipher.

```c
#include <openssl/cms.h>

EVP_CIPHER_CTX *CMS_RecipientInfo_kari_get0_ctx(CMS_RecipientInfo *ri);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KARI recipient info structure."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="EVP_CIPHER_CTX *" data-desc="A pointer to the internal EVP_CIPHER_CTX, or NULL on error."></x-field>
</x-field-group>

### CMS_RecipientInfo_kari_get0_reks

Retrieves the stack of `CMS_RecipientEncryptedKey` structures from a KARI `RecipientInfo`. In a key agreement scenario, there is one such structure for each recipient.

```c
#include <openssl/cms.h>

STACK_OF(CMS_RecipientEncryptedKey) *CMS_RecipientInfo_kari_get0_reks(CMS_RecipientInfo *ri);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KARI recipient info structure."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="STACK_OF(CMS_RecipientEncryptedKey) *" data-desc="An internal pointer to the stack of recipient encrypted keys, or NULL if the type is not KARI."></x-field>
</x-field-group>

## Key Encryption Key (KEKRI) Functions

These functions apply to `RecipientInfo` structures of type `CMS_RECIPINFO_KEK`, where the CEK is encrypted with a pre-shared symmetric key.

### CMS_RecipientInfo_kekri_get0_id

Retrieves the key identifier information from a KEKRI structure.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_kekri_get0_id(CMS_RecipientInfo *ri, X509_ALGOR **palg,
                                    ASN1_OCTET_STRING **pid,
                                    ASN1_GENERALIZEDTIME **pdate,
                                    ASN1_OBJECT **potherid,
                                    ASN1_TYPE **pothertype);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KEKRI recipient info structure."></x-field>
  <x-field data-name="palg" data-type="X509_ALGOR **" data-desc="Output pointer for the key encryption algorithm."></x-field>
  <x-field data-name="pid" data-type="ASN1_OCTET_STRING **" data-desc="Output pointer for the key identifier."></x-field>
  <x-field data-name="pdate" data-type="ASN1_GENERALIZEDTIME **" data-desc="Output pointer for the optional date."></x-field>
  <x-field data-name="potherid" data-type="ASN1_OBJECT **" data-desc="Output pointer for the optional other key attribute ID."></x-field>
  <x-field data-name="pothertype" data-type="ASN1_TYPE **" data-desc="Output pointer for the optional other key attribute value."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 1 for success or 0 on failure."></x-field>
</x-field-group>

### CMS_RecipientInfo_kekri_id_cmp

Compares a given key identifier with the one stored in a KEKRI structure.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_kekri_id_cmp(CMS_RecipientInfo *ri,
                                   const unsigned char *id, size_t idlen);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KEKRI recipient info structure."></x-field>
  <x-field data-name="id" data-type="const unsigned char *" data-desc="The key identifier to compare."></x-field>
  <x-field data-name="idlen" data-type="size_t" data-desc="The length of the key identifier."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 0 for a successful match, and non-zero otherwise."></x-field>
</x-field-group>

### CMS_RecipientInfo_set0_key

Associates a symmetric key with a KEKRI structure to enable decryption.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri,
                               unsigned char *key, size_t keylen);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KEKRI recipient info structure."></x-field>
  <x-field data-name="key" data-type="unsigned char *" data-desc="The symmetric key."></x-field>
  <x-field data-name="keylen" data-type="size_t" data-desc="The length of the symmetric key."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 1 for success or 0 on failure."></x-field>
</x-field-group>

## Password-Based (PWRI) Functions

This function applies to `RecipientInfo` structures of type `CMS_RECIPINFO_PASS`.

### CMS_RecipientInfo_set0_password

Associates a password with a PWRI structure to enable decryption.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_set0_password(CMS_RecipientInfo *ri,
                                    unsigned char *pass,
                                    ossl_ssize_t passlen);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The PWRI recipient info structure."></x-field>
  <x-field data-name="pass" data-type="unsigned char *" data-desc="The password."></x-field>
  <x-field data-name="passlen" data-type="ossl_ssize_t" data-desc="The length of the password. If -1, the password is treated as a null-terminated string."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 1 for success or 0 on failure."></x-field>
</x-field-group>

## KEM (KEMRI) Functions

These functions apply to `RecipientInfo` structures of type `CMS_RECIPINFO_KEM` (Key Encapsulation Mechanism), a method often used in post-quantum cryptography.

### CMS_RecipientInfo_kemri_cert_cmp

Compares a certificate with the identifier in a KEMRI structure.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_kemri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KEMRI recipient info structure."></x-field>
  <x-field data-name="cert" data-type="X509 *" data-desc="The certificate to compare."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 0 for a successful match, and non-zero otherwise."></x-field>
</x-field-group>

### CMS_RecipientInfo_kemri_set0_pkey

Associates a private key with a KEMRI structure to enable decapsulation of the shared secret.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_kemri_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pk);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KEMRI recipient info structure."></x-field>
  <x-field data-name="pk" data-type="EVP_PKEY *" data-desc="The recipient's private key."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 1 for success or 0 on failure."></x-field>
</x-field-group>

### CMS_RecipientInfo_kemri_get0_ctx

Returns the `EVP_CIPHER_CTX` used for wrapping the CEK, allowing the caller to specify the key wrap cipher.

```c
#include <openssl/cms.h>

EVP_CIPHER_CTX *CMS_RecipientInfo_kemri_get0_ctx(CMS_RecipientInfo *ri);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KEMRI recipient info structure."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="EVP_CIPHER_CTX *" data-desc="A pointer to the internal EVP_CIPHER_CTX, or NULL on error."></x-field>
</x-field-group>

### CMS_RecipientInfo_kemri_get0_kdf_alg

Returns the `X509_ALGOR` for the Key Derivation Function (KDF) used in the KEMRI.

```c
#include <openssl/cms.h>

X509_ALGOR *CMS_RecipientInfo_kemri_get0_kdf_alg(CMS_RecipientInfo *ri);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KEMRI recipient info structure."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="X509_ALGOR *" data-desc="A pointer to the internal KDF algorithm identifier, or NULL on error."></x-field>
</x-field-group>

### CMS_RecipientInfo_kemri_set_ukm

Sets the optional User Keying Material (UKM) for the KDF.

```c
#include <openssl/cms.h>

int CMS_RecipientInfo_kemri_set_ukm(CMS_RecipientInfo *ri,
                                    const unsigned char *ukm,
                                    int ukmLength);
```

<x-field-group>
  <x-field data-name="ri" data-type="CMS_RecipientInfo *" data-desc="The KEMRI recipient info structure."></x-field>
  <x-field data-name="ukm" data-type="const unsigned char *" data-desc="The user keying material."></x-field>
  <x-field data-name="ukmLength" data-type="int" data-desc="The length of the UKM."></x-field>
</x-field-group>

**Return Value**

<x-field-group>
  <x-field data-name="return" data-type="int" data-desc="Returns 1 for success or 0 on failure."></x-field>
</x-field-group>

## Summary

This section covered the complete API for managing recipients in CMS `EnvelopedData` structures. You should now be able to add, identify, and process recipients of all supported types, from traditional key transport to modern key encapsulation mechanisms.

For more information on the high-level encryption and decryption process, see [CMS_encrypt(3)](./api-main.md) and [CMS_decrypt(3)](./api-main.md). To understand how these functions fit into a complete workflow, refer to the [Encryption & Decryption](./guides-encrypting-decrypting.md) guide.