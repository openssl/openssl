This guide provides a systematic workflow for requesting, generating, and verifying signed receipts in CMS, a critical feature for ensuring non-repudiation and confirming message delivery. You will learn the complete, end-to-end process, from adding a receipt request to an outgoing message to validating the returned receipt.

# Signed Receipts

Signed receipts provide a cryptographic acknowledgment that a message has been received and processed by a recipient. This mechanism is defined in RFC 2634 and is essential for workflows requiring proof of delivery. The process involves three main stages: requesting a receipt, generating the receipt, and verifying the receipt.

## Overview of the Signed Receipt Workflow

The signed receipt process creates a verifiable trail confirming that a specific recipient has received the original message.

1.  **Request (Original Sender)**: The sender of a `SignedData` message includes a special signed attribute, `CMS_ReceiptRequest`, in their `SignerInfo`. This attribute specifies who should generate a receipt and where it should be sent.
2.  **Generation (Recipient)**: Upon receiving and successfully verifying the `SignedData` message, the recipient identifies the `CMS_ReceiptRequest`. They then construct a new `SignedData` message (the receipt), sign it with their own private key, and send it back to the designated address. The receipt's content cryptographically links it to the original message.
3.  **Verification (Original Sender)**: The original sender receives the signed receipt. They verify its signature and its contents to confirm that it is a valid acknowledgment for the message they sent.

## 1. Requesting a Signed Receipt

To initiate the process, the sender must add a `CMS_ReceiptRequest` attribute to the `SignerInfo` structure before signing the message.

### Creating the Receipt Request

A `CMS_ReceiptRequest` object is created using `CMS_ReceiptRequest_create0()` or its extended version, `CMS_ReceiptRequest_create0_ex()`. This function defines the parameters for the request.

-   `CMS_ReceiptRequest_create0(unsigned char *id, int idlen, int allorfirst, STACK_OF(GENERAL_NAMES) *receiptList, STACK_OF(GENERAL_NAMES) *receiptsTo)`

Key parameters:
*   **`id` and `idlen`**: A unique identifier for the content being signed. If `id` is `NULL`, a 32-byte random value is generated. This identifier is crucial for linking the receipt back to the original message.
*   **`allorfirst` / `receiptList`**: Specifies which recipients should generate receipts.
    *   If `receiptList` is `NULL`, `allorfirst` is used. A value of `0` means all recipients should send a receipt, while `1` means only first-tier recipients (those who can decrypt the message directly) should.
    *   If `receiptList` is provided, only the recipients listed are requested to send a receipt.
*   **`receiptsTo`**: A stack of `GENERAL_NAMES` specifying the address(es) where the generated receipts should be sent.

### Adding the Request to SignerInfo

Once the `CMS_ReceiptRequest` is created, it must be added as a signed attribute to the `CMS_SignerInfo` using `CMS_add1_ReceiptRequest()`.

```c sign_with_receipt_request.c
#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Assume sender_cert, sender_key, and other_certs are loaded.
// Assume data_bio contains the content to be signed.

int main() {
    // ... (Load certificates, key, and data)

    // 1. Create the CMS_ContentInfo structure for signing
    CMS_ContentInfo *cms = CMS_sign(NULL, NULL, other_certs, data_bio, CMS_PARTIAL | CMS_DETACHED);
    if (!cms) goto err;

    // 2. Add the signer
    CMS_SignerInfo *si = CMS_add1_signer(cms, sender_cert, sender_key, EVP_sha256(), 0);
    if (!si) goto err;

    // 3. Create a receipt request
    // Request a receipt to be sent to "receipt-handler@example.com"
    GENERAL_NAME *gen = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_EMAIL, "receipt-handler@example.com", 0);
    STACK_OF(GENERAL_NAME) *gens = sk_GENERAL_NAME_new_null();
    sk_GENERAL_NAME_push(gens, gen);
    STACK_OF(GENERAL_NAMES) *receiptsTo = sk_GENERAL_NAMES_new_null();
    sk_GENERAL_NAMES_push(receiptsTo, gens);

    // Request from all recipients (allorfirst = 0)
    CMS_ReceiptRequest *rr = CMS_ReceiptRequest_create0(NULL, -1, 0, NULL, receiptsTo);
    if (!rr) goto err;

    // 4. Add the receipt request attribute to the SignerInfo
    if (!CMS_add1_ReceiptRequest(si, rr)) {
        CMS_ReceiptRequest_free(rr);
        goto err;
    }
    CMS_ReceiptRequest_free(rr); // CMS_add1_ReceiptRequest makes an internal copy

    // 5. Finalize the SignedData structure
    if (!CMS_final(cms, data_bio, NULL, 0)) goto err;
    
    // ... (Write cms to a BIO, e.g., PEM_write_bio_CMS)
    
    // Cleanup...
    return 0;

err:
    ERR_print_errors_fp(stderr);
    // Cleanup...
    return 1;
}
```

## 2. Generating a Signed Receipt

When a recipient receives a message containing a `CMS_ReceiptRequest`, they perform the following steps to generate and return a receipt.

### Extracting the Receipt Request

First, the recipient must verify the incoming message as usual with `CMS_verify()`. After successful verification, they can inspect each `CMS_SignerInfo` to see if a receipt was requested using `CMS_get1_ReceiptRequest()`.

-   `CMS_get1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest **prr)`: Checks for a receipt request in `si`. It returns `1` if found, `0` if not present, and `-1` on error. The decoded request is stored in `*prr`.

### Creating and Signing the Receipt

If a request is found, the recipient generates the receipt using `CMS_sign_receipt()`. This function creates a new `SignedData` structure that serves as the receipt.

-   `CMS_sign_receipt(CMS_SignerInfo *si, X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs, unsigned int flags)`

This function internally performs several critical operations:
1.  It extracts the `signedContentIdentifier` from the original request.
2.  It takes the `contentType` attribute from the original `SignerInfo`.
3.  It uses the signature value from the original `SignerInfo` as the `originatorSignatureValue`.
4.  It calculates a `msgSigDigest` attribute, which is a hash of the signed attributes from the original `SignerInfo`, securely linking the receipt to the original message signer's attributes.
5.  It signs the new receipt structure with the recipient's certificate (`signcert`) and private key (`pkey`).

```c generate_receipt.c
#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Assume original_cms is the parsed message received.
// Assume recipient_cert and recipient_key are the recipient's credentials.
// Assume trusted_store and other_certs are available for verification.

int main() {
    // ... (Load original_cms, recipient credentials, and verification certs)

    // 1. Verify the original message first
    if (!CMS_verify(original_cms, other_certs, trusted_store, NULL, NULL, 0)) {
        fprintf(stderr, "Original message verification failed.\n");
        goto err;
    }

    STACK_OF(CMS_SignerInfo) *sis = CMS_get0_SignerInfos(original_cms);
    if (!sis) goto err;

    // 2. Iterate through signers to find a receipt request
    for (int i = 0; i < sk_CMS_SignerInfo_num(sis); i++) {
        CMS_SignerInfo *si = sk_CMS_SignerInfo_value(sis, i);
        CMS_ReceiptRequest *rr = NULL;

        if (CMS_get1_ReceiptRequest(si, &rr) > 0) {
            printf("Receipt requested by signer %d. Generating receipt...\n", i);

            // 3. Generate and sign the receipt
            CMS_ContentInfo *receipt_cms = CMS_sign_receipt(si, recipient_cert, recipient_key, NULL, 0);
            
            if (receipt_cms) {
                // ... (Send receipt_cms back to the address from rr->receiptsTo)
                PEM_write_bio_CMS(BIO_s_mem(), receipt_cms); // Example: write to memory BIO
                printf("Receipt generated successfully.\n");
                CMS_ContentInfo_free(receipt_cms);
            } else {
                fprintf(stderr, "Failed to generate receipt for signer %d.\n", i);
            }
            CMS_ReceiptRequest_free(rr);
        }
    }
    
    // Cleanup...
    return 0;

err:
    ERR_print_errors_fp(stderr);
    // Cleanup...
    return 1;
}
```

## 3. Verifying a Signed Receipt

When the original sender receives the signed receipt, they must verify it to complete the process. This is done with `CMS_verify_receipt()`, which performs a more stringent verification than a standard `CMS_verify()` call.

-   `CMS_verify_receipt(CMS_ContentInfo *rcms, CMS_ContentInfo *ocms, STACK_OF(X509) *certs, X509_STORE *store, unsigned int flags)`

This function ensures the receipt is cryptographically tied to the original message (`ocms`). It checks:
1.  The receipt's signature is valid.
2.  The receipt's content type is `id-smime-ct-receipt`.
3.  The `originatorSignatureValue` in the receipt matches the signature of one of the signers in the original message.
4.  The `signedContentIdentifier` matches the one from the original request.
5.  The `msgSigDigest` in the receipt correctly corresponds to the signed attributes of the matched signer in the original message.

```c verify_receipt.c
#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Assume original_sent_cms is the message the sender originally sent.
// Assume received_receipt_cms is the receipt they got back.
// Assume trusted_store and other_certs are available for verification.

int main() {
    // ... (Load original_sent_cms, received_receipt_cms, and verification certs)

    // 1. Verify the receipt against the original sent message
    int result = CMS_verify_receipt(received_receipt_cms, original_sent_cms, other_certs, trusted_store, 0);

    if (result > 0) {
        printf("Signed receipt verification successful.\n");
    } else {
        fprintf(stderr, "Signed receipt verification failed.\n");
        ERR_print_errors_fp(stderr);
    }

    // Cleanup...
    return (result > 0) ? 0 : 1;
}
```

## Command-Line Usage

The `openssl cms` command provides a convenient way to perform these operations.

1.  **Sign a message and request a receipt:**
    The sender uses the `-sign` command with `-receipt_request_to`.

    ```sh Sign and request receipt
    openssl cms -sign -in message.txt -out signed_msg.pem \
      -signer sender.pem -inkey sender.key \
      -receipt_request_to receipt-handler@example.com
    ```

2.  **Generate a signed receipt:**
    The recipient uses the `-sign_receipt` command, providing their credentials and the original message.

    ```sh Generate a receipt
    openssl cms -sign_receipt -in signed_msg.pem \
      -signer recipient.pem -inkey recipient.key \
      -out receipt.pem
    ```

3.  **Verify a signed receipt:**
    The original sender uses `-verify_receipt`, providing the received receipt and the original message they sent.

    ```sh Verify a receipt
    openssl cms -verify_receipt -in receipt.pem \
      -receipt signed_msg.pem -CAfile ca_chain.pem
    ```

## Summary

The signed receipt mechanism in CMS offers a robust and standardized method for tracking message delivery. By following the workflow of request, generation, and verification, applications can build reliable systems for non-repudiation. For further details on the functions used, refer to the [CMS_sign_receipt(3)](https://www.openssl.org/docs/manmaster/man3/CMS_sign_receipt.html), [CMS_verify_receipt(3)](https://www.openssl.org/docs/manmaster/man3/CMS_verify_receipt.html), and [CMS_get1_ReceiptRequest(3)](https://www.openssl.org/docs/manmaster/man3/CMS_get1_ReceiptRequest.html) manual pages.