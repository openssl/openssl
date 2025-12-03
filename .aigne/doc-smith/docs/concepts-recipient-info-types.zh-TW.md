# Recipient Info 類型

在密碼學訊息語法（Cryptographic Message Syntax）中，`RecipientInfo` 結構是用於將內容加密金鑰（content-encryption key, CEK）安全地傳遞給每個接收者的機制。本文件詳細介紹六種 `RecipientInfo` 結構類型，解釋每種類型如何保護和傳輸金鑰，讓您能為應用程式的安全需求選擇適當的方法。

在 CMS `EnvelopedData` 結構中，訊息內容是使用一個隨機產生的單一對稱金鑰（稱為內容加密金鑰，CEK）來加密。為確保只有授權的接收者可以存取內容，CEK 本身必須被安全地分發。這是透過為每個接收者建立一個 `RecipientInfo` 結構來實現的。每個結構都包含一份 CEK 的副本，該副本以對其預期接收者而言是唯一且僅能由其解密的方式進行加密。

<!-- DIAGRAM_IMAGE_START:intro:16:9 -->
![Recipient Info 類型](./assets/diagram/concepts-recipient-info-types-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

OpenSSL 支援六種不同的金鑰管理機制，每種機制都由一個唯一的類型來識別。

## 金鑰傳輸接收者資訊 (Key Transport Recipient Info, KTRI)

金鑰傳輸是分發 CEK 最常見的方法之一。它使用非對稱（公開金鑰）密碼學，直接用接收者的公開金鑰來加密 CEK。

*   **類型識別碼**：`CMS_RECIPINFO_TRANS`
*   **機制**：傳送者產生一個 CEK，使用接收者的公開金鑰（通常是 RSA）對其進行加密，並將結果放入一個 `KeyTransRecipientInfo` 結構中。接收者使用其對應的私密金鑰來解密 CEK，然後存取訊息內容。
*   **使用案例**：非常適合標準的公開金鑰基礎設施（PKI）環境，其中接收者擁有包含 RSA 或類似適用於加密的公開金鑰的 X.509 憑證。
*   **ASN.1 結構**：`KeyTransRecipientInfo`

這種方法直接且被廣泛支援。用於新增 KTRI 接收者的主要函式是 `CMS_add1_recipient_cert()`。

```c
CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms,
                                           X509 *recip, unsigned int flags);
```

## 金鑰協商接收者資訊 (Key Agreement Recipient Info, KARI)

金鑰協商允許兩方或多方在一個不安全的通道上產生一個共享的秘密，該秘密隨後被用來衍生一個金鑰加密金鑰（key-encryption key, KEK），以封裝 CEK。

*   **類型識別碼**：`CMS_RECIPINFO_AGREE`
*   **機制**：傳送者產生一對臨時金鑰（例如，Diffie-Hellman 或 Elliptic Curve Diffie-Hellman）。使用自己的私密金鑰和接收者的公開金鑰，他們衍生出一個共享秘密。這個秘密被用來衍生一個 KEK，該 KEK 用於加密 CEK。接收者使用自己的私密金鑰和傳送者的臨時公開金鑰執行相同的衍生過程。
*   **使用案例**：適用於基於 Diffie-Hellman (DH) 或 Elliptic Curve Diffie-Hellman (ECDH) 的協定，若使用臨時金鑰，可提供完全正向保密（Perfect Forward Secrecy）。
*   **ASN.1 結構**：`KeyAgreeRecipientInfo`

此方法比 KTRI 更複雜，但提供更進階的安全性。

## 金鑰加密金鑰接收者資訊 (Key Encryption Key Recipient Info, KEKRI)

此方法使用一個預共享的對稱金鑰，稱為金鑰加密金鑰（Key Encryption Key, KEK），來加密 CEK。

*   **類型識別碼**：`CMS_RECIPINFO_KEK`
*   **機制**：傳送者和接收者都必須已擁有一個共享的對稱金鑰。傳送者使用此 KEK 來加密 CEK，通常使用如 AES Key Wrap 等金鑰封裝演算法。接收者使用相同的 KEK 來解封裝它。KEK 由一個唯一的金鑰識別碼來識別。
*   **使用案例**：適用於可以透過頻外方式安全地提供和管理對稱金鑰的封閉系統。它避免了公開金鑰密碼學的開銷。
*   **ASN.1 結構**：`KEKRecipientInfo`

用於新增 KEKRI 接收者的主要函式是 `CMS_add0_recipient_key()`。

```c
CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid,
                                          unsigned char *key, size_t keylen,
                                          unsigned char *id, size_t idlen,
                                          ASN1_GENERALIZEDTIME *date,
                                          ASN1_OBJECT *otherTypeId,
                                          ASN1_TYPE *otherType);
```

## 密碼接收者資訊 (Password Recipient Info, PWRI)

基於密碼的金鑰管理從共享的密碼或密碼片語中衍生出一個 KEK。

*   **類型識別碼**：`CMS_RECIPINFO_PASS`
*   **機制**：使用金鑰衍生函式（KDF），例如 PBKDF2，從密碼中衍生出一個 KEK。這個 KEK 隨後被用來加密 CEK。知道相同密碼的接收者執行相同的 KDF 來重新衍生 KEK 並解密 CEK。
*   **使用案例**：適用於安全性基於人類可記憶的秘密，而非憑證或已配置金鑰的場景。
*   **ASN.1 結構**：`PasswordRecipientInfo`

`CMS_add0_recipient_password()` 函式用於新增 PWRI 接收者。

```c
CMS_RecipientInfo *CMS_add0_recipient_password(CMS_ContentInfo *cms,
                                               int iter, int wrap_nid,
                                               int pbe_nid,
                                               unsigned char *pass,
                                               ossl_ssize_t passlen,
                                               const EVP_CIPHER *kekciph);
```

## 金鑰封裝機制接收者資訊 (Key Encapsulation Mechanism Recipient Info, KEMRI)

KEMRI 是一種用於安全建立金鑰的現代方法，尤其與後量子密碼學相關。它是金鑰傳輸的一種變體。

*   **類型識別碼**：`CMS_RECIPINFO_KEM`
*   **機制**：金鑰封裝機制（Key Encapsulation Mechanism, KEM）是一套用於封裝和解封裝共享秘密的演算法。傳送者使用接收者的公開金鑰來產生一個共享秘密和一個密文（被封裝的金鑰）。該共享秘密與一個 KDF 一起使用以衍生出一個 KEK，該 KEK 用於封裝 CEK。接收者使用其私密金鑰來解封裝密文，取回相同的共享秘密，並衍生出相同的 KEK。
*   **使用案例**：為新興的密碼學演算法提供了一個標準化框架，特別是那些設計用來抵抗量子電腦攻擊的演算法。
*   **ASN.1 結構**：`KEMRecipientInfo`（在 `OtherRecipientInfo` 內）

## 其他接收者資訊 (Other Recipient Info, ORI)

此類型作為一個擴充點，用於定義未被標準集合涵蓋的新接收者資訊類型。

*   **類型識別碼**：`CMS_RECIPINFO_OTHER`
*   **機制**：其結構和處理規則由具體實作定義，並由一個唯一的物件識別碼（`oriType`）來識別。KEMRI 是使用 `OtherRecipientInfo` 實現的一個著名機制範例。
*   **使用案例**：透過允許整合新穎的金鑰管理方案，而無需更新規範版本，來確保 CMS 標準的未來適用性。
*   **ASN.1 結構**：`OtherRecipientInfo`

## 接收者類型總結

下表提供了不同 `RecipientInfo` 類型的高階比較。

| 類型 | 識別碼 | 金鑰管理 | 主要金鑰類型 | 常見使用案例 |
| :--- | :--- | :--- | :--- | :--- |
| **KTRI** | `CMS_RECIPINFO_TRANS` | 非對稱金鑰傳輸 | RSA 公開金鑰 | 標準的基於憑證的加密。 |
| **KARI** | `CMS_RECIPINFO_AGREE` | 非對稱金鑰協商 | DH/ECDH 公開金鑰 | 建立共享秘密以進行金鑰衍生。 |
| **KEKRI** | `CMS_RECIPINFO_KEK` | 對稱金鑰封裝 | 預共享的對稱金鑰 | 具有預先配置的對稱金鑰的系統。 |
| **PWRI** | `CMS_RECIPINFO_PASS` | 基於對稱密碼 | 密碼/密碼片語 | 基於共享秘密的安全性。 |
| **KEMRI**| `CMS_RECIPINFO_KEM` | 金鑰封裝 | KEM 公開金鑰 | 後量子密碼學和現代方案。 |
| **ORI** | `CMS_RECIPINFO_OTHER` | 自訂 | 不定 | 為新的金鑰管理機制提供擴充性。 |

---

### 延伸閱讀

-   要了解 `RecipientInfo` 如何融入整體訊息結構，請參閱 [內容類型](./concepts-content-types.md)。
-   有關實作加密的逐步說明，請參考 [加密與解密](./guides-encrypting-decrypting.md) 指南。
-   有關詳細的 API 參考，請造訪 [RecipientInfo 函式](./api-recipientinfo.md) 文件。