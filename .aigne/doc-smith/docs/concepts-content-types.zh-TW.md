本節將詳細介紹密碼訊息語法 (Cryptographic Message Syntax, CMS) 的六個基本建構區塊。閱讀完本指南後，您將能夠區分每種核心 CMS 內容類型，並理解其各自的特定密碼學用途。

# 內容類型

密碼訊息語法的核心是 `ContentInfo` 結構，這是一個用於所有受保護資料的通用容器。`ContentInfo` 物件包含一個內容類型識別碼及對應的內容本身。CMS 定義了六種主要的內容類型，每種類型都具有獨特的密碼學功能。這些類型可以巢狀組合以實現複合操作，例如建立先簽署後加密的訊息。

下圖說明了這些內容類型之間的關聯，其中 `Data` 類型通常作為最內層的內容。

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![This section breaks down the six fundamental building blocks of the Cryptographic Message Syntax ...](./assets/diagram/content-types-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

理解這六種類型對於有效使用 OpenSSL CMS 函式庫至關重要，因為它們是所有簽署和加密操作的基礎。

| 內容類型 | ASN.1 物件識別碼 | 用途 |
| :--- | :--- | :--- |
| **Data** | `pkcs7-data` | 封裝任意的八位元字串資料，不提供密碼學保護。它通常作為其他類型的最內層內容。 |
| **SignedData** | `pkcs7-signedData` | 對內容套用數位簽章，提供身份驗證、完整性和不可否認性。 |
| **EnvelopedData** | `pkcs7-envelopedData` | 為一個或多個接收者加密內容，提供機密性。 |
| **DigestedData** | `pkcs7-digestData` | 透過封裝內容及該內容的訊息摘要來提供內容完整性。 |
| **EncryptedData** | `pkcs7-encryptedData` | 使用對稱金鑰加密內容。與 `EnvelopedData` 不同，它不包含用於金鑰管理的接收者資訊。 |
| **AuthEnvelopedData** | `id-smime-ct-authEnvelopedData` | 提供帶有關聯資料的驗證性加密 (AEAD)，在單一操作中結合了機密性和完整性。 |

---

## Data

`Data` 內容類型是最基本的。它僅包含一個八位元字串的資料，不提供任何密碼學保護。它最常用於封裝在其他 CMS 類型中，例如 `SignedData` 或 `EnvelopedData`。

-   **用途**：持有原始訊息內容。
-   **結構**：由單一欄位 `OCTET STRING` 組成，其中包含訊息資料。

```sh ASN.1 定義
ContentInfo ::= SEQUENCE {
  contentType                OBJECT IDENTIFIER (pkcs7-data),
  content               [0]  EXPLICIT ANY DEFINED BY contentType OPTIONAL
                               -- 包含一個 OCTET STRING
}
```

---

## SignedData

`SignedData` 內容類型用於對內容套用一個或多個數位簽章。它提供資料完整性、簽署者身份驗證和不可否認性。內容本身可以是分離的，也可以封裝在結構內部。

-   **用途**：建立和驗證數位簽章。
-   **主要功能**：支援多個簽署者、分離式簽章，並可包含憑證和 CRLs 以協助驗證。

### 結構

`SignedData` 結構是關於簽署者、摘要演算法以及被簽署內容的資訊集合。

| 欄位 | 說明 |
| :--- | :--- |
| `version` | 語法版本號碼。它會根據所使用的元件自動設定（例如，若使用 `subjectKeyIdentifier`，則版本為 3）。 |
| `digestAlgorithms` | 簽署者使用的一組訊息摘要演算法識別碼。 |
| `encapContentInfo` | 被封裝的內容，包括其類型和內容本身（對於分離式簽章，此項可能被省略）。 |
| `certificates` | 一組可選的憑證，有助於驗證簽章。 |
| `crls` | 一組可選的憑證撤銷清冊 (CRLs)，用於路徑驗證。 |
| `signerInfos` | 一組 `SignerInfo` 結構，每個簽署者對應一個。每個 `SignerInfo` 包含簽署者的身份、摘要和簽章演算法、已簽署的屬性以及簽章本身。 |

有關管理簽署者資訊的更多詳細資訊，請參閱 [SignerInfo Functions](./api-signerinfo.md) API 參考。

---

## EnvelopedData

`EnvelopedData` 內容類型用於為一個或多個接收者加密內容，以確保機密性。其運作方式是產生一個隨機的對稱內容加密金鑰 (CEK)，用 CEK 加密資料，然後為每個接收者使用其各自的公鑰來加密 CEK。

-   **用途**：為特定接收者加密資料。
-   **主要功能**：支援使用各種金鑰管理技術的多個接收者。

### 結構

`EnvelopedData` 結構包含加密後的內容以及接收者解密所需的所有必要資訊。

| 欄位 | 說明 |
| :--- | :--- |
| `version` | 語法版本號碼，由接收者資訊的類型和其他存在的欄位決定。 |
| `originatorInfo` | 一個可選欄位，包含憑證和 CRLs，以幫助接收者建立金鑰協商金鑰。 |
| `recipientInfos` | 一組 `RecipientInfo` 結構，每個接收者對應一個。每個結構包含接收者的識別碼和加密後的 CEK。 |
| `encryptedContentInfo` | 包含加密後的內容、內容加密演算法以及加密內容本身。 |
| `unprotectedAttrs` | 一組可選的未受密碼學保護的屬性。 |

要了解如何為不同接收者管理金鑰，請參閱 [Recipient Info Types](./concepts-recipient-info-types.md) 文件。

---

## DigestedData

`DigestedData` 內容類型提供了一種確保內容完整性的直接方法。它由內容和該內容的訊息摘要（雜湊值）組成，該摘要是使用指定的演算法計算的。它不提供身份驗證或機密性。

-   **用途**：驗證內容在傳輸過程中未被修改。
-   **主要功能**：當僅需完整性時，比 `SignedData` 更簡單。

### 結構

| 欄位 | 說明 |
| :--- | :--- |
| `version` | 語法版本號碼。 |
| `digestAlgorithm` | 所使用的訊息摘要演算法的識別碼。 |
| `encapContentInfo` | 被摘要的封裝內容。 |
| `digest` | 計算出的內容訊息摘要。 |

---

## EncryptedData

`EncryptedData` 內容類型用於使用對稱金鑰加密資料。與 `EnvelopedData` 不同，它不提供將對稱金鑰安全分發給接收者的機制。金鑰必須透過外部的帶外通道進行管理。

-   **用途**：當金鑰管理被分開處理時，對內容進行對稱加密。
-   **主要功能**：適用於傳送方和接收方已共享一個秘密金鑰的情境。

### 結構

| 欄位 | 說明 |
| :--- | :--- |
| `version` | 語法版本號碼。 |
| `encryptedContentInfo` | 包含加密後的內容、內容加密演算法以及加密內容本身。 |
| `unprotectedAttrs` | 一組可選的未受密碼學保護的屬性。 |

---

## AuthEnvelopedData

`AuthEnvelopedData` 內容類型提供驗證性加密，這是一種將機密性和完整性結合到單一密碼學操作中的模式。它通常與 AEAD（帶有關聯資料的驗證性加密）加密法（如 AES-GCM）一起使用。

-   **用途**：在加密內容的同時提供完整性和真實性保護。
-   **主要功能**：比分開應用加密和 MAC（例如，Encrypt-then-MAC）更有效率且更安全。

### 結構

| 欄位 | 說明 |
| :--- | :--- |
| `version` | 語法版本號碼。 |
| `originatorInfo` | 關於發起方的可選資訊，類似於 `EnvelopedData`。 |
| `recipientInfos` | 一組用於管理內容加密金鑰的 `RecipientInfo` 結構。 |
| `authEncryptedContentInfo` | 包含加密後的內容和加密演算法。 |
| `authAttrs` | 一組可選的已驗證屬性，這些屬性會被包含在 MAC 計算中。 |
| `mac` | 訊息驗證碼 (tag)，確保資料的完整性和真實性。 |
| `unauthAttrs` | 一組可選的未驗證屬性。 |

## 總結

六種 CMS 內容類型為保護資料提供了一套靈活的工具集。`Data` 是基礎，而 `SignedData` 和 `EnvelopedData` 分別是簽署和加密的主力。`DigestedData`、`EncryptedData` 和 `AuthEnvelopedData` 則為完整性、簡單對稱加密和驗證性加密提供了專門的解決方案。

要更深入地了解如何在 `EnvelopedData` 和 `AuthEnvelopedData` 中為接收者管理金鑰，請繼續閱讀 [Recipient Info Types](./concepts-recipient-info-types.md) 章節。