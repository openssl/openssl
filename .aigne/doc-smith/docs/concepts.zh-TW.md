# 核心概念

要有效使用 OpenSSL 密碼學訊息語法 (Cryptographic Message Syntax, CMS) 函式庫，首先必須了解其架構藍圖。本文件提供了 CMS 訊息主要元件的基礎概覽，說明它們如何互動，以及各自在建立安全數位訊息中所扮演的角色。這個概念框架將為您在後續指南中的實際應用做好準備。

## CMS 架構藍圖

密碼學訊息語法 (CMS) 在 [RFC 5652](https://tools.ietf.org/html/rfc5652) 中指定，是一種保護資料的標準。它為多種密碼學操作提供了語法，包括數位簽章、訊息摘要、身份驗證和加密。其最著名的應用是在 **S/MIME** (Secure/Multipurpose Internet Mail Extensions) 協定中，用於保護電子郵件通訊。

在其核心，每個 CMS 訊息都是一個 `ContentInfo` 結構。此結構作為一個通用包裝器，包含兩個關鍵資訊：

1.  **內容類型 (Content Type)**：一個物件識別碼 (OID)，指定所包含的資料類型。
2.  **內容 (Content)**：根據指定內容類型結構化的實際資料。

這種分層設計允許巢狀結構，即一個 CMS 結構可以被包裝在另一個結構內。例如，一個已簽章的訊息 (`SignedData`) 本身可以被加密，使整個 `SignedData` 結構成為 `EnvelopedData` 結構的內容。下圖說明了這種階層式結構：

<!-- DIAGRAM_IMAGE_START:architecture:3:4 -->
![核心概念](assets/diagram/concepts-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## CMS 內容類型

OpenSSL CMS 實作支援數種標準內容類型，每種都為特定的密碼學目的而設計。了解這些類型是建立和解析 CMS 訊息的第一步。

有關每種類型的深入詳細資訊，請參閱 [內容類型](./concepts-content-types.md) 文件。

<x-cards data-columns="3">
  <x-card data-title="Data" data-icon="lucide:file-text">
    最簡單的類型，表示任意的八位元字串資料。它作為其他類型的純文字內容。
  </x-card>
  <x-card data-title="SignedData" data-icon="lucide:pen-square">
    提供數位簽章。它包含原始內容、簽署者資訊 (SignerInfo) 和數位簽章。
  </x-card>
  <x-card data-title="EnvelopedData" data-icon="lucide:mail">
    透過加密提供機密性。它包含加密後的內容以及解密所需的收件者特定資訊 (RecipientInfo)。
  </x-card>
  <x-card data-title="DigestedData" data-icon="lucide:hash">
    透過儲存內容的訊息摘要 (雜湊值) 來提供內容完整性。
  </x-card>
  <x-card data-title="EncryptedData" data-icon="lucide:lock">
    包含對稱加密的內容，但與 EnvelopedData 不同，它不包含收件者金鑰管理資訊。金鑰必須透過帶外方式管理。
  </x-card>
  <x-card data-title="AuthEnvelopedData" data-icon="lucide:shield-check">
    提供帶有關聯資料的驗證性加密 (AEAD)，在單一操作中結合了機密性和完整性。
  </x-card>
</x-cards>

## 內容類型中的關鍵元件

`SignerInfo` 和 `RecipientInfo` 這兩個關鍵結構分別是 `SignedData` 和 `EnvelopedData` 類型的運作核心。

### SignerInfo：簽章區塊

`SignerInfo` 結構是 `SignedData` 內容類型的核心。訊息的每個簽署者都會貢獻一個 `SignerInfo` 區塊。此區塊包含驗證簽章所需的所有資訊，包括：

*   **簽署者識別碼 (Signer Identifier)**：唯一識別簽署者的憑證，通常透過發行者和序號，或透過主體金鑰識別碼來識別。
*   **摘要演算法 (Digest Algorithm)**：在簽署前用於雜湊訊息內容的演算法（例如 SHA-256）。
*   **簽章演算法 (Signature Algorithm)**：用於建立數位簽章的演算法（例如 RSA）。
*   **已簽署屬性 (Signed Attributes)**：一組與內容摘要一起簽署的已驗證屬性。這通常包括內容類型和簽署時間。
*   **簽章值 (Signature Value)**：實際的數位簽章八位元字串。
*   **未簽署屬性 (Unsigned Attributes)**：非簽章計算一部分的選用屬性，例如副署簽章。

### RecipientInfo：解密之鑰

`RecipientInfo` 結構是 `EnvelopedData` 和 `AuthEnvelopedData` 的核心。它為特定收件者提供了必要的資訊以解密訊息。一個訊息可以包含多個 `RecipientInfo` 結構，每個收件者一個。

CMS 定義了幾種將內容加密金鑰 (CEK) 傳遞給收件者的方法，每種方法對應不同的 `RecipientInfo` 類型。類型的選擇取決於收件者使用的憑證種類。

有關每種類型的完整說明，請參閱 [Recipient Info 類型](./concepts-recipient-info-types.md) 文件。

| 類型  | 常數                  | 說明                                                                                                    | 常見憑證                  |
| :---- | :---------------------- | :------------------------------------------------------------------------------------------------------ | :------------------------ |
| KTRI  | `CMS_RECIPINFO_TRANS`   | **金鑰傳輸 (Key Transport)**：CEK 使用收件者的公鑰加密（例如 RSA）。                                         | X.509 憑證 (RSA)          |
| KARI  | `CMS_RECIPINFO_AGREE`   | **金鑰協商 (Key Agreement)**：使用收件者和發起者的金鑰衍生出一個共享密鑰（例如 DH/ECDH）。                    | X.509 憑證 (DH/EC)        |
| KEKRI | `CMS_RECIPINFO_KEK`     | **金鑰加密金鑰 (Key Encryption Key)**：CEK 使用預共享的對稱金鑰進行包裝。                                   | 對稱金鑰                  |
| PWRI  | `CMS_RECIPINFO_PASS`    | **密碼 (Password)**：CEK 從密碼中衍生而來。                                                               | 密碼 / 通行詞             |
| KEMRI | `CMS_RECIPINFO_KEM`     | **金鑰封裝機制 (Key Encapsulation Mechanism)**：用於金鑰交換的抗量子機制。                                  | 後量子金鑰                |
| ORI   | `CMS_RECIPINFO_OTHER`   | **其他 (Other)**：為自訂或未來的收件者類型保留的佔位符。                                                  | 自訂                      |

## 與 `openssl cms` 指令的關係

`openssl cms` 命令列工具是 CMS 函式庫功能的高階介面。其每個主要操作都直接對應到特定 CMS 內容類型的建立或處理。了解這種對應關係有助於理解命令列操作如何轉換為底層 API。

| `openssl cms` 指令      | 對應的 CMS 內容類型 | 核心 API 函式                              |
| :---------------------------- | :----------------------------- | :------------------------------------------------- |
| `-sign`, `-verify`, `-resign` | `SignedData`                   | `CMS_sign()`, `CMS_verify()`                       |
| `-encrypt`, `-decrypt`        | `EnvelopedData`                | `CMS_encrypt()`, `CMS_decrypt()`                   |
| `-digest_create`, `-digest_verify` | `DigestedData`                 | `CMS_digest_create()`, `CMS_digest_verify()`       |
| `-EncryptedData_encrypt`, `-EncryptedData_decrypt` | `EncryptedData`                | `CMS_EncryptedData_encrypt()`, `CMS_EncryptedData_decrypt()` |
| `-compress`, `-uncompress`    | `CompressedData`               | `CMS_compress()`, `CMS_uncompress()`               |
| `-data_create`                | `Data`                         | `CMS_data_create()`                                |

## 總結

密碼學訊息語法提供了一個結構化、分層的框架，用於對資料應用密碼學保護。其核心是 `ContentInfo` 結構，它包裝了如 `SignedData` 和 `EnvelopedData` 等各種內容類型。而這些類型又依賴 `SignerInfo` 和 `RecipientInfo` 來管理簽章和加密金鑰。

有了這個概念基礎，您現在已準備好探索更具體的主題：

<x-cards data-columns="2">
  <x-card data-title="快速入門" data-icon="lucide:rocket" data-href="/quick-start">
    以最少的理論進行常見 CMS 操作的實作指南。
  </x-card>
  <x-card data-title="內容類型" data-icon="lucide:box" data-href="/concepts/content-types">
    對每種主要 CMS 內容類型的詳細檢視。
  </x-card>
  <x-card data-title="Recipient Info 類型" data-icon="lucide:key-round" data-href="/concepts/recipient-info-types">
    深入探討收件者金鑰管理的不同方法。
  </x-card>
  <x-card data-title="CLI 工具 (openssl cms)" data-icon="lucide:terminal" data-href="/command-line">
    命令列介面的綜合參考。
  </x-card>
</x-cards>