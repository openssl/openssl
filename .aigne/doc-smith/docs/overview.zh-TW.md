本文件說明了密碼訊息語法（Cryptographic Message Syntax, CMS）的用途、其在 S/MIME 等安全訊息應用中的角色，以及 OpenSSL CMS 函式庫的高層架構。閱讀完畢後，您將能理解 CMS 訊息的基本組成部分以及它們如何協同運作。

# 總覽

密碼訊息語法（CMS），定義於 [RFC 5652](https://tools.ietf.org/html/rfc5652)，是一種使用密碼學保護資料的標準。它為各種密碼學操作定義了一套語法，包括數位簽章、訊息摘要、身份驗證和加密。CMS 是安全訊息傳遞標準的基石，例如用於簽署和加密電子郵件的安全/多用途網際網路郵件延伸（Secure/Multipurpose Internet Mail Extensions, S/MIME）。

OpenSSL CMS 模組提供了此標準全面而靈活的實作，可透過 C 語言 API 和功能強大的命令列介面（`openssl cms`）存取。

## CMS 的目的

CMS 提供了一種「包裝」格式，用以封裝資料及相關的密碼學資訊。這使得建立獨立、安全的訊息成為可能，並可透過不安全的網路傳輸。CMS 的核心功能包括：

*   **資料完整性：** 確保資料在傳輸過程中未被修改，通常使用數位簽章達成。
*   **身份驗證：** 驗證寄件者的身份。
*   **機密性：** 加密資料，使其僅有授權的收件者可以檢視。
*   **不可否認性：** 提供特定寄件者建立訊息的證明，防止其事後否認。

## 高層架構

CMS 結構的核心是一個 `ContentInfo` 物件。此物件作為一個容器，包含兩項關鍵資訊：

1.  **內容類型：** 一個識別碼，用於指定所應用的密碼學保護類型（例如：簽署資料、信封資料）。
2.  **內容：** 根據指定內容類型結構化的實際資料。

CMS 的強大之處在於其模組化設計，不同的內容類型可以相互巢狀，以組合密碼學操作，例如建立一則先簽署後加密的訊息。

下圖說明了 `ContentInfo` 容器與其各種內容類型之間的關係：

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![This document explains the purpose of the Cryptographic Message Syntax (CMS), its role in secure ...](./assets/diagram/overview-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

### 核心內容類型

OpenSSL 的 CMS 實作支援數種標準內容類型，每種都有其獨特的用途。理解這些類型是有效使用此函式庫的基礎。

| 內容類型 | 說明 | 常見使用案例 |
| :--- | :--- | :--- |
| **Data** | 任意資料的簡單包裝，不具任何密碼學保護。它通常作為巢狀結構中最內層的內容。 | 在簽署或加密前封裝原始訊息。 |
| **SignedData** | 包含資料以及來自一個或多個簽署者的數位簽章。它提供身份驗證、完整性和不可否認性。 | 驗證文件或電子郵件的作者。 |
| **EnvelopedData** | 包含加密資料以及供一個或多個收件者解密的資訊。它提供機密性。 | 向多個收件者傳送機密訊息。 |
| **DigestedData** | 包含資料及該資料的訊息摘要（雜湊）。它提供一種基本的完整性檢查形式。 | 驗證檔案在下載過程中是否損毀。 |
| **EncryptedData** | 包含以對稱金鑰加密的資料。與 `EnvelopedData` 不同，它不包含用於金鑰管理的收件者資訊。 | 在金鑰分發另行處理的情況下，進行簡單的對稱加密。 |
| **AuthEnvelopedData** | 提供驗證性加密（AEAD），在單一高效的操作中結合了機密性和完整性。 | 保護同時需要機密性和真實性的資料。 |
| **CompressedData** | 包含壓縮資料。此類型通常在加密前使用，以減少訊息的大小。 | 在加密並傳送大型附件前對其進行壓縮。 |

關於每種類型的更詳細說明，請參閱[核心概念](./concepts-content-types.md)章節。

### 簽署者與收件者

在主要的內容類型中，還有另外兩種結構扮演著關鍵角色：

*   `SignerInfo`：用於 `SignedData` 結構中。每個 `SignerInfo` 物件包含單一簽署者的簽章及相關資訊，包括其憑證識別碼和已簽署屬性的雜湊值。一則訊息可以有多個簽署者，每個都由一個獨立的 `SignerInfo` 結構表示。

*   `RecipientInfo`：用於 `EnvelopedData` 結構中。每個 `RecipientInfo` 物件包含為單一收件者加密的內容加密金鑰。此設計允許訊息僅加密一次，但可由多個收件者使用各自的私鑰解密。CMS 支援多種金鑰管理方法，詳見[收件者資訊類型](./concepts-recipient-info-types.md)。

## 函式庫 vs. 命令列工具

OpenSSL 提供了兩種主要方式來與 CMS 模組互動：

1.  **`openssl cms` 命令列工具：** 一個多功能的公用程式，可直接從 shell 執行常見的 CMS 操作，如簽署、驗證、加密和解密檔案。它非常適合用於腳本編寫和手動任務。

2.  **C 函式庫 (`libcrypto`)：** 一個豐富的 API，揭示了 CMS 實作的全部功能。這是為需要在其 C/C++ 應用程式中直接整合安全訊息功能的開發人員所設計的路徑，提供了對 CMS 結構各個方面的精細控制。

命令列工具直接建構於 C 函式庫之上，其選項通常直接對應到 API 函數和旗標。例如，執行 `openssl cms -sign` 會呼叫底層的 `CMS_sign()` 函數。本文件旨在彌合兩者之間的差距，讓熟悉命令列的使用者能夠過渡到 API，反之亦然。

## 瀏覽本文件

本文件的結構旨在引導您從高層概念到實際的實作細節。

<x-cards data-columns="2">
  <x-card data-title="快速入門" data-icon="lucide:rocket" data-href="/quick-start">
    本指南提供最常見操作的即時、實用範例，帶您動手入門。
  </x-card>
  <x-card data-title="核心概念" data-icon="lucide:book-open" data-href="/concepts">
    本節詳細介紹 CMS 的架構組件，助您深入理解其理論基礎。
  </x-card>
  <x-card data-title="操作指南" data-icon="lucide:wrench" data-href="/guides">
    這些指南提供針對特定使用案例的逐步工作流程，以任務為導向進行說明。
  </x-card>
  <x-card data-title="API 參考" data-icon="lucide:library" data-href="/api">
    本節提供 API 中每個函數的全面參考，供您查閱詳細的技術資訊。
  </x-card>
</x-cards>

---

### 總結

*   **CMS 是一項標準：** 它提供了一種多功能的語法（RFC 5652），用於對資料應用簽章和加密等密碼學保護。
*   **它是一個包裝系統：** 核心的 `ContentInfo` 結構使用不同的 `內容類型`（例如 `SignedData`、`EnvelopedData`）來包裝資料以確保其安全。
*   **OpenSSL 提供完整支援：** 功能可透過靈活的 `openssl cms` 命令列工具和全面的 C 函式庫 API 使用。
*   **關鍵結構：** `SignerInfo` 和 `RecipientInfo` 分別實現了多重簽署者和多重收件者的功能。