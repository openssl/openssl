本文件為 `openssl cms` 命令列工具提供了詳細的參考，將其操作和旗標對應到底層的 OpenSSL 函式庫函式。透過理解這些關聯，您可以更有效地從命令列使用過渡到程式化的 API 實作。

# CLI 工具 (`openssl cms`)

`openssl cms` 命令提供了一個用於處理密碼學訊息語法 (Cryptographic Message Syntax, CMS) 資料的命令列介面。它允許使用者執行廣泛的密碼學操作，例如建立數位簽章、驗證簽章，以及加密或解密訊息內容，與 S/MIME 等安全電子郵件標準保持一致。

此工具可視為 OpenSSL CMS 函式庫核心功能的實用封裝。理解其用法有助於深入了解如何以程式化方式應用 API 來處理更複雜的工作流程。

下圖說明了 `openssl cms` 命令列工具、其主要操作，以及它們所利用的核心 OpenSSL 函式庫函式之間的關係。

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![本文件為 `openssl cms` 命令列工具提供了詳細的參考，將其操作和旗標對應到底層的 OpenSSL 函式庫函式。](./assets/diagram/command-line-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## 操作

`openssl cms` 工具的主要功能由單一的操作選項決定。每個操作都對應一個高階工作流程，該流程結合了從讀取輸入資料到格式化最終輸出的多個步驟。下表將最常見的操作對應到它們主要的函式庫函式和 CMS 內容類型。

| 操作選項 | CMS 內容類型 | 核心 API 函式 | 說明 |
| :--- | :--- | :--- | :--- |
| `-sign` | `SignedData` | `CMS_sign()` | 對輸入資料建立數位簽章。 |
| `-verify` | `SignedData` | `CMS_verify()` | 驗證已簽章訊息的完整性和真實性。 |
| `-encrypt` | `EnvelopedData` | `CMS_encrypt()` | 為一個或多個接收者加密內容。 |
| `-decrypt` | `EnvelopedData` | `CMS_decrypt()` | 使用接收者的私鑰解密內容。 |
| `-compress` | `CompressedData` | `CMS_compress()` | 使用 zlib 壓縮輸入資料。 |
| `-uncompress` | `CompressedData` | `CMS_uncompress()` | 解壓縮一個 `CompressedData` 物件。 |
| `-resign` | `SignedData` | `CMS_sign()` 搭配 `CMS_REUSE_DIGEST` | 將一個新的簽章加入到現有的 `SignedData` 結構中。 |
| `-digest_create`| `DigestedData` | `CMS_digest_create()` | 建立一個包含訊息摘要的結構。 |
| `-EncryptedData_encrypt` | `EncryptedData` | `CMS_EncryptedData_encrypt()` | 使用對稱金鑰加密資料，不包含接收者資訊。 |

## 選項參考

每個操作的行為都由一組旗標控制。這些旗標通常直接對應到底層 C API 函式中的參數或旗標。

### 一般與 I/O 選項

這些選項控制輸入和輸出的來源與格式。

| 旗標 | 參數 | 說明 |
| :--- | :--- | :--- |
| `-in` | `<filename>` | 指定輸入檔案。 |
| `-out` | `<filename>` | 指定輸出檔案。 |
| `-inform` | `SMIME` \| `PEM` \| `DER` | 設定輸入格式。預設為 `SMIME`。 |
| `-outform`| `SMIME` \| `PEM` \| `DER` | 設定輸出格式。預設為 `SMIME`。 |
| `-binary` | (無) | 防止標準文本轉換 (CRLF 轉換)。用於二進位資料。對應 `CMS_BINARY` 旗標。 |
| `-stream`, `-indef` | (無) | 啟用串流 I/O，其使用 BER 不定長度編碼。對應 `CMS_STREAM` 旗標。 |
| `-content`| `<filename>` | 指定用於驗證的分離式內容檔案。 |
| `-text` | (無) | 簽章/加密時新增 `text/plain` MIME 標頭，或在驗證/解密時移除它們。對應 `CMS_TEXT` 旗標。 |

### 簽章與驗證選項

這些旗標修改 `-sign` 和 `-verify` 操作的行為。

| 旗標 | 參數 | 操作 | 說明 |
| :--- | :--- | :--- | :--- |
| `-signer` | `<certfile>` | Sign, Verify | 指定簽署者的憑證。可多次使用以處理多重簽署者訊息。 |
| `-inkey` | `<keyfile>` | Sign, Decrypt | 指定與 `-signer` 或 `-recip` 憑證對應的私鑰。 |
| `-md` | `<digest>` | Sign | 設定摘要演算法 (例如 `sha256`)。 |
| `-nodetach`| (無) | Sign | 建立一個不透明簽章，其中內容嵌入在 `SignedData` 結構內。清除 `CMS_DETACHED` 旗標。 |
| `-nocerts` | (無) | Sign | 從 `SignedData` 結構中排除簽署者的憑證。對應 `CMS_NOCERTS` 旗標。 |
| `-noattr` | (無) | Sign | 排除所有已簽章屬性，包括簽署時間和 S/MIME 功能。對應 `CMS_NOATTR` 旗標。 |
| `-noverify`| (無) | Verify | 略過對簽署者憑證鏈的驗證。對應 `CMS_NO_SIGNER_CERT_VERIFY` 旗標。 |
| `-nosigs` | (無) | Verify | 略過對數位簽章本身的驗證。對應 `CMS_NOSIGS` 旗標。 |
| `-certfile`| `<certs.pem>` | Sign, Verify | 提供額外的憑證，以包含在訊息中或在驗證期間用於建立憑證鏈。 |
| `-CAfile` | `<ca.pem>` | Verify | 指定一個包含受信任 CA 憑證的檔案，用於憑證鏈驗證。 |

### 加密與解密選項

這些旗標修改 `-encrypt` 和 `-decrypt` 操作的行為。

| 旗標 | 參數 | 操作 | 說明 |
| :--- | :--- | :--- | :--- |
| `-recip` | `<cert.pem>` | Encrypt, Decrypt | 指定用於加密或解密的接收者憑證。 |
| `-<cipher>` | (無) | Encrypt | 指定內容加密演算法 (例如 `-aes256`、`-des3`)。 |
| `-keyid` | (無) | Encrypt, Sign | 透過主體金鑰識別碼 (Subject Key Identifier) 而非簽發者和序號 (Issuer and Serial Number) 來識別接收者或簽署者。對應 `CMS_USE_KEYID` 旗標。 |
| `-secretkey`| `<key>` | Encrypt, Decrypt | 用於 `KEKRecipientInfo` (加密) 或 `EncryptedData` 操作的十六進位編碼對稱金鑰。 |
| `-secretkeyid`| `<id>` | Encrypt, Decrypt | 用於 KEK 接收者的十六進位編碼金鑰識別碼。 |
| `-pwri_password`| `<password>` | Encrypt, Decrypt | 用於 `PasswordRecipientInfo` (PWRI) 的密碼。 |
| `-originator` | `<cert.pem>` | Decrypt | 指定用於金鑰協商機制 (例如 ECDH) 的發起者憑證。 |

## 實用範例

以下範例展示了 `openssl cms` 工具的常見用法。

### 建立分離式簽章

此命令會對一則訊息進行簽章，並將簽章輸出到一個獨立的檔案中，同時保持原始內容不變。這是預設的簽章行為。

```sh 建立分離式簽章 icon=lucide:terminal
openssl cms -sign -in message.txt -text -out signature.pem \
  -signer signer_cert.pem -inkey signer_key.pem
```

### 驗證分離式簽章

要驗證簽章，您必須提供原始內容、簽章檔案以及簽署者的憑證。

```sh 驗證分離式簽章 icon=lucide:terminal
openssl cms -verify -in signature.pem -inform PEM \
  -content message.txt -CAfile trusted_ca.pem -out verified_message.txt
```

### 建立不透明 (附加式) 簽章

不透明簽章會將原始內容嵌入到 CMS 結構中。若不進行解析，產生的檔案將不具人類可讀性。

```sh 建立不透明簽章 icon=lucide:terminal
openssl cms -sign -in message.txt -text -nodetach \
  -out signed_opaque.pem -signer signer_cert.pem
```

### 為多個接收者加密訊息

此命令為兩個不同的接收者加密一個檔案。任一接收者都可以用其對應的私鑰解密該訊息。

```sh 為多個接收者加密 icon=lucide:terminal
openssl cms -encrypt -in confidential.txt -out encrypted.pem \
  -recip recip1_cert.pem -recip recip2_cert.pem
```

### 解密訊息

接收者使用他們的憑證和私鑰來解密訊息。

```sh 解密訊息 icon=lucide:terminal
openssl cms -decrypt -in encrypted.pem -out confidential.txt \
  -recip recip1_cert.pem -inkey recip1_key.pem
```

### 先簽章後加密訊息

要建立一則同時經過簽章和加密的訊息，需要將操作串連起來。`-sign` 命令的輸出會透過管道傳遞給 `-encrypt` 命令的輸入。

```sh 先簽章後加密訊息 icon=lucide:terminal
openssl cms -sign -in message.txt -signer signer.pem -text \
  | openssl cms -encrypt -recip recipient.pem -out signed_and_encrypted.pem
```

## 總結

`openssl cms` 命令列工具是一個功能多樣的公用程式，用於管理 CMS 結構。其選項和操作與 OpenSSL 函式庫中可用的函式直接對應。對於開發人員來說，分析其原始碼和行為是學習如何以程式化方式實作這些功能的有效方法。

有關底層 API 的更多詳細資訊，請參閱以下章節：
- [主要函式](./api-main.md)
- [簽章與驗證](./guides-signing-verifying.md)
- [加密與解密](./guides-encrypting-decrypting.md)