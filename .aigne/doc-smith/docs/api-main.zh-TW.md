# 主要函式

本節為用於建立、解析、最終確定及管理核心密碼訊息語法 (Cryptographic Message Syntax, CMS) 結構的高階函式提供詳細參考。這些函式是簽署、驗證、加密和解密資料等常見操作的主要進入點。

下圖說明了用於簽署/驗證和加密/解密資料流程的主要 CMS 函式之間的關係。

<!-- DIAGRAM_IMAGE_START:flowchart:16:9 -->
![主要函式](./assets/diagram/api-main-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## 簽署與驗證

這些函式處理 CMS `SignedData` 結構的建立與驗證，這對於確保資料完整性和真實性至關重要。

### CMS_sign

`CMS_sign()` 和 `CMS_sign_ex()` 函式會建立一個 `SignedData` 型別的 `CMS_ContentInfo` 結構。此操作涉及使用私密金鑰簽署資料，並包含對應的憑證以及任何其他附加憑證，以形成一個完整、可驗證的訊息。

#### 函式原型

```c
#include <openssl/cms.h>

CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
                          BIO *data, unsigned int flags);

CMS_ContentInfo *CMS_sign_ex(X509 *signcert, EVP_PKEY *pkey,
                             STACK_OF(X509) *certs, BIO *data,
                             unsigned int flags, OSSL_LIB_CTX *libctx,
                             const char *propq);
```

#### 參數

<x-field-group>
  <x-field data-name="signcert" data-type="X509*" data-required="false" data-desc="簽署者的憑證。若為僅含憑證的結構，可為 NULL。"></x-field>
  <x-field data-name="pkey" data-type="EVP_PKEY*" data-required="false" data-desc="與 signcert 對應的私密金鑰。若為僅含憑證的結構，可為 NULL。"></x-field>
  <x-field data-name="certs" data-type="STACK_OF(X509)*" data-required="false" data-desc="一個可選的附加憑證堆疊，用於包含在結構中，例如中繼 CA。"></x-field>
  <x-field data-name="data" data-type="BIO*" data-required="true" data-desc="一個包含待簽署資料的 BIO。"></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="一個用於控制簽署操作的旗標位元遮罩。"></x-field>
  <x-field data-name="libctx" data-type="OSSL_LIB_CTX*" data-required="false" data-desc="一個 OpenSSL 程式庫上下文 (用於 CMS_sign_ex)。若為 NULL，則使用預設上下文。"></x-field>
  <x-field data-name="propq" data-type="const char*" data-required="false" data-desc="一個用於演算法擷取的屬性查詢字串 (用於 CMS_sign_ex)。"></x-field>
</x-field-group>

#### 旗標

`flags` 參數可修改簽署操作的行為。多個旗標可使用位元 OR 運算結合。

| 旗標 | 說明 |
| --- | --- |
| `CMS_TEXT` | 在內容前加上標準的 `text/plain` MIME 標頭。 |
| `CMS_NOCERTS` | 從 `SignedData` 結構中排除簽署者的憑證。簽署時，`signcert` 參數中仍需提供該憑證。 |
| `CMS_DETACHED` | 建立分離式簽章，其中內容不包含在最終的 `CMS_ContentInfo` 結構中。 |
| `CMS_BINARY` | 防止對內容進行 MIME 標準化。這對於避免二進位資料損壞至關重要。 |
| `CMS_NOATTR` | 排除所有已簽署的屬性，包括簽署時間和 SMIMECapabilities。 |
| `CMS_NOSMIMECAP` | 省略 `SMIMECapabilities` 已簽署屬性。 |
| `CMS_NO_SIGNING_TIME` | 省略簽署時間屬性。 |
| `CMS_USE_KEYID` | 透過簽署者憑證的主體金鑰識別碼來識別，而非預設的發行者和序號。 |
| `CMS_STREAM` | 為串流初始化 `CMS_ContentInfo` 結構，但延遲實際的簽署操作。資料在最終確定期間讀取和處理。 |
| `CMS_PARTIAL` | 建立一個部分的 `CMS_ContentInfo` 結構，允許在呼叫 `CMS_final()` 之前新增更多簽署者或屬性。 |

#### 回傳值

成功時回傳一個有效的 `CMS_ContentInfo` 結構，失敗時回傳 `NULL`。可從 OpenSSL 錯誤佇列中擷取錯誤資訊。

### CMS_verify

`CMS_verify()` 函式用於驗證一個 CMS `SignedData` 結構。它會檢查已簽署內容的完整性、驗證簽署者的簽章，並可選擇性地根據受信任的儲存庫來驗證簽署者的憑證鏈。

#### 函式原型

```c
#include <openssl/cms.h>

int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs, X509_STORE *store,
               BIO *detached_data, BIO *out, unsigned int flags);
```

#### 參數

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="要驗證的 CMS_ContentInfo 結構。"></x-field>
  <x-field data-name="certs" data-type="STACK_OF(X509)*" data-required="false" data-desc="一個可選的不受信任憑證堆疊，用於搜尋簽署者憑證及協助建立憑證鏈。"></x-field>
  <x-field data-name="store" data-type="X509_STORE*" data-required="false" data-desc="一個用於路徑驗證的受信任憑證儲存庫。"></x-field>
  <x-field data-name="detached_data" data-type="BIO*" data-required="false" data-desc="若簽章為分離式，則此 BIO 包含內容。對於內嵌式簽章，應為 NULL。"></x-field>
  <x-field data-name="out" data-type="BIO*" data-required="false" data-desc="一個用於寫入已驗證內容的 BIO。若為 NULL，內容會被讀取和驗證，但不會寫出。"></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="一個用於控制驗證操作的旗標位元遮罩。"></x-field>
</x-field-group>

#### 旗標

| 旗標 | 說明 |
| --- | --- |
| `CMS_NOINTERN` | 防止在 CMS 結構內部搜尋簽署者的憑證。憑證必須在 `certs` 參數中提供。 |
| `CMS_TEXT` | 從內容中移除 `text/plain` MIME 標頭。若內容型別不是 `text/plain`，則會發生錯誤。 |
| `CMS_NO_SIGNER_CERT_VERIFY` | 略過對簽署者憑證的憑證鏈驗證。 |
| `CMS_NO_ATTR_VERIFY` | 略過對已簽署屬性簽章的驗證。 |
| `CMS_NO_CONTENT_VERIFY` | 略過對內容摘要的驗證。這表示會檢查簽章，但不會根據簽章驗證內容本身。 |
| `CMS_NOCRL` | 在憑證驗證期間，忽略 CMS 結構中存在的任何 CRL。 |
| `CMS_CADES` | 啟用 CAdES 特定檢查，例如驗證 `signingCertificate` 或 `signingCertificateV2` 屬性。 |

#### 回傳值

成功驗證時回傳 `1`，失敗時回傳 `0`。詳細的錯誤資訊可從 OpenSSL 錯誤佇列中擷取。

### CMS_get0_signers

此公用程式函式從 `CMS_ContentInfo` 結構中擷取所有簽署者的憑證。它應僅在成功驗證後呼叫，因為驗證過程負責尋找憑證並將其與每個 `SignerInfo` 關聯。

#### 函式原型

```c
#include <openssl/cms.h>

STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);
```

#### 參數

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="成功驗證的 CMS 結構。"></x-field>
</x-field-group>

#### 回傳值

回傳一個指向內部 `STACK_OF(X509)` 的指標，其中包含簽署者的憑證。應用程式不應釋放此指標。若發生錯誤或找不到簽署者，則回傳 `NULL`。

## 加密與解密

這些函式用於為一個或多個收件者建立和解析 `EnvelopedData` 結構，以進行資料加密和解密。

### CMS_encrypt

`CMS_encrypt()` 和 `CMS_encrypt_ex()` 函式會建立一個 `EnvelopedData` 或 `AuthEnvelopedData` 型別的 `CMS_ContentInfo` 結構。內容會使用一個隨機產生的對稱金鑰進行加密，然後透過各收件者的公開金鑰對該金鑰進行加密，以安全地分發給每個收件者。

#### 函式原型

```c
#include <openssl/cms.h>

CMS_ContentInfo *CMS_encrypt(STACK_OF(X509) *certs, BIO *in,
                             const EVP_CIPHER *cipher, unsigned int flags);

CMS_ContentInfo *CMS_encrypt_ex(STACK_OF(X509) *certs, BIO *in,
                                const EVP_CIPHER *cipher, unsigned int flags,
                                OSSL_LIB_CTX *libctx, const char *propq);
```

#### 參數

<x-field-group>
  <x-field data-name="certs" data-type="STACK_OF(X509)*" data-required="true" data-desc="一個收件者憑證的堆疊。"></x-field>
  <x-field data-name="in" data-type="BIO*" data-required="true" data-desc="一個包含待加密資料的 BIO。"></x-field>
  <x-field data-name="cipher" data-type="const EVP_CIPHER*" data-required="true" data-desc="用於內容加密的對稱加密演算法 (例如 EVP_aes_256_cbc())。"></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="一個用於控制加密操作的旗標位元遮罩。"></x-field>
  <x-field data-name="libctx" data-type="OSSL_LIB_CTX*" data-required="false" data-desc="一個 OpenSSL 程式庫上下文 (用於 CMS_encrypt_ex)。若為 NULL，則使用預設上下文。"></x-field>
  <x-field data-name="propq" data-type="const char*" data-required="false" data-desc="一個用於演算法擷取的屬性查詢字串 (用於 CMS_encrypt_ex)。"></x-field>
</x-field-group>

#### 旗標

| 旗標 | 說明 |
| --- | --- |
| `CMS_TEXT` | 在加密前，於內容前加上標準的 `text/plain` MIME 標頭。 |
| `CMS_BINARY` | 防止對內容進行 MIME 標準化，這對於二進位資料是必要的。 |
| `CMS_USE_KEYID` | 透過收件者的主體金鑰識別碼來識別。若收件者憑證缺乏此擴充功能，則會發生錯誤。 |
| `CMS_STREAM` | 為串流 I/O 初始化 `CMS_ContentInfo` 結構，但延遲從輸入 BIO 讀取資料。 |
| `CMS_PARTIAL` | 建立一個部分的 `CMS_ContentInfo` 結構，允許在最終確定前新增更多收件者。 |
| `CMS_DETACHED` | 從最終結構中省略加密後的內容。此旗標很少使用。 |

#### 回傳值

成功時回傳一個有效的 `CMS_ContentInfo` 結構，失敗時回傳 `NULL`。

### CMS_decrypt

`CMS_decrypt()` 函式用於解密一個 `EnvelopedData` 或 `AuthEnvelopedData` 型別的 `CMS_ContentInfo` 結構。它使用收件者的私密金鑰解密內容加密金鑰，然後再用該金鑰解密實際內容。

#### 函式原型

```c
#include <openssl/cms.h>

int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert,
                BIO *dcont, BIO *out, unsigned int flags);
```

#### 參數

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="要解密的 CMS 結構。"></x-field>
  <x-field data-name="pkey" data-type="EVP_PKEY*" data-required="true" data-desc="收件者的私密金鑰。"></x-field>
  <x-field data-name="cert" data-type="X509*" data-required="false" data-desc="收件者的憑證。雖然解密並非嚴格要求，但強烈建議提供此憑證以定位正確的 RecipientInfo 並防止潛在攻擊。"></x-field>
  <x-field data-name="dcont" data-type="BIO*" data-required="false" data-desc="若加密內容為分離式，則此 BIO 包含該內容。通常為 NULL。"></x-field>
  <x-field data-name="out" data-type="BIO*" data-required="true" data-desc="一個用於寫入解密後內容的 BIO。"></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="一個用於控制解密的旗標位元遮罩。"></x-field>
</x-field-group>

#### 旗標

| 旗標 | 說明 |
| --- | --- |
| `CMS_TEXT` | 從解密後的內容中移除 `text/plain` MIME 標頭。若內容型別不是 `text/plain`，則會發生錯誤。 |
| `CMS_DEBUG_DECRYPT` | 停用 MMA (Bleichenbacher 攻擊) 的防護措施。若沒有任何收件者金鑰能成功解密，會立即回傳錯誤，而不是使用隨機金鑰進行解密。請極度謹慎使用。 |

#### 回傳值

成功時回傳 `1`，失敗時回傳 `0`。

### 輔助解密函式

為了進行更精細的控制，您可以使用以下函式預先設定解密金鑰，然後在呼叫 `CMS_decrypt()` 時將 `pkey` 和 `cert` 設為 `NULL`。

#### 函式原型

```c
#include <openssl/cms.h>

int CMS_decrypt_set1_pkey(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert);

int CMS_decrypt_set1_pkey_and_peer(CMS_ContentInfo *cms, EVP_PKEY *pk,
                                   X509 *cert, X509 *peer);

int CMS_decrypt_set1_password(CMS_ContentInfo *cms,
                              unsigned char *pass, ossl_ssize_t passlen);
```

#### 說明

-   `CMS_decrypt_set1_pkey()` 和 `CMS_decrypt_set1_pkey_and_peer()` 使用私密金鑰 `pk` 解密內容加密金鑰。憑證 `cert` 有助於識別正確的 `RecipientInfo`。`peer` 憑證用於金鑰協商機制。
-   `CMS_decrypt_set1_password()` 對於 `PWRI` (Password Recipient Info) 型別，使用密碼進行解密。

這些函式成功時回傳 `1`，失敗時回傳 `0`。

## 最終確定函式

當使用 `CMS_STREAM` 或 `CMS_PARTIAL` 旗標建立 CMS 結構時，在處理完所有資料後，需要一個最終確定步驟來完成該結構。

### CMS_final

`CMS_final()` 函式用於最終確定一個 `CMS_ContentInfo` 結構。這通常涉及在所有內容都透過串流 BIO 寫入後，計算並編碼摘要和簽章。在不使用串流 I/O 的情況下使用 `CMS_PARTIAL` 旗標時，此函式至關重要。

#### 函式原型

```c
#include <openssl/cms.h>

int CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont, unsigned int flags);
```

#### 參數

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="要最終確定的部分 CMS 結構。"></x-field>
  <x-field data-name="data" data-type="BIO*" data-required="true" data-desc="一個包含待處理內容的 BIO。"></x-field>
  <x-field data-name="dcont" data-type="BIO*" data-required="false" data-desc="一個用於在處理後寫入內容的 BIO (用於分離式簽章)。通常為 NULL。"></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="用於控制處理的旗標，例如 MIME 標準化。"></x-field>
</x-field-group>

#### 回傳值

成功時回傳 `1`，失敗時回傳 `0`。

### CMS_dataFinal

當啟用串流時，`CMS_dataFinal()` 和 `CMS_dataFinal_ex()` 函式用於最終確定 CMS 結構。它們會被 `i2d_CMS_bio_stream()` 等函式在內部呼叫，但也可以直接使用以進行精細控制。對於如 EdDSA 這類無雜湊的簽章機制，需要使用 `CMS_dataFinal_ex`。

#### 函式原型

```c
#include <openssl/cms.h>

int CMS_dataFinal(CMS_ContentInfo *cms, BIO *cmsbio);

int CMS_dataFinal_ex(CMS_ContentInfo *cms, BIO *cmsbio, BIO *data);
```

#### 參數

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="要最終確定的串流 CMS 結構。"></x-field>
  <x-field data-name="cmsbio" data-type="BIO*" data-required="true" data-desc="從 CMS_dataInit() 回傳的 BIO 鏈，資料已透過此鏈寫入。"></x-field>
  <x-field data-name="data" data-type="BIO*" data-required="false" data-desc="原始資料 BIO，對於需要重新讀取原始資料的無雜湊簽章機制是必需的 (用於 CMS_dataFinal_ex)。"></x-field>
</x-field-group>

#### 回傳值

成功時回傳 `1`，失敗時回傳 `0`。

## 總結

本節涵蓋了建立和處理 CMS 訊息的主要進入點。若要對訊息元件進行更詳細的控制，請參考 [SignerInfo 函式](./api-signerinfo.md) 和 [RecipientInfo 函式](./api-recipientinfo.md) 章節中的函式。 [簽署與驗證](./guides-signing-verifying.md) 和 [加密與解密](./guides-encrypting-decrypting.md) 的操作指南提供了使用這些函式的實用範例。