# Compression

This guide provides a step-by-step procedure for using the `CompressedData` content type to reduce message size. You will learn how to compress content before transmission and uncompress it upon receipt using the OpenSSL CMS API.

The `CompressedData` content type offers a standardized way to compress message content within the CMS framework. This is particularly useful for reducing bandwidth and storage requirements when transmitting large messages. The current implementation in OpenSSL relies on the zlib compression library.

## Prerequisites

For the compression and uncompression functionalities to be available, OpenSSL must be compiled with zlib support. If zlib support is not included, the functions described in this guide will return an error.

:::warning
The only compression algorithm supported at present is zlib, identified by the NID `NID_zlib_compression`. Attempting to use other algorithms will result in an error.
:::

## Compressing Data

The primary function for creating a `CompressedData` structure is `CMS_compress()`. This function takes input data from a BIO, compresses it using the specified algorithm (zlib), and encapsulates it within a `CMS_ContentInfo` structure.

The workflow involves these steps:
1.  Initialize necessary libraries.
2.  Open the input data source (`BIO`).
3.  Call `CMS_compress()` to create the CMS structure in memory.
4.  Open the output destination (`BIO`).
5.  Write the `CMS_ContentInfo` structure to the output BIO, typically using `SMIME_write_CMS()`.

### Example: Compressing a File

The following example demonstrates how to read content from a file named `comp.txt`, compress it, and write the resulting CMS structure to `smcomp.txt`.

```c cms_comp.c
/* Simple S/MIME compress example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    /*
     * On OpenSSL 1.0.0+ only:
     * for streaming set CMS_STREAM
     */
    int flags = CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Open content being compressed */
    in = BIO_new_file("comp.txt", "r");
    if (!in)
        goto err;

    /* Compress content */
    cms = CMS_compress(in, NID_zlib_compression, flags);
    if (!cms)
        goto err;

    /* Open file to write compressed data to */
    out = BIO_new_file("smcomp.txt", "w");
    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;

    ret = EXIT_SUCCESS;

 err:
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Error Compressing Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    BIO_free(in);
    BIO_free(out);
    return ret;
}
```

In this example, `CMS_compress()` is called with the `CMS_STREAM` flag. This flag is recommended for stream-based processing, where the data is not held entirely in memory. When using `CMS_STREAM`, the `CMS_ContentInfo` structure must be finalized by a function that supports streaming, such as `SMIME_write_CMS()` or `i2d_CMS_bio_stream()`.

## Uncompressing Data

To uncompress a `CompressedData` structure, you use the `CMS_uncompress()` function. This function extracts the compressed content from the `CMS_ContentInfo` structure, uncompresses it, and writes the original data to an output BIO.

The uncompression workflow is as follows:
1.  Initialize necessary libraries.
2.  Open the `CMS_ContentInfo` data source (`BIO`).
3.  Read the CMS structure into memory using `SMIME_read_CMS()`.
4.  Open the final output destination (`BIO`).
5.  Call `CMS_uncompress()` to extract and uncompress the content.

### Example: Uncompressing a File

This example reads a compressed CMS message from `smcomp.txt`, uncompresses its content, and writes the original data to `smuncomp.txt`.

```c cms_uncomp.c
/* Simple S/MIME uncompression example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Open compressed content */
    in = BIO_new_file("smcomp.txt", "r");
    if (!in)
        goto err;

    /* Read S/MIME message */
    cms = SMIME_read_CMS(in, NULL);
    if (!cms)
        goto err;

    /* Open file to write uncompressed data to */
    out = BIO_new_file("smuncomp.txt", "w");
    if (!out)
        goto err;

    /* Uncompress S/MIME message */
    if (!CMS_uncompress(cms, out, NULL, 0))
        goto err;

    ret = EXIT_SUCCESS;

 err:
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Error Uncompressing Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    BIO_free(in);
    BIO_free(out);
    return ret;
}
```

The third argument to `CMS_uncompress()` is a BIO for detached content (`dcont`). This is rarely used and should typically be set to `NULL`.

## API Reference

This section provides a summary of the core functions for CMS compression and uncompression.

### `CMS_compress`

Creates a `CMS_ContentInfo` structure of type `CompressedData`.

```c
CMS_ContentInfo *CMS_compress(BIO *in, int comp_nid, unsigned int flags);
```

| Parameter  | Type              | Description                                                                                             |
| :--------- | :---------------- | :------------------------------------------------------------------------------------------------------ |
| `in`       | `BIO *`           | A BIO containing the data to be compressed.                                                             |
| `comp_nid` | `int`             | The NID of the compression algorithm. Must be `NID_zlib_compression`. Use `NID_undef` for the default.  |
| `flags`    | `unsigned int`    | A bitfield of flags to modify the operation. Common flags include `CMS_STREAM`, `CMS_BINARY`, `CMS_TEXT`. |

**Return Value**

Returns a pointer to a `CMS_ContentInfo` structure on success, or `NULL` on failure. Errors can be retrieved from the OpenSSL error queue.

### `CMS_uncompress`

Extracts and uncompresses content from a `CompressedData` structure.

```c
int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out, unsigned int flags);
```

| Parameter | Type                | Description                                                                                                    |
| :-------- | :------------------ | :------------------------------------------------------------------------------------------------------------- |
| `cms`     | `CMS_ContentInfo *` | The parsed `CompressedData` structure.                                                                         |
| `dcont`   | `BIO *`             | A BIO containing the detached content, if applicable. Normally set to `NULL`.                                  |
| `out`     | `BIO *`             | The BIO where the uncompressed content will be written.                                                        |
| `flags`   | `unsigned int`      | An optional set of flags. The `CMS_TEXT` flag can be used to handle MIME headers for `text/plain` content type. |

**Return Value**

Returns `1` for success and `0` for failure.

## Summary

The OpenSSL CMS `CompressedData` type provides a simple mechanism for reducing message size. The process is managed by two primary functions: `CMS_compress()` for creating the compressed message and `CMS_uncompress()` for restoring the original content. Successful operation depends on the availability of the zlib library during the OpenSSL build process.

For further reading on related CMS operations, refer to the following guides:
<x-cards data-columns="2">
  <x-card data-title="Signing and Verifying" data-href="/guides/signing-verifying" data-icon="lucide:pen-square">
    Learn how to create and validate digital signatures.
  </x-card>
  <x-card data-title="Encryption & Decryption" data-href="/guides/encrypting-decrypting" data-icon="lucide:lock">
    Understand how to encrypt and decrypt CMS messages.
  </x-card>
</x-cards>