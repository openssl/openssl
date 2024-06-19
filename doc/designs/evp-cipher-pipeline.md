EVP APIs for supporting cipher pipelining in provided ciphers
=============================================================

OpenSSL previously supported "pipeline" ciphers via ENGINE implementations. That support was lost when we moved to providers. This document discusses API design to restore that capability and enable providers to implement such ciphers.

Pipeline operation
-------------------

Certain ciphers, such as AES-GCM, can be optimized by computing blocks in parallel. Cipher pipelining support allows application to submit multiple chunks of data in one cipher update call, thereby allowing the provided implementation to take advantage of parallel computing. This is very beneficial for hardware accelerators as pipeline amortizes the latency over multiple chunks. Our libssl makes use of pipeline as discussed in [here](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_max_pipelines.html).

Pipelining with ENGINE
-----------------------

Before discussing API design for providers, let's take a look at existing pipeline API that works with engines.

**EVP Interface:**
flag to denote pipeline support
```
cipher->flags & EVP_CIPH_FLAG_PIPELINE
```

Input/output and aad buffers are set using `EVP_CIPHER_CTX_ctrl()`
```
EVP_CIPHER_CTX_ctrl() 
    - EVP_CTRL_AEAD_TLS1_AAD (loop: one aad at a time)
    - EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS (array of buffer pointers)
    - EVP_CTRL_SET_PIPELINE_INPUT_BUFS (array of buffer pointers)
    - EVP_CTRL_SET_PIPELINE_INPUT_LENS
```

Single-call cipher invoked to perform encryption/decryption. 
```
EVP_Cipher()
```


Proposal for EVP pipeline APIs
-------------------------------------

Current API design is made similar to non-pipeline counterpart. The below proposal will be updated as per decisions made in next section (Design decisions).

**EVP Interface:**
API to check for pipeline support in provided cipher.
```c
/**
 * @brief checks if the provider has exported required pipeline functions
 * @return 0 (pipeline not supported) or 1 (pipeline supported)
 */
int EVP_CIPHER_can_pipeline(const EVP_CIPHER *cipher)
```

Multi-call APIs for init, update and final. Associated data for AEAD ciphers are set in `EVP_CipherPipelineUpdate`.
```c
/**
 * @param iv    array of pointers (array length must be numpipes)
 */
EVP_CipherPipelineInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key, size_t numpipes, const unsigned char **iv, int enc);

/**
 * @param out   array of pointers to output buffers (array length must be numpipes)
 *              when NULL, input buffers are treated as AAD data
 * @param outl  array of size_t (array length must be numpipes)
 * @param in    array of pointers to input buffers (array length must be numpipes)
 * @param inl   array of size_t (array length must be numpipes)
 */
EVP_CipherPipelineUpdate(EVP_CIPHER_CTX *ctx, unsigned char **out, size_t *outl, const unsigned char **in, size_t *inl);

/**
 * @param outm  array of pointers to output buffers (array length must be numpipes)
 * @param outl  array of size_t (array length must be numpipes)
 */
EVP_CipherPipelineFinal(EVP_CIPHER_CTX *ctx, unsigned char **outm, size_t *outl);
```

API to get/set AEAD auth tag.
```c
/**
 * @param buf   array of pointers to in/out buffers (array length must be numpipes)
 * @param bsize aead tag length
 */
OSSL_CIPHER_PARAM_PIPELINE_AEAD_TAG (type OSSL_PARAM_OCTET_PTR)
```

**Design Decisions:**
1. Denoting pipeline support
    - [ ] a. A cipher flag `EVP_CIPH_FLAG_PROVIDED_PIPELINE` (this has to be different than EVP_CIPH_FLAG_PIPELINE, so that it doesn't break legacy applications).
    - [x] b. A function `EVP_CIPHER_can_pipeline()` that checks if the provider exports pipeline functions.
    > **Justification:** flags variable is deprecated in EVP_CIPHER struct. Moreover, EVP can check for presence of pipeline functions, rather than requiring providers to set a flag.

2. `numpipes` argument
    - [x] a. `numpipes` received only in `EVP_CipherPipelineInit()` and saved in EVP_CIPHER_CTX for further use.
    - [ ] b. `numpipes` value is repeatedly received in each `EVP_CipherPipelineInit()`, `EVP_CipherPipelineUpdate()` and `EVP_CipherPipelineFinal()` call.
    > **Justification:** It is expected for numpipes to be same across init, update and final operation.

3. Input/Output buffers
    - [ ] a. A set of buffers is represented by an array of buffer pointers and an array of lengths. Example: `unsigned char **out, size_t *outl`.
    - [ ] b. iovec style: A new type that holds one buffer pointer along with its size.
    ```c
    struct {
        unsigned char *buf;
        size_t buf_len;
    } iovec_buf;
    EVP_CipherPipelineUpdate(EVP_CIPHER_CTX *ctx, struct iovec_buf in, struct iovec_buf *out);
    ```
    > **Justification:** 

4. AEAD tag
    - [x] a. A new OSSL_CIPHER_PARAM of type OSSL_PARAM_OCTET_PTR, `OSSL_CIPHER_PARAM_PIPELINE_AEAD_TAG`, that uses an array of buffer pointers. This can be used with `iovec_buf` if we decide with 3.b.
    - [ ] b. Reuse `OSSL_CIPHER_PARAM_AEAD_TAG` by using it in a loop, processing one tag at a time.
    > **Justification:** Reduces cipher get/set param operations.

**Usage Examples:**
```c
/*
 * WARNING: This example aims to demonstrate only API usage. 
 * It leaves out multiple necessary steps required for secure AES-GCM use.
 * TODO: add error handling
 */
#define PIPE_COUNT  8
#define AAD_LEN     16
#define TAG_LEN     16
#define IV_LEN      12
void do_cipher() {
    unsigned char key[128 / 8];
    unsigned char ct[PIPE_COUNT][64], pt[PIPE_COUNT][64], iv_data[8][IV_LEN];
    unsigned char add_data[PIPE_COUNT][AAD_LEN], tag[PIPE_COUNT][TAG_LEN];
    unsigned char *out[PIPE_COUNT], *in[PIPE_COUNT], *iv[PIPE_COUNT], *aad[PIPE_COUNT];
    size_t outl[PIPE_COUNT], inl[PIPE_COUNT], aadl[PIPE_COUNT];

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = EVP_aes_128_gcm();
    if (!EVP_CIPHER_can_pipeline(cipher)) {
        printf("Not supported\n");
        return;
    }
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherPipelineInit(ctx, cipher, key, PIPE_COUNT, NULL, 1);

    for (int i = 0; i < PIPE_COUNT; i++) {
        iv[i] = iv_data[i];
        in[i] = pt[i];
        inl[i] = 64;
        aad[i] = add_data[i];
        aadl[i] = AAD_LEN;
        out[i] = ct[i];
        outl[i] = 0;
    }

    /* set IV */
    assert(EVP_CIPHER_CTX_get_iv_length(ctx) == IV_LEN);
    EVP_CipherPipelineInit(ctx, cipher, NULL, PIPE_COUNT, iv, 1);

    /* set AAD */
    EVP_CipherPipelineUpdate(ctx, NULL, NULL, aad, aadl);

    EVP_CipherPipelineUpdate(ctx, out, outl, in, inl);

    for (int i = 0; i < PIPE_COUNT; i++) {
        out[i] += outl[i];
        outl[i] = 0;
        in[i] = tag[i];
    }

    EVP_CipherPipelineFinal(ctx, out, outl);

    /* get auth tag */
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    params[0] = OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_PIPELINE_AEAD_TAG, in, TAG_LEN);
    evp_do_ciph_ctx_getparams(ctx->cipher, ctx->algctx, params);
}
```

Q&A
----
1. It would be nice to have a mechanism for fetching provider with pipeline support over other providers that don't support pipeline. How can we achieve this?