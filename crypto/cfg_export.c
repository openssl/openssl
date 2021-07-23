#if !defined(_WIN64) && defined(_WIN32)
#ifndef OPENSSL_NO_BF
#include <openssl/blowfish.h>
#endif

#ifndef OPENSSL_NO_CAMELLIA
# include <openssl/camellia.h>
#endif

#ifndef OPENSSL_NO_DES
# include <openssl/des.h>
#endif

#ifndef OPENSSL_NO_RC4
# include <openssl/rc4.h>
#endif

#include <openssl/crypto.h>
#include <openssl/evp.h>

void poly1305_blocks_sse2();
void poly1305_emit_sse2();
void poly1305_init();
void poly1305_blocks();
void poly1305_emit();
void poly1305_blocks_avx2();

void cfg_export(void *fp[64]) {

size_t idx = 0;

#ifndef OPENSSL_NO_BF
    fp[idx++] = (void*)(uintptr_t)BF_encrypt;
    fp[idx++] = (void*)(uintptr_t)BF_decrypt;
    fp[idx++] = (void*)(uintptr_t)BF_cbc_encrypt;
#endif

#ifndef OPENSSL_NO_CAMELLIA
    fp[idx++] = (void*)(uintptr_t)Camellia_set_key;
#endif

#ifndef OPENSSL_NO_DES
    fp[idx++] = (void*)(uintptr_t)DES_encrypt1;
    fp[idx++] = (void*)(uintptr_t)DES_encrypt2;
    fp[idx++] = (void*)(uintptr_t)DES_encrypt3;
    fp[idx++] = (void*)(uintptr_t)DES_decrypt3;
    fp[idx++] = (void*)(uintptr_t)DES_ncbc_encrypt;
    fp[idx++] = (void*)(uintptr_t)DES_ede3_cbc_encrypt;

    fp[idx++] = (void*)(uintptr_t)EVP_des_ede3_cfb64;
    fp[idx++] = (void*)(uintptr_t)EVP_CIPHER_CTX_iv_noconst;
#endif

#ifndef OPENSSL_NO_RC4
    fp[idx++] = (void*)(uintptr_t)RC4;
    fp[idx++] = (void*)(uintptr_t)RC4_set_key;
    fp[idx++] = (void*)(uintptr_t)RC4_options;
#endif

    fp[idx++] = (void*)(uintptr_t)OPENSSL_cleanse;
    fp[idx++] = (void*)(uintptr_t)CRYPTO_memcmp;

    fp[idx++] = (void*)(uintptr_t)poly1305_init;
    fp[idx++] = (void*)(uintptr_t)poly1305_blocks;
    fp[idx++] = (void*)(uintptr_t)poly1305_emit;
    fp[idx++] = (void*)(uintptr_t)poly1305_blocks_avx2;

    fp[idx++] = (void*)(uintptr_t)poly1305_blocks_sse2;
    fp[idx++] = (void*)(uintptr_t)poly1305_emit_sse2;
}
#endif
