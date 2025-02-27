#include "prov/ciphercommon.h"

#define ossl_prov_cipher_hw_aes_cfb ossl_prov_cipher_hw_aes_cfb128

const PROV_CIPHER_HW *ossl_prov_cipher_hw_aes_cfb128(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_aes_cfb1(size_t keybits);
const PROV_CIPHER_HW *ossl_prov_cipher_hw_aes_cfb8(size_t keybits);
