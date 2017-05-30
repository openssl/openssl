/*
 * Copyright 2009-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include "../ppc_arch.h"

#ifdef OPENSSL_NO_CHACHA
NON_EMPTY_TRANSLATION_UNIT
#else
void ChaCha20_ctr32_int(unsigned char *out, const unsigned char *inp,
                        size_t len, const unsigned int key[8],
                        const unsigned int counter[4]);
void ChaCha20_ctr32_vmx(unsigned char *out, const unsigned char *inp,
                        size_t len, const unsigned int key[8],
                        const unsigned int counter[4]);
void ChaCha20_ctr32(unsigned char *out, const unsigned char *inp,
                    size_t len, const unsigned int key[8],
                    const unsigned int counter[4])
{
    OPENSSL_ppccap_P & PPC_ALTIVEC
        ? ChaCha20_ctr32_vmx(out, inp, len, key, counter)
        : ChaCha20_ctr32_int(out, inp, len, key, counter);
}
#endif
