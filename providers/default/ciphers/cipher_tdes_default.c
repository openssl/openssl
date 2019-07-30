/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cipher_tdes_default.h"

IMPLEMENT_tdes_cipher(ede3, EDE3,  ofb, OFB, TDES_FLAGS, 64*3,  8, 64, stream);
IMPLEMENT_tdes_cipher(ede3, EDE3,  cfb, CFB, TDES_FLAGS, 64*3,  8, 64, stream);
IMPLEMENT_tdes_cipher(ede3, EDE3, cfb1, CFB, TDES_FLAGS, 64*3,  8, 64, stream);
IMPLEMENT_tdes_cipher(ede3, EDE3, cfb8, CFB, TDES_FLAGS, 64*3,  8, 64, stream);

IMPLEMENT_tdes_cipher(ede2, EDE2, ecb, ECB, TDES_FLAGS, 64*2, 64, 64, block);
IMPLEMENT_tdes_cipher(ede2, EDE2, cbc, CBC, TDES_FLAGS, 64*2, 64, 64, block);
IMPLEMENT_tdes_cipher(ede2, EDE2, ofb, OFB, TDES_FLAGS, 64*2,  8, 64, stream);
IMPLEMENT_tdes_cipher(ede2, EDE2, cfb, CFB, TDES_FLAGS, 64*2,  8, 64, stream);

