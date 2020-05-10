/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_NO_CMS

/* internal CMS-ESS related stuff */

int cms_add1_signing_cert(CMS_SignerInfo *si, ESS_SIGNING_CERT *sc);
int cms_add1_signing_cert_v2(CMS_SignerInfo *si, ESS_SIGNING_CERT_V2 *sc);

int cms_signerinfo_get_signing_cert_v2(CMS_SignerInfo *si,
                                       ESS_SIGNING_CERT_V2 **psc);
int cms_signerinfo_get_signing_cert(CMS_SignerInfo *si,
                                    ESS_SIGNING_CERT **psc);
#endif
