/* crypto/ecdsa/ecs_locl.h */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "ecdsa.h"

#ifndef HEADER_ECS_LOCL_H
#define HEADER_ECS_LOCL_H

#ifdef __cplusplus
extern "C" {
#endif

#define OPENSSL_ECDSA_ABORT(r) { reason = (r); goto err; }

/* some structures needed for the asn1 encoding */
typedef struct x9_62_fieldid_st {
        ASN1_OBJECT *fieldType;
        ASN1_TYPE   *parameters;
        } X9_62_FIELDID;

typedef struct x9_62_curve_st {
        ASN1_OCTET_STRING *a;
        ASN1_OCTET_STRING *b;
        ASN1_BIT_STRING   *seed;
        } X9_62_CURVE;

typedef struct x9_62_ec_parameters {
        ASN1_INTEGER      *version;
        X9_62_FIELDID     *fieldID;
        X9_62_CURVE       *curve;
        ASN1_OCTET_STRING *base;
        ASN1_INTEGER      *order;
        ASN1_INTEGER      *cofactor;
        } X9_62_EC_PARAMETERS;

typedef struct ec_parameters {
	int	type;
	union {
		ASN1_OBJECT 	    *named_curve;
		X9_62_EC_PARAMETERS *parameters;
		ASN1_NULL	    *implicitlyCA;
	} value;
	} EC_PARAMETERS;

typedef struct ecdsa_priv_key_st {
        int               version;
        EC_PARAMETERS	  *parameters;
	ASN1_OBJECT	  *named_curve;
        ASN1_OCTET_STRING *pub_key;
        BIGNUM            *priv_key;
        } ECDSAPrivateKey;


X9_62_FIELDID *ECDSA_get_X9_62_FIELDID(const ECDSA *ecdsa, X9_62_FIELDID *field);
X9_62_CURVE   *ECDSA_get_X9_62_CURVE(const ECDSA *ecdsa, X9_62_CURVE *curve);
X9_62_EC_PARAMETERS *ECDSA_get_X9_62_EC_PARAMETERS(const ECDSA *ecdsa, X9_62_EC_PARAMETERS *params);
EC_PARAMETERS *ECDSA_get_EC_PARAMETERS(const ECDSA *ecdsa, EC_PARAMETERS *params);

ECDSA	*ECDSA_x9_62parameters2ecdsa(const X9_62_EC_PARAMETERS *params, ECDSA *ecdsa);
ECDSA	*ECDSA_ecparameters2ecdsa(const EC_PARAMETERS *params, ECDSA *ecdsa);

#ifdef  __cplusplus
}
#endif
#endif
