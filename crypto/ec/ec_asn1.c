/* crypto/ec/ec_asn1.c */
/* ====================================================================
 * Copyright (c) 2000-2002 The OpenSSL Project.  All rights reserved.
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

#include <string.h>
#include "ec_lcl.h"
#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <string.h>

/* some structures needed for the asn1 encoding */
typedef struct x9_62_fieldid_st {
        ASN1_OBJECT *fieldType;
        ASN1_TYPE   *parameters;
        } X9_62_FIELDID;

typedef struct x9_62_characteristic_two_st {
	ASN1_INTEGER *m;
	ASN1_OBJECT  *basis;
	ASN1_TYPE    *parameters;
	} X9_62_CHARACTERISTIC_TWO;

typedef struct x9_62_pentanomial_st {
	ASN1_INTEGER k1;
	ASN1_INTEGER k2;
	ASN1_INTEGER k3;
	} X9_62_PENTANOMIAL;

typedef struct x9_62_curve_st {
        ASN1_OCTET_STRING *a;
        ASN1_OCTET_STRING *b;
        ASN1_BIT_STRING   *seed;
        } X9_62_CURVE;

typedef struct ec_parameters_st {
        ASN1_INTEGER      *version;
        X9_62_FIELDID     *fieldID;
        X9_62_CURVE       *curve;
        ASN1_OCTET_STRING *base;
        ASN1_INTEGER      *order;
        ASN1_INTEGER      *cofactor;
        } ECPARAMETERS;

struct ecpk_parameters_st {
	int	type;
	union {
		ASN1_OBJECT  *named_curve;
		ECPARAMETERS *parameters;
		ASN1_NULL    *implicitlyCA;
	} value;
	}/* ECPKPARAMETERS */;

/* SEC1 ECPrivateKey */
typedef struct ec_privatekey_st {
	int               version;
	ASN1_OCTET_STRING *privateKey;
        ECPKPARAMETERS    *parameters;
	ASN1_BIT_STRING   *publicKey;
	} EC_PRIVATEKEY;

/* the OpenSSL asn1 definitions */

ASN1_SEQUENCE(X9_62_FIELDID) = {
	ASN1_SIMPLE(X9_62_FIELDID, fieldType, ASN1_OBJECT),
	ASN1_SIMPLE(X9_62_FIELDID, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(X9_62_FIELDID)

DECLARE_ASN1_FUNCTIONS_const(X9_62_FIELDID)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(X9_62_FIELDID, X9_62_FIELDID)
IMPLEMENT_ASN1_FUNCTIONS_const(X9_62_FIELDID)

ASN1_SEQUENCE(X9_62_CHARACTERISTIC_TWO) = {
	ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, m, ASN1_INTEGER),
	ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, basis, ASN1_OBJECT),
	ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(X9_62_CHARACTERISTIC_TWO)

DECLARE_ASN1_FUNCTIONS_const(X9_62_CHARACTERISTIC_TWO)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(X9_62_CHARACTERISTIC_TWO, X9_62_CHARACTERISTIC_TWO)
IMPLEMENT_ASN1_FUNCTIONS_const(X9_62_CHARACTERISTIC_TWO)

ASN1_SEQUENCE(X9_62_PENTANOMIAL) = {
	ASN1_SIMPLE(X9_62_PENTANOMIAL, k1, ASN1_INTEGER),
	ASN1_SIMPLE(X9_62_PENTANOMIAL, k2, ASN1_INTEGER),
	ASN1_SIMPLE(X9_62_PENTANOMIAL, k3, ASN1_INTEGER)
} ASN1_SEQUENCE_END(X9_62_PENTANOMIAL)

DECLARE_ASN1_FUNCTIONS_const(X9_62_PENTANOMIAL)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(X9_62_PENTANOMIAL, X9_62_PENTANOMIAL)
IMPLEMENT_ASN1_FUNCTIONS_const(X9_62_PENTANOMIAL)

ASN1_SEQUENCE(X9_62_CURVE) = {
	ASN1_SIMPLE(X9_62_CURVE, a, ASN1_OCTET_STRING),
	ASN1_SIMPLE(X9_62_CURVE, b, ASN1_OCTET_STRING),
	ASN1_OPT(X9_62_CURVE, seed, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(X9_62_CURVE)

DECLARE_ASN1_FUNCTIONS_const(X9_62_CURVE)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(X9_62_CURVE, X9_62_CURVE)
IMPLEMENT_ASN1_FUNCTIONS_const(X9_62_CURVE)

ASN1_SEQUENCE(ECPARAMETERS) = {
	ASN1_SIMPLE(ECPARAMETERS, version, ASN1_INTEGER),
	ASN1_SIMPLE(ECPARAMETERS, fieldID, X9_62_FIELDID),
	ASN1_SIMPLE(ECPARAMETERS, curve, X9_62_CURVE),
	ASN1_SIMPLE(ECPARAMETERS, base, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ECPARAMETERS, order, ASN1_INTEGER),
	ASN1_SIMPLE(ECPARAMETERS, cofactor, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ECPARAMETERS)

DECLARE_ASN1_FUNCTIONS_const(ECPARAMETERS)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(ECPARAMETERS, ECPARAMETERS)
IMPLEMENT_ASN1_FUNCTIONS_const(ECPARAMETERS)

ASN1_CHOICE(ECPKPARAMETERS) = {
	ASN1_SIMPLE(ECPKPARAMETERS, value.named_curve, ASN1_OBJECT),
	ASN1_SIMPLE(ECPKPARAMETERS, value.parameters, ECPARAMETERS),
	ASN1_SIMPLE(ECPKPARAMETERS, value.implicitlyCA, ASN1_NULL)
} ASN1_CHOICE_END(ECPKPARAMETERS)

DECLARE_ASN1_FUNCTIONS_const(ECPKPARAMETERS)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(ECPKPARAMETERS, ECPKPARAMETERS)
IMPLEMENT_ASN1_FUNCTIONS_const(ECPKPARAMETERS)

ASN1_SEQUENCE(EC_PRIVATEKEY) = {
	ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
	ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
	ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
	ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
} ASN1_SEQUENCE_END(EC_PRIVATEKEY)

DECLARE_ASN1_FUNCTIONS_const(EC_PRIVATEKEY)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(EC_PRIVATEKEY, EC_PRIVATEKEY)
IMPLEMENT_ASN1_FUNCTIONS_const(EC_PRIVATEKEY)

/* some internal functions */

static X9_62_FIELDID *ec_asn1_group2field(const EC_GROUP *, X9_62_FIELDID *);
static X9_62_CURVE *ec_asn1_group2curve(const EC_GROUP *, X9_62_CURVE *);
static EC_GROUP *ec_asn1_parameters2group(const ECPARAMETERS *); 
static ECPARAMETERS *ec_asn1_group2parameters(const EC_GROUP *, 
                                              ECPARAMETERS *);
EC_GROUP *EC_ASN1_pkparameters2group(const ECPKPARAMETERS *); 
ECPKPARAMETERS *EC_ASN1_group2pkparameters(const EC_GROUP *, ECPKPARAMETERS *);

static X9_62_FIELDID *ec_asn1_group2field(const EC_GROUP *group, 
                                          X9_62_FIELDID *field)
	{
	int           ok=0, nid;
	X9_62_FIELDID *ret=NULL;
	BIGNUM        *tmp=NULL;
	
	if (field == NULL)
		{
		if ((ret = X9_62_FIELDID_new()) == NULL)
			{
			ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
			return NULL;
			}
		}
	else
		{	
		ret = field;
		if (ret->fieldType != NULL)
			ASN1_OBJECT_free(ret->fieldType);
		if (ret->parameters != NULL)
			ASN1_TYPE_free(ret->parameters);
		}

	nid = EC_METHOD_get_field_type(EC_GROUP_method_of(group));

	if ((ret->fieldType = OBJ_nid2obj(nid)) == NULL)
		{
		ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_OBJ_LIB);
		goto err;
		}

	if (nid == NID_X9_62_prime_field)
		{
		if ((tmp = BN_new()) == NULL) 
			{
			ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
			goto err;
			}
		if ((ret->parameters = ASN1_TYPE_new()) == NULL)
			{
			ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_MALLOC_FAILURE);
			goto err;
			}
		ret->parameters->type = V_ASN1_INTEGER;
		if (!EC_GROUP_get_curve_GFp(group, tmp, NULL, NULL, NULL))
			{
			ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_EC_LIB);
			goto err;
			}
		ret->parameters->value.integer = BN_to_ASN1_INTEGER(tmp, NULL);
		if (ret->parameters->value.integer == NULL)
			{
			ECerr(EC_F_EC_ASN1_GROUP2FIELDID, ERR_R_ASN1_LIB);
			goto err;
			}
		}
	else
		goto err;

	ok = 1;

err :	if (!ok)
	{
		if (ret && !field)
			X9_62_FIELDID_free(ret);
		ret = NULL;
	}
	if (tmp)
		BN_free(tmp);
	return(ret);
}

static X9_62_CURVE *ec_asn1_group2curve(const EC_GROUP *group, 
                                        X9_62_CURVE *curve)
	{
	int           ok=0, nid;
	X9_62_CURVE   *ret=NULL;
	BIGNUM        *tmp_1=NULL,
	              *tmp_2=NULL;
	unsigned char *buffer_1=NULL,
	              *buffer_2=NULL,
	              *a_buf=NULL,
	              *b_buf=NULL;
	size_t        len_1, len_2;
	unsigned char char_zero = 0;

	if ((tmp_1 = BN_new()) == NULL || (tmp_2 = BN_new()) == NULL)
		{
		ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (curve == NULL)
		{
		if ((ret = X9_62_CURVE_new()) == NULL)
			{
			ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_MALLOC_FAILURE);
			goto err;
			}
		}
	else
		{
		ret = curve;
		if (ret->a)
			ASN1_OCTET_STRING_free(ret->a);
		if (ret->b)
			ASN1_OCTET_STRING_free(ret->b);
		if (ret->seed)
			ASN1_BIT_STRING_free(ret->seed);
		}

	nid = EC_METHOD_get_field_type(EC_GROUP_method_of(group));

	/* get a and b */
	if (nid == NID_X9_62_prime_field)
		{
		if (!EC_GROUP_get_curve_GFp(group, NULL, tmp_1, tmp_2, NULL))
			{
			ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_EC_LIB);
			goto err;
			}

		len_1 = (size_t)BN_num_bytes(tmp_1);
		len_2 = (size_t)BN_num_bytes(tmp_2);

		if (len_1 == 0)
			{
			/* len_1 == 0 => a == 0 */
			a_buf = &char_zero;
			len_1 = 1;
			}
		else
			{
			if ((buffer_1 = OPENSSL_malloc(len_1)) == NULL)
				{
				ECerr(EC_F_EC_ASN1_GROUP2CURVE,
				      ERR_R_MALLOC_FAILURE);
				goto err;
				}
			if ( (len_1 = BN_bn2bin(tmp_1, buffer_1)) == 0)
				{
				ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_BN_LIB);
				goto err;
				}
			a_buf = buffer_1;
			}

		if (len_2 == 0)
			{
			/* len_2 == 0 => b == 0 */
			b_buf = &char_zero;
			len_2 = 1;
			}
		else
			{
			if ((buffer_2 = OPENSSL_malloc(len_2)) == NULL)
				{
				ECerr(EC_F_EC_ASN1_GROUP2CURVE,
				      ERR_R_MALLOC_FAILURE);
				goto err;
				}
			if ( (len_2 = BN_bn2bin(tmp_2, buffer_2)) == 0)
				{
				ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_BN_LIB);
				goto err;
				}
			b_buf = buffer_2;
			}
		}
	else
		goto err;

	/* set a and b */
	if ((ret->a = M_ASN1_OCTET_STRING_new()) == NULL || 
	    (ret->b = M_ASN1_OCTET_STRING_new()) == NULL )
		{
		ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (!M_ASN1_OCTET_STRING_set(ret->a, a_buf, len_1) ||
	    !M_ASN1_OCTET_STRING_set(ret->b, b_buf, len_2))
		{
		ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_ASN1_LIB);
		goto err;
		}
	
	/* set the seed (optional) */
	if (group->seed)
		{	
		if ((ret->seed = ASN1_BIT_STRING_new()) == NULL) goto err;
		if (!ASN1_BIT_STRING_set(ret->seed, group->seed, 
		                         (int)group->seed_len))
			{
			ECerr(EC_F_EC_ASN1_GROUP2CURVE, ERR_R_ASN1_LIB);
			goto err;
			}
		}
	else
		ret->seed = NULL;

	ok = 1;

err :	if (!ok)
	{
		if (ret && !curve)
			X9_62_CURVE_free(ret);
		ret = NULL;
	}
	if (buffer_1)
		OPENSSL_free(buffer_1);
	if (buffer_2)
		OPENSSL_free(buffer_2);
	if (tmp_1)
		BN_free(tmp_1);
	if (tmp_2)
		BN_free(tmp_2);
	return(ret);
}

static ECPARAMETERS *ec_asn1_group2parameters(const EC_GROUP *group,
                                              ECPARAMETERS *param)
	{
	int	ok=0;
	size_t  len=0;
	ECPARAMETERS   *ret=NULL;
	BIGNUM	       *tmp=NULL;
	unsigned char  *buffer=NULL;
	const EC_POINT *point=NULL;
	point_conversion_form_t form;

	if ((tmp = BN_new()) == NULL)
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (param == NULL)
	{
		if ((ret = ECPARAMETERS_new()) == NULL)
			{
			ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, 
			      ERR_R_MALLOC_FAILURE);
			goto err;
			}
	}
	else
		ret = param;

	/* set the version (always one) */
	if (ret->version == NULL && !(ret->version = ASN1_INTEGER_new()))
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (!ASN1_INTEGER_set(ret->version, (long)0x1))
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_ASN1_LIB);
		goto err;
		}

	/* set the fieldID */
	ret->fieldID = ec_asn1_group2field(group, ret->fieldID);
	if (ret->fieldID == NULL)
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
		goto err;
		}

	/* set the curve */
	ret->curve = ec_asn1_group2curve(group, ret->curve);
	if (ret->curve == NULL)
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
		goto err;
		}

	/* set the base point */
	if ((point = EC_GROUP_get0_generator(group)) == NULL)
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, EC_R_UNDEFINED_GENERATOR);
		goto err;
		}

	form = EC_GROUP_get_point_conversion_form(group);

	len = EC_POINT_point2oct(group, point, form, NULL, len, NULL);
	if (len == 0)
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
		goto err;
		}
	if ((buffer = OPENSSL_malloc(len)) == NULL)
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (!EC_POINT_point2oct(group, point, form, buffer, len, NULL))
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
		goto err;
		}
	if (ret->base == NULL && (ret->base = ASN1_OCTET_STRING_new()) == NULL)
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (!ASN1_OCTET_STRING_set(ret->base, buffer, len))
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_ASN1_LIB);
		goto err;
		}

	/* set the order */
	if (!EC_GROUP_get_order(group, tmp, NULL))
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
		goto err;
		}
	ret->order = BN_to_ASN1_INTEGER(tmp, ret->order);
	if (ret->order == NULL)
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_ASN1_LIB);
		goto err;
		}

	/* set the cofactor */
	if (!EC_GROUP_get_cofactor(group, tmp, NULL))
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_EC_LIB);
		goto err;
		}
	ret->cofactor = BN_to_ASN1_INTEGER(tmp, ret->cofactor);
	if (ret->cofactor == NULL)
		{
		ECerr(EC_F_EC_ASN1_GROUP2PARAMETERS, ERR_R_ASN1_LIB);
		goto err;
		}

	ok = 1;

err :	if(!ok)
		{
		if (ret && !param)
			ECPARAMETERS_free(ret);
		ret = NULL;
		}
	if (tmp)
		BN_free(tmp);
	if (buffer)
		OPENSSL_free(buffer);
	return(ret);
	}

ECPKPARAMETERS *EC_ASN1_group2pkparameters(const EC_GROUP *group, 
                                           ECPKPARAMETERS *params)
	{
	int            ok = 1, tmp;
	ECPKPARAMETERS *ret = params;

	if (ret == NULL)
		{
		if ((ret = ECPKPARAMETERS_new()) == NULL)
			{
			ECerr(EC_F_EC_ASN1_GROUP2PKPARAMETERS, 
			      ERR_R_MALLOC_FAILURE);
			return NULL;
			}
		}
	else
		{
		if (ret->type == 0 && ret->value.named_curve)
			ASN1_OBJECT_free(ret->value.named_curve);
		else if (ret->type == 1 && ret->value.parameters)
			ECPARAMETERS_free(ret->value.parameters);
		}

	if (EC_GROUP_get_asn1_flag(group))
		{
		/* use the asn1 OID to describe the
		 * the elliptic curve parameters
		 */
		tmp = EC_GROUP_get_nid(group);
		if (tmp)
			{
			ret->type = 0;
			if ((ret->value.named_curve = OBJ_nid2obj(tmp)) == NULL)
				ok = 0;
			}
		else
			{
			/* we have no nid => use the normal
			 * ECPARAMETERS structure 
			 */
			ret->type = 1;
			if ((ret->value.parameters = ec_asn1_group2parameters(
			     group, NULL)) == NULL)
				ok = 0;
			}
		}
	else
		{	
		/* use the ECPARAMETERS structure */
		ret->type = 1;
		if ((ret->value.parameters = ec_asn1_group2parameters(
		     group, NULL)) == NULL)
			ok = 0;
		}

	if (!ok)
		{
		ECPKPARAMETERS_free(ret);
		return NULL;
		}
	return ret;
	}

static EC_GROUP *ec_asn1_parameters2group(const ECPARAMETERS *params)
	{
	int	  ok=0, tmp;
	EC_GROUP  *ret=NULL;
	BIGNUM	  *p=NULL, *a=NULL, *b=NULL;
	EC_POINT  *point=NULL;

	if (!params->fieldID || !params->fieldID->fieldType || 
	    !params->fieldID->parameters)
		{
		ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
		goto err;
		}

	tmp = OBJ_obj2nid(params->fieldID->fieldType);

	if (tmp == NID_X9_62_characteristic_two_field)
		{
		ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_NOT_IMPLEMENTED);
		goto err;
		}
	else if (tmp == NID_X9_62_prime_field)
		{
		/* we have a curve over a prime field */
		/* extract the prime number */
		if (params->fieldID->parameters->type != V_ASN1_INTEGER ||
		    !params->fieldID->parameters->value.integer)
			{
			ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
			goto err;
			}
		p = ASN1_INTEGER_to_BN(params->fieldID->parameters->value.integer, NULL);
		if (p == NULL)
			{
			ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_ASN1_LIB);
			goto err;
			}
		/* now extract the curve parameters a and b */
		if (!params->curve || !params->curve->a || 
		    !params->curve->a->data || !params->curve->b ||
		    !params->curve->b->data)
			{
			ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
			goto err;
			}
		a = BN_bin2bn(params->curve->a->data, 
		              params->curve->a->length, NULL);
		if (a == NULL)
			{
			ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_BN_LIB);
			goto err;
			}
		b = BN_bin2bn(params->curve->b->data, params->curve->b->length, NULL);
		if (b == NULL)
			{
			ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_BN_LIB);
			goto err;
			}
		/* create the EC_GROUP structure */
/* TODO */
		ret = EC_GROUP_new_curve_GFp(p, a, b, NULL);
		if (ret == NULL)
			{
			ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_EC_LIB);
			goto err;
			}
		/* create the generator */
		if ((point = EC_POINT_new(ret)) == NULL) goto err;
		}
	else 
		{
		ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_UNKNOWN_FIELD);
		goto err;
		}

	if (params->curve->seed != NULL)
		{
		if (ret->seed != NULL)
			OPENSSL_free(ret->seed);
		if (!(ret->seed = OPENSSL_malloc(params->curve->seed->length)))
			{
			ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, 
			      ERR_R_MALLOC_FAILURE);
			goto err;
			}
		memcpy(ret->seed, params->curve->seed->data, 
		       params->curve->seed->length);
		ret->seed_len = params->curve->seed->length;
		}

	if (!params->order || !params->cofactor || !params->base ||
	    !params->base->data)
		{
		ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
		goto err;
		}


	a = ASN1_INTEGER_to_BN(params->order, a);
	b = ASN1_INTEGER_to_BN(params->cofactor, b);
	if (!a || !b)
		{
		ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_ASN1_LIB);
		goto err;
		}

	if (!EC_POINT_oct2point(ret, point, params->base->data, 
		                params->base->length, NULL))
		{
		ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_EC_LIB);
		goto err;
		}

	/* set the point conversion form */
	EC_GROUP_set_point_conversion_form(ret, (point_conversion_form_t)
				(params->base->data[0] & ~0x01));

	if (!EC_GROUP_set_generator(ret, point, a, b))
		{
		ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, ERR_R_EC_LIB);
		goto err;
		}

	ok = 1;

err:	if (!ok)
		{
		if (ret) 
			EC_GROUP_clear_free(ret);
		ret = NULL;
		}

	if (p)	
		BN_free(p);
	if (a)	
		BN_free(a);
	if (b)	
		BN_free(b);
	if (point)	
		EC_POINT_free(point);
	return(ret);
}

EC_GROUP *EC_ASN1_pkparameters2group(const ECPKPARAMETERS *params)
	{
	EC_GROUP *ret=NULL;
	int      tmp=0;

	if (params == NULL)
		{
		ECerr(EC_F_EC_ASN1_PKPARAMETERS2GROUP, 
		      EC_R_MISSING_PARAMETERS);
		return NULL;
		}

	if (params->type == 0)
		{ /* the curve is given by an OID */
		tmp = OBJ_obj2nid(params->value.named_curve);
		if ((ret = EC_GROUP_new_by_name(tmp)) == NULL)
			{
			ECerr(EC_F_EC_ASN1_PKPARAMETERS2GROUP, 
			      EC_R_EC_GROUP_NEW_BY_NAME_FAILURE);
			return NULL;
			}
		EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_NAMED_CURVE);
		}
	else if (params->type == 1)
		{ /* the parameters are given by a ECPARAMETERS
		   * structure */
		ret = ec_asn1_parameters2group(params->value.parameters);
		if (!ret)
			{
			ECerr(EC_F_EC_ASN1_PKPARAMETERS2GROUP, ERR_R_EC_LIB);
			return NULL;
			}
		EC_GROUP_set_asn1_flag(ret, 0x0);
		}
	else if (params->type == 2)
		{ /* implicitlyCA */
		return NULL;
		}
	else
	{
		ECerr(EC_F_EC_ASN1_PARAMETERS2GROUP, EC_R_ASN1_ERROR);
		return NULL;
	}

	return ret;
}

/* EC_GROUP <-> DER encoding of ECPKPARAMETERS */

EC_GROUP *d2i_ECPKParameters(EC_GROUP **a, const unsigned char **in, long len)
	{
	EC_GROUP	*group  = NULL;
	ECPKPARAMETERS	*params = NULL;

	if ((params = d2i_ECPKPARAMETERS(NULL, in, len)) == NULL)
		{
		ECerr(EC_F_D2I_ECPKPARAMETERS, EC_R_D2I_ECPKPARAMETERS_FAILURE);
		ECPKPARAMETERS_free(params);
		return NULL;
		}
	
	if ((group = EC_ASN1_pkparameters2group(params)) == NULL)
		{
		ECerr(EC_F_D2I_ECPKPARAMETERS, EC_R_PKPARAMETERS2GROUP_FAILURE);
		return NULL; 
		}

	
	if (a && *a)
		EC_GROUP_clear_free(*a);
	if (a)
		*a = group;

	ECPKPARAMETERS_free(params);
	return(group);
	}

int i2d_ECPKParameters(const EC_GROUP *a, unsigned char **out)
	{
	int		ret=0;
	ECPKPARAMETERS	*tmp = EC_ASN1_group2pkparameters(a, NULL);
	if (tmp == NULL)
		{
		ECerr(EC_F_I2D_ECPKPARAMETERS, EC_R_GROUP2PKPARAMETERS_FAILURE);
		return 0;
		}
	if ((ret = i2d_ECPKPARAMETERS(tmp, out)) == 0)
		{
		ECerr(EC_F_I2D_ECPKPARAMETERS, EC_R_I2D_ECPKPARAMETERS_FAILURE);
		ECPKPARAMETERS_free(tmp);
		return 0;
		}	
	ECPKPARAMETERS_free(tmp);
	return(ret);
	}

/* some EC_KEY functions */

EC_KEY *d2i_ECPrivateKey(EC_KEY **a, const unsigned char **in, long len)
	{
	int             ok=0;
	EC_KEY          *ret=NULL;
	EC_PRIVATEKEY   *priv_key=NULL;

	if ((priv_key = EC_PRIVATEKEY_new()) == NULL)
		{
		ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_MALLOC_FAILURE);
		return NULL;
		}

	if ((priv_key = d2i_EC_PRIVATEKEY(&priv_key, in, len)) == NULL)
		{
		ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
		EC_PRIVATEKEY_free(priv_key);
		return NULL;
		}

	if (a == NULL || *a == NULL)
		{
		if ((ret = EC_KEY_new()) == NULL)	
			{
			ECerr(EC_F_D2I_ECPRIVATEKEY,
                                 ERR_R_MALLOC_FAILURE);
			goto err;
			}
		if (a)
			*a = ret;
		}
	else
		ret = *a;

	if (priv_key->parameters)
		{
		if (ret->group)
			EC_GROUP_clear_free(ret->group);
		ret->group = EC_ASN1_pkparameters2group(priv_key->parameters);
		}

	if (ret->group == NULL)
		{
		ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
		goto err;
		}

	ret->version = priv_key->version;

	if (priv_key->privateKey)
		{
		ret->priv_key = BN_bin2bn(
			M_ASN1_STRING_data(priv_key->privateKey),
			M_ASN1_STRING_length(priv_key->privateKey),
			ret->priv_key);
		if (ret->priv_key == NULL)
			{
			ECerr(EC_F_D2I_ECPRIVATEKEY,
                              ERR_R_BN_LIB);
			goto err;
			}
		}
	else
		{
		ECerr(EC_F_D2I_ECPRIVATEKEY, 
                      EC_R_MISSING_PRIVATE_KEY);
		goto err;
		}

	if (priv_key->publicKey)
		{
		if (ret->pub_key)
			EC_POINT_clear_free(ret->pub_key);
		ret->pub_key = EC_POINT_new(ret->group);
		if (ret->pub_key == NULL)
			{
			ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
			goto err;
			}
		if (!EC_POINT_oct2point(ret->group, ret->pub_key,
			M_ASN1_STRING_data(priv_key->publicKey),
			M_ASN1_STRING_length(priv_key->publicKey), NULL))
			{
			ECerr(EC_F_D2I_ECPRIVATEKEY, ERR_R_EC_LIB);
			goto err;
			}
		}

	ok = 1;
err:
	if (!ok)
		{
		if (ret)
			EC_KEY_free(ret);
		ret = NULL;
		}

	if (priv_key)
		EC_PRIVATEKEY_free(priv_key);

	return(ret);
	}

int	i2d_ECPrivateKey(EC_KEY *a, unsigned char **out)
	{
	int             ret=0, ok=0;
	unsigned char   *buffer=NULL;
	size_t          buf_len=0, tmp_len;
	EC_PRIVATEKEY   *priv_key=NULL;

	if (a == NULL || a->group == NULL || a->priv_key == NULL)
		{
		ECerr(EC_F_I2D_ECPRIVATEKEY,
                      ERR_R_PASSED_NULL_PARAMETER);
		goto err;
		}

	if ((priv_key = EC_PRIVATEKEY_new()) == NULL)
		{
		ECerr(EC_F_I2D_ECPRIVATEKEY,
                      ERR_R_MALLOC_FAILURE);
		goto err;
		}

	priv_key->version = a->version;

	buf_len = (size_t)BN_num_bytes(a->priv_key);
	buffer = OPENSSL_malloc(buf_len);
	if (buffer == NULL)
		{
		ECerr(EC_F_I2D_ECPRIVATEKEY,
                      ERR_R_MALLOC_FAILURE);
		goto err;
		}
	
	if (!BN_bn2bin(a->priv_key, buffer))
		{
		ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_BN_LIB);
		goto err;
		}

	if (!M_ASN1_OCTET_STRING_set(priv_key->privateKey, buffer, buf_len))
		{
		ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_ASN1_LIB);
		goto err;
		}	

	if (!(a->enc_flag & EC_PKEY_NO_PARAMETERS))
		{
		if ((priv_key->parameters = EC_ASN1_group2pkparameters(
			a->group, priv_key->parameters)) == NULL)
			{
			ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_EC_LIB);
			goto err;
			}
		}

	if (!(a->enc_flag & EC_PKEY_NO_PUBKEY))
		{
		priv_key->publicKey = M_ASN1_BIT_STRING_new();
		if (priv_key->publicKey == NULL)
			{
			ECerr(EC_F_I2D_ECPRIVATEKEY,
				ERR_R_MALLOC_FAILURE);
			goto err;
			}

		tmp_len = EC_POINT_point2oct(a->group, a->pub_key, 
				a->conv_form, NULL, 0, NULL);

		if (tmp_len > buf_len)
			buffer = OPENSSL_realloc(buffer, tmp_len);
		if (buffer == NULL)
			{
			ECerr(EC_F_I2D_ECPRIVATEKEY,
				ERR_R_MALLOC_FAILURE);
			goto err;
			}

		buf_len = tmp_len;

		if (!EC_POINT_point2oct(a->group, a->pub_key, 
			a->conv_form, buffer, buf_len, NULL))
			{
			ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_EC_LIB);
			goto err;
			}

		if (!M_ASN1_BIT_STRING_set(priv_key->publicKey, buffer, 
				buf_len))
			{
			ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_ASN1_LIB);
			goto err;
			}
		}

	if ((ret = i2d_EC_PRIVATEKEY(priv_key, out)) == 0)
		{
		ECerr(EC_F_I2D_ECPRIVATEKEY, ERR_R_EC_LIB);
		goto err;
		}
	ok=1;
err:
	if (buffer)
		OPENSSL_free(buffer);
	if (priv_key)
		EC_PRIVATEKEY_free(priv_key);
	return(ok?ret:0);
	}

int i2d_ECParameters(EC_KEY *a, unsigned char **out)
	{
	if (a == NULL)
		{
		ECerr(EC_F_I2D_ECPARAMETERS, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	return i2d_ECPKParameters(a->group, out);
	}

EC_KEY *d2i_ECParameters(EC_KEY **a, const unsigned char **in, long len)
	{
	EC_GROUP *group;
	EC_KEY   *ret;

	if (in == NULL || *in == NULL)
		{
		ECerr(EC_F_D2I_ECPARAMETERS, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}

	group = d2i_ECPKParameters(NULL, in, len);

	if (group == NULL)
		{
		ECerr(EC_F_D2I_ECPARAMETERS, ERR_R_EC_LIB);
		return NULL;
		}

	if (a == NULL || *a == NULL)
		{
		if ((ret = EC_KEY_new()) == NULL)
			{
			ECerr(EC_F_D2I_ECPARAMETERS, ERR_R_MALLOC_FAILURE);
			return NULL;
			}
		if (a)
			*a = ret;
		}
	else
		ret = *a;

	if (ret->group)
		EC_GROUP_clear_free(ret->group);

	ret->group = group;
	
	return ret;
	}

EC_KEY *ECPublicKey_set_octet_string(EC_KEY **a, const unsigned char **in, 
					long len)
	{
	EC_KEY *ret=NULL;

	if (a == NULL || (*a) == NULL || (*a)->group == NULL)
		{
		/* sorry, but a EC_GROUP-structur is necessary
                 * to set the public key */
		ECerr(EC_F_ECPUBLICKEY_SET_OCTET, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	ret = *a;
	if (ret->pub_key == NULL && 
		(ret->pub_key = EC_POINT_new(ret->group)) == NULL)
		{
		ECerr(EC_F_ECPUBLICKEY_SET_OCTET, ERR_R_MALLOC_FAILURE);
		return 0;
		}
	if (!EC_POINT_oct2point(ret->group, ret->pub_key, *in, len, NULL))
		{
		ECerr(EC_F_ECPUBLICKEY_SET_OCTET, ERR_R_EC_LIB);
		return 0;
		}
	/* save the point conversion form */
	ret->conv_form = (point_conversion_form_t)(*in[0] & ~0x01);
	return ret;
	}

int ECPublicKey_get_octet_string(EC_KEY *a, unsigned char **out)
	{
        size_t  buf_len=0;

        if (a == NULL) 
		{
		ECerr(EC_F_ECPUBLICKEY_GET_OCTET, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}

        buf_len = EC_POINT_point2oct(a->group, a->pub_key, 
                              a->conv_form, NULL, 0, NULL);

	if (out == NULL || buf_len == 0)
	/* out == NULL => just return the length of the octet string */
		return buf_len;

	if (*out == NULL)
		if ((*out = OPENSSL_malloc(buf_len)) == NULL)
			{
			ECerr(EC_F_ECPUBLICKEY_GET_OCTET, 
				ERR_R_MALLOC_FAILURE);
			return 0;
			}
        if (!EC_POINT_point2oct(a->group, a->pub_key, a->conv_form,
				*out, buf_len, NULL))
		{
		ECerr(EC_F_ECPUBLICKEY_GET_OCTET, ERR_R_EC_LIB);
		OPENSSL_free(*out);
		*out = NULL;
		return 0;
		}
	return buf_len;
	}
