/* crypto/ecdsa/ecs_asn1.c */
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

#include "cryptlib.h"
#include "ecs_locl.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>

static point_conversion_form_t POINT_CONVERSION_FORM = POINT_CONVERSION_COMPRESSED;

ASN1_SEQUENCE(ECDSA_SIG) = {
	ASN1_SIMPLE(ECDSA_SIG, r, CBIGNUM),
	ASN1_SIMPLE(ECDSA_SIG, s, CBIGNUM)
} ASN1_SEQUENCE_END(ECDSA_SIG)

IMPLEMENT_ASN1_FUNCTIONS_const(ECDSA_SIG)

ASN1_SEQUENCE(X9_62_FIELDID) = {
	ASN1_SIMPLE(X9_62_FIELDID, fieldType, ASN1_OBJECT),
	ASN1_SIMPLE(X9_62_FIELDID, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(X9_62_FIELDID)

IMPLEMENT_ASN1_FUNCTIONS_const(X9_62_FIELDID)

ASN1_SEQUENCE(X9_62_CURVE) = {
	ASN1_SIMPLE(X9_62_CURVE, a, ASN1_OCTET_STRING),
	ASN1_SIMPLE(X9_62_CURVE, b, ASN1_OCTET_STRING),
	ASN1_OPT(X9_62_CURVE, seed, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(X9_62_CURVE)

IMPLEMENT_ASN1_FUNCTIONS_const(X9_62_CURVE)

ASN1_SEQUENCE(X9_62_EC_PARAMETERS) = {
	ASN1_OPT(X9_62_EC_PARAMETERS, version, ASN1_INTEGER),
	ASN1_SIMPLE(X9_62_EC_PARAMETERS, fieldID, X9_62_FIELDID),
	ASN1_SIMPLE(X9_62_EC_PARAMETERS, curve, X9_62_CURVE),
	ASN1_SIMPLE(X9_62_EC_PARAMETERS, base, ASN1_OCTET_STRING),
	ASN1_SIMPLE(X9_62_EC_PARAMETERS, order, ASN1_INTEGER),
	ASN1_SIMPLE(X9_62_EC_PARAMETERS, cofactor, ASN1_INTEGER)
} ASN1_SEQUENCE_END(X9_62_EC_PARAMETERS)

IMPLEMENT_ASN1_FUNCTIONS_const(X9_62_EC_PARAMETERS)

ASN1_CHOICE(EC_PARAMETERS) = {
	ASN1_SIMPLE(EC_PARAMETERS, value.named_curve, ASN1_OBJECT),
	ASN1_SIMPLE(EC_PARAMETERS, value.parameters, X9_62_EC_PARAMETERS),
	ASN1_SIMPLE(EC_PARAMETERS, value.implicitlyCA, ASN1_NULL)
} ASN1_CHOICE_END(EC_PARAMETERS)

IMPLEMENT_ASN1_FUNCTIONS_const(EC_PARAMETERS)
             
ASN1_SEQUENCE(ECDSAPrivateKey) = {
	ASN1_SIMPLE(ECDSAPrivateKey, version, LONG),
	ASN1_SIMPLE(ECDSAPrivateKey, parameters, EC_PARAMETERS),
	ASN1_SIMPLE(ECDSAPrivateKey, pub_key, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ECDSAPrivateKey, priv_key, BIGNUM)
} ASN1_SEQUENCE_END(ECDSAPrivateKey)

IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(ECDSAPrivateKey, ECDSAPrivateKey, ECDSAPrivateKey)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(ECDSAPrivateKey, ECDSAPrivateKey, ecdsaPrivateKey)

ASN1_SEQUENCE(ecdsa_pub_internal) = {
	ASN1_SIMPLE(ECDSAPrivateKey, pub_key, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ECDSAPrivateKey, parameters, EC_PARAMETERS),
} ASN1_SEQUENCE_END_name(ECDSAPrivateKey, ecdsa_pub_internal)

ASN1_CHOICE(ECDSAPublicKey) = {
	ASN1_SIMPLE(ECDSAPrivateKey, pub_key, ASN1_OCTET_STRING),
	ASN1_EX_COMBINE(0, 0, ecdsa_pub_internal)
} ASN1_CHOICE_END_selector(ECDSAPrivateKey, ECDSAPublicKey, write_params)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(ECDSAPrivateKey, ECDSAPublicKey, ecdsaPublicKey)


X9_62_FIELDID 	*ECDSA_get_X9_62_FIELDID(const ECDSA *ecdsa, X9_62_FIELDID *field)
{
	/* TODO : characteristic two */
	int	ok=0, reason=ERR_R_ASN1_LIB;
	X9_62_FIELDID *ret=NULL;
	BIGNUM  *tmp=NULL;
	
	if (!ecdsa || !ecdsa->group)
		OPENSSL_ECDSA_ABORT(ECDSA_R_MISSING_PARAMETERS)
	if (field == NULL)
	{
		if ((ret = X9_62_FIELDID_new()) == NULL) return NULL;
	}
	else
	{	
		ret = field;
		if (ret->fieldType != NULL)	ASN1_OBJECT_free(ret->fieldType);
		if (ret->parameters != NULL)	ASN1_TYPE_free(ret->parameters);
	}
	if ((tmp = BN_new()) == NULL) 
		OPENSSL_ECDSA_ABORT(ERR_R_BN_LIB)
	if ((ret->fieldType = OBJ_nid2obj(NID_X9_62_prime_field)) == NULL)
		OPENSSL_ECDSA_ABORT(ERR_R_OBJ_LIB)
	if ((ret->parameters = ASN1_TYPE_new()) == NULL) goto err;
	ret->parameters->type = V_ASN1_INTEGER;
	if (!EC_GROUP_get_curve_GFp(ecdsa->group, tmp, NULL, NULL, NULL))
		OPENSSL_ECDSA_ABORT(ERR_R_EC_LIB)
	if ((ret->parameters->value.integer = BN_to_ASN1_INTEGER(tmp, NULL)) == NULL) goto err;
	ok = 1;
err :	if (!ok)
	{
		if (ret && !field) X9_62_FIELDID_free(ret);
		ret = NULL;
		ECDSAerr(ECDSA_F_ECDSA_GET_X9_62_FIELDID, reason);
	}
	if (tmp) BN_free(tmp);
	return(ret);
}

X9_62_CURVE   *ECDSA_get_X9_62_CURVE(const ECDSA *ecdsa, X9_62_CURVE *curve)
{
	int	ok=0, reason=ERR_R_BN_LIB, len1=0, len2=0;
	X9_62_CURVE *ret=NULL;
	BIGNUM      *tmp1=NULL, *tmp2=NULL;
	unsigned char *buffer=NULL;
	unsigned char char_buf = 0;

	if (!ecdsa || !ecdsa->group)
		OPENSSL_ECDSA_ABORT(ECDSA_R_MISSING_PARAMETERS)
	if ((tmp1 = BN_new()) == NULL || (tmp2 = BN_new()) == NULL) goto err;
	if (curve == NULL)
	{
		if ((ret = X9_62_CURVE_new()) == NULL)
			OPENSSL_ECDSA_ABORT(ECDSA_R_X9_62_CURVE_NEW_FAILURE)
	}
	else
	{
		ret = curve;
		if (ret->a)	ASN1_OCTET_STRING_free(ret->a);
		if (ret->b)	ASN1_OCTET_STRING_free(ret->b);
		if (ret->seed)	ASN1_BIT_STRING_free(ret->seed);
	}
	if (!EC_GROUP_get_curve_GFp(ecdsa->group, NULL, tmp1, tmp2, NULL))
		OPENSSL_ECDSA_ABORT(ERR_R_EC_LIB)

	if ((ret->a = M_ASN1_OCTET_STRING_new()) == NULL || 
	    (ret->b = M_ASN1_OCTET_STRING_new()) == NULL )
		OPENSSL_ECDSA_ABORT(ERR_R_ASN1_LIB)

	len1 = BN_num_bytes(tmp1);
	len2 = BN_num_bytes(tmp2);

	if ((buffer = OPENSSL_malloc(len1 > len2 ? len1 : len2)) == NULL)
		OPENSSL_ECDSA_ABORT(ERR_R_MALLOC_FAILURE)

	if (len1 == 0) /* => a == 0 */
	{
		if (!M_ASN1_OCTET_STRING_set(ret->a, &char_buf, 1))
			OPENSSL_ECDSA_ABORT(ERR_R_ASN1_LIB)
	}
	else
	{
		if ((len1 = BN_bn2bin(tmp1, buffer)) == 0) goto err;
		if (!M_ASN1_OCTET_STRING_set(ret->a, buffer, len1))
			OPENSSL_ECDSA_ABORT(ERR_R_ASN1_LIB)
	}
	if (len2 == 0) /* => b == 0 */
	{
		if (!M_ASN1_OCTET_STRING_set(ret->a, &char_buf, 1))
			OPENSSL_ECDSA_ABORT(ERR_R_ASN1_LIB)
	}
	else
	{
		if ((len2 = BN_bn2bin(tmp2, buffer)) == 0) goto err;
		if (!M_ASN1_OCTET_STRING_set(ret->b, buffer, len2))
			OPENSSL_ECDSA_ABORT(ERR_R_ASN1_LIB)
	}

	if (ecdsa->seed)
	{	
		if ((ret->seed = ASN1_BIT_STRING_new()) == NULL) goto err;
		if (!ASN1_BIT_STRING_set(ret->seed, ecdsa->seed, (int)ecdsa->seed_len))
			OPENSSL_ECDSA_ABORT(ERR_R_ASN1_LIB)
	}
	else
		ret->seed = NULL;

	ok = 1;
err :	if (!ok)
	{
		if (ret && !curve) X9_62_CURVE_free(ret);
		ret = NULL;
		ECDSAerr(ECDSA_F_ECDSA_GET_X9_62_CURVE, reason);
	}
	if (buffer) OPENSSL_free(buffer);
	if (tmp1)   BN_free(tmp1);
	if (tmp2)   BN_free(tmp2);
	return(ret);
}

X9_62_EC_PARAMETERS *ECDSA_get_X9_62_EC_PARAMETERS(const ECDSA *ecdsa, X9_62_EC_PARAMETERS *param)
{
	int	ok=0, reason=ERR_R_ASN1_LIB;
	size_t  len=0;
	X9_62_EC_PARAMETERS *ret=NULL;
	BIGNUM	      *tmp=NULL;
	unsigned char *buffer=NULL;
	EC_POINT      *point=NULL;

	if (!ecdsa || !ecdsa->group)
		OPENSSL_ECDSA_ABORT(ECDSA_R_MISSING_PARAMETERS)
	if ((tmp = BN_new()) == NULL)
		OPENSSL_ECDSA_ABORT(ERR_R_BN_LIB)
	if (param == NULL)
	{
		if ((ret = X9_62_EC_PARAMETERS_new()) == NULL)
			OPENSSL_ECDSA_ABORT(ECDSA_R_X9_62_EC_PARAMETERS_NEW_FAILURE)
	}
	else
		ret = param;
	if (ecdsa->version == 1)
		ret->version = NULL;
	else
	{
		if (ret->version == NULL && (ret->version = ASN1_INTEGER_new()) == NULL)
			OPENSSL_ECDSA_ABORT(ERR_R_MALLOC_FAILURE)
		if (!ASN1_INTEGER_set(ret->version, (long)ecdsa->version)) goto err;
	}
	if ((ret->fieldID = ECDSA_get_X9_62_FIELDID(ecdsa, ret->fieldID)) == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_ECDSA_GET_X9_62_FIELDID_FAILURE)
	if ((ret->curve = ECDSA_get_X9_62_CURVE(ecdsa, ret->curve)) == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_ECDSA_GET_X9_62_CURVE_FAILURE)
	if ((point = EC_GROUP_get0_generator(ecdsa->group)) == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_CAN_NOT_GET_GENERATOR)
	if (!(len = EC_POINT_point2oct(ecdsa->group, point, POINT_CONVERSION_COMPRESSED, NULL, len, NULL)))
		OPENSSL_ECDSA_ABORT(ECDSA_R_UNEXPECTED_PARAMETER_LENGTH)
	if ((buffer = OPENSSL_malloc(len)) == NULL)
		OPENSSL_ECDSA_ABORT(ERR_R_MALLOC_FAILURE)
	if (!EC_POINT_point2oct(ecdsa->group, point, POINT_CONVERSION_COMPRESSED, buffer, len, NULL)) 
		OPENSSL_ECDSA_ABORT(ERR_R_EC_LIB)
	if (ret->base == NULL && (ret->base = ASN1_OCTET_STRING_new()) == NULL)
		OPENSSL_ECDSA_ABORT(ERR_R_MALLOC_FAILURE)
	if (!ASN1_OCTET_STRING_set(ret->base, buffer, len)) goto err;
	if (!EC_GROUP_get_order(ecdsa->group, tmp, NULL))
		OPENSSL_ECDSA_ABORT(ERR_R_EC_LIB)
	if ((ret->order = BN_to_ASN1_INTEGER(tmp, ret->order)) == NULL) goto err;
	if (!EC_GROUP_get_cofactor(ecdsa->group, tmp, NULL))
		OPENSSL_ECDSA_ABORT(ERR_R_EC_LIB)
	if ((ret->cofactor = BN_to_ASN1_INTEGER(tmp, ret->cofactor)) == NULL) goto err;
	ok = 1;

err :	if(!ok)
	{
		ECDSAerr(ECDSA_F_ECDSA_GET_X9_62_EC_PARAMETERS, reason);
		if (ret && !param) X9_62_EC_PARAMETERS_free(ret);
		ret = NULL;
	}
	if (tmp)    BN_free(tmp);
	if (buffer) OPENSSL_free(buffer);
	return(ret);
}

EC_PARAMETERS *ECDSA_get_EC_PARAMETERS(const ECDSA *ecdsa, EC_PARAMETERS *params)
{
	int ok = 1;
	int tmp = 0;
	EC_PARAMETERS *ret = params;
	if (ret == NULL)
		if ((ret = EC_PARAMETERS_new()) == NULL)
		{
			ECDSAerr(ECDSA_F_ECDSA_GET_EC_PARAMETERS, ERR_R_MALLOC_FAILURE);
			return NULL;
		}
	if (ecdsa == NULL)
	{	/* missing parameter */
		ECDSAerr(ECDSA_F_ECDSA_GET_EC_PARAMETERS, ECDSA_R_MISSING_PARAMETERS);
		EC_PARAMETERS_free(params);
		return NULL;
	}
	if (ecdsa->parameter_flags & ECDSA_FLAG_NAMED_CURVE)
	{	/* use a named curve */
		tmp = EC_GROUP_get_nid(ecdsa->group);
		if (tmp)
		{
			ret->type = 0;
			if ((ret->value.named_curve = OBJ_nid2obj(tmp)) == NULL)
				ok = 0;
		}
		else
		{
			/* use the x9_64 ec_parameters structure */
			ret->type = 1;
			if ((ret->value.parameters = ECDSA_get_X9_62_EC_PARAMETERS(ecdsa, NULL)) == NULL)
				ok = 0;
		}
	}
	else if (ecdsa->parameter_flags & ECDSA_FLAG_IMPLICITLYCA)
	{	/* use implicitlyCA */
		ret->type = 2;
		if ((ret->value.implicitlyCA = ASN1_NULL_new()) == NULL)
			ok = 0;
	}
	else
	{	/* use the x9_64 ec_parameters structure */
		ret->type = 1;
		if ((ret->value.parameters = ECDSA_get_X9_62_EC_PARAMETERS(ecdsa, NULL)) == NULL)
			ok = 0;
	}
	if (!ok)
	{
		EC_PARAMETERS_free(ret);
		return NULL;
	}
		return ret;
}

ECDSA         *ECDSA_x9_62parameters2ecdsa(const X9_62_EC_PARAMETERS *params, ECDSA *ecdsa)
{
	int	  ok=0, reason=ERR_R_EC_LIB, tmp;
	ECDSA	  *ret=NULL;
	const EC_METHOD *meth=NULL;
	BIGNUM	  *tmp_1=NULL, *tmp_2=NULL, *tmp_3=NULL;
	EC_POINT  *point=NULL;

	if (!params) 
		OPENSSL_ECDSA_ABORT(ECDSA_R_MISSING_PARAMETERS)
	if (ecdsa == NULL)
	{
		if ((ret = ECDSA_new()) == NULL) 
			OPENSSL_ECDSA_ABORT(ECDSA_R_ECDSA_NEW_FAILURE)
	}
	else
	{
		if (ecdsa->group)	EC_GROUP_free(ecdsa->group);
		if (ecdsa->pub_key)	EC_POINT_free(ecdsa->pub_key);
		ecdsa->pub_key = NULL;
		if (ecdsa->priv_key)	BN_clear_free(ecdsa->priv_key);
		ecdsa->priv_key = NULL;
		if (ecdsa->seed)	OPENSSL_free(ecdsa->seed);
		ecdsa->seed = NULL;
		if (ecdsa->kinv)	
		{
			BN_clear_free(ecdsa->kinv);
			ecdsa->kinv = NULL;
		}
		if (ecdsa->r)
		{
			BN_clear_free(ecdsa->r);
			ecdsa->r = NULL;
		}
		ret = ecdsa;
	}
	/* TODO : characteristic two */
	if (!params->fieldID || !params->fieldID->fieldType || !params->fieldID->parameters)
		OPENSSL_ECDSA_ABORT(ECDSA_R_NO_FIELD_SPECIFIED)
	tmp = OBJ_obj2nid(params->fieldID->fieldType); 
	if (tmp == NID_X9_62_characteristic_two_field)
	{
		OPENSSL_ECDSA_ABORT(ECDSA_R_NOT_SUPPORTED)
	}
	else if (tmp == NID_X9_62_prime_field)
	{
		/* TODO : optimal method for the curve */
		meth = EC_GFp_mont_method();
		if ((ret->group = EC_GROUP_new(meth)) == NULL) goto err;
		if (params->fieldID->parameters->type != V_ASN1_INTEGER)
			OPENSSL_ECDSA_ABORT(ECDSA_R_UNEXPECTED_ASN1_TYPE)
		if (!params->fieldID->parameters->value.integer)
			OPENSSL_ECDSA_ABORT(ECDSA_R_PRIME_MISSING)
		if ((tmp_1 = ASN1_INTEGER_to_BN(params->fieldID->parameters->value.integer, NULL)) == NULL)
			OPENSSL_ECDSA_ABORT(ERR_R_ASN1_LIB)
		if (!params->curve)
			OPENSSL_ECDSA_ABORT(ECDSA_R_NO_CURVE_SPECIFIED)
		if (!params->curve->a || !params->curve->a->data)
			OPENSSL_ECDSA_ABORT(ECDSA_R_NO_CURVE_PARAMETER_A_SPECIFIED)
		if ((tmp_2 = BN_bin2bn(params->curve->a->data, params->curve->a->length, NULL)) == NULL)
			OPENSSL_ECDSA_ABORT(ERR_R_BN_LIB)
		if (!params->curve->b || !params->curve->b->data)
			OPENSSL_ECDSA_ABORT(ECDSA_R_NO_CURVE_PARAMETER_B_SPECIFIED)
		if ((tmp_3 = BN_bin2bn(params->curve->b->data, params->curve->b->length, NULL)) == NULL)
			OPENSSL_ECDSA_ABORT(ERR_R_BN_LIB)
		if (!EC_GROUP_set_curve_GFp(ret->group, tmp_1, tmp_2, tmp_3, NULL)) goto err;
		if ((point = EC_POINT_new(ret->group)) == NULL) goto err;
	}
	else OPENSSL_ECDSA_ABORT(ECDSA_R_WRONG_FIELD_IDENTIFIER)
	if (params->curve->seed != NULL)
	{
		if (ret->seed != NULL)
			OPENSSL_free(ret->seed);
		if ((ret->seed = OPENSSL_malloc(params->curve->seed->length)) == NULL)
			OPENSSL_ECDSA_ABORT(ERR_R_MALLOC_FAILURE)
		memcpy(ret->seed, params->curve->seed->data, params->curve->seed->length);
		ret->seed_len = params->curve->seed->length;
	}
	if (params->version)
	{
		if ((ret->version = (int)ASN1_INTEGER_get(params->version)) < 0)
			OPENSSL_ECDSA_ABORT(ECDSA_R_UNEXPECTED_VERSION_NUMER)
	}
	else
		ret->version  = 1;
	if (params->order && params->cofactor && params->base && params->base->data)
	{
		if ((tmp_1 = ASN1_INTEGER_to_BN(params->order, tmp_1)) == NULL)
			OPENSSL_ECDSA_ABORT(ERR_R_ASN1_LIB)
		if ((tmp_2 = ASN1_INTEGER_to_BN(params->cofactor, tmp_2)) == NULL)
			OPENSSL_ECDSA_ABORT(ERR_R_ASN1_LIB)
		if (!EC_POINT_oct2point(ret->group, point, params->base->data, 
			        params->base->length, NULL)) goto err;
		if (!EC_GROUP_set_generator(ret->group, point, tmp_1, tmp_2)) goto err;
	}
	ok = 1;

err:	if (!ok)
	{
		ECDSAerr(ECDSA_F_ECDSA_GET, reason);
		if (ret && !ecdsa) ECDSA_free(ret);
		ret = NULL;
	}
	if (tmp_1)	BN_free(tmp_1);
	if (tmp_2)	BN_free(tmp_2);
	if (tmp_3)	BN_free(tmp_3);
	if (point)	EC_POINT_free(point);
	return(ret);
}

ECDSA *ECDSA_ecparameters2ecdsa(const EC_PARAMETERS *params, ECDSA *ecdsa)
{
	ECDSA *ret = ecdsa;
	int tmp = 0;
	if (ret == NULL)
		if ((ret = ECDSA_new()) == NULL)
		{
			ECDSAerr(ECDSA_F_ECDSA_GET_ECDSA, ERR_R_MALLOC_FAILURE);
			return NULL;
		}
	if (params == NULL)
	{
		ECDSAerr(ECDSA_F_ECDSA_GET_ECDSA, ECDSA_R_MISSING_PARAMETERS);
		ECDSA_free(ret);
		return NULL;
	}
	if (params->type == 0)
	{
		if (ret->group)
			EC_GROUP_free(ret->group);
		tmp = OBJ_obj2nid(params->value.named_curve);
		ret->parameter_flags |= ECDSA_FLAG_NAMED_CURVE;
		if ((ret->group = EC_GROUP_new_by_name(tmp)) == NULL)
		{
			ECDSAerr(ECDSA_F_ECDSA_GET_ECDSA, ECDSA_R_EC_GROUP_NID2CURVE_FAILURE);
			ECDSA_free(ret);
			return NULL;
		}
	}
	else if (params->type == 1)
	{
		ret = ECDSA_x9_62parameters2ecdsa(params->value.parameters, ret);
	}
	else if (params->type == 2)
	{
		if (ret->group)
			EC_GROUP_free(ret->group);
		ret->group = NULL;
		ret->parameter_flags |= ECDSA_FLAG_IMPLICITLYCA;		
	}
	else
	{
		ECDSAerr(ECDSA_F_ECDSA_GET_ECDSA, ECDSA_R_UNKNOWN_PARAMETERS_TYPE);
		ECDSA_free(ret);
		ret = NULL;
	}
	return ret;
}

ECDSA 	*d2i_ECDSAParameters(ECDSA **a, const unsigned char **in, long len)
{
	ECDSA		*ecdsa = (a && *a)? *a : NULL;
	EC_PARAMETERS	*params = NULL;

	if ((params = d2i_EC_PARAMETERS(NULL, in, len)) == NULL)
	{
		ECDSAerr(ECDSA_F_D2I_ECDSAPARAMETERS, ECDSA_R_D2I_EC_PARAMETERS_FAILURE);
		EC_PARAMETERS_free(params);
		return NULL;
	}
	if ((ecdsa = ECDSA_ecparameters2ecdsa(params, ecdsa)) == NULL)
	{
		ECDSAerr(ECDSA_F_D2I_ECDSAPARAMETERS, ECDSA_R_ECPARAMETERS2ECDSA_FAILURE);
		return NULL; 
	}
	EC_PARAMETERS_free(params);
	return(ecdsa);	
}

int	i2d_ECDSAParameters(ECDSA *a, unsigned char **out)
{
	int		ret=0;
	EC_PARAMETERS	*tmp = ECDSA_get_EC_PARAMETERS(a, NULL);
	if (tmp == NULL)
	{
		ECDSAerr(ECDSA_F_I2D_ECDSAPARAMETERS, ECDSA_R_ECDSA_GET_EC_PARAMETERS_FAILURE);
		return 0;
	}
	if ((ret = i2d_EC_PARAMETERS(tmp, out)) == 0)
	{
		ECDSAerr(ECDSA_F_I2D_ECDSAPARAMETERS, ECDSA_R_ECDSA_R_D2I_EC_PARAMETERS_FAILURE);
		EC_PARAMETERS_free(tmp);
		return 0;
	}	
	EC_PARAMETERS_free(tmp);
	return(ret);
}

ECDSA 	*d2i_ECDSAPrivateKey(ECDSA **a, const unsigned char **in, long len)
{
	int reason=ERR_R_BN_LIB, ok=0;
	ECDSA *ret=NULL;
	ECDSAPrivateKey *priv_key=NULL;

	if ((priv_key = ECDSAPrivateKey_new()) == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_ECDSAPRIVATEKEY_NEW_FAILURE)
	if ((priv_key = d2i_ecdsaPrivateKey(&priv_key, in, len)) == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_D2I_ECDSA_PRIVATEKEY_FAILURE)
	if ((ret = ECDSA_ecparameters2ecdsa(priv_key->parameters, NULL)) == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_ECDSA_GET_FAILURE)
	ret->version = priv_key->version;
	ret->write_params = priv_key->write_params;
	if (priv_key->priv_key)
	{
		if ((ret->priv_key = BN_dup(priv_key->priv_key)) == NULL)
			OPENSSL_ECDSA_ABORT(ERR_R_BN_LIB)
	}
	else
		OPENSSL_ECDSA_ABORT(ECDSA_R_D2I_ECDSAPRIVATEKEY_MISSING_PRIVATE_KEY)
	if ((ret->pub_key = EC_POINT_new(ret->group)) == NULL)
		OPENSSL_ECDSA_ABORT(ERR_R_EC_LIB)
	if (!EC_POINT_oct2point(ret->group, ret->pub_key, priv_key->pub_key->data, priv_key->pub_key->length, NULL))
		OPENSSL_ECDSA_ABORT(ERR_R_EC_LIB)
	ok = 1;
err :	if (!ok)
	{
		if (ret) ECDSA_free(ret);
		ret = NULL;
		ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY, reason);
	}
	if (priv_key)	ECDSAPrivateKey_free(priv_key);
	return(ret);
}

int	i2d_ECDSAPrivateKey(ECDSA *a, unsigned char **out)
{
	int ret=0, ok=0, reason=ERR_R_EC_LIB;
	unsigned char   *buffer=NULL;
	size_t		buf_len=0;
	ECDSAPrivateKey *priv_key=NULL;

	if (a == NULL || a->group == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_MISSING_PARAMETERS)
	if ((priv_key = ECDSAPrivateKey_new()) == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_ECDSAPRIVATEKEY_NEW_FAILURE)
	if ((priv_key->parameters = ECDSA_get_EC_PARAMETERS(a, priv_key->parameters)) == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_ECDSA_GET_X9_62_EC_PARAMETERS_FAILURE)
	priv_key->version      = a->version;
	if (BN_copy(priv_key->priv_key, a->priv_key) == NULL)
		OPENSSL_ECDSA_ABORT(ERR_R_BN_LIB)
	buf_len = EC_POINT_point2oct(a->group, a->pub_key, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
	if ((buffer = OPENSSL_malloc(buf_len)) == NULL)
		OPENSSL_ECDSA_ABORT(ERR_R_MALLOC_FAILURE)
	if (!EC_POINT_point2oct(a->group, a->pub_key, POINT_CONVERSION_COMPRESSED,
	                        buffer, buf_len, NULL)) goto err;
	if (!M_ASN1_OCTET_STRING_set(priv_key->pub_key, buffer, buf_len))
		OPENSSL_ECDSA_ABORT(ERR_R_ASN1_LIB)
	if ((ret = i2d_ecdsaPrivateKey(priv_key, out)) == 0)
		OPENSSL_ECDSA_ABORT(ECDSA_R_I2D_ECDSA_PRIVATEKEY)
	ok=1;
	
err:	if (!ok)
		ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY, reason);
	if (buffer)   OPENSSL_free(buffer);
	if (priv_key) ECDSAPrivateKey_free(priv_key);	
	return(ok?ret:0);
}


ECDSA 	*d2i_ECDSAPublicKey(ECDSA **a, const unsigned char **in, long len)
{
	int reason=ERR_R_BN_LIB, ok=0, ecdsa_new=1;
	ECDSA *ret=NULL;
	ECDSAPrivateKey *priv_key=NULL;

	if (a && *a)
	{
		ecdsa_new = 0;
		ret = *a;
	}
	else if ((ret = ECDSA_new()) == NULL)
		OPENSSL_ECDSA_ABORT(ERR_R_MALLOC_FAILURE); 
	if ((priv_key = ECDSAPrivateKey_new()) == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_ECDSAPRIVATEKEY_NEW_FAILURE)
	if ((priv_key = d2i_ecdsaPublicKey(&priv_key, in, len)) == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_D2I_ECDSA_PRIVATEKEY_FAILURE)
	if (priv_key->write_params == 0)
	{
		if (ecdsa_new || !ret->group)
			OPENSSL_ECDSA_ABORT(ECDSA_R_MISSING_PARAMETERS)
		if (ret->pub_key == NULL && (ret->pub_key = EC_POINT_new(ret->group)) == NULL)
			OPENSSL_ECDSA_ABORT(ERR_R_MALLOC_FAILURE)
		if (!EC_POINT_oct2point(ret->group, ret->pub_key, priv_key->pub_key->data,
					priv_key->pub_key->length, NULL))
			OPENSSL_ECDSA_ABORT(ERR_R_EC_LIB)
	}
	else if (priv_key->write_params == 1)
	{
		if ((ret = ECDSA_ecparameters2ecdsa(priv_key->parameters, ret)) == NULL)
			OPENSSL_ECDSA_ABORT(ECDSA_R_ECDSA_GET_FAILURE)
		if (ret->pub_key == NULL && (ret->pub_key = EC_POINT_new(ret->group)) == NULL)
			OPENSSL_ECDSA_ABORT(ERR_R_EC_LIB)
		if (!EC_POINT_oct2point(ret->group, ret->pub_key, priv_key->pub_key->data, 
				priv_key->pub_key->length, NULL))
			OPENSSL_ECDSA_ABORT(ERR_R_EC_LIB)
	}
	else	OPENSSL_ECDSA_ABORT(ECDSA_R_UNEXPECTED_PARAMETER)
	ret->write_params = 1;
	ok = 1;
err :	if (!ok)
	{
		if (ret && ecdsa_new) ECDSA_free(ret);
		ret = NULL;
		ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY, reason);
	}
	if (priv_key)	ECDSAPrivateKey_free(priv_key);
	return(ret);
}

int 	i2d_ECDSAPublicKey(ECDSA *a, unsigned char **out)
{
        int 	ret=0, reason=ERR_R_EC_LIB, ok=0;
        unsigned char   *buffer=NULL;
        size_t          buf_len=0;
        ECDSAPrivateKey *priv_key=NULL;

        if (a == NULL) 
		OPENSSL_ECDSA_ABORT(ECDSA_R_MISSING_PARAMETERS)
        if ((priv_key = ECDSAPrivateKey_new()) == NULL) 
		OPENSSL_ECDSA_ABORT(ECDSA_R_ECDSAPRIVATEKEY_NEW_FAILURE)
        if ((priv_key->parameters = ECDSA_get_EC_PARAMETERS(a, priv_key->parameters)) == NULL)
		OPENSSL_ECDSA_ABORT(ECDSA_R_ECDSA_GET_X9_62_EC_PARAMETERS_FAILURE)
        priv_key->version = a->version;
        priv_key->write_params = a->write_params;
        buf_len = EC_POINT_point2oct(a->group, a->pub_key, POINT_CONVERSION_FORM, NULL, 0, NULL);
        if (!buf_len || (buffer = OPENSSL_malloc(buf_len)) == NULL)
		OPENSSL_ECDSA_ABORT(ERR_R_MALLOC_FAILURE)
        if (!EC_POINT_point2oct(a->group, a->pub_key, POINT_CONVERSION_FORM,
	 		        buffer, buf_len, NULL)) goto err;
        if (!M_ASN1_OCTET_STRING_set(priv_key->pub_key, buffer, buf_len))
		OPENSSL_ECDSA_ABORT(ERR_R_ASN1_LIB)
        if ((ret = i2d_ecdsaPublicKey(priv_key, out)) == 0)
		OPENSSL_ECDSA_ABORT(ECDSA_R_I2D_ECDSA_PUBLICKEY)
	ok = 1;

err:    if (!ok)
		ECDSAerr(ECDSA_F_I2D_ECDSAPUBLICKEY, reason);
	if (buffer)   OPENSSL_free(buffer);
        if (priv_key) ECDSAPrivateKey_free(priv_key);
        return(ok?ret:0);
}
