/* crypto/dsa/dsa_asn1.c */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/dsa.h>
#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>

DSA_SIG *DSA_SIG_new(void)
{
	DSA_SIG *ret;

	ret = Malloc(sizeof(DSA_SIG));
	if (ret == NULL)
		{
		DSAerr(DSA_F_DSA_SIG_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	ret->r = NULL;
	ret->s = NULL;
	return(ret);
}

void DSA_SIG_free(DSA_SIG *r)
{
	if (r == NULL) return;
	if (r->r) BN_clear_free(r->r);
	if (r->s) BN_clear_free(r->s);
	Free(r);
}

int i2d_DSA_SIG(DSA_SIG *v, unsigned char **pp)
{
	int t=0,len;
	ASN1_INTEGER rbs,sbs;
	unsigned char *p;

	rbs.data=Malloc(BN_num_bits(v->r)/8+1);
	if (rbs.data == NULL)
		{
		DSAerr(DSA_F_I2D_DSA_SIG, ERR_R_MALLOC_FAILURE);
		return(0);
		}
	rbs.type=V_ASN1_INTEGER;
	rbs.length=BN_bn2bin(v->r,rbs.data);
	sbs.data=Malloc(BN_num_bits(v->s)/8+1);
	if (sbs.data == NULL)
		{
		Free(rbs.data);
		DSAerr(DSA_F_I2D_DSA_SIG, ERR_R_MALLOC_FAILURE);
		return(0);
		}
	sbs.type=V_ASN1_INTEGER;
	sbs.length=BN_bn2bin(v->s,sbs.data);

	len=i2d_ASN1_INTEGER(&rbs,NULL);
	len+=i2d_ASN1_INTEGER(&sbs,NULL);

	if (pp)
		{
		p=*pp;
		ASN1_put_object(&p,1,len,V_ASN1_SEQUENCE,V_ASN1_UNIVERSAL);
		i2d_ASN1_INTEGER(&rbs,&p);
		i2d_ASN1_INTEGER(&sbs,&p);
		}
	t=ASN1_object_size(1,len,V_ASN1_SEQUENCE);
	Free(rbs.data);
	Free(sbs.data);
	return(t);
}

DSA_SIG *d2i_DSA_SIG(DSA_SIG **a, unsigned char **pp, long length)
{
	int i=ERR_R_NESTED_ASN1_ERROR;
	ASN1_INTEGER *bs=NULL;
	M_ASN1_D2I_vars(a,DSA_SIG *,DSA_SIG_new);

	M_ASN1_D2I_Init();
	M_ASN1_D2I_start_sequence();
	M_ASN1_D2I_get(bs,d2i_ASN1_INTEGER);
	if ((ret->r=BN_bin2bn(bs->data,bs->length,ret->r)) == NULL)
		goto err_bn;
	M_ASN1_D2I_get(bs,d2i_ASN1_INTEGER);
	if ((ret->s=BN_bin2bn(bs->data,bs->length,ret->s)) == NULL)
		goto err_bn;
	M_ASN1_BIT_STRING_free(bs);
	M_ASN1_D2I_Finish_2(a);

err_bn:
	i=ERR_R_BN_LIB;
err:
	DSAerr(DSA_F_D2I_DSA_SIG,i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret))) DSA_SIG_free(ret);
	if (bs != NULL) M_ASN1_BIT_STRING_free(bs);
	return(NULL);
}
