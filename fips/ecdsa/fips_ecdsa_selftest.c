/* fips/ecdsa/fips_ecdsa_selftest.c */

#define OPENSSL_FIPSAPI

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#ifdef OPENSSL_FIPS

static const unsigned char str1[]="12345678901234567890";

static int corrupt_ecdsa = 0;

void FIPS_corrupt_ecdsa()
    {
    corrupt_ecdsa = 1;
    }

int FIPS_selftest_ecdsa()
    {
    EC_KEY *ec=NULL;
    int ret = 0;
    EVP_MD_CTX mctx;
    ECDSA_SIG *esig = NULL;

    FIPS_md_ctx_init(&mctx);

    ec = EC_KEY_new_by_curve_name(NID_secp384r1);

    if(ec == NULL)
	goto err;

    EC_KEY_generate_key(ec);

    if (!FIPS_digestinit(&mctx, EVP_sha512()))
	goto err;
    if (!FIPS_digestupdate(&mctx, str1, 20))
	goto err;
    esig = FIPS_ecdsa_sign_ctx(ec, &mctx);
    if (!esig)
	goto err;

    if (corrupt_ecdsa)
	BN_add_word(esig->r, 1);

    if (!FIPS_digestinit(&mctx, EVP_sha512()))
	goto err;
    if (!FIPS_digestupdate(&mctx, str1, 20))
	goto err;
    if (FIPS_ecdsa_verify_ctx(ec, &mctx, esig) != 1)
	goto err;

    ret = 1;

    err:
    FIPS_md_ctx_cleanup(&mctx);
    if (ec)
	EC_KEY_free(ec);
    if (esig)
	FIPS_ecdsa_sig_free(esig);
    if (ret == 0)
	    FIPSerr(FIPS_F_FIPS_SELFTEST_ECDSA,FIPS_R_SELFTEST_FAILED);
    return ret;
    }
#endif
