#include <openssl/evp.h>
#include "lms_local.h"

const uint16_t OSSL_LMS_D_PBLC          = 0x8080;
const uint16_t OSSL_LMS_D_MESG          = 0x8181;
const uint16_t OSSL_LMS_D_LEAF          = 0x8282;
const uint16_t OSSL_LMS_D_INTR          = 0x8383;
const uint16_t OSSL_LMS_D_C             = 0xFFFD;
const uint16_t OSSL_LMS_D_CHILD_SEED    = 0xFFFE;
const uint16_t OSSL_LMS_D_CHILD_I       = 0xFFFF;

int ossl_lms_hash(EVP_MD_CTX *ctx,
                  const unsigned char *in1, size_t in1len,
                  const unsigned char *in2, size_t in2len,
                  unsigned char *out)
{
    return EVP_DigestInit_ex2(ctx, NULL, NULL)
           && EVP_DigestUpdate(ctx, in1, in1len)
           && (in2 == NULL || EVP_DigestUpdate(ctx, in2, in2len))
           && EVP_DigestFinal_ex(ctx, out, NULL);
}
