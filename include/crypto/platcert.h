#include <openssl/platcert.h>
#include <openssl/bio.h>

int print_notice(BIO *out, USERNOTICE *notice, int indent);

int OSSL_URI_REFERENCE_print(BIO *out, OSSL_URI_REFERENCE *value, int indent);
int OSSL_COMPONENT_CLASS_print(BIO *out, OSSL_COMPONENT_CLASS *value, int indent);
int OSSL_COMMON_CRITERIA_MEASURES_print(BIO *out,
                                        OSSL_COMMON_CRITERIA_MEASURES *value,
                                        int indent);
int OSSL_FIPS_LEVEL_print(BIO *out, OSSL_FIPS_LEVEL *value, int indent);
int OSSL_TBB_SECURITY_ASSERTIONS_print(BIO *out, OSSL_TBB_SECURITY_ASSERTIONS *value, int indent);
int OSSL_MANUFACTURER_ID_print(BIO *out, OSSL_MANUFACTURER_ID *value, int indent);
int OSSL_TCG_SPEC_VERSION_print(BIO *out, OSSL_TCG_SPEC_VERSION *value, int indent);
int OSSL_TCG_PLATFORM_SPEC_print(BIO *out, OSSL_TCG_PLATFORM_SPEC *value);
int OSSL_TCG_CRED_TYPE_print(BIO *out, OSSL_TCG_CRED_TYPE *value, int indent);
int OSSL_COMPONENT_ADDRESS_print(BIO *out, OSSL_COMPONENT_ADDRESS *value, int indent);
int OSSL_PLATFORM_PROPERTY_print(BIO *out, OSSL_PLATFORM_PROPERTY *value, int indent);
int OSSL_HASHED_CERTIFICATE_IDENTIFIER_print(BIO *out,
                                             OSSL_HASHED_CERTIFICATE_IDENTIFIER *value,
                                             int indent);
int OSSL_PCV2_CERTIFICATE_IDENTIFIER_print(BIO *out,
                                           OSSL_PCV2_CERTIFICATE_IDENTIFIER *value,
                                           int indent);
int OSSL_COMPONENT_IDENTIFIER_print(BIO *out, OSSL_COMPONENT_IDENTIFIER *value, int indent);
int OSSL_PLATFORM_CONFIG_print(BIO *out, OSSL_PLATFORM_CONFIG *value, int indent);
int OSSL_PLATFORM_CONFIG_V3_print(BIO *out, OSSL_PLATFORM_CONFIG_V3 *value, int indent);
int OSSL_ISO9000_CERTIFICATION_print(BIO *out, OSSL_ISO9000_CERTIFICATION *value, int indent);
int print_traits(BIO *out, STACK_OF(OSSL_PCV2_TRAIT) *traits, int indent);
