#include <openssl/platcert.h>
#include <openssl/bio.h>

int print_notice(BIO *out, USERNOTICE *notice, int indent);

int URI_REFERENCE_print (BIO *out, URI_REFERENCE *value, int indent);
int COMPONENT_CLASS_print (BIO *out, COMPONENT_CLASS *value, int indent);
int COMMON_CRITERIA_MEASURES_print (BIO *out, COMMON_CRITERIA_MEASURES *value, int indent);
int FIPS_LEVEL_print (BIO *out, FIPS_LEVEL *value, int indent);
int TBB_SECURITY_ASSERTIONS_print (BIO *out, TBB_SECURITY_ASSERTIONS *value, int indent);
int MANUFACTURER_ID_print (BIO *out, MANUFACTURER_ID *value, int indent);
int TCG_SPEC_VERSION_print (BIO *out, TCG_SPEC_VERSION *value, int indent);
int TCG_PLATFORM_SPEC_print (BIO *out, TCG_PLATFORM_SPEC *value);
int TCG_CRED_TYPE_print (BIO *out, TCG_CRED_TYPE *value, int indent);
int COMPONENT_ADDRESS_print (BIO *out, COMPONENT_ADDRESS *value, int indent);
int PLATFORM_PROPERTY_print (BIO *out, PLATFORM_PROPERTY *value, int indent);
int ATTRIBUTE_CERTIFICATE_IDENTIFIER_print (BIO *out, ATTRIBUTE_CERTIFICATE_IDENTIFIER *value, int indent);
int CERTIFICATE_IDENTIFIER_print (BIO *out, CERTIFICATE_IDENTIFIER *value, int indent);
int COMPONENT_IDENTIFIER_print (BIO *out, COMPONENT_IDENTIFIER *value, int indent);
int PLATFORM_CONFIG_print (BIO *out, PLATFORM_CONFIG *value, int indent);
