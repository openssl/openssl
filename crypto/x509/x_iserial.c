#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/asn1t.h>

ASN1_SEQUENCE(OSSL_ISSUER_SERIAL) = {
    ASN1_SIMPLE(OSSL_ISSUER_SERIAL, issuer, GENERAL_NAMES),
    ASN1_EMBED(OSSL_ISSUER_SERIAL, serial, ASN1_INTEGER),
    ASN1_OPT(OSSL_ISSUER_SERIAL, issuerUID, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(OSSL_ISSUER_SERIAL)

IMPLEMENT_ASN1_FUNCTIONS(OSSL_ISSUER_SERIAL)

int i2r_ISSUER_SERIAL(X509V3_EXT_METHOD *method,
                      OSSL_ISSUER_SERIAL *iss,
                      BIO *out, int indent)
{
    if (iss->issuer != NULL) {
        BIO_printf(out, "%*sIssuer Names:\n", indent, "");
        ossl_print_gens(out, iss->issuer, indent);
        BIO_puts(out, "\n");
    }
    BIO_printf(out, "%*sIssuer Serial: ", indent, "");
    if (i2a_ASN1_INTEGER(out, &iss->serial) <= 0)
        return 0;
    BIO_puts(out, "\n");
    if (iss->issuerUID != NULL) {
        BIO_printf(out, "%*sIssuer UID: ", indent, "");
        if (i2a_ASN1_STRING(out, iss->issuerUID, V_ASN1_BIT_STRING) <= 0)
            return 0;
        BIO_puts(out, "\n");
    }
    return 1;
}
