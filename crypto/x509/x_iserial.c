#include <openssl/x509v3.h>

int i2r_ISSUER_SERIAL(X509V3_EXT_METHOD *method,
                      ISSUER_SERIAL *iss,
                      BIO *out, int indent)
{
    if (iss->issuer != NULL) {
        BIO_printf(out, "%*sIssuer Names:\n", indent, "");
        ossl_print_gens(out, iss->issuer, indent);
        BIO_puts(out, "\n");
    }
    if (iss->serial != NULL) {
        BIO_printf(out, "%*sIssuer Serial: ", indent, "");
        if (i2a_ASN1_INTEGER(out, iss->serial) <= 0)
            return 0;
        BIO_puts(out, "\n");
    }
    if (iss->issuerUID != NULL) {
        BIO_printf(out, "%*sIssuer UID: ", indent, "");
        if (i2a_ASN1_STRING(out, iss->issuerUID, V_ASN1_BIT_STRING) <= 0)
            return 0;
        BIO_puts(out, "\n");
    }
    return 1;
}
