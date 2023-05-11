#include <openssl/x509v3.h>

int print_notice(BIO *out, USERNOTICE *notice, int indent)
{
    int i;
    if (notice->noticeref) {
        NOTICEREF *ref;
        ref = notice->noticeref;
        if (BIO_printf(out, "%*sOrganization: %.*s\n", indent, "",
                   ref->organization->length,
                   ref->organization->data) <= 0) {
            return 0;
        }
        if (BIO_printf(out, "%*sNumber%s: ", indent, "",
                   sk_ASN1_INTEGER_num(ref->noticenos) > 1 ? "s" : "") <= 0) {
            return 0;
        }
        for (i = 0; i < sk_ASN1_INTEGER_num(ref->noticenos); i++) {
            ASN1_INTEGER *num;
            char *tmp;
            num = sk_ASN1_INTEGER_value(ref->noticenos, i);
            if (i && BIO_puts(out, ", ") <= 0) {
                return 0;
            }
            if (num == NULL && BIO_puts(out, "(null)") <= 0)
                return 0;
            else {
                tmp = i2s_ASN1_INTEGER(NULL, num);
                if (tmp == NULL)
                    return 0;
                if (BIO_puts(out, tmp) <= 0) {
                    return 0;
                }
                OPENSSL_free(tmp);
            }
        }
        if (notice->exptext && BIO_puts(out, "\n") <= 0) {
            return 0;
        }
    }
    if (notice->exptext)
        return BIO_printf(out, "%*sExplicit Text: %.*s", indent, "",
                   notice->exptext->length,
                   notice->exptext->data);
    return 1;
}
