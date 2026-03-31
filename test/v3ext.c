/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "internal/nelem.h"

#include "testutil.h"

#include <crypto/asn1.h>

static const char *infile;

static int test_pathlen(void)
{
    X509 *x = NULL;
    BIO *b = NULL;
    long pathlen;
    int ret = 0;

    if (!TEST_ptr(b = BIO_new_file(infile, "r"))
        || !TEST_ptr(x = PEM_read_bio_X509(b, NULL, NULL, NULL))
        || !TEST_int_eq(pathlen = X509_get_pathlen(x), 6))
        goto end;

    ret = 1;

end:
    BIO_free(b);
    X509_free(x);
    return ret;
}

#ifndef OPENSSL_NO_RFC3779
static int test_asid(void)
{
    ASN1_INTEGER *val1 = NULL, *val2 = NULL;
    ASIdentifiers *asid1 = ASIdentifiers_new(), *asid2 = ASIdentifiers_new(),
                  *asid3 = ASIdentifiers_new(), *asid4 = ASIdentifiers_new();
    int testresult = 0;

    if (!TEST_ptr(asid1)
        || !TEST_ptr(asid2)
        || !TEST_ptr(asid3))
        goto err;

    if (!TEST_ptr(val1 = ASN1_INTEGER_new())
        || !TEST_true(ASN1_INTEGER_set_int64(val1, 64496)))
        goto err;

    if (!TEST_true(X509v3_asid_add_id_or_range(asid1, V3_ASID_ASNUM, val1, NULL)))
        goto err;

    val1 = NULL;
    if (!TEST_ptr(val2 = ASN1_INTEGER_new())
        || !TEST_true(ASN1_INTEGER_set_int64(val2, 64497)))
        goto err;

    if (!TEST_true(X509v3_asid_add_id_or_range(asid2, V3_ASID_ASNUM, val2, NULL)))
        goto err;

    val2 = NULL;
    if (!TEST_ptr(val1 = ASN1_INTEGER_new())
        || !TEST_true(ASN1_INTEGER_set_int64(val1, 64496))
        || !TEST_ptr(val2 = ASN1_INTEGER_new())
        || !TEST_true(ASN1_INTEGER_set_int64(val2, 64497)))
        goto err;

    /*
     * Just tests V3_ASID_ASNUM for now. Could be extended at some point to also
     * test V3_ASID_RDI if we think it is worth it.
     */
    if (!TEST_true(X509v3_asid_add_id_or_range(asid3, V3_ASID_ASNUM, val1, val2)))
        goto err;
    val1 = val2 = NULL;

    /* Actual subsets */
    if (!TEST_true(X509v3_asid_subset(NULL, NULL))
        || !TEST_true(X509v3_asid_subset(NULL, asid1))
        || !TEST_true(X509v3_asid_subset(asid1, asid1))
        || !TEST_true(X509v3_asid_subset(asid2, asid2))
        || !TEST_true(X509v3_asid_subset(asid1, asid3))
        || !TEST_true(X509v3_asid_subset(asid2, asid3))
        || !TEST_true(X509v3_asid_subset(asid3, asid3))
        || !TEST_true(X509v3_asid_subset(asid4, asid1))
        || !TEST_true(X509v3_asid_subset(asid4, asid2))
        || !TEST_true(X509v3_asid_subset(asid4, asid3)))
        goto err;

    /* Not subsets */
    if (!TEST_false(X509v3_asid_subset(asid1, NULL))
        || !TEST_false(X509v3_asid_subset(asid1, asid2))
        || !TEST_false(X509v3_asid_subset(asid2, asid1))
        || !TEST_false(X509v3_asid_subset(asid3, asid1))
        || !TEST_false(X509v3_asid_subset(asid3, asid2))
        || !TEST_false(X509v3_asid_subset(asid1, asid4))
        || !TEST_false(X509v3_asid_subset(asid2, asid4))
        || !TEST_false(X509v3_asid_subset(asid3, asid4)))
        goto err;

    testresult = 1;
err:
    ASN1_INTEGER_free(val1);
    ASN1_INTEGER_free(val2);
    ASIdentifiers_free(asid1);
    ASIdentifiers_free(asid2);
    ASIdentifiers_free(asid3);
    ASIdentifiers_free(asid4);
    return testresult;
}

static struct ip_ranges_st {
    const unsigned int afi;
    const char *ip1;
    const char *ip2;
    int rorp;
} ranges[] = {
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.0.1", IPAddressOrRange_addressPrefix },
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.0.2", IPAddressOrRange_addressRange },
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.0.3", IPAddressOrRange_addressPrefix },
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.0.254", IPAddressOrRange_addressRange },
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.0.255", IPAddressOrRange_addressPrefix },
    { IANA_AFI_IPV4, "192.168.0.1", "192.168.0.255", IPAddressOrRange_addressRange },
    { IANA_AFI_IPV4, "192.168.0.1", "192.168.0.1", IPAddressOrRange_addressPrefix },
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.255.255", IPAddressOrRange_addressPrefix },
    { IANA_AFI_IPV4, "192.168.1.0", "192.168.255.255", IPAddressOrRange_addressRange },
    { IANA_AFI_IPV6, "2001:0db8::0", "2001:0db8::1", IPAddressOrRange_addressPrefix },
    { IANA_AFI_IPV6, "2001:0db8::0", "2001:0db8::2", IPAddressOrRange_addressRange },
    { IANA_AFI_IPV6, "2001:0db8::0", "2001:0db8::3", IPAddressOrRange_addressPrefix },
    { IANA_AFI_IPV6, "2001:0db8::0", "2001:0db8::fffe", IPAddressOrRange_addressRange },
    { IANA_AFI_IPV6, "2001:0db8::0", "2001:0db8::ffff", IPAddressOrRange_addressPrefix },
    { IANA_AFI_IPV6, "2001:0db8::1", "2001:0db8::ffff", IPAddressOrRange_addressRange },
    { IANA_AFI_IPV6, "2001:0db8::1", "2001:0db8::1", IPAddressOrRange_addressPrefix },
    { IANA_AFI_IPV6, "2001:0db8::0:0", "2001:0db8::ffff:ffff", IPAddressOrRange_addressPrefix },
    { IANA_AFI_IPV6, "2001:0db8::1:0", "2001:0db8::ffff:ffff", IPAddressOrRange_addressRange }
};

static int check_addr(IPAddrBlocks *addr, int type)
{
    IPAddressFamily *fam;
    IPAddressOrRange *aorr;

    if (!TEST_int_eq(sk_IPAddressFamily_num(addr), 1))
        return 0;

    fam = sk_IPAddressFamily_value(addr, 0);
    if (!TEST_ptr(fam))
        return 0;

    if (!TEST_int_eq(fam->ipAddressChoice->type, IPAddressChoice_addressesOrRanges))
        return 0;

    if (!TEST_int_eq(sk_IPAddressOrRange_num(fam->ipAddressChoice->u.addressesOrRanges), 1))
        return 0;

    aorr = sk_IPAddressOrRange_value(fam->ipAddressChoice->u.addressesOrRanges, 0);
    if (!TEST_ptr(aorr))
        return 0;

    if (!TEST_int_eq(aorr->type, type))
        return 0;

    return 1;
}

static int test_addr_ranges(void)
{
    IPAddrBlocks *addr = NULL;
    ASN1_OCTET_STRING *ip1 = NULL, *ip2 = NULL;
    size_t i;
    int testresult = 0;

    for (i = 0; i < OSSL_NELEM(ranges); i++) {
        addr = sk_IPAddressFamily_new_null();
        if (!TEST_ptr(addr))
            goto end;
        /*
         * Has the side effect of installing the comparison function onto the
         * stack.
         */
        if (!TEST_true(X509v3_addr_canonize(addr)))
            goto end;

        ip1 = a2i_IPADDRESS(ranges[i].ip1);
        if (!TEST_ptr(ip1))
            goto end;
        if (!TEST_true(ip1->length == 4 || ip1->length == 16))
            goto end;
        ip2 = a2i_IPADDRESS(ranges[i].ip2);
        if (!TEST_ptr(ip2))
            goto end;
        if (!TEST_int_eq(ip2->length, ip1->length))
            goto end;
        if (!TEST_true(memcmp(ip1->data, ip2->data, ip1->length) <= 0))
            goto end;

        if (!TEST_true(X509v3_addr_add_range(addr, ranges[i].afi, NULL, ip1->data, ip2->data)))
            goto end;

        if (!TEST_true(X509v3_addr_is_canonical(addr)))
            goto end;

        if (!check_addr(addr, ranges[i].rorp))
            goto end;

        sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
        addr = NULL;
        ASN1_OCTET_STRING_free(ip1);
        ASN1_OCTET_STRING_free(ip2);
        ip1 = ip2 = NULL;
    }

    testresult = 1;
end:
    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
    ASN1_OCTET_STRING_free(ip1);
    ASN1_OCTET_STRING_free(ip2);
    return testresult;
}

static int test_addr_fam_len(void)
{
    int testresult = 0;
    IPAddrBlocks *addr = NULL;
    IPAddressFamily *f1 = NULL;
    ASN1_OCTET_STRING *ip1 = NULL, *ip2 = NULL;
    unsigned char key[6];
    unsigned int keylen;
    unsigned afi = IANA_AFI_IPV4;

    /* Create the IPAddrBlocks with a good IPAddressFamily */
    addr = sk_IPAddressFamily_new_null();
    if (!TEST_ptr(addr))
        goto end;
    ip1 = a2i_IPADDRESS(ranges[0].ip1);
    if (!TEST_ptr(ip1))
        goto end;
    ip2 = a2i_IPADDRESS(ranges[0].ip2);
    if (!TEST_ptr(ip2))
        goto end;
    if (!TEST_true(X509v3_addr_add_range(addr, ranges[0].afi, NULL, ip1->data, ip2->data)))
        goto end;
    if (!TEST_true(X509v3_addr_is_canonical(addr)))
        goto end;

    /* Create our malformed IPAddressFamily */
    key[0] = (afi >> 8) & 0xFF;
    key[1] = afi & 0xFF;
    key[2] = 0xD;
    key[3] = 0xE;
    key[4] = 0xA;
    key[5] = 0xD;
    keylen = 6;
    if ((f1 = IPAddressFamily_new()) == NULL)
        goto end;
    if (f1->ipAddressChoice == NULL && (f1->ipAddressChoice = IPAddressChoice_new()) == NULL)
        goto end;
    if (f1->addressFamily == NULL && (f1->addressFamily = ASN1_OCTET_STRING_new()) == NULL)
        goto end;
    if (!ASN1_OCTET_STRING_set(f1->addressFamily, key, keylen))
        goto end;

    /* Push and transfer memory ownership to stack */
    if (!sk_IPAddressFamily_push(addr, f1))
        goto end;
    f1 = NULL;

    /* Shouldn't be able to canonize this as the len is > 3*/
    if (!TEST_false(X509v3_addr_canonize(addr)))
        goto end;

    /* Pop and free the new stack element */
    IPAddressFamily_free(sk_IPAddressFamily_pop(addr));

    /* Create a well-formed IPAddressFamily */
    key[0] = (afi >> 8) & 0xFF;
    key[1] = afi & 0xFF;
    key[2] = 0x1;
    keylen = 3;
    if ((f1 = IPAddressFamily_new()) == NULL)
        goto end;
    if (f1->ipAddressChoice == NULL && (f1->ipAddressChoice = IPAddressChoice_new()) == NULL)
        goto end;
    if (f1->addressFamily == NULL && (f1->addressFamily = ASN1_OCTET_STRING_new()) == NULL)
        goto end;
    if (!ASN1_OCTET_STRING_set(f1->addressFamily, key, keylen))
        goto end;

    /* Mark this as inheritance so we skip some of the is_canonize checks */
    f1->ipAddressChoice->type = IPAddressChoice_inherit;

    /* Push and transfer memory ownership to stack */
    if (!sk_IPAddressFamily_push(addr, f1))
        goto end;
    f1 = NULL;

    /* Should be able to canonize now */
    if (!TEST_true(X509v3_addr_canonize(addr)))
        goto end;

    testresult = 1;
end:
    /* Free stack and any memory owned by detached element */
    IPAddressFamily_free(f1);
    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);

    ASN1_OCTET_STRING_free(ip1);
    ASN1_OCTET_STRING_free(ip2);
    return testresult;
}

static struct extvalues_st {
    const char *value;
    int pass;
} extvalues[] = {
    /* No prefix is ok */
    { "sbgp-ipAddrBlock = IPv4:192.0.0.1\n", 1 },
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0/0\n", 1 },
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0/1\n", 1 },
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0/32\n", 1 },
    /* Prefix is too long */
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0/33\n", 0 },
    /* Unreasonably large prefix */
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0/12341234\n", 0 },
    /* Invalid IP addresses */
    { "sbgp-ipAddrBlock = IPv4:192.0.0\n", 0 },
    { "sbgp-ipAddrBlock = IPv4:256.0.0.0\n", 0 },
    { "sbgp-ipAddrBlock = IPv4:-1.0.0.0\n", 0 },
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0.0\n", 0 },
    { "sbgp-ipAddrBlock = IPv3:192.0.0.0\n", 0 },

    /* IPv6 */
    /* No prefix is ok */
    { "sbgp-ipAddrBlock = IPv6:2001:db8::\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001::db8\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:0db8:0000:0000:0000:0000:0000:0000\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/0\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/1\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/32\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:0db8:0000:0000:0000:0000:0000:0000/32\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/128\n", 1 },
    /* Prefix is too long */
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/129\n", 0 },
    /* Unreasonably large prefix */
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/12341234\n", 0 },
    /* Invalid IP addresses */
    /* Not enough blocks of numbers */
    { "sbgp-ipAddrBlock = IPv6:2001:0db8:0000:0000:0000:0000:0000\n", 0 },
    /* Too many blocks of numbers */
    { "sbgp-ipAddrBlock = IPv6:2001:0db8:0000:0000:0000:0000:0000:0000:0000\n", 0 },
    /* First value too large */
    { "sbgp-ipAddrBlock = IPv6:1ffff:0db8:0000:0000:0000:0000:0000:0000\n", 0 },
    /* First value with invalid characters */
    { "sbgp-ipAddrBlock = IPv6:fffg:0db8:0000:0000:0000:0000:0000:0000\n", 0 },
    /* First value is negative */
    { "sbgp-ipAddrBlock = IPv6:-1:0db8:0000:0000:0000:0000:0000:0000\n", 0 }
};

static int test_ext_syntax(void)
{
    size_t i;
    int testresult = 1;

    for (i = 0; i < OSSL_NELEM(extvalues); i++) {
        X509V3_CTX ctx;
        BIO *extbio = BIO_new_mem_buf(extvalues[i].value,
            (int)strlen(extvalues[i].value));
        CONF *conf;
        long eline;

        if (!TEST_ptr(extbio))
            return 0;

        conf = NCONF_new_ex(NULL, NULL);
        if (!TEST_ptr(conf)) {
            BIO_free(extbio);
            return 0;
        }
        if (!TEST_long_gt(NCONF_load_bio(conf, extbio, &eline), 0)) {
            testresult = 0;
        } else {
            X509V3_set_ctx_test(&ctx);
            X509V3_set_nconf(&ctx, conf);

            if (extvalues[i].pass) {
                if (!TEST_true(X509V3_EXT_add_nconf(conf, &ctx, "default",
                        NULL))) {
                    TEST_info("Value: %s", extvalues[i].value);
                    testresult = 0;
                }
            } else {
                ERR_set_mark();
                if (!TEST_false(X509V3_EXT_add_nconf(conf, &ctx, "default",
                        NULL))) {
                    testresult = 0;
                    TEST_info("Value: %s", extvalues[i].value);
                    ERR_clear_last_mark();
                } else {
                    ERR_pop_to_mark();
                }
            }
        }
        BIO_free(extbio);
        NCONF_free(conf);
    }

    return testresult;
}

static int test_addr_subset(void)
{
    int i;
    int ret = 0;
    IPAddrBlocks *addrEmpty = NULL;
    IPAddrBlocks *addr[3] = { NULL, NULL };
    ASN1_OCTET_STRING *ip1[3] = { NULL, NULL };
    ASN1_OCTET_STRING *ip2[3] = { NULL, NULL };
    int sz = OSSL_NELEM(addr);

    for (i = 0; i < sz; ++i) {
        /* Create the IPAddrBlocks with a good IPAddressFamily */
        if (!TEST_ptr(addr[i] = sk_IPAddressFamily_new_null())
            || !TEST_ptr(ip1[i] = a2i_IPADDRESS(ranges[i].ip1))
            || !TEST_ptr(ip2[i] = a2i_IPADDRESS(ranges[i].ip2))
            || !TEST_true(X509v3_addr_add_range(addr[i], ranges[i].afi, NULL,
                ip1[i]->data, ip2[i]->data)))
            goto end;
    }

    ret = TEST_ptr(addrEmpty = sk_IPAddressFamily_new_null())
        && TEST_true(X509v3_addr_subset(NULL, NULL))
        && TEST_true(X509v3_addr_subset(NULL, addr[0]))
        && TEST_true(X509v3_addr_subset(addrEmpty, addr[0]))
        && TEST_true(X509v3_addr_subset(addr[0], addr[0]))
        && TEST_true(X509v3_addr_subset(addr[0], addr[1]))
        && TEST_true(X509v3_addr_subset(addr[0], addr[2]))
        && TEST_true(X509v3_addr_subset(addr[1], addr[2]))
        && TEST_false(X509v3_addr_subset(addr[0], NULL))
        && TEST_false(X509v3_addr_subset(addr[1], addr[0]))
        && TEST_false(X509v3_addr_subset(addr[2], addr[1]))
        && TEST_false(X509v3_addr_subset(addr[0], addrEmpty));
end:
    sk_IPAddressFamily_pop_free(addrEmpty, IPAddressFamily_free);
    for (i = 0; i < sz; ++i) {
        sk_IPAddressFamily_pop_free(addr[i], IPAddressFamily_free);
        ASN1_OCTET_STRING_free(ip1[i]);
        ASN1_OCTET_STRING_free(ip2[i]);
    }
    return ret;
}

/*
 * Test that adding a range with inverted bounds (max, min) is accepted and
 * normalized, and canonize succeeds.
 */
static int test_addr_inverted_range(void)
{
    IPAddrBlocks *addr = NULL;
    ASN1_OCTET_STRING *ip1 = NULL, *ip2 = NULL;
    int testresult = 0;

    addr = sk_IPAddressFamily_new_null();
    if (!TEST_ptr(addr))
        goto end;
    ip1 = a2i_IPADDRESS("192.168.0.10");
    if (!TEST_ptr(ip1) || !TEST_int_eq(ip1->length, 4))
        goto end;
    ip2 = a2i_IPADDRESS("192.168.0.5");
    if (!TEST_ptr(ip2) || !TEST_int_eq(ip2->length, 4))
        goto end;
    /* Pass (max, min) - should be normalized and succeed */
    if (!TEST_true(X509v3_addr_add_range(addr, IANA_AFI_IPV4, NULL, ip1->data, ip2->data)))
        goto end;
    if (!TEST_true(X509v3_addr_canonize(addr)))
        goto end;
    if (!TEST_true(X509v3_addr_is_canonical(addr)))
        goto end;
    testresult = 1;
end:
    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
    ASN1_OCTET_STRING_free(ip1);
    ASN1_OCTET_STRING_free(ip2);
    return testresult;
}

/*
 * Overlapping adds are accepted; canonize rejects a non-canonical list.
 */
static int test_addr_overlap(void)
{
    IPAddrBlocks *addr = NULL;
    ASN1_OCTET_STRING *ip1 = NULL, *ip2 = NULL, *ip3 = NULL, *ip4 = NULL;
    int testresult = 0;

    addr = sk_IPAddressFamily_new_null();
    if (!TEST_ptr(addr))
        goto end;
    ip1 = a2i_IPADDRESS("192.168.0.0");
    ip2 = a2i_IPADDRESS("192.168.0.255");
    if (!TEST_ptr(ip1) || !TEST_ptr(ip2))
        goto end;
    if (!TEST_true(X509v3_addr_add_range(addr, IANA_AFI_IPV4, NULL, ip1->data, ip2->data)))
        goto end;
    ip3 = a2i_IPADDRESS("192.168.0.100");
    ip4 = a2i_IPADDRESS("192.168.1.100");
    if (!TEST_ptr(ip3) || !TEST_ptr(ip4))
        goto end;
    if (!TEST_true(X509v3_addr_add_range(addr, IANA_AFI_IPV4, NULL, ip3->data, ip4->data)))
        goto end;
    if (!TEST_false(X509v3_addr_canonize(addr)))
        goto end;
    /* addr canonize returns 0 on overlap without always pushing an error */
    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
    addr = NULL;
    ASN1_OCTET_STRING_free(ip1);
    ASN1_OCTET_STRING_free(ip2);
    ASN1_OCTET_STRING_free(ip3);
    ASN1_OCTET_STRING_free(ip4);
    ip1 = ip2 = ip3 = ip4 = NULL;

    addr = sk_IPAddressFamily_new_null();
    if (!TEST_ptr(addr))
        goto end;
    ip1 = a2i_IPADDRESS("192.168.0.0");
    ip2 = a2i_IPADDRESS("192.168.0.255");
    ip3 = a2i_IPADDRESS("192.168.0.0");
    if (!TEST_ptr(ip1) || !TEST_ptr(ip2) || !TEST_ptr(ip3))
        goto end;
    if (!TEST_true(X509v3_addr_add_range(addr, IANA_AFI_IPV4, NULL, ip1->data, ip2->data)))
        goto end;
    if (!TEST_true(X509v3_addr_add_prefix(addr, IANA_AFI_IPV4, NULL, ip3->data, 24)))
        goto end;
    if (!TEST_false(X509v3_addr_canonize(addr)))
        goto end;
    testresult = 1;
end:
    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
    ASN1_OCTET_STRING_free(ip1);
    ASN1_OCTET_STRING_free(ip2);
    ASN1_OCTET_STRING_free(ip3);
    ASN1_OCTET_STRING_free(ip4);
    return testresult;
}

/*
 * Test that adding an AS range with inverted bounds (max, min) is accepted
 * and canonize succeeds.
 */
static int test_asid_inverted_range(void)
{
    ASIdentifiers *asid = NULL;
    ASN1_INTEGER *min = NULL, *max = NULL;
    int testresult = 0;

    asid = ASIdentifiers_new();
    if (!TEST_ptr(asid))
        goto end;
    min = ASN1_INTEGER_new();
    max = ASN1_INTEGER_new();
    if (!TEST_ptr(min) || !TEST_ptr(max))
        goto end;
    if (!TEST_true(ASN1_INTEGER_set_int64(min, 100))
        || !TEST_true(ASN1_INTEGER_set_int64(max, 50)))
        goto end;
    /* Pass (min=100, max=50) - should be normalized and succeed */
    if (!TEST_true(X509v3_asid_add_id_or_range(asid, V3_ASID_ASNUM, min, max)))
        goto end;
    min = max = NULL;
    if (!TEST_true(X509v3_asid_canonize(asid)))
        goto end;
    if (!TEST_true(X509v3_asid_is_canonical(asid)))
        goto end;
    testresult = 1;
end:
    ASN1_INTEGER_free(min);
    ASN1_INTEGER_free(max);
    ASIdentifiers_free(asid);
    return testresult;
}

/*
 * Overlapping AS id inside an existing range: adds succeed, canonize fails.
 */
static int test_asid_overlap(void)
{
    ASIdentifiers *asid = NULL;
    ASN1_INTEGER *v1 = NULL, *v2 = NULL, *v3 = NULL;
    int testresult = 0;

    asid = ASIdentifiers_new();
    if (!TEST_ptr(asid))
        goto end;
    v1 = ASN1_INTEGER_new();
    v2 = ASN1_INTEGER_new();
    v3 = ASN1_INTEGER_new();
    if (!TEST_ptr(v1) || !TEST_ptr(v2) || !TEST_ptr(v3))
        goto end;
    if (!TEST_true(ASN1_INTEGER_set_int64(v1, 100))
        || !TEST_true(ASN1_INTEGER_set_int64(v2, 200))
        || !TEST_true(ASN1_INTEGER_set_int64(v3, 150)))
        goto end;
    if (!TEST_true(X509v3_asid_add_id_or_range(asid, V3_ASID_ASNUM, v1, v2)))
        goto end;
    v1 = v2 = NULL;
    if (!TEST_true(X509v3_asid_add_id_or_range(asid, V3_ASID_ASNUM, v3, NULL)))
        goto end;
    v3 = NULL;
    ERR_clear_error();
    if (!TEST_false(X509v3_asid_canonize(asid)))
        goto end;
    {
        unsigned long err = ERR_peek_last_error();

        if (!TEST_true(err != 0))
            goto end;
        if (ERR_GET_REASON(err) != X509V3_R_EXTENSION_VALUE_ERROR)
            TEST_note("Overlap canonize error reason %lu, expected %d",
                (unsigned long)ERR_GET_REASON(err), X509V3_R_EXTENSION_VALUE_ERROR);
    }
    testresult = 1;
end:
    ASN1_INTEGER_free(v1);
    ASN1_INTEGER_free(v2);
    ASN1_INTEGER_free(v3);
    ASIdentifiers_free(asid);
    return testresult;
}

/*
 * Canonize must reject overlapping ranges when data was not built via the
 * add API (e.g. from the wire).  Build one range via API, then push a second
 * overlapping range directly onto the stack and expect canonize to fail.
 */
static int test_canonize_rejects_overlapping_addr(void)
{
    IPAddrBlocks *addr = NULL;
    IPAddressFamily *f = NULL;
    IPAddressOrRanges *aors = NULL;
    IPAddressOrRange *aor = NULL;
    ASN1_OCTET_STRING *ip1 = NULL, *ip2 = NULL;
    unsigned char min4[4] = { 192, 168, 0, 100 };
    unsigned char max4[4] = { 192, 168, 1, 100 };
    int testresult = 0;

    addr = sk_IPAddressFamily_new_null();
    if (!TEST_ptr(addr))
        goto end;
    ip1 = a2i_IPADDRESS("192.168.0.0");
    ip2 = a2i_IPADDRESS("192.168.0.255");
    if (!TEST_ptr(ip1) || !TEST_ptr(ip2))
        goto end;
    if (!TEST_true(X509v3_addr_add_range(addr, IANA_AFI_IPV4, NULL, ip1->data, ip2->data)))
        goto end;
    f = sk_IPAddressFamily_value(addr, 0);
    if (!TEST_ptr(f) || !TEST_ptr(f->ipAddressChoice)
        || f->ipAddressChoice->type != IPAddressChoice_addressesOrRanges
        || !TEST_ptr(aors = f->ipAddressChoice->u.addressesOrRanges))
        goto end;

    aor = IPAddressOrRange_new();
    if (!TEST_ptr(aor))
        goto end;
    aor->type = IPAddressOrRange_addressRange;
    aor->u.addressRange = IPAddressRange_new();
    if (!TEST_ptr(aor->u.addressRange))
        goto end;
    if (aor->u.addressRange->min == NULL
        && !TEST_ptr(aor->u.addressRange->min = ASN1_BIT_STRING_new()))
        goto end;
    if (aor->u.addressRange->max == NULL
        && !TEST_ptr(aor->u.addressRange->max = ASN1_BIT_STRING_new()))
        goto end;
    if (!ASN1_BIT_STRING_set(aor->u.addressRange->min, min4, sizeof(min4))
        || !ASN1_BIT_STRING_set(aor->u.addressRange->max, max4, sizeof(max4)))
        goto end;
    /* Use full bytes (no bits_left); ASN1_BIT_STRING_set leaves flags 0 for full bytes */
    aor->u.addressRange->min->flags &= ~7;
    aor->u.addressRange->max->flags &= ~7;

    if (!sk_IPAddressOrRange_push(aors, aor))
        goto end;
    aor = NULL;

    if (!TEST_false(X509v3_addr_canonize(addr)))
        goto end;
    testresult = 1;
end:
    IPAddressOrRange_free(aor);
    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
    ASN1_OCTET_STRING_free(ip1);
    ASN1_OCTET_STRING_free(ip2);
    return testresult;
}

/*
 * Canonize must reject overlapping AS ids/ranges when data was not built via
 * the add API.  Add one range via API, then push a second overlapping range
 * directly and expect canonize to fail.
 */
static int test_canonize_rejects_overlapping_asid(void)
{
    ASIdentifiers *asid = NULL;
    ASIdOrRange *aor = NULL;
    ASN1_INTEGER *v1 = NULL, *v2 = NULL, *v3 = NULL, *v4 = NULL;
    int testresult = 0;

    asid = ASIdentifiers_new();
    if (!TEST_ptr(asid))
        goto end;
    v1 = ASN1_INTEGER_new();
    v2 = ASN1_INTEGER_new();
    v3 = ASN1_INTEGER_new();
    v4 = ASN1_INTEGER_new();
    if (!TEST_ptr(v1) || !TEST_ptr(v2) || !TEST_ptr(v3) || !TEST_ptr(v4))
        goto end;
    if (!TEST_true(ASN1_INTEGER_set_int64(v1, 100))
        || !TEST_true(ASN1_INTEGER_set_int64(v2, 200))
        || !TEST_true(ASN1_INTEGER_set_int64(v3, 150))
        || !TEST_true(ASN1_INTEGER_set_int64(v4, 250)))
        goto end;
    if (!TEST_true(X509v3_asid_add_id_or_range(asid, V3_ASID_ASNUM, v1, v2)))
        goto end;
    v1 = v2 = NULL;

    aor = ASIdOrRange_new();
    if (!TEST_ptr(aor))
        goto end;
    aor->type = ASIdOrRange_range;
    aor->u.range = ASRange_new();
    if (!TEST_ptr(aor->u.range))
        goto end;
    aor->u.range->min = v3;
    aor->u.range->max = v4;
    v3 = v4 = NULL;

    if (!TEST_ptr(asid->asnum) || asid->asnum->type != ASIdentifierChoice_asIdsOrRanges
        || !TEST_ptr(asid->asnum->u.asIdsOrRanges))
        goto end;
    if (!sk_ASIdOrRange_push(asid->asnum->u.asIdsOrRanges, aor))
        goto end;
    aor = NULL;

    if (!TEST_false(X509v3_asid_canonize(asid)))
        goto end;
    testresult = 1;
end:
    ASIdOrRange_free(aor);
    ASN1_INTEGER_free(v1);
    ASN1_INTEGER_free(v2);
    ASN1_INTEGER_free(v3);
    ASN1_INTEGER_free(v4);
    ASIdentifiers_free(asid);
    return testresult;
}

#endif /* OPENSSL_NO_RFC3779 */

OPT_TEST_DECLARE_USAGE("cert.pem\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(infile = test_get_argument(0)))
        return 0;

    ADD_TEST(test_pathlen);
#ifndef OPENSSL_NO_RFC3779
    ADD_TEST(test_asid);
    ADD_TEST(test_addr_ranges);
    ADD_TEST(test_addr_inverted_range);
    ADD_TEST(test_addr_overlap);
    ADD_TEST(test_canonize_rejects_overlapping_addr);
    ADD_TEST(test_canonize_rejects_overlapping_asid);
    ADD_TEST(test_ext_syntax);
    ADD_TEST(test_addr_fam_len);
    ADD_TEST(test_addr_subset);
    ADD_TEST(test_asid_overlap);
    ADD_TEST(test_asid_inverted_range);
#endif /* OPENSSL_NO_RFC3779 */
    return 1;
}
