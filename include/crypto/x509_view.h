/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_CRYPTO_X509_VIEW_H)
#define OSSL_CRYPTO_X509_VIEW_H

#include <stddef.h>
#include <stdint.h>

#include "internal/bytestring.h"

/**
 * @struct x509_view
 * @brief A one-pass view of a DER encoded certificate.  Every CBS is a
 * whole element, tag and length included, in the caller's encoding, which
 * must outlive the structure.
 */
struct x509_view {
    CBS tbs; /**< The TBSCertificate */
    int version; /**< The version as encoded, 0 for v1 to 2 for v3 */
    CBS serial; /**< The serialNumber INTEGER */
    /** The TBSCertificate's signature AlgorithmIdentifier */
    CBS inner_sig_alg;
    CBS issuer; /**< The issuer Name */
    CBS not_before; /**< The notBefore Time */
    int64_t not_before_posix; /**< notBefore as a POSIX time */
    CBS not_after; /**< The notAfter Time */
    int64_t not_after_posix; /**< notAfter as a POSIX time */
    CBS subject; /**< The subject Name */
    CBS spki; /**< The SubjectPublicKeyInfo */
    int has_issuer_uid; /**< Whether issuerUniqueID is present */
    CBS issuer_uid; /**< The issuerUniqueID, when present */
    int has_subject_uid; /**< Whether subjectUniqueID is present */
    CBS subject_uid; /**< The subjectUniqueID, when present */
    CBS sig_alg; /**< The Certificate's signatureAlgorithm */
    int sig_nid; /**< The NID of sig_alg's algorithm, or NID_undef */
    int sig_alg_matches; /**< Whether sig_alg and inner_sig_alg are equal */
    int self_issued; /**< Whether issuer and subject are equal */
    CBS signature; /**< The signatureValue BIT STRING */

    CBS extensions; /**< The Extensions SEQUENCE, empty when absent */
    int has_basic_constraints; /**< Whether basicConstraints was decoded */
    int ca; /**< The basicConstraints cA */
    int64_t path_len; /**< The basicConstraints pathLenConstraint, or -1 */
    int has_key_usage; /**< Whether keyUsage was decoded */
    uint32_t key_usage; /**< The named keyUsage bits, as KU_ values */
    int has_ext_key_usage; /**< Whether extendedKeyUsage was decoded */
    /** The known extendedKeyUsage purposes, as XKU_ values */
    uint32_t ext_key_usage;
    int has_san; /**< Whether subjectAltName was decoded */
    CBS san; /**< The subjectAltName GeneralNames */
    size_t san_count; /**< The number of GeneralNames in san */
    int has_skid; /**< Whether subjectKeyIdentifier was decoded */
    CBS skid; /**< The subjectKeyIdentifier OCTET STRING */
    int has_akid; /**< Whether authorityKeyIdentifier was decoded */
    int has_akid_keyid; /**< Whether keyIdentifier is present */
    CBS akid_keyid; /**< The authorityKeyIdentifier keyIdentifier */
    int has_akid_issuer; /**< Whether authorityCertIssuer is present */
    CBS akid_issuer; /**< The authorityKeyIdentifier authorityCertIssuer */
    int has_akid_serial; /**< Whether authorityCertSerialNumber is present */
    /** The authorityKeyIdentifier authorityCertSerialNumber */
    CBS akid_serial;
    int has_nc; /**< Whether nameConstraints was decoded */
    CBS nc; /**< The NameConstraints */
    /** X509_VIEW_EXT_ bits of extensions present */
    uint32_t extensions_present;
    /**
     * Whether a critical extension is neither decoded nor recorded in
     * extensions_present
     */
    int has_unhandled_critical;
    int has_malformed_extension; /**< Whether an extension is malformed */
};

#define X509_VIEW_EXT_NAME_CONSTRAINTS (1U << 0) /**< nameConstraints */
#define X509_VIEW_EXT_CERTIFICATE_POLICIES (1U << 1) /**< certificatePolicies */
#define X509_VIEW_EXT_POLICY_MAPPINGS (1U << 2) /**< policyMappings */
#define X509_VIEW_EXT_POLICY_CONSTRAINTS (1U << 3) /**< policyConstraints */
#define X509_VIEW_EXT_INHIBIT_ANY_POLICY (1U << 4) /**< inhibitAnyPolicy */
#define X509_VIEW_EXT_IP_ADDR_BLOCKS (1U << 5) /**< sbgp-ipAddrBlock */
#define X509_VIEW_EXT_AUTONOMOUS_SYS_IDS (1U << 6) /**< sbgp-autonomousSysNum */

/** The X509_VIEW_EXT_ bits of the policy extensions. */
#define X509_VIEW_EXT_POLICY                                            \
    (X509_VIEW_EXT_CERTIFICATE_POLICIES | X509_VIEW_EXT_POLICY_MAPPINGS \
        | X509_VIEW_EXT_POLICY_CONSTRAINTS | X509_VIEW_EXT_INHIBIT_ANY_POLICY)

/**
 * @brief Parses der into cert, rejecting an encoded v1, a version past v3,
 * unique identifiers in a v1 certificate, extensions outside a v3
 * certificate and trailing octets.  The view decodes basicConstraints,
 * keyUsage, extendedKeyUsage, subjectAltName, subjectKeyIdentifier,
 * authorityKeyIdentifier and nameConstraints, and records the presence
 * of each X509_VIEW_EXT_ extension in extensions_present.  A critical
 * extension that is neither is recorded in has_unhandled_critical.  An
 * empty Extensions, a repeated extension and a decoded extension that is
 * malformed are recorded in has_malformed_extension.
 * @param der the DER encoded certificate, which must outlive cert
 * @param der_len the length of der
 * @param cert the view to fill in
 * @returns 1 if der is accepted, 0 otherwise
 */
int x509_view_parse(const uint8_t *der, size_t der_len, struct x509_view *cert);

/**
 * @brief Sets *out to the certificate's TBSCertificate, tag and length
 * included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1
 */
int x509_view_get_tbs(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's serialNumber, tag and length included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1
 */
int x509_view_get_serial(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's TBSCertificate signature
 * AlgorithmIdentifier, tag and length included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1
 */
int x509_view_get_tbs_sig_alg(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's issuer Name, tag and length included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1
 */
int x509_view_get_issuer(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's notBefore Time, tag and length
 * included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1
 */
int x509_view_get_not_before(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's notAfter Time, tag and length included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1
 */
int x509_view_get_not_after(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's subject Name, tag and length included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1
 */
int x509_view_get_subject(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's SubjectPublicKeyInfo, tag and length
 * included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1
 */
int x509_view_get_spki(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's signatureAlgorithm, tag and length
 * included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1
 */
int x509_view_get_sig_alg(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's signatureValue, tag and length
 * included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1
 */
int x509_view_get_signature(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's issuerUniqueID, tag and length
 * included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1, or 0 if the certificate has no issuerUniqueID
 */
int x509_view_get_issuer_uid(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's subjectUniqueID, tag and length
 * included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1, or 0 if the certificate has no subjectUniqueID
 */
int x509_view_get_subject_uid(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's subjectAltName GeneralNames, tag and
 * length included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1, or 0 if the certificate has no subjectAltName GeneralNames
 */
int x509_view_get_san(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's subjectKeyIdentifier, tag and length
 * included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1, or 0 if the certificate has no subjectKeyIdentifier
 */
int x509_view_get_skid(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's authorityKeyIdentifier keyIdentifier,
 * tag and length included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1, or 0 if the certificate has no authorityKeyIdentifier
 *          keyIdentifier
 */
int x509_view_get_akid_keyid(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's authorityKeyIdentifier
 * authorityCertIssuer, tag and length included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1, or 0 if the certificate has no authorityKeyIdentifier
 *          authorityCertIssuer
 */
int x509_view_get_akid_issuer(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's authorityKeyIdentifier
 * authorityCertSerialNumber, tag and length included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1, or 0 if the certificate has no authorityKeyIdentifier
 *          authorityCertSerialNumber
 */
int x509_view_get_akid_serial(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's NameConstraints, tag and length
 * included.
 * @param view the view
 * @param out the CBS to set
 * @returns 1, or 0 if the certificate has no NameConstraints
 */
int x509_view_get_name_constraints(const struct x509_view *view, CBS *out);

/**
 * @brief Sets *out to the certificate's Extensions SEQUENCE, tag and length
 * included, or to an empty CBS when the certificate has none.
 * @param view the view
 * @param out the CBS to set
 * @returns 1
 */
int x509_view_get_extensions(const struct x509_view *view, CBS *out);

/**
 * @brief Removes the next GeneralName from names, a SEQUENCE OF
 * GeneralName's contents, setting *out_type to its GEN_ type and *out to
 * its content octets.
 * @param names the GeneralNames contents to read from
 * @param out_type set to the GEN_ type of the name
 * @param out set to the content octets of the name
 * @returns 1 on success, 0 when names is empty or the next element is not
 *          a GeneralName
 */
int x509_view_next_general_name(CBS *names, int *out_type, CBS *out);

/**
 * @brief Removes the next Extension from exts, the contents of an
 * Extensions SEQUENCE, setting *out_oid to its extnID's content octets,
 * *out_critical to its criticality and *out_value to the content octets
 * of its extnValue.
 * @param exts the Extensions contents to read from
 * @param out_oid set to the content octets of the extnID
 * @param out_critical set to the criticality
 * @param out_value set to the content octets of the extnValue
 * @returns 1 on success, 0 when exts is empty or the next element is not
 *          an Extension
 */
int x509_view_next_extension(CBS *exts, CBS *out_oid, int *out_critical,
    CBS *out_value);

/**
 * @brief Returns whether the certificate's basicConstraints has cA set.
 * @param view the view
 * @returns 1 if the certificate's basicConstraints has cA set, 0 if not
 */
int x509_view_is_ca(const struct x509_view *view);

/**
 * @brief Returns whether the certificate's issuer and subject are equal.
 * @param view the view
 * @returns 1 if the certificate's issuer and subject are equal, 0 if not
 */
int x509_view_is_self_issued(const struct x509_view *view);

/**
 * @brief Returns whether the certificate has a critical extension the view
 * neither decodes nor records in extensions_present.
 * @param view the view
 * @returns 1 if the certificate has such an extension, 0 if not
 */
int x509_view_has_unhandled_critical(const struct x509_view *view);

/**
 * @brief Returns whether the certificate has an empty Extensions, a repeated
 * extension or a malformed decoded extension.
 * @param view the view
 * @returns 1 if the certificate has an empty Extensions, a repeated extension
 *          or a malformed decoded extension, 0 if not
 */
int x509_view_has_malformed_extension(const struct x509_view *view);

/**
 * @brief Returns whether the certificate's two signature AlgorithmIdentifiers
 * are equal.
 * @param view the view
 * @returns 1 if the certificate's two signature AlgorithmIdentifiers are equal,
 *          0 if not
 */
int x509_view_sig_algs_match(const struct x509_view *view);

/**
 * @brief The X509_VIEW_EXT_ bits in mask of extensions the certificate
 * carries.
 * @param view the view
 * @param mask the X509_VIEW_EXT_ bits to ask about
 * @returns the bits of mask for extensions present
 */
uint32_t x509_view_extensions_present(const struct x509_view *view,
    uint32_t mask);

/**
 * @brief Returns the certificate's notBefore as a POSIX time.
 * @param view the view
 * @returns the POSIX time
 */
int64_t x509_view_not_before_posix(const struct x509_view *view);

/**
 * @brief Returns the certificate's notAfter as a POSIX time.
 * @param view the view
 * @returns the POSIX time
 */
int64_t x509_view_not_after_posix(const struct x509_view *view);

/**
 * @brief Returns the NID of the certificate's signatureAlgorithm.
 * @param view the view
 * @returns the NID, or NID_undef if the algorithm is unknown
 */
int x509_view_sig_nid(const struct x509_view *view);

/**
 * @brief Returns the certificate's version.
 * @param view the view
 * @returns 0 for v1, 1 for v2 or 2 for v3
 */
int x509_view_version(const struct x509_view *view);

/**
 * @brief Sets *out to the certificate's keyUsage bits, as KU_ values.
 * @param view the view
 * @param out the value to set
 * @returns 1, or 0 if the certificate has no keyUsage
 */
int x509_view_key_usage(const struct x509_view *view, uint32_t *out);

/**
 * @brief Sets *out to the certificate's known extendedKeyUsage purposes, as
 * XKU_ values.
 * @param view the view
 * @param out the value to set
 * @returns 1, or 0 if the certificate has no extendedKeyUsage
 */
int x509_view_ext_key_usage(const struct x509_view *view, uint32_t *out);

/**
 * @brief Sets *out to the certificate's basicConstraints pathLenConstraint.
 * @param view the view
 * @param out the value to set
 * @returns 1, or 0 if the certificate has no pathLenConstraint
 */
int x509_view_path_len(const struct x509_view *view, int64_t *out);

#endif /* !defined(OSSL_CRYPTO_X509_VIEW_H) */
