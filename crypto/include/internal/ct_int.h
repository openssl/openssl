/* crypto/ct/ct_locl.h */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2015.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */
#ifndef HEADER_CT_LOCL_H
# define HEADER_CT_LOCL_H

# ifdef __cplusplus
extern "C" {
# endif

# ifndef OPENSSL_NO_CT

/* All hashes are currently SHA256 */
#  define SCT_V1_HASHLEN  32
/* Minimum RSA key size, from RFC6962 */
#  define SCT_MIN_RSA_BITS 2048

/*
 * From RFC6962: opaque SerializedSCT<1..2^16-1>; struct { SerializedSCT
 * sct_list <1..2^16-1>; } SignedCertificateTimestampList;
 */

#  define MAX_SCT_SIZE            65535
#  define MAX_SCT_LIST_SIZE       MAX_SCT_SIZE

typedef enum {
    UNSET_ENTRY = -1,
    X509_ENTRY = 0,
    PRECERT_ENTRY = 1
} log_entry_type_t;

typedef enum {
    UNSET_VERSION = -1,
    SCT_V1 = 0
} sct_version_t;

typedef struct {
    sct_version_t version;
    /* If version is not SCT_V1 this contains the encoded SCT */
    unsigned char *sct;
    size_t sct_len;
    /*
     * If version is SCT_V1, fields below contain components of the SCT.
     * "log_id", "ext" and "sig" point to buffers allocated with
     * OPENSSL_malloc().
     */
    unsigned char *log_id;
    size_t log_id_len;

    /*
     * Note, we cannot distinguish between an unset timestamp, and one
     * that is set to 0.  However since CT didn't exist in 1970, no real
     * SCT should ever be set as such.
     */
    uint64_t timestamp;
    unsigned char *ext;
    size_t ext_len;
    unsigned char hash_alg;
    unsigned char sig_alg;
    unsigned char *sig;
    size_t sig_len;
    /* Log entry type */
    log_entry_type_t entry_type;
} SCT;

DECLARE_STACK_OF(SCT)

/*
 * Allocate new SCT.
 * Caller is responsible for calling SCT_free when done.
 */
SCT *SCT_new(void);

/*
 * Free SCT and underlying datastructures.
 */
void SCT_free(SCT *sct);

/*
 * Set the version of an SCT.
 * Returns 1 on success, 0 if the version is unrecognized.
 */
int SCT_set_version(SCT *sct, sct_version_t version);

/*
 * Set the log entry type of an SCT.
 * Returns 1 on success.
 */
int SCT_set_log_entry_type(SCT *sct, log_entry_type_t entry_type);

/*
 * Set the log id of an SCT to point directly to the *log_id specified.
 * The SCT takes ownership of the specified pointer.
 * Returns 1 on success.
 */
int SCT_set0_log_id(SCT *sct, unsigned char *log_id, size_t log_id_len);

/*
 * Set the timestamp of an SCT.
 */
void SCT_set_timestamp(SCT *sct, uint64_t timestamp);

/*
 * Set the signature type of an SCT
 * Currently NID_sha256WithRSAEncryption or NID_ecdsa_with_SHA256.
 * Returns 1 on success.
 */
int SCT_set_signature_nid(SCT *sct, int nid);

/*
 * Set the extensions of an SCT to point directly to the *ext specified.
 * The SCT takes ownership of the specified pointer.
 */
void SCT_set0_extensions(SCT *sct, unsigned char *ext, size_t ext_len);

/*
 * Set the signature of an SCT to point directly to the *sig specified.
 * The SCT takes ownership of the specified pointer.
 */
void SCT_set0_signature(SCT *sct, unsigned char *sig, size_t sig_len);

/*
 * Returns the version of the SCT.
 */
sct_version_t SCT_get_version(const SCT *sct);

/*
 * Returns the log entry type of the SCT.
 */
log_entry_type_t SCT_get_log_entry_type(const SCT *sct);

/*
 * Set *log_id to point to the log id for the SCT. log_id must not be NULL.
 * The SCT retains ownership of this pointer.
 * Returns length of the data pointed to.
 */
size_t SCT_get0_log_id(const SCT *sct, unsigned char **log_id);

/*
 * Returns the timestamp for the SCT.
 */
uint64_t SCT_get_timestamp(const SCT *sct);

/*
 * Return the nid for the signature used by the SCT.
 * Currently NID_sha256WithRSAEncryption or NID_ecdsa_with_SHA256
 * (or NID_undef).
 */
int SCT_get_signature_nid(const SCT *sct);

/*
 * Set *ext to point to the extension data for the SCT. ext must not be NULL.
 * The SCT retains ownership of this pointer.
 * Returns length of the data pointed to.
 */
size_t SCT_get0_extensions(const SCT *sct, unsigned char **ext);

/*
 * Set *sig to point to the signature for the SCT. sig must not be NULL.
 * The SCT retains ownership of this pointer.
 * Returns length of the data pointed to.
 */
size_t SCT_get0_signature(const SCT *sct, unsigned char **sig);


# endif

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_CT_strings(void);

/* Error codes for the CT functions. */

/* Function codes. */
# define CT_F_SCT_NEW                                     100
# define CT_F_SCT_SET0_LOG_ID                             101
# define CT_F_SCT_SET_LOG_ENTRY_TYPE                      102
# define CT_F_SCT_SET_SIGNATURE_NID                       103
# define CT_F_SCT_SET_VERSION                             104

/* Reason codes. */
# define CT_R_INVALID_LOG_ID_LENGTH                       100
# define CT_R_UNRECOGNIZED_SIGNATURE_NID                  101
# define CT_R_UNSUPPORTED_ENTRY_TYPE                      102
# define CT_R_UNSUPPORTED_VERSION                         103

#ifdef  __cplusplus
}
#endif
#endif
