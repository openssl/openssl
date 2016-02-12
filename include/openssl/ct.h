/*
* Public API for Certificate Transparency (CT).
* Written by Rob Percival (robpercival@google.com) for the OpenSSL project.
*/
/* ====================================================================
* Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
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
*/

#ifdef OPENSSL_NO_CT
# error "CT is disabled"
#endif

#ifndef HEADER_CT_H
# define HEADER_CT_H

# include <openssl/safestack.h>
# include <openssl/x509.h>

# ifdef  __cplusplus
extern "C" {
# endif

/* Minimum RSA key size, from RFC6962 */
# define SCT_MIN_RSA_BITS 2048

/* All hashes are SHA256 in v1 of Certificate Transparency */
# define CT_V1_HASHLEN SHA256_DIGEST_LENGTH

typedef enum {
    CT_LOG_ENTRY_TYPE_NOT_SET = -1,
    CT_LOG_ENTRY_TYPE_X509 = 0,
    CT_LOG_ENTRY_TYPE_PRECERT = 1
} ct_log_entry_type_t;

typedef enum {
    SCT_VERSION_NOT_SET = -1,
    SCT_VERSION_V1 = 0
} sct_version_t;

/*******************
 * Data structures *
 *******************/

/* Signed Certificate Timestamp (SCT) */
typedef struct sct_st SCT;
DEFINE_STACK_OF(SCT)

/*****************
 * SCT functions *
 *****************/

/*
 * Creates a new, blank SCT.
 * The caller is responsible for calling SCT_free when finished with the SCT.
 */
SCT *SCT_new(void);

/*
 * Frees the SCT and the underlying data structures.
 */
void SCT_free(SCT *sct);

/*
 * Free a stack of SCTs, and the underlying SCTs themselves.
 * Intended to be compatible with X509V3_EXT_FREE.
 */
void SCT_LIST_free(STACK_OF(SCT) *a);

/*
 * Returns the version of the SCT.
 */
sct_version_t SCT_get_version(const SCT *sct);

/*
 * Set the version of an SCT.
 * Returns 1 on success, 0 if the version is unrecognized.
 */
int SCT_set_version(SCT *sct, sct_version_t version);

/*
 * Returns the log entry type of the SCT.
 */
ct_log_entry_type_t SCT_get_log_entry_type(const SCT *sct);

/*
 * Set the log entry type of an SCT.
 * Returns 1 on success.
 */
int SCT_set_log_entry_type(SCT *sct, ct_log_entry_type_t entry_type);

/*
 * Gets the ID of the log that an SCT came from.
 * Ownership of the log ID remains with the SCT.
 * Returns the length of the log ID.
 */
size_t SCT_get0_log_id(const SCT *sct, unsigned char **log_id);

/*
 * Set the log ID of an SCT to point directly to the *log_id specified.
 * The SCT takes ownership of the specified pointer.
 * Returns 1 on success.
 */
int SCT_set0_log_id(SCT *sct, unsigned char *log_id, size_t log_id_len);

/*
 * Set the log ID of an SCT.
 * This makes a copy of the log_id.
 * Returns 1 on success.
 */
int SCT_set1_log_id(SCT *sct, const unsigned char *log_id, size_t log_id_len);

/*
 * Returns the timestamp for the SCT (epoch time in milliseconds).
 */
uint64_t SCT_get_timestamp(const SCT *sct);

/*
 * Set the timestamp of an SCT (epoch time in milliseconds).
 */
void SCT_set_timestamp(SCT *sct, uint64_t timestamp);

/*
 * Return the NID for the signature used by the SCT.
 * For CT v1, this will be either NID_sha256WithRSAEncryption or
 * NID_ecdsa_with_SHA256 (or NID_undef if incorrect/unset).
 */
int SCT_get_signature_nid(const SCT *sct);

/*
 * Set the signature type of an SCT
 * For CT v1, this should be either NID_sha256WithRSAEncryption or
 * NID_ecdsa_with_SHA256.
 * Returns 1 on success.
 */
int SCT_set_signature_nid(SCT *sct, int nid);

/*
 * Set *ext to point to the extension data for the SCT. ext must not be NULL.
 * The SCT retains ownership of this pointer.
 * Returns length of the data pointed to.
 */
size_t SCT_get0_extensions(const SCT *sct, unsigned char **ext);

/*
 * Set the extensions of an SCT to point directly to the *ext specified.
 * The SCT takes ownership of the specified pointer.
 */
void SCT_set0_extensions(SCT *sct, unsigned char *ext, size_t ext_len);

/*
 * Set the extensions of an SCT.
 * This takes a copy of the ext.
 * Returns 1 on success.
 */
int SCT_set1_extensions(SCT *sct, const unsigned char *ext, size_t ext_len);

/*
 * Set *sig to point to the signature for the SCT. sig must not be NULL.
 * The SCT retains ownership of this pointer.
 * Returns length of the data pointed to.
 */
size_t SCT_get0_signature(const SCT *sct, unsigned char **sig);

/*
 * Set the signature of an SCT to point directly to the *sig specified.
 * The SCT takes ownership of the specified pointer.
 */
void SCT_set0_signature(SCT *sct, unsigned char *sig, size_t sig_len);

/*
 * Set the signature of an SCT to be a copy of the *sig specified.
 * Returns 1 on success.
 */
int SCT_set1_signature(SCT *sct, const unsigned char *sig, size_t sig_len);

/*
 * Pretty-prints an |sct| to |out|.
 * It will be indented by the number of spaces specified by |indent|.
 */
void SCT_print(const SCT *sct, BIO *out, int indent);

/*
 * Pretty-prints an |sct_list| to |out|.
 * It will be indented by the number of spaces specified by |indent|.
 * SCTs will be delimited by |separator|.
 */
void SCT_LIST_print(const STACK_OF(SCT) *sct_list, BIO *out, int indent,
                    const char *separator);

/*********************************
 * SCT parsing and serialisation *
 *********************************/

/*
 * Serialize (to TLS format) a stack of SCTs and return the length.
 * "a" must not be NULL.
 * If "pp" is NULL, just return the length of what would have been serialized.
 * If "pp" is not NULL and "*pp" is null, function will allocate a new pointer
 * for data that caller is responsible for freeing (only if function returns
 * successfully).
 * If "pp" is NULL and "*pp" is not NULL, caller is responsible for ensuring
 * that "*pp" is large enough to accept all of the serializied data.
 * Returns < 0 on error, >= 0 indicating bytes written (or would have been)
 * on success.
 */
int i2o_SCT_LIST(STACK_OF(SCT) *a, unsigned char **pp);

/*
 * Convert TLS format SCT list to a stack of SCTs.
 * If "a" or "*a" is NULL, a new stack will be created that the caller is
 * responsible for freeing (by calling SCT_LIST_free).
 * "**pp" and "*pp" must not be NULL.
 * Upon success, "*pp" will point to after the last bytes read, and a stack
 * will be returned.
 * Upon failure, a NULL pointer will be returned, and the position of "*pp" is
 * not defined.
 */
STACK_OF(SCT) *o2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp,
                            size_t len);

/*
 * Serialize (to DER format) a stack of SCTs and return the length.
 * "a" must not be NULL.
 * If "pp" is NULL, just returns the length of what would have been serialized.
 * If "pp" is not NULL and "*pp" is null, function will allocate a new pointer
 * for data that caller is responsible for freeing (only if function returns
 * successfully).
 * If "pp" is NULL and "*pp" is not NULL, caller is responsible for ensuring
 * that "*pp" is large enough to accept all of the serializied data.
 * Returns < 0 on error, >= 0 indicating bytes written (or would have been)
 * on success.
 */
int i2d_SCT_LIST(STACK_OF(SCT) *a, unsigned char **pp);

/*
 * Parses an SCT list in DER format and returns it.
 * If "a" or "*a" is NULL, a new stack will be created that the caller is
 * responsible for freeing (by calling SCT_LIST_free).
 * "**pp" and "*pp" must not be NULL.
 * Upon success, "*pp" will point to after the last bytes read, and a stack
 * will be returned.
 * Upon failure, a NULL pointer will be returned, and the position of "*pp" is
 * not defined.
 */
STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp,
                            size_t len);

/*
 * Serialize (to TLS format) an |sct| and write it to |out|.
 * If |out| is null, no SCT will be output but the length will still be returned.
 * If |out| points to a null pointer, a string will be allocated to hold the
 * TLS-format SCT. It is the responsibility of the caller to free it.
 * If |out| points to an allocated string, the TLS-format SCT will be written
 * to it.
 * The length of the SCT in TLS format will be returned.
 */
int i2o_SCT(const SCT *sct, unsigned char **out);

/*
 * Parses an SCT in TLS format and returns it.
 * If |psct| is not null, it will end up pointing to the parsed SCT. If it
 * already points to a non-null pointer, the pointer will be free'd.
 * |in| should be a pointer to a string contianing the TLS-format SCT.
 * |in| will be advanced to the end of the SCT if parsing succeeds.
 * |len| should be the length of the SCT in |in|.
 * Returns NULL if an error occurs.
 * If the SCT is an unsupported version, only the SCT's 'sct' and 'sct_len'
 * fields will be populated (with |in| and |len| respectively).
 */
SCT *o2i_SCT(SCT **psct, const unsigned char **in, size_t len);

/*
* Serialize (to TLS format) an |sct| signature and write it to |out|.
* If |out| is null, no signature will be output but the length will be returned.
* If |out| points to a null pointer, a string will be allocated to hold the
* TLS-format signature. It is the responsibility of the caller to free it.
* If |out| points to an allocated string, the signature will be written to it.
* The length of the signature in TLS format will be returned.
*/
int i2o_SCT_signature(const SCT *sct, unsigned char **out);

/*
* Parses an SCT signature in TLS format and populates the |sct| with it.
* |in| should be a pointer to a string contianing the TLS-format signature.
* |in| will be advanced to the end of the signature if parsing succeeds.
* |len| should be the length of the signature in |in|.
* Returns the number of bytes parsed, or a negative integer if an error occurs.
*/
int o2i_SCT_signature(SCT *sct, const unsigned char **in, size_t len);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_CT_strings(void);

/* Error codes for the CT functions. */

/* Function codes. */
# define CT_F_CTLOG_NEW                                   100
# define CT_F_CTLOG_NEW_FROM_BASE64                       101
# define CT_F_CTLOG_NEW_FROM_CONF                         102
# define CT_F_CTLOG_NEW_NULL                              103
# define CT_F_CTLOG_STORE_GET0_LOG_BY_ID                  104
# define CT_F_CTLOG_STORE_LOAD_CTX_NEW                    105
# define CT_F_CTLOG_STORE_LOAD_FILE                       106
# define CT_F_CT_BASE64_DECODE                            107
# define CT_F_CT_EC_KEY_DUP                               108
# define CT_F_CT_KEY_DUP                                  109
# define CT_F_CT_POLICY_EVAL_CTX_GET0_BAD_SCTS            110
# define CT_F_CT_POLICY_EVAL_CTX_GET0_CERT                111
# define CT_F_CT_POLICY_EVAL_CTX_GET0_GOOD_SCTS           112
# define CT_F_CT_POLICY_EVAL_CTX_GET0_ISSUER              113
# define CT_F_CT_POLICY_EVAL_CTX_GET0_LOG_STORE           114
# define CT_F_CT_POLICY_EVAL_CTX_NEW                      115
# define CT_F_CT_POLICY_EVAL_CTX_SET0_BAD_SCTS            116
# define CT_F_CT_POLICY_EVAL_CTX_SET0_CERT                117
# define CT_F_CT_POLICY_EVAL_CTX_SET0_GOOD_SCTS           118
# define CT_F_CT_POLICY_EVAL_CTX_SET0_ISSUER              119
# define CT_F_CT_POLICY_EVAL_CTX_SET0_LOG_STORE           120
# define CT_F_CT_RSA_KEY_DUP                              121
# define CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO          122
# define CT_F_CT_V1_LOG_ID_FROM_PKEY                      123
# define CT_F_CT_VERIFY_AT_LEAST_ONE_GOOD_SCT             124
# define CT_F_CT_VERIFY_NO_BAD_SCTS                       125
# define CT_F_D2I_SCT_LIST                                126
# define CT_F_I2D_SCT_LIST                                127
# define CT_F_I2O_SCT                                     128
# define CT_F_I2O_SCT_LIST                                129
# define CT_F_I2O_SCT_SIGNATURE                           130
# define CT_F_O2I_SCT                                     131
# define CT_F_O2I_SCT_LIST                                132
# define CT_F_O2I_SCT_SIGNATURE                           133
# define CT_F_SCT_CTX_NEW                                 134
# define CT_F_SCT_LIST_VALIDATE                           135
# define CT_F_SCT_NEW                                     136
# define CT_F_SCT_NEW_FROM_BASE64                         137
# define CT_F_SCT_SET0_LOG_ID                             138
# define CT_F_SCT_SET1_EXTENSIONS                         139
# define CT_F_SCT_SET1_LOG_ID                             140
# define CT_F_SCT_SET1_SIGNATURE                          141
# define CT_F_SCT_SET_LOG_ENTRY_TYPE                      142
# define CT_F_SCT_SET_SIGNATURE_NID                       143
# define CT_F_SCT_SET_VERSION                             144
# define CT_F_SCT_SIGNATURE_IS_VALID                      145
# define CT_F_SCT_VALIDATE                                146
# define CT_F_SCT_VERIFY                                  147
# define CT_F_SCT_VERIFY_V1                               148

/* Reason codes. */
# define CT_R_BAD_WRITE                                   100
# define CT_R_BASE64_DECODE_ERROR                         101
# define CT_R_ENCODE_FAILURE                              102
# define CT_R_ILLEGAL_CURVE                               103
# define CT_R_INVALID_LOG_ID_LENGTH                       104
# define CT_R_LOG_CONF_INVALID                            105
# define CT_R_LOG_CONF_INVALID_KEY                        106
# define CT_R_LOG_CONF_MISSING_DESCRIPTION                107
# define CT_R_LOG_CONF_MISSING_KEY                        108
# define CT_R_LOG_KEY_INVALID                             109
# define CT_R_NOT_ENOUGH_SCTS                             110
# define CT_R_RSA_KEY_TOO_WEAK                            111
# define CT_R_SCT_INVALID                                 112
# define CT_R_SCT_INVALID_SIGNATURE                       113
# define CT_R_SCT_LIST_INVALID                            114
# define CT_R_SCT_LOG_ID_MISMATCH                         115
# define CT_R_SCT_NOT_SET                                 116
# define CT_R_SCT_UNSUPPORTED_VERSION                     117
# define CT_R_UNRECOGNIZED_SIGNATURE_NID                  118
# define CT_R_UNSUPPORTED_ALGORITHM                       119
# define CT_R_UNSUPPORTED_ENTRY_TYPE                      120
# define CT_R_UNSUPPORTED_VERSION                         121

#ifdef  __cplusplus
}
#endif
#endif
