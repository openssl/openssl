/* crypto/crypto.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* If you are happy to use the assmbler version of bn/bn_mulw.c, define
 * BN_ASM */
#ifndef BN_ASM
#undef BN_ASM
#define X86_ASM
#endif

#ifndef DES_ASM
#undef DES_ASM
#endif

#ifndef BF_ASM
#undef BF_ASM
#endif

/* The following defines are only to break the compiles into chunks.
 * If you wish to not compile some sections, use the 'NO_XXX' macros
 */
#ifndef CRYPTO_SUBSET
/* Define all subset symbols. */
#define CRYPTO_LIB_SUBSET
#define CRYPTO_ASN1_SUBSET
#define CRYPTO_BN_SUBSET
#define CRYPTO_BUFFER_SUBSET
#define CRYPTO_BIO_SUBSET
#define CRYPTO_CONF_SUBSET
#define CRYPTO_DES_SUBSET
#define CRYPTO_DH_SUBSET
#define CRYPTO_DSA_SUBSET
#define CRYPTO_ERROR_SUBSET
#define CRYPTO_EVP_SUBSET
#define CRYPTO_IDEA_SUBSET
#define CRYPTO_LHASH_SUBSET
#define CRYPTO_MD_SUBSET
#define CRYPTO_MDC2_SUBSET
#define CRYPTO_METH_SUBSET
#define CRYPTO_OBJECTS_SUBSET
#define CRYPTO_PEM_SUBSET
#define CRYPTO_RAND_SUBSET
#define CRYPTO_RC_SUBSET
#define CRYPTO_BLOWFISH_SUBSET
#define CRYPTO_CAST_SUBSET
#define CRYPTO_RSA_SUBSET
#define CRYPTO_SHA_SUBSET
#define CRYPTO_HMAC_SUBSET
#define CRYPTO_SHA1_SUBSET
#define CRYPTO_STACK_SUBSET
#define CRYPTO_TXT_DB_SUBSET
#define CRYPTO_X509_SUBSET
#define CRYPTO_PKCS7_SUBSET
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USE_SOCKETS
#include "../e_os.h"

#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/stack.h>
#include <openssl/lhash.h>

#include <openssl/err.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/txt_db.h>

#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>

#ifdef CRYPTO_LIB_SUBSET
#include "cryptlib.c"
#include "mem.c"
#include "cversion.c"
#endif

#ifdef CRYPTO_ASN1_SUBSET
#include "asn1/a_meth.c"
#include "asn1/a_bitstr.c"
#include "asn1/a_d2i_fp.c"
#include "asn1/a_dup.c"
#include "asn1/a_hdr.c"
#include "asn1/a_i2d_fp.c"
#include "asn1/a_int.c"
#include "asn1/a_bool.c"
#include "asn1/a_bytes.c"
#include "asn1/a_object.c"
#include "asn1/a_octet.c"
#include "asn1/a_print.c"
#include "asn1/a_set.c"
#include "asn1/a_sign.c"
#include "asn1/a_type.c"
#include "asn1/a_utctm.c"
#include "asn1/a_verify.c"
#include "asn1/a_digest.c"
#include "asn1/asn1_err.c"
#include "asn1/asn1_lib.c"
#include "asn1/asn1_par.c"
#ifndef NO_DH
#include "asn1/d2i_dhp.c"
#include "asn1/i2d_dhp.c"
#endif
#ifndef NO_DSA
#include "asn1/d2i_dsap.c"
#include "asn1/i2d_dsap.c"
#include "asn1/d2i_s_pr.c"
#include "asn1/i2d_s_pr.c"
#include "asn1/d2i_s_pu.c"
#include "asn1/i2d_s_pu.c"
#endif
#ifndef NO_RSA
#include "asn1/d2i_r_pr.c"
#include "asn1/i2d_r_pr.c"
#include "asn1/d2i_r_pu.c"
#include "asn1/i2d_r_pu.c"
#include "asn1/n_pkey.c"
#endif
#include "asn1/d2i_pr.c"
#include "asn1/d2i_pu.c"
#include "asn1/i2d_pr.c"
#include "asn1/i2d_pu.c"
#include "asn1/f_int.c"
#include "asn1/f_string.c"
#include "asn1/p7_dgst.c"
#include "asn1/p7_enc.c"
#include "asn1/p7_enc_c.c"
#include "asn1/p7_evp.c"
#include "asn1/p7_i_s.c"
#include "asn1/p7_lib.c"
#include "asn1/p7_recip.c"
#include "asn1/p7_s_e.c"
#include "asn1/p7_signd.c"
#include "asn1/p7_signi.c"
#include "asn1/t_pkey.c"
#include "asn1/t_req.c"
#include "asn1/t_x509.c"
#include "asn1/x_algor.c"
#include "asn1/x_attrib.c"
#include "asn1/x_exten.c"
#include "asn1/x_cinf.c"
#include "asn1/x_crl.c"
#include "asn1/x_info.c"
#include "asn1/x_name.c"
#include "asn1/x_pkey.c"
#include "asn1/x_pubkey.c"
#include "asn1/x_req.c"
#include "asn1/x_sig.c"
#include "asn1/x_spki.c"
#include "asn1/x_val.c"
#include "asn1/x_x509.c"
#endif

#ifdef CRYPTO_BN_SUBSET
#include "bn/bn_add.c"
#include "bn/bn_div.c"
#include "bn/bn_exp.c"
#include "bn/bn_mont.c"
#include "bn/bn_recp.c"
#include "bn/bn_gcd.c"
#include "bn/bn_lib.c"
#include "bn/bn_mod.c"
#include "bn/bn_mul.c"
#ifndef BN_ASM
#include "bn/bn_mulw.c"
#endif
#include "bn/bn_prime.c"
#include "bn/bn_rand.c"
#include "bn/bn_shift.c"
#include "bn/bn_sqr.c"
#include "bn/bn_sub.c"
#include "bn/bn_word.c"
#include "bn/bn_print.c"
#include "bn/bn_err.c"
#include "bn/bn_blind.c"
#endif

#ifdef CRYPTO_BIO_SUBSET
#include "bio/bf_buff.c"
#include "bio/bf_null.c"
#include "bio/bf_nbio.c"
#include "bio/bio_cb.c"
#include "bio/bio_lib.c"
#include "bio/bss_fd.c"
#include "bio/bss_file.c"
#include "bio/bss_mem.c"
#include "bio/bss_null.c"
#ifdef VMS
#include "bio/bss_rtcp.c"
#endif
#include "bio/bss_sock.c"
#include "bio/bss_conn.c"
#include "bio/bss_acpt.c"
#include "bio/b_sock.c"
#include "bio/b_print.c"
#include "bio/b_dump.c"
#include "bio/bio_err.c"
#endif

#ifdef CRYPTO_BUFFER_SUBSET
#include "buffer/buf_err.c"
#include "buffer/buffer.c"
#endif

#ifdef CRYPTO_CONF_SUBSET
#include "conf/conf.c"
#include "conf/conf_err.c"
#endif

#ifdef CRYPTO_DES_SUBSET
#include "des/read_pwd.c"
#ifndef NO_DES
#ifndef DES_ASM
#include "des/fcrypt_b.c"
#include "des/des_enc.c"
#endif
#include "des/cbc_cksm.c"
#include "des/xcbc_enc.c"
#include "des/cbc_enc.c"
#include "des/cfb64ede.c"
#include "des/cfb64enc.c"
#include "des/cfb_enc.c"
#include "des/ecb3_enc.c"
#include "des/ecb_enc.c"
#include "des/enc_read.c"
#include "des/enc_writ.c"
#include "des/fcrypt.c"
#include "des/ofb64ede.c"
#include "des/ofb64enc.c"
#include "des/ofb_enc.c"
#include "des/pcbc_enc.c"
#include "des/qud_cksm.c"
#include "des/rand_key.c"
#include "des/read2pwd.c"
#include "des/rpc_enc.c"
#include "des/set_key.c"
#include "des/str2key.c"
#include "des/supp.c"
#endif
#endif

#ifdef CRYPTO_DH_SUBSET
#ifndef NO_DH
#include "dh/dh_check.c"
#include "dh/dh_err.c"
#include "dh/dh_gen.c"
#include "dh/dh_key.c"
#include "dh/dh_lib.c"
#endif
#endif

#ifdef CRYPTO_DSA_SUBSET
#ifndef NO_DSA
#include "dsa/dsa_gen.c"
#include "dsa/dsa_key.c"
#include "dsa/dsa_lib.c"
#include "dsa/dsa_sign.c"
#include "dsa/dsa_vrf.c"
#include "dsa/dsa_err.c"
#endif
#endif

#ifdef CRYPTO_ERROR_SUBSET
#include "err/err.c"
#include "err/err_all.c"
#include "err/err_prn.c"
#endif

#ifdef CRYPTO_EVP_SUBSET
#include "evp/bio_md.c"
#include "evp/bio_b64.c"
#include "evp/bio_enc.c"
#include "evp/c_all.c"
#include "evp/digest.c"
#ifndef NO_DES
#include "evp/e_cbc_3d.c"
#include "evp/e_cfb_3d.c"
#include "evp/e_ecb_3d.c"
#include "evp/e_ofb_3d.c"
#include "evp/e_cbc_d.c"
#include "evp/e_cfb_d.c"
#include "evp/e_xcbc_d.c"
#include "evp/e_ecb_d.c"
#include "evp/e_ofb_d.c"
#endif
#ifndef NO_IDEA
#include "evp/e_cbc_i.c"
#include "evp/e_cfb_i.c"
#include "evp/e_ecb_i.c"
#include "evp/e_ofb_i.c"
#endif
#ifndef NO_RC2
#include "evp/e_cbc_r2.c"
#include "evp/e_cfb_r2.c"
#include "evp/e_ecb_r2.c"
#include "evp/e_ofb_r2.c"
#endif
#ifndef NO_BF
#include "evp/e_cbc_bf.c"
#include "evp/e_cfb_bf.c"
#include "evp/e_ecb_bf.c"
#include "evp/e_ofb_bf.c"
#endif
#ifndef NO_CAST
#include "evp/e_cbc_c.c"
#include "evp/e_cfb_c.c"
#include "evp/e_ecb_c.c"
#include "evp/e_ofb_c.c"
#endif
#ifndef NO_RC4
#include "evp/e_rc4.c"
#endif
#include "evp/names.c"
#include "evp/e_null.c"
#include "evp/encode.c"
#include "evp/evp_enc.c"
#include "evp/evp_err.c"
#include "evp/evp_key.c"
#include "evp/m_null.c"
#include "evp/p_lib.c"
#ifndef NO_RSA
#include "evp/p_open.c"
#include "evp/p_seal.c"
#endif
#include "evp/p_sign.c"
#include "evp/p_verify.c"
#endif

#ifdef CRYPTO_IDEA_SUBSET
#ifndef NO_IDEA
#include "idea/i_cbc.c"
#include "idea/i_cfb64.c"
#include "idea/i_ecb.c"
#include "idea/i_ofb64.c"
#include "idea/i_skey.c"
#endif
#endif

#ifdef CRYPTO_BLOWFISH_SUBSET
#ifndef NO_BF
#include "bf/bf_cfb64.c"
#include "bf/bf_ecb.c"
#ifndef BF_ASM
#include "bf/bf_enc.c"
#endif
#include "bf/bf_ofb64.c"
#include "bf/bf_skey.c"
#endif
#endif

#ifdef CRYPTO_CAST_SUBSET
#ifndef NO_CAST
#include "cast/c_cfb64.c"
#include "cast/c_ecb.c"
#ifndef CAST_ASM
#include "cast/c_enc.c"
#endif
#include "cast/c_ofb64.c"
#include "cast/c_skey.c"
#endif
#endif

#ifdef CRYPTO_LHASH_SUBSET
#include "lhash/lh_stats.c"
#include "lhash/lhash.c"
#endif

#ifdef CRYPTO_MD_SUBSET
#ifndef NO_MD2
#include "md2/md2_dgst.c"
#include "md2/md2_one.c"
#include "evp/m_md2.c"
#endif
#ifndef NO_MD5
#include "md5/md5_dgst.c"
#include "md5/md5_one.c"
#include "evp/m_md5.c"
#endif
#endif

#ifdef CRYPTO_MDC2_SUBSET
#ifndef NO_MDC2
#include "mdc2/mdc2dgst.c"
#include "mdc2/mdc2_one.c"
#include "evp/m_mdc2.c"
#endif
#endif

#ifdef CRYPTO_OBJECTS_SUBSET
#include "objects/obj_dat.c"
#include "objects/obj_err.c"
#include "objects/obj_lib.c"
#endif

#ifdef CRYPTO_PEM_SUBSET
#include "pem/pem_err.c"
#include "pem/pem_info.c"
#include "pem/pem_lib.c"
#include "pem/pem_all.c"
#ifndef NO_RSA
#include "pem/pem_seal.c"
#include "pem/pem_sign.c"
#endif
#endif

#ifdef CRYPTO_RAND_SUBSET
#include "rand/md_rand.c"
#include "rand/randfile.c"
#endif

#ifdef CRYPTO_RC_SUBSET
#ifndef NO_RC2
#include "rc2/rc2_cbc.c"
#include "rc2/rc2_ecb.c"
#include "rc2/rc2_skey.c"
#include "rc2/rc2cfb64.c"
#include "rc2/rc2ofb64.c"
#endif
#ifndef NO_RC4
#include "rc4/rc4_skey.c"
#ifndef RC4_ASM
#include "rc4/rc4_enc.c"
#endif
#endif
#endif

#ifdef CRYPTO_HMAC_SUBSET
#include "hmac/hmac.c"
#endif

#ifdef CRYPTO_RSA_SUBSET
#ifndef NO_RSA
#include "rsa/rsa_eay.c"
#include "rsa/rsa_err.c"
#include "rsa/rsa_gen.c"
#include "rsa/rsa_lib.c"
#include "rsa/rsa_sign.c"
#include "rsa/rsa_saos.c"
#endif
#endif

#ifndef NO_SHA
#ifdef CRYPTO_SHA1_SUBSET
#ifndef NO_SHA1
#include "sha/sha1_one.c"
#include "sha/sha1dgst.c"
#include "evp/m_dss1.c"
#include "evp/m_sha1.c"
#endif
#endif

#ifdef CRYPTO_SHA_SUBSET
#ifndef NO_SHA0
#include "evp/m_dss.c"
#include "sha/sha_dgst.c"
#include "sha/sha_one.c"
#include "evp/m_sha.c"
#endif
#endif
#endif
 
#ifdef CRYPTO_STACK_SUBSET
#include "stack/stack.c"
#endif

#ifdef CRYPTO_TXT_DB_SUBSET
#include "txt_db/txt_db.c"
#endif

#ifdef CRYPTO_X509_SUBSET
#include "x509/x509_cmp.c"
#include "x509/x509_d2.c"
#include "x509/x509_def.c"
#include "x509/x509_err.c"
#include "x509/x509_ext.c"
#include "x509/x509_lu.c"
#include "x509/x509_obj.c"
#include "x509/x509_r2x.c"
#include "x509/x509_req.c"
#include "x509/x509_set.c"
#include "x509/x509_v3.c"
#include "x509/x509_vfy.c"
#include "x509/x509name.c"
#include "x509/x509pack.c"
#include "x509/x509rset.c"
#include "x509/x509type.c"
#include "x509/x_all.c"
#include "x509/x509_txt.c"
#include "x509/by_dir.c"
#include "x509/by_file.c"
#include "x509/v3_net.c"
#include "x509/v3_x509.c"
#endif


#ifdef CRYPTO_PKCS7_SUBSET /* I have an explicit removal of 7 lines */
#include "pkcs7/pk7_lib.c"
#include "pkcs7/pkcs7err.c"
#include "pkcs7/pk7_doit.c"
#endif /* CRYPTO_PKCS7_SUBSET */

