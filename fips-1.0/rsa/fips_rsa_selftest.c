/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 *
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/fips.h>
#include <openssl/rsa.h>
#include <openssl/fips_sha.h>
#include <openssl/opensslconf.h>

#ifdef OPENSSL_FIPS
#define SetKey \
  key->n = BN_bin2bn(n, sizeof(n)-1, key->n); \
  key->e = BN_bin2bn(e, sizeof(e)-1, key->e); \
  key->d = BN_bin2bn(d, sizeof(d)-1, key->d); \
  key->p = BN_bin2bn(p, sizeof(p)-1, key->p); \
  key->q = BN_bin2bn(q, sizeof(q)-1, key->q); \
  key->dmp1 = BN_bin2bn(dmp1, sizeof(dmp1)-1, key->dmp1); \
  key->dmq1 = BN_bin2bn(dmq1, sizeof(dmq1)-1, key->dmq1); \
  key->iqmp = BN_bin2bn(iqmp, sizeof(iqmp)-1, key->iqmp); \
  memcpy(c, ctext_ex, sizeof(ctext_ex) - 1); \
  return (sizeof(ctext_ex) - 1);

static unsigned char n[] =
"\x00\xBB\xF8\x2F\x09\x06\x82\xCE\x9C\x23\x38\xAC\x2B\x9D\xA8\x71"
"\xF7\x36\x8D\x07\xEE\xD4\x10\x43\xA4\x40\xD6\xB6\xF0\x74\x54\xF5"
"\x1F\xB8\xDF\xBA\xAF\x03\x5C\x02\xAB\x61\xEA\x48\xCE\xEB\x6F\xCD"
"\x48\x76\xED\x52\x0D\x60\xE1\xEC\x46\x19\x71\x9D\x8A\x5B\x8B\x80"
"\x7F\xAF\xB8\xE0\xA3\xDF\xC7\x37\x72\x3E\xE6\xB4\xB7\xD9\x3A\x25"
"\x84\xEE\x6A\x64\x9D\x06\x09\x53\x74\x88\x34\xB2\x45\x45\x98\x39"
"\x4E\xE0\xAA\xB1\x2D\x7B\x61\xA5\x1F\x52\x7A\x9A\x41\xF6\xC1\x68"
"\x7F\xE2\x53\x72\x98\xCA\x2A\x8F\x59\x46\xF8\xE5\xFD\x09\x1D\xBD"
"\xCB";


static int setrsakey(RSA *key, unsigned char *c)
    {
    static const unsigned char e[] = "\x11";

    static const unsigned char d[] =
"\x00\xA5\xDA\xFC\x53\x41\xFA\xF2\x89\xC4\xB9\x88\xDB\x30\xC1\xCD"
"\xF8\x3F\x31\x25\x1E\x06\x68\xB4\x27\x84\x81\x38\x01\x57\x96\x41"
"\xB2\x94\x10\xB3\xC7\x99\x8D\x6B\xC4\x65\x74\x5E\x5C\x39\x26\x69"
"\xD6\x87\x0D\xA2\xC0\x82\xA9\x39\xE3\x7F\xDC\xB8\x2E\xC9\x3E\xDA"
"\xC9\x7F\xF3\xAD\x59\x50\xAC\xCF\xBC\x11\x1C\x76\xF1\xA9\x52\x94"
"\x44\xE5\x6A\xAF\x68\xC5\x6C\x09\x2C\xD3\x8D\xC3\xBE\xF5\xD2\x0A"
"\x93\x99\x26\xED\x4F\x74\xA1\x3E\xDD\xFB\xE1\xA1\xCE\xCC\x48\x94"
"\xAF\x94\x28\xC2\xB7\xB8\x88\x3F\xE4\x46\x3A\x4B\xC8\x5B\x1C\xB3"
"\xC1";

    static const unsigned char p[] =
"\x00\xEE\xCF\xAE\x81\xB1\xB9\xB3\xC9\x08\x81\x0B\x10\xA1\xB5\x60"
"\x01\x99\xEB\x9F\x44\xAE\xF4\xFD\xA4\x93\xB8\x1A\x9E\x3D\x84\xF6"
"\x32\x12\x4E\xF0\x23\x6E\x5D\x1E\x3B\x7E\x28\xFA\xE7\xAA\x04\x0A"
"\x2D\x5B\x25\x21\x76\x45\x9D\x1F\x39\x75\x41\xBA\x2A\x58\xFB\x65"
"\x99";

    static const unsigned char q[] =
"\x00\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9"
"\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5A\x0F\x20\x35\x02\x8B\x9D"
"\x86\x98\x40\xB4\x16\x66\xB4\x2E\x92\xEA\x0D\xA3\xB4\x32\x04\xB5"
"\xCF\xCE\x33\x52\x52\x4D\x04\x16\xA5\xA4\x41\xE7\x00\xAF\x46\x15"
"\x03";

    static const unsigned char dmp1[] =
"\x54\x49\x4C\xA6\x3E\xBA\x03\x37\xE4\xE2\x40\x23\xFC\xD6\x9A\x5A"
"\xEB\x07\xDD\xDC\x01\x83\xA4\xD0\xAC\x9B\x54\xB0\x51\xF2\xB1\x3E"
"\xD9\x49\x09\x75\xEA\xB7\x74\x14\xFF\x59\xC1\xF7\x69\x2E\x9A\x2E"
"\x20\x2B\x38\xFC\x91\x0A\x47\x41\x74\xAD\xC9\x3C\x1F\x67\xC9\x81";

    static const unsigned char dmq1[] =
"\x47\x1E\x02\x90\xFF\x0A\xF0\x75\x03\x51\xB7\xF8\x78\x86\x4C\xA9"
"\x61\xAD\xBD\x3A\x8A\x7E\x99\x1C\x5C\x05\x56\xA9\x4C\x31\x46\xA7"
"\xF9\x80\x3F\x8F\x6F\x8A\xE3\x42\xE9\x31\xFD\x8A\xE4\x7A\x22\x0D"
"\x1B\x99\xA4\x95\x84\x98\x07\xFE\x39\xF9\x24\x5A\x98\x36\xDA\x3D";
    
    static const unsigned char iqmp[] =
"\x00\xB0\x6C\x4F\xDA\xBB\x63\x01\x19\x8D\x26\x5B\xDB\xAE\x94\x23"
"\xB3\x80\xF2\x71\xF7\x34\x53\x88\x50\x93\x07\x7F\xCD\x39\xE2\x11"
"\x9F\xC9\x86\x32\x15\x4F\x58\x83\xB1\x67\xA9\x67\xBF\x40\x2B\x4E"
"\x9E\x2E\x0F\x96\x56\xE6\x98\xEA\x36\x66\xED\xFB\x25\x79\x80\x39"
"\xF7";

    static const unsigned char ctext_ex[] =
"\x42\x4b\xc9\x51\x61\xd4\xca\xa0\x18\x6c\x4d\xca\x61\x8f\x2d\x07"
"\x8c\x63\xc5\x6b\xa2\x4c\x32\xb1\xda\xb7\xdd\x32\xb6\x51\x68\xc3"
"\x6e\x98\x46\xd6\xbb\x1a\xd5\x99\x05\x92\x7c\xd7\xbc\x08\x9e\xe4"
"\xc3\x70\x4d\xe6\x99\x7e\x61\x31\x07\x7a\x19\xdb\x3e\x11\xfa\x3d"
"\x7c\x61\xd7\x78\x14\x3f\x05\x16\xa0\xc4\xbf\xcd\xee\xca\x67\x4c"
"\x80\x4e\xca\x43\x2f\x35\x43\x58\xa7\x50\x7e\x3e\x52\x82\xab\xac"
"\xa6\x50\xe8\x39\x9f\xe0\x7f\x58\x1d\x1b\x90\x93\x04\xec\xb3\xf9"
"\x24\xd3\x75\x3e\x39\xd1\x14\xc6\x33\xce\xd6\xee\x20\x47\xec\xe4";

    SetKey;
    }

void FIPS_corrupt_rsa()
    {
    n[0]++;
    }

int FIPS_selftest_rsa()
    {
    int clen;
    RSA *key;
    unsigned char expected_ctext[256];
    unsigned char ctext[256];
    unsigned char ptext[256];
    static const unsigned char original_ptext[] =
	"\x01\x23\x45\x67\x89\xab\xcd\xef\x12\x34\x56\x78\x9a\xbc\xde\xf0"
	"\x23\x45\x67\x89\xab\xcd\xef\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12"
	"\x45\x67\x89\xab\xcd\xef\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34"
	"\x67\x89\xab\xcd\xef\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56"
	"\x89\xab\xcd\xef\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78"
	"\xab\xcd\xef\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a"
	"\xcd\xef\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc"
	"\xef\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde"
	"\xf0\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde";
    unsigned char md[SHA_DIGEST_LENGTH];
    static const unsigned char mdkat[SHA_DIGEST_LENGTH] =
	"\x2d\x57\x1d\x6f\x5c\x37\xf9\xf0\x3b\xb4\x3c\xe8\x2c\x4c\xb3\x04"
	"\x75\xa2\x0e\xfb";
    static const unsigned char ctextkat[] =
	"\x3e\xc5\x0a\xbe\x29\xa2\xca\x9a\x35\x14\x17\x26\xa4\x0f\xa3\x03"
	"\x65\xb5\x37\xf5\x6a\xaa\xb\xf\x2c\x0d\x8\xc0\x73\x8\x3c\x88\x85"
	"\x36\x68\x16\xfe\x2f\x59\x77\x7e\x2a\x76\x9a\xc7\x27\x19\x9b\x54"
	"\x14\x87\xf3\xe0\xce\x1e\x68\x10\x40\x14\xac\xbc\xe6\x6f\x26\x1f"
	"\x55\xd1\x15\x81\x48\x10\xf4\x89\xe5\x67\x52\x42\x87\x04\x74\x4e"
	"\x96\x14\x7c\x53\xc9\x1e\x84\x11\x7d\x7d\x23\xbd\xff\x6c\xcb\x00"
	"\x96\x2e\x7d\xfb\x47\xea\x78\xcd\xd8\x04\x3a\x98\x06\x13\x68\x39"
	"\xa1\xe2\xbc\x9f\x64\xc7\x62\xf0\x74\x4d\x42\xe0\x0b\xcf\x24\x48";
    int i;

    /* Perform pairwise consistency test by: ... */

    key=RSA_new();
    clen=setrsakey(key,expected_ctext);
    /* ...1) apply public key to plaintext, resulting ciphertext must be
     * different
    */
    i=RSA_public_encrypt(128,original_ptext,ctext,key,
			 RSA_NO_PADDING);
    if(i != clen || memcmp(ctext,expected_ctext,i))
  	{
  	FIPSerr(FIPS_F_FIPS_SELFTEST_RSA,FIPS_R_SELFTEST_FAILED);
 	return 0;
 	}
    if(!memcmp(ctext,original_ptext,i))
  	{
  	FIPSerr(FIPS_F_FIPS_SELFTEST_RSA,FIPS_R_SELFTEST_FAILED);
 	return 0;
 	}
    /* ...2) apply private key to ciphertext and compare result to
     *       original plaintext; results must be equal
    */
    i=RSA_private_decrypt(i,ctext,ptext,key,RSA_NO_PADDING);
    if(i != 128 || memcmp(ptext,original_ptext,i))
	{
	FIPSerr(FIPS_F_FIPS_SELFTEST_RSA,FIPS_R_SELFTEST_FAILED);
	return 0;
	}

    /* Perform sign and verify Known Answer Test by... */

    /* ...1)  using the same RSA key to encrypt the SHA-1 hash of a
     * plaintext value larger than the RSA key size
    */
    if (RSA_size(key) >= sizeof(original_ptext) - 1)
	{
	FIPSerr(FIPS_F_FIPS_SELFTEST_RSA,FIPS_R_SELFTEST_FAILED);
	return 0;
	}
    /* ...2) then generate the SHA-1 digest of plaintext, and compare the
     * digest to the Known Answer (note here we duplicate the SHA-1 KAT)
     */
    SHA1(original_ptext,sizeof(original_ptext) - 1,md);
    if(memcmp(md,mdkat,SHA_DIGEST_LENGTH))
	{
	FIPSerr(FIPS_F_FIPS_SELFTEST_SHA,FIPS_R_SELFTEST_FAILED);
	return 0;
	}
    /* ...3) then encrypt the digest, and compare the ciphertext
     * to the Known Answer
     */
    i=RSA_private_encrypt(sizeof(md),md,ctext,key,RSA_PKCS1_PADDING);
    if(i != clen || memcmp(ctextkat,ctext,i))
	{
	FIPSerr(FIPS_F_FIPS_SELFTEST_RSA,FIPS_R_SELFTEST_FAILED);
	return 0;
	}
    /* ...4) and finally decrypt the signed digest and compare with
     * the original Known Answer
     */
    i=RSA_public_decrypt(i,ctext,md,key,RSA_PKCS1_PADDING);
    if(i != sizeof(md) || memcmp(mdkat,md,i))
	{
	FIPSerr(FIPS_F_FIPS_SELFTEST_RSA,FIPS_R_SELFTEST_FAILED);
	return 0;
	}

    RSA_free(key);
    return 1;
    }

#endif /* def OPENSSL_FIPS */
