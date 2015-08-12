/*------------------------------------------------------------------
 * fips/kdf/fips_kdf_tls.c - TLS KDF vector tests
 *
 * This product contains software written by:
 * Barry Fussell (bfussell@cisco.com)
 * Cisco Systems, March 2015
 *
 * Copyright (c) 2015 by Cisco Systems, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *------------------------------------------------------------------
 */

#define OPENSSL_FIPSAPI
#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
#include <stdio.h>

int main(int argc, char *argv[])
{
    printf("No FIPS KDF TLS support\n");
    return(0);
}

#else

#include <openssl/bn.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

#define TLS_MD_MASTER_SECRET_CONST              "master secret"
#define TLS_MD_MASTER_SECRET_CONST_SIZE         13
#define TLS_MD_KEY_EXPANSION_CONST              "key expansion"
#define TLS_MD_KEY_EXPANSION_CONST_SIZE         13


#define TLS_COUNTER 100   /* Sample vectors may be less than 100 */
#define VERBOSE 0
/*-----------------------------------------------*/
static int proc_kdf_tls_file (char *rqfile, char *rspfile)
    {
    char afn[256], rfn[256];
    FILE *afp = NULL, *rfp = NULL;
    char ibuf[2048];
    char tbuf[2048];
    int ret, shr_len = 0, chr_len = 0, psm_len = 0, sha_len, cr_len = 0, sr_len = 0, len, count = 0;
    unsigned char *shr = NULL, *chr = NULL, *psm = NULL, *sr = NULL, *cr = NULL;
    unsigned char *key_block1, *key_block2, *master_secret1, *master_secret2;
    char tmp_len[8];
    int err = 0, step = 0, i;
    char *rp;
    int counter = 0, olen1 = 0, olen2 = 0, len1;
    const EVP_MD *evp_md1 = NULL, *evp_md2 = NULL;

    if (!rqfile || !(*rqfile))
	{
	printf("No req file\n");
	return -1;
	}
    strcpy(afn, rqfile);

    if ((afp = fopen(afn, "r")) == NULL)
	{
	printf("Cannot open file: %s, %s\n", 
	       afn, strerror(errno));
	return -1;
	}
    if (!rspfile)
	{
	strcpy(rfn,afn);
	rp=strstr(rfn,"req/");
#ifdef OPENSSL_SYS_WIN32
	if (!rp)
	    rp=strstr(rfn,"req\\");
#endif
	memcpy(rp,"rsp",3);
	rp = strstr(rfn, ".req");
	memcpy(rp, ".rsp", 4);
	rspfile = rfn;
	}
    if ((rfp = fopen(rspfile, "w")) == NULL)
	{
	printf("Cannot open file: %s, %s\n", 
	       rfn, strerror(errno));
	fclose(afp);
	afp = NULL;
	return -1;
	}

    key_block1 = malloc(4096);
    key_block2 = malloc(4096);
    master_secret1 = malloc(4096);
    master_secret2 = malloc(4096);

    if (!key_block1 || !key_block2 || !master_secret1 || !master_secret2) {
        printf("\nFailed to malloc");
	return -1;
    }


    while (!err && (fgets(ibuf, sizeof(ibuf), afp)) != NULL)
	{
	tidy_line(tbuf, ibuf);
	if (VERBOSE)
	    printf("step=%d ibuf=%s",step,ibuf);

	switch (step)
	{
	case 0:  /* walk thru and write out preamble */
	    if (ibuf[0] == '\n')
	    {
	        copy_line(ibuf, rfp);
		step++;
		break;
            }
	    else if (ibuf[0] != '#')
		{
		printf("Invalid preamble item: %s\n", ibuf);
		err = 1;
		}
	    copy_line(ibuf, rfp);
	    break;

	case 1:  /* read parameter lengths */
	    if (ibuf[0] == '[') {
                copy_line(ibuf, rfp);
		if (fips_strncasecmp(ibuf+1, "TLS 1.2, SHA-", 13) == 0) {
		    strncpy(tmp_len, (char*)ibuf+14, 4);
		    for (i=0; i<4; i++) {
		        if (ibuf[i+14] == ']') {
		            tmp_len[i] = 0;
			    break;
		        }
                    }
		    count = 1;
		    sha_len = atoi(tmp_len);
		    if (VERBOSE) printf("\nFound sha_len length = %s", tmp_len);
		    switch (sha_len) 
		    {
		    case 1:
		    case 256:
		        evp_md1 = evp_md2 = EVP_sha256();
			break;
		    case 384:
		        evp_md1 = evp_md2 = EVP_sha384();
			break;
		    case 512:
		        evp_md1 = evp_md2 = EVP_sha512();
			break;
		    default:
		        printf("\nBad sha size %d", sha_len);
			return -1;
		    }
		}

		if (fips_strncasecmp(ibuf+1, "TLS 1.0/1.1", 11) == 0) {
		/* 
		 * If TLS 1.0/1.1 KDF is not supported then error out here
		 *  evp_md1 = EVP_md5();
		 *  evp_md2 = EVP_sha1();
		 *  count = 2;
		 *  ^^^^^ these 3 lines will handle 1.0/1.1
		 */
		    printf("\nBad TLS version type");
		    return -1;
		}
	    }
	    if (fips_strncasecmp(ibuf+1, "pre-master secret length = ", 27) == 0) {
	        memset(tmp_len, 0, 5);
		strncpy(tmp_len, (char*)ibuf+28, 5);

	        for (i=0; i<5; i++) {
		    if (ibuf[i+28] == ']') {
		        tmp_len[i] = 0;
		        break;
                    }
		}
		olen1 = atoi(tmp_len)/8;
            }
	    if (fips_strncasecmp(ibuf+1, "key block length = ", 19) == 0) {
	        memset(tmp_len, 0, 5);
		strncpy(tmp_len, (char*)ibuf+20, 5);

	        for (i=0; i<4; i++) {
		    if (ibuf[i+20] == ']') {
		        tmp_len[i] = 0;
		        break;
                    }
		}
		olen2 = atoi(tmp_len)/8;
		step++;
            }
	    break;

	case 2:  /* read key, hash and session id, for each of 100 tests */
	    if (ibuf[0] == '\n') {
	        copy_line(ibuf, rfp);
	    }
	    if (strncmp(ibuf, "pre_master_secret = ", 20) == 0) {
	        psm = malloc(420);
		if (!psm) {
		    printf("\nFailed to malloc psm");
		    return -1;
		}
	        psm_len = hex2bin((char*)ibuf+20, psm);
	        fprintf(rfp,"COUNT = %d" RESP_EOL ,counter);
	        copy_line(ibuf, rfp);
	    }
	    if (strncmp(ibuf, "serverHello_random = ", 21) == 0) {
	        shr = malloc(420);
		if (!shr) {
		    printf("\nFailed to malloc shr");
		    return -1;
		}
	        shr_len = hex2bin((char*)ibuf+21, shr);
	        copy_line(ibuf, rfp);
	    }
	    if (strncmp(ibuf, "clientHello_random = ", 21) == 0) {
	        chr = malloc(420);
		if (!chr) {
		    printf("\nFailed to malloc chr");
		    return -1;
		}
	        chr_len = hex2bin((char*)ibuf+21, chr);
	        copy_line(ibuf, rfp);
	    }
	    if (strncmp(ibuf, "server_random = ", 16) == 0) {
	        sr = malloc(420);
		if (!sr) {
		    printf("\nFailed to malloc sr");
		    return -1;
		}
	        sr_len = hex2bin((char*)ibuf+16, sr);
	        copy_line(ibuf, rfp);
	    }
	    if (strncmp(ibuf, "client_random = ", 16) == 0) {
	        cr = malloc(420);
		if (!cr) {
		    printf("\nFailed to malloc cr");
		    return -1;
		}
	        cr_len = hex2bin((char*)ibuf+16, cr);
	        copy_line(ibuf, rfp);
	    }

	    if (psm_len && shr_len && chr_len && sr_len && cr_len) {  /* run test here */

	        len = psm_len / count;
		if (count == 1)
	            psm_len = 0;

		memset(master_secret1, 0, 4096);
 		ret = kdf_tls12_P_hash(evp_md1, (const unsigned char *)psm, len + (psm_len & 1), 
	                               TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
				       chr, chr_len,
				       shr, shr_len,
				       NULL, 0,
				       NULL, 0,
				       master_secret2, olen1);
		if (ret == 0) {
		    printf("\nKDF TLS failed on master secret");
		    return -1;
                }
                for (i = 0; i < olen1; i++) {
                    master_secret1[i] ^= master_secret2[i];
		}    

                if (evp_md1 != evp_md2) {
		ret = kdf_tls12_P_hash(evp_md2, (const unsigned char *)psm + len, len + (psm_len & 1), 
	                               TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
				       chr, chr_len,
				       shr, shr_len,
				       NULL, 0,
				       NULL, 0,
				       master_secret2, olen1);
		if (ret == 0) {
		    printf("\nKDF TLS failed on master secret");
		    return -1;
                }
                for (i = 0; i < olen1; i++) {
                    master_secret1[i] ^= master_secret2[i];
		}
                }

	        OutputValue("master_secret", master_secret1, olen1, rfp, 0);

		memset(key_block1, 0, 4096);
		len1 = olen1;
	        len = len1 / count;
		if (count == 1)
	            len1 = 0;
		ret = kdf_tls12_P_hash(evp_md1, (const unsigned char *)master_secret1, 
				       len + (len1 & 1),
		                       TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
				       sr, sr_len,
				       cr, cr_len,
				       NULL, 0,
				       NULL, 0,
				       key_block2, olen2);
		if (ret == 0) {
		    printf("\nKDF TLS failed on expansion");
		    return -1;
                }
                for (i = 0; i < olen2; i++) {
                    key_block1[i] ^= key_block2[i];
		}    
                if (evp_md1 != evp_md2) {
		ret = kdf_tls12_P_hash(evp_md2, (const unsigned char *)master_secret1 + len,
				       len + (len1 & 1),
		                       TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
				       sr, sr_len,
				       cr, cr_len,
				       NULL, 0,
				       NULL, 0,
				       key_block2, olen2);
		if (ret == 0) {
		    printf("\nKDF TLS failed on expansion");
		    return -1;
                }
                for (i = 0; i < olen2; i++) {
                    key_block1[i] ^= key_block2[i];
		}    
		}
	        OutputValue("key_block", key_block1, olen2, rfp, 0);


	        free(psm);
	        free(shr);
	        free(chr);
	        free(sr);
	        free(cr);
		psm_len = shr_len = chr_len = sr_len = cr_len = 0;
	        counter++;
	    }
	    break;
	}
	/* each length has 100 passes, counter pre-incremented */
	if (counter == TLS_COUNTER) {
	    counter = 0;
            fprintf(rfp, RESP_EOL);  /* add separator */
	    step = 1;
        }	    
    }

    free(key_block1);
    free(key_block2);
    free(master_secret1);
    free(master_secret2);
    if (rfp)
	fclose(rfp);
    if (afp)
	fclose(afp);
    return err;
}

/*
 * --------------------------------------------------
 * Processes a single file
 * --------------------------------------------------
 */

#ifdef FIPS_ALGVS
int fips_kdf_tls_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
    {
    char *rspfile = NULL;
    char fn[250] = "";
    fips_algtest_init();

    if (VERBOSE) 
        printf("\nKDF TLS start: %s\n", argv[1]);

    strcpy(fn, argv[1]);
    rspfile = argv[2];
    if (proc_kdf_tls_file(fn, rspfile))
	{
	printf(">>> Processing failed for: %s <<<\n", fn);
	}
    return 0;
    }
#endif
