/*------------------------------------------------------------------
 * fips/kdf/fips_kdf_ikev2.c - IKEV2 KDF vector tests
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
    printf("No FIPS KDF IKEV2 support\n");
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


#define IKEV2_COUNTER 100   /* Sample vectors may be less than 100 */
#define VERBOSE 0
/*-----------------------------------------------*/
static int proc_kdf_ikev2_file (char *rqfile, char *rspfile)
    {
    char afn[256], rfn[256];
    char tmp_len[8];
    FILE *afp = NULL, *rfp = NULL;
    char ibuf[2048];
    char tbuf[2048];
    const EVP_MD *evp_md = NULL;
    int err = 0, step = 0, i, sha_len, dkm_len = 0, dkm_sa_len = 0;
    int ni_len = 0, nr_len = 0, spii_len = 0, spir_len = 0, gir_len = 0, gir_new_len = 0;
    unsigned char *ni, *nr, *spii, *spir, *gir, *gir_new, *dkm, *dkm_sa, *dkm_sa_dh;
    unsigned char *temp, *skeyseed, *re_skeyseed;
    char *rp;
    int counter = 0;

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

    /* Just allocate plenty here */
    dkm = malloc(1024);
    dkm_sa = malloc(1024);
    dkm_sa_dh = malloc(1024);
    gir = malloc(1024);
    gir_new = malloc(1024);
    ni = malloc(256);
    nr = malloc(256);
    spii = malloc(256);
    spir = malloc(256);
    skeyseed = malloc(256);
    re_skeyseed = malloc(256);
    temp = malloc(1024);

    if (!ni || !nr || !spii || !spir || !gir || !gir_new || !dkm || !dkm_sa || !dkm_sa_dh) {
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
	    copy_line(ibuf, rfp);
	    if (ibuf[0] == '\n')
	    {
		step++;
		break;
            }
	    else if (ibuf[0] != '#')
	    {
		printf("Invalid preamble item: %s\n", ibuf);
		err = 1;
	    }
	    break;

	case 1:  /* read lengths, ignore. read SHA */
            copy_line(ibuf, rfp);
	    if (ibuf[0] == '[') {
		if (fips_strncasecmp(ibuf+1, "SHA-", 4) == 0) {
		    strncpy(tmp_len, (char*)ibuf+5, 4);
		    for (i=0; i<3; i++) {
		        if (ibuf[i+5] == ']') {
		            tmp_len[i] = 0;
			    break;
		        }
                    }
		    sha_len = atoi(tmp_len);
		    if (VERBOSE) printf("\nFound sha_len length = %s", tmp_len);
		    switch (sha_len) 
		    {
		    case 1:
		        evp_md = EVP_sha1();
			break;
		    case 224:
		        evp_md = EVP_sha224();
			break;
		    case 256:
		        evp_md = EVP_sha256();
			break;
		    case 384:
		        evp_md = EVP_sha384();
			break;
		    case 512:
		        evp_md = EVP_sha512();
			break;
		    default:
		        printf("\nBad sha size %d", sha_len);
			return -1;
		    }
		}
		if (fips_strncasecmp(ibuf+1, "DKM length = ", 13) == 0) {
		    dkm_len = atoi(ibuf+14)/8;
                }

		if (fips_strncasecmp(ibuf+1, "Child SA DKM length = ", 22) == 0) {
		    dkm_sa_len = atoi(ibuf+23)/8;
		    step++;
                }
	    }
	    break;
	case 2:  /* read password, used for 100 tests */
	    copy_line(ibuf, rfp);
	    /* get the password and run the kdf */
	    if (strncmp(ibuf, "Ni = ", 5) == 0) {
	        ni_len = hex2bin((char*)ibuf+5, ni);
	    }
	    if (strncmp(ibuf, "Nr = ", 5) == 0) {
	        nr_len = hex2bin((char*)ibuf+5, nr);
	    }
	    if (strncmp(ibuf, "g^ir = ", 7) == 0) {
	        gir_len = hex2bin((char*)ibuf+7, gir);
	    }
	    if (strncmp(ibuf, "g^ir (new) = ", 13) == 0) {
	        gir_new_len = hex2bin((char*)ibuf+13, gir_new);
	    }
	    if (strncmp(ibuf, "SPIi = ", 7) == 0) {
	        spii_len = hex2bin((char*)ibuf+7, spii);
	    }
	    if (strncmp(ibuf, "SPIr = ", 7) == 0) {
	        spir_len = hex2bin((char*)ibuf+7, spir);
	    }

	    if (ni_len && nr_len && gir_len && gir_new_len && spii_len && spir_len) {
	        memset(temp, 0, 1024);
		memcpy(temp, ni, ni_len);
		memcpy(temp + ni_len, nr, nr_len);
		
	        if (kdf_ikev2_gen(skeyseed, evp_md, temp, ni_len + nr_len, gir, gir_len)) {
		     printf("\nFailed to gen key");
		     return -1;
                }
		OutputValue("SKEYSEED", skeyseed, evp_md->md_size, rfp, 0);

		memcpy(temp + ni_len + nr_len, spii, spii_len);
		memcpy(temp + ni_len + nr_len + spii_len, spir, spir_len);
	        if (kdf_ikev2_dkm(dkm, dkm_len, evp_md, skeyseed, evp_md->md_size, temp,
		              ni_len + nr_len + spii_len + spir_len, NULL, 0)) {
		     printf("\nFailed DKM");
		     return -1;
                }
		OutputValue("DKM", dkm, dkm_len, rfp, 0);

	        if (kdf_ikev2_dkm(dkm_sa, dkm_sa_len, evp_md, dkm, evp_md->md_size, temp,
		              ni_len + nr_len, NULL, 0)) {
		     printf("\nFailed DKM SA");
		     return -1;
                }
		OutputValue("DKM(Child SA)", dkm_sa, dkm_sa_len, rfp, 0);

	        if (kdf_ikev2_dkm(dkm_sa_dh, dkm_sa_len, evp_md, dkm, evp_md->md_size, temp,
		              ni_len + nr_len, gir_new, gir_new_len)) {
		     printf("\nFailed DKM SA DH");
		     return -1;
                }
		OutputValue("DKM(Child SA D-H)", dkm_sa_dh, dkm_sa_len, rfp, 0);

	        if (kdf_ikev2_rekey(re_skeyseed, evp_md, temp, ni_len + nr_len,
		                gir_new, gir_new_len, 1, dkm, evp_md->md_size)) {
		     printf("\nFailed rekey");
		     return -1;
                }
		OutputValue("SKEYSEED(Rekey)", re_skeyseed, evp_md->md_size, rfp, 0);

		ni_len = nr_len = gir_len = gir_new_len = spii_len = spir_len = 0;
		counter++;
	    }
	}
	/* each length has 100 passes, counter pre-incremented */
	if (counter == IKEV2_COUNTER) {
	    counter = 0;
	    step = 1;
        }	    
    }
    free(ni);
    free(nr);
    free(spii);
    free(spir);
    free(gir);
    free(gir_new);
    free(dkm);
    free(dkm_sa);
    free(dkm_sa_dh);

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
int fips_kdf_ikev2_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
    {
    char *rspfile = NULL;
    char fn[250] = "";
    fips_algtest_init();

    if (VERBOSE) 
        printf("\nKDF IKEV2 start: %s\n", argv[1]);

    strcpy(fn, argv[1]);
    rspfile = argv[2];
    if (proc_kdf_ikev2_file(fn, rspfile))
	{
	printf(">>> Processing failed for: %s <<<\n", fn);
	}
    return 0;
    }
#endif
