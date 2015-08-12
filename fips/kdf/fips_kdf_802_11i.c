/*------------------------------------------------------------------
 * fips/kdf/fips_kdf_802_11i.c - 802_11i KDF vector tests
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
    printf("No FIPS KDF 802_11I support\n");
    return(0);
}

#else

#include <openssl/bn.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"


#define K802_COUNTER 40   /* Sample vectors may be less */
#define VERBOSE 0
/*-----------------------------------------------*/
static int proc_kdf_802_11i_file (char *rqfile, char *rspfile)
    {
    char afn[256], rfn[256];
    FILE *afp = NULL, *rfp = NULL;
    unsigned char *out;
    char ibuf[2048];
    char tbuf[2048];
    int ctr_loc = 0, rlen = 0, len = 0, ret, key_len = 0, fd_len = 0;
    char tmp_len[8];
    int err = 0, step = 0, i, sha_len;
    unsigned char *key;
    unsigned char *fixed_data;
    char *rp;
    int counter = 0;
    const EVP_MD *evp_md = NULL;

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
    key = malloc(1024);
    fixed_data = malloc(1024);

    if (!key || !fixed_data) {
	printf("\nFailed to allocate memory");
	return -1;
    }

    while (!err && (fgets(ibuf, sizeof(ibuf), afp)) != NULL)
	{
	if (VERBOSE)
	    printf("step=%d ibuf=%s",step,ibuf);

	switch (step) {
	case 0:  /* walk thru and write out preamble */
	    tidy_line(tbuf, ibuf);
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
	case 1:  /* read HMAC type, rlen and ctrlocation */
	    if (ibuf[0] == '[') {
	        if (fips_strncasecmp(ibuf+1, "PRF=HMAC_SHA", 12) == 0) {
		    strncpy(tmp_len, (char*)ibuf+13, 3);
		    for (i=0; i<3; i++) {
		        if (ibuf[i+13] == ']') {
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
		    fprintf(rfp, "%s", ibuf);
	        }
		if (fips_strncasecmp(ibuf+1, "CTRLOCATION=", 12) == 0) {
	            if (fips_strncasecmp(ibuf+13, "AFTER_FIXED", 11) != 0) {
		        printf("\nWrong counter location");
			return -1;
		    }
		    ctr_loc = 1;
		    fprintf(rfp, "%s", ibuf);
	        }
		if (fips_strncasecmp(ibuf+1, "RLEN=", 5) == 0) {
	            if (fips_strncasecmp(ibuf+6, "8_BITS", 6) != 0) {
		        printf("\nWrong rlen value");
		        return -1;
		    }
		    rlen = 1;
		    fprintf(rfp, "%s", ibuf);
	        }

            } else {
	        fprintf(rfp, RESP_EOL);  /* add separator */
	    }
            if (evp_md && rlen && ctr_loc) {
	        step++;
	    }
	    break;
	case 2:  /* read arguments for 40 tests loop */
	    /* don't tidy, CAVS won't like it */
	    if (strncmp(ibuf, "COUNT=", 6) == 0) {
		fprintf(rfp, "%s", ibuf);
		break;
            }
	    tidy_line(tbuf, ibuf);
	    copy_line(ibuf, rfp);

	    if (strncmp(ibuf, "L = ", 4) == 0) {
		memset(tmp_len, 0, 3);
		strncpy(tmp_len, (char*)ibuf+4, 3);
		len = atoi(tmp_len)/8;
	    }

	    if (strncmp(ibuf, "KI = ", 5) == 0) {
		memset(key, 0, 1024);
	        key_len = hex2bin((char*)ibuf+5, key);
	    }

	    if (key_len && rlen) {
		out = malloc(4096);  /* overkill for buffer overrun */
		if (!out) {
		    printf("\nFailed to malloc out");
		    return -1;
		}

	        fd_len = 60;
		if (RAND_bytes(fixed_data, fd_len) <= 0) {
	            fprintf(stderr, "\nUnable to generate fixed data");
		    goto error;
	        }

		if (VERBOSE) printf("\nProcessing KDF for 802_11I");
		ret = kdf_802_11i(key, key_len, NULL, 0, fixed_data, fd_len, out, 
		                  len + evp_md->md_size, evp_md);

	        copy_line("FixedInputDataByteLen = 60\n", rfp);
		OutputValue("FixedInputData", fixed_data, 60, rfp, 0);
	        if (ret > 0) {
		    OutputValue("KO", out + evp_md->md_size, len, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
	        }
		len = fd_len = key_len = 0;
		counter++;
	        if (out) {
	           free(out);
	        }
		/* each length has 40 passes, counter pre-incremented */
		if (counter == K802_COUNTER) {
		    counter = 0;
		    evp_md = NULL;
		    rlen = ctr_loc = 0;
		    step = 1;
                }
	    }
	    break;
	}
    }

error:
    free(key);
    free(fixed_data);

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
int fips_kdf_802_11i_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
    {
    char *rspfile = NULL;
    char fn[250] = "";
    fips_algtest_init();

    if (VERBOSE) 
        printf("\nKDF 802_11i start: %s\n", argv[1]);

    strcpy(fn, argv[1]);
    rspfile = argv[2];
    if (proc_kdf_802_11i_file(fn, rspfile))
	{
	printf(">>> Processing failed for: %s <<<\n", fn);
	}
    return 0;
    }
#endif
