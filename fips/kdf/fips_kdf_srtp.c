/*------------------------------------------------------------------
 * fips/kdf/fips_kdf_srtp.c - SRTP KDF vector tests
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
    printf("No FIPS KDF SRTP support\n");
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


#define SRTP_COUNTER 100   /* Sample vectors may be less than 100 */
#define VERBOSE 0
/*-----------------------------------------------*/
static int proc_kdf_srtp_file (char *rqfile, char *rspfile)
    {
    char afn[256], rfn[256];
    FILE *afp = NULL, *rfp = NULL;
    unsigned char *out;
    char ibuf[2048];
    char tbuf[2048];
    int len = 0, ret, km_len = 0, ms_len = 0, kdr_len = 0, srtp_index_len = 0, srtcp_index_len = 0;
    unsigned char *km, *ms, *kdr, *srtp_index, *srtcp_index;
    int err = 0, step = 0;
    const EVP_CIPHER *cipher = NULL;
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
    km = malloc(256);
    ms = malloc(256);
    kdr = malloc(256);
    srtp_index = malloc(256);
    srtcp_index = malloc(256);

    if (!km || !ms || !kdr || !srtp_index || !srtcp_index) {
	printf("\nFailed to allocate memory");
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
	    else 
	       {
		copy_line(ibuf, rfp);
		}
	    break;

	case 1:  /* AES cipher type/key size */
            copy_line(ibuf, rfp);
	    if (ibuf[0] == '[') {
		if (fips_strncasecmp(ibuf+1, "AES-128", 7) == 0) {
		    cipher = EVP_aes_128_ctr();
		    if (VERBOSE) printf("\nFound AES cipher mode = 128");
		    len = 16;
                }
		if (fips_strncasecmp(ibuf+1, "AES-192", 7) == 0) {
		    cipher = EVP_aes_192_ctr();
		    if (VERBOSE) printf("\nFound AES cipher mode = 192");
		    len = 24;
                }
		if (fips_strncasecmp(ibuf+1, "AES-256", 7) == 0) {
		    cipher = EVP_aes_256_ctr();
		    if (VERBOSE) printf("\nFound AES cipher mode = 256");
		    len = 32;
		}
		if (fips_strncasecmp(ibuf+1, "KDR:All possible values", 23) == 0) {
	            step++;
		}
	    }
	    break;
	case 2:  /* read each of the input arguments, for each of 100 tests */
            copy_line(ibuf, rfp);
	    if (strncmp(ibuf, "k_master = ", 11) == 0) {
       		km_len = hex2bin((char*)ibuf+11, km);
	    }
	    if (strncmp(ibuf, "master_salt = ", 14) == 0) {
       		ms_len = hex2bin((char*)ibuf+14, ms);
	    }
	    if (strncmp(ibuf, "kdr = ", 6) == 0) {
       		kdr_len = hex2bin((char*)ibuf+6, kdr);
	    }
	    if (strncmp(ibuf, "index = ", 8) == 0) {
       		srtp_index_len = hex2bin((char*)ibuf+8, srtp_index);
	    }
	    if (strncmp(ibuf, "index (SRTCP) = ", 16) == 0) {
       		srtcp_index_len = hex2bin((char*)ibuf+16, srtcp_index);
	    }
	    /* If we have all the arguments then run the kdf */
	    if (srtp_index_len && srtcp_index_len && kdr_len && ms_len && km_len) {

	        out = malloc(128);  /* overkill for buffer overrun */
		if (!out) {
		    printf("\nFailed to malloc out");
		    return -1;
		}
		if (VERBOSE) printf("\nProcessing KDF for SRTP");
		memset(out, 0, 128);
		ret = kdf_srtp(cipher, (char *)km, (char *)ms, (char *)kdr, 
		               (char *)srtp_index, 00, (char *)out);

		if (ret == 0) {
		    OutputValue("SRTP k_e", out, len, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
	        }
		memset(out, 0, 128);
		ret = kdf_srtp(cipher, (char *)km, (char *)ms, (char *)kdr, 
		               (char *)srtp_index, 01, (char *)out);

		if (ret == 0) {
		    OutputValue("SRTP k_a", out, 20, rfp, 0);
                } else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
	        }
		memset(out, 0, 128);
		ret = kdf_srtp(cipher, (char *)km, (char *)ms, (char *)kdr, 
		               (char *)srtp_index, 02, (char *)out);

	        if (ret == 0) {
		    OutputValue("SRTP k_s", out, 14, rfp, 0);
                } else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
	        }
		memset(out, 0, 128);
		ret = kdf_srtp(cipher, (char *)km, (char *)ms, (char *)kdr, 
		               (char *)srtcp_index, 03, (char *)out);

		if (ret == 0) {
		    OutputValue("SRTCP k_e", out, len, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
		}
		memset(out, 0, 128);
		ret = kdf_srtp(cipher, (char *)km, (char *)ms, (char *)kdr, 
		               (char *)srtcp_index, 04, (char *)out);

		if (ret == 0) {
		    OutputValue("SRTCP k_a", out, 20, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
		}
		memset(out, 0, 128);
		ret = kdf_srtp(cipher, (char *)km, (char *)ms, (char *)kdr, 
		               (char *)srtcp_index, 05, (char *)out);

		if (ret == 0) {
		    OutputValue("SRTCP k_s", out, 14, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
		}

		km_len = ms_len = kdr_len = srtp_index_len = srtcp_index_len = 0;
		counter++;
		step = 2;
		if (out) {
	            free(out);
	        }
	    }
	    break;
        }
	/* each length has 100 passes */
	if (counter == SRTP_COUNTER) {
	    counter = 0;
	    step = 1;
        }	    
    }

    free(ms);
    free(km);
    free(kdr);
    free(srtp_index);
    free(srtcp_index);

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
int fips_kdf_srtp_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
    {
    char *rspfile = NULL;
    char fn[250] = "";
    fips_algtest_init();

    if (VERBOSE) 
        printf("\nKDF SRTP start: %s\n", argv[1]);

    strcpy(fn, argv[1]);
    rspfile = argv[2];
    if (proc_kdf_srtp_file(fn, rspfile))
	{
	printf(">>> Processing failed for: %s <<<\n", fn);
	}
    return 0;
    }
#endif
