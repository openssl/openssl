/*------------------------------------------------------------------
 * fips/kdf/fips_kdf_snmp.c - SNMP KDF vector tests
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
    printf("No FIPS KDF SNMP support\n");
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


#define SNMP_COUNTER 100   /* Sample vectors may be less than 100 */
#define VERBOSE 0
/*-----------------------------------------------*/
static int proc_kdf_snmp_file (char *rqfile, char *rspfile)
    {
    char afn[256], rfn[256];
    FILE *afp = NULL, *rfp = NULL;
    unsigned char *out;
    char ibuf[2048];
    char tbuf[2048];
    int len, password_len = 0, e_len = 0;
    char pw_len[8];
    int err = 0, step = 0, preamble = 0, i;
    unsigned char *key;
    char *password;
    unsigned char *e_id;
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
    key = malloc(1024);
    e_id = malloc(256);
    password = malloc(1024);

    if (!key || !e_id || !password) {
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
	        if (preamble == 0)
		{ /* end of preamble */
		    printf("Missing parts of preamble \n");
		    err = 1;
		    break;
	        } else {
		    copy_line(ibuf, rfp);
		    step++;
		    break;
		}
            }
	    else if (ibuf[0] != '#')
		{
		printf("Invalid preamble item: %s\n", ibuf);
		err = 1;
		}
	    else
		{ /* process preamble */
		char *pp = ibuf+2;

		copy_line(ibuf, rfp);
		if (strncmp(pp, "SHA-1", 5) == 0)
		    {
		    preamble++;
		    }
		}
	    break;

	case 1:  /* read engineID and passwordLen */
            copy_line(ibuf, rfp);
	    if (ibuf[0] == '[') {
		if (fips_strncasecmp(ibuf+1, "engineID = ", 11) == 0) {
		    memset(e_id, 0, 128);
		    /* null terminate the engine ID */
		    for (i=0; i<128; i++) {
		        if (ibuf[i+12] == ']') {
		            ibuf[i+12] = 0;
		            break;
                        }
		    }
		    /* parse the length value, its in bits */
		    e_len = hex2bin((char*)ibuf+12, e_id);

		    if (VERBOSE) printf("\nFound engineID length = 0x%08x", e_len);
                } else { 
		    if (fips_strncasecmp(ibuf+1, "passwordLen = ", 14) == 0) {
		        memset(pw_len, 0, 4);

			strncpy(pw_len, (char*)ibuf+15, 4);
			for (i=0; i<4; i++) {
		            if (ibuf[i+15] == ']') {
		                pw_len[i] = 0;
			        break;
                            }
		        }
		        password_len = atoi(pw_len);
			if (VERBOSE) printf("\nFound passwordLen = 0x%08x", password_len);
		        step++;
                    }
		}
	    }
	    break;
	case 2:  /* read password, used for 100 tests */
	    copy_line(ibuf, rfp);
	    /* get the password and run the kdf */
	    if (strncmp(ibuf, "password = ", 11) == 0) {
		memset(password, 0, password_len+1);
		strncpy(password, (char*)ibuf+11, password_len);
	        if (VERBOSE) printf("\nPassword = %s, len = %d", password, password_len);

		out = malloc(4096);  /* overkill for buffer overrun */
		if (!out) {
		    printf("\nFailed to malloc out");
		    return -1;
		}
		if (VERBOSE) printf("\nProcessing KDF for SNMP");
		len = kdf_snmp(e_id, e_len, password, 
                               password_len, out);

	        if (len > 0) {
		    OutputValue("Shared_key", out, len, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
	        }
		counter++;
	        if (out) {
	           free(out);
	        }
	    }
	    break;
	}
	/* each length has 100 passes, counter pre-incremented */
	if (counter == SNMP_COUNTER) {
	    counter = 0;
	    step = 1;
        }	    
    }

    free(key);
    free(e_id);
    free(password);

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
int fips_kdf_snmp_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
    {
    char *rspfile = NULL;
    char fn[250] = "";
    fips_algtest_init();

    if (VERBOSE) 
        printf("\nKDF SNMP start: %s\n", argv[1]);

    strcpy(fn, argv[1]);
    rspfile = argv[2];
    if (proc_kdf_snmp_file(fn, rspfile))
	{
	printf(">>> Processing failed for: %s <<<\n", fn);
	}
    return 0;
    }
#endif
