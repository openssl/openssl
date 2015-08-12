/*------------------------------------------------------------------
 * fips/kdf/fips_kdf_ssh.c - SSH KDF vector tests
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
    printf("No FIPS KDF SSH support\n");
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


#define SSH_COUNTER 100   /* Sample vectors may be less than 100 */
#define VERBOSE 0
/*-----------------------------------------------*/
static int proc_kdf_ssh_file (char *rqfile, char *rspfile)
    {
    char afn[256], rfn[256];
    FILE *afp = NULL, *rfp = NULL;
    unsigned char *out;
    char ibuf[2048];
    char tbuf[2048];
    int ret, ss_len = 0, iv_len = 0, key_len = 0, sha_len;
    int k_len = 0, sid_len = 0, h_len = 0;
    unsigned char *sid = NULL, *hash = NULL, *key = NULL;
    char tmp_len[8];
    int err = 0, step = 0, i;
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
		if (fips_strncasecmp(ibuf+1, "shared secret length = ", 23) == 0) {
		    memset(tmp_len, 0, 8);
		    strncpy(tmp_len, (char*)ibuf+24, 4);
		    /* null terminate the engine ID */
		    for (i=0; i<8; i++) {
		        if (ibuf[i+24] == ']') {
		            tmp_len[i] = 0;
		            break;
                        }
		    }
		    ss_len = atoi(tmp_len)/8;
		    if (VERBOSE) printf("\nFound ss_len length = 0x%08x", ss_len);
                } 
		if (fips_strncasecmp(ibuf+1, "IV length = ", 12) == 0) {
		    memset(tmp_len, 0, 4);
		    strncpy(tmp_len, (char*)ibuf+13, 4);


		    for (i=0; i<8; i++) {
		        if (ibuf[i+13] == ']') {
		            tmp_len[i] = 0;
		            break;
                        }
		    }
		    iv_len = atoi(tmp_len)/8;
		    if (VERBOSE) printf("\nFound iv_len = 0x%08x", iv_len);
		}
		if (fips_strncasecmp(ibuf+1, "encryption key length = ", 24) == 0) {
		    memset(tmp_len, 0, 4);
		    strncpy(tmp_len, (char*)ibuf+25, 4);


		    for (i=0; i<8; i++) {
		        if (ibuf[i+24] == ']') {
		            tmp_len[i] = 0;
		            break;
                        }
		    }
		    key_len = atoi(tmp_len)/8;
		    if (VERBOSE) printf("\nFound key_len = 0x%08x", key_len);
		}
		/* ready for next step ? */
		if (ss_len && iv_len && key_len) {
		    step++;
                }
	    }
	    break;

	case 2:  /* read key, hash and session id, for each of 100 tests */
	    if (ibuf[0] == '\n') {
	        copy_line(ibuf, rfp);
	    }
	    /* get the password and run the kdf */
	    if (strncmp(ibuf, "K = ", 4) == 0) {
	        key = malloc(4200);  /* > 4K key plus 4 byte mpint */
		if (!key) {
		    printf("\nFailed to malloc key");
		    return -1;
		}
		/* strangely enough the whole buffer is used, including the mpint length */
	        k_len = hex2bin((char*)ibuf+4, key);
	        fprintf(rfp,"COUNT = %d" RESP_EOL ,counter);
	        copy_line(ibuf, rfp);
	    }
	    if (strncmp(ibuf, "H = ", 4) == 0) {
	        hash = malloc(evp_md->md_size);
		if (!hash) {
		    printf("\nFailed to malloc hash");
		    return -1;
		}
	        h_len = hex2bin((char*)ibuf+4, hash);
	        copy_line(ibuf, rfp);
	    }
	    if (strncmp(ibuf, "session_id = ", 13) == 0) {
	        sid = malloc(evp_md->md_size);
		if (!sid) {
		    printf("\nFailed to malloc sid");
		    return -1;
		}
	        sid_len = hex2bin((char*)ibuf+13, sid);
	        copy_line(ibuf, rfp);
	    }

	    /* If all have been read, process the kdf */
	    if (k_len && h_len && sid_len) {
		out = malloc(4096);  /* overkill for buffer overrun */
		if (!out) {
		    printf("\nFailed to malloc out");
		    return -1;
		}
		if (VERBOSE) printf("\nProcessing KDF for SSH");

		ret = kdf_ssh(evp_md, 'A', iv_len, (char *)key, k_len, (char *)sid, sid_len,
                              (char *)hash, h_len, out);
	        if (ret == 0) {
		    OutputValue("Initial IV (client to server)", out, iv_len, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
	        }

		ret = kdf_ssh(evp_md, 'B', iv_len, (char *)key, k_len, (char *)sid, sid_len,
                              (char *)hash, h_len, out);
	        if (ret == 0) {
		    OutputValue("Initial IV (server to client)", out, iv_len, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
	        }

		ret = kdf_ssh(evp_md, 'C', key_len, (char *)key, k_len, (char *)sid, sid_len,
                              (char *)hash, h_len, out);
	        if (ret == 0) {
		    OutputValue("Encryption key (client to server)", out, key_len, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
	        }

		ret = kdf_ssh(evp_md, 'D', key_len, (char *)key, k_len, (char *)sid, sid_len,
                              (char *)hash, h_len, out);
	        if (ret == 0) {
		    OutputValue("Encryption key (server to client)", out, key_len, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
	        }

		ret = kdf_ssh(evp_md, 'E', evp_md->md_size, (char *)key, k_len, (char *)sid, sid_len,
                              (char *)hash, h_len, out);
	        if (ret == 0) {
		    OutputValue("Integrity key (client to server)", out, evp_md->md_size, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
	        }

		ret = kdf_ssh(evp_md, 'F', evp_md->md_size, (char *)key, k_len, (char *)sid, sid_len,
                              (char *)hash, h_len, out);
	        if (ret == 0) {
		    OutputValue("Integrity key (server to client)", out, evp_md->md_size, rfp, 0);
		} else {
		    fprintf(rfp,"FAIL" RESP_EOL); 
	        }

		h_len = k_len = sid_len = 0;
		free(key);
		free(hash);
		free(sid);
		free(out);

		counter++;
	    }
	    break;
	}
	/* each length has 100 passes, counter pre-incremented */
	if (counter == SSH_COUNTER) {
	    counter = 0;
	    ss_len = iv_len = key_len = 0;
            fprintf(rfp, RESP_EOL);  /* add separator */
	    step = 1;
        }	    
    }


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
int fips_kdf_ssh_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
    {
    char *rspfile = NULL;
    char fn[250] = "";
    fips_algtest_init();

    if (VERBOSE) 
        printf("\nKDF SSH start: %s\n", argv[1]);

    strcpy(fn, argv[1]);
    rspfile = argv[2];
    if (proc_kdf_ssh_file(fn, rspfile))
	{
	printf(">>> Processing failed for: %s <<<\n", fn);
	}
    return 0;
    }
#endif
