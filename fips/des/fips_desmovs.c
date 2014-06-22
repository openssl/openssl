/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
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
/*---------------------------------------------
  NIST DES Modes of Operation Validation System
  Test Program

  Based on the AES Validation Suite, which was:
  Donated to OpenSSL by:
  V-ONE Corporation
  20250 Century Blvd, Suite 300
  Germantown, MD 20874
  U.S.A.
  ----------------------------------------------*/

#define OPENSSL_FIPSAPI

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <openssl/err.h>
#include "e_os.h"

#ifndef OPENSSL_FIPS

int main(int argc, char *argv[])
{
    printf("No FIPS DES support\n");
    return(0);
}

#else

#include "fips_utl.h"
#include <openssl/fips.h>

#define DES_BLOCK_SIZE 8

#define VERBOSE 0

static int DESTest(EVP_CIPHER_CTX *ctx,
	    char *amode, int akeysz, unsigned char *aKey,
	    unsigned char *iVec,
	    int dir,  /* 0 = decrypt, 1 = encrypt */
	    unsigned char *out, unsigned char *in, int len)
    {
    const EVP_CIPHER *cipher = NULL;

    if (akeysz != 192)
	{
	printf("Invalid key size: %d\n", akeysz);
	return 0;
	}

    if (fips_strcasecmp(amode, "CBC") == 0)
	cipher = EVP_des_ede3_cbc();
    else if (fips_strcasecmp(amode, "ECB") == 0)
	cipher = EVP_des_ede3_ecb();
    else if (fips_strcasecmp(amode, "CFB64") == 0)
	cipher = EVP_des_ede3_cfb64();
    else if (fips_strncasecmp(amode, "OFB", 3) == 0)
	cipher = EVP_des_ede3_ofb();
    else if(!fips_strcasecmp(amode,"CFB8"))
	cipher = EVP_des_ede3_cfb8();
    else if(!fips_strcasecmp(amode,"CFB1"))
	cipher = EVP_des_ede3_cfb1();
    else
	{
	printf("Unknown mode: %s\n", amode);
	return 0;
	}

    if (FIPS_cipherinit(ctx, cipher, aKey, iVec, dir) <= 0)
	return 0;
    if(!fips_strcasecmp(amode,"CFB1"))
	M_EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS);
    FIPS_cipher(ctx, out, in, len);

    return 1;
    }
#if 0
static void DebugValue(char *tag, unsigned char *val, int len)
    {
    char obuf[2048];
    int olen;
    olen = bin2hex(val, len, obuf);
    printf("%s = %.*s\n", tag, olen, obuf);
    }
#endif
static void shiftin(unsigned char *dst,unsigned char *src,int nbits)
    {
    int n;

    /* move the bytes... */
    memmove(dst,dst+nbits/8,3*8-nbits/8);
    /* append new data */
    memcpy(dst+3*8-nbits/8,src,(nbits+7)/8);
    /* left shift the bits */
    if(nbits%8)
	for(n=0 ; n < 3*8 ; ++n)
	    dst[n]=(dst[n] << (nbits%8))|(dst[n+1] >> (8-nbits%8));
    }	

/*-----------------------------------------------*/
char *tdes_t_tag[2] = {"PLAINTEXT", "CIPHERTEXT"};
char *tdes_t_mode[6] = {"CBC","ECB","OFB","CFB1","CFB8","CFB64"};
enum tdes_Mode {TCBC, TECB, TOFB, TCFB1, TCFB8, TCFB64};
int Sizes[6]={64,64,64,1,8,64};

static int do_tmct(char *amode,
	    int akeysz, int numkeys, unsigned char *akey,unsigned char *ivec,
	    int dir, unsigned char *text, int len,
	    FILE *rfp)
    {
    int i,imode;
    unsigned char nk[4*8]; /* longest key+8 */
    unsigned char text0[8];

    for (imode=0 ; imode < 6 ; ++imode)
	if(!strcmp(amode,tdes_t_mode[imode]))
	    break;
    if (imode == 6)
	{
	printf("Unrecognized mode: %s\n", amode);
	return 0;
	}
    for(i=0 ; i < 400 ; ++i)
	{
	int j;
	int n;
	int kp=akeysz/64;
	unsigned char old_iv[8];
	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);

	fprintf(rfp,RESP_EOL "COUNT = %d" RESP_EOL,i);
	if(kp == 1)
	    OutputValue("KEY",akey,8,rfp,0);
	else
	    for(n=0 ; n < kp ; ++n)
		{
		fprintf(rfp,"KEY%d",n+1);
		OutputValue("",akey+n*8,8,rfp,0);
		}

	if(imode != TECB)
	    OutputValue("IV",ivec,8,rfp,0);
	OutputValue(tdes_t_tag[dir^1],text,len,rfp,imode == TCFB1);
#if 0
	/* compensate for endianness */
	if(imode == TCFB1)
	    text[0]<<=7;
#endif
	memcpy(text0,text,8);

	for(j=0 ; j < 10000 ; ++j)
	    {
	    unsigned char old_text[8];

	    memcpy(old_text,text,8);
	    if(j == 0)
		{
		memcpy(old_iv,ivec,8);
		DESTest(&ctx,amode,akeysz,akey,ivec,dir,text,text,len);
		}
	    else
		{
		memcpy(old_iv,ctx.iv,8);
		FIPS_cipher(&ctx,text,text,len);
		}
	    if(j == 9999)
		{
		OutputValue(tdes_t_tag[dir],text,len,rfp,imode == TCFB1);
		/*		memcpy(ivec,text,8); */
		}
	    /*	    DebugValue("iv",ctx.iv,8); */
	    /* accumulate material for the next key */
	    shiftin(nk,text,Sizes[imode]);
	    /*	    DebugValue("nk",nk,24);*/
	    if((dir && (imode == TCFB1 || imode == TCFB8
			|| imode == TCFB64 || imode == TCBC)) || imode == TOFB)
		memcpy(text,old_iv,8);

	    if(!dir && (imode == TCFB1 || imode == TCFB8 || imode == TCFB64))
		{
		/* the test specifies using the output of the raw DES operation
		   which we don't have, so reconstruct it... */
		for(n=0 ; n < 8 ; ++n)
		    text[n]^=old_text[n];
		}
	    }
	for(n=0 ; n < 8 ; ++n)
	    akey[n]^=nk[16+n];
	for(n=0 ; n < 8 ; ++n)
	    akey[8+n]^=nk[8+n];
	for(n=0 ; n < 8 ; ++n)
	    akey[16+n]^=nk[n];
	if(numkeys < 3)
	    memcpy(&akey[2*8],akey,8);
	if(numkeys < 2)
	    memcpy(&akey[8],akey,8);
	DES_set_odd_parity((DES_cblock *)akey);
	DES_set_odd_parity((DES_cblock *)(akey+8));
	DES_set_odd_parity((DES_cblock *)(akey+16));
	memcpy(ivec,ctx.iv,8);

	/* pointless exercise - the final text doesn't depend on the
	   initial text in OFB mode, so who cares what it is? (Who
	   designed these tests?) */
	if(imode == TOFB)
	    for(n=0 ; n < 8 ; ++n)
		text[n]=text0[n]^old_iv[n];
	FIPS_cipher_ctx_cleanup(&ctx);
	}
    return 1;
    }

static int tproc_file(char *rqfile, char *rspfile)
    {
    char afn[256], rfn[256];
    FILE *afp = NULL, *rfp = NULL;
    char ibuf[2048], tbuf[2048];
    int len;
    char amode[8] = "";
    char atest[100] = "";
    int akeysz=0;
    unsigned char iVec[20], aKey[40];
    int dir = -1, err = 0, step = 0, echo = 1;
    unsigned char plaintext[2048];
    unsigned char ciphertext[2048];
    char *rp;
    EVP_CIPHER_CTX ctx;
    int numkeys=1;
    FIPS_cipher_ctx_init(&ctx);

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
	assert(rp);
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
	/*	printf("step=%d ibuf=%s",step,ibuf);*/
	if(step == 3 && !strcmp(amode,"ECB"))
	    {
	    memset(iVec, 0, sizeof(iVec));
	    step = (dir)? 4: 5;  /* no ivec for ECB */
	    }
	switch (step)
	    {
	case 0:  /* read preamble */
	    if (ibuf[0] == '\n')
		{ /* end of preamble */
		if (*amode == '\0')
		    {
		    printf("Missing Mode\n");
		    err = 1;
		    }
		else
		    {
		    copy_line(ibuf, rfp);
		    ++ step;
		    }
		}
	    else if (ibuf[0] != '#')
		{
		printf("Invalid preamble item: %s\n", ibuf);
		err = 1;
		}
	    else
		{ /* process preamble */
		char *xp, *pp = ibuf+2;
		int n;
		if(*amode)
		    { /* insert current time & date */
		    time_t rtim = time(0);
		    fputs("# ", rfp);
		    copy_line(ctime(&rtim), rfp);
		    }
		else
		    {
		    copy_line(ibuf, rfp);
		    if(!strncmp(pp,"INVERSE ",8) || !strncmp(pp,"DES ",4)
		       || !strncmp(pp,"TDES ",5)
		       || !strncmp(pp,"PERMUTATION ",12)
		       || !strncmp(pp,"SUBSTITUTION ",13)
		       || !strncmp(pp,"VARIABLE ",9))
			{
			/* get test type */
			if(!strncmp(pp,"DES ",4))
			    pp+=4;
			else if(!strncmp(pp,"TDES ",5))
			    pp+=5;
			xp = strchr(pp, ' ');
			n = xp-pp;
			strncpy(atest, pp, n);
			atest[n] = '\0';
			/* get mode */
			xp = strrchr(pp, ' '); /* get mode" */
			n = strlen(xp+1)-1;
			strncpy(amode, xp+1, n);
			amode[n] = '\0';
			if (!strcmp(atest, "Monte"))
				echo = 0;
			/* amode[3] = '\0'; */
			if (VERBOSE)
				printf("Test=%s, Mode=%s\n",atest,amode);
			}
		    }
		}
	    break;

	case 1:  /* [ENCRYPT] | [DECRYPT] */
	    if(ibuf[0] == '\n')
		break;
	    if (ibuf[0] == '[')
		{
		copy_line(ibuf, rfp);
		++step;
		if (fips_strncasecmp(ibuf, "[ENCRYPT]", 9) == 0)
		    dir = 1;
		else if (fips_strncasecmp(ibuf, "[DECRYPT]", 9) == 0)
		    dir = 0;
		else
		    {
		    printf("Invalid keyword: %s\n", ibuf);
		    err = 1;
		    }
		break;
		}
	    else if (dir == -1)
		{
		err = 1;
		printf("Missing ENCRYPT/DECRYPT keyword\n");
		break;
		}
	    else
		step = 2;

	case 2: /* KEY = xxxx */
	    if(*ibuf == '\n')
		{
	        copy_line(ibuf, rfp);
		break;
                }
	    if(!fips_strncasecmp(ibuf,"COUNT = ",8))
		{
	        copy_line(ibuf, rfp);
		break;
                }
	    if(!fips_strncasecmp(ibuf,"COUNT=",6))
		{
	        copy_line(ibuf, rfp);
		break;
                }
	    if(!fips_strncasecmp(ibuf,"NumKeys = ",10))
		{
		numkeys=atoi(ibuf+10);
		break;
		}
	    if (echo)
	    	copy_line(ibuf, rfp);
	    if(!fips_strncasecmp(ibuf,"KEY = ",6))
		{
		akeysz=64;
		len = hex2bin((char*)ibuf+6, aKey);
		if (len < 0)
		    {
		    printf("Invalid KEY\n");
		    err=1;
		    break;
		    }
		PrintValue("KEY", aKey, len);
		++step;
		}
	    else if(!fips_strncasecmp(ibuf,"KEYs = ",7))
		{
		akeysz=64*3;
		len=hex2bin(ibuf+7,aKey);
		if(len != 8)
		    {
		    printf("Invalid KEY\n");
		    err=1;
		    break;
		    }
		memcpy(aKey+8,aKey,8);
		memcpy(aKey+16,aKey,8);
		ibuf[4]='\0';
		PrintValue("KEYs",aKey,len);
		++step;
		}
	    else if(!fips_strncasecmp(ibuf,"KEY",3))
		{
		int n=ibuf[3]-'1';

		akeysz=64*3;
		len=hex2bin(ibuf+7,aKey+n*8);
		if(len != 8)
		    {
		    printf("Invalid KEY\n");
		    err=1;
		    break;
		    }
		ibuf[4]='\0';
		PrintValue(ibuf,aKey,len);
		if(n == 2)
		    ++step;
		}
	    else
		{
		printf("Missing KEY\n");
		err = 1;
		}
	    break;

	case 3: /* IV = xxxx */
	    if (echo)
	    	copy_line(ibuf, rfp);
	    if (fips_strncasecmp(ibuf, "IV = ", 5) != 0)
		{
		printf("Missing IV\n");
		err = 1;
		}
	    else
		{
		len = hex2bin((char*)ibuf+5, iVec);
		if (len < 0)
		    {
		    printf("Invalid IV\n");
		    err =1;
		    break;
		    }
		PrintValue("IV", iVec, len);
		step = (dir)? 4: 5;
		}
	    break;

	case 4: /* PLAINTEXT = xxxx */
	    if (echo)
	    	copy_line(ibuf, rfp);
	    if (fips_strncasecmp(ibuf, "PLAINTEXT = ", 12) != 0)
		{
		printf("Missing PLAINTEXT\n");
		err = 1;
		}
	    else
		{
		int nn = strlen(ibuf+12);
		if(!strcmp(amode,"CFB1"))
		    len=bint2bin(ibuf+12,nn-1,plaintext);
		else
		    len=hex2bin(ibuf+12, plaintext);
		if (len < 0)
		    {
		    printf("Invalid PLAINTEXT: %s", ibuf+12);
		    err =1;
		    break;
		    }
		if (len >= (int)sizeof(plaintext))
		    {
		    printf("Buffer overflow\n");
		    }
		PrintValue("PLAINTEXT", (unsigned char*)plaintext, len);
		if (strcmp(atest, "Monte") == 0)  /* Monte Carlo Test */
		    {
		    if (!do_tmct(amode,akeysz,numkeys,aKey,iVec,
					dir,plaintext,len,rfp))
			return -1;
		    }
		else
		    {
		    assert(dir == 1);
		    DESTest(&ctx, amode, akeysz, aKey, iVec,
				  dir,  /* 0 = decrypt, 1 = encrypt */
				  ciphertext, plaintext, len);
		    OutputValue("CIPHERTEXT",ciphertext,len,rfp,
				!strcmp(amode,"CFB1"));
		    }
		step = 6;
		}
	    break;

	case 5: /* CIPHERTEXT = xxxx */
	    if (echo)
	    	copy_line(ibuf, rfp);
	    if (fips_strncasecmp(ibuf, "CIPHERTEXT = ", 13) != 0)
		{
		printf("Missing KEY\n");
		err = 1;
		}
	    else
		{
		if(!strcmp(amode,"CFB1"))
		    len=bint2bin(ibuf+13,strlen(ibuf+13)-1,ciphertext);
		else
		    len = hex2bin(ibuf+13,ciphertext);
		if (len < 0)
		    {
		    printf("Invalid CIPHERTEXT\n");
		    err =1;
		    break;
		    }
		
		PrintValue("CIPHERTEXT", ciphertext, len);
		if (strcmp(atest, "Monte") == 0)  /* Monte Carlo Test */
		    {
		    do_tmct(amode, akeysz, numkeys, aKey, iVec,
			   dir, ciphertext, len, rfp);
		    }
		else
		    {
		    assert(dir == 0);
		    DESTest(&ctx, amode, akeysz, aKey, iVec,
				  dir,  /* 0 = decrypt, 1 = encrypt */
				  plaintext, ciphertext, len);
		    OutputValue("PLAINTEXT",(unsigned char *)plaintext,len,rfp,
				!strcmp(amode,"CFB1"));
		    }
		step = 6;
		}
	    break;

	case 6:
	    if (ibuf[0] != '\n')
		{
		err = 1;
		printf("Missing terminator\n");
		}
	    else if (strcmp(atest, "MCT") != 0)
		{ /* MCT already added terminating nl */
		copy_line(ibuf, rfp);
		}
	    step = 1;
	    break;
	    }
	}
    if (rfp)
	fclose(rfp);
    if (afp)
	fclose(afp);
    FIPS_cipher_ctx_cleanup(&ctx);
    return err;
    }

/*--------------------------------------------------
  Processes either a single file or
  a set of files whose names are passed in a file.
  A single file is specified as:
    aes_test -f xxx.req
  A set of files is specified as:
    aes_test -d xxxxx.xxx
  The default is: -d req.txt
--------------------------------------------------*/
#ifdef FIPS_ALGVS
int fips_desmovs_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
    {
    char *rqlist = "req.txt", *rspfile = NULL;
    FILE *fp = NULL;
    char fn[250] = "", rfn[256] = "";
    int d_opt = 1;

    fips_algtest_init();
    if (argc > 1)
	{
	if (fips_strcasecmp(argv[1], "-d") == 0)
	    {
	    d_opt = 1;
	    }
	else if (fips_strcasecmp(argv[1], "-f") == 0)
	    {
	    d_opt = 0;
	    }
	else
	    {
	    printf("Invalid parameter: %s\n", argv[1]);
	    return 0;
	    }
	if (argc < 3)
	    {
	    printf("Missing parameter\n");
	    return 0;
	    }
	if (d_opt)
	    rqlist = argv[2];
	else
	    {
	    strcpy(fn, argv[2]);
	    rspfile = argv[3];
	    }
	}
    if (d_opt)
	{ /* list of files (directory) */
	if (!(fp = fopen(rqlist, "r")))
	    {
	    printf("Cannot open req list file\n");
	    return -1;
	    }
	while (fgets(fn, sizeof(fn), fp))
	    {
	    strtok(fn, "\r\n");
	    strcpy(rfn, fn);
	    printf("Processing: %s\n", rfn);
	    if (tproc_file(rfn, rspfile))
		{
		printf(">>> Processing failed for: %s <<<\n", rfn);
		return -1;
		}
	    }
	fclose(fp);
	}
    else /* single file */
	{
	if (VERBOSE)
		printf("Processing: %s\n", fn);
	if (tproc_file(fn, rspfile))
	    {
	    printf(">>> Processing failed for: %s <<<\n", fn);
	    }
	}
    return 0;
    }

#endif
