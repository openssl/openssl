/* crypto/rand/rand_vms.c -*- mode:C; c-file-style: "eay" -*- */
/* Written by Richard Levitte <richard@levitte.org> for the OpenSSL
 * project 2000.
 * RAND_poll() written by Taka Shinagawa <takaaki.shinagawa@compaq.com>
 * for the OpenSSL project.
 */
 */
/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/rand.h>
#include "rand_lcl.h"

#if defined(OPENSSL_SYS_VMS)
#define __NEW_STARLET 1
#define NUM_OF_ITEMS 11

#include <efndef.h>
#include <descrip.h>
#include <jpidef.h>

#ifdef __alpha
#include <iledef.h>
#include <iosbdef.h>
#else
typedef struct _ile3 {                 /* Copied from ILEDEF.H for Alpha   */
#pragma __nomember_alignment
    unsigned short int ile3$w_length;   /* Length of buffer in bytes        */
    unsigned short int ile3$w_code;     /* Item code value                  */
    void *ile3$ps_bufaddr;              /* Buffer address                   */
    unsigned short int *ile3$ps_retlen_addr; /* Address of word for returned length */
    } ILE3;

typedef struct _iosb {                 /* Copied from IOSBDEF.H for Alpha  */
#pragma __nomember_alignment
    __union  {
        __struct  {
            unsigned short int iosb$w_status; /* Final I/O status           */
            __union  {
                __struct  {             /* 16-bit byte count variant        */
                    unsigned short int iosb$w_bcnt; /* 16-bit byte count    */
                    __union  {
                        unsigned int iosb$l_dev_depend; /* 32-bit device dependent info */
                        unsigned int iosb$l_pid; /* 32-bit pid              */
                        } iosb$r_l;
                    } iosb$r_bcnt_16;
                __struct  {             /* 32-bit byte count variant        */
                    unsigned int iosb$l_bcnt; /* 32-bit byte count (unaligned) */
                    unsigned short int iosb$w_dev_depend_high; /* 16-bit device dependent info */
                    } iosb$r_bcnt_32;
                } iosb$r_devdepend;
            } iosb$r_io_64;
        __struct  {
            __union  {
                unsigned int iosb$l_getxxi_status; /* Final GETxxI status   */
                unsigned int iosb$l_reg_status; /* Final $Registry status   */
                } iosb$r_l_status;
            unsigned int iosb$l_reserved; /* Reserved field                 */
            } iosb$r_get_64;
        } iosb$r_io_get;
    } IOSB;

#if !defined(__VAXC)
#define iosb$w_status iosb$r_io_get.iosb$r_io_64.iosb$w_status
#define iosb$w_bcnt iosb$r_io_get.iosb$r_io_64.iosb$r_devdepend.iosb$r_bcnt_16.iosb$w_bcnt
#define iosb$r_l        iosb$r_io_get.iosb$r_io_64.iosb$r_devdepend.iosb$r_bcnt_16.iosb$r_l
#define iosb$l_dev_depend iosb$r_l.iosb$l_dev_depend
#define iosb$l_pid iosb$r_l.iosb$l_pid
#define iosb$l_bcnt iosb$r_io_get.iosb$r_io_64.iosb$r_devdepend.iosb$r_bcnt_32.iosb$l_bcnt
#define iosb$w_dev_depend_high iosb$r_io_get.iosb$r_io_64.iosb$r_devdepend.iosb$r_bcnt_32.iosb$w_dev_depend_high
#define iosb$l_getxxi_status iosb$r_io_get.iosb$r_get_64.iosb$r_l_status.iosb$l_getxxi_status
#define iosb$l_reg_status iosb$r_io_get.iosb$r_get_64.iosb$r_l_status.iosb$l_reg_status
#endif          /* #if !defined(__VAXC) */

#endif                                 /* End of IOSBDEF */

#include <syidef.h>
#include <ssdef.h>
#include <starlet.h>
#ifdef __DECC
# pragma message disable DOLLARID
#endif

static struct items_data_st
	{
	short length, code;	/* length is amount of bytes */
	} items_data[] =
		{ { 4, JPI$_BUFIO },
		  { 4, JPI$_CPUTIM },
		  { 4, JPI$_DIRIO },
		  { 4, JPI$_IMAGECOUNT },
		  { 8, JPI$_LAST_LOGIN_I },
		  { 8, JPI$_LOGINTIM },
		  { 4, JPI$_PAGEFLTS },
		  { 4, JPI$_PID },
		  { 4, JPI$_PPGCNT },
		  { 4, JPI$_WSSIZE },
		  { 4, JPI$_WSPEAK },
		  { 4, JPI$_FINALEXC },
		  { 0, 0 }
		};
		  
int RAND_poll(void)
	{
	IOSB iosb;
	long pid;
	int status = 0;
#if __INITIAL_POINTER_SIZE == 64
	ILEB_64 item[32], *pitem;
#else
	ILE3 item[32], *pitem;
#endif
	int data_buffer[256];
	int total_length = 0;
	struct items_data_st *pitems_data;

	pitems_data = items_data;
	pitem = item;

	/* Setup */
	while (pitems_data->length)
		{
#if __INITIAL_POINTER_SIZE == 64

		pitem->ileb_64$w_mbo = 1;
		pitem->ileb_64$w_code = pitems_data->code;
		pitem->ileb_64$l_mbmo = -1;
                pitem->ileb_64$q_length = pitems_data->length;
                pitem->ileb_64$pq_bufaddr = &data_buffer[total_length];
                pitem->ileb_64$pq_retlen_addr = (unsigned __int64 *)&length;
		
                total_length += pitems_data->length/4;
#else
                pitem->ile3$w_length = (short)pitems_data->length;
                pitem->ile3$w_code = (short)pitems_data->code;
                pitem->ile3$ps_bufaddr = &data_buffer[total_length];
                pitem->ile3$ps_retlen_addr = &length;
               
		total_length += pitems_data->length/4;
#endif
		pitems_data++;
		pitem++;
		}
	/* Last item of the item list is null terminated */
#if __INITIAL_POINTER_SIZE == 64
	pitem->ileb_64$q_length = pitem->ileb_64$w_code = 0;
#else
	pitem->ile3$w_length = pitem->ile3$w_code = 0;
#endif

	/*
	 * Scan through all the processes in the system and add entropy with
	 * results from the processes that were possible to look at.
	 * However, view the information as only half trustable.
	 */
	pid = -1;			/* search context */
	while ((status = sys$getjpiw(EFN$C_ENF, &pid,  0, item, iosb, 0, 0))
		!= SS$_NOMOREPROC)
		{
		if (status == SS$_NORMAL)
			{
			int i;
			int tmp_length;

			for(i = 0; i < total_length; i++)
				{
				unsigned int sys_time[2];

				sys$gettim(sys_time);
				srand(sys_time[0]*data_buffer[0]*data_buffer[1]+i);
				if(i==(total_length-1)) /* for JPI$_FINALEXC */
					{
					long int *ptr = (long *)data_buffer[i];
					tmp_length = 0;

					for(j=0; j<4; j++)
						{
						data_buffer[i+j] = ptr[j];
						/* OK to use rand() just
						   to scramble the seed */
						data_buffer[i+j] ^=
							(sys_time ^ rand());
						tmp_length++;
						}
					}
				else
					{
					/* OK to use rand() just
					   to scramble the seed */
					data_buffer[i] ^= (sys_time ^ rand());
					}
				}
			total_length += (tmp_length - 1);

			/* size of seed is total_length*4 bytes (64bytes) */
			RAND_add(data_buffer, total_length, total_length*2);
			}
		}
	return RAND_status();
}

#endif
