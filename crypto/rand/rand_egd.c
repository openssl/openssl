/* crypto/rand/rand_egd.c */
/* Written by Ulf Moeller for the OpenSSL project. */
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

#include <openssl/rand.h>

/* Query the EGD <URL: http://www.lothar.com/tech/crypto/>.
 */

#if defined(WIN32) || defined(VMS) || defined(__VMS)
int RAND_egd(const char *path)
	{
	return(-1);
	}

int RAND_egd_bytes(const char *path,int bytes)
	{
	return(-1);
	}
#else
#include <openssl/opensslconf.h>
#include OPENSSL_UNISTD
#include <sys/types.h>
#include <sys/socket.h>
#ifndef NO_SYS_UN_H
#include <sys/un.h>
#else
struct	sockaddr_un {
	short	sun_family;		/* AF_UNIX */
	char	sun_path[108];		/* path name (gag) */
};
#endif /* NO_SYS_UN_H */
#include <string.h>

#ifndef offsetof
#  define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

int RAND_egd(const char *path)
	{
	int ret = -1;
	struct sockaddr_un addr;
	int len, num;
	int fd = -1;
	unsigned char buf[256];

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(path) > sizeof(addr.sun_path))
		return (-1);
	strcpy(addr.sun_path,path);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(path);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) return (-1);
	if (connect(fd, (struct sockaddr *)&addr, len) == -1) goto err;
	buf[0] = 1;
	buf[1] = 255;
	write(fd, buf, 2);
	if (read(fd, buf, 1) != 1) goto err;
	if (buf[0] == 0) goto err;
	num = read(fd, buf, 255);
	if (num < 1) goto err;
	RAND_seed(buf, num);
	if (RAND_status() == 1)
		ret = num;
 err:
	if (fd != -1) close(fd);
	return(ret);
	}

int RAND_egd_bytes(const char *path,int bytes)
	{
	int ret = 0;
	struct sockaddr_un addr;
	int len, num;
	int fd = -1;
	unsigned char buf[255];

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(path) > sizeof(addr.sun_path))
		return (-1);
	strcpy(addr.sun_path,path);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(path);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) return (-1);
	if (connect(fd, (struct sockaddr *)&addr, len) == -1) goto err;

	while(bytes > 0)
	    {
	    buf[0] = 1;
	    buf[1] = bytes < 255 ? bytes : 255;
	    write(fd, buf, 2);
	    if (read(fd, buf, 1) != 1)
		{
		ret=-1;
		goto err;
		}
	    if(buf[0] == 0)
		goto err;
	    num = read(fd, buf, buf[0]);
	    if (num < 1)
		{
		ret=-1;
		goto err;
		}
	    RAND_seed(buf, num);
	    if (RAND_status() != 1)
		{
		ret=-1;
		goto err;
		}
	    ret += num;
	    bytes-=num;
	    }
 err:
	if (fd != -1) close(fd);
	return(ret);
	}


#endif
