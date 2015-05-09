/* $OpenBSD: s_socket.c,v 1.41 2014/06/12 15:49:27 deraadt Exp $ */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "apps.h"

#include <openssl/ssl.h>

#include "s_apps.h"

static int ssl_sock_init(void);
static int init_server(int *sock, int port, int type);
static int init_server_long(int *sock, int port, char *ip, int type);
static int do_accept(int acc_sock, int *sock, char **host);

#define SOCKET_PROTOCOL	IPPROTO_TCP

static int
ssl_sock_init(void)
{
	return (1);
}

int
init_client(int *sock, char *host, char *port, int type, int af)
{
	struct addrinfo hints, *ai_top, *ai;
	int i, s;

	if (!ssl_sock_init())
		return (0);

	memset(&hints, '\0', sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = type;

	if ((i = getaddrinfo(host, port, &hints, &ai_top)) != 0) {
		BIO_printf(bio_err, "getaddrinfo: %s\n", gai_strerror(i));
		return (0);
	}
	if (ai_top == NULL || ai_top->ai_addr == NULL) {
		BIO_printf(bio_err, "getaddrinfo returned no addresses\n");
		if (ai_top != NULL) {
			freeaddrinfo(ai_top);
		}
		return (0);
	}
	for (ai = ai_top; ai != NULL; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1) {
			continue;
		}
		if (type == SOCK_STREAM) {
			i = 0;
			i = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
			    (char *) &i, sizeof(i));
			if (i < 0) {
				perror("keepalive");
				close(s);
				return (0);
			}
		}
		if ((i = connect(s, ai->ai_addr, ai->ai_addrlen)) == 0) {
			*sock = s;
			freeaddrinfo(ai_top);
			return (1);
		}
		close(s);
	}

	perror("connect");
	close(s);
	freeaddrinfo(ai_top);
	return (0);
}

int
do_server(int port, int type, int *ret,
    int (*cb) (char *hostname, int s, unsigned char *context),
    unsigned char *context)
{
	int sock;
	char *name = NULL;
	int accept_socket = 0;
	int i;

	if (!init_server(&accept_socket, port, type))
		return (0);

	if (ret != NULL) {
		*ret = accept_socket;
		/* return(1); */
	}
	for (;;) {
		if (type == SOCK_STREAM) {
			if (do_accept(accept_socket, &sock, &name) == 0) {
				shutdown(accept_socket, SHUT_RD);
				close(accept_socket);
				return (0);
			}
		} else
			sock = accept_socket;
		i = (*cb) (name, sock, context);
		free(name);
		if (type == SOCK_STREAM) {
			shutdown(sock, SHUT_RDWR);
			close(sock);
		}
		if (i < 0) {
			shutdown(accept_socket, SHUT_RDWR);
			close(accept_socket);
			return (i);
		}
	}
}

static int
init_server_long(int *sock, int port, char *ip, int type)
{
	int ret = 0;
	struct sockaddr_in server;
	int s = -1;

	if (!ssl_sock_init())
		return (0);

	memset((char *) &server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons((unsigned short) port);
	if (ip == NULL)
		server.sin_addr.s_addr = INADDR_ANY;
	else
		memcpy(&server.sin_addr.s_addr, ip, 4);

	if (type == SOCK_STREAM)
		s = socket(AF_INET, SOCK_STREAM, SOCKET_PROTOCOL);
	else			/* type == SOCK_DGRAM */
		s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (s == -1)
		goto err;
#if defined SOL_SOCKET && defined SO_REUSEADDR
	{
		int j = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
		    (void *) &j, sizeof j);
	}
#endif
	if (bind(s, (struct sockaddr *) & server, sizeof(server)) == -1) {
		perror("bind");
		goto err;
	}
	/* Make it 128 for linux */
	if (type == SOCK_STREAM && listen(s, 128) == -1)
		goto err;
	*sock = s;
	ret = 1;
err:
	if ((ret == 0) && (s != -1)) {
		shutdown(s, SHUT_RD);
		close(s);
	}
	return (ret);
}

static int
init_server(int *sock, int port, int type)
{
	return (init_server_long(sock, port, NULL, type));
}

static int
do_accept(int acc_sock, int *sock, char **host)
{
	int ret;
	struct hostent *h1, *h2;
	static struct sockaddr_in from;
	socklen_t len;
/*	struct linger ling; */

	if (!ssl_sock_init())
		return (0);

redoit:

	memset((char *) &from, 0, sizeof(from));
	len = sizeof(from);
	ret = accept(acc_sock, (struct sockaddr *) & from, &len);
	if (ret == -1) {
		if (errno == EINTR) {
			/* check_timeout(); */
			goto redoit;
		}
		fprintf(stderr, "errno=%d ", errno);
		perror("accept");
		return (0);
	}
/*
	ling.l_onoff=1;
	ling.l_linger=0;
	i=setsockopt(ret,SOL_SOCKET,SO_LINGER,(char *)&ling,sizeof(ling));
	if (i < 0) { perror("linger"); return(0); }
	i=0;
	i=setsockopt(ret,SOL_SOCKET,SO_KEEPALIVE,(char *)&i,sizeof(i));
	if (i < 0) { perror("keepalive"); return(0); }
*/

	if (host == NULL)
		goto end;
	h1 = gethostbyaddr((char *) &from.sin_addr.s_addr,
	    sizeof(from.sin_addr.s_addr), AF_INET);
	if (h1 == NULL) {
		BIO_printf(bio_err, "bad gethostbyaddr\n");
		*host = NULL;
		/* return(0); */
	} else {
		if ((*host = strdup(h1->h_name)) == NULL) {
			perror("strdup");
			close(ret);
			return (0);
		}

		h2 = gethostbyname(*host);
		if (h2 == NULL) {
			BIO_printf(bio_err, "gethostbyname failure\n");
			close(ret);
			return (0);
		}
		if (h2->h_addrtype != AF_INET) {
			BIO_printf(bio_err, "gethostbyname addr is not AF_INET\n");
			close(ret);
			return (0);
		}
	}

end:
	*sock = ret;
	return (1);
}

int
extract_host_port(char *str, char **host_ptr, unsigned char *ip,
    char **port_ptr)
{
	char *h, *p;

	h = str;
	p = strrchr(str, '/');	/* IPv6 host/port */
	if (p == NULL) {
		p = strrchr(str, ':');
	}
	if (p == NULL) {
		BIO_printf(bio_err, "no port defined\n");
		return (0);
	}
	*(p++) = '\0';

	if (host_ptr != NULL)
		*host_ptr = h;

	if (port_ptr != NULL && p != NULL && *p != '\0')
		*port_ptr = p;

	return (1);
}

int
extract_port(char *str, short *port_ptr)
{
	int i;
	const char *errstr;
	struct servent *s;

	i = strtonum(str, 1, 65535, &errstr);
	if (!errstr) {
		*port_ptr = (unsigned short) i;
	} else {
		s = getservbyname(str, "tcp");
		if (s == NULL) {
			BIO_printf(bio_err, "getservbyname failure for %s\n", str);
			return (0);
		}
		*port_ptr = ntohs((unsigned short) s->s_port);
	}
	return (1);
}
