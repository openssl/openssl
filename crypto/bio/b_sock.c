/* crypto/bio/b_sock.c */
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

#ifndef NO_SOCK

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#define USE_SOCKETS
#include "cryptlib.h"
#include "bio.h"

/*	BIOerr(BIO_F_WSASTARTUP,BIO_R_WSASTARTUP ); */

#ifdef WIN16
#define SOCKET_PROTOCOL 0 /* more microsoft stupidity */
#else
#define SOCKET_PROTOCOL IPPROTO_TCP
#endif

#ifdef SO_MAXCONN
#define MAX_LISTEN  SOMAXCONN
#elif defined(SO_MAXCONN)
#define MAX_LISTEN  SO_MAXCONN
#else
#define MAX_LISTEN  32
#endif

#ifdef WINDOWS
static int wsa_init_done=0;
#endif

static unsigned long BIO_ghbn_hits=0L;
static unsigned long BIO_ghbn_miss=0L;

#define GHBN_NUM	4
static struct ghbn_cache_st
	{
	char name[129];
	struct hostent *ent;
	unsigned long order;
	} ghbn_cache[GHBN_NUM];

#ifndef NOPROTO
static int get_ip(char *str,unsigned char *ip);
static void ghbn_free(struct hostent *a);
static struct hostent *ghbn_dup(struct hostent *a);
#else
static int get_ip();
static void ghbn_free();
static struct hostent *ghbn_dup();
#endif

int BIO_get_host_ip(str,ip)
char *str;
unsigned char *ip;
	{
	int i;
	struct hostent *he;

	i=get_ip(str,ip);
	if (i > 0) return(1);
	if (i < 0)
		{
		BIOerr(BIO_F_BIO_GET_HOST_IP,BIO_R_INVALID_IP_ADDRESS);
		ERR_add_error_data(2,"host=",str);
		return(0);
		}
	else
		{ /* do a gethostbyname */
		if (!BIO_sock_init()) return(0);

		he=BIO_gethostbyname(str);
		if (he == NULL)
			{
			BIOerr(BIO_F_BIO_GET_HOST_IP,BIO_R_BAD_HOSTNAME_LOOKUP);
			ERR_add_error_data(2,"host=",str);
			return(0);
			}

		/* cast to short because of win16 winsock definition */
		if ((short)he->h_addrtype != AF_INET)
			{
			BIOerr(BIO_F_BIO_GET_HOST_IP,BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET);
			ERR_add_error_data(2,"host=",str);
			return(0);
			}
		for (i=0; i<4; i++)
			ip[i]=he->h_addr_list[0][i];
		}
	return(1);
	}

int BIO_get_port(str,port_ptr)
char *str;
short *port_ptr;
	{
	int i;
	struct servent *s;

	if (str == NULL)
		{
		BIOerr(BIO_F_BIO_GET_PORT,BIO_R_NO_PORT_DEFINED);
		return(0);
		}
	i=atoi(str);
	if (i != 0)
		*port_ptr=(unsigned short)i;
	else
		{
		s=getservbyname(str,"tcp");
		if (s == NULL)
			{
			if (strcmp(str,"http") == 0)
				*port_ptr=80;
			else if (strcmp(str,"telnet") == 0)
				*port_ptr=23;
			else if (strcmp(str,"socks") == 0)
				*port_ptr=1080;
			else if (strcmp(str,"https") == 0)
				*port_ptr=443;
			else if (strcmp(str,"ssl") == 0)
				*port_ptr=443;
			else if (strcmp(str,"ftp") == 0)
				*port_ptr=21;
			else if (strcmp(str,"gopher") == 0)
				*port_ptr=70;
#if 0
			else if (strcmp(str,"wais") == 0)
				*port_ptr=21;
#endif
			else
				{
				SYSerr(SYS_F_GETSERVBYNAME,get_last_socket_error());
				ERR_add_error_data(3,"service='",str,"'");
				return(0);
				}
			return(1);
			}
		*port_ptr=htons((unsigned short)s->s_port);
		}
	return(1);
	}

int BIO_sock_error(sock)
int sock;
	{
	int j,i,size;
		 
	size=sizeof(int);

	i=getsockopt(sock,SOL_SOCKET,SO_ERROR,(char *)&j,&size);
	if (i < 0)
		return(1);
	else
		return(j);
	}

long BIO_ghbn_ctrl(cmd,iarg,parg)
int cmd;
int iarg;
char *parg;
	{
	int i;
	char **p;

	switch (cmd)
		{
	case BIO_GHBN_CTRL_HITS:
		return(BIO_ghbn_hits);
		break;
	case BIO_GHBN_CTRL_MISSES:
		return(BIO_ghbn_miss);
		break;
	case BIO_GHBN_CTRL_CACHE_SIZE:
		return(GHBN_NUM);
		break;
	case BIO_GHBN_CTRL_GET_ENTRY:
		if ((iarg >= 0) && (iarg <GHBN_NUM) &&
			(ghbn_cache[iarg].order > 0))
			{
			p=(char **)parg;
			if (p == NULL) return(0);
			*p=ghbn_cache[iarg].name;
			ghbn_cache[iarg].name[128]='\0';
			return(1);
			}
		return(0);
		break;
	case BIO_GHBN_CTRL_FLUSH:
		for (i=0; i<GHBN_NUM; i++)
			ghbn_cache[i].order=0;
		break;
	default:
		return(0);
		}
	return(1);
	}

static struct hostent *ghbn_dup(a)
struct hostent *a;
	{
	struct hostent *ret;
	int i,j;

	ret=(struct hostent *)malloc(sizeof(struct hostent));
	if (ret == NULL) return(NULL);
	memset(ret,0,sizeof(struct hostent));

	for (i=0; a->h_aliases[i] != NULL; i++)
		;
	i++;
	ret->h_aliases=(char **)malloc(sizeof(char *)*i);
	memset(ret->h_aliases,0,sizeof(char *)*i);
	if (ret == NULL) goto err;

	for (i=0; a->h_addr_list[i] != NULL; i++)
		;
	i++;
	ret->h_addr_list=(char **)malloc(sizeof(char *)*i);
	memset(ret->h_addr_list,0,sizeof(char *)*i);
	if (ret->h_addr_list == NULL) goto err;

	j=strlen(a->h_name)+1;
	if ((ret->h_name=malloc(j)) == NULL) goto err;
	memcpy((char *)ret->h_name,a->h_name,j);
	for (i=0; a->h_aliases[i] != NULL; i++)
		{
		j=strlen(a->h_aliases[i])+1;
		if ((ret->h_aliases[i]=malloc(j)) == NULL) goto err;
		memcpy(ret->h_aliases[i],a->h_aliases[i],j);
		}
	ret->h_length=a->h_length;
	ret->h_addrtype=a->h_addrtype;
	for (i=0; a->h_addr_list[i] != NULL; i++)
		{
		if ((ret->h_addr_list[i]=malloc(a->h_length)) == NULL)
			goto err;
		memcpy(ret->h_addr_list[i],a->h_addr_list[i],a->h_length);
		}
	return(ret);
err:	
	if (ret != NULL)
		ghbn_free(ret);
	return(NULL);
	}

static void ghbn_free(a)
struct hostent *a;
	{
	int i;

	if (a->h_aliases != NULL)
		{
		for (i=0; a->h_aliases[i] != NULL; i++)
			free(a->h_aliases[i]);
		free(a->h_aliases);
		}
	if (a->h_addr_list != NULL)
		{
		for (i=0; a->h_addr_list[i] != NULL; i++)
			free(a->h_addr_list[i]);
		free(a->h_addr_list);
		}
	if (a->h_name != NULL) free((char *)a->h_name);
	free(a);
	}

struct hostent *BIO_gethostbyname(name)
char *name;
	{
	struct hostent *ret;
	int i,lowi=0,j;
	unsigned long low= (unsigned long)-1;

/*	return(gethostbyname(name)); */

	CRYPTO_w_lock(CRYPTO_LOCK_BIO_GETHOSTBYNAME);
	j=strlen(name);
	if (j < 128)
		{
		for (i=0; i<GHBN_NUM; i++)
			{
			if (low > ghbn_cache[i].order)
				{
				low=ghbn_cache[i].order;
				lowi=i;
				}
			if (ghbn_cache[i].order > 0)
				{
				if (strncmp(name,ghbn_cache[i].name,128) == 0)
					break;
				}
			}
		}
	else
		i=GHBN_NUM;

	if (i == GHBN_NUM) /* no hit*/
		{
		BIO_ghbn_miss++;
		ret=gethostbyname(name);

		if (ret == NULL) return(NULL);
		if (j > 128) return(ret); /* too big to cache */

		/* else add to cache */
		if (ghbn_cache[lowi].ent != NULL)
			ghbn_free(ghbn_cache[lowi].ent);

		strncpy(ghbn_cache[lowi].name,name,128);
		ghbn_cache[lowi].ent=ghbn_dup(ret);
		ghbn_cache[lowi].order=BIO_ghbn_miss+BIO_ghbn_hits;
		}
	else
		{
		BIO_ghbn_hits++;
		ret= ghbn_cache[i].ent;
		ghbn_cache[i].order=BIO_ghbn_miss+BIO_ghbn_hits;
		}
	CRYPTO_w_unlock(CRYPTO_LOCK_BIO_GETHOSTBYNAME);
	return(ret);
	}

int BIO_sock_init()
	{
#ifdef WINDOWS
	static struct WSAData wsa_state;

	if (!wsa_init_done)
		{
		int err;
	  
#ifdef SIGINT
		signal(SIGINT,(void (*)(int))BIO_sock_cleanup);
#endif
		wsa_init_done=1;
		memset(&wsa_state,0,sizeof(wsa_state));
		if (WSAStartup(0x0101,&wsa_state)!=0)
			{
			err=WSAGetLastError();
			SYSerr(SYS_F_WSASTARTUP,err);
			BIOerr(BIO_F_BIO_SOCK_INIT,BIO_R_WSASTARTUP);
			return(-1);
			}
		}
#endif /* WINDOWS */
	return(1);
	}

void BIO_sock_cleanup()
	{
#ifdef WINDOWS
	if (wsa_init_done)
		{
		wsa_init_done=0;
		WSACancelBlockingCall();
		WSACleanup();
		}
#endif
	}

int BIO_socket_ioctl(fd,type,arg)
int fd;
long type;
unsigned long *arg;
	{
	int i;

	i=ioctlsocket(fd,type,arg);
	if (i < 0)
		SYSerr(SYS_F_IOCTLSOCKET,get_last_socket_error());
	return(i);
	}

/* The reason I have implemented this instead of using sscanf is because
 * Visual C 1.52c gives an unresolved external when linking a DLL :-( */
static int get_ip(str,ip)
char *str;
unsigned char ip[4];
	{
	unsigned int tmp[4];
	int num=0,c,ok=0;

	tmp[0]=tmp[1]=tmp[2]=tmp[3]=0;

	for (;;)
		{
		c= *(str++);
		if ((c >= '0') && (c <= '9'))
			{
			ok=1;
			tmp[num]=tmp[num]*10+c-'0';
			if (tmp[num] > 255) return(-1);
			}
		else if (c == '.')
			{
			if (!ok) return(-1);
			if (num == 3) break;
			num++;
			ok=0;
			}
		else if ((num == 3) && ok)
			break;
		else
			return(0);
		}
	ip[0]=tmp[0];
	ip[1]=tmp[1];
	ip[2]=tmp[2];
	ip[3]=tmp[3];
	return(1);
	}

int BIO_get_accept_socket(host)
char *host;
	{
	int ret=0;
	struct sockaddr_in server;
	int s= -1;
	unsigned char ip[4];
	short port;
	char *str,*h,*p,*e;
	unsigned long l;

	if (!BIO_sock_init()) return(INVALID_SOCKET);

	if ((str=BUF_strdup(host)) == NULL) return(INVALID_SOCKET);

	h=p=NULL;
	h=str;
	for (e=str; *e; e++)
		{
		if (*e == ':')
			{
			p= &(e[1]);
			*e='\0';
			}
		else if (*e == '/')
			{
			*e='\0';
			break;
			}
		}

	if (p == NULL)
		{
		p=h;
		h="*";
		}

	if (!BIO_get_port(p,&port)) return(INVALID_SOCKET);

	memset((char *)&server,0,sizeof(server));
	server.sin_family=AF_INET;
	server.sin_port=htons((unsigned short)port);

	if (strcmp(h,"*") == 0)
		server.sin_addr.s_addr=INADDR_ANY;
	else
		{
		if (!BIO_get_host_ip(h,&(ip[0]))) return(INVALID_SOCKET);
		l=(unsigned long)
			((unsigned long)ip[0]<<24L)|
			((unsigned long)ip[0]<<16L)|
			((unsigned long)ip[0]<< 8L)|
			((unsigned long)ip[0]);
		server.sin_addr.s_addr=htonl(l);
		}

	s=socket(AF_INET,SOCK_STREAM,SOCKET_PROTOCOL);
	if (s == INVALID_SOCKET)
		{
		SYSerr(SYS_F_SOCKET,get_last_socket_error());
		ERR_add_error_data(3,"port='",host,"'");
		BIOerr(BIO_F_BIO_GET_ACCEPT_SOCKET,BIO_R_UNABLE_TO_CREATE_SOCKET);
		goto err;
		}
	if (bind(s,(struct sockaddr *)&server,sizeof(server)) == -1)
		{
		SYSerr(SYS_F_BIND,get_last_socket_error());
		ERR_add_error_data(3,"port='",host,"'");
		BIOerr(BIO_F_BIO_GET_ACCEPT_SOCKET,BIO_R_UNABLE_TO_BIND_SOCKET);
		goto err;
		}
	if (listen(s,MAX_LISTEN) == -1)
		{
		SYSerr(SYS_F_BIND,get_last_socket_error());
		ERR_add_error_data(3,"port='",host,"'");
		BIOerr(BIO_F_BIO_GET_ACCEPT_SOCKET,BIO_R_UNABLE_TO_LISTEN_SOCKET);
		goto err;
		}
	ret=1;
err:
	if (str != NULL) Free(str);
	if ((ret == 0) && (s != INVALID_SOCKET))
		{
#ifdef WINDOWS
		closesocket(s);
#else
		close(s);
#endif
		s= INVALID_SOCKET;
		}
	return(s);
	}

int BIO_accept(sock,addr)
int sock;
char **addr;
	{
	int ret=INVALID_SOCKET;
	static struct sockaddr_in from;
	unsigned long l;
	short port;
	int len;
	char *p;

	memset((char *)&from,0,sizeof(from));
	len=sizeof(from);
	ret=accept(sock,(struct sockaddr *)&from,&len);
	if (ret == INVALID_SOCKET)
		{
		SYSerr(SYS_F_ACCEPT,get_last_socket_error());
		BIOerr(BIO_F_BIO_ACCEPT,BIO_R_ACCEPT_ERROR);
		goto end;
		}

	if (addr == NULL) goto end;

	l=ntohl(from.sin_addr.s_addr);
	port=ntohs(from.sin_port);
	if (*addr == NULL)
		{
		if ((p=Malloc(24)) == NULL)
			{
			BIOerr(BIO_F_BIO_ACCEPT,ERR_R_MALLOC_FAILURE);
			goto end;
			}
		*addr=p;
		}
	sprintf(*addr,"%d.%d.%d.%d:%d",
		(unsigned char)(l>>24L)&0xff,
		(unsigned char)(l>>16L)&0xff,
		(unsigned char)(l>> 8L)&0xff,
		(unsigned char)(l     )&0xff,
		port);
end:
	return(ret);
	}

int BIO_set_tcp_ndelay(s,on)
int s;
int on;
	{
	int ret=0;
#if defined(TCP_NODELAY) && (defined(IPPROTO_TCP) || defined(SOL_TCP))
	int opt;

#ifdef SOL_TCP
	opt=SOL_TCP;
#else
#ifdef IPPROTO_TCP
	opt=IPPROTO_TCP;
#endif
#endif
	
	ret=setsockopt(s,opt,TCP_NODELAY,(char *)&on,sizeof(on));
#endif
	return(ret == 0);
	}
#endif

