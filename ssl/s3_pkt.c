/* ssl/s3_pkt.c */
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

#include <stdio.h>
#include <errno.h>
#define USE_SOCKETS
#include "evp.h"
#include "buffer.h"
#include "ssl_locl.h"

/* SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_PEER_ERROR_NO_CIPHER);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_PEER_ERROR_NO_CERTIFICATE);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_PEER_ERROR_CERTIFICATE);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_UNKNOWN_REMOTE_ERROR_TYPE);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_BAD_RECORD_MAC);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_NO_CERTIFICATE);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_BAD_CERTIFICATE);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN);
 * SSLerr(SSL_F_GET_SERVER_HELLO,SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER);
 */

#ifndef NOPROTO
static int do_ssl3_write(SSL *s, int type, char *buf, unsigned int len);
static int ssl3_write_pending(SSL *s, int type, char *buf, unsigned int len);
static int ssl3_get_record(SSL *s);
static int do_compress(SSL *ssl);
static int do_uncompress(SSL *ssl);
static int do_change_cipher_spec(SSL *ssl);
#else
static int do_ssl3_write();
static int ssl3_write_pending();
static int ssl3_get_record();
static int do_compress();
static int do_uncompress();
static int do_change_cipher_spec();
#endif

static int ssl3_read_n(s,n,max,extend)
SSL *s;
int n;
int max;
int extend;
	{
	int i,off,newb;

	/* if there is stuff still in the buffer from a previous read,
	 * and there is more than we want, take some. */
	if (s->s3->rbuf.left >= (int)n)
		{
		if (extend)
			s->packet_length+=n;
		else
			{
			s->packet= &(s->s3->rbuf.buf[s->s3->rbuf.offset]);
			s->packet_length=n;
			}
		s->s3->rbuf.left-=n;
		s->s3->rbuf.offset+=n;
		return(n);
		}

	/* else we need to read more data */
	if (!s->read_ahead) max=n;
	if (max > SSL3_RT_MAX_PACKET_SIZE)
		max=SSL3_RT_MAX_PACKET_SIZE;

	/* First check if there is some left or we want to extend */
	off=0;
	if (	(s->s3->rbuf.left != 0) ||
		((s->packet_length != 0) && extend))
		{
		newb=s->s3->rbuf.left;
		if (extend)
			{
			/* Copy bytes back to the front of the buffer 
			 * Take the bytes already pointed to by 'packet'
			 * and take the extra ones on the end. */
			off=s->packet_length;
			if (s->packet != s->s3->rbuf.buf)
				memcpy(s->s3->rbuf.buf,s->packet,newb+off);
			}
		else if (s->s3->rbuf.offset != 0)
			{ /* so the data is not at the start of the buffer */
			memcpy(s->s3->rbuf.buf,
				&(s->s3->rbuf.buf[s->s3->rbuf.offset]),newb);
			s->s3->rbuf.offset=0;
			}

		s->s3->rbuf.left=0;
		}
	else
		newb=0;

	/* So we now have 'newb' bytes at the front of 
	 * s->s3->rbuf.buf and need to read some more in on the end
	 * We start reading into the buffer at 's->s3->rbuf.offset'
	 */
	s->packet=s->s3->rbuf.buf;

	while (newb < n)
		{
		clear_sys_error();
		if (s->rbio != NULL)
			{
			s->rwstate=SSL_READING;
			i=BIO_read(s->rbio,
				(char *)&(s->s3->rbuf.buf[off+newb]),
				max-newb);
			}
		else
			{
			SSLerr(SSL_F_SSL3_READ_N,SSL_R_READ_BIO_NOT_SET);
			i= -1;
			}

		if (i <= 0)
			{
			s->s3->rbuf.left+=newb;
			return(i);
			}
		newb+=i;
		}

	/* record used data read */
	if (newb > n)
		{
		s->s3->rbuf.offset=n+off;
		s->s3->rbuf.left=newb-n;
		}
	else
		{
		s->s3->rbuf.offset=0;
		s->s3->rbuf.left=0;
		}

	if (extend)
		s->packet_length+=n;
	else
		s->packet_length+=n;
	return(n);
	}

/* Call this to get a new input record.
 * It will return <= 0 if more data is needed, normally due to an error
 * or non-blocking IO.
 * When it finishes, one packet has been decoded and can be found in
 * ssl->s3->rrec.type	- is the type of record
 * ssl->s3->rrec.data, 	- data
 * ssl->s3->rrec.length, - number of bytes
 */
static int ssl3_get_record(s)
SSL *s;
	{
	char tmp_buf[512];
	int ssl_major,ssl_minor,al;
	int n,i,ret= -1;
	SSL3_BUFFER *rb;
	SSL3_RECORD *rr;
	SSL_SESSION *sess;
	unsigned char *p;
	unsigned char md[EVP_MAX_MD_SIZE];
	short version;
	unsigned int mac_size;
	int clear=0,extra;

	rr= &(s->s3->rrec);
	rb= &(s->s3->rbuf);
	sess=s->session;

	if (s->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER)
		extra=SSL3_RT_MAX_EXTRA;
	else
		extra=0;

again:
	/* check if we have the header */
	if (	(s->rstate != SSL_ST_READ_BODY) ||
		(s->packet_length < SSL3_RT_HEADER_LENGTH)) 
		{
		n=ssl3_read_n(s,SSL3_RT_HEADER_LENGTH,
			SSL3_RT_MAX_PACKET_SIZE,0);
		if (n <= 0) return(n); /* error or non-blocking */
		s->rstate=SSL_ST_READ_BODY;

		p=s->packet;

		/* Pull apart the header into the SSL3_RECORD */
		rr->type= *(p++);
		ssl_major= *(p++);
		ssl_minor= *(p++);
		version=(ssl_major<<8)|ssl_minor;
		n2s(p,rr->length);

		/* Lets check version */
		if (s->first_packet)
			{
			s->first_packet=0;
			}
		else
			{
			if (version != s->version)
				{
				SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_WRONG_VERSION_NUMBER);
				/* Send back error using their
				 * version number :-) */
				s->version=version;
				al=SSL_AD_PROTOCOL_VERSION;
				goto f_err;
				}
			}

		if ((version>>8) != SSL3_VERSION_MAJOR)
			{
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_WRONG_VERSION_NUMBER);
			goto err;
			}

		if (rr->length > 
			(unsigned int)SSL3_RT_MAX_ENCRYPTED_LENGTH+extra)
			{
			al=SSL_AD_RECORD_OVERFLOW;
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_PACKET_LENGTH_TOO_LONG);
			goto f_err;
			}

		s->rstate=SSL_ST_READ_BODY;
		}

	/* get and decode the data */
	if (s->rstate == SSL_ST_READ_BODY)
		{
		if (rr->length > (s->packet_length-SSL3_RT_HEADER_LENGTH))
			{
			i=rr->length;
			/*-(s->packet_length-SSL3_RT_HEADER_LENGTH); */
			n=ssl3_read_n(s,i,i,1);
			if (n <= 0) return(n); /* error or non-blocking io */
			}
		s->rstate=SSL_ST_READ_HEADER;
		}

	/* At this point, we have the data in s->packet and there should be
	 * s->packet_length bytes, we must not 'overrun' this buffer :-)
	 * One of the following functions will copy the data from the
	 * s->packet buffer */

	rr->input= &(s->packet[SSL3_RT_HEADER_LENGTH]);

	/* ok, we can now read from 's->packet' data into 'rr'
	 * rr->input points at rr->length bytes, which
	 * need to be copied into rr->data by either
	 * the decryption or by the decompression
	 * When the data is 'copied' into the rr->data buffer,
	 * rr->input will be pointed at the new buffer */ 

	/* Set the state for the following operations */
	s->rstate=SSL_ST_READ_HEADER;

	/* We now have - encrypted [ MAC [ compressed [ plain ] ] ]
	 * rr->length bytes of encrypted compressed stuff. */

	/* check is not needed I belive */
	if (rr->length > (unsigned int)SSL3_RT_MAX_ENCRYPTED_LENGTH+extra)
		{
		al=SSL_AD_RECORD_OVERFLOW;
		SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
		goto f_err;
		}

	/* decrypt in place in 'rr->input' */
	rr->data=rr->input;
	memcpy(tmp_buf,rr->input,(rr->length > 512)?512:rr->length);

	if (!s->method->ssl3_enc->enc(s,0))
		{
		al=SSL_AD_DECRYPT_ERROR;
		goto f_err;
		}
#ifdef TLS_DEBUG
printf("dec %d\n",rr->length);
{ int z; for (z=0; z<rr->length; z++) printf("%02X%c",rr->data[z],((z+1)%16)?' ':'\n'); }
printf("\n");
#endif
	/* r->length is now the compressed data plus mac */
	if (	(sess == NULL) ||
		(s->enc_read_ctx == NULL) ||
		(s->read_hash == NULL))
		clear=1;

	if (!clear)
		{
		mac_size=EVP_MD_size(s->read_hash);

		if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH+extra+mac_size)
			{
			al=SSL_AD_RECORD_OVERFLOW;
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_PRE_MAC_LENGTH_TOO_LONG);
			goto f_err;
			}
		/* check MAC for rr->input' */
		if (rr->length < mac_size)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		rr->length-=mac_size;
		i=s->method->ssl3_enc->mac(s,md,0);
		if (memcmp(md,&(rr->data[rr->length]),mac_size) != 0)
			{
			al=SSL_AD_BAD_RECORD_MAC;
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_BAD_MAC_DECODE);
			ret= -1;
			goto f_err;
			}
		}

	/* r->length is now just compressed */
	if ((sess != NULL) && (sess->read_compression != NULL))
		{
		if (rr->length > 
			(unsigned int)SSL3_RT_MAX_COMPRESSED_LENGTH+extra)
			{
			al=SSL_AD_RECORD_OVERFLOW;
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_COMPRESSED_LENGTH_TOO_LONG);
			goto f_err;
			}
		if (!do_uncompress(s))
			{
			al=SSL_AD_DECOMPRESSION_FAILURE;
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_BAD_DECOMPRESSION);
			goto f_err;
			}
		}

	if (rr->length > (unsigned int)SSL3_RT_MAX_PLAIN_LENGTH+extra)
		{
		al=SSL_AD_RECORD_OVERFLOW;
		SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_DATA_LENGTH_TOO_LONG);
		goto f_err;
		}

	rr->off=0;
	/* So at this point the following is true
	 * ssl->s3->rrec.type 	is the type of record
	 * ssl->s3->rrec.length	== number of bytes in record
	 * ssl->s3->rrec.off	== offset to first valid byte
	 * ssl->s3->rrec.data	== where to take bytes from, increment
	 *			   after use :-).
	 */

	/* we have pulled in a full packet so zero things */
	s->packet_length=0;

	/* just read a 0 length packet */
	if (rr->length == 0) goto again;

	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	return(ret);
	}

static int do_uncompress(ssl)
SSL *ssl;
	{
	return(1);
	}

static int do_compress(ssl)
SSL *ssl;
	{
	return(1);
	}

/* Call this to write data
 * It will return <= 0 if not all data has been sent or non-blocking IO.
 */
int ssl3_write_bytes(s,type,buf,len)
SSL *s;
int type;
char *buf;
int len;
	{
	unsigned int tot,n,nw;
	int i;

	s->rwstate=SSL_NOTHING;
	tot=s->s3->wnum;
	s->s3->wnum=0;

	if (SSL_in_init(s) && !s->in_handshake)
		{
		i=s->handshake_func(s);
		if (i < 0) return(i);
		if (i == 0)
			{
			SSLerr(SSL_F_SSL3_WRITE_BYTES,SSL_R_SSL_HANDSHAKE_FAILURE);
			return(-1);
			}
		}

	n=(len-tot);
	for (;;)
		{
		if (n > SSL3_RT_MAX_PLAIN_LENGTH)
			nw=SSL3_RT_MAX_PLAIN_LENGTH;
		else
			nw=n;
			
		i=do_ssl3_write(s,type,&(buf[tot]),nw);
		if (i <= 0)
			{
			s->s3->wnum=tot;
			return(i);
			}

		if (type == SSL3_RT_HANDSHAKE)
			ssl3_finish_mac(s,(unsigned char *)&(buf[tot]),i);

		if (i == (int)n) return(tot+i);

		n-=i;
		tot+=i;
		}
	}

static int do_ssl3_write(s,type,buf,len)
SSL *s;
int type;
char *buf;
unsigned int len;
	{
	unsigned char *p,*plen;
	int i,mac_size,clear=0;
	SSL3_RECORD *wr;
	SSL3_BUFFER *wb;
	SSL_SESSION *sess;

	/* first check is there is a SSL3_RECORD still being written
	 * out.  This will happen with non blocking IO */
	if (s->s3->wbuf.left != 0)
		return(ssl3_write_pending(s,type,buf,len));

	/* If we have an alert to send, lets send it */
	if (s->s3->alert_dispatch)
		{
		i=ssl3_dispatch_alert(s);
		if (i <= 0)
			return(i);
		/* if it went, fall through and send more stuff */
		}

	if (len <= 0) return(len);
	
	wr= &(s->s3->wrec);
	wb= &(s->s3->wbuf);
	sess=s->session;

	if (	(sess == NULL) ||
		(s->enc_write_ctx == NULL) ||
		(s->write_hash == NULL))
		clear=1;

	if (clear)
		mac_size=0;
	else
		mac_size=EVP_MD_size(s->write_hash);

	p=wb->buf;

	/* write the header */
	*(p++)=type&0xff;
	wr->type=type;

	*(p++)=(s->version>>8);
	*(p++)=s->version&0xff;
	
	/* record where we are to write out packet length */
	plen=p; 
	p+=2;
	
	/* lets setup the record stuff. */
	wr->data=p;
	wr->length=(int)len;
	wr->input=(unsigned char *)buf;

	/* we now 'read' from wr->input, wr->length bytes into
	 * wr->data */

	/* first we compress */
	if ((sess != NULL) && (sess->write_compression != NULL))
		{
		if (!do_compress(s))
			{
			SSLerr(SSL_F_DO_SSL3_WRITE,SSL_R_COMPRESSION_FAILURE);
			goto err;
			}
		}
	else
		{
		memcpy(wr->data,wr->input,wr->length);
		wr->input=wr->data;
		}

	/* we should still have the output to wr->data and the input
	 * from wr->input.  Length should be wr->length.
	 * wr->data still points in the wb->buf */

	if (mac_size != 0)
		{
		s->method->ssl3_enc->mac(s,&(p[wr->length]),1);
		wr->length+=mac_size;
		wr->input=p;
		wr->data=p;
		}

	/* ssl3_enc can only have an error on read */
	s->method->ssl3_enc->enc(s,1);

	/* record length after mac and block padding */
	s2n(wr->length,plen);

	/* we should now have
	 * wr->data pointing to the encrypted data, which is
	 * wr->length long */
	wr->type=type; /* not needed but helps for debugging */
	wr->length+=SSL3_RT_HEADER_LENGTH;

	/* Now lets setup wb */
	wb->left=wr->length;
	wb->offset=0;

	s->s3->wpend_tot=len;
	s->s3->wpend_buf=buf;
	s->s3->wpend_type=type;
	s->s3->wpend_ret=len;

	/* we now just need to write the buffer */
	return(ssl3_write_pending(s,type,buf,len));
err:
	return(-1);
	}

/* if s->s3->wbuf.left != 0, we need to call this */
static int ssl3_write_pending(s,type,buf,len)
SSL *s;
int type;
char *buf;
unsigned int len;
	{
	int i;

/* XXXX */
	if ((s->s3->wpend_tot > (int)len) || (s->s3->wpend_buf != buf)
		|| (s->s3->wpend_type != type))
		{
		SSLerr(SSL_F_SSL3_WRITE_PENDING,SSL_R_BAD_WRITE_RETRY);
		return(-1);
		}

	for (;;)
		{
		clear_sys_error();
		if (s->wbio != NULL)
			{
			s->rwstate=SSL_WRITING;
			i=BIO_write(s->wbio,
				(char *)&(s->s3->wbuf.buf[s->s3->wbuf.offset]),
				(unsigned int)s->s3->wbuf.left);
			}
		else
			{
			SSLerr(SSL_F_SSL3_WRITE_PENDING,SSL_R_BIO_NOT_SET);
			i= -1;
			}
		if (i == s->s3->wbuf.left)
			{
			s->s3->wbuf.left=0;
			s->rwstate=SSL_NOTHING;
			return(s->s3->wpend_ret);
			}
		else if (i <= 0)
			return(i);
		s->s3->wbuf.offset+=i;
		s->s3->wbuf.left-=i;
		}
	}

int ssl3_read_bytes(s,type,buf,len)
SSL *s;
int type;
char *buf;
int len;
	{
	int al,i,j,n,ret;
	SSL3_RECORD *rr;
	void (*cb)()=NULL;
	BIO *bio;

	if (s->s3->rbuf.buf == NULL) /* Not initalised yet */
		if (!ssl3_setup_buffers(s))
			return(-1);

	if (!s->in_handshake && SSL_in_init(s))
		{
		i=s->handshake_func(s);
		if (i < 0) return(i);
		if (i == 0)
			{
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_SSL_HANDSHAKE_FAILURE);
			return(-1);
			}
		}
start:
	s->rwstate=SSL_NOTHING;

	/* s->s3->rrec.type	- is the type of record
	 * s->s3->rrec.data, 	- data
	 * s->s3->rrec.off, 	- ofset into 'data' for next read
	 * s->s3->rrec.length,	- number of bytes. */
	rr= &(s->s3->rrec);

	/* get new packet */
	if ((rr->length == 0) || (s->rstate == SSL_ST_READ_BODY))
		{
		ret=ssl3_get_record(s);
		if (ret <= 0) return(ret);
		}

	/* we now have a packet which can be read and processed */

	if (s->s3->change_cipher_spec && (rr->type != SSL3_RT_HANDSHAKE))
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_DATA_BETWEEN_CCS_AND_FINISHED);
		goto err;
		}

	/* If the other end has shutdown, throw anything we read away */
	if (s->shutdown & SSL_RECEIVED_SHUTDOWN)
		{
		rr->length=0;
		s->rwstate=SSL_NOTHING;
		return(0);
		}

	/* Check for an incoming 'Client Request' message */
	if ((rr->type == SSL3_RT_HANDSHAKE) && (rr->length == 4) &&
		(rr->data[0] == SSL3_MT_CLIENT_REQUEST) &&
		(s->session != NULL) && (s->session->cipher != NULL))
		{
		if ((rr->data[1] != 0) || (rr->data[2] != 0) ||
			(rr->data[3] != 0))
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_BAD_CLIENT_REQUEST);
			goto err;
			}

		if (SSL_is_init_finished(s) &&
			!(s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS) &&
			!s->s3->renegotiate)
			{
			ssl3_renegotiate(s);
			if (ssl3_renegotiate_check(s))
				{
				n=s->handshake_func(s);
				if (n < 0) return(n);
				if (n == 0)
					{
					SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_SSL_HANDSHAKE_FAILURE);
					return(-1);
					}
				}
			}
		rr->length=0;
/* ZZZ */	goto start;
		}

	/* if it is not the type we want, or we have shutdown and want
	 * the peer shutdown */
	if ((rr->type != type) || (s->shutdown & SSL_SENT_SHUTDOWN))
		{
		if (rr->type == SSL3_RT_ALERT)
			{
			if ((rr->length != 2) || (rr->off != 0))
				{
				al=SSL_AD_DECODE_ERROR;
				SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_BAD_ALERT_RECORD);
				goto f_err;
				}

			i=rr->data[0];
			n=rr->data[1];

			/* clear from buffer */
			rr->length=0;

			if (s->info_callback != NULL)
				cb=s->info_callback;
			else if (s->ctx->info_callback != NULL)
				cb=s->ctx->info_callback;

			if (cb != NULL)
				{
				j=(i<<8)|n;
				cb(s,SSL_CB_READ_ALERT,j);
				}

			if (i == 1)
				{
				s->s3->warn_alert=n;
				if (n == SSL_AD_CLOSE_NOTIFY)
					{
					s->shutdown|=SSL_RECEIVED_SHUTDOWN;
					return(0);
					}
				}
			else if (i == 2)
				{
				char tmp[16];

				s->rwstate=SSL_NOTHING;
				s->s3->fatal_alert=n;
				SSLerr(SSL_F_SSL3_READ_BYTES,1000+n);
				sprintf(tmp,"%d",n);
				ERR_add_error_data(2,"SSL alert number ",tmp);
				s->shutdown|=SSL_RECEIVED_SHUTDOWN;
				SSL_CTX_remove_session(s->ctx,s->session);
				return(0);
				}
			else
				{
				al=SSL_AD_ILLEGAL_PARAMETER;
				SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_UNKNOWN_ALERT_TYPE);
				goto f_err;
				}

			rr->length=0;
			goto start;
			}

		if (s->shutdown & SSL_SENT_SHUTDOWN)
			{
			s->rwstate=SSL_NOTHING;
			rr->length=0;
			return(0);
			}

		if (rr->type == SSL3_RT_CHANGE_CIPHER_SPEC)
			{
			if (	(rr->length != 1) || (rr->off != 0) ||
				(rr->data[0] != SSL3_MT_CCS))
				{
				i=SSL_AD_ILLEGAL_PARAMETER;
				SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_BAD_CHANGE_CIPHER_SPEC);
				goto err;
				}

			rr->length=0;
			s->s3->change_cipher_spec=1;
			if (!do_change_cipher_spec(s))
				goto err;
			else
				goto start;
			}

		/* else we have a handshake */
		if ((rr->type == SSL3_RT_HANDSHAKE) &&
			!s->in_handshake)
			{
			if (((s->state&SSL_ST_MASK) == SSL_ST_OK) &&
				!(s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS))
				{
				s->state=SSL_ST_BEFORE;
				s->new_session=1;
				}
			n=s->handshake_func(s);
			if (n < 0) return(n);
			if (n == 0)
				{
				SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_SSL_HANDSHAKE_FAILURE);
				return(-1);
				}

			/* In the case where we try to read application data
			 * the first time, but we trigger an SSL handshake, we
			 * return -1 with the retry option set.  I do this
			 * otherwise renegotiation can cause nasty problems 
			 * in the non-blocking world */

			s->rwstate=SSL_READING;
			bio=SSL_get_rbio(s);
			BIO_clear_retry_flags(bio);
			BIO_set_retry_read(bio);
			return(-1);
			}

		switch (rr->type)
			{
		default:
#ifndef NO_TLS
			/* TLS just ignores unknown message types */
			if (s->version == TLS1_VERSION)
				{
				goto start;
				}
#endif
		case SSL3_RT_CHANGE_CIPHER_SPEC:
		case SSL3_RT_ALERT:
		case SSL3_RT_HANDSHAKE:
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_UNEXPECTED_RECORD);
			goto f_err;
		case SSL3_RT_APPLICATION_DATA:
			/* At this point, we were expecting something else,
			 * but have application data.  What we do is set the
			 * error, and return -1.  On the way out, if the
			 * library was running inside ssl3_read() and it makes
			 * sense to read application data at this point, we
			 * will indulge it.  This will mostly happen during
			 * session renegotiation.
			 */
			if (s->s3->in_read_app_data &&
				(s->s3->total_renegotiations != 0) &&
				((
				  (s->state & SSL_ST_CONNECT) &&
				  (s->state >= SSL3_ST_CW_CLNT_HELLO_A) &&
				  (s->state <= SSL3_ST_CR_SRVR_HELLO_A)
				 ) || (
				  (s->state & SSL_ST_ACCEPT) &&
				  (s->state <= SSL3_ST_SW_HELLO_REQ_A) &&
				  (s->state >= SSL3_ST_SR_CLNT_HELLO_A)
				 )
				))
				{
				s->s3->in_read_app_data=0;
				return(-1);
				}
			else
				{
				al=SSL_AD_UNEXPECTED_MESSAGE;
				SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_UNEXPECTED_RECORD);
				goto f_err;
				}
			}
		}

	/* make sure that we are not getting application data when we
	 * are doing a handshake for the first time */
	if (SSL_in_init(s) && (type == SSL3_RT_APPLICATION_DATA) &&
		(s->enc_read_ctx == NULL))
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_APP_DATA_IN_HANDSHAKE);
		goto f_err;
		}

	if (len <= 0) return(len);

	if ((unsigned int)len > rr->length)
		n=rr->length;
	else
		n=len;

	memcpy(buf,&(rr->data[rr->off]),(unsigned int)n);
	rr->length-=n;
	rr->off+=n;
	if (rr->length <= 0)
		{
		s->rstate=SSL_ST_READ_HEADER;
		rr->off=0;
		}

	if (type == SSL3_RT_HANDSHAKE)
		ssl3_finish_mac(s,(unsigned char *)buf,n);
	return(n);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	return(-1);
	}

static int do_change_cipher_spec(s)
SSL *s;
	{
	int i;
	unsigned char *sender;
	int slen;

	if (s->state & SSL_ST_ACCEPT)
		i=SSL3_CHANGE_CIPHER_SERVER_READ;
	else
		i=SSL3_CHANGE_CIPHER_CLIENT_READ;

	if (s->s3->tmp.key_block == NULL)
		{
		s->session->cipher=s->s3->tmp.new_cipher;
		if (!s->method->ssl3_enc->setup_key_block(s)) return(0);
		}

	if (!s->method->ssl3_enc->change_cipher_state(s,i))
		return(0);

	/* we have to record the message digest at
	 * this point so we can get it before we read
	 * the finished message */
	if (s->state & SSL_ST_CONNECT)
		{
		sender=s->method->ssl3_enc->server_finished;
		slen=s->method->ssl3_enc->server_finished_len;
		}
	else
		{
		sender=s->method->ssl3_enc->client_finished;
		slen=s->method->ssl3_enc->client_finished_len;
		}

	s->method->ssl3_enc->final_finish_mac(s,
		&(s->s3->finish_dgst1),
		&(s->s3->finish_dgst2),
		sender,slen,&(s->s3->tmp.finish_md[0]));

	return(1);
	}

int ssl3_do_write(s,type)
SSL *s;
int type;
	{
	int ret;

	ret=ssl3_write_bytes(s,type,(char *)
		&(s->init_buf->data[s->init_off]),s->init_num);
	if (ret == s->init_num)
		return(1);
	if (ret < 0) return(-1);
	s->init_off+=ret;
	s->init_num-=ret;
	return(0);
	}

void ssl3_send_alert(s,level,desc)
SSL *s;
int level;
int desc;
	{
	/* Map tls/ssl alert value to correct one */
	desc=s->method->ssl3_enc->alert_value(desc);
	if (desc < 0) return;
	/* If a fatal one, remove from cache */
	if ((level == 2) && (s->session != NULL))
		SSL_CTX_remove_session(s->ctx,s->session);

	s->s3->alert_dispatch=1;
	s->s3->send_alert[0]=level;
	s->s3->send_alert[1]=desc;
	if (s->s3->wbuf.left == 0) /* data still being written out */
		ssl3_dispatch_alert(s);
	/* else data is still being written out, we will get written
	 * some time in the future */
	}

int ssl3_dispatch_alert(s)
SSL *s;
	{
	int i,j;
	void (*cb)()=NULL;

	s->s3->alert_dispatch=0;
	i=do_ssl3_write(s,SSL3_RT_ALERT,&(s->s3->send_alert[0]),2);
	if (i <= 0)
		{
		s->s3->alert_dispatch=1;
		}
	else
		{
		/* If it is important, send it now.  If the message
		 * does not get sent due to non-blocking IO, we will
		 * not worry too much. */
		if (s->s3->send_alert[0] == SSL3_AL_FATAL)
			BIO_flush(s->wbio);

		if (s->info_callback != NULL)
			cb=s->info_callback;
		else if (s->ctx->info_callback != NULL)
			cb=s->ctx->info_callback;
		
		if (cb != NULL)
			{
			j=(s->s3->send_alert[0]<<8)|s->s3->send_alert[1];
			cb(s,SSL_CB_WRITE_ALERT,j);
			}
		}
	return(i);
	}

