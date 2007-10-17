/* ssl/d1_both.c */
/* 
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.  
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>


/* XDTLS:  figure out the right values */
static unsigned int g_probable_mtu[] = {1500 - 28, 512 - 28, 256 - 28};

static unsigned int dtls1_min_mtu(void);
static unsigned int dtls1_guess_mtu(unsigned int curr_mtu);
static void dtls1_fix_message_header(SSL *s, unsigned long frag_off, 
	unsigned long frag_len);
static unsigned char *dtls1_write_message_header(SSL *s,
	unsigned char *p);
static void dtls1_set_message_header_int(SSL *s, unsigned char mt,
	unsigned long len, unsigned short seq_num, unsigned long frag_off, 
	unsigned long frag_len);
static int dtls1_retransmit_buffered_messages(SSL *s);
static long dtls1_get_message_fragment(SSL *s, int st1, int stn, 
	long max, int *ok);

static hm_fragment *
dtls1_hm_fragment_new(unsigned long frag_len)
	{
	hm_fragment *frag = NULL;
	unsigned char *buf = NULL;

	frag = (hm_fragment *)OPENSSL_malloc(sizeof(hm_fragment));
	if ( frag == NULL)
		return NULL;

	if (frag_len)
		{
		buf = (unsigned char *)OPENSSL_malloc(frag_len);
		if ( buf == NULL)
			{
			OPENSSL_free(frag);
			return NULL;
			}
		}

	/* zero length fragment gets zero frag->fragment */
	frag->fragment = buf;

	return frag;
	}

static void
dtls1_hm_fragment_free(hm_fragment *frag)
	{
	if (frag->fragment) OPENSSL_free(frag->fragment);
	OPENSSL_free(frag);
	}

/* send s->init_buf in records of type 'type' (SSL3_RT_HANDSHAKE or SSL3_RT_CHANGE_CIPHER_SPEC) */
int dtls1_do_write(SSL *s, int type)
	{
	int ret;
	int curr_mtu;
	unsigned int len, frag_off;

	/* AHA!  Figure out the MTU, and stick to the right size */
	if ( ! (SSL_get_options(s) & SSL_OP_NO_QUERY_MTU))
		{
		s->d1->mtu = 
			BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_QUERY_MTU, 0, NULL);

		/* I've seen the kernel return bogus numbers when it doesn't know
		 * (initial write), so just make sure we have a reasonable number */
		if ( s->d1->mtu < dtls1_min_mtu())
			{
			s->d1->mtu = 0;
			s->d1->mtu = dtls1_guess_mtu(s->d1->mtu);
			BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SET_MTU, 
				s->d1->mtu, NULL);
			}
		}
#if 0 
	mtu = s->d1->mtu;

	fprintf(stderr, "using MTU = %d\n", mtu);

	mtu -= (DTLS1_HM_HEADER_LENGTH + DTLS1_RT_HEADER_LENGTH);

	curr_mtu = mtu - BIO_wpending(SSL_get_wbio(s));

	if ( curr_mtu > 0)
		mtu = curr_mtu;
	else if ( ( ret = BIO_flush(SSL_get_wbio(s))) <= 0)
		return ret;

	if ( BIO_wpending(SSL_get_wbio(s)) + s->init_num >= mtu)
		{
		ret = BIO_flush(SSL_get_wbio(s));
		if ( ret <= 0)
			return ret;
		mtu = s->d1->mtu - (DTLS1_HM_HEADER_LENGTH + DTLS1_RT_HEADER_LENGTH);
		}

	OPENSSL_assert(mtu > 0);  /* should have something reasonable now */

#endif

	if ( s->init_off == 0  && type == SSL3_RT_HANDSHAKE)
		OPENSSL_assert(s->init_num == 
			(int)s->d1->w_msg_hdr.msg_len + DTLS1_HM_HEADER_LENGTH);

	frag_off = 0;
	while( s->init_num)
		{
		curr_mtu = s->d1->mtu - BIO_wpending(SSL_get_wbio(s)) - 
			DTLS1_RT_HEADER_LENGTH;

		if ( curr_mtu <= DTLS1_HM_HEADER_LENGTH)
			{
			/* grr.. we could get an error if MTU picked was wrong */
			ret = BIO_flush(SSL_get_wbio(s));
			if ( ret <= 0)
				return ret;
			curr_mtu = s->d1->mtu - DTLS1_RT_HEADER_LENGTH;
			}

		if ( s->init_num > curr_mtu)
			len = curr_mtu;
		else
			len = s->init_num;


		/* XDTLS: this function is too long.  split out the CCS part */
		if ( type == SSL3_RT_HANDSHAKE)
			{
			if ( s->init_off != 0)
				{
				OPENSSL_assert(s->init_off > DTLS1_HM_HEADER_LENGTH);
				s->init_off -= DTLS1_HM_HEADER_LENGTH;
				s->init_num += DTLS1_HM_HEADER_LENGTH;

				/* write atleast DTLS1_HM_HEADER_LENGTH bytes */
				if ( len <= DTLS1_HM_HEADER_LENGTH)  
					len += DTLS1_HM_HEADER_LENGTH;
				}

			dtls1_fix_message_header(s, frag_off, 
				len - DTLS1_HM_HEADER_LENGTH);

			dtls1_write_message_header(s, (unsigned char *)&s->init_buf->data[s->init_off]);

			OPENSSL_assert(len >= DTLS1_HM_HEADER_LENGTH);
			}

		ret=dtls1_write_bytes(s,type,&s->init_buf->data[s->init_off],
			len);
		if (ret < 0)
			{
			/* might need to update MTU here, but we don't know
			 * which previous packet caused the failure -- so can't
			 * really retransmit anything.  continue as if everything
			 * is fine and wait for an alert to handle the
			 * retransmit 
			 */
			if ( BIO_ctrl(SSL_get_wbio(s),
				BIO_CTRL_DGRAM_MTU_EXCEEDED, 0, NULL))
				s->d1->mtu = BIO_ctrl(SSL_get_wbio(s),
					BIO_CTRL_DGRAM_QUERY_MTU, 0, NULL);
			else
				return(-1);
			}
		else
			{

			/* bad if this assert fails, only part of the handshake
			 * message got sent.  but why would this happen? */
			OPENSSL_assert(len == (unsigned int)ret);

			if (type == SSL3_RT_HANDSHAKE && ! s->d1->retransmitting)
				{
				/* should not be done for 'Hello Request's, but in that case
				 * we'll ignore the result anyway */
				unsigned char *p = (unsigned char *)&s->init_buf->data[s->init_off];
				const struct hm_header_st *msg_hdr = &s->d1->w_msg_hdr;
				int xlen;

				if (frag_off == 0 && s->client_version != DTLS1_BAD_VER)
					{
					/* reconstruct message header is if it
					 * is being sent in single fragment */
					*p++ = msg_hdr->type;
					l2n3(msg_hdr->msg_len,p);
					s2n (msg_hdr->seq,p);
					l2n3(0,p);
					l2n3(msg_hdr->msg_len,p);
					p  -= DTLS1_HM_HEADER_LENGTH;
					xlen = ret;
					}
				else
					{
					p  += DTLS1_HM_HEADER_LENGTH;
					xlen = ret - DTLS1_HM_HEADER_LENGTH;
					}

				ssl3_finish_mac(s, p, xlen);
				}

			if (ret == s->init_num)
				{
				if (s->msg_callback)
					s->msg_callback(1, s->version, type, s->init_buf->data, 
						(size_t)(s->init_off + s->init_num), s, 
						s->msg_callback_arg);

				s->init_off = 0;  /* done writing this message */
				s->init_num = 0;

				return(1);
				}
			s->init_off+=ret;
			s->init_num-=ret;
			frag_off += (ret -= DTLS1_HM_HEADER_LENGTH);
			}
		}
	return(0);
	}


/* Obtain handshake message of message type 'mt' (any if mt == -1),
 * maximum acceptable body length 'max'.
 * Read an entire handshake message.  Handshake messages arrive in
 * fragments.
 */
long dtls1_get_message(SSL *s, int st1, int stn, int mt, long max, int *ok)
	{
	int i, al;
	struct hm_header_st *msg_hdr;

	/* s3->tmp is used to store messages that are unexpected, caused
	 * by the absence of an optional handshake message */
	if (s->s3->tmp.reuse_message)
		{
		s->s3->tmp.reuse_message=0;
		if ((mt >= 0) && (s->s3->tmp.message_type != mt))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_DTLS1_GET_MESSAGE,SSL_R_UNEXPECTED_MESSAGE);
			goto f_err;
			}
		*ok=1;
		s->init_msg = s->init_buf->data + DTLS1_HM_HEADER_LENGTH;
		s->init_num = (int)s->s3->tmp.message_size;
		return s->init_num;
		}

	msg_hdr = &s->d1->r_msg_hdr;
	do
		{
		if ( msg_hdr->frag_off == 0)
			{
			/* s->d1->r_message_header.msg_len = 0; */
			memset(msg_hdr, 0x00, sizeof(struct hm_header_st));
			}

		i = dtls1_get_message_fragment(s, st1, stn, max, ok);
		if ( i == DTLS1_HM_BAD_FRAGMENT ||
			i == DTLS1_HM_FRAGMENT_RETRY)  /* bad fragment received */
			continue;
		else if ( i <= 0 && !*ok)
			return i;

		/* Note that s->init_sum is used as a counter summing
		 * up fragments' lengths: as soon as they sum up to
		 * handshake packet length, we assume we have got all
		 * the fragments. Overlapping fragments would cause
		 * premature termination, so we don't expect overlaps.
		 * Well, handling overlaps would require something more
		 * drastic. Indeed, as it is now there is no way to
		 * tell if out-of-order fragment from the middle was
		 * the last. '>=' is the best/least we can do to control
		 * the potential damage caused by malformed overlaps. */
		if ((unsigned int)s->init_num >= msg_hdr->msg_len)
			{
			unsigned char *p = (unsigned char *)s->init_buf->data;
			unsigned long msg_len = msg_hdr->msg_len;

			/* reconstruct message header as if it was
			 * sent in single fragment */
			*(p++) = msg_hdr->type;
			l2n3(msg_len,p);
			s2n (msg_hdr->seq,p);
			l2n3(0,p);
			l2n3(msg_len,p);
			if (s->client_version != DTLS1_BAD_VER)
				p       -= DTLS1_HM_HEADER_LENGTH,
				msg_len += DTLS1_HM_HEADER_LENGTH;

			ssl3_finish_mac(s, p, msg_len);
			if (s->msg_callback)
				s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
					p, msg_len,
					s, s->msg_callback_arg);

			memset(msg_hdr, 0x00, sizeof(struct hm_header_st));

			s->d1->handshake_read_seq++;
			/* we just read a handshake message from the other side:
			 * this means that we don't need to retransmit of the
			 * buffered messages.  
			 * XDTLS: may be able clear out this
			 * buffer a little sooner (i.e if an out-of-order
			 * handshake message/record is received at the record
			 * layer.  
			 * XDTLS: exception is that the server needs to
			 * know that change cipher spec and finished messages
			 * have been received by the client before clearing this
			 * buffer.  this can simply be done by waiting for the
			 * first data  segment, but is there a better way?  */
			dtls1_clear_record_buffer(s);

			s->init_msg = s->init_buf->data + DTLS1_HM_HEADER_LENGTH;
			return s->init_num;
			}
		else
			msg_hdr->frag_off = i;
		} while(1) ;

f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
	*ok = 0;
	return -1;
	}


static int dtls1_preprocess_fragment(SSL *s,struct hm_header_st *msg_hdr,int max)
	{
	size_t frag_off,frag_len,msg_len;

	msg_len  = msg_hdr->msg_len;
	frag_off = msg_hdr->frag_off;
	frag_len = msg_hdr->frag_len;

	/* sanity checking */
	if ( (frag_off+frag_len) > msg_len)
		{
		SSLerr(SSL_F_DTLS1_PREPROCESS_FRAGMENT,SSL_R_EXCESSIVE_MESSAGE_SIZE);
		return SSL_AD_ILLEGAL_PARAMETER;
		}

	if ( (frag_off+frag_len) > (unsigned long)max)
		{
		SSLerr(SSL_F_DTLS1_PREPROCESS_FRAGMENT,SSL_R_EXCESSIVE_MESSAGE_SIZE);
		return SSL_AD_ILLEGAL_PARAMETER;
		}

	if ( s->d1->r_msg_hdr.frag_off == 0) /* first fragment */
		{
		/* msg_len is limited to 2^24, but is effectively checked
		 * against max above */
		if (!BUF_MEM_grow_clean(s->init_buf,(int)msg_len+DTLS1_HM_HEADER_LENGTH))
			{
			SSLerr(SSL_F_DTLS1_PREPROCESS_FRAGMENT,ERR_R_BUF_LIB);
			return SSL_AD_INTERNAL_ERROR;
			}

		s->s3->tmp.message_size  = msg_len;
		s->d1->r_msg_hdr.msg_len = msg_len;
		s->s3->tmp.message_type  = msg_hdr->type;
		s->d1->r_msg_hdr.type    = msg_hdr->type;
		s->d1->r_msg_hdr.seq     = msg_hdr->seq;
		}
	else if (msg_len != s->d1->r_msg_hdr.msg_len)
		{
		/* They must be playing with us! BTW, failure to enforce
		 * upper limit would open possibility for buffer overrun. */
		SSLerr(SSL_F_DTLS1_PREPROCESS_FRAGMENT,SSL_R_EXCESSIVE_MESSAGE_SIZE);
		return SSL_AD_ILLEGAL_PARAMETER;
		}

	return 0; /* no error */
	}


static int
dtls1_retrieve_buffered_fragment(SSL *s, long max, int *ok)
	{
	/* (0) check whether the desired fragment is available
	 * if so:
	 * (1) copy over the fragment to s->init_buf->data[]
	 * (2) update s->init_num
	 */
	pitem *item;
	hm_fragment *frag;
	int al;

	*ok = 0;
	item = pqueue_peek(s->d1->buffered_messages);
	if ( item == NULL)
		return 0;

	frag = (hm_fragment *)item->data;

	if ( s->d1->handshake_read_seq == frag->msg_header.seq)
		{
		pqueue_pop(s->d1->buffered_messages);

		al=dtls1_preprocess_fragment(s,&frag->msg_header,max);

		if (al==0) /* no alert */
			{
			unsigned char *p = (unsigned char *)s->init_buf->data+DTLS1_HM_HEADER_LENGTH;
			memcpy(&p[frag->msg_header.frag_off],
				frag->fragment,frag->msg_header.frag_len);
			}

		dtls1_hm_fragment_free(frag);
		pitem_free(item);

		if (al==0)
			{
			*ok = 1;
			return frag->msg_header.frag_len;
			}

		ssl3_send_alert(s,SSL3_AL_FATAL,al);
		s->init_num = 0;
		*ok = 0;
		return -1;
		}
	else
		return 0;
	}


static int
dtls1_process_out_of_seq_message(SSL *s, struct hm_header_st* msg_hdr, int *ok)
{
	int i=-1;
	hm_fragment *frag = NULL;
	pitem *item = NULL;
	PQ_64BIT seq64;
	unsigned long frag_len = msg_hdr->frag_len;

	if ((msg_hdr->frag_off+frag_len) > msg_hdr->msg_len)
		goto err;

	if (msg_hdr->seq <= s->d1->handshake_read_seq)
		{
		unsigned char devnull [256];

		while (frag_len)
			{
			i = s->method->ssl_read_bytes(s,SSL3_RT_HANDSHAKE,
				devnull,
				frag_len>sizeof(devnull)?sizeof(devnull):frag_len,0);
			if (i<=0) goto err;
			frag_len -= i;
			}
		}

	frag = dtls1_hm_fragment_new(frag_len);
	if ( frag == NULL)
		goto err;

	memcpy(&(frag->msg_header), msg_hdr, sizeof(*msg_hdr));

	if (frag_len)
		{
		/* read the body of the fragment (header has already been read */
		i = s->method->ssl_read_bytes(s,SSL3_RT_HANDSHAKE,
			frag->fragment,frag_len,0);
		if (i<=0 || (unsigned long)i!=frag_len)
			goto err;
		}

	pq_64bit_init(&seq64);
	pq_64bit_assign_word(&seq64, msg_hdr->seq);

	item = pitem_new(seq64, frag);
	pq_64bit_free(&seq64);
	if ( item == NULL)
		goto err;

	pqueue_insert(s->d1->buffered_messages, item);
	return DTLS1_HM_FRAGMENT_RETRY;

err:
	if ( frag != NULL) dtls1_hm_fragment_free(frag);
	if ( item != NULL) OPENSSL_free(item);
	*ok = 0;
	return i;
	}


static long
dtls1_get_message_fragment(SSL *s, int st1, int stn, long max, int *ok)
	{
	unsigned char wire[DTLS1_HM_HEADER_LENGTH];
	unsigned long l, frag_off, frag_len;
	int i,al;
	struct hm_header_st msg_hdr;

	/* see if we have the required fragment already */
	if ((frag_len = dtls1_retrieve_buffered_fragment(s,max,ok)) || *ok)
		{
		if (*ok)	s->init_num += frag_len;
		return frag_len;
		}

	/* read handshake message header */
	i=s->method->ssl_read_bytes(s,SSL3_RT_HANDSHAKE,wire,
		DTLS1_HM_HEADER_LENGTH, 0);
	if (i <= 0) 	/* nbio, or an error */
		{
		s->rwstate=SSL_READING;
		*ok = 0;
		return i;
		}
	OPENSSL_assert(i == DTLS1_HM_HEADER_LENGTH);

	/* parse the message fragment header */
	dtls1_get_message_header(wire, &msg_hdr);

	/* 
	 * if this is a future (or stale) message it gets buffered
	 * (or dropped)--no further processing at this time 
	 */
	if ( msg_hdr.seq != s->d1->handshake_read_seq)
		return dtls1_process_out_of_seq_message(s, &msg_hdr, ok);

	l = msg_hdr.msg_len;
	frag_off = msg_hdr.frag_off;
	frag_len = msg_hdr.frag_len;

	if (!s->server && s->d1->r_msg_hdr.frag_off == 0 &&
		wire[0] == SSL3_MT_HELLO_REQUEST)
		{
		/* The server may always send 'Hello Request' messages --
		 * we are doing a handshake anyway now, so ignore them
		 * if their format is correct. Does not count for
		 * 'Finished' MAC. */
		if (wire[1] == 0 && wire[2] == 0 && wire[3] == 0)
			{
			if (s->msg_callback)
				s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE, 
					wire, DTLS1_HM_HEADER_LENGTH, s, 
					s->msg_callback_arg);
			
			s->init_num = 0;
			return dtls1_get_message_fragment(s, st1, stn,
				max, ok);
			}
		else /* Incorrectly formated Hello request */
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_DTLS1_GET_MESSAGE_FRAGMENT,SSL_R_UNEXPECTED_MESSAGE);
			goto f_err;
			}
		}

	if ((al=dtls1_preprocess_fragment(s,&msg_hdr,max)))
		goto f_err;

	/* XDTLS:  ressurect this when restart is in place */
	s->state=stn;

	if ( frag_len > 0)
		{
		unsigned char *p=(unsigned char *)s->init_buf->data+DTLS1_HM_HEADER_LENGTH;

		i=s->method->ssl_read_bytes(s,SSL3_RT_HANDSHAKE,
			&p[frag_off],frag_len,0);
		/* XDTLS:  fix this--message fragments cannot span multiple packets */
		if (i <= 0)
			{
			s->rwstate=SSL_READING;
			*ok = 0;
			return i;
			}
		}
	else
		i = 0;

	/* XDTLS:  an incorrectly formatted fragment should cause the 
	 * handshake to fail */
	OPENSSL_assert(i == (int)frag_len);

	*ok = 1;

	/* Note that s->init_num is *not* used as current offset in
	 * s->init_buf->data, but as a counter summing up fragments'
	 * lengths: as soon as they sum up to handshake packet
	 * length, we assume we have got all the fragments. */
	s->init_num += frag_len;
	return frag_len;

f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
	s->init_num = 0;

	*ok=0;
	return(-1);
	}

int dtls1_send_finished(SSL *s, int a, int b, const char *sender, int slen)
	{
	unsigned char *p,*d;
	int i;
	unsigned long l;

	if (s->state == a)
		{
		d=(unsigned char *)s->init_buf->data;
		p= &(d[DTLS1_HM_HEADER_LENGTH]);

		i=s->method->ssl3_enc->final_finish_mac(s,
			&(s->s3->finish_dgst1),
			&(s->s3->finish_dgst2),
			sender,slen,s->s3->tmp.finish_md);
		s->s3->tmp.finish_md_len = i;
		memcpy(p, s->s3->tmp.finish_md, i);
		p+=i;
		l=i;

#ifdef OPENSSL_SYS_WIN16
		/* MSVC 1.5 does not clear the top bytes of the word unless
		 * I do this.
		 */
		l&=0xffff;
#endif

		d = dtls1_set_message_header(s, d, SSL3_MT_FINISHED, l, 0, l);
		s->init_num=(int)l+DTLS1_HM_HEADER_LENGTH;
		s->init_off=0;

		/* buffer the message to handle re-xmits */
		dtls1_buffer_message(s, 0);

		s->state=b;
		}

	/* SSL3_ST_SEND_xxxxxx_HELLO_B */
	return(dtls1_do_write(s,SSL3_RT_HANDSHAKE));
	}

/* for these 2 messages, we need to
 * ssl->enc_read_ctx			re-init
 * ssl->s3->read_sequence		zero
 * ssl->s3->read_mac_secret		re-init
 * ssl->session->read_sym_enc		assign
 * ssl->session->read_compression	assign
 * ssl->session->read_hash		assign
 */
int dtls1_send_change_cipher_spec(SSL *s, int a, int b)
	{ 
	unsigned char *p;

	if (s->state == a)
		{
		p=(unsigned char *)s->init_buf->data;
		*p++=SSL3_MT_CCS;
		s->d1->handshake_write_seq = s->d1->next_handshake_write_seq;
		s->init_num=DTLS1_CCS_HEADER_LENGTH;

		if (s->client_version == DTLS1_BAD_VER)
			{
			s->d1->next_handshake_write_seq++;
			s2n(s->d1->handshake_write_seq,p);
			s->init_num+=2;
			}

		s->init_off=0;

		dtls1_set_message_header_int(s, SSL3_MT_CCS, 0, 
			s->d1->handshake_write_seq, 0, 0);

		/* buffer the message to handle re-xmits */
		dtls1_buffer_message(s, 1);

		s->state=b;
		}

	/* SSL3_ST_CW_CHANGE_B */
	return(dtls1_do_write(s,SSL3_RT_CHANGE_CIPHER_SPEC));
	}

unsigned long dtls1_output_cert_chain(SSL *s, X509 *x)
	{
	unsigned char *p;
	int n,i;
	unsigned long l= 3 + DTLS1_HM_HEADER_LENGTH;
	BUF_MEM *buf;
	X509_STORE_CTX xs_ctx;
	X509_OBJECT obj;

	/* TLSv1 sends a chain with nothing in it, instead of an alert */
	buf=s->init_buf;
	if (!BUF_MEM_grow_clean(buf,10))
		{
		SSLerr(SSL_F_DTLS1_OUTPUT_CERT_CHAIN,ERR_R_BUF_LIB);
		return(0);
		}
	if (x != NULL)
		{
		if(!X509_STORE_CTX_init(&xs_ctx,s->ctx->cert_store,NULL,NULL))
			{
			SSLerr(SSL_F_DTLS1_OUTPUT_CERT_CHAIN,ERR_R_X509_LIB);
			return(0);
			}

		for (;;)
			{
			n=i2d_X509(x,NULL);
			if (!BUF_MEM_grow_clean(buf,(int)(n+l+3)))
				{
				SSLerr(SSL_F_DTLS1_OUTPUT_CERT_CHAIN,ERR_R_BUF_LIB);
				return(0);
				}
			p=(unsigned char *)&(buf->data[l]);
			l2n3(n,p);
			i2d_X509(x,&p);
			l+=n+3;
			if (X509_NAME_cmp(X509_get_subject_name(x),
				X509_get_issuer_name(x)) == 0) break;

			i=X509_STORE_get_by_subject(&xs_ctx,X509_LU_X509,
				X509_get_issuer_name(x),&obj);
			if (i <= 0) break;
			x=obj.data.x509;
			/* Count is one too high since the X509_STORE_get uped the
			 * ref count */
			X509_free(x);
			}

		X509_STORE_CTX_cleanup(&xs_ctx);
		}

	/* Thawte special :-) */
	if (s->ctx->extra_certs != NULL)
	for (i=0; i<sk_X509_num(s->ctx->extra_certs); i++)
		{
		x=sk_X509_value(s->ctx->extra_certs,i);
		n=i2d_X509(x,NULL);
		if (!BUF_MEM_grow_clean(buf,(int)(n+l+3)))
			{
			SSLerr(SSL_F_DTLS1_OUTPUT_CERT_CHAIN,ERR_R_BUF_LIB);
			return(0);
			}
		p=(unsigned char *)&(buf->data[l]);
		l2n3(n,p);
		i2d_X509(x,&p);
		l+=n+3;
		}

	l-= (3 + DTLS1_HM_HEADER_LENGTH);

	p=(unsigned char *)&(buf->data[DTLS1_HM_HEADER_LENGTH]);
	l2n3(l,p);
	l+=3;
	p=(unsigned char *)&(buf->data[0]);
	p = dtls1_set_message_header(s, p, SSL3_MT_CERTIFICATE, l, 0, l);

	l+=DTLS1_HM_HEADER_LENGTH;
	return(l);
	}

int dtls1_read_failed(SSL *s, int code)
	{
	DTLS1_STATE *state;
	BIO *bio;
	int send_alert = 0;

	if ( code > 0)
		{
		fprintf( stderr, "invalid state reached %s:%d", __FILE__, __LINE__);
		return 1;
		}

	bio = SSL_get_rbio(s);
	if ( ! BIO_dgram_recv_timedout(bio))
		{
		/* not a timeout, none of our business, 
		   let higher layers handle this.  in fact it's probably an error */
		return code;
		}

	if ( ! SSL_in_init(s))  /* done, no need to send a retransmit */
		{
		BIO_set_flags(SSL_get_rbio(s), BIO_FLAGS_READ);
		return code;
		}

	state = s->d1;
	state->timeout.num_alerts++;
	if ( state->timeout.num_alerts > DTLS1_TMO_ALERT_COUNT)
		{
		/* fail the connection, enough alerts have been sent */
		SSLerr(SSL_F_DTLS1_READ_FAILED,SSL_R_READ_TIMEOUT_EXPIRED);
		return 0;
		}

	state->timeout.read_timeouts++;
	if ( state->timeout.read_timeouts > DTLS1_TMO_READ_COUNT)
		{
		send_alert = 1;
		state->timeout.read_timeouts = 1;
		}


#if 0 /* for now, each alert contains only one record number */
	item = pqueue_peek(state->rcvd_records);
	if ( item )
		{
		/* send an alert immediately for all the missing records */
		}
	else
#endif

#if 0  /* no more alert sending, just retransmit the last set of messages */
		if ( send_alert)
			ssl3_send_alert(s,SSL3_AL_WARNING,
				DTLS1_AD_MISSING_HANDSHAKE_MESSAGE);
#endif

	return dtls1_retransmit_buffered_messages(s) ;
	}


static int
dtls1_retransmit_buffered_messages(SSL *s)
	{
	pqueue sent = s->d1->sent_messages;
	piterator iter;
	pitem *item;
	hm_fragment *frag;
	int found = 0;

	iter = pqueue_iterator(sent);

	for ( item = pqueue_next(&iter); item != NULL; item = pqueue_next(&iter))
		{
		frag = (hm_fragment *)item->data;
		if ( dtls1_retransmit_message(s, frag->msg_header.seq, 0, &found) <= 0 &&
			found)
			{
			fprintf(stderr, "dtls1_retransmit_message() failed\n");
			return -1;
			}
		}

	return 1;
	}

int
dtls1_buffer_message(SSL *s, int is_ccs)
	{
	pitem *item;
	hm_fragment *frag;
	PQ_64BIT seq64;
	unsigned int epoch = s->d1->w_epoch;

	/* this function is called immediately after a message has 
	 * been serialized */
	OPENSSL_assert(s->init_off == 0);

	frag = dtls1_hm_fragment_new(s->init_num);

	memcpy(frag->fragment, s->init_buf->data, s->init_num);

	if ( is_ccs)
		{
		OPENSSL_assert(s->d1->w_msg_hdr.msg_len + 
			DTLS1_CCS_HEADER_LENGTH <= (unsigned int)s->init_num);
		epoch++;
		}
	else
		{
		OPENSSL_assert(s->d1->w_msg_hdr.msg_len + 
			DTLS1_HM_HEADER_LENGTH == (unsigned int)s->init_num);
		}

	frag->msg_header.msg_len = s->d1->w_msg_hdr.msg_len;
	frag->msg_header.seq = s->d1->w_msg_hdr.seq;
	frag->msg_header.type = s->d1->w_msg_hdr.type;
	frag->msg_header.frag_off = 0;
	frag->msg_header.frag_len = s->d1->w_msg_hdr.msg_len;
	frag->msg_header.is_ccs = is_ccs;

	pq_64bit_init(&seq64);
	pq_64bit_assign_word(&seq64, epoch<<16 | frag->msg_header.seq);

	item = pitem_new(seq64, frag);
	pq_64bit_free(&seq64);
	if ( item == NULL)
		{
		dtls1_hm_fragment_free(frag);
		return 0;
		}

#if 0
	fprintf( stderr, "buffered messge: \ttype = %xx\n", msg_buf->type);
	fprintf( stderr, "\t\t\t\t\tlen = %d\n", msg_buf->len);
	fprintf( stderr, "\t\t\t\t\tseq_num = %d\n", msg_buf->seq_num);
#endif

	pqueue_insert(s->d1->sent_messages, item);
	return 1;
	}

int
dtls1_retransmit_message(SSL *s, unsigned short seq, unsigned long frag_off,
	int *found)
	{
	int ret;
	/* XDTLS: for now assuming that read/writes are blocking */
	pitem *item;
	hm_fragment *frag ;
	unsigned long header_length;
	PQ_64BIT seq64;

	/*
	  OPENSSL_assert(s->init_num == 0);
	  OPENSSL_assert(s->init_off == 0);
	 */

	/* XDTLS:  the requested message ought to be found, otherwise error */
	pq_64bit_init(&seq64);
	pq_64bit_assign_word(&seq64, seq);

	item = pqueue_find(s->d1->sent_messages, seq64);
	pq_64bit_free(&seq64);
	if ( item == NULL)
		{
		fprintf(stderr, "retransmit:  message %d non-existant\n", seq);
		*found = 0;
		return 0;
		}

	*found = 1;
	frag = (hm_fragment *)item->data;

	if ( frag->msg_header.is_ccs)
		header_length = DTLS1_CCS_HEADER_LENGTH;
	else
		header_length = DTLS1_HM_HEADER_LENGTH;

	memcpy(s->init_buf->data, frag->fragment, 
		frag->msg_header.msg_len + header_length);
		s->init_num = frag->msg_header.msg_len + header_length;

	dtls1_set_message_header_int(s, frag->msg_header.type, 
		frag->msg_header.msg_len, frag->msg_header.seq, 0, 
		frag->msg_header.frag_len);

	s->d1->retransmitting = 1;
	ret = dtls1_do_write(s, frag->msg_header.is_ccs ? 
		SSL3_RT_CHANGE_CIPHER_SPEC : SSL3_RT_HANDSHAKE);
	s->d1->retransmitting = 0;

	(void)BIO_flush(SSL_get_wbio(s));
	return ret;
	}

/* call this function when the buffered messages are no longer needed */
void
dtls1_clear_record_buffer(SSL *s)
	{
	pitem *item;

	for(item = pqueue_pop(s->d1->sent_messages);
		item != NULL; item = pqueue_pop(s->d1->sent_messages))
		{
		dtls1_hm_fragment_free((hm_fragment *)item->data);
		pitem_free(item);
		}
	}


unsigned char *
dtls1_set_message_header(SSL *s, unsigned char *p, unsigned char mt,
			unsigned long len, unsigned long frag_off, unsigned long frag_len)
	{
	if ( frag_off == 0)
		{
		s->d1->handshake_write_seq = s->d1->next_handshake_write_seq;
		s->d1->next_handshake_write_seq++;
		}

	dtls1_set_message_header_int(s, mt, len, s->d1->handshake_write_seq,
		frag_off, frag_len);

	return p += DTLS1_HM_HEADER_LENGTH;
	}


/* don't actually do the writing, wait till the MTU has been retrieved */
static void
dtls1_set_message_header_int(SSL *s, unsigned char mt,
			    unsigned long len, unsigned short seq_num, unsigned long frag_off,
			    unsigned long frag_len)
	{
	struct hm_header_st *msg_hdr = &s->d1->w_msg_hdr;

	msg_hdr->type = mt;
	msg_hdr->msg_len = len;
	msg_hdr->seq = seq_num;
	msg_hdr->frag_off = frag_off;
	msg_hdr->frag_len = frag_len;
	}

static void
dtls1_fix_message_header(SSL *s, unsigned long frag_off,
			unsigned long frag_len)
	{
	struct hm_header_st *msg_hdr = &s->d1->w_msg_hdr;

	msg_hdr->frag_off = frag_off;
	msg_hdr->frag_len = frag_len;
	}

static unsigned char *
dtls1_write_message_header(SSL *s, unsigned char *p)
	{
	struct hm_header_st *msg_hdr = &s->d1->w_msg_hdr;

	*p++ = msg_hdr->type;
	l2n3(msg_hdr->msg_len, p);

	s2n(msg_hdr->seq, p);
	l2n3(msg_hdr->frag_off, p);
	l2n3(msg_hdr->frag_len, p);

	return p;
	}

static unsigned int 
dtls1_min_mtu(void)
	{
	return (g_probable_mtu[(sizeof(g_probable_mtu) / 
		sizeof(g_probable_mtu[0])) - 1]);
	}

static unsigned int 
dtls1_guess_mtu(unsigned int curr_mtu)
	{
	size_t i;

	if ( curr_mtu == 0 )
		return g_probable_mtu[0] ;

	for ( i = 0; i < sizeof(g_probable_mtu)/sizeof(g_probable_mtu[0]); i++)
		if ( curr_mtu > g_probable_mtu[i])
			return g_probable_mtu[i];

	return curr_mtu;
	}

void
dtls1_get_message_header(unsigned char *data, struct hm_header_st *msg_hdr)
	{
	memset(msg_hdr, 0x00, sizeof(struct hm_header_st));
	msg_hdr->type = *(data++);
	n2l3(data, msg_hdr->msg_len);

	n2s(data, msg_hdr->seq);
	n2l3(data, msg_hdr->frag_off);
	n2l3(data, msg_hdr->frag_len);
	}

void
dtls1_get_ccs_header(unsigned char *data, struct ccs_header_st *ccs_hdr)
	{
	memset(ccs_hdr, 0x00, sizeof(struct ccs_header_st));

	ccs_hdr->type = *(data++);
	}
