/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tcp.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET_TCP_H
#define _NETINET_TCP_H	1

#include <features.h>

/*
 * User-settable options (used with setsockopt).
 */
#define	TCP_NODELAY	 1	/* Don't delay send to coalesce packets  */
#define	TCP_MAXSEG	 2	/* Set maximum segment size  */
#define TCP_CORK	 3	/* Control sending of partial frames  */
#define TCP_KEEPIDLE	 4	/* Start keeplives after this period */
#define TCP_KEEPINTVL	 5	/* Interval between keepalives */
#define TCP_KEEPCNT	 6	/* Number of keepalives before death */
#define TCP_SYNCNT	 7	/* Number of SYN retransmits */
#define TCP_LINGER2	 8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT 9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP 10	/* Bound advertised window */
#define TCP_INFO	 11	/* Information about this connection. */
#define	TCP_QUICKACK	 12	/* Bock/reenable quick ACKs.  */
#define TCP_CONGESTION	 13	/* Congestion control algorithm.  */
#define TCP_MD5SIG	 14	/* TCP MD5 Signature (RFC2385) */
#define TCP_THIN_LINEAR_TIMEOUTS 16      /* Use linear timeouts for thin streams*/
#define TCP_THIN_DUPACK         17      /* Fast retrans. after 1 dupack */
#define TCP_USER_TIMEOUT        18      /* How long for loss retry before timeout */
#define TCP_REPAIR              19      /* TCP sock is under repair right now */
#define TCP_REPAIR_QUEUE        20
#define TCP_QUEUE_SEQ           21
#define TCP_REPAIR_OPTIONS      22
#define TCP_FASTOPEN            23      /* Enable FastOpen on listeners */
#define TCP_TIMESTAMP           24
#define TCP_NOTSENT_LOWAT       25      /* limit number of unsent bytes in write queue */
#define TCP_CC_INFO             26      /* Get Congestion Control (optional) info */
#define TCP_SAVE_SYN            27      /* Record SYN headers for new connections */
#define TCP_SAVED_SYN           28      /* Get SYN headers recorded for connection */
#define TCP_REPAIR_WINDOW       29      /* Get/set window parameters */

#ifdef __USE_MISC
# include <sys/types.h>
# include <sys/socket.h>

# ifdef __FAVOR_BSD
typedef	u_int32_t tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr
  {
    u_int16_t th_sport;		/* source port */
    u_int16_t th_dport;		/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;		/* (unused) */
    u_int8_t th_off:4;		/* data offset */
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;		/* data offset */
    u_int8_t th_x2:4;		/* (unused) */
#  endif
    u_int8_t th_flags;
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
    u_int16_t th_win;		/* window */
    u_int16_t th_sum;		/* checksum */
    u_int16_t th_urp;		/* urgent pointer */
};

# else /* !__FAVOR_BSD */
struct tcphdr
  {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};
# endif /* __FAVOR_BSD */

enum
{
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING   /* now a valid state */
};

# define TCPOPT_EOL		0
# define TCPOPT_NOP		1
# define TCPOPT_MAXSEG		2
# define TCPOLEN_MAXSEG		4
# define TCPOPT_WINDOW		3
# define TCPOLEN_WINDOW		3
# define TCPOPT_SACK_PERMITTED	4		/* Experimental */
# define TCPOLEN_SACK_PERMITTED	2
# define TCPOPT_SACK		5		/* Experimental */
# define TCPOPT_TIMESTAMP	8
# define TCPOLEN_TIMESTAMP	10
# define TCPOLEN_TSTAMP_APPA	(TCPOLEN_TIMESTAMP+2) /* appendix A */

# define TCPOPT_TSTAMP_HDR	\
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

/*
 * Default maximum segment size for TCP.
 * With an IP MSS of 576, this is 536,
 * but 512 is probably more convenient.
 * This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)).
 */
# define TCP_MSS	512

# define TCP_MAXWIN	65535	/* largest value for (unscaled) window */

# define TCP_MAX_WINSHIFT	14	/* maximum window shift */

# define SOL_TCP		6	/* TCP level */


# define TCPI_OPT_TIMESTAMPS	1
# define TCPI_OPT_SACK		2
# define TCPI_OPT_WSCALE	4
# define TCPI_OPT_ECN		8

/* Values for tcpi_state.  */
enum tcp_ca_state
{
  TCP_CA_Open = 0,
  TCP_CA_Disorder = 1,
  TCP_CA_CWR = 2,
  TCP_CA_Recovery = 3,
  TCP_CA_Loss = 4
};

struct tcp_info
{
  u_int8_t	tcpi_state;
  u_int8_t	tcpi_ca_state;
  u_int8_t	tcpi_retransmits;
  u_int8_t	tcpi_probes;
  u_int8_t	tcpi_backoff;
  u_int8_t	tcpi_options;
  u_int8_t	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

  u_int32_t	tcpi_rto;
  u_int32_t	tcpi_ato;
  u_int32_t	tcpi_snd_mss;
  u_int32_t	tcpi_rcv_mss;

  u_int32_t	tcpi_unacked;
  u_int32_t	tcpi_sacked;
  u_int32_t	tcpi_lost;
  u_int32_t	tcpi_retrans;
  u_int32_t	tcpi_fackets;

  /* Times. */
  u_int32_t	tcpi_last_data_sent;
  u_int32_t	tcpi_last_ack_sent;	/* Not remembered, sorry.  */
  u_int32_t	tcpi_last_data_recv;
  u_int32_t	tcpi_last_ack_recv;

  /* Metrics. */
  u_int32_t	tcpi_pmtu;
  u_int32_t	tcpi_rcv_ssthresh;
  u_int32_t	tcpi_rtt;
  u_int32_t	tcpi_rttvar;
  u_int32_t	tcpi_snd_ssthresh;
  u_int32_t	tcpi_snd_cwnd;
  u_int32_t	tcpi_advmss;
  u_int32_t	tcpi_reordering;

  u_int32_t	tcpi_rcv_rtt;
  u_int32_t	tcpi_rcv_space;

  u_int32_t	tcpi_total_retrans;
};


/* For TCP_MD5SIG socket option.  */
#define TCP_MD5SIG_MAXKEYLEN	80

struct tcp_md5sig
{
  struct sockaddr_storage tcpm_addr;		/* Address associated.  */
  u_int16_t	__tcpm_pad1;			/* Zero.  */
  u_int16_t	tcpm_keylen;			/* Key length.  */
  u_int32_t	__tcpm_pad2;			/* Zero.  */
  u_int8_t	tcpm_key[TCP_MD5SIG_MAXKEYLEN];	/* Key (binary).  */
};


/****************************************************/
/*                  TLS NEW STUFF                   */
/****************************************************/
#define TCP_ULP                 31

#define SOL_TLS                 282
#define TLS_TX                  1
//#define TLS_RX                  2

/* Supported versions */
#define TLS_VERSION_MINOR(ver)	((ver) & 0xFF)
#define TLS_VERSION_MAJOR(ver)	(((ver) >> 8) & 0xFF)

#define TLS_VERSION_NUMBER(id)	((((id##_VERSION_MAJOR) & 0xFF) << 8) |	\
				 ((id##_VERSION_MINOR) & 0xFF))

#define TLS_1_2_VERSION_MAJOR	0x3
#define TLS_1_2_VERSION_MINOR	0x3
#define TLS_1_2_VERSION		TLS_VERSION_NUMBER(TLS_1_2)

/* Supported ciphers */
#define TLS_CIPHER_AES_GCM_128			51
#define TLS_CIPHER_AES_GCM_128_IV_SIZE		((size_t)8)
#define TLS_CIPHER_AES_GCM_128_KEY_SIZE		((size_t)16)
#define TLS_CIPHER_AES_GCM_128_SALT_SIZE	((size_t)4)
#define TLS_CIPHER_AES_GCM_128_TAG_SIZE		((size_t)16)
#define TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE	((size_t)8)

#define TLS_SET_RECORD_TYPE	1

struct tls_crypto_info {
	unsigned short version;
	unsigned short cipher_type;
};

struct tls12_crypto_info_aes_gcm_128 {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
	unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	unsigned char rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};
/****************************************************/

#endif /* Misc.  */

#endif /* netinet/tcp.h */
