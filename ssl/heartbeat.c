#include "heartbeat.h"
#include <openssl/ssl.h>

int heartbeat_size(int payload, int padding)
	{
	return  1 /* heartbeat type */   +
		2 /* heartbeat length */ +
		payload + padding;
	}

int heartbeat_size_std(int payload)
	{
	return heartbeat_size(payload, 16);
	}

void apply_msg_callback(SSL *s)
	{
	if (s->msg_callback)
		s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT,
			&s->s3->rrec.data[0], s->s3->rrec.length,
			s, s->msg_callback_arg);
	}

}

//-- int heartbeat_read_payload(SSL *s, unsigned char *pl, unsigned short hbtype, unsigned int payload) {
//--     unsigned char *p = &s->s3->rrec.data[0];
//-- 	/* Read type and payload length first */
//-- 	if (1 + 2 + 16 > s->s3->rrec.length)
//-- 		return 0; /* silently discard */
//-- 	hbtype = *p++;
//-- 	n2s(p, payload);
//-- 	if (1 + 2 + payload + 16 > s->s3->rrec.length)
//-- 		return 0; /* silently discard per RFC 6520 sec. 4 */
//-- 	pl = p;
//-- }
