#include "heartbeat.h"

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

