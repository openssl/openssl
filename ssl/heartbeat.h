#ifndef _INCL_HEARTBEAT_H
#define _INCL_HEARTBEAT_H

#include <openssl/ssl.h>

int heartbeat_size(int payload, int padding);
int heartbeat_size_std(int payload);

void apply_msg_callback(SSL *s);
void heartbeat_read_payload(SSL *s);
#endif
