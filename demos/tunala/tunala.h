/* Tunala ("Tunneler with a New Zealand accent")
 *
 * Written by Geoff Thorpe, but endorsed/supported by noone. Please use this is
 * if it's useful or informative to you, but it's only here as a scratchpad for
 * ideas about how you might (or might not) program with OpenSSL. If you deploy
 * this is in a mission-critical environment, and have not read, understood,
 * audited, and modified this code to your satisfaction, and the result is that
 * all hell breaks loose and you are looking for a new employer, then it proves
 * nothing except perhaps that Darwinism is alive and well. Let's just say, *I*
 * don't use this in a mission-critical environment, so it would be stupid for
 * anyone to assume that it is solid and/or tested enough when even its author
 * doesn't place that much trust in it. You have been warned.
 *
 * With thanks to Cryptographic Appliances, Inc.
 */

#ifndef _TUNALA_H
#define _TUNALA_H

#ifndef NO_SYSTEM_H
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif /* !defined(NO_SYSTEM_H) */

#ifndef NO_OPENSSL
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#endif /* !defined(NO_OPENSSL) */

#ifndef NO_BUFFER
/* This is the generic "buffer" type that is used when feeding the
 * state-machine. It's basically a FIFO with respect to the "adddata" &
 * "takedata" type functions that operate on it. */
#define MAX_DATA_SIZE 16384
typedef struct _buffer_t {
	unsigned char data[MAX_DATA_SIZE];
	unsigned int used;
} buffer_t;

/* Initialise a buffer structure before use */
void buffer_init(buffer_t *buf);
/* Cleanup a buffer structure - presently not needed, but if buffer_t is
 * converted to using dynamic allocation, this would be required - so should be
 * called to protect against an explosion of memory leaks later if the change is
 * made. */
void buffer_close(buffer_t *buf);

/* Basic functions to manipulate buffers */

unsigned int buffer_used(buffer_t *buf); /* How much data in the buffer */
unsigned int buffer_unused(buffer_t *buf); /* How much space in the buffer */
int buffer_full(buffer_t *buf); /* Boolean, is it full? */
int buffer_notfull(buffer_t *buf); /* Boolean, is it not full? */
int buffer_empty(buffer_t *buf); /* Boolean, is it empty? */
int buffer_notempty(buffer_t *buf); /* Boolean, is it not empty? */

/* Add data to the tail of the buffer, returns the amount that was actually
 * added (so, you need to check if return value is less than size) */
unsigned int buffer_adddata(buffer_t *buf, const unsigned char *ptr,
		unsigned int size);

/* Take data from the front of the buffer (and scroll the rest forward). If
 * "ptr" is NULL, this just removes data off the front of the buffer. Return
 * value is the amount actually removed (can be less than size if the buffer has
 * too little data). */
unsigned int buffer_takedata(buffer_t *buf, unsigned char *ptr,
		unsigned int size);

/* Flushes as much data as possible out of the "from" buffer into the "to"
 * buffer. Return value is the amount moved. The amount moved can be restricted
 * to a maximum by specifying "cap" - setting it to -1 means no limit. */
unsigned int buffer_tobuffer(buffer_t *to, buffer_t *from, int cap);

#ifndef NO_IP
/* Read or write between a file-descriptor and a buffer */
int buffer_from_fd(buffer_t *buf, int fd);
int buffer_to_fd(buffer_t *buf, int fd);
#endif /* !defined(NO_IP) */

#ifndef NO_OPENSSL
/* Read or write between an SSL or BIO and a buffer */
void buffer_from_SSL(buffer_t *buf, SSL *ssl);
void buffer_to_SSL(buffer_t *buf, SSL *ssl);
void buffer_from_BIO(buffer_t *buf, BIO *bio);
void buffer_to_BIO(buffer_t *buf, BIO *bio);

/* Callbacks */
void cb_ssl_info(SSL *s, int where, int ret);
void cb_ssl_info_set_output(FILE *fp); /* Called if output should be sent too */
int cb_ssl_verify(int ok, X509_STORE_CTX *ctx);
void cb_ssl_verify_set_output(FILE *fp);
void cb_ssl_verify_set_depth(unsigned int verify_depth);
#endif /* !defined(NO_OPENSSL) */
#endif /* !defined(NO_BUFFER) */

#ifndef NO_TUNALA
#ifdef NO_BUFFER
#error "TUNALA section of tunala.h requires BUFFER support"
#endif
typedef struct _state_machine_t {
	SSL *ssl;
	BIO *bio_intossl;
	BIO *bio_fromssl;
	buffer_t clean_in, clean_out;
	buffer_t dirty_in, dirty_out;
} state_machine_t;
typedef enum {
	SM_CLEAN_IN, SM_CLEAN_OUT,
	SM_DIRTY_IN, SM_DIRTY_OUT
} sm_buffer_t;
void state_machine_init(state_machine_t *machine);
void state_machine_close(state_machine_t *machine);
buffer_t *state_machine_get_buffer(state_machine_t *machine, sm_buffer_t type);
SSL *state_machine_get_SSL(state_machine_t *machine);
int state_machine_set_SSL(state_machine_t *machine, SSL *ssl, int is_server);
/* Performs the data-IO loop and returns zero if the machine should close */
int state_machine_churn(state_machine_t *machine);
/* Is used to handle closing conditions - namely when one side of the tunnel has
 * closed but the other should finish flushing. */
int state_machine_close_clean(state_machine_t *machine);
int state_machine_close_dirty(state_machine_t *machine);
#endif /* !defined(NO_TUNALA) */

#ifndef NO_IP
/* Initialise anything related to the networking. This includes blocking pesky
 * SIGPIPE signals. */
int ip_initialise(void);
/* ip is the 4-byte ip address (eg. 127.0.0.1 is {0x7F,0x00,0x00,0x01}), port is
 * the port to listen on (host byte order), and the return value is the
 * file-descriptor or -1 on error. */
int ip_create_listener_split(const unsigned char *ip, unsigned short port);
/* Same semantics as above. */
int ip_create_connection_split(const unsigned char *ip, unsigned short port);
/* Converts a string into the ip/port before calling the above */
int ip_create_listener(const char *address);
int ip_create_connection(const char *address);
/* Just does a string conversion on its own. NB: If accept_all_ip is non-zero,
 * then the address string could be just a port. Ie. it's suitable for a
 * listening address but not a connecting address. */
int ip_parse_address(const char *address, unsigned char **parsed_ip,
		unsigned short *port, int accept_all_ip);
/* Accepts an incoming connection through the listener. Assumes selects and
 * what-not have deemed it an appropriate thing to do. */
int ip_accept_connection(int listen_fd);
#endif /* !defined(NO_IP) */

#endif /* !defined(_TUNALA_H) */
