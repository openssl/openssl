/*
 *  Copyright 20xx-20yy The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static const char*      revision = "1.0.2";

static const int        server_port = 4433;

/*
 * This flag won't be useful until both accept/read (TCP & SSL) methods
 * can be called with a timeout. TBD.
 */
static volatile bool    server_running = true;

int create_socket(bool isServer) {
	int 				s;
	int					optval = 1;
	struct sockaddr_in	addr;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	if (isServer) {
		addr.sin_family = AF_INET;
		addr.sin_port = htons(server_port);
		addr.sin_addr.s_addr = INADDR_ANY;

		/* Reuse the address; good for quick restarts */
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
				< 0) {
			perror("setsockopt(SO_REUSEADDR) failed");
			exit(EXIT_FAILURE);
		}

		if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
			perror("Unable to bind");
			exit(EXIT_FAILURE);
		}

		if (listen(s, 1) < 0) {
			perror("Unable to listen");
			exit(EXIT_FAILURE);
		}
	}

	return s;
}

SSL_CTX* create_context(bool isServer) {
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	if (isServer)
		method = TLS_server_method();
	else
		method = TLS_client_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

void configure_context(SSL_CTX *ctx) {
	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

void usage() {
	printf("Usage: sslecho s\n");
	printf("       --or--\n");
	printf("       sslecho c ip\n");
	printf("       c=client, s=server, ip=dotted ip of server\n");
	exit(1);
}

int main(int argc, char **argv) {
    bool        isServer;
    int         result;

    SSL_CTX*    ssl_ctx = NULL;
    SSL*        ssl = NULL;

    int         server_skt = -1;
    int         client_skt = -1;

    char*       txbuf = (char*)malloc(128);
    size_t      txcap = 128;
    int         txlen;

    char*       rxbuf = (char*)malloc(128);
    int         rxcap = 128;
    int         rxlen;

    char*       rem_server_ip = NULL;

    struct sockaddr_in      addr;
    unsigned int            addr_len = sizeof(addr);

	/* Splash */
	printf("\nsslecho : Revision %s : %s : %s\n\n", revision, __DATE__,
			__TIME__);

	/* Need to know if client or server */
	if (argc < 2) {
		usage();
		/* NOTREACHED */
	}
	isServer = (argv[1][0] == 's') ? true : false;
	/* If client get remote server address (could be 127.0.0.1) */
	if (!isServer) {
		if (argc != 3) {
			usage();
			/* NOTREACHED */
		}
		rem_server_ip = argv[2];
	}

	/* Create context used by both client and server */
	ssl_ctx = create_context(isServer);
	/* Configure context with appropriate key files */
	configure_context(ssl_ctx);

	/* If server */
	if (isServer) {
		printf("We are the server on port: %d\n\n", server_port);

		/* Create server socket; will bind with server port and listen */
		server_skt = create_socket(true);

		/*
		 * Loop to accept clients.
		 * Need to implement timeouts on TCP & SSL connect/read functions
		 * before we can catch a CTRL-C and kill the server.
		 */
		while (server_running) {
			/* Wait for TCP connection from client */
			client_skt = accept(server_skt, (struct sockaddr*) &addr,
					&addr_len);
			if (client_skt < 0) {
				perror("Unable to accept");
				exit(EXIT_FAILURE);
			}

			printf("Client TCP connection accepted\n");

			/* Create server SSL structure using the new socket */
			ssl = SSL_new(ssl_ctx);
			SSL_set_fd(ssl, client_skt);

			/* Wait for SSL connection from the client */
			if (SSL_accept(ssl) <= 0) {
				ERR_print_errors_fp(stderr);
			} else {

				printf("Client SSL connection accepted\n\n");

				/* Echo loop */
				while (true) {
					/* Get message from client; will fail if client closes connection */
					if ((rxlen = SSL_read(ssl, rxbuf, rxcap)) <= 0) {
						if (rxlen == 0) {
							printf("Client closed connection\n");
						}
						ERR_print_errors_fp(stderr);
						break;
					}
					/* Insure null terminated input */
					rxbuf[rxlen] = 0;
					/* Look for kill switch */
					if (strcmp(rxbuf, "kill\n") == 0) {
						/* Terminate...with extreme prejudice */
						printf("Server received 'kill' command\n");
						server_running = false;
						break;
					}
					/* Show received message */
					printf("Received: %s", rxbuf);
					/* Echo it back */
					if (SSL_write(ssl, rxbuf, rxlen) <= 0) {
						ERR_print_errors_fp(stderr);
					}
				}
			}
			if (server_running) {
				/* Cleanup for next client */
				SSL_shutdown(ssl);
				SSL_free(ssl);
				close(client_skt);
			}
		}
		printf("Server exiting...\n");
	}
	/* Else client */
	else {
		printf("We are the client\n\n");

		/* Create "bare" socket */
		client_skt = create_socket(false);
		/* Set up connect address */
		addr.sin_family = AF_INET;
		inet_pton(AF_INET, rem_server_ip, &addr.sin_addr.s_addr);
		addr.sin_port = htons(server_port);
		/* Do TCP connect with server */
		if (connect(client_skt, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
			perror("Unable to TCP connect to server");
			goto Exit;
		} else {
			printf("TCP connection to server successful\n");
		}

		/* Create server SSL structure using client socket */
		ssl = SSL_new(ssl_ctx);
		SSL_set_fd(ssl, client_skt);

		/* Now do SSL connect with server */
		if (SSL_connect(ssl) == 1) {
			printf("SSL connection to server successful\n\n");

			/* Loop to send input from keyboard */
			while (true) {
				/* Get a line of input */
				txlen = getline(&txbuf, &txcap, stdin);
				/* Exit loop if just a carriage return */
				if (txbuf[0] == '\n') {
					break;
				}

				/* Send it to the server */
				if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
					printf("Server closed connection\n");
					ERR_print_errors_fp(stderr);
					break;
				}

				/* Wait for the echo */
				rxlen = SSL_read(ssl, rxbuf, rxcap);
				if (rxlen <= 0) {
					printf("Server closed connection\n");
					ERR_print_errors_fp(stderr);
					break;
				} else {
					/* Show it */
					rxbuf[rxlen] = 0;
					printf("Received: %s", rxbuf);
				}
			}
			printf("Client exiting...\n");
		} else
			ERR_print_errors_fp(stderr);
	}
	Exit:
	/* Close up */
	if (ssl != NULL) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	SSL_CTX_free(ssl_ctx);

	if (client_skt != -1)
		close(client_skt);
	if (server_skt != -1)
		close(server_skt);

	free(txbuf);
	free(rxbuf);

	printf("sslecho exiting\n");
}
