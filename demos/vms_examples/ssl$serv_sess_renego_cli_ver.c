/*
 * ++
 * FACILITY:
 *
 *    Simplest SSL Server + "Socket BIO" + "client certificate verification" + "SSL Renegotiation"
 *
 * ABSTRACT:
 *
 *      This is an example of a SSL server with minimum functionality.
 *      This server uses Socket BIO.
 *      The socket APIs are used to handle TCP/IP operations. This SSL
 *      server loads its own certificate and key,
 *      and it requests & verifies the certificate of the SSL client.
 *
 *      This SSL server also demonstrates how to implement SSL Renegotiation
 *      in the server.
 *
 * ENVIRONMENT:
 *
 *    OpenVMS Alpha V7.2-2
 *    TCP/IP Services V5.0A or higher
 *
 * AUTHOR:
 *
 *    Taka Shinagawa, OpenVMS Security Group
 *
 * CREATION DATE:
 *
 *    1-Jan-2002
 *
 * --
 */

/* Assumptions, Build, Configuration, and Execution Instructions */

/*
 *  ASSUMPTIONS:
 *
 *    The following are assumed to be true for the
 *    execution of this program to succeed:
 *
 *    - SSL is installed and started on this system.
 *
 *    - this server program, and its accompanying client
 *      program are run on the same system, but in different
 *      processes.
 *
 *    - the certificate and keys referenced by this program
 *      reside in the same directory as this program.  There
 *      is a command procedure, SSL$EXAMPLES_SETUP.COM, to
 *      help set up the certificates and keys.
 *
 *  BUILD INSTRUCTIONS:
 *
 *    To build this example program use commands of the form,
 *
 *      For a 32-bit application using only SSL APIs needs to run the following commands for SSL_APP.C .
 *       -----------------------------------------------------------------
 *       $CC/POINTER_SIZE=32/PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES SSL_APP.C
 *       $LINK SSL_APP.OBJ, VMS_DECC_OPTIONS.OPT/OPT
 *       -----------------------------------------------------------------
 *       VMS_DECC_OPTIONS.OPT should include the following lines.
 *       -------------------------------------------------
 *       SYS$LIBRARY:OPENSSL$LIBCRYPTO_SHR32.EXE/SHARE
 *       SYS$LIBRARY:OPENSSL$LIBSSL_SHR32.EXE/SHARE
 *       -------------------------------------------------
 *
 *       Creating a 64-bit application of SSL_APP.C should run the following commands.
 *       -----------------------------------------------------------------
 *       $CC/POINTER_SIZE=64/PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES SSL_APP.C
 *       $LINK SSL_APP.OBJ, VMS_DECC_OPTIONS.OPT/OPT
 *       -----------------------------------------------------------------
 *       VMS_DECC_OPTIONS.OPT should include the following lines.
 *       -------------------------------------------------
 *       SYS$LIBRARY:OPENSSL$LIBCRYPTO_SHR.EXE/SHARE
 *       SYS$LIBRARY:OPENSSL$LIBSSL_SHR.EXE/SHARE
 *       -------------------------------------------------
 *
 *
 * CONFIGURATION INSTRUCTIONS:
 *
 *
 * RUN INSTRUCTIONS:
 *
 *    To run this example program:
 *
 *    1) Start the server program,
 *
 *       $ run server
 *
 *    2) Start the client program on this same system,
 *
 *       $ run client
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>

#ifdef __VMS
#include <types.h>
#include <socket.h>
#include <in.h>
#include <inet.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define RSA_SERVER_CERT 	"server.crt"
#define RSA_SERVER_KEY 		"server.key"

#define RSA_SERVER_CA_CERT	"server_ca.crt"
#define RSA_SERVER_CA_PATH	"sys$common:[syshlp.examples.ssl]"

#define ON 	1
#define OFF 	0

#define RETURN_NULL(x) if ((x)==NULL) exit(1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }

void main ()
{
	int 	err;
	int 	verify_client = ON; /* To verify a client certificate, set ON */

  	int 	listen_sock;
  	int 	sock;
  	struct sockaddr_in sa_serv;
  	struct sockaddr_in sa_cli;
  	size_t client_len;
  	char	*str;
  	char     buf[4096];

	SSL_CTX		*ctx;
        SSL		*ssl;
  	SSL_METHOD 	*meth;
	X509		*client_cert = NULL;
	BIO		*sbio = NULL;
	SSL_SESSION	*sess = NULL;

	short int       s_port = 5555;

        /*-----------------------------------------------------------------------------------------*/
	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();

	/* Load the error strings for SSL & CRYPTO APIs */
 	SSL_load_error_strings();

	/* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
  	meth = TLSv1_method();

	/* Create a SSL_CTX structure */
  	ctx = SSL_CTX_new(meth);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Load the server certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ctx, RSA_SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
    		ERR_print_errors_fp(stderr);
    		exit(1);
	}

	/* Load the private-key corresponding to the server certificate */
  	if (SSL_CTX_use_PrivateKey_file(ctx, RSA_SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
    		ERR_print_errors_fp(stderr);
    		exit(1);
  	}

	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx)) {
    		fprintf(stderr,"Private key does not match the certificate public key\n");
    		exit(1);
  	}

	if(verify_client == ON)
	{
		/* Load the RSA CA certificate into the SSL_CTX structure */
		if (!SSL_CTX_load_verify_locations(ctx, RSA_SERVER_CA_CERT, NULL)) {
                	ERR_print_errors_fp(stderr);
                	exit(1);
        	}

		/* Set to require peer (client) certificate verification */
		SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);

		/* Set the verification depth to 1 */
		SSL_CTX_set_verify_depth(ctx,1);
	}

	/* ----------------------------------------------- */
	/* Set up a TCP socket */

	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);   
	RETURN_ERR(listen_sock, "socket");

  	memset (&sa_serv, '\0', sizeof(sa_serv));
  	sa_serv.sin_family      = AF_INET;
  	sa_serv.sin_addr.s_addr = INADDR_ANY;
  	sa_serv.sin_port        = htons (s_port);          /* Server Port number */
  
  	err = bind(listen_sock, (struct sockaddr*)&sa_serv,sizeof(sa_serv));
	RETURN_ERR(err, "bind");
	     
  	/* Wait for an incoming TCP connection. */
  	err = listen(listen_sock, 5);                    
	RETURN_ERR(err, "listen");

  	client_len = sizeof(sa_cli);
 
	/* Socket for a TCP/IP connection is created */
  	sock = accept(listen_sock, (struct sockaddr*)&sa_cli, &client_len);
  	RETURN_ERR(sock, "accept");
  	close (listen_sock);

  	printf ("Connection from %lx, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);

  	/* ----------------------------------------------- */
	/* TCP connection is ready. */

	/* A SSL structure is created */
	ssl = SSL_new(ctx);
	RETURN_NULL(ssl);

	if(1){ /* Use a socket BIO between the socket and SSL structure */
		/* Create a socket BIO */
		sbio = BIO_new_socket(sock, BIO_NOCLOSE);

		/* Assign the socket BIO to the SSL structure*/
		SSL_set_bio(ssl, sbio, sbio);
		
	}
	else{
		/* Assign the socket into the SSL structure (SSL and socket without BIO) */
		SSL_set_fd(ssl, sock);
	}

	/* Perform SSL Handshake on the SSL server */
	err = SSL_accept(ssl);
	RETURN_SSL(err);

  	/* Informational output (optional) */
  	printf("SSL connection using %s\n", SSL_get_cipher (ssl));

	/* Session established with the first SSL handshake */
	sess = SSL_get_session(ssl);
	printf("Session 1: SSL_SESSION_hash(sess) >> %d\n", SSL_SESSION_hash(sess));

  	/* Get the client's certificate (optional) */
  	client_cert = SSL_get_peer_certificate(ssl);

  	if (client_cert != NULL) 
	{
    		printf ("Client certificate:\n");
   
    		str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
    		RETURN_NULL(str);
    		printf ("\t subject: %s\n", str);
    		free (str);

    		str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
    		RETURN_NULL(str);
    		printf ("\t issuer: %s\n", str);
   		free (str);

    		X509_free(client_cert);
	} 
	else
		printf("The SSL client does not have certificate.\n");


	/*--------------- DATA EXCHANGE - Receive message and send reply. ---------------*/

	/* Receive data from the SSL client */
	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	RETURN_SSL(err);
	buf[err] = '\0';
	printf ("Received %d chars:'%s'\n", err, buf);

	/* Send data to the SSL client */
	err = SSL_write(ssl, "This message is from the SSL server\n", strlen("This message is from the SSL server"));
	RETURN_SSL(err);

        /*--------------- Renegotiation 1 (initiated by the SSL server)  ---------------*/
	printf(">> Starting Renegotiation 1 (initiated by the server) \n");

        if(SSL_renegotiate(ssl)<=0){
                printf("SSL_renegotiate() failed.\n");
                exit(1);
        }

        if(SSL_do_handshake(ssl)<=0){
                printf("SSL_do_handshake() failed.\n");
                exit(1);
        }

        ssl->state = SSL_ST_ACCEPT;

        if(SSL_do_handshake(ssl)<=0){
                printf("SSL_do_handshake() failed.\n");
                exit(1);
        }

        printf(">> SSL Renegotiation succeeded\n");

	/* Session established with the first SSL renegotiation */
        sess = SSL_get_session(ssl);
        printf("Session 2 (with 1st SSL renegotiation): SSL_SESSION_hash(sess) >> %d\n", SSL_SESSION_hash(sess));

        /*----------------------------------------------------------------*/
        /* Receive a message from Client over the new SSL session */
        err = SSL_read(ssl, buf, sizeof(buf) - 1);
        RETURN_SSL(err);
        buf[err] = '\0';
        printf ("Received %d chars:'%s'\n", err, buf);

        /* Send a message to Client over the new SSL session */
        err = SSL_write(ssl, "From the server after SSL Renegotiation.", strlen("From the server after SSL Renegotiation."));
        RETURN_SSL(err);

	/*--------------- Renegotiation 2 (initiated by the SSL client)  ---------------*/

        printf("\n>> Starting Renegotiation 2 (initiated by the client)\n");

        err = SSL_read(ssl, buf, sizeof(buf) - 1);
        switch(SSL_get_error(ssl,err)){
                case SSL_ERROR_WANT_READ:
                        printf(">> SSL Renegotiation succeeded\n");
                        break;
                default:
                        printf("error\n");
                        exit(1);
        }

	/* Session established with the second SSL renegotiation */
        sess = SSL_get_session(ssl);
        printf("Session 3 (with 2nd SSL renegotiation): SSL_SESSION_hash(sess) >> %d\n", SSL_SESSION_hash(sess));

	/* Receive a message from Client over the new SSL session */
        err = SSL_read(ssl, buf, sizeof(buf) - 1);
        RETURN_SSL(err);
        buf[err] = '\0';
        printf ("Received %d chars:'%s'\n", err, buf);

	/* Send a message to Client over the new SSL session */
        err = SSL_write(ssl, "From the server after SSL Renegotiation.", strlen("From the server after SSL Renegotiation."));
        RETURN_SSL(err);

	/*--------------- SSL closure ---------------*/
	/* Shutdown this side of the connection */
	err = SSL_shutdown(ssl);
	RETURN_SSL(err);

	/* Terminate communication on a socket */
	err = close(sock);
	RETURN_ERR(err, "close");

	/* Free the SSL structure */
	SSL_free(ssl);

	/* Free the SSL_CTX structure */
 	SSL_CTX_free(ctx);
}

