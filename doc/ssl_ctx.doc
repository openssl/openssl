This is now a bit dated, quite a few of the SSL_ functions could be
SSL_CTX_ functions.  I will update this in the future. 30 Aug 1996

From eay@orb.mincom.oz.au Mon Dec 11 21:37:08 1995
Received: by orb.mincom.oz.au id AA00696
  (5.65c/IDA-1.4.4 for eay); Mon, 11 Dec 1995 11:37:08 +1000
Date: Mon, 11 Dec 1995 11:37:08 +1000 (EST)
From: Eric Young <eay@mincom.oz.au>
X-Sender: eay@orb
To: sameer <sameer@c2.org>
Cc: Eric Young <eay@mincom.oz.au>
Subject: Re: PEM_readX509 oesn't seem to be working
In-Reply-To: <199512110102.RAA12521@infinity.c2.org>
Message-Id: <Pine.SOL.3.91.951211112115.28608D-100000@orb>
Mime-Version: 1.0
Content-Type: TEXT/PLAIN; charset=US-ASCII
Status: RO
X-Status: 

On Sun, 10 Dec 1995, sameer wrote:
> 	OK, that's solved. I've found out that it is saying "no
> certificate set" in SSL_accept because s->conn == NULL
> so there is some place I need to initialize s->conn that I am
> not initializing it.

The full order of things for a server should be.

ctx=SSL_CTX_new();

/* The next line should not really be using ctx->cert but I'll leave it 
 * this way right now... I don't want a X509_ routine to know about an SSL
 * structure, there should be an SSL_load_verify_locations... hmm, I may 
 * add it tonight.
 */
X509_load_verify_locations(ctx->cert,CAfile,CApath);

/* Ok now for each new connection we do the following */
con=SSL_new(ctx);
SSL_set_fd(con,s);
SSL_set_verify(con,verify,verify_callback);

/* set the certificate and private key to use. */
SSL_use_certificate_ASN1(con,X509_certificate);
SSL_use_RSAPrivateKey_ASN1(con,RSA_private_key);

SSL_accept(con);

SSL_read(con)/SSL_write(con);

There is a bit more than that but that is basically the structure.

Create a context and specify where to lookup certificates.

foreach connection
	{
	create a SSL structure
	set the certificate and private key
	do a SSL_accept
	
	we should now be ok
	}

eric
--
Eric Young                  | Signature removed since it was generating
AARNet: eay@mincom.oz.au    | more followups than the message contents :-)


