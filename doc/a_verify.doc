From eay@mincom.com Fri Oct  4 18:29:06 1996
Received: by orb.mincom.oz.au id AA29080
  (5.65c/IDA-1.4.4 for eay); Fri, 4 Oct 1996 08:29:07 +1000
Date: Fri, 4 Oct 1996 08:29:06 +1000 (EST)
From: Eric Young <eay@mincom.oz.au>
X-Sender: eay@orb
To: wplatzer <wplatzer@iaik.tu-graz.ac.at>
Cc: Eric Young <eay@mincom.oz.au>, SSL Mailing List <ssl-users@mincom.com>
Subject: Re: Netscape's Public Key
In-Reply-To: <19961003134837.NTM0049@iaik.tu-graz.ac.at>
Message-Id: <Pine.SOL.3.91.961004081346.8018K-100000@orb>
Mime-Version: 1.0
Content-Type: TEXT/PLAIN; charset=US-ASCII
Status: RO
X-Status: 

On Thu, 3 Oct 1996, wplatzer wrote:
> I get Public Key from Netscape (Gold 3.0b4), but cannot do anything
> with it... It looks like (asn1parse):
> 
> 0:d=0 hl=3 l=180 cons: SEQUENCE
> 3:d=1 hl=2 l= 96 cons: SEQUENCE
> 5:d=2 hl=2 l= 92 cons: SEQUENCE
> 7:d=3 hl=2 l= 13 cons: SEQUENCE
> 9:d=4 hl=2 l= 9 prim: OBJECT :rsaEncryption
> 20:d=4 hl=2 l= 0 prim: NULL
> 22:d=3 hl=2 l= 75 prim: BIT STRING
> 99:d=2 hl=2 l= 0 prim: IA5STRING :
> 101:d=1 hl=2 l= 13 cons: SEQUENCE
> 103:d=2 hl=2 l= 9 prim: OBJECT :md5withRSAEncryption
> 114:d=2 hl=2 l= 0 prim: NULL
> 116:d=1 hl=2 l= 65 prim: BIT STRING
> 
> The first BIT STRING is the public key and the second BIT STRING is 
> the signature.
> But a public key consists of the public exponent and the modulus. Are 
> both numbers in the first BIT STRING?
> Is there a document simply describing this coding stuff (checking 
> signature, get the public key, etc.)?

Minimal in SSLeay.  If you want to see what the modulus and exponent are,
try asn1parse -offset 25 -length 75 <key.pem
asn1parse will currently stuff up on the 'length 75' part (fixed in next 
release) but it will print the stuff.  If you are after more 
documentation on ASN.1, have a look at www.rsa.com and get their PKCS 
documents, most of my initial work on SSLeay was done using them.

As for SSLeay,
util/crypto.num and util/ssl.num are lists of all exported functions in 
the library (but not macros :-(.

The ones for extracting public keys from certificates and certificate 
requests are EVP_PKEY *      X509_REQ_extract_key(X509_REQ *req);
EVP_PKEY *      X509_extract_key(X509 *x509);

To verify a signature on a signed ASN.1 object
int X509_verify(X509 *a,EVP_PKEY *key);
int X509_REQ_verify(X509_REQ *a,EVP_PKEY *key);
int X509_CRL_verify(X509_CRL *a,EVP_PKEY *key);
int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a,EVP_PKEY *key);

I should mention that EVP_PKEY can be used to hold a public or a private key,
since for  things like RSA and DSS, a public key is just a subset of what 
is stored for the private key.

To sign any of the above structures

int X509_sign(X509 *a,EVP_PKEY *key,EVP_MD *md);
int X509_REQ_sign(X509_REQ *a,EVP_PKEY *key,EVP_MD *md);
int X509_CRL_sign(X509_CRL *a,EVP_PKEY *key,EVP_MD *md);
int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *a,EVP_PKEY *key,EVP_MD *md);

where md is the message digest to sign with.

There are all defined in x509.h and all the _sign and _verify functions are
actually macros to the ASN1_sign() and ASN1_verify() functions.
These functions will put the correct algorithm identifiers in the correct 
places in the structures.

eric
--
Eric Young                  | BOOL is tri-state according to Bill Gates.
AARNet: eay@mincom.oz.au    | RTFM Win32 GetMessage().


