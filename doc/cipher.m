From ssl-lists-owner@mincom.com Tue Oct 15 18:16:14 1996
Received: from cygnus.mincom.oz.au by orb.mincom.oz.au with SMTP id AA11550
  (5.65c/IDA-1.4.4 for eay); Tue, 15 Oct 1996 08:17:41 +1000
Received: (from daemon@localhost) by cygnus.mincom.oz.au (8.7.5/8.7.3) id IAA12472 for ssl-users-outgoing; Tue, 15 Oct 1996 08:16:35 +1000 (EST)
Received: from orb.mincom.oz.au (eay@orb.mincom.oz.au [192.55.197.1]) by cygnus.mincom.oz.au (8.7.5/8.7.3) with SMTP id IAA12463 for <ssl-users@listserv.mincom.oz.au>; Tue, 15 Oct 1996 08:16:32 +1000 (EST)
Received: by orb.mincom.oz.au id AA11544
  (5.65c/IDA-1.4.4 for ssl-users@listserv.mincom.oz.au); Tue, 15 Oct 1996 08:16:15 +1000
Date: Tue, 15 Oct 1996 08:16:14 +1000 (EST)
From: Eric Young <eay@mincom.com>
X-Sender: eay@orb
To: Roland Haring <rharing@tandem.cl>
Cc: ssl-users@mincom.com
Subject: Re: Symmetric encryption with ssleay
In-Reply-To: <m0vBpyq-00001aC@tandemnet.tandem.cl>
Message-Id: <Pine.SOL.3.91.961015075623.11394A-100000@orb>
Mime-Version: 1.0
Content-Type: TEXT/PLAIN; charset=US-ASCII
Sender: ssl-lists-owner@mincom.com
Precedence: bulk
Status: RO
X-Status: 


On Fri, 11 Oct 1996, Roland Haring wrote:
> THE_POINT:
> 	Would somebody be so kind to give me the minimum basic 
> 	calls I need to do to libcrypto.a to get some text encrypted
> 	and decrypted again? ...hopefully with code included to do
> 	base64 encryption and decryption ... e.g. that sign-it.c code
> 	posted some while ago was a big help :-) (please, do not point
> 	me to apps/enc.c where I suspect my Heissenbug to be hidden :-)

Ok, the base64 encoding stuff in 'enc.c' does the wrong thing sometimes 
when the data is less than a line long (this is for decoding).  I'll dig 
up the exact fix today and post it.  I am taking longer on 0.6.5 than I 
intended so I'll just post this patch.

The documentation to read is in
doc/cipher.doc,
doc/encode.doc (very sparse :-).
and perhaps
doc/digest.doc,

The basic calls to encrypt with say triple DES are

Given
char key[EVP_MAX_KEY_LENGTH];
char iv[EVP_MAX_IV_LENGTH];
EVP_CIPHER_CTX ctx;
unsigned char out[512+8];
int outl;

/* optional generation of key/iv data from text password using md5
 * via an upward compatable verson of PKCS#5. */
EVP_BytesToKey(EVP_des_ede3_cbc,EVP_md5,NULL,passwd,strlen(passwd),
	key,iv);

/* Initalise the EVP_CIPHER_CTX */
EVP_EncryptInit(ctx,EVP_des_ede3_cbc,key,iv);

while (....)
	{
	/* This is processing 512 bytes at a time, the bytes are being
	 * copied into 'out', outl bytes are output.  'out' should not be the
	 * same as 'in' for reasons mentioned in the documentation. */
	EVP_EncryptUpdate(ctx,out,&outl,in,512);
	}

/* Output the last 'block'.  If the cipher is a block cipher, the last
 * block is encoded in such a way so that a wrong decryption will normally be
 * detected - again, one of the PKCS standards. */

EVP_EncryptFinal(ctx,out,&outl);

To decrypt, use the EVP_DecryptXXXXX functions except that EVP_DecryptFinal()
will return 0 if the decryption fails (only detectable on block ciphers).

You can also use
EVP_CipherInit()
EVP_CipherUpdate()
EVP_CipherFinal()
which does either encryption or decryption depending on an extra 
parameter to EVP_CipherInit().


To do the base64 encoding,
EVP_EncodeInit()
EVP_EncodeUpdate()
EVP_EncodeFinal()

EVP_DecodeInit()
EVP_DecodeUpdate()
EVP_DecodeFinal()

where the encoding is quite simple, but the decoding can be a bit more 
fun (due to dud input).

EVP_DecodeUpdate() returns -1 for an error on an input line, 0 if the 
'last line' was just processed, and 1 if more lines should be submitted.

EVP_DecodeFinal() returns -1 for an error or 1 if things are ok.

So the loop becomes
EVP_DecodeInit(....)
for (;;)
	{
	i=EVP_DecodeUpdate(....);
	if (i < 0) goto err;

	/* process the data */

	if (i == 0) break;
	}
EVP_DecodeFinal(....);
/* process the data */

The problem in 'enc.c' is that I was stuff the processing up after the 
EVP_DecodeFinal(...) when the for(..) loop was not being run (one line of 
base64 data) and this was because 'enc.c' tries to scan over a file until
it hits the first valid base64 encoded line.

hope this helps a bit.
eric
--
Eric Young                  | BOOL is tri-state according to Bill Gates.
AARNet: eay@mincom.oz.au    | RTFM Win32 GetMessage().


