The Blowfish library.

Blowfish is a block cipher that operates on 64bit (8 byte) quantities.  It
uses variable size key, but 128bit (16 byte) key would normally be considered
good.  It can be used in all the modes that DES can be used.  This
library implements the ecb, cbc, cfb64, ofb64 modes.

Blowfish is quite a bit faster that DES, and much faster than IDEA or
RC2.  It is one of the faster block ciphers.

For all calls that have an 'input' and 'output' variables, they can be the
same.

This library requires the inclusion of 'blowfish.h'.

All of the encryption functions take what is called an BF_KEY as an 
argument.  An BF_KEY is an expanded form of the Blowfish key.
For all modes of the Blowfish algorithm, the BF_KEY used for
decryption is the same one that was used for encryption.

The define BF_ENCRYPT is passed to specify encryption for the functions
that require an encryption/decryption flag. BF_DECRYPT is passed to
specify decryption.

Please note that any of the encryption modes specified in my DES library
could be used with Blowfish.  I have only implemented ecb, cbc, cfb64 and
ofb64 for the following reasons.
- ecb is the basic Blowfish encryption.
- cbc is the normal 'chaining' form for block ciphers.
- cfb64 can be used to encrypt single characters, therefore input and output
  do not need to be a multiple of 8.
- ofb64 is similar to cfb64 but is more like a stream cipher, not as
  secure (not cipher feedback) but it does not have an encrypt/decrypt mode.
- If you want triple Blowfish, thats 384 bits of key and you must be totally
  obsessed with security.  Still, if you want it, it is simple enough to
  copy the function from the DES library and change the des_encrypt to
  BF_encrypt; an exercise left for the paranoid reader :-).

The functions are as follows:

void BF_set_key(
BF_KEY *ks;
int len;
unsigned char *key;
        BF_set_key converts an 'len' byte key into a BF_KEY.
        A 'ks' is an expanded form of the 'key' which is used to
        perform actual encryption.  It can be regenerated from the Blowfish key
        so it only needs to be kept when encryption or decryption is about
        to occur.  Don't save or pass around BF_KEY's since they
        are CPU architecture dependent, 'key's are not.  Blowfish is an
	interesting cipher in that it can be used with a variable length
	key.  'len' is the length of 'key' to be used as the key.
	A 'len' of 16 is recomended by me, but blowfish can use upto
	72 bytes.  As a warning, blowfish has a very very slow set_key
	function, it actually runs BF_encrypt 521 times.
	
void BF_encrypt(unsigned long *data, BF_KEY *key);
void BF_decrypt(unsigned long *data, BF_KEY *key);
	These are the Blowfish encryption function that gets called by just
	about every other Blowfish routine in the library.  You should not
	use this function except to implement 'modes' of Blowfish.
	I say this because the
	functions that call this routine do the conversion from 'char *' to
	long, and this needs to be done to make sure 'non-aligned' memory
	access do not occur.
	Data is a pointer to 2 unsigned long's and key is the
	BF_KEY to use. 

void BF_ecb_encrypt(
unsigned char *in,
unsigned char *out,
BF_KEY *key,
int encrypt);
	This is the basic Electronic Code Book form of Blowfish (in DES this
	mode is called Electronic Code Book so I'm going to use the term
	for blowfish as well.
	Input is encrypted into output using the key represented by
	key.  Depending on the encrypt, encryption or
	decryption occurs.  Input is 8 bytes long and output is 8 bytes.
	
void BF_cbc_encrypt(
unsigned char *in,
unsigned char *out,
long length,
BF_KEY *ks,
unsigned char *ivec,
int encrypt);
	This routine implements Blowfish in Cipher Block Chaining mode.
	Input, which should be a multiple of 8 bytes is encrypted
	(or decrypted) to output which will also be a multiple of 8 bytes.
	The number of bytes is in length (and from what I've said above,
	should be a multiple of 8).  If length is not a multiple of 8, bad 
	things will probably happen.  ivec is the initialisation vector.
	This function updates iv after each call so that it can be passed to
	the next call to BF_cbc_encrypt().
	
void BF_cfb64_encrypt(
unsigned char *in,
unsigned char *out,
long length,
BF_KEY *schedule,
unsigned char *ivec,
int *num,
int encrypt);
	This is one of the more useful functions in this Blowfish library, it
	implements CFB mode of Blowfish with 64bit feedback.
	This allows you to encrypt an arbitrary number of bytes,
	you do not require 8 byte padding.  Each call to this
	routine will encrypt the input bytes to output and then update ivec
	and num.  Num contains 'how far' we are though ivec.
	'Encrypt' is used to indicate encryption or decryption.
	CFB64 mode operates by using the cipher to generate a stream
	of bytes which is used to encrypt the plain text.
	The cipher text is then encrypted to generate the next 64 bits to
	be xored (incrementally) with the next 64 bits of plain
	text.  As can be seen from this, to encrypt or decrypt,
	the same 'cipher stream' needs to be generated but the way the next
	block of data is gathered for encryption is different for
	encryption and decryption.
	
void BF_ofb64_encrypt(
unsigned char *in,
unsigned char *out,
long length,
BF_KEY *schedule,
unsigned char *ivec,
int *num);
	This functions implements OFB mode of Blowfish with 64bit feedback.
	This allows you to encrypt an arbitrary number of bytes,
	you do not require 8 byte padding.  Each call to this
	routine will encrypt the input bytes to output and then update ivec
	and num.  Num contains 'how far' we are though ivec.
	This is in effect a stream cipher, there is no encryption or
	decryption mode.
	
For reading passwords, I suggest using des_read_pw_string() from my DES library.
To generate a password from a text string, I suggest using MD5 (or MD2) to
produce a 16 byte message digest that can then be passed directly to
BF_set_key().

=====
For more information about the specific Blowfish modes in this library
(ecb, cbc, cfb and ofb), read the section entitled 'Modes of DES' from the
documentation on my DES library.  What is said about DES is directly
applicable for Blowfish.

