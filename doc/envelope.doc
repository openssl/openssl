The following routines are use to create 'digital' envelopes.
By this I mean that they perform various 'higher' level cryptographic
functions.  Have a read of 'cipher.doc' and 'digest.doc' since those
routines are used by these functions.
cipher.doc contains documentation about the cipher part of the
envelope library and digest.doc contatins the description of the
message digests supported.

To 'sign' a document involves generating a message digest and then encrypting
the digest with an private key.

#define EVP_SignInit(a,b)		EVP_DigestInit(a,b)
#define EVP_SignUpdate(a,b,c)		EVP_DigestUpdate(a,b,c)
Due to the fact this operation is basically just an extended message
digest, the first 2 functions are macro calls to Digest generating
functions.

int     EVP_SignFinal(
EVP_MD_CTX *ctx,
unsigned char *md,
unsigned int *s,
EVP_PKEY *pkey);
	This finalisation function finishes the generation of the message
digest and then encrypts the digest (with the correct message digest 
object identifier) with the EVP_PKEY private key.  'ctx' is the message digest
context.  'md' will end up containing the encrypted message digest.  This
array needs to be EVP_PKEY_size(pkey) bytes long.  's' will actually
contain the exact length.  'pkey' of course is the private key.  It is
one of EVP_PKEY_RSA or EVP_PKEY_DSA type.
If there is an error, 0 is returned, otherwise 1.
		
Verify is used to check an signed message digest.

#define EVP_VerifyInit(a,b)		EVP_DigestInit(a,b)
#define EVP_VerifyUpdate(a,b,c)		EVP_DigestUpdate(a,b,c)
Since the first step is to generate a message digest, the first 2 functions
are macros.

int EVP_VerifyFinal(
EVP_MD_CTX *ctx,
unsigned char *md,
unsigned int s,
EVP_PKEY *pkey);
	This function finishes the generation of the message digest and then
compares it with the supplied encrypted message digest.  'md' contains the
's' bytes of encrypted message digest.  'pkey' is used to public key decrypt
the digest.  It is then compared with the message digest just generated.
If they match, 1 is returned else 0.

int	EVP_SealInit(EVP_CIPHER_CTX *ctx, EVP_CIPHER *type, unsigned char **ek,
		int *ekl, unsigned char *iv, EVP_PKEY **pubk, int npubk);
Must have at least one public key, error is 0.  I should also mention that
the buffers pointed to by 'ek' need to be EVP_PKEY_size(pubk[n]) is size.

#define EVP_SealUpdate(a,b,c,d,e)	EVP_EncryptUpdate(a,b,c,d,e)	
void	EVP_SealFinal(EVP_CIPHER_CTX *ctx,unsigned char *out,int *outl);


int	EVP_OpenInit(EVP_CIPHER_CTX *ctx,EVP_CIPHER *type,unsigned char *ek,
		int ekl,unsigned char *iv,EVP_PKEY *priv);
0 on failure

#define EVP_OpenUpdate(a,b,c,d,e)	EVP_DecryptUpdate(a,b,c,d,e)

int	EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
Decrypt final return code

