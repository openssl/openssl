typedef void (*block_f)(const unsigned char in[16],
			unsigned char out[16],
			const void *key);

void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block_f block);
void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block_f block);

void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], unsigned char ecount_buf[16],
			unsigned int *num, block_f block);

void CRYPTO_ofb128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], int *num,
			block_f block);

void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], int *num,
			int enc, block_f block);
void CRYPTO_cfb128_8_encrypt(const unsigned char *in, unsigned char *out,
			size_t length, const void *key,
			unsigned char ivec[16], int *num,
			int enc, block_f block);
void CRYPTO_cfb128_1_encrypt(const unsigned char *in, unsigned char *out,
			size_t bits, const void *key,
			unsigned char ivec[16], int *num,
			int enc, block_f block);

