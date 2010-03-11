extern int int_rsa_verify(int dtype, const unsigned char *m, unsigned int m_len,
		unsigned char *rm, size_t *prm_len,
		const unsigned char *sigbuf, size_t siglen,
		RSA *rsa);

int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const unsigned char *mHash,
			const EVP_MD *Hash, const EVP_MD *mgf1Hash, 
			const unsigned char *EM, int sLen);

int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, unsigned char *EM,
			const unsigned char *mHash,
			const EVP_MD *Hash, const EVP_MD *mgf1Hash, int sLen);
