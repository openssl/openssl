static void scaling(uint64_t out[][GFBITS], uint64_t inv[][GFBITS], const unsigned char *sk, uint64_t *recv) {
	int i, j;
	uint64_t sk_int[GFBITS];

	uint64_t eval[64][GFBITS];
	uint64_t tmp[GFBITS];

	// computing inverses

	for (i = 0; i < GFBITS; i++)
		sk_int[i] = load8(sk + i * 8);

	fft(eval, sk_int);

	for (i = 0; i < 64; i++)
		vec_sq(eval[i], eval[i]);

	vec_copy(inv[0], eval[0]);

	for (i = 1; i < 64; i++)
		vec_mul(inv[i], inv[i - 1], eval[i]);

	vec_inv(tmp, inv[63]);

	for (i = 62; i >= 0; i--) {
		vec_mul(inv[i + 1], tmp, inv[i]);
		vec_mul(tmp, tmp, eval[i + 1]);
	}

	vec_copy(inv[0], tmp);

	//

	for (i = 0; i < 64; i++)
		for (j = 0; j < GFBITS; j++)
			out[i][j] = inv[i][j] & recv[i];
}

static void scaling_inv(uint64_t out[][GFBITS], uint64_t inv[][GFBITS], uint64_t *recv) {
	int i, j;

	for (i = 0; i < 64; i++)
		for (j = 0; j < GFBITS; j++)
			out[i][j] = inv[i][j] & recv[i];
}

static void preprocess(uint64_t *recv, const unsigned char *s) {
	int i;

	for (i = 0; i < 64; i++)
		recv[i] = 0;

	for (i = 0; i < SYND_BYTES / 8; i++)
		recv[i] = load8(s + i * 8);

	for (i = SYND_BYTES % 8 - 1; i >= 0; i--) {
		recv[SYND_BYTES / 8] <<= 8;
		recv[SYND_BYTES / 8] |= s[SYND_BYTES / 8 * 8 + i];
	}
}

//

static void acc(uint64_t *c, uint64_t v) {
	int i;

	uint64_t carry = v;
	uint64_t t;

	for (i = 0; i < 8; i++) {
		t = c[i] ^ carry;
		carry = c[i] & carry;

		c[i] = t;
	}
}

static int weight(uint64_t *v) {
	int i;
	int w;

	union {
		uint64_t data_64[8];
		uint8_t data_8[64];
	} counter;

	//

	for (i = 0; i < 8; i++)
		counter.data_64[i] = 0;

	for (i = 0; i < 64; i++)
		acc(counter.data_64, v[i]);

	transpose_8x64(counter.data_64);

	//

	w = 0;
	for (i = 0; i < 64; i++)
		w += counter.data_8[i];

	return w;
}

//

static void syndrome_adjust(uint64_t in[][GFBITS]) {
	int i;

	for (i = 0; i < GFBITS; i++) {
		in[1][i] <<= (128 - SYS_T * 2);
		in[1][i] >>= (128 - SYS_T * 2);
	}
}

static int decrypt(unsigned char *e, const unsigned char *sk, const unsigned char *s) {
	int i, j;

	uint64_t t;

	uint64_t diff;

	uint64_t inv[64][GFBITS];
	uint64_t scaled[64][GFBITS];
	uint64_t eval[64][GFBITS];

	uint64_t error[64];

	uint64_t s_priv[2][GFBITS];
	uint64_t s_priv_cmp[2][GFBITS];
	uint64_t locator[GFBITS];

	uint64_t recv[64];
	uint64_t cond[COND_BYTES / 8];

	//

	for (i = 0; i < COND_BYTES / 8; i++)
		cond[i] = load8(sk + IRR_BYTES + i * 8);

	preprocess(recv, s);
	benes_compact(recv, cond, 1);
	scaling(scaled, inv, sk, recv); // scaling
	fft_tr(s_priv, scaled);         // transposed FFT
	syndrome_adjust(s_priv);
	bm(locator, s_priv); // Berlekamp Massey
	fft(eval, locator);  // FFT

	for (i = 0; i < 64; i++) {
		error[i] = vec_or(eval[i]);
		error[i] = ~error[i];
	}

	{
		// reencrypt

		scaling_inv(scaled, inv, error);
		fft_tr(s_priv_cmp, scaled);
		syndrome_adjust(s_priv_cmp);

		diff = 0;
		for (i = 0; i < 2; i++)
			for (j = 0; j < GFBITS; j++)
				diff |= s_priv[i][j] ^ s_priv_cmp[i][j];

		diff |= diff >> 32;
		diff |= diff >> 16;
		diff |= diff >> 8;
		t = diff & 0xFF;
	}

	benes_compact(error, cond, 0);

	for (i = 0; i < 64; i++)
		store8(e + i * 8, error[i]);

	//

	t |= weight(error) ^ SYS_T;
	t -= 1;
	t >>= 63;

	return (t - 1);
}
