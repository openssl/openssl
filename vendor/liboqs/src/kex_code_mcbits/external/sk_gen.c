static int irr_gen(gf *out, gf *f) {
	int i, j, k, c;

	gf mat[SYS_T + 1][SYS_T];
	gf mask, inv, t;

	// fill matrix

	mat[0][0] = 1;
	for (i = 1; i < SYS_T; i++)
		mat[0][i] = 0;

	for (i = 0; i < SYS_T; i++)
		mat[1][i] = f[i];

	for (j = 2; j <= SYS_T; j++)
		GF_mul(mat[j], mat[j - 1], f);

	// gaussian

	for (j = 0; j < SYS_T; j++) {
		for (k = j + 1; k < SYS_T; k++) {
			mask = gf_diff(mat[j][j], mat[j][k]);

			for (c = 0; c < SYS_T + 1; c++)
				mat[c][j] ^= mat[c][k] & mask;
		}

		if (mat[j][j] == 0) { // return if not invertible
			return -1;
		}

		// compute inverse

		inv = gf_inv(mat[j][j]);

		for (c = 0; c < SYS_T + 1; c++)
			mat[c][j] = gf_mul(mat[c][j], inv);

		//

		for (k = 0; k < SYS_T; k++) {
			t = mat[j][k];

			if (k != j) {
				for (c = 0; c < SYS_T + 1; c++)
					mat[c][k] ^= gf_mul(mat[c][j], t);
			}
		}
	}

	//

	for (i = 0; i < SYS_T; i++)
		out[i] = mat[SYS_T][i];

	out[SYS_T] = 1;

	return 0;
}

static void sk_gen(unsigned char *sk, OQS_RAND *r) {
	uint64_t cond[COND_BYTES / 8];
	uint64_t sk_int[GFBITS];

	int i, j;

	gf irr[SYS_T + 1];
	gf f[SYS_T];

	while (1) {
		OQS_RAND_n(r, (uint8_t *) f, sizeof(f));

		for (i = 0; i < SYS_T; i++)
			f[i] &= (1 << GFBITS) - 1;

		if (irr_gen(irr, f) == 0)
			break;
	}

	for (i = 0; i < GFBITS; i++) {
		sk_int[i] = 0;

		for (j = SYS_T; j >= 0; j--) {
			sk_int[i] <<= 1;
			sk_int[i] |= (irr[j] >> i) & 1;
		}

		store8(sk + i * 8, sk_int[i]);
	}

	//

	OQS_RAND_n(r, (uint8_t *) cond, sizeof(cond));

	for (i = 0; i < COND_BYTES / 8; i++)
		store8(sk + IRR_BYTES + i * 8, cond[i]);
}
