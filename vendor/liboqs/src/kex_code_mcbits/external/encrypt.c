static void gen_e(unsigned char *e, OQS_RAND *r) {
	int i, j, eq;

	uint16_t ind[SYS_T];
	uint64_t e_int[64];
	uint64_t one = 1;
	uint64_t mask;
	uint64_t val[SYS_T];

	while (1) {
		OQS_RAND_n(r, (uint8_t *) ind, sizeof(ind));

		for (i = 0; i < SYS_T; i++)
			ind[i] &= (1 << GFBITS) - 1;

		eq = 0;
		for (i = 1; i < SYS_T; i++)
			for (j = 0; j < i; j++)
				if (ind[i] == ind[j])
					eq = 1;

		if (eq == 0)
			break;
	}

	for (j = 0; j < SYS_T; j++)
		val[j] = one << (ind[j] & 63);

	for (i = 0; i < 64; i++) {
		e_int[i] = 0;

		for (j = 0; j < SYS_T; j++) {
			mask = i ^ (ind[j] >> 6);
			mask -= 1;
			mask >>= 63;
			mask = -mask;

			e_int[i] |= val[j] & mask;
		}
	}

	for (i = 0; i < 64; i++)
		store8(e + i * 8, e_int[i]);
}

#define C ((PK_NCOLS + 63) / 64)

static void syndrome(unsigned char *s, const unsigned char *pk, const unsigned char *e) {
	int i, j, t;

	const unsigned char *e_ptr = e + SYND_BYTES;

	uint64_t e_int[C];
	uint64_t row_int[C];
	uint64_t tmp[8];

	unsigned char b;

	//

	memcpy(s, e, SYND_BYTES);

	e_int[C - 1] = 0;
	memcpy(e_int, e_ptr, PK_NCOLS / 8);

	for (i = 0; i < PK_NROWS; i += 8) {
		for (t = 0; t < 8; t++) {
			row_int[C - 1] = 0;
			memcpy(row_int, &pk[(i + t) * (PK_NCOLS / 8)], PK_NCOLS / 8);

			tmp[t] = 0;
			for (j = 0; j < C; j++)
				tmp[t] ^= e_int[j] & row_int[j];
		}

		b = 0;

		for (t = 7; t >= 0; t--)
			tmp[t] ^= (tmp[t] >> 32);
		for (t = 7; t >= 0; t--)
			tmp[t] ^= (tmp[t] >> 16);
		for (t = 7; t >= 0; t--)
			tmp[t] ^= (tmp[t] >> 8);
		for (t = 7; t >= 0; t--)
			tmp[t] ^= (tmp[t] >> 4);
		for (t = 7; t >= 0; t--) {
			b <<= 1;
			b |= (0x6996 >> (tmp[t] & 0xF)) & 1;
		}

		s[i / 8] ^= b;
	}
}

static void encrypt(unsigned char *s, unsigned char *e, const unsigned char *pk, OQS_RAND *r) {
	gen_e(e, r);
	syndrome(s, pk, e);
}
