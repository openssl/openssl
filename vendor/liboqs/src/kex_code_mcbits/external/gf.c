typedef uint16_t gf;

static gf gf_mul(gf in0, gf in1) {
	int i;

	uint32_t tmp;
	uint32_t t0;
	uint32_t t1;
	uint32_t t;

	t0 = in0;
	t1 = in1;

	tmp = t0 * (t1 & 1);

	for (i = 1; i < GFBITS; i++)
		tmp ^= (t0 * (t1 & (1 << i)));

	t = tmp & 0x7FC000;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	t = tmp & 0x3000;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	return tmp & ((1 << GFBITS) - 1);
}

static gf gf_sq(gf in) {
	const uint32_t B[] = {0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF};

	uint32_t x = in;
	uint32_t t;

	x = (x | (x << 8)) & B[3];
	x = (x | (x << 4)) & B[2];
	x = (x | (x << 2)) & B[1];
	x = (x | (x << 1)) & B[0];

	t = x & 0x7FC000;
	x ^= t >> 9;
	x ^= t >> 12;

	t = x & 0x3000;
	x ^= t >> 9;
	x ^= t >> 12;

	return x & ((1 << GFBITS) - 1);
}

static gf gf_inv(gf in) {
	gf tmp_11;
	gf tmp_1111;

	gf out = in;

	out = gf_sq(out);
	tmp_11 = gf_mul(out, in); // 11

	out = gf_sq(tmp_11);
	out = gf_sq(out);
	tmp_1111 = gf_mul(out, tmp_11); // 1111

	out = gf_sq(tmp_1111);
	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_mul(out, tmp_1111); // 11111111

	out = gf_sq(out);
	out = gf_sq(out);
	out = gf_mul(out, tmp_11); // 1111111111

	out = gf_sq(out);
	out = gf_mul(out, in); // 11111111111

	return gf_sq(out); // 111111111110
}

static gf gf_diff(gf a, gf b) {
	uint32_t t = (uint32_t)(a ^ b);

	t = ((t - 1) >> 20) ^ 0xFFF;

	return (gf) t;
}

///////////////////////////////////////////////////////////

static void GF_mul(gf *out, gf *in0, gf *in1) {
	int i, j;

	gf tmp[123];

	for (i = 0; i < 123; i++)
		tmp[i] = 0;

	for (i = 0; i < 62; i++)
		for (j = 0; j < 62; j++)
			tmp[i + j] ^= gf_mul(in0[i], in1[j]);

	//

	for (i = 122; i >= 62; i--) {
		tmp[i - 55] ^= gf_mul(tmp[i], (gf) 1763);
		tmp[i - 61] ^= gf_mul(tmp[i], (gf) 1722);
		tmp[i - 62] ^= gf_mul(tmp[i], (gf) 4033);
	}

	for (i = 0; i < 62; i++)
		out[i] = tmp[i];
}
