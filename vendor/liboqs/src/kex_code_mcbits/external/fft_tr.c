#define vec_add(z, x, y)           \
	for (b = 0; b < GFBITS; b++) { \
		z[b] = x[b] ^ y[b];        \
	}

static void radix_conversions_tr(uint64_t in[][GFBITS]) {
	int i, j, k;

	const uint64_t mask[6][2] = {
	    {0x2222222222222222, 0x4444444444444444},
	    {0x0C0C0C0C0C0C0C0C, 0x3030303030303030},
	    {0x00F000F000F000F0, 0x0F000F000F000F00},
	    {0x0000FF000000FF00, 0x00FF000000FF0000},
	    {0x00000000FFFF0000, 0x0000FFFF00000000},
	    {0xFFFFFFFF00000000, 0x00000000FFFFFFFF}};

	const uint64_t s[5][2][GFBITS] = {
#include "scalars_2x.data"
	};

	//

	for (j = 5; j >= 0; j--) {
		if (j < 5) {
			vec_mul(in[0], in[0], s[j][0]); // scaling
			vec_mul(in[1], in[1], s[j][1]); // scaling
		}

		for (i = 0; i < GFBITS; i++)
			for (k = j; k <= 4; k++) {
				in[0][i] ^= (in[0][i] & mask[k][0]) << (1 << k);
				in[0][i] ^= (in[0][i] & mask[k][1]) << (1 << k);

				in[1][i] ^= (in[1][i] & mask[k][0]) << (1 << k);
				in[1][i] ^= (in[1][i] & mask[k][1]) << (1 << k);
			}

		for (i = 0; i < GFBITS; i++) {
			in[1][i] ^= (in[0][i] & mask[5][0]) >> 32;
			in[1][i] ^= (in[1][i] & mask[5][1]) << 32;
		}
	}
}

static void butterflies_tr(uint64_t out[][GFBITS], uint64_t in[][GFBITS]) {
	int i, j, k, s, b;

	uint64_t tmp[GFBITS];
	uint64_t pre[6][GFBITS];
	uint64_t buf[64];

	const uint64_t consts[63][GFBITS] = {
#include "consts.data"
	};

	uint64_t consts_ptr = 63;

	const unsigned char reversal[64] = {
	    0, 32, 16, 48, 8, 40, 24, 56,
	    4, 36, 20, 52, 12, 44, 28, 60,
	    2, 34, 18, 50, 10, 42, 26, 58,
	    6, 38, 22, 54, 14, 46, 30, 62,
	    1, 33, 17, 49, 9, 41, 25, 57,
	    5, 37, 21, 53, 13, 45, 29, 61,
	    3, 35, 19, 51, 11, 43, 27, 59,
	    7, 39, 23, 55, 15, 47, 31, 63};

	const uint16_t beta[6] = {8, 1300, 3408, 1354, 2341, 1154};

	// butterflies

	for (i = 5; i >= 0; i--) {
		s = 1 << i;
		consts_ptr -= s;

		for (j = 0; j < 64; j += 2 * s)
			for (k = j; k < j + s; k++) {
				vec_add(in[k], in[k], in[k + s]);
				vec_mul(tmp, in[k], consts[consts_ptr + (k - j)]);
				vec_add(in[k + s], in[k + s], tmp);
			}
	}

	// transpose

	for (i = 0; i < GFBITS; i++) {
		for (j = 0; j < 64; j++)
			buf[reversal[j]] = in[j][i];

		transpose_64x64_compact(buf, buf);

		for (j = 0; j < 64; j++)
			in[j][i] = buf[j];
	}

	// boradcast

	vec_copy(pre[0], in[32]);
	vec_add(in[33], in[33], in[32]);
	vec_copy(pre[1], in[33]);
	vec_add(in[35], in[35], in[33]);
	vec_add(pre[0], pre[0], in[35]);
	vec_add(in[34], in[34], in[35]);
	vec_copy(pre[2], in[34]);
	vec_add(in[38], in[38], in[34]);
	vec_add(pre[0], pre[0], in[38]);
	vec_add(in[39], in[39], in[38]);
	vec_add(pre[1], pre[1], in[39]);
	vec_add(in[37], in[37], in[39]);
	vec_add(pre[0], pre[0], in[37]);
	vec_add(in[36], in[36], in[37]);
	vec_copy(pre[3], in[36]);
	vec_add(in[44], in[44], in[36]);
	vec_add(pre[0], pre[0], in[44]);
	vec_add(in[45], in[45], in[44]);
	vec_add(pre[1], pre[1], in[45]);
	vec_add(in[47], in[47], in[45]);
	vec_add(pre[0], pre[0], in[47]);
	vec_add(in[46], in[46], in[47]);
	vec_add(pre[2], pre[2], in[46]);
	vec_add(in[42], in[42], in[46]);
	vec_add(pre[0], pre[0], in[42]);
	vec_add(in[43], in[43], in[42]);
	vec_add(pre[1], pre[1], in[43]);
	vec_add(in[41], in[41], in[43]);
	vec_add(pre[0], pre[0], in[41]);
	vec_add(in[40], in[40], in[41]);
	vec_copy(pre[4], in[40]);
	vec_add(in[56], in[56], in[40]);
	vec_add(pre[0], pre[0], in[56]);
	vec_add(in[57], in[57], in[56]);
	vec_add(pre[1], pre[1], in[57]);
	vec_add(in[59], in[59], in[57]);
	vec_add(pre[0], pre[0], in[59]);
	vec_add(in[58], in[58], in[59]);
	vec_add(pre[2], pre[2], in[58]);
	vec_add(in[62], in[62], in[58]);
	vec_add(pre[0], pre[0], in[62]);
	vec_add(in[63], in[63], in[62]);
	vec_add(pre[1], pre[1], in[63]);
	vec_add(in[61], in[61], in[63]);
	vec_add(pre[0], pre[0], in[61]);
	vec_add(in[60], in[60], in[61]);
	vec_add(pre[3], pre[3], in[60]);
	vec_add(in[52], in[52], in[60]);
	vec_add(pre[0], pre[0], in[52]);
	vec_add(in[53], in[53], in[52]);
	vec_add(pre[1], pre[1], in[53]);
	vec_add(in[55], in[55], in[53]);
	vec_add(pre[0], pre[0], in[55]);
	vec_add(in[54], in[54], in[55]);
	vec_add(pre[2], pre[2], in[54]);
	vec_add(in[50], in[50], in[54]);
	vec_add(pre[0], pre[0], in[50]);
	vec_add(in[51], in[51], in[50]);
	vec_add(pre[1], pre[1], in[51]);
	vec_add(in[49], in[49], in[51]);
	vec_add(pre[0], pre[0], in[49]);
	vec_add(in[48], in[48], in[49]);
	vec_copy(pre[5], in[48]);
	vec_add(in[16], in[16], in[48]);
	vec_add(pre[0], pre[0], in[16]);
	vec_add(in[17], in[17], in[16]);
	vec_add(pre[1], pre[1], in[17]);
	vec_add(in[19], in[19], in[17]);
	vec_add(pre[0], pre[0], in[19]);
	vec_add(in[18], in[18], in[19]);
	vec_add(pre[2], pre[2], in[18]);
	vec_add(in[22], in[22], in[18]);
	vec_add(pre[0], pre[0], in[22]);
	vec_add(in[23], in[23], in[22]);
	vec_add(pre[1], pre[1], in[23]);
	vec_add(in[21], in[21], in[23]);
	vec_add(pre[0], pre[0], in[21]);
	vec_add(in[20], in[20], in[21]);
	vec_add(pre[3], pre[3], in[20]);
	vec_add(in[28], in[28], in[20]);
	vec_add(pre[0], pre[0], in[28]);
	vec_add(in[29], in[29], in[28]);
	vec_add(pre[1], pre[1], in[29]);
	vec_add(in[31], in[31], in[29]);
	vec_add(pre[0], pre[0], in[31]);
	vec_add(in[30], in[30], in[31]);
	vec_add(pre[2], pre[2], in[30]);
	vec_add(in[26], in[26], in[30]);
	vec_add(pre[0], pre[0], in[26]);
	vec_add(in[27], in[27], in[26]);
	vec_add(pre[1], pre[1], in[27]);
	vec_add(in[25], in[25], in[27]);
	vec_add(pre[0], pre[0], in[25]);
	vec_add(in[24], in[24], in[25]);
	vec_add(pre[4], pre[4], in[24]);
	vec_add(in[8], in[8], in[24]);
	vec_add(pre[0], pre[0], in[8]);
	vec_add(in[9], in[9], in[8]);
	vec_add(pre[1], pre[1], in[9]);
	vec_add(in[11], in[11], in[9]);
	vec_add(pre[0], pre[0], in[11]);
	vec_add(in[10], in[10], in[11]);
	vec_add(pre[2], pre[2], in[10]);
	vec_add(in[14], in[14], in[10]);
	vec_add(pre[0], pre[0], in[14]);
	vec_add(in[15], in[15], in[14]);
	vec_add(pre[1], pre[1], in[15]);
	vec_add(in[13], in[13], in[15]);
	vec_add(pre[0], pre[0], in[13]);
	vec_add(in[12], in[12], in[13]);
	vec_add(pre[3], pre[3], in[12]);
	vec_add(in[4], in[4], in[12]);
	vec_add(pre[0], pre[0], in[4]);
	vec_add(in[5], in[5], in[4]);
	vec_add(pre[1], pre[1], in[5]);
	vec_add(in[7], in[7], in[5]);
	vec_add(pre[0], pre[0], in[7]);
	vec_add(in[6], in[6], in[7]);
	vec_add(pre[2], pre[2], in[6]);
	vec_add(in[2], in[2], in[6]);
	vec_add(pre[0], pre[0], in[2]);
	vec_add(in[3], in[3], in[2]);
	vec_add(pre[1], pre[1], in[3]);
	vec_add(in[1], in[1], in[3]);

	vec_add(pre[0], pre[0], in[1]);
	vec_add(out[0], in[0], in[1]);

	//

	for (j = 0; j < GFBITS; j++) {
		tmp[j] = (beta[0] >> j) & 1;
		tmp[j] = -tmp[j];
	}

	vec_mul(out[1], pre[0], tmp);

	for (i = 1; i < 6; i++) {
		for (j = 0; j < GFBITS; j++) {
			tmp[j] = (beta[i] >> j) & 1;
			tmp[j] = -tmp[j];
		}

		vec_mul(tmp, pre[i], tmp);
		vec_add(out[1], out[1], tmp);
	}
}

static void fft_tr(uint64_t out[][GFBITS], uint64_t in[][GFBITS]) {
	butterflies_tr(out, in);
	radix_conversions_tr(out);
}
