static int pk_gen(unsigned char *pk, const unsigned char *sk) {
	unsigned char *pk_ptr = pk;

	int i, j, k;
	int row, c, tail;

	uint64_t mat[GFBITS * SYS_T][64];
	uint64_t mask;
	uint64_t u;

	uint64_t points[64][GFBITS] = {
#include "points.data"
	};

	uint64_t sk_int[GFBITS];

	uint64_t eval[64][GFBITS];
	uint64_t inv[64][GFBITS];
	uint64_t tmp[GFBITS];

	uint64_t cond[COND_BYTES / 8];

	// compute the inverses

	for (i = 0; i < GFBITS; i++)
		sk_int[i] = load8(sk + i * 8);

	fft(eval, sk_int);

	vec_copy(inv[0], eval[0]);

	for (i = 1; i < 64; i++)
		vec_mul(inv[i], inv[i - 1], eval[i]);

	vec_inv(tmp, inv[63]);

	for (i = 62; i >= 0; i--) {
		vec_mul(inv[i + 1], tmp, inv[i]);
		vec_mul(tmp, tmp, eval[i + 1]);
	}

	vec_copy(inv[0], tmp);

	// fill matrix

	for (j = 0; j < 64; j++)
		for (k = 0; k < GFBITS; k++)
			mat[k][j] = inv[j][k];

	for (i = 1; i < SYS_T; i++)
		for (j = 0; j < 64; j++) {
			vec_mul(inv[j], inv[j], points[j]);

			for (k = 0; k < GFBITS; k++)
				mat[i * GFBITS + k][j] = inv[j][k];
		}

	// permute

	for (i = 0; i < COND_BYTES / 8; i++)
		cond[i] = load8(sk + IRR_BYTES + i * 8);

	for (i = 0; i < GFBITS * SYS_T; i++)
		benes_compact(mat[i], cond, 0);

	// gaussian elimination

	for (i = 0; i < (GFBITS * SYS_T + 63) / 64; i++)
		for (j = 0; j < 64; j++) {
			row = i * 64 + j;

			if (row >= GFBITS * SYS_T)
				break;

			for (k = row + 1; k < GFBITS * SYS_T; k++) {
				mask = mat[row][i] ^ mat[k][i];
				mask >>= j;
				mask &= 1;
				mask = -mask;

				for (c = 0; c < 64; c++)
					mat[row][c] ^= mat[k][c] & mask;
			}

			if (((mat[row][i] >> j) & 1) == 0) { // return if not invertible
				return -1;
			}

			for (k = 0; k < GFBITS * SYS_T; k++) {
				if (k != row) {
					mask = mat[k][i] >> j;
					mask &= 1;
					mask = -mask;

					for (c = 0; c < 64; c++)
						mat[k][c] ^= mat[row][c] & mask;
				}
			}
		}

	// store pk

	tail = ((GFBITS * SYS_T) & 63) >> 3;

	for (i = 0; i < GFBITS * SYS_T; i++) {
		u = mat[i][(GFBITS * SYS_T + 63) / 64 - 1];

		for (k = tail; k < 8; k++)
			pk_ptr[k - tail] = (u >> (8 * k)) & 0xFF;

		pk_ptr += 8 - tail;

		for (j = (GFBITS * SYS_T + 63) / 64; j < 64; j++) {
			store8(pk_ptr, mat[i][j]);

			pk_ptr += 8;
		}
	}

	return 0;
}
