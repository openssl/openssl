#include "params.h"

static uint16_t bitrev_table[KYBER_N] = {
    0, 128, 64, 192, 32, 160, 96, 224, 16, 144, 80, 208, 48, 176, 112, 240,
    8, 136, 72, 200, 40, 168, 104, 232, 24, 152, 88, 216, 56, 184, 120, 248,
    4, 132, 68, 196, 36, 164, 100, 228, 20, 148, 84, 212, 52, 180, 116, 244,
    12, 140, 76, 204, 44, 172, 108, 236, 28, 156, 92, 220, 60, 188, 124, 252,
    2, 130, 66, 194, 34, 162, 98, 226, 18, 146, 82, 210, 50, 178, 114, 242,
    10, 138, 74, 202, 42, 170, 106, 234, 26, 154, 90, 218, 58, 186, 122, 250,
    6, 134, 70, 198, 38, 166, 102, 230, 22, 150, 86, 214, 54, 182, 118, 246,
    14, 142, 78, 206, 46, 174, 110, 238, 30, 158, 94, 222, 62, 190, 126, 254,
    1, 129, 65, 193, 33, 161, 97, 225, 17, 145, 81, 209, 49, 177, 113, 241,
    9, 137, 73, 201, 41, 169, 105, 233, 25, 153, 89, 217, 57, 185, 121, 249,
    5, 133, 69, 197, 37, 165, 101, 229, 21, 149, 85, 213, 53, 181, 117, 245,
    13, 141, 77, 205, 45, 173, 109, 237, 29, 157, 93, 221, 61, 189, 125, 253,
    3, 131, 67, 195, 35, 163, 99, 227, 19, 147, 83, 211, 51, 179, 115, 243,
    11, 139, 75, 203, 43, 171, 107, 235, 27, 155, 91, 219, 59, 187, 123, 251,
    7, 135, 71, 199, 39, 167, 103, 231, 23, 151, 87, 215, 55, 183, 119, 247,
    15, 143, 79, 207, 47, 175, 111, 239, 31, 159, 95, 223, 63, 191, 127, 255,
};

static void bitrev_vector(uint16_t *poly) {
	unsigned int i, r;
	uint16_t tmp;

	for (i = 0; i < KYBER_N; i++) {
		r = bitrev_table[i];
		if (i < r) {
			tmp = poly[i];
			poly[i] = poly[r];
			poly[r] = tmp;
		}
	}
}

static void mul_coefficients(uint16_t *poly, const uint16_t *factors) {
	unsigned int i;

	for (i = 0; i < KYBER_N; i++)
		poly[i] = montgomery_reduce((poly[i] * factors[i]));
}

/* GS_bo_to_no; omegas need to be in Montgomery domain */
static void ntt(uint16_t *a, const uint16_t *omega) {
	int start, j, jTwiddle, level;
	uint16_t temp, W;
	uint32_t t;

	for (level = 0; level < 8; level++) {
		for (start = 0; start < (1 << level); start++) {
			jTwiddle = 0;
			for (j = start; j < KYBER_N - 1; j += 2 * (1 << level)) {
				W = omega[jTwiddle++];
				temp = a[j];

				if (level & 1) // odd level
					a[j] = barrett_reduce((temp + a[j + (1 << level)]));
				else
					a[j] = (temp + a[j + (1 << level)]); // Omit reduction (be lazy)

				t = (W * ((uint32_t) temp + 4 * KYBER_Q - a[j + (1 << level)]));

				a[j + (1 << level)] = montgomery_reduce(t);
			}
		}
	}
}
