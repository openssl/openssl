// [.]_2
void MACRIFY(oqs_kex_lwe_frodo_round2)(unsigned char *out, uint16_t *in) {
	oqs_kex_lwe_frodo_key_round(in, PARAMS_NBAR * PARAMS_NBAR, PARAMS_LOG2Q - PARAMS_EXTRACTED_BITS);
	for (int i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
		in[i] >>= PARAMS_LOG2Q - PARAMS_EXTRACTED_BITS; // drop bits that were zeroed out
	}

	// out should have enough space for the key
	oqs_kex_lwe_frodo_pack(out, PARAMS_KEY_BITS / 8, in, PARAMS_NBAR * PARAMS_NBAR, PARAMS_EXTRACTED_BITS);
}

void MACRIFY(oqs_kex_lwe_frodo_crossround2)(unsigned char *out, const uint16_t *in) {
	// out should have enough space for N_BAR * N_BAR bits
	memset((unsigned char *) out, 0, PARAMS_REC_HINT_LENGTH);

	uint16_t whole = 1 << (PARAMS_LOG2Q - PARAMS_EXTRACTED_BITS);
	uint16_t half = whole >> 1;
	uint16_t mask = whole - 1;

	for (int i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
		uint16_t remainder = in[i] & mask;
		out[i / 8] += (remainder >= half) << (i % 8);
	}
}

void MACRIFY(oqs_kex_lwe_frodo_reconcile)(unsigned char *out, uint16_t *w, const unsigned char *hint) {
	oqs_kex_lwe_frodo_key_round_hints(w, PARAMS_NBAR * PARAMS_NBAR, PARAMS_LOG2Q - PARAMS_EXTRACTED_BITS, hint);
	for (int i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
		w[i] >>= PARAMS_LOG2Q - PARAMS_EXTRACTED_BITS; // drop bits that were zeroed out
	}
	oqs_kex_lwe_frodo_pack(out, PARAMS_KEY_BITS / 8, w, PARAMS_NBAR * PARAMS_NBAR, PARAMS_EXTRACTED_BITS);
}

// Generate-and-multiply: generate A row-wise, multiply by s on the right.
void MACRIFY(oqs_kex_lwe_frodo_mul_add_as_plus_e_on_the_fly)(uint16_t *out, const uint16_t *s, const uint16_t *e, struct oqs_kex_lwe_frodo_params *params) {
	// A (N x N)
	// s,e (N x N_BAR)
	// out = A * s + e (N x N_BAR)

	memcpy(out, e, PARAMS_NBAR * PARAMS_N * sizeof(uint16_t));

	// transpose s to store it in the column-major order
	uint16_t s_transpose[PARAMS_NBAR * PARAMS_N];
	for (int j = 0; j < PARAMS_N; j++) {
		for (int k = 0; k < PARAMS_NBAR; k++) {
			s_transpose[k * PARAMS_N + j] = s[j * PARAMS_NBAR + k];
		}
	}

	assert(params->seed_len == 16);
	void *aes_key_schedule = NULL;
	OQS_AES128_load_schedule(params->seed, &aes_key_schedule, 1);

	for (int i = 0; i < PARAMS_N; i++) {
		uint16_t a_row[PARAMS_N] = {0};
		// go through A's rows
		for (int j = 0; j < PARAMS_N; j += PARAMS_STRIPE_STEP) {
			// Loading values in the little-endian order!
			a_row[j] = i;
			a_row[j + 1] = j;
		}

		OQS_AES128_ECB_enc_sch((uint8_t *) a_row, sizeof(a_row), aes_key_schedule, (uint8_t *) a_row);

		for (int k = 0; k < PARAMS_NBAR; k++) {
			uint16_t sum = 0;
			for (int j = 0; j < PARAMS_N; j++) {
				// matrix-vector multiplication happens here
				sum += a_row[j] * s_transpose[k * PARAMS_N + j];
			}
			out[i * PARAMS_NBAR + k] += sum;
			//Equivalent to %= PARAMS_Q if PARAMS_Q is a power of 2
			out[i * PARAMS_NBAR + k] &= PARAMS_Q - 1;
		}
	}

	OQS_AES128_free_schedule(aes_key_schedule);
}

// Generate-and-multiply: generate A column-wise, multiply by s' on the left.
void MACRIFY(oqs_kex_lwe_frodo_mul_add_sa_plus_e_on_the_fly)(uint16_t *out, const uint16_t *s, const uint16_t *e, struct oqs_kex_lwe_frodo_params *params) {
	// a (N x N)
	// s',e' (N_BAR x N)
	// out = s'a + e' (N_BAR x N)

	memcpy(out, e, PARAMS_NBAR * PARAMS_N * sizeof(uint16_t));

	assert(params->seed_len == 16);

	void *aes_key_schedule = NULL;
	OQS_AES128_load_schedule(params->seed, &aes_key_schedule, 1);

	for (int kk = 0; kk < PARAMS_N; kk += PARAMS_STRIPE_STEP) {
		// Go through A's columns, 8 (== PARAMS_STRIPE_STEP) columns at a time.
		// a_cols stores 8 columns of A at a time.
		uint16_t a_cols[PARAMS_N * PARAMS_STRIPE_STEP] = {0};
		for (int i = 0; i < PARAMS_N; i++) {
			// Loading values in the little-endian order!
			a_cols[i * PARAMS_STRIPE_STEP] = i;
			a_cols[i * PARAMS_STRIPE_STEP + 1] = kk;
		}

		OQS_AES128_ECB_enc_sch((uint8_t *) a_cols, sizeof(a_cols), aes_key_schedule, (uint8_t *) a_cols);

		// transpose a_cols to have access to it in the column-major order.
		uint16_t a_cols_t[PARAMS_N * PARAMS_STRIPE_STEP];
		for (int i = 0; i < PARAMS_N; i++) {
			for (int k = 0; k < PARAMS_STRIPE_STEP; k++) {
				a_cols_t[k * PARAMS_N + i] = a_cols[i * PARAMS_STRIPE_STEP + k];
			}
		}

		for (int i = 0; i < PARAMS_NBAR; i++) {
			for (int k = 0; k < PARAMS_STRIPE_STEP; k++) {
				uint16_t sum = 0;
				for (int j = 0; j < PARAMS_N; j++) {
					sum += s[i * PARAMS_N + j] * a_cols_t[k * PARAMS_N + j];
				}
				out[i * PARAMS_N + kk + k] += sum;
				out[i * PARAMS_N + kk + k] &= PARAMS_Q - 1; //Works as long as PARAMS_Q is a power of 2
			}
		}
	}
	OQS_AES128_free_schedule(aes_key_schedule);
}

// multiply by s on the right
void MACRIFY(oqs_kex_lwe_frodo_mul_bs)(uint16_t *out, const uint16_t *b, const uint16_t *s) {
	// b (N_BAR x N)
	// s (N x N_BAR)
	// out = bs
	for (int i = 0; i < PARAMS_NBAR; i++) {
		for (int j = 0; j < PARAMS_NBAR; j++) {
			uint16_t sum = 0;
			for (int k = 0; k < PARAMS_N; k++) {
				sum += b[i * PARAMS_N + k] * s[k * PARAMS_NBAR + j];
			}
			out[i * PARAMS_NBAR + j] = sum & (PARAMS_Q - 1);
		}
	}
}

// multiply by s on the left
void MACRIFY(oqs_kex_lwe_frodo_mul_add_sb_plus_e)(uint16_t *out, const uint16_t *b, const uint16_t *s, const uint16_t *e) {
	// b (N x N_BAR)
	// s (N_BAR x N)
	// e (N_BAR x N_BAR)
	// out = sb + e
	memcpy(out, e, PARAMS_NBAR * PARAMS_NBAR * sizeof(uint16_t));
	for (int k = 0; k < PARAMS_NBAR; k++) {
		for (int i = 0; i < PARAMS_NBAR; i++) {
			uint16_t sum = 0;
			for (int j = 0; j < PARAMS_N; j++) {
				sum += s[k * PARAMS_N + j] * b[j * PARAMS_NBAR + i];
			}
			out[k * PARAMS_NBAR + i] += sum;
			out[k * PARAMS_NBAR + i] &= PARAMS_Q - 1; // not really necessary since LWE_Q is a power of 2.
		}
	}
}
