#if defined(_WIN32)
#define strdup _strdup // for strdup deprecation warning
#endif

OQS_KEX *MACRIFY(OQS_KEX_lwe_frodo_new)(OQS_RAND *rand, const uint8_t *seed, const size_t seed_len, const char *named_parameters) {

	OQS_KEX *k;
	struct oqs_kex_lwe_frodo_params *params;

	if ((seed_len == 0) || (seed == NULL)) {
		return NULL;
	}

	k = malloc(sizeof(OQS_KEX));
	if (k == NULL) {
		goto err;
	}
	k->named_parameters = NULL;
	k->method_name = NULL;

	k->params = malloc(sizeof(struct oqs_kex_lwe_frodo_params));
	if (NULL == k->params) {
		goto err;
	}
	params = (struct oqs_kex_lwe_frodo_params *) k->params;
	params->cdf_table = NULL;
	params->seed = NULL;
	params->param_name = NULL;

	k->rand = rand;
	k->ctx = NULL;
	k->alice_priv_free = &OQS_KEX_lwe_frodo_alice_priv_free;
	k->free = &OQS_KEX_lwe_frodo_free;

	if (strcmp(named_parameters, "recommended") == 0) {

		k->alice_0 = &OQS_KEX_lwe_frodo_alice_0_recommended;
		k->bob = &OQS_KEX_lwe_frodo_bob_recommended;
		k->alice_1 = &OQS_KEX_lwe_frodo_alice_1_recommended;

		k->method_name = strdup("LWE Frodo recommended");
		if (NULL == k->method_name) {
			goto err;
		}
		k->estimated_classical_security = 144;
		k->estimated_quantum_security = 130;
		k->named_parameters = strdup(named_parameters);
		if (k->named_parameters == NULL) {
			goto err;
		}

		params->seed = malloc(seed_len);
		if (NULL == params->seed) {
			goto err;
		}
		memcpy(params->seed, seed, seed_len);
		params->seed_len = seed_len;
		params->param_name = strdup("recommended");
		if (NULL == params->param_name) {
			goto err;
		}
		params->log2_q = PARAMS_LOG2Q;
		params->q = PARAMS_Q;
		params->n = PARAMS_N;
		params->extracted_bits = PARAMS_EXTRACTED_BITS;
		params->nbar = PARAMS_NBAR;
		params->key_bits = PARAMS_KEY_BITS;
		params->rec_hint_len = PARAMS_REC_HINT_LENGTH;
		params->pub_len = PARAMS_REC_PUB_LENGTH;
		params->stripe_step = PARAMS_STRIPE_STEP;
		params->sampler_num = 12;
		params->cdf_table_len = 6;
		params->cdf_table = malloc(params->cdf_table_len * sizeof(uint16_t));
		if (NULL == params->cdf_table) {
			goto err;
		}
		uint16_t cdf_table_tmp[6] = {602, 1521, 1927, 2031, 2046, 2047};
		memcpy(params->cdf_table, cdf_table_tmp, sizeof(cdf_table_tmp));
	} else {
		goto err;
	}
	return k;
err:
	OQS_KEX_lwe_frodo_free(k);
	return NULL;
}

OQS_STATUS MACRIFY(OQS_KEX_lwe_frodo_alice_0)(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len) {

	OQS_STATUS ret;

	struct oqs_kex_lwe_frodo_params *params = (struct oqs_kex_lwe_frodo_params *) k->params;

	*alice_priv = NULL;
	*alice_msg = NULL;

	/* allocate private key, error, and outgoing message */
	*alice_priv = malloc(PARAMS_N * PARAMS_NBAR * sizeof(uint16_t));
	if (*alice_priv == NULL) {
		goto err;
	}
	uint16_t b[PARAMS_N * PARAMS_NBAR];
	uint16_t e[PARAMS_N * PARAMS_NBAR];

	*alice_msg = malloc(PARAMS_REC_PUB_LENGTH);
	*alice_msg_len = PARAMS_REC_PUB_LENGTH;
	if (*alice_msg == NULL) {
		goto err;
	}

	/* generate S and E */
	oqs_kex_lwe_frodo_sample_n(*alice_priv, PARAMS_N * PARAMS_NBAR, params, k->rand);
	oqs_kex_lwe_frodo_sample_n(e, PARAMS_N * PARAMS_NBAR, params, k->rand);

	/* compute B = AS + E */
	MACRIFY(oqs_kex_lwe_frodo_mul_add_as_plus_e_on_the_fly)
	(b, *alice_priv, e, params);

	oqs_kex_lwe_frodo_pack(*alice_msg, PARAMS_REC_PUB_LENGTH, b, PARAMS_N * PARAMS_NBAR, PARAMS_LOG2Q);

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	OQS_MEM_cleanse(e, sizeof(e));
	free(*alice_msg);
	*alice_msg = NULL;
	free(*alice_priv);
	*alice_priv = NULL;
	ret = OQS_ERROR;

cleanup:
	return ret;
}

OQS_STATUS MACRIFY(OQS_KEX_lwe_frodo_bob)(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len) {

	OQS_STATUS ret;

	struct oqs_kex_lwe_frodo_params *params = (struct oqs_kex_lwe_frodo_params *) k->params;

	uint8_t *bob_rec = NULL;
	*bob_msg = NULL;
	*key = NULL;

	/* check length of other party's public key */
	if (alice_msg_len != PARAMS_REC_PUB_LENGTH) {
		goto err;
	}

	/* allocate private key, errors, outgoing message, and key */
	uint16_t bob_priv[PARAMS_N * PARAMS_NBAR];
	uint16_t bprime[PARAMS_N * PARAMS_NBAR];
	uint16_t eprime[PARAMS_N * PARAMS_NBAR];
	uint16_t eprimeprime[PARAMS_N * PARAMS_NBAR];
	uint16_t b[PARAMS_N * PARAMS_NBAR];
	uint16_t v[PARAMS_N * PARAMS_NBAR];
	*bob_msg = malloc(PARAMS_REC_PUB_LENGTH + PARAMS_REC_HINT_LENGTH);
	if (*bob_msg == NULL) {
		goto err;
	}
	bob_rec = *bob_msg + PARAMS_REC_PUB_LENGTH;
	*key = malloc(PARAMS_KEY_BYTES);
	if (*key == NULL) {
		goto err;
	}

	/* generate S' and E' */
	oqs_kex_lwe_frodo_sample_n(bob_priv, PARAMS_N * PARAMS_NBAR, params, k->rand);
	oqs_kex_lwe_frodo_sample_n(eprime, PARAMS_N * PARAMS_NBAR, params, k->rand);

	/* compute B' = S'A + E' */
	MACRIFY(oqs_kex_lwe_frodo_mul_add_sa_plus_e_on_the_fly)
	(bprime, bob_priv, eprime, params);

	oqs_kex_lwe_frodo_pack(*bob_msg, PARAMS_REC_PUB_LENGTH, bprime, PARAMS_N * PARAMS_NBAR, PARAMS_LOG2Q);

	/* generate E'' */
	oqs_kex_lwe_frodo_sample_n(eprimeprime, PARAMS_NBAR * PARAMS_NBAR, params, k->rand);

	/* unpack B */
	oqs_kex_lwe_frodo_unpack(b, PARAMS_N * PARAMS_NBAR, alice_msg, alice_msg_len, PARAMS_LOG2Q);

	/* compute V = S'B + E'' */
	MACRIFY(oqs_kex_lwe_frodo_mul_add_sb_plus_e)
	(v, b, bob_priv, eprimeprime);

	/* compute C = <V>_{2^B} */
	MACRIFY(oqs_kex_lwe_frodo_crossround2)
	(bob_rec, v);

	/* compute K = round(V)_{2^B} */
	MACRIFY(oqs_kex_lwe_frodo_round2)
	(*key, v);

	*bob_msg_len = PARAMS_REC_PUB_LENGTH + PARAMS_REC_HINT_LENGTH;
	*key_len = PARAMS_KEY_BYTES;

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;
	free(*bob_msg);
	*bob_msg = NULL;
	OQS_MEM_secure_free(*key, PARAMS_KEY_BYTES);
	*key = NULL;

cleanup:
	OQS_MEM_cleanse(eprime, sizeof(eprime));
	OQS_MEM_cleanse(eprimeprime, sizeof(eprimeprime));
	OQS_MEM_cleanse(v, sizeof(v));

	return ret;
}

OQS_STATUS MACRIFY(OQS_KEX_lwe_frodo_alice_1)(UNUSED OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) {

	OQS_STATUS ret;
	*key = NULL;

	/* check length of other party's public key */
	if (bob_msg_len != PARAMS_REC_PUB_LENGTH + PARAMS_REC_HINT_LENGTH) {
		goto err;
	}

	/* allocate working values and session key */
	uint16_t bprime[PARAMS_N * PARAMS_NBAR];
	uint16_t w[PARAMS_N * PARAMS_NBAR];

	*key = malloc(PARAMS_KEY_BYTES);
	if (*key == NULL) {
		goto err;
	}

	/* unpack B' */
	oqs_kex_lwe_frodo_unpack(bprime, PARAMS_N * PARAMS_NBAR, bob_msg, PARAMS_REC_PUB_LENGTH, PARAMS_LOG2Q);

	/* compute W = B'S */
	MACRIFY(oqs_kex_lwe_frodo_mul_bs)
	(w, bprime, (uint16_t *) alice_priv);

	/* compute K = rec(B'S, C) */
	const uint8_t *bob_rec = bob_msg + PARAMS_REC_PUB_LENGTH;
	MACRIFY(oqs_kex_lwe_frodo_reconcile)
	(*key, w, bob_rec);

	*key_len = PARAMS_KEY_BYTES;

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;
	OQS_MEM_secure_free(*key, PARAMS_KEY_BYTES);
	*key = NULL;

cleanup:
	return ret;
}
