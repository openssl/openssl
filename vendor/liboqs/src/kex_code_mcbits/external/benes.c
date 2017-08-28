static void func(uint64_t *bs, uint64_t *cond_ptr, int low) {
	int i, j, x, y;

	int high = 5 - low;

	uint64_t diff;

	//

	for (j = 0; j < (1 << low); j++) {
		x = (0 << low) + j;
		y = (1 << low) + j;

		for (i = 0; i < (1 << high); i++) {
			diff = bs[x] ^ bs[y];
			diff &= (*cond_ptr++);
			bs[x] ^= diff;
			bs[y] ^= diff;

			x += (1 << (low + 1));
			y += (1 << (low + 1));
		}
	}
}

static void benes_compact(uint64_t *bs, uint64_t *cond, int rev) {
	uint64_t *cond_ptr;
	int inc, low;

	//

	if (rev == 0) {
		inc = 32;
		cond_ptr = cond;
	} else {
		inc = -32;
		cond_ptr = &cond[704];
	}

	//

	for (low = 0; low <= 5; low++) {
		func(bs, cond_ptr, low);
		cond_ptr += inc;
	}

	transpose_64x64_compact(bs, bs);

	for (low = 0; low <= 5; low++) {
		func(bs, cond_ptr, low);
		cond_ptr += inc;
	}
	for (low = 4; low >= 0; low--) {
		func(bs, cond_ptr, low);
		cond_ptr += inc;
	}

	transpose_64x64_compact(bs, bs);

	for (low = 5; low >= 0; low--) {
		func(bs, cond_ptr, low);
		cond_ptr += inc;
	}
}
