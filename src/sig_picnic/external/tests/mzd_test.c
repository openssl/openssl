#include "../mzd_additional.h"
#include <m4ri/m4ri.h>

#include "utils.c.i"

static void test_mzd_local_equal(void) {
  for (unsigned int i = 0; i < 10; ++i) {
    mzd_local_t* a = oqs_sig_picnic_mzd_local_init(1, (i + 1) * 64);
    mzd_randomize_ssl(a);
    mzd_local_t* b = oqs_sig_picnic_mzd_local_copy(NULL, a);

    if (oqs_sig_picnic_mzd_local_equal(a, b)) {
      printf("equal: ok [%u]\n", (i + 1) * 64);
    }

    b = oqs_sig_picnic_mzd_xor(b, b, a);
    if (oqs_sig_picnic_mzd_local_equal(a, b)) {
      printf("equal: ok [%u]\n", (i + 1) * 64);
    }

    oqs_sig_picnic_mzd_local_free(a);
    oqs_sig_picnic_mzd_local_free(b);
  }
}

static int test_mzd_mul_avx(void) {
  int ret = 0;

#ifdef WITH_AVX2

  unsigned int size = 192;
  mzd_t* A    = mzd_init(size, size);
  mzd_t* v    = mzd_init(1, size);
  mzd_t* c    = mzd_init(1, size);

  mzd_randomize(A);
  mzd_randomize(v);
  mzd_randomize(c);

  mzd_local_t* Al = mzd_convert(A);
  mzd_local_t* vl = mzd_convert(v);
  mzd_local_t* c2 = mzd_convert(c);

  for (unsigned int k = 0; k < 3; ++k) {

    mzd_t* r  = mzd_mul_naive(c, v, A);
    mzd_local_t* rl = oqs_sig_picnic_mzd_mul_v_avx(c2, vl, Al);

    mzd_local_t* rc = mzd_convert(r);

    if (!oqs_sig_picnic_mzd_local_equal(rc, rl)) {
      printf("mul: fail [%u x %u]\n", size, size);
      ret = -1;
    } else {
      printf("mul: ok [%u x %u]\n", size, size);
    }

    oqs_sig_picnic_mzd_local_free(rc);
  }

  mzd_free(A);
  mzd_free(v);
  mzd_free(c);

  oqs_sig_picnic_mzd_local_free(c2);
  oqs_sig_picnic_mzd_local_free(Al);
  oqs_sig_picnic_mzd_local_free(vl);
#endif

  return ret;
}

#ifdef WITH_NEON
static void test_mzd_mul_vl_neon_192(void) {

  unsigned int size = 192;
  mzd_local_t* A    = mzd_init(size, size);
  mzd_local_t* v    = mzd_init(1, size);
  mzd_local_t* c    = mzd_init(1, size);

  mzd_randomize(A);
  mzd_randomize(v);
  mzd_randomize(c);

  mzd_local_t* Al  = oqs_sig_picnic_mzd_local_copy(NULL, A);
  mzd_local_t* All = oqs_sig_picnic_mzd_precompute_matrix_lookup(Al);
  mzd_local_t* vl  = oqs_sig_picnic_mzd_local_copy(NULL, v);

  mzd_local_t* c2 = oqs_sig_picnic_mzd_local_copy(NULL, c);

  for (unsigned int k = 0; k < 3; ++k) {

    mzd_local_t* r  = mzd_mul_naive(c, v, A);
    mzd_local_t* rl = mzd_mul_vl_neon_multiple_of_128(c2, vl, All);

    if (!oqs_sig_picnic_mzd_local_equal(r, rl)) {
      printf("mul: fail [%u x %u]\n", size, size);
      printf("r =  ");
      mzd_print(r);
      printf("rl = ");
      mzd_print(rl);
    } else {
      printf("mul: ok [%u x %u]\n", size, size);
    }
  }

  mzd_free(A);
  mzd_free(v);
  mzd_free(c);

  oqs_sig_picnic_mzd_local_free(c2);
  oqs_sig_picnic_mzd_local_free(Al);
  oqs_sig_picnic_mzd_local_free(vl);
}

static void test_mzd_mul_vl_neon_256(void) {

  unsigned int size = 256;
  mzd_local_t* A    = mzd_init(size, size);
  mzd_local_t* v    = mzd_init(1, size);
  mzd_local_t* c    = mzd_init(1, size);

  mzd_randomize(A);
  mzd_randomize(v);
  mzd_randomize(c);

  mzd_local_t* Al  = oqs_sig_picnic_mzd_local_copy(NULL, A);
  mzd_local_t* All = oqs_sig_picnic_mzd_precompute_matrix_lookup(Al);
  mzd_local_t* vl  = oqs_sig_picnic_mzd_local_copy(NULL, v);

  mzd_local_t* c2 = oqs_sig_picnic_mzd_local_copy(NULL, c);

  for (unsigned int k = 0; k < 3; ++k) {

    mzd_local_t* r  = mzd_mul_naive(c, v, A);
    mzd_local_t* rl = mzd_mul_vl_neon_multiple_of_128(c2, vl, All);

    if (!oqs_sig_picnic_mzd_local_equal(r, rl)) {
      printf("mul: fail [%u x %u]\n", size, size);
      printf("r =  ");
      mzd_print(r);
      printf("rl = ");
      mzd_print(rl);
    } else {
      printf("mul: ok [%u x %u]\n", size, size);
    }
  }

  mzd_free(A);
  mzd_free(v);
  mzd_free(c);

  oqs_sig_picnic_mzd_local_free(c2);
  oqs_sig_picnic_mzd_local_free(Al);
  oqs_sig_picnic_mzd_local_free(vl);
}

static void test_mzd_addmul_vl_neon_192(void) {

  unsigned int size = 192;
  mzd_local_t* A    = mzd_init(size, size);
  mzd_local_t* v    = mzd_init(1, size);
  mzd_local_t* c    = mzd_init(1, size);

  mzd_randomize(A);
  mzd_randomize(v);
  mzd_randomize(c);

  mzd_local_t* Al  = oqs_sig_picnic_mzd_local_copy(NULL, A);
  mzd_local_t* All = oqs_sig_picnic_mzd_precompute_matrix_lookup(Al);
  mzd_local_t* vl  = oqs_sig_picnic_mzd_local_copy(NULL, v);

  mzd_local_t* c2 = oqs_sig_picnic_mzd_local_copy(NULL, c);
  mzd_local_t* c3 = oqs_sig_picnic_mzd_local_copy(NULL, c);

  for (unsigned int k = 0; k < 3; ++k) {

    mzd_local_t* r   = mzd_addmul_naive(c, v, A);
    mzd_local_t* rl2 = mzd_addmul_vl_neon(c3, vl, All);

    if (!oqs_sig_picnic_mzd_local_equal(r, rl2)) {
      printf("addmul2: fail [%u x %u]\n", size, size);
      printf("r =  ");
      mzd_print(r);
      printf("rl = ");
      mzd_print(rl2);
    } else {
      printf("addmul2: ok [%u x %u]\n", size, size);
    }
  }

  mzd_free(A);
  mzd_free(v);
  mzd_free(c);

  oqs_sig_picnic_mzd_local_free(c2);
  oqs_sig_picnic_mzd_local_free(Al);
  oqs_sig_picnic_mzd_local_free(vl);
}

static void test_mzd_addmul_vl_neon_256(void) {

  unsigned int size = 256;
  mzd_local_t* A    = mzd_init(size, size);
  mzd_local_t* v    = mzd_init(1, size);
  mzd_local_t* c    = mzd_init(1, size);

  mzd_randomize(A);
  mzd_randomize(v);
  mzd_randomize(c);

  mzd_local_t* Al  = oqs_sig_picnic_mzd_local_copy(NULL, A);
  mzd_local_t* All = oqs_sig_picnic_mzd_precompute_matrix_lookup(Al);
  mzd_local_t* vl  = oqs_sig_picnic_mzd_local_copy(NULL, v);

  mzd_local_t* c2 = oqs_sig_picnic_mzd_local_copy(NULL, c);
  mzd_local_t* c3 = oqs_sig_picnic_mzd_local_copy(NULL, c);

  for (unsigned int k = 0; k < 3; ++k) {

    mzd_local_t* r   = mzd_addmul_naive(c, v, A);
    mzd_local_t* rl2 = mzd_addmul_vl_neon(c3, vl, All);

    if (!oqs_sig_picnic_mzd_local_equal(r, rl2)) {
      printf("addmul2: fail [%u x %u]\n", size, size);
      printf("r =  ");
      mzd_print(r);
      printf("rl = ");
      mzd_print(rl2);
    } else {
      printf("addmul2: ok [%u x %u]\n", size, size);
    }
  }

  mzd_free(A);
  mzd_free(v);
  mzd_free(c);

  oqs_sig_picnic_mzd_local_free(c2);
  oqs_sig_picnic_mzd_local_free(Al);
  oqs_sig_picnic_mzd_local_free(vl);
}

#endif

static void test_mzd_mul(void) {
  for (unsigned int i = 1; i <= 10; ++i) {
    for (unsigned int j = 1; j <= 10; ++j) {
      mzd_t* A = mzd_init(i * 64, j * 64);
      mzd_t* v = mzd_init(1, i * 64);
      mzd_t* c = mzd_init(1, j * 64);

      mzd_randomize(A);
      mzd_randomize(v);
      mzd_randomize(c);

      mzd_local_t* Al  = mzd_convert(A);
      mzd_local_t* All = oqs_sig_picnic_mzd_precompute_matrix_lookup(Al);
      mzd_local_t* vl  = mzd_convert(v);
      mzd_local_t* cl  = mzd_convert(c);
      mzd_local_t* cll = mzd_convert(c);

      mzd_t* At = mzd_transpose(NULL, A);
      mzd_t* vt = mzd_transpose(NULL, v);
      mzd_t* c2 = mzd_copy(NULL, c);
      mzd_t* c3 = mzd_transpose(NULL, c);

      for (unsigned int k = 0; k < 3; ++k) {
        mzd_local_t* r  = oqs_sig_picnic_mzd_mul_v(cl, vl, Al);
        mzd_local_t* rl = oqs_sig_picnic_mzd_mul_vl(cll, vl, All);
        mzd_t* r2 = mzd_mul(c2, v, A, __M4RI_STRASSEN_MUL_CUTOFF);
        mzd_t* r3 = mzd_mul(c3, At, vt, __M4RI_STRASSEN_MUL_CUTOFF);

        if (!oqs_sig_picnic_mzd_local_equal(r, rl)) {
          printf("mul: fail [%u x %u]\n", i * 64, j * 64);
        }

        mzd_local_t* rc = mzd_convert(r2);
        if (!oqs_sig_picnic_mzd_local_equal(r, rc)) {
          printf("mul: fail [%u x %u]\n", i * 64, j * 64);
        }
        oqs_sig_picnic_mzd_local_free(rc);

        mzd_t* r4 = mzd_transpose(NULL, r3);
        if (mzd_cmp(r4, r2) != 0) {
          printf("mul: fail [%u x %u]\n", i * 64, j * 64);
        }
        mzd_free(r4);
      }

      mzd_free(At);
      mzd_free(A);
      mzd_free(v);
      mzd_free(c);

      mzd_free(vt);
      mzd_free(c2);
      mzd_free(c3);

      oqs_sig_picnic_mzd_local_free(All);
      oqs_sig_picnic_mzd_local_free(Al);
      oqs_sig_picnic_mzd_local_free(cll);
      oqs_sig_picnic_mzd_local_free(cl);
      oqs_sig_picnic_mzd_local_free(vl);
    }
  }
}

static void test_mzd_shift(void) {
#ifdef WITH_OPT
#ifdef WITH_SSE2
  if (CPU_SUPPORTS_SSE2) {
    mzd_local_t* v = oqs_sig_picnic_mzd_local_init(1, 128);
    mzd_local_t* w = oqs_sig_picnic_mzd_local_copy(NULL, v);
    mzd_local_t* r = oqs_sig_picnic_mzd_local_copy(NULL, v);
    __m128i* wr    = __builtin_assume_aligned(FIRST_ROW(w), 16);

    for (unsigned int i = 0; i < 32; ++i) {
      mzd_randomize_ssl(v);
      oqs_sig_picnic_mzd_local_copy(w, v);

      mzd_shift_left(r, v, i);
      *wr = mm128_shift_left(*wr, i);

      if (mzd_cmp(r, w) != 0) {
        printf("lshift fail\n");
      }
    }

    for (unsigned int i = 0; i < 32; ++i) {
      mzd_randomize_ssl(v);
      oqs_sig_picnic_mzd_local_copy(w, v);

      mzd_shift_right(r, v, i);
      *wr = mm128_shift_right(*wr, i);

      if (mzd_cmp(r, w) != 0) {
        printf("rshift fail\n");
      }
    }

    oqs_sig_picnic_mzd_local_free(w);
    oqs_sig_picnic_mzd_local_free(v);
    oqs_sig_picnic_mzd_local_free(r);
  }
#endif
#ifdef WITH_AVX2
  if (CPU_SUPPORTS_AVX2) {
    mzd_local_t* v = oqs_sig_picnic_mzd_local_init(1, 256);
    mzd_local_t* w = oqs_sig_picnic_mzd_local_copy(NULL, v);
    mzd_local_t* r = oqs_sig_picnic_mzd_local_copy(NULL, v);
    __m256i* wr    = __builtin_assume_aligned(FIRST_ROW(w), 32);

    for (unsigned int i = 0; i < 32; ++i) {
      mzd_randomize_ssl(v);
      oqs_sig_picnic_mzd_local_copy(w, v);

      mzd_shift_left(r, v, i);
      *wr = mm256_shift_left(*wr, i);

      if (mzd_cmp(r, w) != 0) {
        printf("lshift fail\n");
      }
    }

    for (unsigned int i = 0; i < 32; ++i) {
      mzd_randomize_ssl(v);
      oqs_sig_picnic_mzd_local_copy(w, v);

      mzd_shift_right(r, v, i);
      mm512_shift_right_avx(wr, wr, i);

      if (mzd_cmp(r, w) != 0) {
        printf("rshift fail\n");
      }
    }

    oqs_sig_picnic_mzd_local_free(w);
    oqs_sig_picnic_mzd_local_free(v);
    oqs_sig_picnic_mzd_local_free(r);
  }
#endif
#ifdef WITH_NEON
  if (CPU_SUPPORTS_NEON) {
    mzd_local_t* v = oqs_sig_picnic_mzd_local_init(1, 384);
    mzd_local_t* w = oqs_sig_picnic_mzd_local_copy(NULL, v);
    mzd_local_t* r = oqs_sig_picnic_mzd_local_copy(NULL, v);
    uint32x4_t* wr = __builtin_assume_aligned(FIRST_ROW(w), alignof(uint32x4_t));

    for (unsigned int i = 0; i < 32; ++i) {
      mzd_randomize_ssl(v);
      oqs_sig_picnic_mzd_local_copy(w, v);

      mzd_shift_left(r, v, i);
      mm384_shift_left(wr, wr, i);

      if (mzd_cmp(r, w) != 0) {
        printf("lshift fail\nv = ");
        mzd_print(v);
        printf("r = ");
        mzd_print(r);
        printf("w = ");
        mzd_print(w);
      }
    }

    for (unsigned int i = 0; i < 32; ++i) {
      mzd_randomize_ssl(v);
      oqs_sig_picnic_mzd_local_copy(w, v);

      mzd_shift_right(r, v, i);
      mm384_shift_right(wr, wr, i);

      if (mzd_cmp(r, w) != 0) {
        printf("rshift fail\nv = ");
        mzd_print(v);
        printf("r = ");
        mzd_print(r);
        printf("w = ");
        mzd_print(w);
      }
    }

    oqs_sig_picnic_mzd_local_free(w);
    oqs_sig_picnic_mzd_local_free(v);
    oqs_sig_picnic_mzd_local_free(r);
  }
#endif
#endif
}

int main(void) {
  test_mzd_local_equal();
  test_mzd_mul();
  test_mzd_mul_avx();
  test_mzd_shift();
#ifdef WITH_NEON
  test_mzd_mul_vl_neon_192();
  test_mzd_mul_vl_neon_256();

  test_mzd_addmul_vl_neon_192();
  test_mzd_addmul_vl_neon_256();
#endif
}
