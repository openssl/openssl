#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <m4ri/m4ri.h>

#include "../mpc.h"
#include "../mzd_additional.h"

#include "utils.c.i"

static mzd_local_t** mpc_init_empty_share_vector(uint32_t n, unsigned sc) {
  mzd_local_t** s = malloc(sc * sizeof(mzd_local_t*));
  oqs_sig_picnic_mzd_local_init_multiple(s, sc, 1, n);
  return s;
}

static mzd_local_t* mpc_reconstruct_from_share(mzd_local_t* dst, mzd_local_t** shared_vec) {
  if (!dst) {
    dst = oqs_sig_picnic_mzd_local_init_ex(shared_vec[0]->nrows, shared_vec[0]->ncols, false);
  }

  oqs_sig_picnic_mzd_xor(dst, shared_vec[0], shared_vec[1]);
  return oqs_sig_picnic_mzd_xor(dst, dst, shared_vec[2]);
}

static mzd_local_t* mzd_init_random_vector(rci_t n) {
  mzd_local_t* a = oqs_sig_picnic_mzd_local_init(1, n);
  mzd_randomize_ssl(a);
  return a;
}

static mzd_local_t** mpc_init_share_vector(mzd_local_t const* v) {
  mzd_local_t** s = malloc(3 * sizeof(mzd_local_t*));
  oqs_sig_picnic_mzd_local_init_multiple_ex(s, 3, 1, v->ncols, false);

  mzd_randomize_ssl(s[0]);
  mzd_randomize_ssl(s[1]);

  oqs_sig_picnic_mzd_xor(s[2], s[0], s[1]);
  oqs_sig_picnic_mzd_xor(s[2], s[2], v);

  return s;
}

static void test_mpc_share(void) {
  mzd_local_t* t1    = mzd_init_random_vector(10);
  mzd_local_t** s1   = mpc_init_share_vector(t1);
  mzd_local_t* t1cmb = mpc_reconstruct_from_share(NULL, s1);

  if (oqs_sig_picnic_mzd_local_equal(t1, t1cmb))
    printf("Share test successful.\n");

  oqs_sig_picnic_mzd_local_free(t1);
  oqs_sig_picnic_mzd_local_free_multiple(s1);
  oqs_sig_picnic_mzd_local_free(t1cmb);
}

static void test_mpc_add(void) {
  mzd_local_t* t1  = mzd_init_random_vector(10);
  mzd_local_t* t2  = mzd_init_random_vector(10);
  mzd_local_t* res = oqs_sig_picnic_mzd_local_init(1, 10);
  oqs_sig_picnic_mzd_xor(res, t1, t2);

  mzd_local_t** s1   = mpc_init_share_vector(t1);
  mzd_local_t** s2   = mpc_init_share_vector(t2);
  mzd_local_t** ress = mpc_init_empty_share_vector(10, 3);
  oqs_sig_picnic_mpc_xor(ress, s1, s2, 3);

  mzd_local_t* cmp = mpc_reconstruct_from_share(NULL, ress);

  if (oqs_sig_picnic_mzd_local_equal(res, cmp))
    printf("Shared add test successful.\n");

  oqs_sig_picnic_mzd_local_free(t1);
  oqs_sig_picnic_mzd_local_free(t2);
  oqs_sig_picnic_mzd_local_free(res);
  oqs_sig_picnic_mzd_local_free_multiple(s1);
  oqs_sig_picnic_mzd_local_free_multiple(s2);
  oqs_sig_picnic_mzd_local_free_multiple(ress);
  oqs_sig_picnic_mzd_local_free(cmp);
}

void run_tests(void) {
  test_mpc_share();
  test_mpc_add();
}

int main(void) {
  run_tests();

  return 0;
}
