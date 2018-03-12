#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "picnic.h"
#include "timing.h"

#include <errno.h>
#if !defined(_MSC_VER)
#include <getopt.h>
#endif
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>

typedef struct { int fd; } timing_context_t;

static bool timing_init(timing_context_t* ctx) {
  struct perf_event_attr pea;
  memset(&pea, 0, sizeof(struct perf_event_attr));

  pea.size                     = sizeof(pea);
  pea.type                     = PERF_TYPE_HARDWARE;
  pea.config                   = PERF_COUNT_HW_CPU_CYCLES;
  pea.disabled                 = 0;
  pea.exclude_kernel           = 1;
  pea.exclude_hv               = 1;
  pea.exclude_callchain_kernel = 1;
  pea.exclude_callchain_user   = 1;

  const long fd = syscall(__NR_perf_event_open, &pea, 0, -1, -1, 0);
  if (fd == -1) {
    printf("Could not open file descriptor\n");
    return false;
  }

  ctx->fd = fd;
  return true;
}

static void timing_close(timing_context_t* ctx) {
  if (ctx->fd != -1) {
    close(ctx->fd);
    ctx->fd = -1;
  }
}

static uint64_t timing_read(timing_context_t* ctx) {
  uint64_t tmp_time;
  if (read(ctx->fd, &tmp_time, sizeof(tmp_time)) != sizeof(tmp_time)) {
    return UINT64_MAX;
  }

  return tmp_time;
}
#else
typedef void* timing_context_t;

static bool timing_init(timing_context_t* ctx) {
  (void)ctx;
  return true;
}

static void timing_close(timing_context_t* ctx) {
  (void)ctx;
}

static uint64_t timing_read(timing_context_t* ctx) {
  (void)ctx;
  return gettime_clock();
}
#endif

#ifndef VERBOSE
static void print_timings(timing_and_size_t* timings, unsigned int iter) {
  const unsigned int numt = sizeof(*timings) / sizeof(timings->data[0]);

  for (unsigned i = 0; i < iter; i++) {
    for (unsigned j = 0; j < numt; j++) {
      printf("%" PRIu64, timings[i].data[j]);
      if (j < numt - 1)
        printf(",");
    }
    printf("\n");
  }
}
#else
#ifdef WITH_DETAILED_TIMING
static void print_timings(timing_and_size_t* timings, unsigned int iter) {
  for (unsigned int i = 0; i != iter; ++i, ++timings) {
    printf("Setup:\n");
    printf("LowMC setup               %9" PRIu64 "\n", timings->gen.lowmc_init);
    printf("LowMC key generation      %9" PRIu64 "\n", timings->gen.keygen);
    printf("Public key computation    %9" PRIu64 "\n", timings->gen.pubkey);
    printf("\n");
    printf("Prove:\n");
    printf("MPC randomess generation  %9" PRIu64 "\n", timings->sign.rand);
    printf("MPC secret sharing        %9" PRIu64 "\n", timings->sign.secret_sharing);
    printf("MPC LowMC encryption      %9" PRIu64 "\n", timings->sign.lowmc_enc);
    printf("Hashing views             %9" PRIu64 "\n", timings->sign.views);
    printf("Generating challenge      %9" PRIu64 "\n", timings->sign.challenge);
    printf("Overall hash time         %6" PRIu64 "\n", timings->sign.hash);
    printf("\n");
    printf("Verify:\n");
    printf("Recomputing challenge     %9" PRIu64 "\n", timings->verify.challenge);
    printf("Verifying output shares   %9" PRIu64 "\n", timings->verify.output_shares);
    printf("Comparing output views    %9" PRIu64 "\n", timings->verify.output_views);
    printf("Verifying views           %9" PRIu64 "\n", timings->verify.verify);
    printf("Overall hash time         %9" PRIu64 "\n", timings->verify.hash);
    printf("\n");
  }
}
#else
static void print_timings(timing_and_size_t* timings, unsigned int iter) {
  for (unsigned int i = 0; i != iter; ++i, ++timings) {
    printf("Sign                      %9" PRIu64 "\n", timings->sign);
    printf("Verify                    %9" PRIu64 "\n", timings->verify);
    printf("\n");
  }
}
#endif
#endif

static bool parse_long(long* value, const char* arg) {
  errno        = 0;
  const long v = strtol(arg, NULL, 10);

  if ((errno == ERANGE && (v == LONG_MAX || v == LONG_MIN)) || (errno != 0 && v == 0)) {
    return false;
  }
  *value = v;

  return true;
}

static bool parse_uint32_t(uint32_t* value, const char* arg) {
  long tmp = 0;
  if (!parse_long(&tmp, arg)) {
    return false;
  }

  if (tmp < 0 || (unsigned long)tmp > UINT32_MAX) {
    return false;
  }

  *value = tmp;
  return true;
}

typedef struct {
  picnic_params_t params;
  uint32_t iter;
} bench_options_t;

static void print_usage(const char* arg0) {
#if defined(_MSC_VER)
  printf("usage: %s iterations instance\n", arg0);
#else
  printf("usage: %s [-i iterations] instance\n", arg0);
#endif
}

static bool parse_args(bench_options_t* options, int argc, char** argv) {
  if (argc <= 1) {
    print_usage(argv[0]);
    return false;
  }

  options->params = PARAMETER_SET_INVALID;
  options->iter   = 10;

#if !defined(_MSC_VER)
  static const struct option long_options[] = {{"iter", required_argument, 0, 'i'}, {0, 0, 0, 0}};

  int c            = -1;
  int option_index = 0;

  while ((c = getopt_long(argc, argv, "i:", long_options, &option_index)) != -1) {
    switch (c) {
    case 'i':
      if (!parse_uint32_t(&options->iter, optarg)) {
        printf("Failed to parse argument as positive base-10 number!\n");
        return false;
      }
      break;

    case '?':
    default:
      printf("usage: %s [-i iter] param\n", argv[0]);
      return false;
    }
  }

  if (optind == argc - 1) {
    uint32_t p = -1;
    if (!parse_uint32_t(&p, argv[optind])) {
      printf("Failed to parse argument as positive base-10 number!\n");
      return false;
    }

    if (p <= PARAMETER_SET_INVALID || p >= PARAMETER_SET_MAX_INDEX) {
      printf("Invalid parameter set selected!\n");
      return false;
    }
    options->params = p;
  } else {
    print_usage(argv[0]);
    return false;
  }
#else
  if (argc != 3) {
	print_usage(argv[0]);
	return false;
  }

  uint32_t p = -1;
  if (!parse_uint32_t(&options->iter, argv[1]) || !parse_uint32_t(&p, argv[2])) { 
	printf("Failed to parse argument as positive base-10 number!\n");
	return false;
  }

  if (p <= PARAMETER_SET_INVALID || p >= PARAMETER_SET_MAX_INDEX) {
	printf("Invalid parameter set selected!\n");
	return false;
  }
  options->params = p;
#endif

  return true;
}

static void sign_and_verify(const bench_options_t* options) {
  static const uint8_t m[] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                              17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

  timing_and_size_t* timings_fis = calloc(options->iter, sizeof(timing_and_size_t));

  const size_t max_signature_size = picnic_signature_size(options->params);
  if (!max_signature_size) {
    printf("Failed to create Picnic instance.\n");
    return;
  }

  uint8_t sig[PICNIC_MAX_SIGNATURE_SIZE];

  timing_context_t ctx;
  timing_init(&ctx);

  for (unsigned int i = 0; i != options->iter; ++i) {
#ifndef WITH_DETAILED_TIMING
    timing_and_size_t* timing_and_size;
    uint64_t start_time = timing_read(&ctx);
#endif
    timing_and_size           = &timings_fis[i];
    timing_and_size->max_size = max_signature_size;

    picnic_privatekey_t private_key;
    picnic_publickey_t public_key;

    if (picnic_keygen(options->params, &public_key, &private_key)) {
      printf("Failed to create key.\n");
      break;
    }

#ifndef WITH_DETAILED_TIMING
    uint64_t tmp_time       = timing_read(&ctx);
    timing_and_size->keygen = tmp_time - start_time;
    start_time              = timing_read(&ctx);
#endif
    size_t siglen = max_signature_size;
    if (!picnic_sign(&private_key, m, sizeof(m), sig, &siglen)) {
#ifndef WITH_DETAILED_TIMING
      tmp_time              = timing_read(&ctx);
      timing_and_size->sign = tmp_time - start_time;
      timing_and_size->size = siglen;
      start_time            = timing_read(&ctx);
#endif

      if (picnic_verify(&public_key, m, sizeof(m), sig, siglen)) {
        printf("picnic_verify: failed\n");
      }
#ifndef WITH_DETAILED_TIMING
      tmp_time                = timing_read(&ctx);
      timing_and_size->verify = tmp_time - start_time;
#endif
    } else {
      printf("picnic_sign: failed\n");
    }
  }

#ifdef VERBOSE
  printf("Picnic signature:\n\n");
#endif
  timing_close(&ctx);
  print_timings(timings_fis, options->iter);

  free(timings_fis);
}

int main(int argc, char** argv) {
  bench_options_t opts;
  int ret = parse_args(&opts, argc, argv) ? 0 : -1;

  if (!ret) {
    sign_and_verify(&opts);
  }

  return ret;
}
