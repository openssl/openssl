/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "cpu.h"

/* If cmake checks were not run, define some known values. */

#if !defined(HAVE_SYS_AUXV_H) && defined(__linux__)
#define HAVE_SYS_AUXV_H
#endif

#if !defined(HAVE_ASM_HWCAP_H) && defined(__linux__) && defined(__arm__)
#define HAVE_ASM_HWCAP_H
#endif

#if defined(__arm__) && defined(HAVE_SYS_AUXV_H) && defined(HAVE_ASM_HWCAP_H)
#include <asm/hwcap.h>
#include <sys/auxv.h>

static unsigned int init_caps(void) {
  unsigned int caps = 0;
  if (getauxval(AT_HWCAP) & HWCAP_NEON) {
    caps |= CPU_CAP_NEON;
  }
  return caps;
}

#elif (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(_MSC_VER))

#ifdef _MSC_VER
#include <intrin.h>

static unsigned init_caps(void) {
  unsigned int caps = 0;

  union {
    struct {
      unsigned int eax, ebx, ecx, edx;
    };
    int data[4];
  } regs = {0};

  __cpuid(regs.data, 0);
  unsigned int max = regs.eax;

  if (max >= 1) {
    __cpuid(regs.data, 0);
    if (regs.edx & (1 << 26)) {
      caps |= CPU_CAP_SSE2;
    }
    if (regs.ecx & (1 << 19)) {
      caps |= CPU_CAP_SSE4_1;
    }
  }

  if (max >= 7) {
    __cpuidex(regs.data, 7, 0);
    if (regs.ebx & (1 << 5)) {
      caps |= CPU_CAP_AVX2;
    }
  }

  return caps;
}
#else
#include <cpuid.h>

static unsigned init_caps(void) {
  unsigned int caps = 0;
  unsigned int eax, ebx, ecx, edx;

  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    if (edx & (1 << 26)) {
      caps |= CPU_CAP_SSE2;
    }
    if (ecx & (1 << 19)) {
      caps |= CPU_CAP_SSE4_1;
    }
  }

  if (__get_cpuid(7, &eax, &ebx, &ecx, &edx)) {
    if (ebx & (1 << 5)) {
      caps |= CPU_CAP_AVX2;
    }
  }

  return caps;
}
#endif

#else

static unsigned init_caps(void) {
  return 0;
}

#endif

#include <limits.h>

static unsigned int cpu_caps = UINT_MAX;

bool cpu_supports(unsigned int caps) {
  if (cpu_caps == UINT_MAX) {
    cpu_caps = init_caps();
  }

  return cpu_caps & caps;
}
