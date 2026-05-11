/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_TEST_MFAIL_H
#define OSSL_TEST_MFAIL_H

/* Flags for mfail_init(). */
#define MFAIL_FLAG_COUNT (1 << 0)

/* Modes */
#define MFAIL_MODE_EXHAUSTIVE 0
#define MFAIL_MODE_SAMPLED 1
#define MFAIL_MODE_SINGLE 2

/* Phases */
#define MFAIL_PHASE_DONE 0
#define MFAIL_PHASE_COUNTING 1
#define MFAIL_PHASE_INJECTING 2

/* Install mem hooks */
int mfail_install(int optional);
/* Check if hooks installed */
int mfail_is_installed(void);
/* Initialize the mfail for test case runs */
void mfail_init(int seq, int flags);
/* Check for the failure loop if another fail execution should be done */
int mfail_has_next(void);
/* Start the failure triggering block */
void mfail_start(void);
/* End the failure triggering block */
void mfail_end(void);
/* Check if the failure was triggered in the block */
int mfail_was_triggered(void);
/* Check if the inject phase was skipped because it got over slow threshold */
int mfail_was_slow_skipped(void);
/* If the counting was executed, get the total number of allocations */
int mfail_get_count(void);
/* Get the total number of failure points */
int mfail_get_total(void);
/* Get the number of iterations that run */
int mfail_iterations(void);
/* Get the current failure point */
int mfail_get_point(void);
/* Get execution phase */
int mfail_get_phase(void);
/* Get execution mode */
int mfail_get_mode(void);
/* Get the configured slow threshold */
int mfail_get_slow_threshold(void);

/* Low level arming at specific point (instead of start) */
void mfail_arm_once(int point);
/* Low level disarming (similar to end) */
void mfail_disarm(void);

/* Check whether to skip all tests */
int mfail_env_skip_all(void);
/* Check whether to skip only slow tests */
int mfail_env_skip_slow(void);

#endif /* OSSL_TEST_MFAIL_H */
