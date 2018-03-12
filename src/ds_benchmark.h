/********************************************************************************************
 * ds_benchmark.h: Macros for simple benchmarking of C code.
 *
 * See instructions for usage below.
 * Software originally developed by Douglas Stebila.
 * Most recent version at https://gist.github.com/dstebila/6980008ec98209ef6075
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org>
 ********************************************************************************************/

/** \file ds_benchmark.h
 * Macros for simple benchmarking of C code.
 */

#if 0
/* example code: timing two operations */
#include "ds_benchmark.h"
...
DEFINE_TIMER_VARIABLES
INITIALIZE_TIMER
START_TIMER
// your operation here
STOP_TIMER
START_TIMER
// another operation here
STOP_TIMER
FINALIZE_TIMER
PRINT_TIME_HEADER
PRINT_TIMER_AVG("my operation")
PRINT_TIMER_FOOTER

/* example code: average multiple runs, run for e.g. 30 seconds */
#include "ds_benchmark.h"
...
PRINT_TIMER_HEADER
TIME_OPERATION_SECONDS(MyFunction(myarg1, myarg2, ...), "my operation", 30)
TIME_OPERATION_SECONDS(MyOtherFunction(myarg3), "my other operation", 30)
PRINT_TIMER_FOOTER

/* example code: average multiple runs, run for e.g. 100 iterations */
#include "ds_benchmark.h"
...
PRINT_TIMER_HEADER
TIME_OPERATION_ITERATIONS(MyFunction(myarg1, myarg2, ...), "my operation", 1000)
TIME_OPERATION_ITERATIONS(MyOtherFunction(myarg3), "my other operation", 100)
PRINT_TIMER_FOOTER

/* For most accurate results:
 *  - disable hyperthreading a.k.a. hardware multithreading
 *    (Linux instructions: http://bench.cr.yp.to/supercop.html)
 *    (Mac OS X instructions: Instruments -> Preferences -> CPUs -> uncheck "Hardware Multi-Threading"
 *     http://forums.macrumors.com/showthread.php?t=1484684)
 *  - disable TurboBoost
 *    (Linux instructions: http://bench.cr.yp.to/supercop.html)
 *    (Max OS X: use http://www.rugarciap.com/turbo-boost-switcher-for-os-x/)
 *  - run when the computer is idle (e.g., shut down all other applications, disable network access if possible, ...)
 */
#endif

#ifndef _DS_BENCHMARK_H
#define _DS_BENCHMARK_H

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#if !defined(_WIN32)
#include <sys/time.h>
#endif
#include <math.h>
#include <time.h>

#if defined(_WIN32)
#include <Windows.h>

int gettimeofday(struct timeval *tp, struct timezone *tzp) {
	// Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
	static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);

	SYSTEMTIME system_time;
	FILETIME file_time;
	uint64_t time;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t) file_time.dwLowDateTime);
	time += ((uint64_t) file_time.dwHighDateTime) << 32;
	tp->tv_sec = (long) ((time - EPOCH) / 10000000L);
	tp->tv_usec = (long) (system_time.wMilliseconds * 1000);
	return 0;
}
#endif

static uint64_t rdtsc(void) {
#if defined(_WIN32)
	return __rdtsc();
#elif defined(__aarch64__)
	uint64_t x;
	asm volatile("isb; mrs %0, cntvct_el0"
	             : "=r"(x));
	return x;
#elif defined(__arm__)
	struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	return (int64_t)(time.tv_sec * 1e9 + time.tv_nsec);
#else
	uint64_t x;
	__asm__ volatile(".byte 0x0f, 0x31"
	                 : "=A"(x));
	return x;
#endif
}

#define DEFINE_TIMER_VARIABLES                                                                              \
	volatile uint64_t _bench_cycles_start, _bench_cycles_end;                                               \
	uint64_t _bench_cycles_cumulative = 0;                                                                  \
	int64_t _bench_cycles_diff;                                                                             \
	struct timeval _bench_timeval_start, _bench_timeval_end;                                                \
	uint64_t _bench_iterations, _bench_time_cumulative;                                                     \
	double _bench_cycles_x, _bench_cycles_mean, _bench_cycles_delta, _bench_cycles_M2, _bench_cycles_stdev; \
	double _bench_time_x, _bench_time_mean, _bench_time_delta, _bench_time_M2, _bench_time_stdev;

#define INITIALIZE_TIMER        \
	_bench_iterations = 0;      \
	_bench_cycles_mean = 0.0;   \
	_bench_cycles_M2 = 0.0;     \
	_bench_time_cumulative = 0; \
	_bench_time_mean = 0.0;     \
	_bench_time_M2 = 0.0;

#define START_TIMER                            \
	gettimeofday(&_bench_timeval_start, NULL); \
	_bench_cycles_start = rdtsc();

// Mean and population standard deviation are calculated in an online way using the algorithm in
//     http://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Online_algorithm
#define STOP_TIMER                                                                                                                                                          \
	_bench_cycles_end = rdtsc();                                                                                                                                            \
	gettimeofday(&_bench_timeval_end, NULL);                                                                                                                                \
	_bench_iterations += 1;                                                                                                                                                 \
	if (_bench_cycles_end < _bench_cycles_start) {                                                                                                                          \
		_bench_cycles_end += (uint64_t) 1 << 32;                                                                                                                            \
	}                                                                                                                                                                       \
	_bench_cycles_diff = _bench_cycles_end;                                                                                                                                 \
	_bench_cycles_diff -= _bench_cycles_start;                                                                                                                              \
	_bench_cycles_cumulative += _bench_cycles_diff;                                                                                                                         \
	_bench_cycles_x = (double) (_bench_cycles_diff);                                                                                                                        \
	_bench_cycles_delta = _bench_cycles_x - _bench_cycles_mean;                                                                                                             \
	_bench_cycles_mean += _bench_cycles_delta / (double) _bench_iterations;                                                                                                 \
	_bench_cycles_M2 += _bench_cycles_delta * (_bench_cycles_x - _bench_cycles_mean);                                                                                       \
	_bench_time_x = (double) ((_bench_timeval_end.tv_sec * 1000000 + _bench_timeval_end.tv_usec) - (_bench_timeval_start.tv_sec * 1000000 + _bench_timeval_start.tv_usec)); \
	_bench_time_delta = _bench_time_x - _bench_time_mean;                                                                                                                   \
	_bench_time_mean += _bench_time_delta / (double) _bench_iterations;                                                                                                     \
	_bench_time_M2 += _bench_time_delta * (_bench_time_x - _bench_time_mean);                                                                                               \
	_bench_time_cumulative += _bench_time_x;

#define FINALIZE_TIMER                                                             \
	if (_bench_iterations == 2) {                                                  \
		_bench_cycles_stdev = 0.0;                                                 \
	} else {                                                                       \
		_bench_cycles_stdev = sqrt(_bench_cycles_M2 / (double) _bench_iterations); \
	}                                                                              \
	if (_bench_iterations == 2) {                                                  \
		_bench_time_stdev = 0.0;                                                   \
	} else {                                                                       \
		_bench_time_stdev = sqrt(_bench_time_M2 / (double) _bench_iterations);     \
	}

#define PRINT_CURRENT_TIME                                                                \
	{                                                                                     \
		char _bench_time_buff[20];                                                        \
		time_t _bench_time_now = time(0);                                                 \
		strftime(_bench_time_buff, 20, "%Y-%m-%d %H:%M:%S", localtime(&_bench_time_now)); \
		printf("%s", _bench_time_buff);                                                   \
	}

#define PRINT_TIMER_HEADER                                                                                                                                                                            \
	printf("Started at ");                                                                                                                                                                            \
	PRINT_CURRENT_TIME                                                                                                                                                                                \
	printf("\n");                                                                                                                                                                                     \
	printf("%-30s | %10s | %14s | %15s | %10s | %16s | %10s\n", "Operation                     ", "Iterations", "Total time (s)", "Time (us): mean", "pop. stdev", "CPU cycles: mean", "pop. stdev"); \
	printf("%-30s | %10s:| %14s:| %15s:| %10s:| %16s:| %10s:\n", "------------------------------", "----------", "--------------", "---------------", "----------", "----------------", "----------");
/* colons are used in above to right-align cell contents in Markdown */

#define PRINT_TIMER_FOOTER \
	printf("Ended at ");   \
	PRINT_CURRENT_TIME     \
	printf("\n");

#define PRINT_TIMER_AVG(op_name) \
	printf("%-30s | %10" PRIu64 " | %14.3f | %15.3f | %10.3f | %16.0f | %10.0f\n", (op_name), _bench_iterations, ((double) _bench_time_cumulative) / 1000000.0, _bench_time_mean, _bench_time_stdev, ((double) _bench_cycles_cumulative) / (double) _bench_iterations, _bench_cycles_stdev);

#define TIME_OPERATION_ITERATIONS(op, op_name, it) \
	{                                              \
		DEFINE_TIMER_VARIABLES                     \
		INITIALIZE_TIMER                           \
		for (int i = 0; i < (it); i++) {           \
			START_TIMER { op; }                    \
			STOP_TIMER                             \
		}                                          \
		FINALIZE_TIMER                             \
		PRINT_TIMER_AVG(op_name)                   \
	}

#define TIME_OPERATION_SECONDS(op, op_name, secs)                 \
	{                                                             \
		DEFINE_TIMER_VARIABLES                                    \
		INITIALIZE_TIMER                                          \
		uint64_t _bench_time_goal_usecs = 1000000 * secs;         \
		while (_bench_time_cumulative < _bench_time_goal_usecs) { \
			START_TIMER { op; }                                   \
			STOP_TIMER                                            \
		}                                                         \
		FINALIZE_TIMER                                            \
		PRINT_TIMER_AVG(op_name)                                  \
	}

#endif
