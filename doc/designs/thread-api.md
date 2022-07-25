Thread Pool Support
===================

OpenSSL wishes to support the internal use of threads for purposes of
concurrency and parallelism in some circumstances. There are various reasons why
this is desirable:

  - Some algorithms are designed to be run in parallel (Argon2);
  - Some transports (e.g. QUIC, DTLS) may need to handle timer events
    independently of application calls to OpenSSL.

To support this end, OpenSSL can manage an internal thread pool. Tasks can be
scheduled on the internal thread pool.

There are three options given to an application which wants to use the thread
pool functionality:

  1. Use OpenSSL's default thread pool functionality.

  2. Use OpenSSL's thread pool functionality with a custom thread spawner
     method.

  3. Provide threads manually to OpenSSL for use as part of its thread pool.

Default Model
-------------

In the default model, OpenSSL creates and manages threads up to a maximum
number of threads authorized by the application.

The application enables thread pooling by calling the following function
during its initialisation:

```c
/*
 * Set the maximum number of threads to be used by the thread pool.
 *
 * If the argument is 0, thread pooling is disabled. OpenSSL will not create any
 * threads and existing threads in the thread pool will be torn down.
 *
 * Returns 1 on success and 0 on failure. Returns failure if OpenSSL-managed
 * thread pooling is not supported (for example, if it is not supported on the
 * current platform, or because OpenSSL is not built with the necessary
 * support).
 */
int OSSL_set_max_threads(uint32_t max_threads);

/*
 * Get the maximum number of threads currently allowed to be used by the
 * thread pool. If thread pooling is disabled or not available, returns 0.
 */
uint32_t OSSL_get_max_threads(void);
```

The maximum thread count is a limit, not a target. Threads will not be spawned
unless (and until) there is demand.

Custom Thread Spawner Method
----------------------------

If an application wishes to control thread spawning, it may set a custom set of
thread method functions. OpenSSL will use these to spawn and join threads.

```c
typedef struct ossl_thread_cookie_st OSSL_THREAD_COOKIE;

typedef struct ossl_thread_method_st {
    /*
     * Spawns thread, calling cb with arg. An opaque cookie representing the
     * thread is written to *thread_cookie.
     *
     * Returns 1 on success or 0 on failure.
     */
    int (*spawn_thread)(void (*cb)(void *arg), void *arg,
                        OSSL_THREAD_COOKIE **thread_cookie);

    /*
     * Wait for a thread to exit.
     */
    void (*join_thread)(OSSL_THREAD_COOKIE *thread_cookie);
} OSSL_THREAD_METHOD;

/*
 * Call OSSL_set_thread_method(&method, sizeof(method)) to set a new thread
 * method. This must be called before OpenSSL creates any threads (e.g. before
 * the call to `OSSL_set_max_threads`), else it fails.
 *
 * The length argument allows ABI compatibility to be preserved if methods are
 * added to the OSSL_THREAD_METHOD structure in future.
 */
int OSSL_set_thread_method(OSSL_THREAD_METHOD *method, size_t len);
```

OpenSSL uses the custom thread spawner method in accordance with the thread
limit set using the default API already introduced. However if necessary, an
application can also control thread creation by causing the `spawn_thread`
method to fail.

Note that this gives the application control over thread spawning and joining,
but not other threading functionality like mutexes or condition variables.
The rationale for this is:

- Thread creation and joining requires OS interaction (syscalls);
- Mutexes or condition variables do not necessarily require OS interaction;
- It is comparatively more likely for applications to want to intercept
  thread management than synchronisation primitives;
- Making synchronisation primitives polymorphic would be overkill
  and add unnecessary overhead;
- We already use synchronisation primitives (e.g. pthread rwmutex)
  without providing options to the application.

This method can be dropped from MVP if it is deemed unnecessary.

Manual Thread Method
--------------------

With this method, the application creates its own threads and donates them to
OpenSSL by calling a function on those threads which does not return (unless
later requested to do so).

Example usage is demonstrated below:

```c
OSSL_thread_pool_cookie *cookie;

{
    /* error checking omitted for brevity */

    cookie = OSSL_thread_pool_cookie_new();
    OSSL_thread_pool_enter(cookie);
    OSSL_thread_pool_cookie_free(cookie);
    /* above function returns due to exit call below */
}
```

If an application wishes to reclaim the thread from the thread pool, it
may do so using the cookie:

```c
{
    /* Causes OSSL_thread_pool_enter to return */
    OSSL_thread_pool_exit(cookie);
}
```

The cookie is created separately to avoid race conditions; the application must
not call `OSSL_thread_pool_exit` before `OSSL_thread_pool_cookie_new` has
returned.

Because `OSSL_thread_pool_cookie_free` is synchronised, as an alternative usage
model, another thread may simultaneously cause a thread to leave a thread pool
and free its cookie:

```c
OSSL_thread_pool_cookie *cookie;

/* thread pool thread */
{
    /* error checking omitted for brevity */

    cookie = OSSL_thread_pool_cookie_new();
    OSSL_thread_pool_enter(cookie);
    /* above function returns due to cookie being freed */
}

/* another controlling thread */
{
    OSSL_thread_pool_cookie_free(cookie);
}
```

The API is as follows:

```c
typedef struct ossl_thread_pool_cookie_st OSSL_THREAD_POOL_COOKIE;

/*
 * Creates a thread pool cookie.
 */
OSSL_THREAD_POOL_COOKIE *OSSL_THREAD_POOL_COOKIE_new(void);

/*
 * Frees a thread pool cookie.
 *
 * Calling this implicitly calls OSSL_thread_pool_exit_wait, therefore it is
 * safe to call even when other threads have calls to OSSL_thread_pool_enter in
 * progress, and will not return until those threads have exited
 * OSSL_thread_pool_enter.
 */
void OSSL_THREAD_POOL_COOKIE_free(OSSL_THREAD_POOL_COOKIE *cookie);

/*
 * Resets a thread pool cookie which was passed to OSSL_thread_pool_exit so that
 * it can be used again.
 */
void OSSL_THREAD_POOL_COOKIE_reset(OSSL_THREAD_POOL_COOKIE *cookie);

/*
 * Donates the executing thread to the OpenSSL thread pool. cookie must have
 * been created by calling OSSL_THREAD_POOL_COOKIE_new.
 *
 * If the application desires to recover the thread at a later time,
 * it can call OSSL_thread_pool_exit using the same cookie, which
 * will cause this function to return.
 *
 * Returns 0 if entering the thread pool failed and 1 if the thread pool
 * was entered successfully but the function subsequently returned
 * due to a call to OSSL_thread_pool_exit.
 */
int OSSL_thread_pool_enter(OSSL_THREAD_POOL_COOKIE *cookie);

/*
 * Causes any in progress calls to OSSL_thread_pool_enter, or any future such
 * call made using the given cookie, to return.
 *
 * Returns 0 if the cookie is invalid. Otherwise returns 1. There is no
 * indication of whether the call caused any OSSL_thread_pool_enter call to
 * return.
 *
 * Multiple calls to this function (before any subsequent call to
 * OSSL_THREAD_POOL_COOKIE_reset) are idempotent.
 */
int OSSL_thread_pool_exit(OSSL_THREAD_POOL_COOKIE *cookie);

/*
 * This is like OSSL_thread_pool_exit, but blocks until all calls to
 * OSSL_thread_pool_enter have returned. It may also be called after any call to
 * OSSL_thread_pool_exit to wait until all calls to OSSL_thread_pool_enter have
 * returned.
 */
int OSSL_thread_pool_exit_wait(OSSL_THREAD_POOL_COOKIE *cookie);
```

Manual threads count towards the thread limit for the purposes of the default
thread model. However, the caller is not prevented from donating threads
manually which exceed the thread limit. This means, for example, you can leave
the thread limit set at its default of zero, meaning that OpenSSL is not allowed
to create threads, and donate threads to it using this API.

If the default model thread limit were set to e.g. 4, and you donated two
threads using the manual API, OpenSSL would only create up to two threads which
it manages itself.

Capability Detection
--------------------

These functions allow the caller to determine if OpenSSL was built with threads
support.

```c
/*
 * Retrieves flags indicating what threading functionality OpenSSL can support
 * based on how it was built and the platform on which it was running.
 */
/* Is thread pool functionality supported at all? */
#define OSSL_THREAD_SUPPORT_FLAG_THREAD_POOL    (1U<<0)

/*
 * Is the default model supported? If THREAD_POOL is supported but DEFAULT_SPAWN
 * is not supported, the custom thread spawner or manual thread method must be
 * used.
 */
#define OSSL_THREAD_SUPPORT_FLAG_DEFAULT_SPAWN  (1U<<1)

/* Returns zero or more of OSSL_THREAD_SUPPORT_FLAG_*. */
uint32_t OSSL_get_thread_support_flags(void);
```

Since deciding on a reasonable number of threads is hardware-specific, a
convenience function will also be provided to give a good ballpark figure:

```c
/*
 * Get the recommended number of threads to be allocated to a thread pool.
 *
 * This is a hardware-specific value which approximates the number of
 * concurrent threads of execution available on the machine.
 *
 * If thread pooling is disabled or not available, this may return 0 or may
 * still return a valid value.
 */
uint32_t OSSL_get_recommended_threads(void);
```

Build Options
-------------

A build option `thread-pool`/`no-thread-pool` will be introduced which allows
thread pool functionality to be compiled out. `no-thread-pool` implies
`no-default-thread-pool`.

A build option `default-thread-pool`/`no-default-thread-pool` will be introduced
which allows the default thread pool functionality to be compiled out. If this
functionality is compiled out, OpenSSL can only use multiple threads via a
spawning method provided via the application, or via donated threads. This is
useful for e.g. embedded applications which desire the thread pool functionality
but for which OpenSSL lacks the necessary OS support.

Internals
---------

New internal components will need to be introduced (e.g. condition variables)
to support this functionality, however there is no intention of making
this functionality public at this time.
