/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * The VMClock generation signal.
 *
 * A guest restored from a snapshot continues with the memory it had when the
 * snapshot was taken, the DRBG states included, and its clocks resume from
 * the snapshot too, so neither the pid check nor the time-based reseed sees
 * the restore. Linux exposes a shared page from the hypervisor, the VMClock
 * device (/dev/vmclock0, include/uapi/linux/vmclock-abi.h), whose
 * vm_generation_counter changes every time the guest is loaded from saved
 * state (flagged by VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT) and whose
 * disruption_marker changes on a restore or a live migration. Firecracker
 * attaches the device to every guest; QEMU does with -device vmclock.
 *
 * ossl_prov_vmclock_epoch() returns a value that changes whenever either
 * field does, and 0 where there is no such device, so that the DRBG can
 * treat a change like a change of pid. The page is mapped once; a read is
 * one seqcount-protected load with no system call.
 */

#include <string.h>
#include "internal/cryptlib.h"
#include "internal/thread_once.h"
#include <openssl/opensslconf.h>
#include "prov/seeding.h"

#if defined(__linux__) && !defined(FIPS_MODULE)
# include <fcntl.h>
# include <stdint.h>
# include <sys/mman.h>
# include <unistd.h>

/* The fields read here, at the offsets of vmclock-abi.h version 1. */
struct ossl_vmclock_page {
    uint32_t magic;
    uint32_t size;
    uint16_t version;
    uint8_t counter_id, time_type;
    uint32_t seq_count;
    uint64_t disruption_marker;
    uint64_t flags;
    uint8_t rest[72];
    uint64_t vm_generation_counter;
};
# define OSSL_VMCLOCK_MAGIC 0x4b4c4356u
# define OSSL_VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT (1u << 8)
# define OSSL_VMCLOCK_SIZE_WITH_GENERATION 112u
# define OSSL_VMCLOCK_DEVICE "/dev/vmclock0"

static volatile struct ossl_vmclock_page *vmclock_page;
static CRYPTO_ONCE vmclock_once = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(do_vmclock_init)
{
    /* OPENSSL_VMCLOCK names another device or file, for tests. */
    const char *path = ossl_safe_getenv("OPENSSL_VMCLOCK");
    long page_size = sysconf(_SC_PAGESIZE);
    void *p;
    int fd;

    if (path == NULL || *path == '\0')
        path = OSSL_VMCLOCK_DEVICE;
    if (page_size <= 0)
        return 1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 1;
    p = mmap(NULL, (size_t)page_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return 1;
    if (((volatile struct ossl_vmclock_page *)p)->magic != OSSL_VMCLOCK_MAGIC) {
        munmap(p, (size_t)page_size);
        return 1;
    }
    vmclock_page = p;
    return 1;
}

uint64_t ossl_prov_vmclock_epoch(void)
{
    uint64_t generation, marker, flags;
    uint32_t seq;

    if (!RUN_ONCE(&vmclock_once, do_vmclock_init) || vmclock_page == NULL)
        return 0;
    do {
        while (((seq = vmclock_page->seq_count) & 1) != 0)
            ;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        flags = vmclock_page->flags;
        marker = vmclock_page->disruption_marker;
        generation = (vmclock_page->size >= OSSL_VMCLOCK_SIZE_WITH_GENERATION
                      && (flags & OSSL_VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT) != 0)
            ? vmclock_page->vm_generation_counter : 0;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    } while (seq != vmclock_page->seq_count);
    /*
     * A change in either field changes the result. Before the first event
     * the result is 0, like the no-device case; the DRBG compares successive
     * values and never needs to tell the two apart.
     */
    return generation ^ (marker * 0x9e3779b97f4a7c15ull);
}

#else

uint64_t ossl_prov_vmclock_epoch(void)
{
    return 0;
}

#endif
