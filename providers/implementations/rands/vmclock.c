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
 * ossl_prov_vmclock_changed() compares the current value of the two fields
 * with the one a DRBG last saw, so that the DRBG can treat a change like a
 * change of pid. Each library context maps the page once, when its first
 * DRBG is created, and unmaps it when the context is freed; the mapping is
 * kept with the context rather than in a static, as the FIPS provider
 * requires. A read is a few loads under the page's sequence count, with no
 * system call.
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/opensslconf.h>
#include "internal/cryptlib.h"
#include "internal/endian.h"
#include "crypto/context.h"
#include "prov/drbg.h"

/* The page is read under a seqcount, with the compiler's fences. */
#if defined(__linux__) && defined(__GNUC__)
#define OSSL_VMCLOCK_SUPPORTED
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(FIPS_MODULE) && defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 16)
#include <sys/auxv.h>
#define OSSL_VMCLOCK_GETAUXVAL
#endif
#elif defined(FIPS_MODULE) && defined(__ANDROID_API__)
#if __ANDROID_API__ >= 18
#include <sys/auxv.h>
#define OSSL_VMCLOCK_GETAUXVAL
#endif
#endif
#endif

/* The library context's mapping, made by its first DRBG. */
typedef struct prov_vmclock_global_st {
    CRYPTO_RWLOCK *lock;
    int mapped; /* set once a mapping has been tried */
    void *page; /* NULL if there is no page we can read */
    size_t len;
} PROV_VMCLOCK_GLOBAL;

void *ossl_prov_vmclock_ctx_new(ossl_unused OSSL_LIB_CTX *libctx)
{
    PROV_VMCLOCK_GLOBAL *vgbl = OPENSSL_zalloc(sizeof(*vgbl));

    if (vgbl == NULL)
        return NULL;

    vgbl->lock = CRYPTO_THREAD_lock_new();
    if (vgbl->lock == NULL) {
        OPENSSL_free(vgbl);
        return NULL;
    }

    return vgbl;
}

void ossl_prov_vmclock_ctx_free(void *vvgbl)
{
    PROV_VMCLOCK_GLOBAL *vgbl = vvgbl;

    if (vgbl == NULL)
        return;

#ifdef OSSL_VMCLOCK_SUPPORTED
    if (vgbl->page != NULL)
        munmap(vgbl->page, vgbl->len);
#endif
    CRYPTO_THREAD_lock_free(vgbl->lock);

    OPENSSL_free(vgbl);
}

#ifdef OSSL_VMCLOCK_SUPPORTED

/*
 * The fields read here, at the offsets of vmclock-abi.h version 1. Every
 * field of the page is little-endian.
 */
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
#define OSSL_VMCLOCK_MAGIC 0x4b4c4356u
#define OSSL_VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT (1u << 8)
#define OSSL_VMCLOCK_SIZE_WITH_GENERATION 112u
#define OSSL_VMCLOCK_DEVICE "/dev/vmclock0"

/*
 * The number of times a reader looks at the sequence count before it gives
 * up. The hypervisor holds the count odd only while it rewrites the page,
 * which takes a few stores; the bound keeps a reader from spinning with a
 * DRBG lock held if the count stays odd. A read that gives up is reported
 * as a change, so the cost of a bound that is too short is one reseed.
 */
#define OSSL_VMCLOCK_MAX_TRIES 1000

static uint16_t vmclock_le16(uint16_t v)
{
    DECLARE_IS_ENDIAN;

    if (IS_LITTLE_ENDIAN)
        return v;
    return (uint16_t)((v >> 8) | (v << 8));
}

static uint32_t vmclock_le32(uint32_t v)
{
    DECLARE_IS_ENDIAN;

    if (IS_LITTLE_ENDIAN)
        return v;
    return (v >> 24) | ((v >> 8) & 0xff00u) | ((v << 8) & 0xff0000u) | (v << 24);
}

static uint64_t vmclock_le64(uint64_t v)
{
    DECLARE_IS_ENDIAN;

    if (IS_LITTLE_ENDIAN)
        return v;
    return ((uint64_t)vmclock_le32((uint32_t)v) << 32)
        | vmclock_le32((uint32_t)(v >> 32));
}

/*
 * OPENSSL_VMCLOCK names another device or file, for tests. A set-user-ID or
 * set-group-ID process ignores it; the FIPS provider, which has no
 * ossl_safe_getenv(), makes the check of OPENSSL_issetugid() itself.
 */
static const char *vmclock_path(void)
{
    const char *path;

#ifndef FIPS_MODULE
    path = ossl_safe_getenv("OPENSSL_VMCLOCK");
#elif defined(OSSL_VMCLOCK_GETAUXVAL)
    path = getauxval(AT_SECURE) != 0 ? NULL : getenv("OPENSSL_VMCLOCK");
#else
    path = getuid() != geteuid() || getgid() != getegid()
        ? NULL
        : getenv("OPENSSL_VMCLOCK");
#endif
    if (path == NULL || *path == '\0')
        return OSSL_VMCLOCK_DEVICE;
    return path;
}

/* Maps the page, setting |*len|; returns NULL if there is none we can read. */
static void *vmclock_map(size_t *len)
{
    const char *path = vmclock_path();
    long page_size = sysconf(_SC_PAGESIZE);
    volatile struct ossl_vmclock_page *page;
    struct stat st;
    void *p;
    int fd;

    if (page_size <= 0 || (size_t)page_size < sizeof(struct ossl_vmclock_page))
        return NULL;
    /* O_NONBLOCK, so that a FIFO or another special file cannot block us. */
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return NULL;
    /*
     * The device, or for tests a regular file that holds the whole
     * structure: reading past the end of a shorter file would fault.
     */
    if (fstat(fd, &st) != 0
        || !(S_ISCHR(st.st_mode)
            || (S_ISREG(st.st_mode)
                && st.st_size >= (off_t)sizeof(struct ossl_vmclock_page)))) {
        close(fd);
        return NULL;
    }
    p = mmap(NULL, (size_t)page_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return NULL;
    page = p;
    /* The checks the kernel makes before it creates the device. */
    if (vmclock_le32(page->magic) != OSSL_VMCLOCK_MAGIC
        || vmclock_le16(page->version) != 1) {
        munmap(p, (size_t)page_size);
        return NULL;
    }
    *len = (size_t)page_size;
    return p;
}

const volatile void *ossl_prov_vmclock_page(OSSL_LIB_CTX *libctx)
{
    PROV_VMCLOCK_GLOBAL *vgbl = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_VMCLOCK_INDEX);
    void *page;

    if (vgbl == NULL || !CRYPTO_THREAD_write_lock(vgbl->lock))
        return NULL;
    if (!vgbl->mapped) {
        vgbl->page = vmclock_map(&vgbl->len);
        vgbl->mapped = 1;
    }
    page = vgbl->page;
    CRYPTO_THREAD_unlock(vgbl->lock);
    return page;
}

/*
 * Reads the two fields under the page's sequence count and folds them into
 * |*epoch|. Returns 0 if the page was being rewritten on every one of
 * OSSL_VMCLOCK_MAX_TRIES looks.
 */
static int vmclock_read(const volatile struct ossl_vmclock_page *page,
    uint64_t *epoch)
{
    uint64_t generation, marker, flags;
    uint32_t seq;
    int tries;

    for (tries = 0; tries < OSSL_VMCLOCK_MAX_TRIES; tries++) {
        seq = vmclock_le32(page->seq_count);
        if ((seq & 1) != 0)
            continue;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        flags = vmclock_le64(page->flags);
        marker = vmclock_le64(page->disruption_marker);
        generation = 0;
        if (vmclock_le32(page->size) >= OSSL_VMCLOCK_SIZE_WITH_GENERATION
            && (flags & OSSL_VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT) != 0)
            generation = vmclock_le64(page->vm_generation_counter);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (seq == vmclock_le32(page->seq_count)) {
            /* A change in either field changes the result. */
            *epoch = generation ^ (marker * 0x9e3779b97f4a7c15ull);
            return 1;
        }
    }
    return 0;
}

int ossl_prov_vmclock_changed(const volatile void *page, uint64_t *epoch)
{
    uint64_t now;

    if (page == NULL)
        return 0;
    if (!vmclock_read(page, &now))
        return 1;
    if (now == *epoch)
        return 0;
    *epoch = now;
    return 1;
}

#else

const volatile void *ossl_prov_vmclock_page(ossl_unused OSSL_LIB_CTX *libctx)
{
    return NULL;
}

int ossl_prov_vmclock_changed(ossl_unused const volatile void *page,
    ossl_unused uint64_t *epoch)
{
    return 0;
}

#endif
