// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar
//
// LD_PRELOAD allocation-failure interposer for the local audit harness.
//
// Fails the Nth heap allocation (1-based) named by AUTHNFT_MALLOC_FAIL_AT,
// counting malloc/calloc/realloc. With the variable unset or <= 0 it is a
// transparent pass-through. The audit harness sweeps N over a run of
// nft_handler_setup under LSan/valgrind so every allocation-failure return
// is exercised; a leak or use-after-free on any of those paths is then
// caught by the detector instead of slipping through because the path was
// never taken.
//
// AUTHNFT_MALLOC_FAIL_VERBOSE=1 prints the failing allocation index to
// stderr (lets the harness map a detector hit back to a specific alloc).
//
// calloc is interposed too. dlsym(RTLD_NEXT, ...) can itself call calloc
// during the loader's first resolution, so a small static arena answers
// allocations that arrive before real_calloc is resolved.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);

static atomic_long g_count = 0;
static long g_fail_at = -1;   /* -1 = never fail */
static int g_verbose = 0;
static atomic_int g_inited = 0;

/* Bootstrap arena for calloc calls that arrive during dlsym resolution. */
static unsigned char g_bootstrap[65536];
static atomic_size_t g_bootstrap_off = 0;

static int from_bootstrap(void *p)
{
    return (unsigned char *)p >= g_bootstrap &&
           (unsigned char *)p < g_bootstrap + sizeof(g_bootstrap);
}

static void *bootstrap_alloc(size_t n)
{
    /* 16-byte align. */
    size_t a = (n + 15) & ~((size_t)15);
    size_t off = atomic_fetch_add(&g_bootstrap_off, a);
    if (off + a > sizeof(g_bootstrap))
        return NULL;
    return &g_bootstrap[off];
}

static void init(void)
{
    if (atomic_load(&g_inited))
        return;
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    const char *e = getenv("AUTHNFT_MALLOC_FAIL_AT");
    g_fail_at = e ? atol(e) : -1;
    g_verbose = getenv("AUTHNFT_MALLOC_FAIL_VERBOSE") ? 1 : 0;
    atomic_store(&g_inited, 1);
}

/* Returns 1 if this allocation should be made to fail. */
static int should_fail(void)
{
    if (g_fail_at <= 0)
        return 0;
    long n = atomic_fetch_add(&g_count, 1) + 1;
    if (n == g_fail_at) {
        if (g_verbose)
            fprintf(stderr, "[malloc_fail] failing allocation #%ld\n", n);
        return 1;
    }
    return 0;
}

void *malloc(size_t size)
{
    if (!real_malloc)
        init();
    if (should_fail())
        return NULL;
    return real_malloc(size);
}

void *calloc(size_t nmemb, size_t size)
{
    if (!real_calloc) {
        init();
        if (!real_calloc) {
            /* still resolving: serve from the bootstrap arena, zeroed. */
            size_t total = nmemb * size;
            void *p = bootstrap_alloc(total);
            if (p)
                memset(p, 0, total);
            return p;
        }
    }
    if (should_fail())
        return NULL;
    return real_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size)
{
    if (!real_realloc)
        init();
    if (should_fail())
        return NULL;
    return real_realloc(ptr, size);
}

void free(void *ptr)
{
    if (from_bootstrap(ptr))
        return;   /* bootstrap arena is never individually freed */
    static void (*real_free)(void *);
    if (!real_free)
        real_free = dlsym(RTLD_NEXT, "free");
    if (real_free)
        real_free(ptr);
}
