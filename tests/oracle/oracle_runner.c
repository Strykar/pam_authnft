// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar
//
// Oracle runner: feeds line-oriented stdin through one of pam_authnft's
// small parsers and prints a parser-agnostic result line for each input.
// Paired with tests/oracle/oracle.py — a Python re-implementation of
// the same parser. The driver script tests/oracle/run.sh feeds the same
// corpus through both, diffs the output. Disagreement = logic bug.
//
// I/O contract:
//   stdin:  one input per line, NUL-terminated by stripping '\n'
//   stdout: one result per input, format depends on the function
//   stderr: optional debug output
//   argv[1]: which function to test
//
// The runner is compiled with -DFUZZ_BUILD so the static qualifier
// is stripped from validate_cgroup_path / keyring_sanitize /
// corr_sanitize_copy. Production lifecycle (and pam_authnft.so) are
// unaffected — these symbols stay file-static in the release build.
//
// Inputs containing literal newlines or NULs cannot be expressed in
// this line-oriented protocol; covered by the libFuzzer harnesses.

#include "authnft.h"
#include "util_validators.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

/* keyring_sanitize and corr_sanitize_copy are declared non-static
 * under -DFUZZ_BUILD in their respective .c files. validate_cgroup_path
 * is now unconditionally extern via util_validators.h (the conditional-
 * extern pattern was retired for it in the input-validators PR). */
ssize_t keyring_sanitize(const char *in, size_t in_len,
                         char *out, size_t out_sz);
size_t corr_sanitize_copy(const char *in, char *out, size_t out_sz);

static void run_username(void) {
    char line[1024];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';
        printf("%d\n", util_is_valid_username(line));
    }
}

static void run_normalize_ip(void) {
    char line[1024];
    char out[IP_STR_MAX];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';
        int rc = util_normalize_ip(line, out, sizeof(out));
        if (rc) printf("1|%s\n", out);
        else    printf("0|\n");
    }
}

static void run_cgroup_path(void) {
    char line[1024];
    char out[CGROUP_PATH_MAX];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';
        int rc = validate_cgroup_path(line, out, sizeof(out));
        if (rc == 0) printf("0|%s\n", out);
        else         printf("-1|\n");
    }
}

static void run_keyring_sanitize(void) {
    char line[1024];
    char out[CLAIMS_TAG_MAX + 1];
    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strcspn(line, "\n");
        line[n] = '\0';
        ssize_t r = keyring_sanitize(line, n, out, sizeof(out));
        if (r < 0) printf("-1|\n");
        else       printf("%zd|%s\n", r, out);
    }
}

static void run_correlation_capture(void) {
    char line[1024];
    char out[CORRELATION_ID_MAX];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';
        size_t r = corr_sanitize_copy(line, out, sizeof(out));
        printf("%zu|%s\n", r, out);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
                "usage: %s {username|normalize_ip|cgroup_path|"
                "keyring_sanitize|correlation_capture}\n",
                argv[0]);
        return 2;
    }
    if      (strcmp(argv[1], "username") == 0)             run_username();
    else if (strcmp(argv[1], "normalize_ip") == 0)         run_normalize_ip();
    else if (strcmp(argv[1], "cgroup_path") == 0)          run_cgroup_path();
    else if (strcmp(argv[1], "keyring_sanitize") == 0)     run_keyring_sanitize();
    else if (strcmp(argv[1], "correlation_capture") == 0)  run_correlation_capture();
    else {
        fprintf(stderr, "unknown function: %s\n", argv[1]);
        return 2;
    }
    return 0;
}
