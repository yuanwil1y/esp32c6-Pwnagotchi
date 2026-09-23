#pragma once

/*
 * Minimal fail-fast test runner for the host regression tests.
 * Each test binary registers its tests from its own main(), then calls
 * test_run_all(); the process exit code is 0 only when every test passes.
 */

void test_register(const char *name, void (*fn)(void));

/* Runs every registered test in order, printing PASS/FAIL per test.
 * Returns the number of failures. */
int test_run_all(void);

/* Records a failure and longjmps back into the runner (fail-fast per
 * test: later CHECKs in the same test are skipped, other tests still run). */
void test_check_fail(const char *file, int line, const char *expr);

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            test_check_fail(__FILE__, __LINE__, #cond);                    \
        }                                                                  \
    } while (0)
