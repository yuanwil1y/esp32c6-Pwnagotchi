#include "runner.h"

#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#define MAX_TESTS 128

typedef struct {
    const char *name;
    void (*fn)(void);
} test_entry_t;

static test_entry_t s_tests[MAX_TESTS];
static int s_test_count;
static int s_failures;

static jmp_buf s_jmp;
static const char *s_current;

void test_register(const char *name, void (*fn)(void))
{
    if (s_test_count < MAX_TESTS) {
        s_tests[s_test_count].name = name;
        s_tests[s_test_count].fn = fn;
        s_test_count++;
    }
}

void test_check_fail(const char *file, int line, const char *expr)
{
    printf("    FAIL %s: %s:%d: %s\n", s_current, file, line, expr);
    s_failures++;
    longjmp(s_jmp, 1);
}

int test_run_all(void)
{
    /* Crash diagnostics must survive the crash itself. */
    setvbuf(stdout, NULL, _IONBF, 0);

    for (volatile int i = 0; i < s_test_count; i++) {
        s_current = s_tests[i].name;
        printf("RUN  %s\n", s_current);
        if (setjmp(s_jmp) == 0) {
            s_tests[i].fn();
            printf("PASS %s\n", s_current);
        }
    }

    const int total = s_test_count;
    printf("%d/%d passed\n", total - s_failures, total);
    return s_failures;
}
