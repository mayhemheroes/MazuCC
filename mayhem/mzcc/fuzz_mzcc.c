/*
 * mayhem/mzcc/fuzz_mzcc.c — in-process libFuzzer harness for MazuCC.
 *
 * MazuCC's CLI (`mzcc file.c`) reads the source from stdin (main.c freopen's the file onto
 * stdin), parses it into an AST via read_toplevels(), and emits x86-64 assembly to `outfp`.
 * The archived original Mayhem target fuzzed that whole file->parse->codegen path. We reproduce
 * exactly that code path in-process (SAME functions: read_toplevels + emit_data_section +
 * emit_toplevel), which is what lets Mayhem's libFuzzer engine collect edge coverage — the raw
 * CLI target recorded 0 edges because Mayhem's "compatible analysis" for a plain sanitizer binary
 * runs no coverage tracer (SPEC.md item 11).
 *
 * Two upstream design facts make a naive in-process call impossible, handled additively here
 * (NO upstream edits):
 *   1. On ANY lex/parse error (and every assert), util.h's errorf() calls exit(1). In-process that
 *      would end the whole fuzzer on input #0. We intercept exit at LINK time (-Wl,--wrap=exit):
 *      __wrap_exit longjmp()s back into the harness while a run is active, and defers to the real
 *      exit otherwise (so libFuzzer/sanitizer shutdown still works).
 *   2. The lexer reads via getc(stdin). We point stdin at an fmemopen() stream over the fuzz bytes
 *      for the duration of the run, then restore it.
 * Codegen output is sent to /dev/null (we fuzz the compiler, not its stdout).
 */
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mzcc.h"

extern FILE *outfp; /* codegen_x64.c */

/*
 * MazuCC has genuine infinite-loop paths on malformed input (e.g. an unterminated /* block
 * comment: skip_block_comment loops forever at EOF — the raw upstream CLI hangs on it too). A
 * hang, unlike a crash, would stall the fuzzer at 0 progress instead of being reported. A per-
 * input SIGALRM converts such a hang into an ABORT with the reproducer saved — it SURFACES the
 * bug (does not hide it), exactly as libFuzzer's own -timeout would, and lets the engine keep
 * exploring other inputs. HANG_SECS is generous so only true loops trip it, not slow parses.
 */
#define HANG_SECS 10
static void on_alarm(int sig)
{
    (void) sig;
    static const char msg[] = "harness: input timed out (infinite loop in mzcc) -> abort\n";
    ssize_t r = write(2, msg, sizeof(msg) - 1);
    (void) r;
    abort();
}

/* --wrap=exit: bounce exit() back into the harness while a run is active. */
extern void __real_exit(int status) __attribute__((noreturn));
static jmp_buf g_jb;
static volatile int g_active = 0;

void __wrap_exit(int status)
{
    if (g_active) {
        g_active = 0;
        longjmp(g_jb, status ? status : 1);
    }
    __real_exit(status);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    (void) argv;
    signal(SIGALRM, on_alarm);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FILE *in = fmemopen((void *) Data, Size, "r");
    if (!in)
        return 0;
    FILE *devnull = fopen("/dev/null", "w");

    FILE *saved_stdin = stdin;
    stdin = in;
    outfp = devnull ? devnull : stderr;

    alarm(HANG_SECS);
    g_active = 1;
    if (setjmp(g_jb) == 0) {
        List *toplevels = read_toplevels();
        emit_data_section();
        for (Iter i = list_iter(toplevels); !iter_end(i);) {
            Ast *v = iter_next(&i);
            emit_toplevel(v);
        }
    }
    g_active = 0;
    alarm(0);

    stdin = saved_stdin;
    fclose(in);
    if (devnull)
        fclose(devnull);
    return 0;
}
