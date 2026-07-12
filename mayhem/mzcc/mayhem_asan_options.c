/* Overlay-only (not upstream): default ASan/LSan options for the fuzz target.
 * MazuCC is a batch compiler that allocates AST/codegen nodes and simply exits without
 * freeing, so LeakSanitizer would report a leak on EVERY input — aborting each run before
 * the fuzzer explores any edges (and drowning out the real memory-safety / UB defects).
 * Disable leak detection here so the sanitized target halts only on genuine ASan/UBSan
 * errors. Linked into the sanitized build only (build.sh); the clean oracle never sees it.
 * NB: Mayhem's runtime does not honor a host ASAN_OPTIONS env, so this MUST be in-binary. */
__attribute__((used)) const char *__asan_default_options(void) {
    return "detect_leaks=0";
}
