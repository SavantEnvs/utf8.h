#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# utf8.h is a single header: every function is defined in utf8.h itself, so compiling each
# harness with $SANITIZER_FLAGS instruments the whole library (there is no separate lib to build).
OUT="$SRC/mayhem/out"           # gitignored (mayhem/.gitignore)
mkdir -p "$OUT"
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -I$SRC -I$SRC/mayhem/harnesses"

# 1) LeakSanitizer off-switch (SPEC §6.2 item 15), linked into every fuzz + standalone binary.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

# 2) Each harness twice: the libFuzzer binary and the run-once standalone reproducer.
#    Linked with $CXX because lsan_off.o is C++.
for h in valid len codepoint casecmp search copy; do
  # fuzzer object: SanCov-instrumented (the header's code is compiled in this TU)
  $CC $FUZZ_CFLAGS -fsanitize=fuzzer-no-link -c "$SRC/mayhem/harnesses/fuzz_$h.c" -o "$OUT/fuzz_$h.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/fuzz_$h.o" "$OUT/lsan_off.o" \
      -o "$SRC/fuzz-$h"
  # standalone object: no SanCov, so it links without the libFuzzer runtime
  $CC $FUZZ_CFLAGS -c "$SRC/mayhem/harnesses/fuzz_$h.c" -o "$OUT/fuzz_$h-standalone.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/fuzz_$h-standalone.o" "$OUT/lsan_off.o" \
      -o "$SRC/fuzz-$h-standalone"
done

# 3) Upstream's own utest suite (test/CMakeLists.txt's utf8_test: the same sources, each under the
#    C/C++ standard upstream assigns it), built with NORMAL flags so test.sh only runs it. Compiled
#    directly rather than through CMake: upstream's CMake adds -Weverything -Werror and builds extra
#    sanitizer variants (thread/memory) that are not part of the functional oracle.
T="$SRC/test"
TOBJ="$OUT/test"
mkdir -p "$TOBJ"
TFLAGS="-O1 -I$SRC $COVERAGE_FLAGS"
$CC  $TFLAGS -std=gnu89 -c "$T/main.c"   -o "$TOBJ/main.o"
$CC  $TFLAGS -std=gnu89 -c "$T/test.c"   -o "$TOBJ/test_c.o"
$CC  $TFLAGS -std=c99   -c "$T/test99.c" -o "$TOBJ/test99.o"
$CC  $TFLAGS -std=c11   -c "$T/test11.c" -o "$TOBJ/test11_c.o"
$CXX $TFLAGS            -c "$T/test.cpp"   -o "$TOBJ/test_cpp.o"
$CXX $TFLAGS -std=gnu++98 -c "$T/test98.cpp" -o "$TOBJ/test98.o"
$CXX $TFLAGS -std=c++11 -c "$T/test11.cpp" -o "$TOBJ/test11_cpp.o"
$CXX $TFLAGS -std=c++14 -c "$T/test14.cpp" -o "$TOBJ/test14.o"
$CXX $TFLAGS -std=c++17 -c "$T/test17.cpp" -o "$TOBJ/test17.o"
$CXX $TFLAGS -std=c++20 -c "$T/test20.cpp" -o "$TOBJ/test20.o"
$CXX $TFLAGS -std=c++20 -fno-char8_t -c "$T/test20_no_char_t.cpp" -o "$TOBJ/test20_no_char_t.o"
$CXX $TFLAGS "$TOBJ"/*.o -o "$OUT/utf8_test"
$CC  $TFLAGS -c "$T/no_malloc.c" -o "$OUT/no_malloc.o"
$CC  $TFLAGS "$OUT/no_malloc.o" -o "$OUT/utf8_no_malloc_test"
echo "build.sh: built $(ls "$SRC"/fuzz-* | wc -l) fuzz binaries and the utest suite"
