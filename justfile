set shell := ["bash", "-cu"]

default:
    @just --list

build:
    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build

test: build
    ctest --test-dir build --output-on-failure

# Build the suite with ASan + UBSan and run it (catches UB the fuzzer relies on
# being instrumented to surface). RelWithDebInfo (-O2 -g) keeps the sanitizers
# fully instrumenting while running optimized code — an order of magnitude
# faster than -O0, with readable traces (-g, frame pointers) and closer to what
# ships than an unoptimized build.
test-asan:
    cmake -B build-asan -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
    cmake --build build-asan
    ctest --test-dir build-asan --output-on-failure

# Build + run the throughput benchmark (opt-in; uses RE2/PCRE2/rure if present).
# Pass --md to print GitHub-markdown tables to stdout instead of the text log,
# e.g. `just bench --md` or `just bench 20 --md`.
bench *args="10":
    cmake -B build-bench -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCH=ON
    cmake --build build-bench --target regexlib_bench
    ./build-bench/test/regexlib_bench {{args}}

# Check that backtick identifiers in docs/*.md and README.md still exist in
# regexlib.h / test/*.cc (catches doc rot from renames). Also run by CI.
lint-docs:
    python3 tools/check_doc_identifiers.py

clean:
    rm -rf build build-asan build-bench
