cmake_minimum_required(VERSION 3.14)
project(regexlib-test CXX)

enable_testing()

# Behavioral test suite: API surface, grapheme semantics, anchors/classes,
# captures, find_all/search, resource limits.
add_executable(regexlib_test regexlib_test.cc)
target_link_libraries(regexlib_test PRIVATE regexlib)
add_test(NAME regexlib_test COMMAND regexlib_test)

# std::regex-compatible API (regexlib::compat, in regexlib.h). Asserts ASCII parity with
# std::regex and pins the deliberate divergences (UTF-8 code-point semantics,
# ReDoS-safe rejection of pathological patterns).
add_executable(regexlib_std_compat_test regexlib_std_compat_test.cc)
target_link_libraries(regexlib_std_compat_test PRIVATE regexlib)
add_test(NAME regexlib_std_compat_test COMMAND regexlib_std_compat_test)

# Differential for the lazy scan(): its full match sequence (whole-match and
# every capture-group span) must equal the eager find_all() across all tiers,
# captures, empty matches, non-ASCII/CRLF subjects; also pins early-break = prefix
# and Match::to_owned(). find_all() is the independent oracle.
add_executable(regexlib_scan_diff scan_diff.cc)
target_link_libraries(regexlib_scan_diff PRIVATE regexlib)
add_test(NAME regexlib_scan_diff COMMAND regexlib_scan_diff)

# Deterministic regression fuzzer: gates on oracle-free robustness invariants
# (no crash/hang, self-consistent match spans, find_all/search agreement) and
# prints an informational std::regex differential. Run under ASan/UBSan in CI.
add_executable(regexlib_fuzz regexlib_fuzz.cc)
find_package(Threads REQUIRED)
target_link_libraries(regexlib_fuzz PRIVATE regexlib Threads::Threads)
add_test(NAME regexlib_fuzz COMMAND regexlib_fuzz)

# Portable semantic-regression corpus: cases adjudicated once against Python's
# `re` and baked into regexlib_corpus_data.h (no runtime oracle needed). The
# generator lives in regexlib_corpus_gen.{cc,py} and is not built by default.
add_executable(regexlib_corpus regexlib_corpus.cc)
target_link_libraries(regexlib_corpus PRIVATE regexlib)
add_test(NAME regexlib_corpus COMMAND regexlib_corpus)

# Throughput microbenchmark (scratch perf tool, not a correctness gate, not run
# by ctest). Opt-in: `cmake -DBUILD_BENCH=ON`. Compares regexlib vs std::regex,
# and vs RE2 when RE2 is found (pkg-config). Build Release for meaningful numbers.
option(BUILD_BENCH "Build the regexlib throughput benchmark" OFF)
if(BUILD_BENCH)
  add_executable(regexlib_bench regexlib_bench.cc)
  target_link_libraries(regexlib_bench PRIVATE regexlib)

  # The "Sherlock" benchmark reads the standard rust-regex/rebar corpus (the
  # public-domain Adventures of Sherlock Holmes), stored under test/data. The
  # bench skips that section gracefully if the file is absent.
  target_compile_definitions(regexlib_bench PRIVATE
    SHERLOCK_PATH="${CMAKE_SOURCE_DIR}/test/data/sherlock.txt")

  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(RE2 QUIET re2)
    pkg_check_modules(PCRE2 QUIET libpcre2-8)
  endif()
  if(RE2_FOUND)
    target_compile_definitions(regexlib_bench PRIVATE HAS_RE2)
    target_include_directories(regexlib_bench PRIVATE ${RE2_INCLUDE_DIRS})
    target_link_libraries(regexlib_bench PRIVATE ${RE2_LINK_LIBRARIES})
    message(STATUS "regexlib_bench: RE2 ${RE2_VERSION} found, comparison enabled")
  else()
    message(STATUS "regexlib_bench: RE2 not found, skipping RE2 comparison")
  endif()
  if(PCRE2_FOUND)
    target_compile_definitions(regexlib_bench PRIVATE HAS_PCRE2)
    target_include_directories(regexlib_bench PRIVATE ${PCRE2_INCLUDE_DIRS})
    target_link_libraries(regexlib_bench PRIVATE ${PCRE2_LINK_LIBRARIES})
    message(STATUS "regexlib_bench: PCRE2 ${PCRE2_VERSION} found, JIT comparison enabled")
  else()
    message(STATUS "regexlib_bench: PCRE2 not found, skipping PCRE2 comparison")
  endif()

  # rure: the Rust regex crate's C API (crates.io `rure`). The other major
  # linear-time automata engine and the closest apples-to-apples comparison to
  # this library. Rather than vendoring the crate, fetch a pinned release on
  # demand (mirroring the UCD pipeline) and build a static librure.a with cargo.
  # Needs cargo and network access; absent either, rure is skipped gracefully.
  find_program(CARGO_EXE cargo)
  if(CARGO_EXE)
    set(RURE_VERSION 0.2.5)
    set(RURE_SHA256 8af70744723e3d5b88fec7869518bbd17883b7d9944f67c9b4a69ae4ed90dc9a)
    set(RURE_FETCH ${CMAKE_BINARY_DIR}/rure)
    set(RURE_CRATE ${RURE_FETCH}/rure-${RURE_VERSION}.crate)
    set(RURE_DIR ${RURE_FETCH}/rure-${RURE_VERSION})
    if(NOT EXISTS ${RURE_DIR}/Cargo.toml)
      file(MAKE_DIRECTORY ${RURE_FETCH})
      file(DOWNLOAD
        https://static.crates.io/crates/rure/rure-${RURE_VERSION}.crate
        ${RURE_CRATE}
        EXPECTED_HASH SHA256=${RURE_SHA256}
        STATUS RURE_DL TIMEOUT 60)
      list(GET RURE_DL 0 RURE_DL_CODE)
      if(RURE_DL_CODE EQUAL 0)
        # `cmake -E tar` keeps this working on the 3.14 minimum (file(ARCHIVE_EXTRACT)
        # is 3.18+).
        execute_process(
          COMMAND ${CMAKE_COMMAND} -E tar xzf ${RURE_CRATE}
          WORKING_DIRECTORY ${RURE_FETCH})
      else()
        list(GET RURE_DL 1 RURE_DL_MSG)
        message(STATUS "regexlib_bench: rure download failed (${RURE_DL_MSG}), skipping rure comparison")
      endif()
    endif()
    if(EXISTS ${RURE_DIR}/Cargo.toml)
      set(RURE_LIB ${RURE_DIR}/target/release/librure.a)
      add_custom_command(
        OUTPUT ${RURE_LIB}
        # --cap-lints=allow silences the fetched crate's own Rust deprecation
        # warnings (e.g. `extern fn` without an explicit ABI) — third-party code,
        # not actionable here.
        COMMAND ${CMAKE_COMMAND} -E env RUSTFLAGS=--cap-lints=allow
                ${CARGO_EXE} build --release --quiet
        WORKING_DIRECTORY ${RURE_DIR}
        COMMENT "Building rure ${RURE_VERSION} (Rust regex C API) via cargo"
        VERBATIM)
      add_custom_target(rure_build DEPENDS ${RURE_LIB})
      add_dependencies(regexlib_bench rure_build)
      target_compile_definitions(regexlib_bench PRIVATE HAS_RURE)
      target_include_directories(regexlib_bench PRIVATE ${RURE_DIR}/include)
      target_link_libraries(regexlib_bench PRIVATE ${RURE_LIB})
      message(STATUS "regexlib_bench: rure ${RURE_VERSION} (fetched) found, Rust regex comparison enabled")
    endif()
  else()
    message(STATUS "regexlib_bench: cargo not found, skipping rure comparison")
  endif()
endif()
