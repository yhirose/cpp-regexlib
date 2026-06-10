// Throughput microbenchmark for regexlib.
//
// Process-internal timing (median over N iterations), reporting MB/s so the
// numbers are corpus-size independent. Each case is built to stress one of the
// engine's dispatch paths / known bottlenecks; see the case table in main().
//
// Compared engines:
//   - regexlib   (this library, always built)
//   - std::regex (C++ standard, always built)
//   - RE2        (optional; built only when HAS_RE2 is defined via CMake)
//   - rure       (optional; Rust regex crate via its C API — the other major
//                 linear-time automata engine. Built when HAS_RURE is defined.)
//   - PCRE2-JIT  (optional; backtracking, shown as a non-linear contrast point)
//
// Usage:  regexlib_bench [iterations]      (default 10)
//
// This is a scratch perf tool, NOT a correctness gate — the fuzzer and corpus
// suites own correctness. MB/s is absolute and machine-dependent; treat the
// per-engine ratios as the portable signal.

#include "regexlib.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

#include <fcntl.h>  // open (silencing stdout in --md mode)
#include <unistd.h> // dup, dup2

#ifdef HAS_RE2
#include <re2/re2.h>
#endif

#ifdef HAS_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#ifdef HAS_RURE
#include <rure.h>
#endif

using namespace std;

//===--------------------------------------------------------------------===//
// Markdown sink (for `--md`: emit GitHub-flavored tables on stdout instead of
// the usual human-readable text). Rows are collected during the run and written
// out at the end.
//===--------------------------------------------------------------------===//

static bool g_md = false;

// One benchmarked row: a (case, pattern) and each engine's metric value. Reused
// for the throughput table (value = MB/s) and the compile table (value = ns).
struct MdRow {
  string name;
  string pattern;
  vector<pair<string, double>> cells; // engine -> value (already filtered)
};

static vector<MdRow> g_md_throughput; // run time, MB/s (higher is faster)
static vector<MdRow> g_md_compile;    // compile time, ns (lower is faster)

// Real-world workload groups, each emitted as its own markdown table.
// Throughput groups carry MB/s (higher is faster); latency groups carry
// ns/call (lower is faster).
static vector<MdRow> g_md_log;       // log parsing throughput
static vector<MdRow> g_md_markup;    // template / config / markup throughput
static vector<MdRow> g_md_lat_http;  // per-call latency: cpp-httplib
static vector<MdRow> g_md_lat_lexer; // per-call latency: lexer / tokenizer
static vector<MdRow> g_md_lat_valid; // per-call latency: data validation
static vector<MdRow> g_md_redos;     // ReDoS immunity (linear engines only)

// run_case appends its cross-engine row here; the throughput-group runner
// repoints it so each group lands in its own table. Defaults to the main
// throughput table (the synthetic + Sherlock cases).
static vector<MdRow> *g_md_run_sink = &g_md_throughput;

// Engines shown as columns, in this order; only those actually present appear.
static const char *kMdEngineOrder[] = {"regexlib", "std::regex", "RE2",
                                       "rure",     "PCRE2-JIT",  "PCRE2"};

static void write_md_table(ostream &out, const string &title,
                           const string &unit, bool higher_is_faster,
                           const vector<MdRow> &rows) {
  if (rows.empty()) return;
  // Columns = engines present in at least one row, in kMdEngineOrder.
  vector<string> cols;
  for (const char *e : kMdEngineOrder) {
    for (const auto &r : rows)
      for (const auto &c : r.cells)
        if (c.first == e) {
          cols.push_back(e);
          goto next_engine;
        }
  next_engine:;
  }
  out << "### " << title << "  (" << unit << ", "
      << (higher_is_faster ? "higher is faster" : "lower is faster") << ")\n\n";
  out << "| case | pattern |";
  for (auto &c : cols)
    out << " " << c << " |";
  out << "\n|---|---|";
  for (size_t i = 0; i < cols.size(); i++)
    out << "--:|";
  out << "\n";
  // A literal '|' inside a GFM table cell breaks the column layout even within
  // a code span, so escape it as '\|'.
  auto esc = [](const string &s) {
    string o;
    for (char ch : s) {
      if (ch == '|')
        o += "\\|";
      else
        o += ch;
    }
    return o;
  };
  for (const auto &r : rows) {
    out << "| " << esc(r.name) << " | `" << esc(r.pattern) << "` |";
    for (auto &col : cols) {
      double v = -1;
      for (const auto &c : r.cells)
        if (c.first == col) {
          v = c.second;
          break;
        }
      char buf[32];
      if (v < 0)
        snprintf(buf, sizeof buf, " — ");
      else
        snprintf(buf, sizeof buf, " %.0f ", v);
      out << buf << "|";
    }
    out << "\n";
  }
  out << "\n";
}

//===--------------------------------------------------------------------===//
// Timing
//===--------------------------------------------------------------------===//

struct BenchResult {
  string engine;
  vector<double> ms;               // per-iteration wall time
  size_t bytes = 0;                // subject bytes processed per iteration
  unsigned long long checksum = 0; // anti-DCE accumulator (match work)

  double median() const {
    auto s = ms;
    sort(s.begin(), s.end());
    auto n = s.size();
    if (n == 0) return 0;
    return n % 2 ? s[n / 2] : (s[n / 2 - 1] + s[n / 2]) / 2.0;
  }

  double mbps() const {
    double sec = median() / 1000.0;
    return sec > 0 ? (bytes / sec) / 1e6 : 0;
  }
};

// Run `func` (which returns the per-iteration checksum) `iters` times after a
// warmup, recording wall time per iteration.
template <typename F>
BenchResult bench(const string &engine, size_t bytes, int iters, F func) {
  BenchResult r;
  r.engine = engine;
  r.bytes = bytes;
  func(); // warmup (also forces lazy DFA / regex compilation caches)
  for (int i = 0; i < iters; i++) {
    auto t0 = chrono::high_resolution_clock::now();
    auto sum = func();
    auto t1 = chrono::high_resolution_clock::now();
    r.checksum = sum;
    r.ms.push_back(chrono::duration_cast<chrono::nanoseconds>(t1 - t0).count() /
                   1e6);
  }
  return r;
}

//===--------------------------------------------------------------------===//
// Corpus generators (deterministic: fixed-seed mt19937)
//===--------------------------------------------------------------------===//

// ~target_bytes of lowercase words separated by single spaces. Word lengths
// 1..12. Optionally sprinkle the literals fox/dog/cat at ~1/`needle_period`
// word positions (for the literal-alternation case).
static string make_words(size_t target_bytes, int needle_period = 0) {
  mt19937 rng(0xC0FFEE);
  uniform_int_distribution<int> len(1, 12);
  uniform_int_distribution<int> ch(0, 25);
  uniform_int_distribution<int> pick(0, 2);
  static const char *needles[] = {"fox", "dog", "cat"};
  string out;
  out.reserve(target_bytes + 16);
  size_t wi = 0;
  while (out.size() < target_bytes) {
    if (!out.empty()) out.push_back(' ');
    if (needle_period && (wi % needle_period) == 0) {
      out += needles[pick(rng)];
    } else {
      int n = len(rng);
      for (int i = 0; i < n; i++)
        out.push_back(char('a' + ch(rng)));
    }
    wi++;
  }
  return out;
}

// Same as make_words, but inject a single non-ASCII grapheme near the middle.
// One non-ASCII byte flips is_ascii() for the WHOLE subject, disabling every
// DFA tier — this case measures the depth of that cliff vs the pure-ASCII one.
static string make_words_one_nonascii(size_t target_bytes) {
  string s = make_words(target_bytes);
  s.insert(s.size() / 2, "\xC3\xA9"); // 'é' (U+00E9, 2 bytes UTF-8)
  return s;
}

// ~target_bytes of "key=value" pairs separated by spaces (key/value are 2..8
// lowercase letters). Drives multi-group captures like (\w+)=(\w+), where each
// group is a distinct span — the case the code-point one-pass engine targets.
static string make_kv_pairs(size_t target_bytes) {
  mt19937 rng(0xC0FFEE);
  uniform_int_distribution<int> len(2, 8);
  uniform_int_distribution<int> ch(0, 25);
  string out;
  out.reserve(target_bytes + 16);
  while (out.size() < target_bytes) {
    if (!out.empty()) out.push_back(' ');
    int k = len(rng);
    for (int i = 0; i < k; i++)
      out.push_back(char('a' + ch(rng)));
    out.push_back('=');
    int v = len(rng);
    for (int i = 0; i < v; i++)
      out.push_back(char('a' + ch(rng)));
  }
  return out;
}

// Many small ASCII documents (stresses per-call DFA setup amortization).
static vector<string> make_docs(size_t doc_bytes, size_t count) {
  vector<string> docs;
  docs.reserve(count);
  for (size_t i = 0; i < count; i++) {
    // Vary the seed per doc so contents differ but stay deterministic.
    mt19937 rng(0xD0C00 + i);
    uniform_int_distribution<int> len(1, 12);
    uniform_int_distribution<int> ch(0, 25);
    string out;
    while (out.size() < doc_bytes) {
      if (!out.empty()) out.push_back(' ');
      int n = len(rng);
      for (int k = 0; k < n; k++)
        out.push_back(char('a' + ch(rng)));
    }
    docs.push_back(std::move(out));
  }
  return docs;
}

// ~target_bytes of Combined-Log-Format access-log lines (one per line). Each
// line has a real structure: client IP, ident/user, [timestamp], "METHOD path
// proto", status, size. Drives the access-log parse and IPv4-extraction cases.
static string make_logs(size_t target_bytes) {
  mt19937 rng(0xACCE55);
  uniform_int_distribution<int> oct(1, 254), sec(0, 59), sz(0, 999999),
      mpick(0, 4), ppick(0, 4), spick(0, 4);
  static const char *methods[] = {"GET", "POST", "PUT", "DELETE", "HEAD"};
  static const char *paths[] = {"/", "/index.html", "/api/v1/users",
                                "/img/logo.png", "/search?q=regex"};
  static const int statuses[] = {200, 301, 404, 500, 403};
  string out;
  out.reserve(target_bytes + 128);
  char line[256];
  while (out.size() < target_bytes) {
    int n = snprintf(
        line, sizeof line,
        "%d.%d.%d.%d - - [10/Oct/2000:13:55:%02d -0700] \"%s %s HTTP/1.0\" %d "
        "%d\n",
        oct(rng), oct(rng), oct(rng), oct(rng), sec(rng), methods[mpick(rng)],
        paths[ppick(rng)], statuses[spick(rng)], sz(rng));
    out.append(line, static_cast<size_t>(n));
  }
  return out;
}

// ~target_bytes of mixed lightweight markup: mustache-style template variables
// ({{ var }}), markdown links ([text](url)), and key=value config, one record
// per line. One corpus feeds all three template/config/markup cases (a real
// document mixes these constructs).
static string make_markup_doc(size_t target_bytes) {
  mt19937 rng(0xDADA);
  uniform_int_distribution<int> wlen(3, 9), ch(0, 25), num(1, 9999);
  auto word = [&] {
    string s;
    int n = wlen(rng);
    for (int i = 0; i < n; i++)
      s.push_back(char('a' + ch(rng)));
    return s;
  };
  string out;
  out.reserve(target_bytes + 128);
  while (out.size() < target_bytes) {
    out += "Hello {{ " + word() + " }}, read [" + word() + " " + word() +
           "](https://example.com/" + word() + ") timeout=" +
           to_string(num(rng)) + "\n";
  }
  return out;
}

//===--------------------------------------------------------------------===//
// Per-engine find_all match counters (return a checksum to defeat DCE)
//===--------------------------------------------------------------------===//

static unsigned long long count_regexlib(const reg::Regex &re,
                                         const vector<string> &docs) {
  unsigned long long sum = 0;
  for (auto &d : docs)
    for (auto m : re.find_iter(d))
      sum += m.end() - m.begin();
  return sum;
}

// Same, but a caller-owned FindCache reused across all docs — persists the DFA
// so docs 2..N (and, when the cache outlives the timed loop, iterations 2..N)
// pay no per-call construction (the B-4 win).
static unsigned long long count_regexlib_cached(const reg::Regex &re,
                                                const vector<string> &docs,
                                                reg::Regex::FindCache &cache) {
  unsigned long long sum = 0;
  for (auto &d : docs)
    for (auto m : re.find_iter(d, cache))
      sum += m.end() - m.begin();
  return sum;
}

static unsigned long long count_std(const std::regex &re,
                                    const vector<string> &docs) {
  unsigned long long sum = 0;
  for (auto &d : docs) {
    for (auto it = sregex_iterator(d.begin(), d.end(), re);
         it != sregex_iterator(); ++it)
      sum += it->length();
  }
  return sum;
}

#ifdef HAS_RE2
static unsigned long long count_re2(const RE2 &re, const vector<string> &docs) {
  unsigned long long sum = 0;
  for (auto &d : docs) {
    re2::StringPiece text(d);
    re2::StringPiece sub[1]; // submatch[0] = whole match (works with 0 groups)
    size_t pos = 0;
    while (pos <= text.size() &&
           re.Match(text, pos, text.size(), RE2::UNANCHORED, sub, 1)) {
      size_t b = sub[0].data() - text.data();
      size_t e = b + sub[0].size();
      sum += sub[0].size();
      pos = (e > b) ? e : e + 1; // advance past an empty match
    }
  }
  return sum;
}
#endif

#ifdef HAS_RURE
// find_all over `docs` with the Rust regex crate via its C API (rure). The
// iterator yields successive non-overlapping leftmost-first matches and
// advances past empty matches internally — same find_all semantics as the RE2
// loop above.
static unsigned long long count_rure(rure *re, const vector<string> &docs) {
  unsigned long long sum = 0;
  for (auto &d : docs) {
    auto h = reinterpret_cast<const uint8_t *>(d.data());
    rure_iter *it = rure_iter_new(re);
    rure_match m;
    while (rure_iter_next(it, h, d.size(), &m))
      sum += m.end - m.start;
    rure_iter_free(it);
  }
  return sum;
}
#endif

#ifdef HAS_PCRE2
// find_all over `docs` using a compiled (optionally JIT-compiled) PCRE2 code.
// `jit` selects pcre2_jit_match vs pcre2_match (same signature, same result).
static unsigned long long count_pcre2(pcre2_code *code, pcre2_match_data *md,
                                      bool jit, const vector<string> &docs) {
  unsigned long long sum = 0;
  for (auto &d : docs) {
    auto subject = reinterpret_cast<PCRE2_SPTR>(d.data());
    size_t len = d.size(), off = 0;
    while (off <= len) {
      int rc = jit ? pcre2_jit_match(code, subject, len, off, 0, md, nullptr)
                   : pcre2_match(code, subject, len, off, 0, md, nullptr);
      if (rc < 0) break; // PCRE2_ERROR_NOMATCH or error -> done with this doc
      PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
      size_t b = ov[0], e = ov[1];
      sum += e - b;
      off = (e > b) ? e : e + 1; // advance past an empty match
    }
  }
  return sum;
}
#endif

//===--------------------------------------------------------------------===//
// Case driver
//===--------------------------------------------------------------------===//

// Test-only marker in Case::rl_flags: build the regexlib row in CodePoint
// (UnicodeScalar) match-unit mode. The unit is a process-wide default now
// (reg::set_default_match_unit), so run_case toggles it around construction.
static constexpr unsigned kRlUS = 1u << 16;

struct Case {
  string name;           // human label
  string pattern;        // portable across all three engines
  bool boolean = false;  // true -> measure test()/PartialMatch, else find_all
  vector<string> docs;   // subject(s)
  unsigned rl_flags = 0; // regexlib-only flags; kRlUS = build in CodePoint
                         // (UnicodeScalar) match-unit mode (a process-wide
                         // default now, toggled around construction). The other
                         // engines (RE2/Rust are already code-point) run the
                         // bare pattern, so the comparison stays apples-to-apples.
};

static size_t total_bytes(const vector<string> &docs) {
  size_t n = 0;
  for (auto &d : docs)
    n += d.size();
  return n;
}

static void run_case(const Case &c, int iters) {
  size_t bytes = total_bytes(c.docs);
  cout << "\n"
       << c.name << "  /" << c.pattern << "/  (" << (bytes / 1024) << " KB, "
       << c.docs.size() << " doc" << (c.docs.size() == 1 ? "" : "s") << ", "
       << (c.boolean ? "test" : "find_all") << ")" << endl;

  vector<BenchResult> results;

  // --- regexlib ---
  {
    bool us = (c.rl_flags & kRlUS) != 0;
    if (us) reg::set_default_match_unit(reg::MatchUnit::CodePoint);
    reg::Regex re(c.pattern, c.rl_flags & ~kRlUS);
    if (us) reg::set_default_match_unit(reg::MatchUnit::Grapheme);
    if (c.boolean) {
      results.push_back(bench("regexlib", bytes, iters, [&] {
        unsigned long long s = 0;
        for (auto &d : c.docs)
          s += re.test(d) ? 1 : 0;
        return s;
      }));
    } else {
      results.push_back(bench("regexlib", bytes, iters,
                              [&] { return count_regexlib(re, c.docs); }));
      // Reused FindCache across docs AND iterations (hoisted out of the timed
      // lambda): persists the DFA (B-4). Same checksum.
      reg::Regex::FindCache cache;
      results.push_back(bench("regexlib(cache)", bytes, iters, [&] {
        return count_regexlib_cached(re, c.docs, cache);
      }));
      // Lazy scan(): view handles, no per-match std::string copies. Isolates
      // result-materialization cost (same checksum as the count above).
      results.push_back(bench("regexlib(scan)", bytes, iters, [&] {
        unsigned long long s = 0;
        for (auto &d : c.docs)
          for (auto m : re.find_iter(d))
            s += m.end() - m.begin();
        return s;
      }));
      // Columnar matches() + a reused FindCache (the recommended loop usage):
      // removes BOTH per-match materialization (columnar) and per-doc/iteration
      // DFA construction (cache hoisted out of the timed lambda). Borrows each
      // doc. Checksum matches find_all.
      reg::Regex::FindCache mcache;
      results.push_back(bench("regexlib(matches+cache)", bytes, iters, [&] {
        unsigned long long s = 0;
        for (auto &d : c.docs)
          for (auto m : re.find_all(std::string_view(d), mcache))
            s += m.end() - m.begin();
        return s;
      }));
    }
  }

  // --- std::regex ---  (ECMAScript: no \p{...}; skip the engine if it can't
  // compile the pattern rather than aborting the whole run)
  try {
    std::regex re(c.pattern, std::regex::ECMAScript);
    if (c.boolean) {
      results.push_back(bench("std::regex", bytes, iters, [&] {
        unsigned long long s = 0;
        for (auto &d : c.docs)
          s += regex_search(d, re) ? 1 : 0;
        return s;
      }));
    } else {
      results.push_back(bench("std::regex", bytes, iters,
                              [&] { return count_std(re, c.docs); }));
    }
  } catch (const std::exception &) {
    cout << "    std::regex               (pattern unsupported)" << endl;
  }

#ifdef HAS_RE2
  // --- RE2 ---
  {
    RE2 re(c.pattern);
    if (c.boolean) {
      results.push_back(bench("RE2", bytes, iters, [&] {
        unsigned long long s = 0;
        for (auto &d : c.docs)
          s += RE2::PartialMatch(d, re) ? 1 : 0;
        return s;
      }));
    } else {
      results.push_back(
          bench("RE2", bytes, iters, [&] { return count_re2(re, c.docs); }));
    }
  }
#endif

#ifdef HAS_RURE
  // --- rure (Rust regex crate) ---
  // RURE_DEFAULT_FLAGS enables Unicode, so \w etc. are code-point classes —
  // matching RE2's default and keeping the comparison apples-to-apples (the
  // regexlib rows for the bare pattern run in EGC/US mode per c.rl_flags).
  {
    rure_error *err = rure_error_new();
    rure *re = rure_compile(reinterpret_cast<const uint8_t *>(c.pattern.data()),
                            c.pattern.size(), RURE_DEFAULT_FLAGS, nullptr, err);
    if (!re) {
      cerr << "    rure compile failed for /" << c.pattern
           << "/: " << rure_error_message(err) << endl;
    } else {
      if (c.boolean) {
        results.push_back(bench("rure", bytes, iters, [&] {
          unsigned long long s = 0;
          for (auto &d : c.docs)
            s += rure_is_match(re, reinterpret_cast<const uint8_t *>(d.data()),
                               d.size(), 0)
                     ? 1
                     : 0;
          return s;
        }));
      } else {
        results.push_back(bench("rure", bytes, iters,
                                [&] { return count_rure(re, c.docs); }));
      }
      rure_free(re);
    }
    rure_error_free(err);
  }
#endif

#ifdef HAS_PCRE2
  // --- PCRE2 (JIT) ---
  {
    int errcode = 0;
    PCRE2_SIZE erroff = 0;
    pcre2_code *code = pcre2_compile(
        reinterpret_cast<PCRE2_SPTR>(c.pattern.data()), c.pattern.size(),
        /*options=*/0, &errcode, &erroff, nullptr);
    if (!code) {
      cerr << "    PCRE2 compile failed for /" << c.pattern << "/" << endl;
    } else {
      bool jit = pcre2_jit_compile(code, PCRE2_JIT_COMPLETE) == 0;
      const char *label = jit ? "PCRE2-JIT" : "PCRE2";
      pcre2_match_data *md =
          pcre2_match_data_create_from_pattern(code, nullptr);
      if (c.boolean) {
        results.push_back(bench(label, bytes, iters, [&] {
          unsigned long long s = 0;
          for (auto &d : c.docs) {
            auto subj = reinterpret_cast<PCRE2_SPTR>(d.data());
            int rc =
                jit ? pcre2_jit_match(code, subj, d.size(), 0, 0, md, nullptr)
                    : pcre2_match(code, subj, d.size(), 0, 0, md, nullptr);
            s += (rc >= 0) ? 1 : 0;
          }
          return s;
        }));
      } else {
        results.push_back(bench(label, bytes, iters, [&] {
          return count_pcre2(code, md, jit, c.docs);
        }));
      }
      pcre2_match_data_free(md);
      pcre2_code_free(code);
    }
  }
#endif

  // Report, fastest first, with ratio vs regexlib as the baseline.
  double base = results.front().mbps(); // regexlib is always first
  for (auto &r : results) {
    double ratio = base > 0 ? r.mbps() / base : 0;
    printf("    %-24s %9.2f MB/s   %8.3f ms   %.2fx vs regexlib   (sum=%llu)\n",
           r.engine.c_str(), r.mbps(), r.median(), ratio, r.checksum);
  }

  // Markdown row: one cross-engine comparison (skip the regexlib(...) variants
  // so the table stays a clean per-engine apples-to-apples view).
  if (g_md) {
    MdRow row{c.name, c.pattern, {}};
    for (auto &r : results)
      if (r.engine.rfind("regexlib(", 0) != 0) // keep "regexlib", drop variants
        row.cells.push_back({r.engine, r.mbps()});
    g_md_run_sink->push_back(std::move(row));
  }
}

//===--------------------------------------------------------------------===//
// Sherlock benchmark
//
// The de-facto-standard real-world regex benchmark: a set of patterns run over
// the full text of "The Adventures of Sherlock Holmes" (public domain; the same
// corpus the Rust regex / rebar suites use, already vendored with rure). Unlike
// the synthetic random-word cases above, this is natural-language prose, and
// the patterns exercise paths those cases miss: case-insensitive literal
// search, name alternations (Teddy), \s joins, word boundaries (Pike), bounded
// ".{0,n}" proximity, negated-class repetition, suffixes, multiline anchors,
// and Unicode categories. The pattern set mirrors the canonical rebar
// "sherlock" group; the pattern strings are facts, not copyrightable, and the
// bench code is original.
//
// NOTE: the corpus is UTF-8 with ~33 non-ASCII bytes (a BOM and a few curly
// quotes, 0.006%). That is enough to flip is_ascii() for the whole subject and
// take regexlib off its ASCII fast paths (prefix memmem skip, DFA tiers) onto
// the grapheme engine — so these numbers expose regexlib's non-ASCII cliff on
// real- world text. RE2/Rust handle UTF-8 natively and have no such cliff,
// hence the large gap on literal/sparse patterns. See docs / the EGC byte path
// work.
//===--------------------------------------------------------------------===//
static string load_file(const char *path) {
  if (!path || !*path) return "";
  FILE *f = fopen(path, "rb");
  if (!f) return "";
  string s;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  if (n > 0) {
    s.resize(static_cast<size_t>(n));
    fseek(f, 0, SEEK_SET);
    size_t got = fread(&s[0], 1, s.size(), f);
    s.resize(got);
  }
  fclose(f);
  return s;
}

static void run_sherlock_bench(int iters) {
#ifdef SHERLOCK_PATH
  string text = load_file(SHERLOCK_PATH);
#else
  string text;
#endif
  if (text.empty()) {
    cout << "\n\n(Sherlock benchmark skipped: corpus not found)\n";
    return;
  }
  cout << "\n\nSherlock benchmark  (" << (text.size() / 1024)
       << " KB of English prose, find_all unless noted)\n"
       << string(72, '=') << endl;

  // Mirrors the canonical rebar "sherlock" patterns; each exercises a distinct
  // engine path. boolean=true measures test()/is_match instead of find_all.
  vector<Case> cases = {
      {"name: Sherlock", "Sherlock", false, {text}},
      {"name: Sherlock (nocase)", "(?i)Sherlock", false, {text}},
      {"name: Sherlock Holmes", "Sherlock Holmes", false, {text}},
      {"name: Sherlock\\s+Holmes", "Sherlock\\s+Holmes", false, {text}},
      {"names alternation",
       "Sherlock|Holmes|Watson|Irene|Adler|John|Baker",
       false,
       {text}},
      {"the (nocase, dense)", "(?i)the", false, {text}},
      {"words \\w+", "\\w+", false, {text}},
      {"word before Holmes", "\\w+\\s+Holmes", false, {text}},
      {"Holmes near Watson",
       "Holmes.{0,25}Watson|Watson.{0,25}Holmes",
       false,
       {text}},
      {"word ending n", "\\b\\w+n\\b", false, {text}},
      {"negated-class repeat", "[a-q][^u-z]{13}x", false, {text}},
      {"negated-class repeat, US", "[a-q][^u-z]{13}x", false, {text}, kRlUS},
      {"ing suffix", "[a-zA-Z]+ing", false, {text}},
      {"multiline name anchor",
       "(?m)^Sherlock Holmes|Sherlock Holmes$",
       false,
       {text}},
      {"letters \\p{L}+", "\\p{L}+", false, {text}},
      {"quoted span", "[\"'][^\"']{0,30}[?!.][\"']", false, {text}},
      {"no match (rare literal)", "zqj", true, {text}},
  };
  for (auto &c : cases)
    run_case(c, iters);

  // Same patterns over an ASCII-FOLDED copy of the corpus (every byte >= 0x80
  // replaced by a space). The corpus above is non-ASCII (~33 bytes: BOM, curly
  // quotes, accents), which sends every subject down the EGC byte path — so the
  // pure-ASCII DFA tiers are NEVER exercised by the section above. That blind
  // spot hid a 7x literal-find regression on ASCII subjects (the common case:
  // logs, code, ASCII prose). These rows make the ASCII path visible; compare
  // each to its non-ASCII twin above. (Same engine; RE2/rure are code-point so
  // ASCII vs non-ASCII barely moves them.)
  string ascii = text;
  for (char &ch : ascii)
    if (static_cast<unsigned char>(ch) >= 0x80) ch = ' ';
  cout << "\n\nSherlock benchmark — ASCII-folded subject (exercises the ASCII "
          "DFA tiers)\n"
       << string(72, '=') << endl;
  vector<Case> ascii_cases = {
      {"name: Sherlock", "Sherlock", false, {ascii}},
      {"name: Sherlock (nocase)", "(?i)Sherlock", false, {ascii}},
      {"name: Sherlock Holmes", "Sherlock Holmes", false, {ascii}},
      {"the (nocase, dense)", "(?i)the", false, {ascii}},
      {"words \\w+", "\\w+", false, {ascii}},
      {"negated-class repeat", "[a-q][^u-z]{13}x", false, {ascii}},
      {"quoted span", "[\"'][^\"']{0,30}[?!.][\"']", false, {ascii}},
      {"no match (rare literal)", "zqj", true, {ascii}},
  };
  for (auto &c : ascii_cases)
    run_case(c, iters);
}

//===--------------------------------------------------------------------===//
// Per-call match latency (real-world groups)
//
// Real services match short strings against a pre-compiled regex, so the cost
// that matters is per-CALL latency on a small subject — not steady-state
// throughput. The Regex is built ONCE outside the timed loop; we time one
// capture-extracting search() per call (median ns) so every engine does the
// same work. Search (UNANCHORED) is used uniformly; some real callers use
// regex_match, but the automaton run is the dominant cost and search keeps the
// cross-engine comparison apples-to-apples. The pattern tables for each group
// (cpp-httplib, lexer, validation, ReDoS) are defined further below.
//===--------------------------------------------------------------------===//
// Median ns/call helper, defined with the compile-time benchmark below and
// reused here for per-call latency timing.
template <typename F> static double med_ns(int iters, int inner, F op);

struct LPat {
  const char *name;
  const char *pat;
  const char *subj;
  unsigned rl;
};

// Generic per-call latency runner. Times one capture-extracting search() per
// call on each pattern's short subject, for every engine, and reports median
// ns/call (lower is faster). Shared by all the latency-shaped real-world groups
// (cpp-httplib, lexer tokens, field validation, ReDoS).
//
// When `skip_backtrack` is set, the BACKTRACKING engines (std::regex, PCRE2)
// are DISABLED instead of run: the ReDoS group feeds them adversarial inputs
// that trigger catastrophic backtracking and would hang the benchmark, so only
// the linear-time automata engines (regexlib, RE2, rure) are measured. Their
// staying flat IS the result that group reports.
//
// Cross-engine rows are appended to `*md_sink` (the apples-to-apples columns:
// regexlib in US mode + the other engines; the EGC row is text-only).
static void run_latency_group(const string &title, const string &blurb,
                              const vector<LPat> &pats, int iters,
                              bool skip_backtrack, vector<MdRow> *md_sink) {
  const int inner = 200;

  cout << "\n\n" << title << "  (" << iters << " iterations x " << inner
       << " inner, median ns/call)\n"
       << string(72, '=') << "\n  " << blurb << "\n";

  auto esc = [](const string &s) { // show control bytes (\r\n) on one line
    string o;
    for (char c : s) {
      if (c == '\r')
        o += "\\r";
      else if (c == '\n')
        o += "\\n";
      else
        o += c;
    }
    return o;
  };

  for (auto &p : pats) {
    cout << "\n"
         << p.name << "  /" << p.pat << "/  on \"" << esc(p.subj) << "\"\n";
    double base = -1;
    MdRow mrow{p.name, p.pat, {}};
    auto row = [&](const char *name, double ns) {
      if (ns < 0) {
        printf("    %-20s %12s\n", name, "(unsupported)");
      } else {
        if (string(name) == "regexlib (US)") base = ns;
        double ratio = base > 0 ? ns / base : 1.0;
        printf("    %-20s %9.0f ns   %.2fx vs regexlib(US)\n", name, ns, ratio);
      }
      // Markdown carries one apples-to-apples row: regexlib (US) under the plain
      // "regexlib" column, plus the other engines as-is; the EGC row is
      // text-only. A negative ns lands as "—" in the table.
      if (g_md && md_sink) {
        string n = name;
        if (n == "regexlib (US)")
          mrow.cells.push_back({"regexlib", ns});
        else if (n != "regexlib (EGC)")
          mrow.cells.push_back({n, ns});
      }
    };

    const string subj = p.subj;

    // regexlib, measured in BOTH match-unit modes. cpp-httplib parses
    // byte-oriented protocol text, so CodePoint (US) is the natural mode AND the
    // apples-to-apples comparison against the byte/code-point engines (RE2 /
    // rure / std::regex); the ratios are taken against it. EGC (the library
    // default) is shown too: on a CR-LF-bearing subject it does grapheme work
    // the others don't, so it is the honest out-of-the-box number.
    auto measure_regexlib = [&](reg::MatchUnit unit) -> double {
      double ns = -1;
      try {
        reg::set_default_match_unit(unit);
        reg::Regex re(p.pat, p.rl);
        reg::set_default_match_unit(reg::MatchUnit::Grapheme);
        ns = med_ns(iters, inner, [&]() -> unsigned long long {
          auto m = re.search(subj);
          unsigned long long s = 0;
          if (m.matched()) {
            s += m.end();
            for (size_t gi = 0; gi <= m.group_count(); gi++) {
              reg::Match g = m.group(gi);
              if (g.matched()) s += g.end() - g.begin();
            }
          }
          return s;
        });
      } catch (...) { ns = -1; }
      return ns;
    };
    row("regexlib (US)", measure_regexlib(reg::MatchUnit::CodePoint));
    row("regexlib (EGC)", measure_regexlib(reg::MatchUnit::Grapheme));

    // std::regex (the engine cpp-httplib actually links). Backtracking, so it
    // is disabled for the ReDoS group rather than allowed to hang.
    if (skip_backtrack) {
      printf("    %-20s %s\n", "std::regex", "(disabled: backtracking)");
    } else {
      double ns = -1;
      try {
        std::regex re(p.pat, std::regex::ECMAScript);
        ns = med_ns(iters, inner, [&]() -> unsigned long long {
          std::smatch m;
          unsigned long long s = 0;
          if (std::regex_search(subj, m, re)) {
            s += m.length(0);
            for (size_t i = 1; i < m.size(); i++)
              if (m[i].matched) s += m.length(i);
          }
          return s;
        });
      } catch (...) { ns = -1; }
      row("std::regex", ns);
    }

#ifdef HAS_RE2
    {
      double ns = -1;
      RE2 re(p.pat);
      if (re.ok()) {
        int ng = re.NumberOfCapturingGroups();
        vector<re2::StringPiece> sub(ng + 1);
        re2::StringPiece text(subj);
        ns = med_ns(iters, inner, [&]() -> unsigned long long {
          unsigned long long s = 0;
          if (re.Match(text, 0, text.size(), RE2::UNANCHORED, sub.data(),
                       ng + 1))
            for (auto &pc : sub)
              if (pc.data()) s += pc.size();
          return s;
        });
      }
      row("RE2", ns);
    }
#endif

#ifdef HAS_RURE
    {
      double ns = -1;
      rure_error *err = rure_error_new();
      rure *re = rure_compile(reinterpret_cast<const uint8_t *>(p.pat),
                              strlen(p.pat), RURE_DEFAULT_FLAGS, nullptr, err);
      if (re) {
        rure_captures *caps = rure_captures_new(re);
        auto h = reinterpret_cast<const uint8_t *>(subj.data());
        ns = med_ns(iters, inner, [&]() -> unsigned long long {
          unsigned long long s = 0;
          if (rure_find_captures(re, h, subj.size(), 0, caps)) {
            size_t nc = rure_captures_len(caps);
            rure_match mm;
            for (size_t i = 0; i < nc; i++)
              if (rure_captures_at(caps, i, &mm)) s += mm.end - mm.start;
          }
          return s;
        });
        rure_captures_free(caps);
        rure_free(re);
      }
      rure_error_free(err);
      row("rure", ns);
    }
#endif

#ifdef HAS_PCRE2
    // PCRE2 (even JIT) is a backtracking engine: disabled for the ReDoS group.
    if (skip_backtrack) {
      printf("    %-20s %s\n", "PCRE2-JIT", "(disabled: backtracking)");
    } else {
      double ns = -1;
      const char *label = "PCRE2";
      int ec;
      PCRE2_SIZE eo;
      pcre2_code *code = pcre2_compile(reinterpret_cast<PCRE2_SPTR>(p.pat),
                                       strlen(p.pat), 0, &ec, &eo, nullptr);
      if (code) {
        bool jit = pcre2_jit_compile(code, PCRE2_JIT_COMPLETE) == 0;
        label = jit ? "PCRE2-JIT" : "PCRE2";
        pcre2_match_data *md =
            pcre2_match_data_create_from_pattern(code, nullptr);
        auto sp = reinterpret_cast<PCRE2_SPTR>(subj.data());
        ns = med_ns(iters, inner, [&]() -> unsigned long long {
          unsigned long long s = 0;
          int rc =
              jit ? pcre2_jit_match(code, sp, subj.size(), 0, 0, md, nullptr)
                  : pcre2_match(code, sp, subj.size(), 0, 0, md, nullptr);
          if (rc >= 0) {
            PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
            for (int i = 0; i < rc; i++)
              if (ov[2 * i] != PCRE2_UNSET) s += ov[2 * i + 1] - ov[2 * i];
          }
          return s;
        });
        pcre2_match_data_free(md);
        pcre2_code_free(code);
      }
      row(label, ns);
    }
#endif

    if (g_md && md_sink) md_sink->push_back(std::move(mrow));
  }
}

//===--------------------------------------------------------------------===//
// Real-world workload groups
//
// The pattern tables below are organized by the domain where each set of
// regexes actually shows up. Latency groups (short subjects, per-call ns) reuse
// run_latency_group; throughput groups (large corpora, find_all MB/s) reuse
// run_case via run_throughput_group. Pattern strings are facts, not
// copyrightable; the corpora are synthetic and deterministic.
//===--------------------------------------------------------------------===//

// cpp-httplib: the regexes httplib actually uses (yhirose/cpp-httplib,
// httplib.h) plus a representative user route. Short header/path subjects; the
// status-line and www-authenticate patterns are the non-longest-safe captures
// (lazy .*? / optional (?:)? / alternation) the bounded backtracker targets.
static vector<LPat> httplib_pats() {
  return {
      {"status line", R"((HTTP/1\.[01]) (\d{3})(?: (.*?))?\r\n)",
       "HTTP/1.1 200 OK\r\n", 0},
      {"www-authenticate", R"~((?:(?:,\s*)?(.+?)=(?:"(.*?)"|([^,]*))))~",
       "realm=\"testrealm@host.com\"", 0},
      {"file extension", R"(\.([a-zA-Z0-9]+)$)", "/var/www/html/index.html", 0},
      {"has-query", R"([^?]+\?.*)", "/search?q=hello&lang=en", 0},
      {"route /users/(\\d+)", R"(/users/(\d+))", "/users/123456", 0},
  };
}

// Lexer / tokenizer: the per-token regexes a language lexer runs while scanning
// source. Anchored-ish, very short subjects — pure per-call latency, the cost
// profile of the embedded-language / DSL market this library targets.
static vector<LPat> lexer_pats() {
  return {
      {"identifier", R"([A-Za-z_]\w*)", "getElementById", 0},
      {"number", R"(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)", "3.14159e-10", 0},
      {"string literal", R"~("(\\.|[^"\\])*")~", "\"hello world\"", 0},
      {"line comment", R"(//[^\n]*)", "// TODO: fix this later", 0},
      {"block comment", R"(/\*.*?\*/)", "/* a doc comment */", 0},
      {"operator", R"(<<=|>>=|->|==|!=|<=|>=|&&|\|\|)", ">>=", 0},
  };
}

// Data validation: anchored full-string field checks (the classic regex_match
// use). Fixed-count {n} quantifiers and digit-boundary structure that the HTTP
// and lexer groups barely exercise.
static vector<LPat> validation_pats() {
  return {
      {"email", R"(^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$)",
       "alice.smith@example.co.uk", 0},
      {"UUID", R"(^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$)",
       "550e8400-e29b-41d4-a716-446655440000", 0},
      {"IPv4", R"(^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)", "192.168.100.42", 0},
      {"ISO-8601 datetime", R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$)",
       "2026-06-08T12:34:56", 0},
      {"semver", R"(^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$)", "1.10.3-rc.2", 0},
      {"hex color", R"(^#[0-9a-fA-F]{6}$)", "#1a2b3c", 0},
  };
}

// ReDoS immunity: textbook catastrophic-backtracking patterns paired with the
// evil inputs that make a backtracker blow up (n repetitions then a character
// that fails the trailing anchor -> exponential paths). A linear automaton
// returns "no match" in O(n); std::regex / PCRE2 are disabled (they would
// hang). This is the safety-vs-untrusted-patterns story as a number.
static vector<LPat> redos_pats() {
  return {
      {"nested quantifier", R"(^(a+)+$)",
       "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!", 0},
      {"alternation star", R"(^(a|a)*$)", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!", 0},
      {"optional-star digits", R"(^(\d+)*$)", "999999999999999999999999!", 0},
      {"overlapping alt", R"(^(a|aa)+$)", "aaaaaaaaaaaaaaaaaaaaaaaaaaaab", 0},
  };
}

// Log parsing: a Combined-Log-Format access-log line parse (multi-capture) and
// a bare IPv4 extraction, run over a synthetic log blob with find_all.
static vector<Case> log_cases() {
  static string corpus = make_logs(256 * 1024);
  return {
      {"access-log line",
       R"~((\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+) ([^"]+)" (\d{3}) (\d+))~",
       false,
       {corpus}},
      {"IPv4 extraction", R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)", false,
       {corpus}},
  };
}

// Templates / config / markup: mustache variables, markdown links, and
// key=value config, find_all over one mixed document.
static vector<Case> markup_cases() {
  static string corpus = make_markup_doc(256 * 1024);
  return {
      {"mustache var", R"(\{\{\s*(\w+)\s*\}\})", false, {corpus}},
      {"markdown link", R"(\[([^\]]+)\]\(([^)]+)\))", false, {corpus}},
      {"key=value config", R"((\w+)=(\S+))", false, {corpus}},
  };
}

// Print a group header, then run each throughput case into `*md_sink` so the
// group gets its own markdown table.
static void run_throughput_group(const string &title, const string &blurb,
                                 vector<Case> cases, int iters,
                                 vector<MdRow> *md_sink) {
  cout << "\n\n" << title << "\n" << string(72, '=') << "\n  " << blurb << endl;
  vector<MdRow> *prev = g_md_run_sink;
  g_md_run_sink = md_sink ? md_sink : prev;
  for (auto &c : cases)
    run_case(c, iters);
  g_md_run_sink = prev;
}

//===--------------------------------------------------------------------===//
// Compile-time benchmark
//
// The throughput cases above construct each engine OUTSIDE the timed loop, so
// they measure steady-state matching only. In scripts the dominant pattern is
// often "compile once, match once" on a short subject, where construction cost
// dominates. This section times Regex construction (and construct + one search)
// across a complexity spectrum, vs the same engines.
//===--------------------------------------------------------------------===//

// Defeat dead-store elimination of a constructed-but-unused object. The
// constructor's heap allocations are already non-elidable, but make it
// explicit.
static void use_obj(const void *p) { asm volatile("" : : "r"(p) : "memory"); }

// Median nanoseconds per `op()` call, batched `inner` per timed sample to
// amortize the clock. `op` returns a checksum (summed into a volatile) so it
// cannot be optimized away. Propagates exceptions (used to detect unsupported
// patterns).
template <typename F> static double med_ns(int iters, int inner, F op) {
  for (int w = 0; w < inner; w++)
    op(); // warmup
  vector<double> s;
  for (int i = 0; i < iters; i++) {
    volatile unsigned long long acc = 0;
    auto t0 = chrono::high_resolution_clock::now();
    for (int k = 0; k < inner; k++)
      acc += op();
    auto t1 = chrono::high_resolution_clock::now();
    (void)acc;
    s.push_back(chrono::duration_cast<chrono::nanoseconds>(t1 - t0).count() /
                static_cast<double>(inner));
  }
  sort(s.begin(), s.end());
  return s[s.size() / 2];
}

struct CPat {
  const char *name;
  const char *pat;
  const char *probe;
  unsigned rl;
};

static void run_compile_bench(int iters) {
  const int inner = 50;
  vector<CPat> pats = {
      {"literal", "foobar", "the quick foobar jumps", 0},
      {"alternation", "(?:fox|dog|cat)", "a lazy dog sat here", 0},
      {"word \\w+", "\\w+", "hello world 123", 0},
      {"char class", "[a-z0-9_]+", "snake_case_99", 0},
      {"captures", "(\\w+)=(\\w+)", "key=value", 0},
      {"anchored email", "^[a-z]+@[a-z]+\\.[a-z]+$", "alice@example.com", 0},
      {"bounded {3,8}", "[a-z]{3,8}", "hello", 0},
      {"unicode \\p{L}", "\\p{L}+", "h\xC3\xA9llo", 0},
      {"complex email", "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
       "Alice+x@mail.example.co", 0},
  };

  cout << "\n\nCompile-time benchmark (" << iters << " iterations x " << inner
       << " inner, median ns)\n"
       << string(72, '=') << "\n"
       << "  [compile] construct only    [+1 match] construct + one search "
          "(one-shot latency)\n";

  for (auto &p : pats) {
    cout << "\n" << p.name << "  /" << p.pat << "/\n";
    double base = -1;
    MdRow mrow{p.name, p.pat, {}};
    auto row = [&](const char *name, double c, double cm) {
      if (c < 0) {
        printf("    %-16s %12s   %14s\n", name, "—", "—");
        return;
      }
      if (string(name) == "regexlib") base = c;
      double ratio = base > 0 ? c / base : 1.0;
      printf("    %-16s %9.0f ns   %11.0f ns   %.2fx compile\n", name, c, cm,
             ratio);
      if (g_md) mrow.cells.push_back({name, c}); // construct-only ns
    };

    // regexlib
    {
      double c = -1, cm = -1;
      try {
        c = med_ns(iters, inner, [&]() -> unsigned long long {
          reg::Regex re(p.pat, p.rl);
          use_obj(&re);
          return 0;
        });
        cm = med_ns(iters, inner, [&]() -> unsigned long long {
          reg::Regex re(p.pat, p.rl);
          auto m = re.search(p.probe);
          return m.matched() ? m.end() : 0;
        });
      } catch (...) { c = cm = -1; }
      row("regexlib", c, cm);
    }

    // std::regex
    {
      double c = -1, cm = -1;
      try {
        c = med_ns(iters, inner, [&]() -> unsigned long long {
          std::regex re(p.pat);
          use_obj(&re);
          return 0;
        });
        cm = med_ns(iters, inner, [&]() -> unsigned long long {
          std::regex re(p.pat);
          std::cmatch m;
          return std::regex_search(p.probe, m, re) ? 1 : 0;
        });
      } catch (...) { c = cm = -1; }
      row("std::regex", c, cm);
    }

#ifdef HAS_RE2
    {
      double c = -1, cm = -1;
      RE2 cap(p.pat);
      if (cap.ok()) {
        c = med_ns(iters, inner, [&]() -> unsigned long long {
          RE2 re(p.pat);
          use_obj(&re);
          return re.ok() ? 1 : 0;
        });
        cm = med_ns(iters, inner, [&]() -> unsigned long long {
          RE2 re(p.pat);
          return RE2::PartialMatch(p.probe, re) ? 1 : 0;
        });
      }
      row("RE2", c, cm);
    }
#endif

#ifdef HAS_RURE
    {
      double c = -1, cm = -1;
      size_t pl = strlen(p.pat), bl = strlen(p.probe);
      rure_error *e0 = rure_error_new();
      rure *cap = rure_compile(reinterpret_cast<const uint8_t *>(p.pat), pl,
                               RURE_DEFAULT_FLAGS, nullptr, e0);
      bool ok = cap != nullptr;
      if (cap) rure_free(cap);
      rure_error_free(e0);
      if (ok) {
        c = med_ns(iters, inner, [&]() -> unsigned long long {
          rure_error *e = rure_error_new();
          rure *re = rure_compile(reinterpret_cast<const uint8_t *>(p.pat), pl,
                                  RURE_DEFAULT_FLAGS, nullptr, e);
          unsigned long long r = re ? 1 : 0;
          if (re) rure_free(re);
          rure_error_free(e);
          return r;
        });
        cm = med_ns(iters, inner, [&]() -> unsigned long long {
          rure_error *e = rure_error_new();
          rure *re = rure_compile(reinterpret_cast<const uint8_t *>(p.pat), pl,
                                  RURE_DEFAULT_FLAGS, nullptr, e);
          unsigned long long r = 0;
          if (re) {
            r = rure_is_match(re, reinterpret_cast<const uint8_t *>(p.probe),
                              bl, 0)
                    ? 1
                    : 0;
            rure_free(re);
          }
          rure_error_free(e);
          return r;
        });
      }
      row("rure", c, cm);
    }
#endif

#ifdef HAS_PCRE2
    {
      double c = -1, cm = -1;
      size_t pl = strlen(p.pat), bl = strlen(p.probe);
      int ec;
      PCRE2_SIZE eo;
      pcre2_code *cap = pcre2_compile(reinterpret_cast<PCRE2_SPTR>(p.pat), pl,
                                      0, &ec, &eo, nullptr);
      bool ok = cap != nullptr;
      if (cap) pcre2_code_free(cap);
      if (ok) {
        c = med_ns(iters, inner, [&]() -> unsigned long long {
          int e2;
          PCRE2_SIZE o2;
          pcre2_code *code = pcre2_compile(reinterpret_cast<PCRE2_SPTR>(p.pat),
                                           pl, 0, &e2, &o2, nullptr);
          unsigned long long r = 0;
          if (code) {
            pcre2_jit_compile(code,
                              PCRE2_JIT_COMPLETE); // JIT = the fast matcher
            r = 1;
            pcre2_code_free(code);
          }
          return r;
        });
        cm = med_ns(iters, inner, [&]() -> unsigned long long {
          int e2;
          PCRE2_SIZE o2;
          pcre2_code *code = pcre2_compile(reinterpret_cast<PCRE2_SPTR>(p.pat),
                                           pl, 0, &e2, &o2, nullptr);
          unsigned long long r = 0;
          if (code) {
            pcre2_jit_compile(code, PCRE2_JIT_COMPLETE);
            pcre2_match_data *md =
                pcre2_match_data_create_from_pattern(code, nullptr);
            r = pcre2_jit_match(code, reinterpret_cast<PCRE2_SPTR>(p.probe), bl,
                                0, 0, md, nullptr) >= 0
                    ? 1
                    : 0;
            pcre2_match_data_free(md);
            pcre2_code_free(code);
          }
          return r;
        });
      }
      row("PCRE2-JIT", c, cm);
    }
#endif
    if (g_md) g_md_compile.push_back(std::move(mrow));
  }
}

//===--------------------------------------------------------------------===//
// Program size / memory
//
// Deterministic (no timing). Quantifies the footprint that the next round of
// ideas targets: B2 (explicit-next Op::Byte + drop the per-sequence Jmp ->
// fewer instructions) and C1 (shrink Inst from 32B). For a Unicode-class
// pattern the byte program dominates resident memory (thousands of 32B insts,
// built for BOTH directions), so we compile the forward byte program directly
// (mirroring the EGC byte path) and report its instruction mix and bytes.
// Re-run after a size change to read the delta without having to wire up match
// benchmarks.
//===--------------------------------------------------------------------===//

static void run_size_bench() {
  namespace d = reg::detail;

  struct SPat {
    const char *name;
    const char *pat;
  };

  vector<SPat> pats = {
      {"dense \\w+", "\\w+"},
      {"unicode \\p{L}+", "\\p{L}+"},
      {"digit \\d+", "\\d+"},
      {"space \\s+", "\\s+"},
      {"captures (\\w+)=(\\w+)", "(\\w+)=(\\w+)"},
      {"ascii [a-z0-9_]+", "[a-z0-9_]+"},
      {"any .+", ".+"},
  };

  printf(
      "\n\nProgram size / memory  (forward byte program; sizeof(Inst)=%zu B)\n",
      sizeof(d::Inst));
  printf("%s\n", string(72, '=').c_str());
  printf("  %-24s %8s %8s %7s %7s %9s\n", "pattern", "insts", "byte", "split",
         "jmp", "KiB(x2)");

  for (auto &p : pats) {
    unordered_map<string, int> named;
    bool icase = false, ml = false, da = false;
    d::Parser parser(p.pat, named, icase, ml, da);
    d::Node root = parser.parse();
    d::Program prog =
        d::Compiler::compile(root, parser.ncap, /*us=*/true, /*reverse=*/false,
                             /*dotall=*/false, /*cp=*/false, /*icase=*/false);
    size_t nb = 0, ns = 0, nj = 0;
    for (auto &in : prog.insts) {
      if (in.op == d::Inst::Op::Byte)
        nb++;
      else if (in.op == d::Inst::Op::Split)
        ns++;
      else if (in.op == d::Inst::Op::Jmp)
        nj++;
    }
    // Logical bytes of the instruction stream; pools are empty in byte
    // programs. x2 because a Regex compiles the forward AND reverse byte
    // programs.
    double kib = 2.0 * prog.insts.size() * sizeof(d::Inst) / 1024.0;
    printf("  %-24s %8zu %8zu %7zu %7zu %9.1f\n", p.name, prog.insts.size(), nb,
           ns, nj, kib);
  }
}

//===--------------------------------------------------------------------===//

int main(int argc, char *argv[]) {
  // Args: [iterations] [--md]. Normally prints the human-readable text to
  // stdout; with --md it prints GitHub-markdown tables to stdout instead.
  int iters = 10;
  for (int i = 1; i < argc; i++) {
    string a = argv[i];
    if (a == "--md") {
      g_md = true;
    } else {
      iters = atoi(a.c_str());
      if (iters <= 0) {
        cerr << "iterations must be positive" << endl;
        return 1;
      }
    }
  }

  const size_t MB = 512 * 1024; // ~0.5 MB subjects

  vector<Case> cases;

  // A-2 target: dense capture-free greedy -> regexlib tier 1 (pure DFA).
  cases.push_back({"dense \\w+ (tier1)", "\\w+", false, {make_words(MB)}});

  // A-1 target: literal alternation -> regexlib tier 3 (Pike + first-byte
  // skip). Non-capturing so it stays capture-free; still longest-unsafe
  // (alternation).
  cases.push_back({"literal-alt (tier3)",
                   "(?:fox|dog|cat)",
                   false,
                   {make_words(MB, /*needle_period=*/20)}});

  // Boolean variant -> regexlib dfa_test path. The needle is ABSENT so every
  // engine must scan the whole subject (a present needle exits at the first
  // hit near byte 0 and measures nothing).
  cases.push_back({"literal-alt test (no match)",
                   "(?:xyzzy|plugh|frobnicate)",
                   true,
                   {make_words(MB)}});

  // C-6 target: the non-ASCII cliff. Identical to dense \w+ but one 'é' near
  // the middle flips is_ascii() and disables every DFA tier for the subject in
  // EGC mode. UnicodeScalar mode keeps the same \w+ on the byte DFA (no
  // is_ascii gate) — the cliff is gone — so the US row should land near the
  // pure-ASCII tier-1 numbers, not the EGC-with-one-é grapheme-Pike fallback.
  cases.push_back({"\\w+ + 1 non-ASCII, EGC",
                   "\\w+",
                   false,
                   {make_words_one_nonascii(MB)},
                   /*rl_flags=*/0});
  cases.push_back({"\\w+ + 1 non-ASCII, US",
                   "\\w+",
                   false,
                   {make_words_one_nonascii(MB)},
                   /*rl_flags=*/kRlUS});
  // Byte-path breadth: a larger Unicode class (\p{L} ~ a bigger byte program
  // than \w) on the byte DFA, to expose how program size affects scan speed.
  cases.push_back({"\\p{L}+ + 1 non-ASCII, US",
                   "\\p{L}+",
                   false,
                   {make_words_one_nonascii(MB)},
                   /*rl_flags=*/kRlUS});

  // B-4 target: many small docs, same Regex -> per-call DFA setup amortization.
  cases.push_back({"\\w+ x many docs", "\\w+", false,
                   make_docs(/*doc_bytes=*/96, /*count=*/8000)});

  // UnicodeScalar captures over non-ASCII. US resolves captures with a three-
  // engine stack (RE2/Rust-style): the one-pass DFA over the byte program when
  // the pattern is one-pass (the case here — ~RE2 speed, see matches+cache),
  // the bounded backtracker on DFA-bounded spans otherwise, and the code-point
  // Pike as the universal fallback. So US captures have no non-ASCII cliff. EGC
  // (the pair below) stays on the grapheme Pike — non-ASCII EGC has no byte
  // DFA, so captures there are Pike-bound (the inherent EGC cliff; US is the
  // fast path). find_all is string-materialization-bound at this match density;
  // matches+cache (columnar) shows the engine speed.
  cases.push_back({"(\\w+) capture, US dense + 1 non-ASCII",
                   "(\\w+)",
                   false,
                   {make_words_one_nonascii(MB)},
                   /*rl_flags=*/kRlUS});
  cases.push_back({"(\\w+) capture, EGC dense + 1 non-ASCII",
                   "(\\w+)",
                   false,
                   {make_words_one_nonascii(MB)},
                   /*rl_flags=*/0});

  // Multi-group captures: two distinct spans per match, joined by a
  // deterministic separator, so the pattern is one-pass. The code-point
  // one-pass engine resolves both captures in a single forward pass (vs the
  // bounded backtracker's re-scan). matches+cache shows the engine speed;
  // find_all is bound by per-match strings.
  cases.push_back(
      {"(\\w+)=(\\w+) capture", "(\\w+)=(\\w+)", false, {make_kv_pairs(MB)}});

  // In markdown mode, silence the verbose human-readable log during the run so
  // stdout carries only the GitHub-flavored tables. The log mixes printf and
  // cout, so redirect the underlying fd (not just cout's buffer) to /dev/null,
  // then restore it before emitting the tables.
  int saved_stdout_fd = -1;
  if (g_md) {
    fflush(stdout);
    cout.flush();
    saved_stdout_fd = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDOUT_FILENO);
    close(devnull);
  }

  cout << "regexlib throughput benchmark (" << iters << " iterations, median)"
#ifdef HAS_RE2
       << "  [+RE2]"
#endif
#ifdef HAS_RURE
       << "  [+rure]"
#endif
#ifdef HAS_PCRE2
       << "  [+PCRE2-JIT]"
#endif
       << endl;
  cout << string(72, '=') << endl;

  for (auto &c : cases)
    run_case(c, iters);

  run_sherlock_bench(iters);

  // Real-world workload groups, each printed (and tabled in --md) on its own.
  run_latency_group("Per-call latency — cpp-httplib regexes",
                    "one capture-extracting search() per call on a short subject",
                    httplib_pats(), iters, /*skip_backtrack=*/false,
                    &g_md_lat_http);
  run_latency_group("Per-call latency — lexer / tokenizer",
                    "the per-token regexes a language lexer runs while scanning",
                    lexer_pats(), iters, /*skip_backtrack=*/false,
                    &g_md_lat_lexer);
  run_latency_group("Per-call latency — data validation",
                    "anchored full-string field validation (regex_match shape)",
                    validation_pats(), iters, /*skip_backtrack=*/false,
                    &g_md_lat_valid);
  run_latency_group(
      "ReDoS immunity — adversarial patterns (linear engines only)",
      "catastrophic-backtracking patterns on evil inputs; std::regex and PCRE2 "
      "are DISABLED (they would hang) — the linear engines staying flat is the "
      "result",
      redos_pats(), iters, /*skip_backtrack=*/true, &g_md_redos);

  run_throughput_group(
      "Log parsing throughput  (Combined-Log-Format corpus, find_all)",
      "structured access-log line parse + IPv4 extraction over a log blob",
      log_cases(), iters, &g_md_log);
  run_throughput_group(
      "Templates / config / markup throughput  (find_all)",
      "mustache vars, markdown links, key=value config over one mixed doc",
      markup_cases(), iters, &g_md_markup);

  run_compile_bench(iters);
  run_size_bench();

  cout << endl;

  if (g_md) {
    fflush(stdout); // restore the real stdout; emit only the markdown tables
    cout.flush();
    dup2(saved_stdout_fd, STDOUT_FILENO);
    close(saved_stdout_fd);
    cout << "_" << iters
         << " iterations, median; absolute numbers are machine- and "
            "runner-dependent — read the per-engine comparison, not the "
            "magnitude._\n\n";
    write_md_table(cout, "Run time (find_all / test throughput)", "MB/s",
                   /*higher_is_faster=*/true, g_md_throughput);
    write_md_table(cout, "Log parsing throughput", "MB/s",
                   /*higher_is_faster=*/true, g_md_log);
    write_md_table(cout, "Templates / config / markup throughput", "MB/s",
                   /*higher_is_faster=*/true, g_md_markup);
    write_md_table(cout, "Per-call latency — cpp-httplib", "ns/call",
                   /*higher_is_faster=*/false, g_md_lat_http);
    write_md_table(cout, "Per-call latency — lexer / tokenizer", "ns/call",
                   /*higher_is_faster=*/false, g_md_lat_lexer);
    write_md_table(cout, "Per-call latency — data validation", "ns/call",
                   /*higher_is_faster=*/false, g_md_lat_valid);
    write_md_table(cout, "ReDoS immunity (linear engines only)", "ns/call",
                   /*higher_is_faster=*/false, g_md_redos);
    write_md_table(cout, "Compile time (construct only)", "ns",
                   /*higher_is_faster=*/false, g_md_compile);
  }
  return 0;
}
