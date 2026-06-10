//
//  regexlib_fuzz.cc
//
//  Deterministic regression fuzzer for regexlib.h. Two jobs:
//
//   1. GATE (portable, fails the test): oracle-free robustness — random
//      patterns/subjects must never crash, hang, or throw anything but
//      RegexError at construction, and every reported match must be
//      self-consistent (span/byte-slice agreement, find_all vs search
//      agreement, capture bounds). Run it under ASan/UBSan in CI for memory
//      safety. A fixed seed makes it reproducible.
//
//   2. INFO (not a gate): a differential pass against std::regex (ECMAScript,
//      which is leftmost-first like us) over the common ASCII subset. The diff
//      count is printed but does NOT fail the test, because std::regex
//      semantics vary across standard libraries (libc++ vs libstdc++ differ on
//      \b at string end and on match-complexity limits). It is a human signal,
//      not a portable assertion.
//
//  Build (standalone):
//    c++ -std=c++17 -Iinclude \
//        test/regexlib_fuzz.cc -o regexlib_fuzz && ./regexlib_fuzz
//

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <random>
#include <regex>
#include <string>
#include <thread>
#include <vector>

#include "regexlib.h"

namespace {

// Per-thread RNG so workers run independent, reproducible streams. Each worker
// reseeds this at startup (base ^ worker_id); worker 0 keeps the base seed, so
// a single-job run reproduces the original sequential sequence exactly.
thread_local std::mt19937 rng(0xC0FFEE); // fixed seed -> reproducible

int U(int lo, int hi) {
  return std::uniform_int_distribution<int>(lo, hi)(rng);
}

const char *LIT = "abc";

std::string gen_atom(int depth);

std::string gen_class() {
  std::string s = "[";
  if (U(0, 3) == 0) s += "^";
  int k = U(1, 3);
  for (int i = 0; i < k; i++) {
    if (U(0, 2) == 0) {
      char a = "ac"[U(0, 1)];
      s += a;
      s += "-";
      s += (a == 'a' ? 'c' : 'z');
    } else {
      s += LIT[U(0, 2)];
    }
  }
  return s + "]";
}

std::string gen_quant() {
  switch (U(0, 5)) {
  case 0: return "*";
  case 1: return "+";
  case 2: return "?";
  case 3: return "{" + std::to_string(U(0, 3)) + "}";
  case 4:
    return "{" + std::to_string(U(0, 2)) + "," + std::to_string(U(2, 4)) + "}";
  default: return "{" + std::to_string(U(1, 2)) + ",}";
  }
}

std::string gen_concat(int depth) {
  std::string s;
  int k = U(1, 3);
  for (int i = 0; i < k; i++) {
    std::string a = gen_atom(depth);
    if (U(0, 2) != 0) {
      a += gen_quant();
      if (U(0, 3) == 0) a += "?";
    }
    s += a;
  }
  return s;
}

std::string gen_alt(int depth) {
  std::string s = gen_concat(depth);
  int k = U(0, 2);
  for (int i = 0; i < k; i++)
    s += "|" + gen_concat(depth);
  return s;
}

std::string gen_atom(int depth) {
  int choice = (depth <= 0) ? U(0, 4) : U(0, 7);
  switch (choice) {
  case 0: return std::string(1, LIT[U(0, 2)]);
  case 1: return ".";
  case 2: return gen_class();
  case 3: {
    const char *e = "\\d\\w\\s";
    return std::string(e + U(0, 2) * 2, 2);
  }
  case 4: return (U(0, 1) ? "^" : "$");
  case 5: return "\\b";
  case 6: return "(" + gen_alt(depth - 1) + ")";
  default: return "(?:" + gen_alt(depth - 1) + ")";
  }
}

std::string gen_subject() {
  // Includes both \n and \r so the generator produces CR-LF clusters (one
  // extended grapheme cluster), exercising EGC-vs-byte-path CRLF handling in
  // the DFA-vs-Pike differential.
  static const char *A = "abcABC 123_\n\r";
  int n = U(0, 12);
  std::string s;
  for (int i = 0; i < n; i++)
    s += A[U(0, 12)];
  return s;
}

// --- UnicodeScalar-mode differential generators ---
// A small alphabet of single-code-point, single-grapheme characters, so EGC
// and US matching coincide and EGC (the proven engine) can be the oracle.
// Includes upper/lower pairs (a/A, é/É, α/Α) so the IgnoreCase differential
// actually exercises case folding. Also s/c/k plus their non-ASCII fold
// pre-images — long-s ſ (U+017F, folds to s) and the Kelvin sign (U+212A, folds
// to k) — so the (?i) clean-prefix byte prefilter's multi-byte lead window is
// exercised (a prefix like "sc"/"kc" on a subject holding ſ/Kelvin).
static const char *kUsChars[] = {
    "a", "b", "1", " ",        "é",          "ñ",   "α", "β", "日",
    "A", "É", "Α", "s",        "c",          "k",   "\xC5\xBF" /*ſ*/,
    "\xE2\x84\xAA" /*Kelvin*/};
static const int kUsN = 17;

std::string gen_us_subject() {
  int n = U(0, 10);
  std::string s;
  for (int i = 0; i < n; i++)
    s += kUsChars[U(0, kUsN - 1)];
  return s;
}

// US pattern atom: literals / `.` / `[...]` ranges / predicates / non-capturing
// & capturing groups / alternation / lookaround / quantifiers (greedy + lazy).
// Phase 4 added captures, anchors and lookaround; on single-code-point subjects
// EGC (the oracle) and US agree on spans AND captures.
std::string gen_us_atom(int depth) {
  static const char *kPred[] = {"\\d", "\\D",    "\\w",    "\\W",   "\\s",
                                "\\S", "\\p{L}", "\\p{N}", "\\P{L}"};
  switch ((depth <= 0) ? U(0, 3) : U(0, 7)) {
  case 0: return kUsChars[U(0, kUsN - 1)];
  case 1: return ".";
  case 2: return kPred[U(0, 8)]; // predicate / property class
  case 3: { // a small class of literal members, ranges, or predicates
    std::string s = "[";
    if (U(0, 3) == 0) s += "^";
    int k = U(1, 3);
    for (int i = 0; i < k; i++) {
      switch (U(0, 3)) {
      case 0: s += "a-c"; break;
      case 1: s += "\\w"; break;
      case 2: s += "\\d"; break;
      default: s += kUsChars[U(0, kUsN - 1)]; break;
      }
    }
    return s + "]";
  }
  case 4: // capturing or non-capturing group with alternation
  case 5: {
    std::string inner;
    int k = U(1, 2);
    for (int i = 0; i < k; i++) {
      if (i) inner += "|";
      inner += gen_us_atom(depth - 1);
    }
    return (U(0, 1) ? "(" : "(?:") + inner + ")";
  }
  default: { // zero-width lookaround
    static const char *kLook[] = {"(?=", "(?!", "(?<=", "(?<!"};
    return std::string(kLook[U(0, 3)]) + gen_us_atom(depth - 1) + ")";
  }
  }
}

std::string gen_us_pattern() {
  std::string s;
  if (U(0, 3) == 0) s += "^"; // leading anchor
  int k = U(1, 3);
  for (int i = 0; i < k; i++) {
    if (U(0, 4) == 0) s += (U(0, 1) ? "\\b" : "\\B"); // boundary assertion
    std::string a = gen_us_atom(2);
    switch (U(0, 6)) { // quantifier: greedy, lazy, or none
    case 0: a += "*"; break;
    case 1: a += "+"; break;
    case 2: a += "?"; break;
    case 3: a += "*?"; break;
    case 4: a += "+?"; break;
    default: break;
    }
    s += a;
  }
  if (U(0, 3) == 0) s += "$";                  // trailing anchor
  if (U(0, 2) == 0) s += "|" + gen_us_atom(2); // top-level alternation
  return s;
}

std::atomic<int> g_fail{0};
std::mutex g_print_mtx;

void fail(const std::string &why, const std::string &pat,
          const std::string &subj) {
  int n = g_fail.fetch_add(1);
  if (n < 25) {
    std::lock_guard<std::mutex> lk(g_print_mtx);
    std::printf("[INVARIANT] %s : /%s/ on \"%s\"\n", why.c_str(), pat.c_str(),
                subj.c_str());
  }
}

// Oracle-free self-consistency checks on a single match.
void check_match(const reg::MatchResult &m, const std::string &s,
                 const std::string &pat, const std::string &subj) {
  if (!m.matched()) return;
  if (!(m.begin() <= m.end() && m.end() <= s.size()))
    fail("match span out of range", pat, subj);
  else if (m.str() != s.substr(m.begin(), m.end() - m.begin()))
    fail("match str != slice", pat, subj);
  for (size_t gi = 0; gi <= m.group_count(); gi++) {
    reg::Match g = m.group(gi);
    if (!g.matched()) continue;
    if (!(g.begin() <= g.end() && g.end() <= s.size()))
      fail("group span out of range", pat, subj);
    else if (g.str() != s.substr(g.begin(), g.end() - g.begin()))
      fail("group str != slice", pat, subj);
  }
}

// The public bulk API is scan() (lazy) + matches() (eager view). This owning
// collector — what find_all() used to return — is built on the eager matches(),
// so it stays an oracle independent of scan() for check_scan below.
std::vector<reg::MatchResult> find_all(const reg::Regex &re,
                                       std::string_view s) {
  std::vector<reg::MatchResult> v;
  for (auto m : re.find_all(s))
    v.push_back(m.to_owned());
  return v;
}

std::vector<reg::MatchResult> find_all(const reg::Regex &re, std::string_view s,
                                       reg::Regex::FindCache &cache) {
  std::vector<reg::MatchResult> v;
  for (auto m : re.find_all(s, cache))
    v.push_back(m.to_owned());
  return v;
}

// The one group-by-group comparison every differential uses: whole-match
// span/str, group count, then each group's matched flag and (when matched)
// span and str. `what` names the surfaces being compared in the fail message.
// Returns false after reporting, so callers can stop early. One definition so
// no differential can drift to a weaker check. `what` stays a C string: the
// success path (virtually every call) must not construct a std::string per
// match; the message is built only on failure.
template <class M1, class M2>
bool compare_groups(const M1 &a, const M2 &b, const char *what,
                    const std::string &pat, const std::string &subj) {
  if (a.begin() != b.begin() || a.end() != b.end() || a.str() != b.str()) {
    fail(std::string(what) + ": span/str mismatch", pat, subj);
    return false;
  }
  if (a.group_count() != b.group_count()) {
    fail(std::string(what) + ": group count mismatch", pat, subj);
    return false;
  }
  for (size_t g = 0; g <= a.group_count(); g++) {
    const auto ga = a.group(g);
    const auto gb = b.group(g);
    if (ga.matched() != gb.matched() ||
        (ga.matched() && (ga.begin() != gb.begin() || ga.end() != gb.end() ||
                          ga.str() != gb.str()))) {
      fail(std::string(what) + ": group mismatch", pat, subj);
      return false;
    }
  }
  return true;
}

// A FindCache reused across subjects (a growing, persisted DFA) must give the
// same results as a fresh find_all. `cache` is shared across the caller's whole
// subject sequence, so this also exercises cross-subject state accumulation.
void check_cache(const reg::Regex &re, const std::string &subj,
                 const std::vector<reg::MatchResult> &all,
                 reg::Regex::FindCache &cache, const std::string &pat) {
  std::vector<reg::MatchResult> got;
  try {
    got = find_all(re, subj, cache);
  } catch (...) {
    fail("find_all(cache) threw", pat, subj);
    return;
  }
  if (got.size() != all.size()) {
    fail("find_all(cache) count != find_all", pat, subj);
    return;
  }
  for (size_t i = 0; i < all.size(); i++)
    if (!compare_groups(got[i], all[i], "find_all(cache) vs find_all", pat,
                        subj))
      return;
}

// The lazy scan() must yield the same sequence as find_all: every whole-match
// span/str and every capture group, in order. (find_all is the eager oracle.)
void check_scan(const reg::Regex &re, const std::string &subj,
                const std::vector<reg::MatchResult> &all,
                const std::string &pat) {
  size_t i = 0;
  try {
    for (auto m : re.find_iter(subj)) {
      if (i >= all.size()) {
        fail("scan() yielded more matches than find_all", pat, subj);
        return;
      }
      if (!compare_groups(m, all[i], "scan() vs find_all", pat, subj)) return;
      i++;
    }
  } catch (...) {
    fail("scan() threw", pat, subj);
    return;
  }
  if (i != all.size())
    fail("scan() yielded fewer matches than find_all", pat, subj);

  // split() must yield exactly all.size()+1 pieces whose concatenation, with
  // each matched text spliced back in order, reconstructs the subject.
  std::vector<std::string> pieces;
  try {
    for (auto p : re.split(subj))
      pieces.emplace_back(p);
  } catch (...) {
    fail("split() threw", pat, subj);
    return;
  }
  if (pieces.size() != all.size() + 1) {
    fail("split() piece count != matches+1", pat, subj);
    return;
  }
  std::string rebuilt;
  for (size_t k = 0; k < all.size(); k++) {
    rebuilt += pieces[k];
    rebuilt += std::string(all[k].str());
  }
  rebuilt += pieces.back();
  if (rebuilt != subj)
    fail("split() pieces do not reconstruct subject", pat, subj);
}

// --- Unicode / grapheme-cluster fuzzing (the engine's differentiator) ---
// A mix of: ASCII, a precomposed accent, a base+combining grapheme, CJK, a
// single emoji, a ZWJ family cluster (many code points, one grapheme), and a
// regional-indicator flag (two code points, one grapheme).
const std::vector<std::string> UCHARS = {
    "a",
    "1",
    " ",
    "\xC3\xA9",         // é  (U+00E9)
    "e\xCC\x81",        // e + combining acute (1 cluster)
    "\xE6\xBC\xA2",     // 漢 (U+6F22)
    "\xF0\x9F\x98\x80", // 😀 (U+1F600)
    "\xF0\x9F\x91\xA8\xE2\x80\x8D\xF0\x9F\x91\xA9\xE2\x80\x8D\xF0\x9F\x91"
    "\xA7",                             // 👨‍👩‍👧
    "\xF0\x9F\x87\xAF\xF0\x9F\x87\xB5", // 🇯🇵 flag
};

std::string gen_uchar() { return UCHARS[U(0, (int)UCHARS.size() - 1)]; }

std::string gen_upattern_inner(int depth); // mutually recursive with gen_uatom

std::string gen_uatom(int depth) {
  switch ((depth <= 0) ? U(0, 3) : U(0, 5)) {
  case 0: return gen_uchar(); // literal grapheme
  case 1: return ".";
  case 2: {
    const char *e = "\\d\\w\\s";
    return std::string(e + U(0, 2) * 2, 2);
  }
  case 3: return "[" + gen_uchar() + gen_uchar() + "]"; // class of clusters
  case 4: return U(0, 1) ? "\\p{L}" : "\\p{N}";
  default: return "(" + gen_upattern_inner(depth - 1) + ")";
  }
}

std::string gen_uconcat(int depth) {
  std::string s;
  int k = U(1, 3);
  for (int i = 0; i < k; i++) {
    std::string a = gen_uatom(depth);
    if (U(0, 2) != 0) a += gen_quant();
    s += a;
  }
  return s;
}

std::string gen_upattern_inner(int depth) {
  std::string s = gen_uconcat(depth);
  int k = U(0, 1);
  for (int i = 0; i < k; i++)
    s += "|" + gen_uconcat(depth);
  return s;
}

std::string gen_usubject() {
  int n = U(0, 8);
  std::string s;
  for (int i = 0; i < n; i++)
    s += gen_uchar();
  return s;
}

// --- Lookaround fuzzing: exercises the reverse-matching lookbehind path,
// which the std::regex-compatible generator never produces. Oracle-free. ---
std::string gen_la_pattern(int depth); // mutually recursive with gen_la_atom

std::string gen_la_atom(int depth) {
  switch ((depth <= 0) ? U(0, 3) : U(0, 6)) {
  case 0: return std::string(1, LIT[U(0, 2)]);
  case 1: return ".";
  case 2: return gen_class();
  case 3: {
    const char *e = "\\d\\w\\s";
    return std::string(e + U(0, 2) * 2, 2);
  }
  case 4: { // lookbehind — the reverse-compiled / reverse-matched path
    const char *p[] = {"(?<=", "(?<!"};
    return std::string(p[U(0, 1)]) + gen_la_pattern(depth - 1) + ")";
  }
  case 5: { // lookahead
    const char *p[] = {"(?=", "(?!"};
    return std::string(p[U(0, 1)]) + gen_la_pattern(depth - 1) + ")";
  }
  default: return "(" + gen_la_pattern(depth - 1) + ")";
  }
}

std::string gen_la_concat(int depth) {
  std::string s;
  int k = U(1, 3);
  for (int i = 0; i < k; i++) {
    std::string a = gen_la_atom(depth);
    if (U(0, 2) != 0) a += gen_quant();
    s += a;
  }
  return s;
}

std::string gen_la_pattern(int depth) {
  std::string s = gen_la_concat(depth);
  int k = U(0, 1);
  for (int i = 0; i < k; i++)
    s += "|" + gen_la_concat(depth);
  return s;
}

void invariant_fuzz_lookaround(int iters) {
  for (int it = 0; it < iters; it++) {
    std::string pat = gen_la_pattern(3);
    reg::Regex *re = nullptr;
    try {
      re = new reg::Regex(pat);
    } catch (const reg::RegexError &) { continue; } catch (...) {
      fail("non-RegexError at construction (lookaround)", pat, "");
      continue;
    }
    reg::Regex::FindCache cache; // reused across this pattern's subjects
    for (int s = 0; s < 5; s++) {
      std::string subj = gen_subject();
      reg::MatchResult m;
      std::vector<reg::MatchResult> all;
      try {
        m = re->search(subj);
        all = find_all(*re, subj);
        if (re->test(subj) != m.matched())
          fail("test() != search (lookaround)", pat, subj);
      } catch (const reg::RegexError &) {
        continue; // step budget on a pathological lookaround is acceptable
      } catch (...) {
        fail("matcher threw (lookaround)", pat, subj);
        continue;
      }
      check_match(m, subj, pat, subj);
      if (m.matched()) {
        if (all.empty())
          fail("matched but find_all empty (lookaround)", pat, subj);
        else if (all[0].begin() != m.begin() || all[0].str() != m.str())
          fail("find_all[0] != search (lookaround)", pat, subj);
      } else if (!all.empty()) {
        fail("no-match but find_all non-empty (lookaround)", pat, subj);
      }
      for (size_t i = 1; i < all.size(); i++) {
        check_match(all[i], subj, pat, subj);
        if (all[i].begin() < all[i - 1].end())
          fail("find_all overlaps (lookaround)", pat, subj);
      }
      check_cache(*re, subj, all, cache, pat);
      check_scan(*re, subj, all, pat);
    }
    delete re;
  }
}

// Oracle-free invariant fuzzing over Unicode/grapheme inputs.
void invariant_fuzz_unicode(int iters) {
  for (int it = 0; it < iters; it++) {
    std::string pat = gen_upattern_inner(3);
    reg::Regex *re = nullptr;
    try {
      re = new reg::Regex(pat);
    } catch (const reg::RegexError &) { continue; } catch (...) {
      fail("non-RegexError at construction (unicode)", pat, "");
      continue;
    }
    reg::Regex::FindCache cache; // reused across this pattern's subjects
    for (int s = 0; s < 5; s++) {
      std::string subj = gen_usubject();
      reg::MatchResult m;
      std::vector<reg::MatchResult> all;
      try {
        m = re->search(subj);
        all = find_all(*re, subj);
        if (re->test(subj) != m.matched())
          fail("test() != search (unicode)", pat, subj);
      } catch (...) {
        fail("matcher threw (unicode)", pat, subj);
        continue;
      }
      check_match(m, subj, pat, subj);
      if (m.matched()) {
        if (all.empty())
          fail("matched but find_all empty (unicode)", pat, subj);
        else if (all[0].begin() != m.begin() || all[0].str() != m.str())
          fail("find_all[0] != search (unicode)", pat, subj);
      } else if (!all.empty()) {
        fail("no-match but find_all non-empty (unicode)", pat, subj);
      }
      for (size_t i = 1; i < all.size(); i++) {
        check_match(all[i], subj, pat, subj);
        if (all[i].begin() < all[i - 1].end())
          fail("find_all overlaps (unicode)", pat, subj);
      }
      check_cache(*re, subj, all, cache, pat);
      check_scan(*re, subj, all, pat);
    }
    delete re;
  }
}

void invariant_fuzz(int iters) {
  for (int it = 0; it < iters; it++) {
    std::string pat = gen_alt(3);
    reg::Regex *re = nullptr;
    try {
      re = new reg::Regex(pat);
    } catch (const reg::RegexError &) {
      continue; // rejecting a pattern is fine
    } catch (...) {
      fail("non-RegexError thrown at construction", pat, "");
      continue;
    }
    // Appending an always-true zero-width assertion forces the full Pike VM:
    // the assertion makes the program non-DFA-able (so the tier-1/tier-2 DFA
    // paths bow out), while `(?:\b|\B)` matches at every position and consumes
    // nothing, so the whole match is identical to the bare pattern. This is an
    // oracle-free DFA-vs-Pike reference — search/find_all take the DFA path for
    // DFA-able patterns, this forces the Pike path for the same matches.
    reg::Regex *pike = nullptr;
    try {
      pike = new reg::Regex("(?:" + pat + ")(?:\\b|\\B)");
    } catch (...) {
      pike = nullptr; // wrapping may hit a limit; skip the differential then
    }
    reg::Regex::FindCache cache; // reused across this pattern's subjects
    for (int s = 0; s < 5; s++) {
      std::string subj = gen_subject();
      reg::MatchResult m;
      std::vector<reg::MatchResult> all;
      try {
        m = re->search(subj);
        all = find_all(*re, subj);
        if (re->test(subj) != m.matched())
          fail("test() != search().matched()", pat, subj);
      } catch (...) {
        fail("matcher threw", pat, subj);
        continue;
      }
      check_match(m, subj, pat, subj);
      // match() and search() must agree whenever the leftmost match is anchored
      // at 0 (both take the DFA path for tier-1 patterns; the Pike reference is
      // the wrapped pattern checked below).
      reg::MatchResult am;
      try {
        am = re->match(subj);
      } catch (...) {
        fail("match() threw", pat, subj);
        continue;
      }
      bool anchored = m.matched() && m.begin() == 0;
      if (am.matched() != anchored)
        fail("match() != (search anchored at 0)", pat, subj);
      else if (am.matched() && (am.end() != m.end() || am.str() != m.str()))
        fail("match() span != search span at 0", pat, subj);
      // find_all must agree with search on the leftmost match.
      if (m.matched()) {
        if (all.empty())
          fail("search matched but find_all empty", pat, subj);
        else if (all[0].begin() != m.begin() || all[0].str() != m.str())
          fail("find_all[0] != search", pat, subj);
      } else if (!all.empty()) {
        fail("search no-match but find_all non-empty", pat, subj);
      }
      // find_all results must advance (non-regressing positions).
      for (size_t i = 1; i < all.size(); i++) {
        check_match(all[i], subj, pat, subj);
        if (all[i].begin() < all[i - 1].end())
          fail("find_all overlaps/regresses", pat, subj);
      }
      // DFA-vs-Pike differential: the wrapped pattern's whole matches (its
      // group-0 spans) must equal the DFA find_all spans, one for one.
      if (pike) {
        std::vector<reg::MatchResult> ref;
        try {
          ref = find_all(*pike, subj);
        } catch (...) {
          fail("pike reference threw", pat, subj);
          continue;
        }
        if (ref.size() != all.size())
          fail("find_all count != Pike", pat, subj);
        else
          // Whole spans AND capture groups must equal the Pike. The
          // (?:PAT)(?:\b|\B) wrap is non-capturing, so the reference keeps
          // PAT's own groups — this validates the leftmost-first capture
          // tiers (S3) against the Pike.
          for (size_t i = 0; i < all.size(); i++)
            compare_groups(all[i], ref[i], "find_all vs Pike", pat, subj);
      }
      check_cache(*re, subj, all, cache, pat);
      check_scan(*re, subj, all, pat);
    }
    delete re;
    delete pike;
  }
}

// Pure printable-ASCII literal fast-path differential. The literal tier
// (literal_only_: memmem + O(1) grapheme-boundary check, no subject
// classification) must agree with the forced Pike on EVERY surface, especially
// on subjects that interleave grapheme-fusing code points around the literal —
// a Prepend just before a match (must reject) or an Extend/ZWJ/SpacingMark just
// after it (must reject). gen_subject() is ASCII-only, so the main
// invariant_fuzz never stresses these boundaries; this does.
void invariant_fuzz_literal(int iters) {
  // Literal alphabet: printable ASCII only (the tier's gate), incl. space and
  // an uppercase letter / digit so probe-byte selection varies.
  static const char *LITCH = "abc D1";
  // Subject units: literal chars (so occurrences arise), plus fusing /
  // non-ASCII pieces that land next to them. \xCC\x81 = U+0301 combining acute
  // (Extend), \xE2\x80\x8D = U+200D ZWJ, \xD8\x80 = U+0600 Arabic number sign
  // (Prepend), \xC3\xA9 = é (a non-ASCII base), plus CR/LF.
  static const char *UNITS[] = {"a",   "b",          "c",          "D",
                                 "1",   " ",          "\xCC\x81",   "\xE2\x80\x8D",
                                 "\xD8\x80", "\xC3\xA9", "\n",      "\r"};
  for (int it = 0; it < iters; it++) {
    int m = U(1, 4);
    std::string pat;
    for (int i = 0; i < m; i++) pat += LITCH[U(0, 5)];
    reg::Regex re(pat);
    reg::Regex pike("(?:" + pat + ")(?:\\b|\\B)");
    reg::Regex::FindCache cache;
    for (int s = 0; s < 6; s++) {
      int k = U(0, 14);
      std::string subj;
      for (int i = 0; i < k; i++) subj += UNITS[U(0, 11)];
      auto all = find_all(re, subj);
      auto ref = find_all(pike, subj);
      reg::MatchResult sm = re.search(subj);
      if (re.test(subj) != sm.matched())
        fail("literal: test() != search().matched()", pat, subj);
      if (re.match(subj).matched() != (sm.matched() && sm.begin() == 0))
        fail("literal: match() != (search anchored at 0)", pat, subj);
      if (all.size() != ref.size())
        fail("literal: find_all count != Pike", pat, subj);
      else
        for (size_t i = 0; i < all.size(); i++)
          compare_groups(all[i], ref[i], "literal: find_all vs Pike", pat,
                         subj);
      check_scan(re, subj, all, pat);
      check_cache(re, subj, all, cache, pat);
    }
  }
}

// Non-ASCII assertion byte tier differential vs the forced Pike. Assert
// patterns
// (^ $ \b \B \w \d \s . [...]) on subjects mixing ASCII, CR-LF,
// single-code-point non-ASCII (é ñ α 日), and an occasional multi-code-point
// cluster (e+combining, which disqualifies the byte tier). On a non-ASCII
// subject the bare pattern runs the cached code-point-aware byte assert DFA;
// the `(?:PAT)(?:\b|\B)` wrap forces the grapheme Pike. They must agree on
// every find_all span, plus search()/test() consistency. Runs with and without
// Multiline (multiline ^/$ line-break logic is part of the byte tier; the
// ASCII-only differential never set the flag).
std::string gen_au_subject() {
  static const char *A[] = {"a",
                            "b",
                            "c",
                            " ",
                            "_",
                            "1",
                            "\n",
                            "\r",
                            "\xC3\xA9" /*é*/,
                            "\xC3\xB1" /*ñ*/,
                            "\xCE\xB1" /*α*/,
                            "\xE6\x97\xA5" /*日*/,
                            "e\xCC\x81" /*e+combining (multi-cp cluster)*/};
  int n = U(0, 14);
  std::string s;
  for (int i = 0; i < n; i++)
    s += A[U(0, 12)];
  return s;
}

// Assert-tier required-trailing-literal differential, with emphasis on the
// `\b \w{a,b} <lit> \b` word-suffix fast path (assert_word_find) and the general
// reverse-suffix path. gen_concat tops out at 3 atoms, so it never emits the
// 4-atom `\b\w+n\b` shape — this builds it directly and checks it (plus `$`/`\z`
// trailing and greedy `.*`/`.?` pre-parts for the general path) against the Pike
// oracle on words interleaved with non-ASCII / combining / boundary characters.
void invariant_fuzz_assert_suffix(int iters) {
  static const char *LITCH = "anigtsy";    // letters that form common suffixes
  static const char *LEAD[] = {"\\b", ""}; // with / without a leading boundary
  static const char *BODY[] = {"\\w+", "\\w*", "\\w{1,3}", ".*",
                               ".?",   ".+",   "[a-z]+"};
  static const char *TAIL[] = {"\\b", "$", "\\b", "\\B"};
  static const char *UNITS[] = {"a", "n", "g", "i", " ",          ".",
                                "_", "1", "\n",    "\xCC\x81" /*comb*/,
                                "\xC3\xA9" /*é*/,  "\xCE\xB1" /*α*/};
  for (int it = 0; it < iters; it++) {
    int lm = U(1, 3);
    std::string lit;
    for (int i = 0; i < lm; i++) lit += LITCH[U(0, 6)];
    std::string pat = std::string(LEAD[U(0, 1)]) + BODY[U(0, 6)] + lit +
                      TAIL[U(0, 3)];
    unsigned ml = (U(0, 1) == 0) ? reg::Multiline : 0u;
    reg::Regex *re = nullptr, *pike = nullptr;
    try {
      re = new reg::Regex(pat, ml);
    } catch (...) { continue; }
    try {
      pike = new reg::Regex("(?:" + pat + ")(?:\\b|\\B)", ml);
    } catch (...) {
      delete re;
      continue;
    }
    reg::Regex::FindCache cache;
    for (int s = 0; s < 6; s++) {
      int k = U(0, 16);
      std::string subj;
      for (int i = 0; i < k; i++) subj += UNITS[U(0, 11)];
      std::vector<reg::MatchResult> all, ref;
      reg::MatchResult m;
      try {
        all = find_all(*re, subj);
        ref = find_all(*pike, subj);
        m = re->search(subj);
        if (re->test(subj) != m.matched())
          fail("assert-suffix: test() != search", pat, subj);
      } catch (...) {
        fail("assert-suffix: threw", pat, subj);
        continue;
      }
      if (all.size() != ref.size())
        fail("assert-suffix: find_all count != Pike", pat, subj);
      else
        for (size_t i = 0; i < all.size(); i++)
          compare_groups(all[i], ref[i], "assert-suffix: find_all vs Pike",
                         pat, subj);
      check_scan(*re, subj, all, pat);
      check_cache(*re, subj, all, cache, pat);
    }
    delete re;
    delete pike;
  }
}

void invariant_fuzz_assert_unicode(int iters) {
  for (int it = 0; it < iters; it++) {
    std::string pat = gen_alt(3); // produces ^ $ \b \d \w \s . [...] groups alt
    // Pin the match unit per-Regex (do NOT read the process-wide default, which
    // other worker threads mutate — that would build `re` in a racy,
    // indeterminate mode). Randomly exercise both EGC and US, each compared
    // against its own Pike in the same flags + unit.
    unsigned flags = (U(0, 1) == 0) ? reg::Multiline : 0u;
    reg::MatchUnit unit =
        (U(0, 1) == 0) ? reg::MatchUnit::CodePoint : reg::MatchUnit::Grapheme;
    reg::Regex *re = nullptr;
    try {
      re = new reg::Regex(pat, flags, unit);
    } catch (const reg::RegexError &) { continue; } catch (...) {
      fail("non-RegexError at construction (assert-uni)", pat, "");
      continue;
    }
    reg::Regex *pike = nullptr;
    try {
      pike = new reg::Regex("(?:" + pat + ")(?:\\b|\\B)", flags, unit);
    } catch (...) { pike = nullptr; }
    for (int s = 0; s < 6; s++) {
      std::string subj = gen_au_subject();
      std::vector<reg::MatchResult> all;
      reg::MatchResult m;
      try {
        all = find_all(*re, subj);
        m = re->search(subj);
        if (re->test(subj) != m.matched())
          fail("test() != search (assert-uni)", pat, subj);
      } catch (...) {
        fail("matcher threw (assert-uni)", pat, subj);
        continue;
      }
      for (size_t i = 0; i < all.size(); i++)
        check_match(all[i], subj, pat, subj);
      if (m.matched()) {
        if (all.empty())
          fail("search matched but find_all empty (assert-uni)", pat, subj);
        else if (all[0].begin() != m.begin() || all[0].str() != m.str())
          fail("find_all[0] != search (assert-uni)", pat, subj);
      } else if (!all.empty()) {
        fail("search no-match but find_all non-empty (assert-uni)", pat, subj);
      }
      if (pike) {
        std::vector<reg::MatchResult> ref;
        try {
          ref = find_all(*pike, subj);
        } catch (...) {
          fail("pike reference threw (assert-uni)", pat, subj);
          continue;
        }
        if (ref.size() != all.size())
          fail("find_all count != Pike (assert-uni)", pat, subj);
        else
          // Spans and capture groups — validates the leftmost-first byte-tier
          // capture path (S4a) against the grapheme Pike on non-ASCII
          // subjects.
          for (size_t i = 0; i < all.size(); i++)
            compare_groups(all[i], ref[i], "find_all vs Pike (assert-uni)",
                           pat, subj);
      }
    }
    delete re;
    delete pike;
  }
}

// UnicodeScalar mode differential: on single-code-point subjects (graphemes ==
// code points), the US byte automaton must agree with the proven EGC engine on
// every match span and string. Validates the UTF-8 range compiler + byte DFA.
// On a non-ASCII single-code-point subject EGC now takes its own byte path
// (byte DFA over byte_prog_, gated by subject_simple), so this also
// differentially validates that path against the independent US engine — spans
// and captures.
void invariant_fuzz_us(int iters) {
  for (int it = 0; it < iters; it++) {
    std::string pat = gen_us_pattern();
    // Half the runs add IgnoreCase to BOTH engines, validating US case-fold
    // expansion (byte automaton) / match-time folding (Pike) against the EGC
    // oracle's folding.
    bool ic = (U(0, 1) == 0);
    reg::Regex *us = nullptr, *egc = nullptr;
    // Pin each engine's match unit per-Regex — no process-wide
    // set_default_match_unit (which would race with the other worker threads
    // that read the global default at construction).
    unsigned f = ic ? reg::IgnoreCase : 0u;
    try {
      us = new reg::Regex(pat, f, reg::MatchUnit::CodePoint);
    } catch (const reg::RegexError &) {
      continue; // US restriction (captures/longest-unsafe/...) or bad pattern
    } catch (...) {
      fail("non-RegexError at US construction", pat, "");
      continue;
    }
    try {
      egc = new reg::Regex(pat, f, reg::MatchUnit::Grapheme);
    } catch (...) {
      delete us;
      continue;
    }
    for (int s = 0; s < 6; s++) {
      std::string subj = gen_us_subject();
      std::vector<reg::MatchResult> au, ae;
      try {
        au = find_all(*us, subj);
        ae = find_all(*egc, subj);
      } catch (...) {
        fail("US/EGC matcher threw", pat, subj);
        continue;
      }
      if (au.size() != ae.size()) {
        fail("US find_all count != EGC", pat, subj);
        continue;
      }
      // Spans and captures (byte Pike) must agree group-for-group with the
      // EGC oracle.
      bool bad = false;
      for (size_t i = 0; i < au.size() && !bad; i++)
        bad = !compare_groups(au[i], ae[i], "US find_all vs EGC", pat, subj);
      if (bad) continue;
      if (us->test(subj) != !au.empty()) fail("US test != find_all", pat, subj);
      // Anchored match(): US and EGC must agree on span, string and captures —
      // covers the EGC byte path's anchored entry on single-code-point
      // subjects.
      reg::MatchResult mu, me;
      try {
        mu = us->match(subj);
        me = egc->match(subj);
      } catch (...) {
        fail("US/EGC match() threw", pat, subj);
        continue;
      }
      if (mu.matched() != me.matched()) {
        fail("US match() matched != EGC", pat, subj);
        continue;
      }
      if (mu.matched())
        compare_groups(mu, me, "US match() vs EGC", pat, subj);
    }
    delete us;
    delete egc;
  }
}

// Random byte patterns (including metacharacters): construction must only ever
// throw RegexError, and matching must not crash.
void parser_fuzz(int iters) {
  static const std::string META = "abc().[]{}|*+?^$\\<>=!:-,0123 dwsbpiPm";
  for (int it = 0; it < iters; it++) {
    int n = U(0, 14);
    std::string pat;
    for (int i = 0; i < n; i++)
      pat += META[U(0, (int)META.size() - 1)];
    try {
      reg::Regex re(pat);
      for (int s = 0; s < 3; s++)
        (void)re.search(gen_subject());
    } catch (const reg::RegexError &) {
    } catch (...) { fail("non-RegexError thrown", pat, ""); }
  }
}

// Informational only: differential vs std::regex. Not a gate.
// Differential summary counters, aggregated across all workers and printed
// once from main().
std::atomic<long> g_diff_cmp{0}, g_diff_diff{0}, g_diff_skip{0};

void differential_info(int iters) {
  long cmp = 0, diff = 0, skip = 0;
  for (int it = 0; it < iters; it++) {
    std::string pat = gen_alt(3);
    reg::Regex *re = nullptr;
    try {
      re = new reg::Regex(pat);
    } catch (...) { continue; }
    std::regex sre;
    try {
      sre = std::regex(pat, std::regex::ECMAScript);
    } catch (...) {
      delete re;
      skip++;
      continue;
    }
    for (int s = 0; s < 4; s++) {
      std::string subj = gen_subject();
      auto m = re->search(subj);
      std::smatch sm;
      bool std_m;
      try {
        std_m = std::regex_search(subj, sm, sre);
      } catch (...) {
        skip++;
        continue;
      }
      cmp++;
      if (m.matched() != std_m || (m.matched() && m.str() != sm.str())) diff++;
    }
    delete re;
  }
  g_diff_cmp += cmp;
  g_diff_diff += diff;
  g_diff_skip += skip;
}

} // namespace

// One worker's slice of the full suite. Each function's total is split evenly
// across `jobs` workers (with the remainder spread over the low-id workers), so
// the union over all workers reproduces the original per-function iteration
// counts. The whole run is fully determined by (base seed, jobs, iters), so a
// failure reproduces by rerunning with the same flags.
void run_worker(std::uint32_t base, int jobs, int t, int inv, int parser_it,
                int diff_it) {
  rng.seed(base ^ static_cast<std::uint32_t>(t));
  auto share = [&](int total) {
    return total / jobs + (t < total % jobs ? 1 : 0);
  };
  invariant_fuzz(share(inv));
  invariant_fuzz_literal(share(inv));
  invariant_fuzz_assert_suffix(share(inv));
  invariant_fuzz_assert_unicode(share(inv));
  invariant_fuzz_unicode(share(inv));
  invariant_fuzz_lookaround(share(inv));
  invariant_fuzz_us(share(inv));
  parser_fuzz(share(parser_it));
  differential_info(share(diff_it));
}

int main(int argc, char **argv) {
  std::uint32_t base = 0xC0FFEE; // base seed
  int jobs = 0;                  // 0 => auto-detect cores
  int inv = 25000;              // per invariant_* function; others scale to it

  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    auto val = [&](const char *def) -> const char * {
      return i + 1 < argc ? argv[++i] : def;
    };
    if (a == "-j" || a == "--jobs")
      jobs = std::atoi(val("0"));
    else if (a == "--seed")
      base = static_cast<std::uint32_t>(std::strtoul(val("0"), nullptr, 0));
    else if (a == "--iters")
      inv = std::atoi(val("25000"));
    else if (a == "-h" || a == "--help") {
      std::printf("usage: regexlib_fuzz [--jobs N] [--seed S] [--iters N]\n"
                  "  --jobs   worker threads (default: detected cores)\n"
                  "  --seed   base RNG seed (default: 0xC0FFEE)\n"
                  "  --iters  per invariant_* function (default: 25000)\n");
      return 0;
    } else {
      std::fprintf(stderr, "unknown arg: %s (try --help)\n", a.c_str());
      return 2;
    }
  }

  if (jobs <= 0) {
    unsigned hc = std::thread::hardware_concurrency();
    jobs = hc ? static_cast<int>(hc) : 1;
  }
  // Preserve the original cross-function ratios (parser 30000, diff 12000
  // relative to invariant 25000).
  int parser_it = static_cast<int>(static_cast<long>(inv) * 6 / 5);
  int diff_it = static_cast<int>(static_cast<long>(inv) * 12 / 25);

  std::printf("regexlib_fuzz: jobs=%d seed=0x%X iters=%d\n", jobs, base, inv);

  std::vector<std::thread> pool;
  pool.reserve(jobs - 1);
  for (int t = 1; t < jobs; t++)
    pool.emplace_back(run_worker, base, jobs, t, inv, parser_it, diff_it);
  run_worker(base, jobs, 0, inv, parser_it, diff_it); // worker 0 on main thread
  for (auto &th : pool) th.join();

  std::printf("[info] differential vs std::regex: %ld compared, %ld diffs, "
              "%ld skipped (platform-dependent; not a gate)\n",
              g_diff_cmp.load(), g_diff_diff.load(), g_diff_skip.load());

  int fails = g_fail.load();
  if (fails == 0) {
    std::printf("regexlib_fuzz: all invariants held, no crashes\n");
    return 0;
  }
  std::printf("regexlib_fuzz: %d invariant violations "
              "(reproduce with --jobs %d --seed 0x%X --iters %d)\n",
              fails, jobs, base, inv);
  return 1;
}
