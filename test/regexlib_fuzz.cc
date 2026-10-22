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
//   2. INFO (not a gate, and only with --std-diff): a differential pass
//      against std::regex (ECMAScript, which is leftmost-first like us) over
//      the common ASCII subset. The diff count is printed but does NOT fail
//      the test, because std::regex semantics vary across standard libraries
//      (libc++ vs libstdc++ differ on \b at string end and on
//      match-complexity limits). It is a human signal, not a portable
//      assertion.
//
//      It is off unless asked for because std::regex backtracks, and the run
//      is then as long as its worst search: with the default seed, one
//      std::regex_search over a 9-byte subject takes 44 s and another 7 s —
//      four fifths of the whole run (50 s against 13 s), and some 14 of the
//      17 minutes of the run under ASan. Nothing regexlib does is in those
//      seconds.
//
//  Run time. The default budget (--iters 25000 per invariant_* function, 17
//  of them) is sized for a Release build: about 0.35 s of CPU per hundred
//  iterations, spread over the worker threads. Under AddressSanitizer the same
//  work takes about 7x as long, under UBSan about 5x, under both about 15x
//  (measured, one worker, 200 iterations: 2.3 s plain, 16.7 s ASan, 11.0 s
//  UBSan, 33.8 s both) — every allocation, free and memset the engines make is
//  instrumented, and they make many. A default run of the full budget under
//  ASan+UBSan is then over twenty minutes on four cores. The sanitizer's job
//  here is memory safety on the paths the fuzzer reaches, which a fifth of the
//  draws reach as surely, so an ASan build defaults to a fifth of the budget
//  (kDefaultIters); the plain build, which checks the invariants against the
//  Pike reference over the full budget, is unchanged. --iters sets either.
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

// Whether this build runs under AddressSanitizer (see "Run time" above).
#if defined(__SANITIZE_ADDRESS__)
constexpr bool kAsan = true;
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
constexpr bool kAsan = true;
#else
constexpr bool kAsan = false;
#endif
#else
constexpr bool kAsan = false;
#endif

// --iters, per invariant_* function, when the command line does not say.
constexpr int kDefaultIters = kAsan ? 5000 : 25000;

// The fuzzer's view into a Regex's plan (the header declares the peer and
// befriends it): whether a Regex is served by the Pike VM and by nothing
// else — no literal, DFA or assert tier, and none of the Pike rung's own
// accelerators either (the start filters that skip to a candidate, the
// bounded backtracker) — with its groups resolved by the VM, not reported
// as the whole match of a capture-free twin. Every reference below is built
// through pike_reference(), which asks.
namespace reg {
namespace detail {
struct PlanProbe {
  static bool literal_only(const Regex &re) { return re.plan_->literal_only_; }
  // Whether a text-anchored plan starts every scan on Rung::TextAnchor, the
  // find from 0, which hands the scan to no other rung: what lets the
  // family rungs and the walk's drivers know nothing of a text anchor.
  static bool text_anchor_starts(const Regex &re) {
    const auto &p = *re.plan_;
    if (!p.text_anchored_) return true;
    for (const auto &st : p.start_)
      if (st.rung != Regex::Rung::TextAnchor) return false;
    return true;
  }
  static bool pike_only(const Regex &re) {
    const auto &p = *re.plan_;
    return !p.literal_only_ && p.literal_alt_.empty() && !p.dfa_ok_ &&
           !p.text_anchored_ &&
           !p.dfa_assert_ok_ && !p.byte_path_ && !p.byte_assert_path_ &&
           !p.lf_prog_.ok() && !p.assert_.anchor_gatefree &&
           !p.aop_.ok && !p.wop_.ok && !p.prefix_.active() && !p.teddy_.ok &&
           !p.first_bytes_.ok && !p.cap_bitstate_ && !p.alias_groups_;
  }
  // Whether the byte classes are exact, for each program of the plan a lazy
  // DFA runs over: classes numbered in byte order, and no instruction that
  // tells two bytes of one class apart (checked against lazy_inst_matches,
  // the question the lazy DFA asks). `max_insts` skips a program too long to
  // be worth the walk here.
  static bool classes_exact(const Regex &re, size_t max_insts = ~size_t{0}) {
    using Op = reg::detail::Inst::Op;
    const auto &p = *re.plan_;
    auto ok = [&](const reg::detail::Program &prog) {
      if (prog.insts.empty() || prog.insts.size() > max_insts) return true;
      const Regex::Plan::ByteClasses bc = p.byte_classes(prog, !p.dfa_ok_);
      if (!bc.n) return true; // not a program a lazy DFA runs over
      int rep[256];
      std::fill(std::begin(rep), std::end(rep), -1);
      unsigned next = 0;
      for (int b = 0; b < 256; b++) {
        const unsigned c = bc.cls[static_cast<size_t>(b)];
        if (c >= bc.n) return false;
        if (rep[c] < 0) {
          if (c != next++) return false;
          rep[c] = b;
        }
      }
      if (next != bc.n) return false;
      for (const auto &in : prog.insts) {
        if (in.op != Op::Byte && in.op != Op::Char && in.op != Op::Class &&
            in.op != Op::Any)
          continue;
        for (int b = 0; b < 256; b++)
          if (p.lazy_inst_matches(prog, in, static_cast<unsigned char>(b)) !=
              p.lazy_inst_matches(
                  prog, in,
                  static_cast<unsigned char>(
                      rep[bc.cls[static_cast<size_t>(b)]])))
            return false;
      }
      return true;
    };
    return ok(p.prog_) && ok(p.rev_prog_.prog) && ok(p.lf_prog_.prog) &&
           ok(p.byte_prog_.prog) && ok(p.byte_rev_prog_.prog) &&
           ok(p.byte_lf_prog_.prog) && ok(p.inner_.pre_rev.prog);
  }
  // The lazy DFAs of a cache, built small: `bytes` of cache each, and
  // `min_clears` refills before a fill has to have paid for itself (see
  // LazyDfa). What `c` holds is dropped, so the settings are what its next
  // scan builds with — until it is bound to another Regex.
  static void dfa_cache(const Regex &re, Regex::FindCache &c, size_t bytes,
                        uint32_t min_clears) {
    c.rebind(re);
    c.dfa_bytes_ = bytes;
    c.dfa_min_clears_ = min_clears;
  }
  // ... and the same for the calling thread's own cache of `re`, which
  // search / test / match and the cache-less finds draw on.
  static void dfa_cache(const Regex &re, size_t bytes, uint32_t min_clears) {
    dfa_cache(re, re.thread_cache(), bytes, min_clears);
  }
  // What test() answers with the boolean look scan's skip to the assert
  // prefix off (LazyDfa::kSkipAssert): every byte stepped, as before there was
  // one. On this thread's cache of `re`, whatever its budget.
  static bool test_unskipped(const Regex &re, std::string_view s) {
    (void)re.test(s); // builds the DFA the boolean steps for this subject
    Regex::FindCache &c = re.thread_cache();
    std::optional<Regex::LazyDfa> *const dfas[] = {
        &c.dfas_[0][Regex::kDfaBool], &c.dfas_[1][Regex::kDfaBool]};
    using L = Regex::LazyDfa;
    bool was[2] = {};
    for (int k = 0; k < 2; k++)
      if ((was[k] = *dfas[k] && (*dfas[k])->skip == L::kSkipAssert))
        (*dfas[k])->skip = L::kSkipNone;
    const bool r = re.test(s);
    for (int k = 0; k < 2; k++)
      if (was[k]) (*dfas[k])->skip = L::kSkipAssert;
    return r;
  }
  // Whether test() over the ASCII assert tier takes the word scan, its
  // start set sparse (Plan::word_scan_sparse).
  static bool word_scan_sparse(const Regex &re) {
    return re.plan_->word_scan_sparse();
  }
  // The families a Grapheme scan of `re` (a find's, or a boolean's: `test`)
  // can stand on, as ladder_gated chooses them, but the one with a (?i)
  // probe chosen for its subject (kFamEgcByteIp, which find_run is not
  // handed): the byte family, the ASCII one, the byte assert one.
  static std::vector<int> step_families(const Regex &re, bool test) {
    const auto &p = *re.plan_;
    std::vector<int> f;
    if (p.us_) return f;
    if (p.byte_path_) f.push_back(Regex::kFamEgcByte);
    if (p.ascii_family(test) != Regex::kFamilyCount)
      f.push_back(p.ascii_family(test));
    if (p.byte_assert_path_) f.push_back(Regex::kFamAssertByte);
    return f;
  }
  // Where `text`, read from its start, stops being one family `fam`
  // answers for (Regex::family_unsound_at).
  static size_t unsound_at(const Regex &re, int fam, std::string_view text) {
    return re.family_unsound_at(static_cast<Regex::Family>(fam), text,
                                Regex::first_nonascii(text));
  }
  static size_t guess_end(std::string_view text, int reach) {
    return Regex::guess_end(text, reach);
  }
  // One step of family `fam`'s ladder (a find's, or a boolean's: `test`;
  // `short_test` the boolean's over a short subject) from byte `pos`, taken
  // as find_rest takes a guess's (find_run): whether it found a match (`r`
  // holds it for a find), how far it read (Regex::step_reach), and whether
  // it stayed on the family — not on the Pike, the reference, nor on a
  // family the subject chose.
  struct Step {
    bool found = false;
    MatchResult r;
    int reach = 0;
    bool on_family = false;
  };
  static Step family_step(const Regex &re, int fam, bool test, bool short_test,
                          std::string_view text, int pos) {
    Step st;
    Regex::Ladder l = re.plan_->family_[fam][test ? (short_test ? 2 : 1) : 0];
    l.set(Regex::Ladder::kSpec);
    Regex::Scr scr;
    Regex::Cursor c;
    c.pos = pos;
    bool walked = false;
    if (test) {
      Regex::NoSink out;
      st.found = re.find_run(text, scr, l, c, walked, out);
    } else {
      Regex::ResultSink out{st.r};
      st.found = re.find_run(text, scr, l, c, walked, out);
    }
    st.on_family = Regex::guess_open(l);
    st.reach = Regex::step_reach(text, scr, l, c, walked, st.found);
    return st;
  }
};
} // namespace detail
} // namespace reg

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

// `s` with one to three pieces that are no UTF-8 (RFC 3629) put in at byte
// offsets drawn at random, a code point's interior among them: lone leads
// and continuations, a byte that leads nothing, a sequence cut short, an
// overlong form, a surrogate, a form past U+10FFFF. Every tier has to read
// them as the Pike does. However the bytes around a piece complete it, the
// code point made is Latin-1, CJK, currency, an emoji or private use: never
// one that joins a cluster, so a subject of single-code-point clusters
// stays one (what check_us_vs_pike and invariant_fuzz_us compare on).
std::string with_strays(std::string s) {
  static const char *const kStray[] = {
      "\xC3",     "\xE9",         "\xF4",     "\x80",         "\xBF",
      "\xFF",     "\xE2\x82",     "\xF0\x9F\x98", "\xC0\xAF", "\xED\xA0\x80",
      "\xF4\x90\x80\x80"};
  for (int k = U(1, 3); k > 0; k--)
    s.insert(static_cast<size_t>(U(0, static_cast<int>(s.size()))),
             kStray[U(0, 10)]);
  return s;
}

// One of `subjects`, drawn at random, with strays put in (with_strays):
// every pattern of the list's invariant meets one.
void stray_one(std::vector<std::string> &subjects) {
  if (subjects.empty()) return;
  std::string &s = subjects[static_cast<size_t>(
      U(0, static_cast<int>(subjects.size()) - 1))];
  s = with_strays(std::move(s));
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

// The reference the differentials compare against: `pat` on the Pike VM,
// forced there by a transformation no accelerated tier can see through. An
// empty LOOKAHEAD `(?=)` matches at every position and consumes nothing, so
// the wrapped pattern has exactly the bare pattern's matches and groups, and
// a lookaround is a construct neither DFA family compiles. (Not
// `(?=[\s\S]|$)`: no class takes a stray byte, so that one fails in front
// of one.)
//
// It used to be `(?:PAT)(?:\b|\B)`, from before the assert tiers existed.
// They serve `\b` and `\B`, so that wrap had come to run on the assert DFAs
// whenever a subject passed their gates — the tiers under test, sharing their
// gates with the code it was supposed to check (`t[^.]+[^q]+\.` matched
// "t\r\n." on both sides). Nothing noticed, because nothing asked; this
// does. A reference that is not Pike-only is a failure of the run.
//
// The same lookahead goes in FRONT as well. The Pike rung is not the bare VM:
// it skips to a candidate first (a literal prefix, Teddy, the first-byte
// set) — at every entry point, since they share one ladder. A reference
// that took those would share them with any pattern the Pike serves; behind
// a lookahead none of them is planned, and the VM starts at every position.
// The front one in a group of its own: a pattern every match of which
// starts at 0 (text_anchored_, `^a`) is found from 0 alone, and the
// analysis that says so looks past a bare lookahead in front — through the
// group it does not. The reference is then the VM started everywhere, and
// it checks that analysis too.
reg::Regex *pike_reference(const std::string &pat, unsigned flags,
                           reg::MatchUnit unit) {
  reg::Regex *pike = nullptr;
  try {
    pike = new reg::Regex("(?:(?=))(?:" + pat + ")(?=)", flags, unit);
  } catch (...) {
    return nullptr; // wrapping may hit a limit; the caller skips the compare
  }
  if (!reg::detail::PlanProbe::pike_only(*pike))
    fail("reference is not Pike-only", pat, "");
  return pike;
}
reg::Regex *pike_reference(const std::string &pat, unsigned flags = 0) {
  return pike_reference(pat, flags, reg::MatchUnit::Grapheme);
}

// The lazy DFAs' cache budget, shrunk for some of the patterns. Stock, a DFA
// holds megabytes and no generated pattern comes near filling it, so the two
// things a full cache does would never run: clear and refill from the state
// the scan stands in (every state id but that one dies, the table moves,
// the start state is made again), and give up for the Pike in the middle of
// a scan. A cache of a few hundred bytes does one or the other every few
// steps, at every entry point — search / test / match and the cache-less
// finds through the thread's cache of `re`, the rest through `held`.
//
// Which patterns, and how small, comes from the pattern's text (and `salt`,
// for the layers that run one pattern in both match units), not from the
// run's generator: the patterns a seed draws stay the ones it drew before.
// Most keep the stock budget. The shared cache of check_shared_cache always
// does — it is bound to a different Regex each time, which resets it.
//
// (Every layer that builds a Regex to check passes it through here, so this
// is also where a sample of the patterns have their plan's byte classes
// checked against the programs they were computed for.)
void squeeze_dfa_cache(const reg::Regex &re, const std::string &pat,
                       unsigned salt = 0,
                       reg::Regex::FindCache *held = nullptr) {
  std::uint32_t h = 2166136261u ^ salt;
  for (unsigned char c : pat)
    h = (h ^ c) * 16777619u;
  h ^= h >> 15;
  // One pattern in sixteen also has its byte classes checked against its
  // programs, instruction by instruction (see classes_exact) — whatever the
  // scans below happen to step.
  if ((h >> 20) % 16 == 0 &&
      !reg::detail::PlanProbe::classes_exact(re, /*max_insts=*/6000))
    fail("byte classes merge bytes an instruction tells apart", pat, "");
  const unsigned mode = h % 8;
  if (mode < 5) return; // stock
  // From "every new state clears" up to "a few dozen states".
  static const size_t kBytes[] = {280, 420, 700, 1400, 4000};
  const size_t bytes = kBytes[(h >> 8) % 5];
  // Mostly: refill for as long as it takes (clearing is what gets
  // exercised). Else the give-up, at once or after a refill or two.
  const std::uint32_t min_clears = mode < 7 ? ~0u : (h >> 16) % 3;
  reg::detail::PlanProbe::dfa_cache(re, bytes, min_clears);
  if (held) reg::detail::PlanProbe::dfa_cache(re, *held, bytes, min_clears);
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

// A FindCache SHARED WITH OTHER REGEXES: one that outlives every pattern, so
// it arrives at each new one bound to the last (by then destroyed), and — the
// Grapheme and CodePoint checks both draw on it — midway to whatever rung
// that one's scan left it on. A step has to bind it before any rung reads a
// DFA out of it: whichever rung the scan starts on, and whichever it moves to
// within the step. The iterator and the single step over it, against the
// rows find_all gave.
void check_shared_cache(const reg::Regex &re, const std::string &subj,
                        const std::vector<reg::MatchResult> &all,
                        const std::string &pat) {
  static thread_local reg::Regex::FindCache shared;
  try {
    size_t i = 0;
    for (auto m : re.find_iter(subj, shared)) {
      if (i >= all.size() || m.begin() != all[i].begin() ||
          m.end() != all[i].end()) {
        fail("find_iter(shared cache) vs find_all", pat, subj);
        return;
      }
      i++;
    }
    if (i != all.size()) {
      fail("find_iter(shared cache) count != find_all", pat, subj);
      return;
    }
    auto at = re.find_at(subj, 0, shared);
    if (at.m.matched() != !all.empty() ||
        (at.m.matched() && (at.m.begin() != all[0].begin() ||
                            at.m.end() != all[0].end())))
      fail("find_at(shared cache) vs find_all", pat, subj);
  } catch (...) {
    fail("find_iter(shared cache) threw", pat, subj);
  }
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
  check_shared_cache(re, subj, all, pat);
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

// A step's answer depends on nothing past its reach (Regex::step_reach):
// on no byte at or past guess_end(reach), the end of the code point there.
// What a guess and a cut text (docs/design.md) both stand on. One family
// of the plan, drawn at random, steps (a find from 0 or from a resume
// position, a boolean from 0) over the part of the subject it answers for
// — where a cut text would end — a find behind 4 KB of newlines or none (a
// walk's budget is seeded with the subject's length: a short one runs out
// in two failed walks). Past guess_end the text is then cut off, or goes on with
// a cluster no family answers for, a CR-LF or an ASCII byte, and maybe a
// piece of the subject: the step answers as before, and for a find with
// the same match and groups. (A step that left the family — for the Pike,
// the reference, or for a family the subject chose — is not compared.)
// Its draws come from the pattern and the subject, not from the stream the
// other checks draw on, which is then what it was without this one. On
// half the subjects: on all, it was 7% of the fuzzer's run.
void check_reach(const reg::Regex &re, const std::string &subj,
                 const std::vector<reg::MatchResult> &all,
                 const std::string &pat) {
  using P = reg::detail::PlanProbe;
  std::mt19937 own(static_cast<uint32_t>(std::hash<std::string>{}(pat) * 31 +
                                         std::hash<std::string>{}(subj)));
  auto draw = [&own](int lo, int hi) {
    return std::uniform_int_distribution<int>(lo, hi)(own);
  };
  if (draw(0, 1)) return;
  const bool test = draw(0, 1) != 0;
  const std::vector<int> fams = P::step_families(re, test);
  if (fams.empty()) return;
  const int fam =
      fams[static_cast<size_t>(draw(0, static_cast<int>(fams.size()) - 1))];
  const bool short_test = draw(0, 1) != 0;
  // (A find's: a boolean scans from 0, and would read the newlines too.)
  const int pad = !test && draw(0, 1) ? 4096 : 0;
  const std::string text = std::string(static_cast<size_t>(pad), '\n') + subj;
  const std::string_view sound(text.data(), P::unsound_at(re, fam, text));
  // (A boolean scans from 0: test() takes no other step.)
  int pos = test ? 0 : pad;
  if (!test && !all.empty() && draw(0, 1))
    pos += static_cast<int>(
        all[static_cast<size_t>(draw(0, static_cast<int>(all.size()) - 1))]
            .end());
  if (pos > static_cast<int>(sound.size())) return;
  static const char *const kOn[] = {
      "", "", "\xE2\x9D\xA4\xEF\xB8\x8F", "e\xCC\x81", "\r\n", "a", " ", "_"};
  try {
    const P::Step a = P::family_step(re, fam, test, short_test, sound, pos);
    if (!a.on_family || !a.found) return;
    const size_t e = P::guess_end(sound, a.reach);
    if (e >= sound.size()) return;
    const int on = draw(0, 7);
    // ... and half the time a piece of the subject: what completes a
    // candidate the step failed for want of more text.
    std::string piece;
    if (!subj.empty() && draw(0, 1))
      piece = subj.substr(
          static_cast<size_t>(draw(0, static_cast<int>(subj.size()) - 1)),
          static_cast<size_t>(draw(1, 8)));
    const std::string cut = std::string(sound.substr(0, e)) + kOn[on] + piece;
    // (Not a piece that goes on with the code point at the reach, or with
    // its CR-LF: a continuation byte after a lead byte the subject cut
    // short, an LF after its CR. guess_end takes those in, so no text has
    // one past it.)
    if (P::guess_end(cut, a.reach) != e) return;
    const P::Step b = P::family_step(re, fam, test, short_test, cut, pos);
    if (!b.on_family) return;
    // (Positions in the text the step read: behind the newlines if padded.)
    const std::string what =
        "step past its reach (family " + std::to_string(fam) +
        (test ? short_test ? ", short test" : ", test" : "") + ", from " +
        std::to_string(pos) + ", reach " + std::to_string(a.reach) +
        ", cut at " + std::to_string(e) + " + kOn[" + std::to_string(on) +
        "] + \"" + piece + "\"" + (pad ? ", behind 4096 newlines" : "") +
        ")";
    const std::string shown(sound.substr(static_cast<size_t>(pad)));
    if (b.found != a.found)
      fail(what + ": found differs", pat, shown);
    else if (!test)
      compare_groups(b.r, a.r, what.c_str(), pat, shown);
  } catch (...) {
    fail("family step threw", pat, subj);
  }
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
      if (U(0, 3) == 0) subj = with_strays(std::move(subj));
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
    squeeze_dfa_cache(*re, pat, 0, &cache);
    for (int s = 0; s < 5; s++) {
      std::string subj = gen_usubject();
      if (U(0, 3) == 0) subj = with_strays(std::move(subj));
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

// The whole invariant battery for ONE generated pattern over a list of
// subjects: every surface checked for self-consistency, then all of them
// against the forced-Pike reference. invariant_fuzz and the shape-targeted
// generator below share this, so a new generator cannot silently check less
// than the old one does.
void check_pattern(const std::string &pat,
                   const std::vector<std::string> &subjects) {
  reg::Regex *re = nullptr;
  try {
    re = new reg::Regex(pat);
  } catch (const reg::RegexError &) {
    return; // rejecting a pattern is fine
  } catch (...) {
    fail("non-RegexError thrown at construction", pat, "");
    return;
  }
  if (!reg::detail::PlanProbe::text_anchor_starts(*re))
    fail("text-anchored plan does not start on Rung::TextAnchor", pat, "");
  // The DFA-vs-Pike reference (see pike_reference): search/find_all take the
  // accelerated tiers for the bare pattern, this takes the Pike for the same
  // matches. Null when the wrap hit a limit; the differential is skipped.
  reg::Regex *pike = pike_reference(pat);
  reg::Regex::FindCache cache; // reused across this pattern's subjects
  squeeze_dfa_cache(*re, pat, 0, &cache);
  for (const std::string &subj : subjects) {
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
        // reference's wrap is non-capturing, so it keeps
        // PAT's own groups — this validates the leftmost-first capture
        // tiers (S3) against the Pike.
        for (size_t i = 0; i < all.size(); i++)
          compare_groups(all[i], ref[i], "find_all vs Pike", pat, subj);
    }
    check_cache(*re, subj, all, cache, pat);
    check_scan(*re, subj, all, pat);
    check_reach(*re, subj, all, pat);
  }
  delete re;
  delete pike;
}

void invariant_fuzz(int iters) {
  for (int it = 0; it < iters; it++) {
    std::vector<std::string> subjects;
    for (int s = 0; s < 5; s++)
      subjects.push_back(gen_subject());
    stray_one(subjects);
    check_pattern(gen_alt(3), subjects);
  }
}

// --- One-walk tier shapes: a repeat that can run more than once over a
// variable-width body. ---
//
// The one-walk tiers (AnchoredOnePass, WordOnePass, the unbounded capture
// walk) decide a match by reading a one-pass table's LAST accept as the
// leftmost-first end. For this exact family that reading is wrong: a long
// single iteration and two short ones end at different offsets, BOTH accept,
// and the last one is the longest parse rather than the end a backtracker
// commits to. `(?:[a-cb].{0,4})+` over "bbc 23_\n_2" accepts at 5 and again at
// 7, and 5 is the answer. Two bugs of exactly this shape shipped (one on the
// bare `^body` table, one on WordOnePass without a trailing `\b`), so the
// structural rules that bar it now live in one predicate — onepass_body_ok /
// onepass_cut_ast_ok in regexlib.h.
//
// gen_alt reaches the family only by accident: it has to draw the anchor, the
// group, a repeat quantifier ON the group and a variable-width quantifier
// INSIDE it, all in one pattern, and then a subject that separates the two
// parses. This generator draws only from that family, so the differential
// actually gets to see it.
std::string gen_onepass_repeat() {
  // A leading `^` or `\b` is what puts a pattern on the one-walk tiers at all
  // (AnchoredOnePass / WordOnePass); unanchored draws still reach the
  // unbounded capture walk through the candidate drivers.
  static const char *HEAD[] = {"^", "\\b", "^", "\\b", "", "\\b\\w*"};
  static const char *ATOM[] = {"[a-c]", ".",  "\\w", "\\d",
                               "a",     "\\s", "[a-cA-C1-3]"};
  // Quantifiers that make the repeat body VARIABLE-width (the whole point).
  static const char *VQ[] = {"{0,2}", "{0,4}", "?", "*", "{0,3}", "{1,3}"};
  // Quantifiers on the group itself that let it run more than once.
  static const char *RQ[] = {"+", "*", "{1,3}", "{2,}", "{1,}", "{2,4}"};
  // A tail that can push the reported end past a passed-over accept, and the
  // trailing anchors that switch the table to its uncut flavour.
  static const char *TAIL[] = {"", "$", "\\b", "x?", "[qr]", "\\d?", "_*"};
  std::string body;
  int k = U(2, 3);
  int vq_at = U(0, k - 1); // at least one variable-width piece
  for (int i = 0; i < k; i++) {
    body += ATOM[U(0, 6)];
    if (i == vq_at || U(0, 1)) body += VQ[U(0, 5)];
  }
  std::string grp = (U(0, 2) == 0 ? "(" : "(?:") + body + ")";
  return std::string(HEAD[U(0, 5)]) + grp + RQ[U(0, 5)] + TAIL[U(0, 6)];
}

void invariant_fuzz_onepass_repeat(int iters) {
  for (int it = 0; it < iters; it++) {
    std::vector<std::string> subjects;
    for (int s = 0; s < 3; s++)
      subjects.push_back(gen_subject());
    // One padded subject per pattern. The candidate drivers' WalkBudget is
    // seeded from the subject length, so on a 10-byte subject a couple of
    // failed candidate walks exhaust it and the driver hands the find back to
    // the proven chain — hiding whatever the walk would have answered. The
    // filler is `\n`, which only `\s` among the atoms above matches (dotall is
    // off, so `.` does not): padding buys budget while usually leaving the
    // interesting positions at the two ends rather than burying them under
    // thousands of matches for the Pike reference to reproduce.
    subjects.push_back(gen_subject() + std::string(4096, '\n') +
                       gen_subject());
    stray_one(subjects);
    check_pattern(gen_onepass_repeat(), subjects);
  }
}

// --- WordOnePass's candidates: the `\b`-led shapes the word scan drives. ---
//
// The find takes its candidates from a scan that answers for a block of
// sixteen positions at a time (word_start_block): a byte of the body's start
// set after a byte that is not a word byte. What that scan can get wrong is
// positional — the lane carried from one block into the next, the partial
// block at the end, where the entry ramp hands over — and gen_subject's
// dozen bytes never leave the ramp. These
// subjects run to several blocks, of tokens that start a candidate at every
// alignment: ones that match, ones that fail a byte or two in, and runs with
// no candidate at all.
std::string gen_word_start() {
  static const char *HEAD[] = {"[0-9]", "[a-c]", "\\d", "[A-C]",
                               "[xy]",  "[a-c1-3]", "\\w", "[_a]"};
  static const char *BODY[] = {"+",       "{1,3}",          "[a-c]+",
                               "[0-9]*x", "(?:\\.[0-9]{1,2}){2}",
                               "\\w+",    "{2}",            "[a-c]{0,2}[0-9]"};
  static const char *TAIL[] = {"\\b", "\\b", "\\b", "x?", "[0-9]?"};
  return std::string("\\b") + HEAD[U(0, 7)] + BODY[U(0, 7)] + TAIL[U(0, 4)];
}

void invariant_fuzz_word_start(int iters) {
  static const char *UNITS[] = {"a",  "b",   "c",   "A",    "1",     "2",
                                "9",  "x",   "_",   " ",    ".",     "-",
                                "\n", ", ",  "12",  "1.2",  "ab1",   "a.b",
                                " 3", ".9.", "x1 ", "\r\n", "1.2.3", "B2"};
  for (int it = 0; it < iters; it++) {
    std::vector<std::string> subjects;
    for (int s = 0; s < 4; s++) {
      std::string subj;
      // Word-dense, sparse, or mostly separators; now and then a stretch
      // with no candidate, longer than a block.
      const int n = U(0, 70), bias = U(0, 2);
      for (int i = 0; i < n; i++) {
        if (U(0, 24) == 0)
          subj += std::string(static_cast<size_t>(U(1, 40)),
                              U(0, 1) ? ' ' : 'q');
        subj += UNITS[bias == 0 ? U(0, 23) : bias == 1 ? U(9, 13) : U(0, 8)];
        if (bias != 0 && U(0, 3) == 0) subj += UNITS[U(0, 23)];
      }
      subjects.push_back(subj);
    }
    stray_one(subjects);
    check_pattern(gen_word_start(), subjects);
  }
}

// US (CodePoint) differential against the EGC forced Pike: find_all, search,
// match and find_iter of `pat` built in CodePoint mode must give the spans
// and groups the grapheme Pike gives. The oracle is valid on subjects whose
// every cluster is ONE code point and that hold no `\r` (US never fuses
// CR-LF, EGC does) — the callers' job. It is the EGC engine on purpose: the code-point
// Pike shares its program with the one-walk tables it would be checking.
// Where the modes part is what a caller is after — the tiers that read the
// byte program or the AST, not those tables — it asks for the code-point
// Pike (`oracle`), and any subject goes.
void check_us_vs_pike(const std::string &pat,
                      const std::vector<std::string> &subjects,
                      reg::MatchUnit oracle = reg::MatchUnit::Grapheme) {
  reg::Regex *us = nullptr, *pike = nullptr;
  try {
    us = new reg::Regex(pat, 0u, reg::MatchUnit::CodePoint);
  } catch (...) {
    return; // rejected pattern: nothing to compare
  }
  if (!reg::detail::PlanProbe::text_anchor_starts(*us))
    fail("text-anchored plan does not start on Rung::TextAnchor (CodePoint)",
         pat, "");
  pike = pike_reference(pat, 0u, oracle);
  if (!pike) {
    delete us;
    return; // wrap limit
  }
  squeeze_dfa_cache(*us, pat, /*salt=*/1);
  for (const std::string &subj : subjects) {
    std::vector<reg::MatchResult> all, ref;
    reg::MatchResult one;
    try {
      all = find_all(*us, subj);
      ref = find_all(*pike, subj);
      one = us->search(subj);
    } catch (...) {
      fail("US vs Pike: matcher threw", pat, subj);
      continue;
    }
    if (all.size() != ref.size()) {
      fail("US vs Pike: find_all count", pat, subj);
      continue;
    }
    bool ok = true;
    for (size_t i = 0; i < all.size() && ok; i++)
      ok = compare_groups(all[i], ref[i], "US find_all vs Pike", pat, subj);
    if (!ok) continue;
    if (one.matched() != !all.empty())
      fail("US vs Pike: search matched != find_all", pat, subj);
    else if (one.matched())
      compare_groups(one, all[0], "US search vs find_all[0]", pat, subj);
    bool t = false;
    try {
      t = us->test(subj);
    } catch (...) {
      fail("US vs Pike: test() threw", pat, subj);
      continue;
    }
    if (t != one.matched())
      fail("US test() != search().matched()", pat, subj);
    // match(): anchored at 0, its own tiers in front of the ladder's.
    try {
      const reg::MatchResult m0 = us->match(subj), r0 = pike->match(subj);
      if (m0.matched() != r0.matched())
        fail("US vs Pike: match()", pat, subj);
      else if (m0.matched())
        compare_groups(m0, r0, "US match() vs Pike", pat, subj);
    } catch (...) {
      fail("US vs Pike: match() threw", pat, subj);
    }
    check_scan(*us, subj, all, pat);
    check_shared_cache(*us, subj, all, pat);
  }
  delete us;
  delete pike;
}

// --- Whole-match capture shapes: every group wraps the entire pattern. ---
//
// `(\w+)`, `((x))`, `(?:(\w+))`, `(?<n>\w+)`. Such a pattern is planned and
// run as its capture-free twin — the groups at the root are peeled off the
// AST, so every tier, prefilter and walk the twin gets is what runs — and the
// groups are written back, each as the whole match, where a result is handed
// out: search()/match() build one way, find_all widens its rows, find_iter
// its single row. A non-capturing wrapper `(?:\w+)` is peeled the same way
// and reports no groups. The reference keeps the groups REAL: the forced-Pike
// wrap (pike_reference) puts the wrappers below the root, so its Save slots
// are computed, not aliased.
//
// gen_alt wraps a whole pattern in a group only when the top-level concat
// happens to be a single unquantified group atom. This generator draws only
// the shape, over bodies that land the twin on different tiers.
std::string gen_whole_match_capture() {
  std::string body;
  switch (U(0, 3)) {
  case 0:
  case 1: {
    // One-walk bodies: Alt-free, greedy-only, no group under a repeat. An
    // optional literal head (the prefix candidate driver) and one piece that
    // is never optional, so the body cannot match empty.
    static const char *HEAD[] = {"", "", "a", "ab", "_", "1"};
    static const char *ATOM[] = {"[a-c]",  "\\w", "\\d",          "\\s",
                                 "[^\\n]", "a",   "[a-cA-C1-3]", "[^ ]"};
    static const char *Q1[] = {"+", "+", "", "{1,3}", "{2}", "{2,}"};
    static const char *Q0[] = {"*", "?", "{0,2}", "+", ""};
    body = HEAD[U(0, 5)];
    int k = U(1, 3), solid = U(0, k - 1);
    for (int i = 0; i < k; i++) {
      body += ATOM[U(0, 7)];
      body += (i == solid) ? Q1[U(0, 5)] : Q0[U(0, 4)];
    }
    break;
  }
  case 2:
    // Refused by the walk's cut rules (a variable-width body under a repeat
    // that can run more than once): gen_onepass_repeat's family, which must
    // stay on the chain.
    body = "(?:[a-c]" + std::string(U(0, 1) ? ".{0,4}" : "x?") + ")" +
           (U(0, 1) ? "+" : "{1,3}");
    break;
  default:
    // Anything: alternation, laziness, nullability, anchors (the assert
    // tiers), inner groups (which make it NOT whole-match — the neighbouring
    // shape, where the wrappers must stay real).
    body = gen_alt(1);
    break;
  }
  switch (U(0, 5)) {
  case 0: return "((" + body + "))";
  case 1: return "(?:(" + body + "))";
  case 2: return "(?<n>" + body + ")";
  case 3: return "(?:" + body + ")";
  default: return "(" + body + ")";
  }
}

void invariant_fuzz_whole_match_capture(int iters) {
  for (int it = 0; it < iters; it++) {
    const std::string pat = gen_whole_match_capture();
    std::vector<std::string> subjects;
    for (int s = 0; s < 3; s++)
      subjects.push_back(gen_subject());
    // Padded, for the reason invariant_fuzz_onepass_repeat pads: the walk
    // budget is seeded from the subject length, and a short subject hands the
    // find back to the chain after a couple of failed candidates.
    subjects.push_back(gen_subject() + std::string(2048, '\n') +
                       gen_subject());
    // One long match (the walk's SIMD run skip).
    subjects.push_back(gen_subject() + std::string(600, 'a') + gen_subject());
    stray_one(subjects);
    // EGC: the full battery, groups included, against the forced Pike.
    check_pattern(pat, subjects);

    // US (CodePoint): the same walk behind a different ladder (see
    // check_us_vs_pike for the oracle and what it asks of a subject). A
    // stray `é` puts a non-ASCII byte in the walk's way: it bails there and
    // the chain serves that match.
    static const char *UNITS[] = {"a", "b", "c",  "A", "C",
                                  " ", "1", "_",  "\n", "\xC3\xA9"};
    std::vector<std::string> us_subjects;
    for (int s = 0; s < 4; s++) {
      std::string subj;
      int n = U(0, 14), top = (s == 0) ? 9 : 8; // subject 0 may hold an é
      for (int i = 0; i < n; i++)
        subj += UNITS[U(0, top)];
      if (s == 3) subj += std::string(600, 'a') + " 1a";
      us_subjects.push_back(std::move(subj));
    }
    stray_one(us_subjects);
    check_us_vs_pike(pat, us_subjects);
  }
}

// --- One-walk drivers across non-ASCII bytes (US). ---
//
// The unbounded one-pass walk and the scalar capture chain step ASCII bytes
// only. In CodePoint mode they run on any subject, so a non-ASCII byte in a
// walk's way is routine, and it is LOCAL: the located-span chain serves that
// one find and the driver is asked again for the next (kWalkLocal). One
// subject therefore alternates between the two engines match by match, in
// find_all and in find_iter through different loops, and a subject where
// most finds bail makes the driver give up for good partway (the
// profitability rule) — a third regime on the same subject. All of it must
// be invisible in the results.
//
// invariant_fuzz_us reaches this only thinly: its patterns are mostly not
// one-walk admissible, its subjects are a dozen units long (the rule needs
// kilobytes before it can trip), and it does not check find_iter.
std::string gen_us_onewalk() {
  // Pieces a one-walk table admits (Alt-free, greedy-only), captured or not,
  // joined by literals that give the prefix / inner-literal / scalar-chain
  // drivers something to anchor on; a trailing `$` is the `body$` shape.
  static const char *HEAD[] = {"", "", "", "a", "_", "k"};
  static const char *ATOM[] = {"\\w", "\\d", "[a-c]", "[^ =:\\n]",
                               "\\s", "[a-c1-3]"};
  static const char *Q[] = {"+", "+", "+", "{1,3}", "*", "?", ""};
  static const char *SEP[] = {"", "", "=", ":", " ", "-", "\\s+"};
  static const char *TAIL[] = {"", "", "", "$"};
  std::string pat = HEAD[U(0, 5)];
  int k = U(1, 3), solid = U(0, k - 1);
  for (int i = 0; i < k; i++) {
    if (i) pat += SEP[U(0, 6)];
    std::string piece = ATOM[U(0, 5)];
    piece += (i == solid) ? Q[U(0, 3)] : Q[U(0, 6)];
    pat += (U(0, 2) == 0) ? "(" + piece + ")" : piece;
  }
  return pat + TAIL[U(0, 3)];
}

void invariant_fuzz_us_onewalk(int iters) {
  // Single-code-point clusters only, no `\r` (see check_us_vs_pike). The
  // last three are the non-ASCII ones: é (a word character), 日 (likewise)
  // and ¡ (punctuation — a non-ASCII byte that ENDS a word).
  static const char *UNITS[] = {"a", "b",          "c",          "1",
                                "2", "_",          " ",          "=",
                                ":", "-",          "\n",        "k",
                                "\xC3\xA9", "\xE6\x97\xA5", "\xC2\xA1"};
  for (int it = 0; it < iters; it++) {
    const std::string pat = gen_us_onewalk();
    std::vector<std::string> subjects;
    // Non-ASCII density per subject: none, sparse, about a fifth, about
    // half of the units.
    static const int NA_PER_20[] = {0, 1, 4, 10};
    auto gen = [&](int units, int na) {
      std::string subj;
      for (int i = 0; i < units; i++)
        subj += (U(0, 19) < na) ? UNITS[U(12, 14)] : UNITS[U(0, 11)];
      return subj;
    };
    for (int s = 0; s < 4; s++)
      subjects.push_back(gen(U(0, 40), NA_PER_20[s]));
    // Long enough for the regimes to change inside one subject: kilobytes of
    // mostly-ASCII (the driver keeps coming back), and — one pattern in four,
    // the Pike reference being what it costs — kilobytes where most finds
    // bail, so the profitability rule trips partway.
    subjects.push_back(gen(3000, 1));
    if (it % 4 == 0) subjects.push_back(gen(4000, 12));
    stray_one(subjects);
    check_us_vs_pike(pat, subjects);
  }
}

// --- Anchor choice: a literal at both ends of the pattern. ---
//
// A find is driven from ONE literal anchor — the pattern's required prefix,
// its required suffix or an interior literal — and which one is decided by
// estimated cost (Plan::AnchorChoice), not by position. So the suffix scan
// and the ReverseInner scan now run on patterns that begin with a literal,
// the assert tiers' leading literal runs on patterns that end with one, and a
// dense prefix is left to the plain scan. Each of those is an engine meeting
// a shape it was never asked to serve: the suffix scan's leftmost-first
// argument with a literal in the pre-part (which the body may absorb, or
// which may repeat inside the match), the reverse(pre) floor with a literal
// at its far end, the assert tiers' multi-character literal runs and the
// word-suffix shape `\b\w+ing\b`.
//
// gen_alt gets here only through `a`, `b` and `c`: three letters, all common,
// so its patterns sit on one side of every comparison the choice makes. This
// generator draws the head and the tail from both sides of the table — a
// common letter in front of a rare one, the reverse, both common, both rare,
// with and without an interior literal — and wraps half of the results in the
// assertions that move a pattern onto the assert tiers. The subjects are
// built from the same letters, so both ends occur densely, alone and
// together.
std::string gen_anchor_choice() {
  // Common by the table (a dense prefix), rare (a prefix that keeps the
  // find), or none / a class (class-led: the suffix against the start set).
  static const char *HEAD[] = {"e", "a",  "t",  "s",  "th", "ea",    "e",
                               "a", "q",  "z",  "Z",  "x1", "Zq",    "",
                               "",  "[A-Z]", "[a-c]"};
  static const char *ATOM[] = {"[a-z]", ".",   "\\w",    "[^.]",
                               "[a-c]", "[^q]", "\\s",   "a",
                               "[a-z ]", "[^\\n]", "e",  "[eq]"};
  static const char *Q[] = {"+", "*", "{3,}", "{2}", "{0,3}",
                            "?", "",  "{1,2}", "+",  "*"};
  static const char *MID[] = {"@", "-", " ", "q", "=", "e", "zq"};
  // Rare, common, one that ends on a non-word byte, none, a class-pair
  // anchor, a single class.
  static const char *TAIL[] = {"q",  "z",  "!",  "\\?", "x",  "ly",
                               "ing", "qz", "e",  "s",   "t",  "\\.",
                               ",",  "e!", "",   "[?!.][\"']", "[qz]"};
  auto atom_q = [&] { return std::string(ATOM[U(0, 11)]) + Q[U(0, 9)]; };
  if (U(0, 9) == 0) {
    // The word-suffix shape `\b\w{n,m}<literal>\b` with a literal of any
    // length — and its near misses, one time in four each: something in
    // front of the `\w` repeat, something between it and the literal,
    // something after the trailing `\b`. Each of those is a different
    // pattern that the shape's test must NOT take for the shape.
    static const char *WQ[] = {"+", "*", "{2,}", "{1,3}", "{0,2}"};
    static const char *WL[] = {"ing", "ly", "e", "qz", "s", "eq"};
    std::string pat = "\\b";
    if (U(0, 3) == 0) pat += U(0, 1) ? std::string(HEAD[U(0, 12)]) : atom_q();
    pat += std::string("\\w") + WQ[U(0, 4)];
    if (U(0, 3) == 0) pat += U(0, 1) ? std::string(MID[U(0, 6)]) : atom_q();
    pat += std::string(WL[U(0, 5)]) + "\\b";
    if (U(0, 3) == 0) pat += U(0, 1) ? std::string(MID[U(0, 6)]) : "$";
    return pat;
  }
  // Three families this generator found wrong on the released engine while
  // looking for something else, each drawn on purpose from here on.
  switch (U(0, 15)) {
  case 0: {
    // A skippable (or looping) group of several atoms behind a
    // variable-width atom, with something required after it: the one-walk
    // tables read their last accept as the leftmost-first end, and here a
    // thread that reached the group EARLIER — the lower-priority one — is
    // still inside it when a later arrival skips past
    // (`[a-z]{3,}(?:\w{2}-)?s` over "hssys-s", `x(?:ab)?(?:abc)?[a-z]`).
    static const char *VQ[] = {"+", "*", "{3,}", "{0,3}", "?", "{1,2}"};
    static const char *GQ[] = {"?", "?", "+", "*", "{1,2}", "{0,2}"};
    static const char *END[] = {"s", "q", "[a-z]", "\\w", "-", ""};
    return std::string(HEAD[U(0, 16)]) + ATOM[U(0, 11)] + VQ[U(0, 5)] +
           "(?:" + ATOM[U(0, 11)] + (U(0, 1) ? "{2}" : "") + ATOM[U(0, 11)] +
           ")" + GQ[U(0, 5)] + END[U(0, 5)];
  }
  case 1: {
    // A BOUNDED class that can consume CR and LF, in front of a literal:
    // on a CR-LF subject it runs on the collapsed byte programs, where the
    // pair is ONE element of the class — and the suffix scan's byte-walking
    // verifier has to be told, at every entry point (`[a-c][^q]{2}q` over
    // "a \r\nq": search() alone lost the match).
    static const char *LEAD[] = {"", "", "[a-c]", "e", "a", "[^q]"};
    static const char *NEG[] = {"[^q]", "[^.]", "[^z]", "[^e]"};
    static const char *BQ[] = {"{2}", "{1}", "{3}", "{1,2}", "{0,2}", "{2,3}"};
    static const char *LIT[] = {"q", "z", "\\.", "x", "e", "qz"};
    return std::string(LEAD[U(0, 5)]) + NEG[U(0, 3)] + BQ[U(0, 5)] +
           LIT[U(0, 5)];
  }
  case 2: {
    // Two unbounded class repeats that both consume CR and LF, side by
    // side, a group around one of them: a byte program can end the first on
    // the `\r` and begin the second on the `\n`, which no grapheme parse
    // does (`([^.]*)[^.]+,` over "Z\r\n," closed its group inside the pair).
    static const char *RUN[] = {"[^.]+", "[^q]*", "\\s+", "[^.]*", "\\s*", "[^q]+"};
    static const char *END[] = {",", "\\.", "q", "", "x?", "[qz]"};
    const bool first = U(0, 1);
    return std::string(HEAD[U(0, 16)]) +
           (first ? "(" : "") + RUN[U(0, 5)] + (first ? ")" : "") +
           (U(0, 3) ? "" : "x?") +
           (first ? "" : "(") + RUN[U(0, 5)] + (first ? "" : ")") +
           END[U(0, 5)];
  }
  default: break;
  }
  // Half of the patterns move to the assert tiers.
  auto decorate = [&](const std::string &pat) {
    switch (U(0, 11)) {
    case 0: return "\\b" + pat + "\\b";
    case 1: return pat + "\\b";
    case 2: return pat + "$";
    case 3: return "(?m)^" + pat;
    case 4: return "\\b" + pat;
    case 5: return "(?m)" + pat + "$";
    default: return pat;
    }
  };
  if (U(0, 9) == 0) {
    // A pre-part with gaps in its lengths directly in front of the literal a
    // scan would be driven from: the shape both the suffix scans and
    // ReverseInner must refuse (`(?:..)*q`, `(?:..)*=x*`), drawn bare so the
    // literal is next to it rather than three pieces away.
    static const char *GQ[] = {"*", "?", "+", "{0,3}", "*", "?"};
    static const char *LIT[] = {"q", "=", "ly", "z", "e", "-"};
    std::string pat = std::string(U(0, 2) ? "" : HEAD[U(0, 16)]) + "(?:" +
                      atom_q() + atom_q() + ")" + GQ[U(0, 5)] + LIT[U(0, 5)];
    if (U(0, 1)) pat += atom_q(); // ... which makes the literal interior
    return decorate(pat);
  }
  std::string pat = HEAD[U(0, 16)];
  int k = U(1, 3), cap = U(0, 5) == 0 ? U(0, k - 1) : -1;
  for (int i = 0; i < k; i++) {
    if (i && U(0, 2) == 0) pat += MID[U(0, 6)];
    std::string piece;
    switch (U(0, 9)) {
    case 0:
    case 1:
      // A repeat whose body is more than one code point: its lengths have
      // gaps, so a match that starts later can end earlier — the shape the
      // suffix scans' pre-part gate must refuse, literal prefix or not
      // (`e(?:..)*q` over "eeqq": the first `q` ends a match from the second
      // `e`, and the leftmost match is the one from the first). The same
      // piece, optional and behind a variable-width one, is the shape the
      // one-walk tables must refuse (`[a-z]{3,}(?:\\w{2}-)?s`), and in front
      // of an interior literal the one ReverseInner must
      // (`(?:..)*=x*`).
      piece = "(?:" + atom_q() + atom_q() + ")" + Q[U(0, 9)];
      break;
    case 2: piece = "(?:a|bc)"; break;
    default: piece = atom_q(); break;
    }
    pat += (i == cap) ? "(" + piece + ")" : piece;
  }
  pat += TAIL[U(0, 16)];
  return decorate(pat);
}

void invariant_fuzz_anchor_choice(int iters) {
  // The generator's own letters and punctuation, a few bystanders, and a
  // line break. [0, kPlain) is plain ASCII, one byte each; the three after it
  // are a CR-LF pair, a non-ASCII letter (the EGC byte path and its fused
  // tiers) and a letter with a combining mark (a cluster the fused tiers
  // must bail on).
  static const char *UNITS[] = {
      "e", "a", "t", "s",  "q",  "z", "!", "?", "x", "l", "y",  "i",
      "n", "g", "b", "c",  "h",  " ", " ", ".", ",", "@", "-",  "=",
      "Z", "1", "\"", "\n", "\r\n", "\xC3\xA9", "e\xCC\x81"};
  const int kPlain = 28;
  for (int it = 0; it < iters; it++) {
    const std::string pat = gen_anchor_choice();
    // Half of a subject is drawn from the bytes the pattern itself spells
    // (its head, its tail, what stands between), so the two ends crowd each
    // other: `e(?:..)*q` needs "eeqq" to tell a leftmost match from a
    // later-starting one that ends first, and uniform draws produce that
    // once in a hundred subjects.
    std::string hot;
    for (char ch : pat)
      for (int u = 0; u < kPlain; u++)
        if (UNITS[u][0] == ch) {
          hot += ch;
          break;
        }
    // `top` is the last unit index a subject may draw; one unit in `special`
    // comes from the specials up to it (0: none).
    auto gen = [&](int units, int top, int special) {
      std::string subj;
      for (int i = 0; i < units; i++) {
        if (special && U(0, special - 1) == 0)
          subj += UNITS[U(kPlain, top)];
        else if (!hot.empty() && U(0, 1))
          subj += hot[static_cast<size_t>(U(0, static_cast<int>(hot.size()) - 1))];
        else
          subj += UNITS[U(0, kPlain - 1)];
      }
      return subj;
    };
    std::vector<std::string> subjects;
    for (int s = 0; s < 10; s++)
      subjects.push_back(gen(U(0, 24), 0, 0)); // ASCII, `\n` lines
    // CR-LF and é, sparse and dense: a CR-LF pair has to land INSIDE a
    // match for the tiers that count it as one element to differ from the
    // ones that count two.
    for (int s = 0; s < 4; s++)
      subjects.push_back(gen(U(0, 30), kPlain + 1, s < 2 ? 6 : 3));
    // Past the failed-walk budgets (they are seeded from the subject length,
    // and a short subject hands the find back to the chain after a couple of
    // failed candidates): an ASCII one for the ASCII tiers and the word
    // scan, one with CR-LF and é for the byte tiers, and — one pattern in
    // eight — one holding a combining mark.
    subjects.push_back(gen(600, 0, 0));
    subjects.push_back(gen(600, kPlain + 1, 12));
    if (it % 8 == 0) subjects.push_back(gen(300, kPlain + 2, 30));
    stray_one(subjects);
    check_pattern(pat, subjects);

    // CodePoint: the same choice in front of a different ladder. Single-code-
    // point clusters and no `\r` (see check_us_vs_pike), so é is the one
    // special allowed.
    std::vector<std::string> us_subjects;
    for (int s = 0; s < 6; s++) {
      std::string subj = gen(U(0, 24), 0, 0);
      if (s >= 4) subj.insert(subj.size() / 2, UNITS[kPlain + 1]);
      us_subjects.push_back(std::move(subj));
    }
    {
      std::string subj = gen(300, 0, 0);
      us_subjects.push_back(subj + UNITS[kPlain + 1] + gen(300, 0, 0));
    }
    stray_one(us_subjects);
    check_us_vs_pike(pat, us_subjects);
  }
}

// --- One-walk drivers on the EGC byte tier. ---
//
// In Grapheme mode a subject that is not pure ASCII — or is, with CR-LF pairs
// in it — runs on the byte programs, and the one-walk drivers run there too:
// candidate + one walk per match, with the located-span chain serving the one
// find whose walk meets a byte the table has no transition for. What that
// rests on is specific to this tier, and none of it is what the CodePoint
// layer above exercises:
//
//  - The candidates. The grapheme program's first-byte set is ASCII-only and
//    would step over a match that STARTS on a non-ASCII byte; the byte
//    program's 256-wide set is the prune here. `[😀漢]+` over " 😀" has no
//    ASCII candidate at all.
//  - The CRLF collapse. A pattern whose classes count a CR-LF pair as one
//    element runs collapsed byte programs, which the code-point table does
//    not mirror — such a plan must stay off the walk (`[^c-za]a?` over
//    "c\r\n3" is [1,3) then [3,4)).
//  - The gate. The byte tier is admitted per subject; one combining mark
//    sends the same pattern to the Pike instead.
//
// Patterns: the CodePoint layer's one-walk shapes, classes that hold only
// non-ASCII members, and bounded classes that touch CR and LF (the collapse
// shapes). Subjects: single-code-point units with CR-LF pairs, at four
// non-ASCII densities, short and kilobytes long.
std::string gen_egc_onewalk() {
  switch (U(0, 5)) {
  case 0: {
    // Only non-ASCII members (or nearly): every match starts where the
    // ASCII first-byte set says nothing can.
    static const char *CLS[] = {"[\xC3\xA9\xE6\x97\xA5]", "[\xF0\x9F\x98\x80\xE6\xBC\xA2]",
                                ("[\xC3\xA9" "a]"), "\\p{L}", "[^ -~\\n\\r]"};
    static const char *Q[] = {"+", "{1,}", "{1,3}", ""};
    static const char *LEAD[] = {"", "", "a?", "(", " "};
    const char *lead = LEAD[U(0, 4)];
    std::string body = std::string(CLS[U(0, 4)]) + Q[U(0, 3)];
    if (lead[0] == '(') return "(" + body + ")";
    return std::string(lead) + body;
  }
  case 1: {
    // The collapse shapes: a bounded / single class matching both CR and LF.
    static const char *NEG[] = {"[^c-za]", "[^q]", "[^.]", "[^ab]"};
    static const char *BQ[] = {"", "{2}", "{1,2}", "{0,2}", "?"};
    static const char *TAIL[] = {"a?", "x", "", "\\d", "[a-c]+"};
    static const char *HEAD[] = {"", "", "a", "[a-c]"};
    return std::string(HEAD[U(0, 3)]) + NEG[U(0, 3)] + BQ[U(0, 4)] +
           TAIL[U(0, 4)];
  }
  default: return gen_us_onewalk();
  }
}

void invariant_fuzz_egc_onewalk(int iters) {
  // [0, 12) ASCII (one byte each, `\n` among them); then a CR-LF pair; then
  // the non-ASCII ones — é and 日 (word characters), ¡ (punctuation: a
  // non-ASCII byte that ENDS a word), 😀 and 漢 (the first class above); and
  // last a letter with a combining mark, which no byte tier may serve.
  static const char *UNITS[] = {
      "a", "b", "c", "1", "2", "_", " ", "=", ":", "-", "\n", "k",
      "\r\n",
      "\xC3\xA9", "\xE6\x97\xA5", "\xC2\xA1", "\xF0\x9F\x98\x80", "\xE6\xBC\xA2",
      "e\xCC\x81"};
  const int kAscii = 12, kCrlf = 12, kNa = 13, kNaEnd = 17, kMark = 18;
  for (int it = 0; it < iters; it++) {
    const std::string pat = gen_egc_onewalk();
    // `na` units in twenty are non-ASCII, `crlf` in twenty a CR-LF pair.
    auto gen = [&](int units, int na, int crlf) {
      std::string subj;
      for (int i = 0; i < units; i++) {
        int r = U(0, 19);
        subj += r < na          ? UNITS[U(kNa, kNaEnd)]
                : r < na + crlf ? UNITS[kCrlf]
                                : UNITS[U(0, kAscii - 1)];
      }
      return subj;
    };
    static const int NA_PER_20[] = {0, 1, 4, 10};
    std::vector<std::string> subjects;
    for (int s = 0; s < 8; s++)
      subjects.push_back(gen(U(0, 30), NA_PER_20[s % 4], s < 4 ? 0 : 3));
    // Long: ASCII with CR-LF line ends (the ASCII subject the byte tier
    // takes), one non-ASCII character in kilobytes of ASCII, and — one
    // pattern in four — a subject where most finds bail, so the
    // profitability rule gives the driver up partway.
    subjects.push_back(gen(1500, 0, 1));
    subjects.push_back(gen(600, 0, 0) + UNITS[U(kNa, kNaEnd)] +
                       gen(600, 0, 0));
    subjects.push_back(gen(1500, 1, 1));
    if (it % 4 == 0) subjects.push_back(gen(2000, 12, 1));
    // One combining mark: the same subject, off the byte tier.
    if (it % 8 == 0)
      subjects.push_back(gen(150, 2, 1) + UNITS[kMark] + gen(150, 2, 1));
    stray_one(subjects);
    check_pattern(pat, subjects);
  }
}

// --- The find ladder's rungs as only some callers take them. ---
//
// search, find_all, find_iter and test climb one ladder, so the layers above
// reach its rungs through whichever entry point they call. Four things are
// not everybody's, or rest on what those layers do not draw — one shape of
// case each (LadderCase::Shape):
//
//   - Anchor: the prefilter rungs asked by a BOOLEAN. test() takes the
//     suffix, the interior-literal, the (?i)-prefix and the fused scans as a
//     find does, but each stops at the first accepting state it reaches
//     instead of going on to the end a find reports (and the suffix scan
//     does not walk forward at all). That is a second way through each of
//     them, and it shows on the subjects a find and a boolean part ways on:
//     long, with the literal absent, or present once, or present in the
//     other case, or only at the very end. The long subjects above are drawn
//     from the pattern's own letters, which rarely lack anything.
//   - TextAnchored: Rung::TextAnchor, a text-anchored pattern's find from 0
//     (find_from0), for every caller, with groups or without: the walk from
//     0, then the families from 0 or the Pike. There a second step has to
//     find nothing, an empty match at 0 must not come back, and a byte the
//     walk has no transition for hands the find to the families (which then
//     must not have lost the groups of a pattern that has them).
//   - LookBack: the interior-literal rung's look-back as a boolean takes it:
//     32 bytes (limits::kBoolFloorBytes) and, with the part before the
//     literal still alive there, the scan instead. A pre-part that needs
//     about that many characters is the shape that sits on the line —
//     `[a-z]{35,}@x` has no start inside the look, and one before it — and
//     nothing above draws a counted repeat that long. The case carries what
//     its subjects are built from: the run's letter, the count, and the text
//     the literal and the rest match.
//   - PassedOver: the fused prefix scan's failed candidates. It verifies a
//     candidate with the byte DFA over bytes its eligibility scan has not
//     reached, so a verify that dies on a combining mark is no verdict: the
//     candidate may start a match the byte engine cannot see. The shape that
//     shows a candidate passed over is a literal prefix, a long branch that
//     runs into the mark and a short one that matches in front of it —
//     `q(?:a[a-z]+z|b)` over "qaqbcd́z" — and a subject short enough
//     for the failed-verify budget to run out. The case carries the subject
//     the pattern is built around.
//
// All of it goes through the Grapheme battery and the CodePoint differential;
// the latter checks test() against search() too.
struct LadderCase {
  enum Shape { Anchor, TextAnchored, LookBack, PassedOver } shape = Anchor;
  std::string pat;
  // LookBack: a run of `unit`, about `k` of them, then `text`.
  int k = 0;
  std::string unit, text;
  // PassedOver: the subject the pattern is built around.
  std::string core;
};

LadderCase gen_ladder() {
  LadderCase lc;
  if (U(0, 9) == 0) {
    lc.shape = LadderCase::PassedOver;
    static const char *LIT[] = {"q", "x", "Zq", "k"};
    static const char *LONG[] = {"a", "e", "", "n"};
    static const char *SHORT[] = {"b", "t", "c", "s"};
    static const char *CLS[] = {"[a-z]", "\\w", "[^ ]", "[a-y]"};
    static const char *REP[] = {"+", "*", "{2,}", "+"};
    static const char *TAIL[] = {"z", "\\.", "z", ","};
    static const char *TAILTEXT[] = {"z", ".", "z", ","};
    static const char *FILL = "aeinlgy";
    const std::string lit = LIT[U(0, 3)], lng = LONG[U(0, 3)],
                      sht = SHORT[U(0, 3)];
    int tl = U(0, 3);
    auto fill = [&](int len) {
      std::string f;
      for (int i = 0; i < len; i++) f += FILL[U(0, 6)];
      return f;
    };
    // prefix, long-branch head, [a second candidate with the short branch],
    // a letter with a combining mark, the tail.
    lc.core = lit + lng + fill(U(0, 3));
    for (int extra = U(0, 2); extra > 0; extra--)
      lc.core += lit + (U(0, 1) ? sht : "") + fill(U(0, 2));
    lc.core += fill(1) + "\xCC\x81" + fill(U(0, 3)) + TAILTEXT[tl];
    std::string longer =
        lng + CLS[U(0, 3)] + REP[U(0, 3)] + TAIL[tl];
    switch (U(0, 2)) {
    case 0: lc.pat = lit + "(?:" + longer + "|" + sht + ")"; break;
    case 1: lc.pat = lit + longer + "|" + lit + sht; break;
    default: lc.pat = lit + longer; break; // one branch: the budget's case
    }
    return lc;
  }
  if (U(0, 7) == 0) {
    lc.shape = LadderCase::LookBack;
    static const char *PRE[] = {"[a-z]", "\\w", "[^?]", "[a-y]", "."};
    static const char *UNIT[] = {"a", "b", "t", "e", "s"};
    static const char *LIT[] = {"@x", "=[a-z]", "\\?", "-[0-9]{2}", "#q"};
    static const char *TEXT[] = {"@x", "=c", "?", "-12", "#q"};
    int sh = U(0, 4);
    lc.k = U(26, 40);
    lc.unit = UNIT[sh];
    lc.text = TEXT[sh];
    std::string count = std::to_string(lc.k);
    switch (U(0, 2)) {
    case 0: count += ","; break;
    case 1: count += "," + std::to_string(lc.k + U(0, 6)); break;
    default: break; // exactly k
    }
    lc.pat = std::string(PRE[sh]) + "{" + count + "}" + LIT[sh];
    return lc;
  }
  if (U(0, 9) < 4) {
    lc.shape = LadderCase::TextAnchored;
    static const char *HEAD[] = {"^", "^", "\\A", "(?m)^", "^(?:", "\\A(?:"};
    static const char *TAIL[] = {"", "", "$", "\\z", "$", ""};
    int h = U(0, 5);
    std::string body;
    switch (U(0, 3)) {
    case 0: body = gen_onepass_repeat(); break; // brings its own `^` or `\b`
    case 1: body = "[a-c]*"; break;             // can match empty at 0
    default: body = gen_us_onewalk(); break;
    }
    lc.pat = HEAD[h] + body;
    if (h >= 4) lc.pat += ")";
    lc.pat += TAIL[U(0, 5)];
    return lc;
  }
  lc.pat = gen_anchor_choice();
  switch (U(0, 7)) {
  case 0:
  case 1: lc.pat = "(?i)" + lc.pat; break;
  case 2: {
    // A branch the literal is no part of.
    static const char *ALT[] = {"\\d\\d", "[A-Z]{2}", "#", "\\s\\s", "Qq"};
    lc.pat += std::string("|") + ALT[U(0, 4)];
    break;
  }
  default: break;
  }
  return lc;
}

void invariant_fuzz_ladder(int iters) {
  // Letters in both cases (the generators' own, and their other case), a
  // few digits and marks, a line break; then a CR-LF pair, a non-ASCII
  // letter and a letter with a combining mark.
  static const char *UNITS[] = {
      "e", "a", "t", "s", "q", "z", "x", "l", "y", "i", "n", "g", "b", "c",
      "k", "E", "A", "T", "S", "Q", "Z", "X", "L", "Y", "I", "N", "G", "B",
      "C", "K", "1", "2", "_", " ", " ", ".", ",", "@", "-", "=", ":", "!",
      "?", "#", "\n", "\r\n", "\xC3\xA9", "e\xCC\x81"};
  const int kPlain = 45, kCrlf = 45, kNa = 46, kMark = 47;
  for (int it = 0; it < iters; it++) {
    const LadderCase lc = gen_ladder();
    const std::string &pat = lc.pat;
    // `cold`: the plain units the pattern does not spell — so a subject
    // drawn from them lacks every literal of it, in the pattern's case.
    // The other case of its letters stays in, which is what makes a (?i)
    // pattern match there. `hot`: the ones it does spell.
    std::vector<int> cold, hot;
    for (int u = 0; u < kPlain; u++)
      (pat.find(UNITS[u]) == std::string::npos ? cold : hot).push_back(u);
    if (cold.empty()) cold.push_back(33);
    if (hot.empty()) hot.push_back(0);
    auto draw = [&](const std::vector<int> &from, int units, int special) {
      std::string subj;
      for (int i = 0; i < units; i++) {
        if (special && U(0, special - 1) == 0)
          subj += UNITS[U(kCrlf, kNa)];
        else
          subj += UNITS[from[static_cast<size_t>(
              U(0, static_cast<int>(from.size()) - 1))]];
      }
      return subj;
    };
    std::vector<std::string> subjects, us_subjects;
    if (lc.shape == LadderCase::TextAnchored) {
      // The match, if any, is at 0: short subjects that begin with the
      // pattern's letters, with others, with nothing; a non-ASCII letter or
      // a CR-LF pair a few units in (the walk bails there); and long ones,
      // for test().
      for (int s = 0; s < 6; s++) {
        std::string subj = draw(s % 2 ? hot : cold, U(0, 6), 0) +
                           draw(hot, U(0, 12), 0) + draw(cold, U(0, 6), 0);
        us_subjects.push_back(subj);
        subjects.push_back(std::move(subj));
      }
      for (int s = 0; s < 4; s++) {
        std::string head = draw(hot, U(0, 5), 0);
        subjects.push_back(head + UNITS[U(kCrlf, kMark)] + draw(hot, 8, 4));
        us_subjects.push_back(head + UNITS[kNa] + draw(hot, 8, 0));
      }
      subjects.push_back(draw(hot, 300, 0));
      subjects.push_back(draw(hot, 300, 20));
      us_subjects.push_back(draw(hot, 300, 0));
    } else {
      // Long ones. None of the pattern's letters; none but for one short
      // window of them; that window in the other case; the window at the
      // very end; the pattern's letters throughout; and the first two again
      // with CR-LF and é in them.
      auto flip = [](std::string w) {
        for (char &ch : w)
          ch = (ch >= 'a' && ch <= 'z')   ? static_cast<char>(ch - 32)
               : (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch + 32)
                                          : ch;
        return w;
      };
      const std::string window = draw(hot, U(2, 12), 0);
      subjects.push_back(draw(cold, 300, 0));
      subjects.push_back(draw(cold, 150, 0) + window + draw(cold, 150, 0));
      subjects.push_back(draw(cold, 150, 0) + flip(window) +
                         draw(cold, 150, 0));
      subjects.push_back(draw(cold, 290, 0) + window); // ... at the very end
      subjects.push_back(draw(hot, 300, 0));
      us_subjects = subjects;
      subjects.push_back(draw(cold, 300, 12));
      subjects.push_back(draw(cold, 150, 12) + window + draw(cold, 150, 12));
      // Every other pattern: a combining mark planted in a match. A short
      // subject of the pattern's letters is searched for one, and the mark
      // goes after one of its characters — its last one included. The bytes
      // of the match are then all there and the match is not (that
      // character is another cluster now), or is a shorter one; a fused
      // scan has to see that for a boolean too, and every other rung has to
      // leave the subject to the Pike. Alone in the subject, and once more
      // behind a non-ASCII letter (the fused scans need one to be taken).
      if (it % 2 == 0) {
        try {
          reg::Regex probe(pat);
          for (int tries = 0; tries < 8; tries++) {
            const std::string hay = draw(hot, U(3, 16), 0);
            auto m = probe.search(hay);
            if (!m.matched() || m.end() == m.begin()) continue;
            const size_t at = m.begin() + 1 +
                              static_cast<size_t>(U(
                                  0, static_cast<int>(m.end() - m.begin()) - 1));
            const std::string planted =
                hay.substr(0, at) + "\xCC\x81" + hay.substr(at);
            subjects.push_back(draw(cold, 150, 0) + planted +
                               draw(cold, 150, 0));
            subjects.push_back(std::string(UNITS[kNa]) + " " + planted);
            break;
          }
        } catch (...) {
          // a rejected pattern: check_pattern says so
        }
      }
      // CodePoint: é but no `\r` (see check_us_vs_pike).
      us_subjects.push_back(draw(cold, 150, 0) + UNITS[kNa] + window +
                            draw(cold, 150, 0));
      // The passed-over candidate: the subject the pattern was built
      // around, bare (the failed-verify budget of a ten-byte subject is a
      // few bytes), behind a non-ASCII letter, in the middle of a long
      // subject, and followed by a match the byte engine does see.
      // (Grapheme only: the mark is a code point of its own to CodePoint.)
      if (lc.shape == LadderCase::PassedOver) {
        subjects.push_back(lc.core);
        subjects.push_back(std::string(UNITS[kNa]) + " " + lc.core);
        subjects.push_back(draw(cold, 120, 0) + " " + lc.core + " " +
                           draw(cold, 60, 0));
        subjects.push_back(lc.core + " " + window + " " +
                           draw(hot, 12, 0));
        subjects.push_back(draw(hot, U(0, 6), 0) + lc.core);
      }
      // The look-back shape: a run of the pre-part's letter a few short of
      // the count, at it, a few past it and well past it, then the literal —
      // at the head of the subject, in the middle of one, and twice (a run
      // too short, then one long enough).
      if (lc.shape == LadderCase::LookBack) {
        auto run = [&](int len) {
          std::string r;
          for (int i = 0; i < len; i++) r += lc.unit;
          return r + lc.text;
        };
        for (int len : {lc.k - U(1, 5), lc.k, lc.k + U(1, 8),
                        lc.k + 60}) {
          for (const std::string &subj :
               {run(len), " " + run(len) + " ",
                draw(cold, 100, 0) + " " + run(len) + " " + draw(cold, 40, 0),
                " " + run(lc.k - 2) + " " + run(len) + " "}) {
            subjects.push_back(subj);
            us_subjects.push_back(subj);
          }
        }
      }
    }
    stray_one(subjects);
    stray_one(us_subjects);
    check_pattern(pat, subjects);
    check_us_vs_pike(pat, us_subjects);
  }
}

// --- Multi-literal alternation: Teddy, and the tier that is nothing else. ---
//
// An alternation of fixed strings is found by their leading bytes (Teddy's
// fingerprints), up to sixty-four of them dealt into eight buckets. Past
// eight they share, and a shared bucket lets through strings that mix its
// members' nibbles: every such candidate has to be turned down, by the scan
// (a caller that asks which fingerprint), by the literal comparison behind
// it, or by the DFA whose start state the scan skips for. gen_alt's
// alternations have two or three branches over three letters, so nothing
// they draw shares a bucket, runs to a second vector block or names a
// fingerprint two literals begin with.
//
// The literals here are drawn over bytes whose nibbles mix INTO EACH OTHER
// (low nibble 1 or 2 under high nibble 2, 3, 4, 6 or 7), so the mixtures a
// shared bucket lets through are strings the subjects are made of; and the
// subjects are the literals themselves — whole, cut short, with one byte
// swapped for another of the set — at every length from under the scan's
// walk threshold to several vector blocks, so a fingerprint straddles
// blocks, ends in the partial one, and starts within its own length of the
// end. Two to seventy literals: a bucket each, shared buckets, and past the
// sixty-four fingerprints a plan takes (a shorter fingerprint, or none).
// Bare (the literal-alternation tier), with a tail (the start skip of the
// DFA tiers and the Pike), under captures (the one-pass walk's candidates),
// and behind an optional head (fingerprints reached through two paths).
// And the shapes a walk can take from its first byte on, where its
// candidates are Teddy's: a literal behind a class of a few bytes (a choice
// of fixed bytes in a CodePoint plan's program, so fingerprints there) or
// behind optional bytes (fingerprints in both modes).
// The bytes: kMixBytes of them mix (low nibble 1 or 2 under high nibble 2,
// 3, 4, 6 or 7), then a few bystanders.
const char kMultiLitBytes[] = "!\"12ABabqrxz ";
const int kMixBytes = 10, kMultiLitByteCount = 13;
char multi_lit_byte(bool any) {
  return kMultiLitBytes[U(0, (any ? kMultiLitByteCount : kMixBytes) - 1)];
}

std::string gen_multi_literal(std::vector<std::string> &lits) {
  const int kind = U(0, 9);
  const int count = kind < 4 ? U(2, 8) : kind < 8 ? U(9, 24) : U(25, 70);
  lits.clear();
  for (int i = 0; i < count; i++) {
    // Mostly two to six bytes; a one-byte literal now and then, which leaves
    // the pattern without a fingerprint of any length.
    const int len = U(0, 39) == 0 ? 1 : U(0, 2) == 0 ? U(2, 3) : U(2, 6);
    std::string lit;
    for (int j = 0; j < len; j++)
      lit += multi_lit_byte(/*any=*/U(0, 3) == 0);
    // (A literal an earlier one is a prefix of can never match — which is
    // exactly what leftmost-first has to get right — so repeats and prefix
    // pairs stay in.)
    lits.push_back(lit);
  }
  std::string alt;
  for (const std::string &l : lits)
    alt += (alt.empty() ? "" : "|") + l;
  switch (U(0, 8)) {
  case 0:
  case 1:
  case 2: return alt;
  case 3: return "(?:" + alt + ")" +
                 std::string(U(0, 1) ? "x?" : U(0, 1) ? "[ab]*" : "(?:rq)?");
  case 4: return "(" + alt + ")";
  case 5: return "(" + alt + ")(a?)";
  case 6: return "(?:" + alt + ")?" + lits[static_cast<size_t>(U(0, count - 1))];
  case 7: {
    // `[ab]lit` or `a?b?lit`, and what they match among the subjects'
    // pieces.
    const std::string lit = lits[static_cast<size_t>(U(0, count - 1))];
    std::string heads;
    for (int i = U(2, 3); i > 0; i--) {
      const char b = multi_lit_byte(/*any=*/false);
      if (heads.find(b) != std::string::npos) continue;
      heads += b;
      lits.push_back(b + lit);
    }
    lits.push_back(heads + lit);
    std::string head = "[" + heads + "]";
    if (U(0, 1)) {
      head.clear();
      for (char b : heads)
        head += std::string(1, b) + "?";
    }
    static const char *kTail[] = {"", "x?", "(a?)", "([ab]*)z"};
    return head + lit + kTail[U(0, 3)];
  }
  default: return "(?:" + alt + ")(?: |$)";
  }
}

void invariant_fuzz_multi_literal(int iters) {
  for (int it = 0; it < iters; it++) {
    std::vector<std::string> lits;
    const std::string pat = gen_multi_literal(lits);
    // `units` pieces: a literal, a literal without its last byte, a literal
    // with one byte swapped, or a stray byte. One piece in `special` is
    // instead a cluster the grapheme tiers have to respect — a non-ASCII
    // letter, CR-LF, a combining mark (which fuses with a literal's last
    // byte: no match there) — up to index `top` of that list (`special` 0:
    // none).
    static const char *kSpecial[] = {"\xC3\xA9", "\r\n", "\xCC\x81"};
    auto gen = [&](int units, int top, int special) {
      std::string subj;
      for (int i = 0; i < units; i++) {
        if (special && U(0, special - 1) == 0) {
          subj += kSpecial[U(0, top)];
          continue;
        }
        std::string piece = lits[static_cast<size_t>(
            U(0, static_cast<int>(lits.size()) - 1))];
        switch (U(0, 5)) {
        case 0:
        case 1: break;
        case 2: piece.pop_back(); break;
        case 3:
          piece[static_cast<size_t>(U(0, static_cast<int>(piece.size()) - 1))] =
              multi_lit_byte(/*any=*/false);
          break;
        default: piece.assign(1, multi_lit_byte(/*any=*/true)); break;
        }
        subj += piece;
      }
      return subj;
    };
    std::vector<std::string> subjects;
    for (int s = 0; s < 6; s++)
      subjects.push_back(gen(U(0, 4), 0, 0)); // around the walk threshold
    for (int s = 0; s < 6; s++)
      subjects.push_back(gen(U(3, 14), 0, 0)); // a block or two
    for (int s = 0; s < 3; s++)
      subjects.push_back(gen(U(20, 120), 0, 0)); // several, and a tail
    for (int s = 0; s < 3; s++)
      subjects.push_back(gen(U(2, 40), 2, 5)); // with clusters
    stray_one(subjects);
    check_pattern(pat, subjects);

    // CodePoint: the same alternation, over the byte program's
    // fingerprints. Single-code-point clusters and no `\r` (see
    // check_us_vs_pike), so é is the one special allowed.
    std::vector<std::string> us_subjects;
    for (int s = 0; s < 3; s++)
      us_subjects.push_back(gen(U(0, 14), 0, 0));
    us_subjects.push_back(gen(U(20, 80), 0, 8));
    stray_one(us_subjects);
    check_us_vs_pike(pat, us_subjects);
    // ... and with the clusters, against the code-point Pike: a literal in
    // front of a combining mark is a match here, where Grapheme mode has
    // none.
    us_subjects.clear();
    for (int s = 0; s < 3; s++)
      us_subjects.push_back(gen(U(2, 40), 2, 5));
    stray_one(us_subjects);
    check_us_vs_pike(pat, us_subjects, reg::MatchUnit::CodePoint);
  }
}

// Pure printable-ASCII literal fast-path differential. The literal tier
// (literal_only_: memmem + O(1) grapheme-boundary check, no subject
// classification) must agree with the forced Pike on EVERY surface, especially
// on subjects that interleave grapheme-fusing code points around the literal —
// a Prepend just before a match (must reject) or an Extend/ZWJ/SpacingMark just
// after it (must reject). gen_subject() is ASCII-only, so the main
// invariant_fuzz never stresses these boundaries; this does. The same
// pattern in CodePoint mode is on the tier too, and takes every occurrence,
// fused or not: against the code-point Pike, over the same subjects.
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
    for (reg::MatchUnit unit :
         {reg::MatchUnit::Grapheme, reg::MatchUnit::CodePoint})
      if (!reg::detail::PlanProbe::literal_only(reg::Regex(pat, 0u, unit)))
        fail("literal: not on the literal tier", pat, "");
    std::vector<std::string> subjects;
    for (int s = 0; s < 6; s++) {
      int k = U(0, 14);
      std::string subj;
      for (int i = 0; i < k; i++) subj += UNITS[U(0, 11)];
      subjects.push_back(subj);
    }
    stray_one(subjects);
    check_pattern(pat, subjects);
    check_us_vs_pike(pat, subjects, reg::MatchUnit::CodePoint);
  }
}

// Non-ASCII assertion byte tier differential vs the forced Pike. Assert
// patterns
// (^ $ \b \B \w \d \s . [...]) on subjects mixing ASCII, CR-LF,
// single-code-point non-ASCII (é ñ α 日), and an occasional multi-code-point
// cluster (e+combining, which disqualifies the byte tier). On a non-ASCII
// subject the bare pattern runs the cached code-point-aware byte assert DFA;
// pike_reference() puts the same pattern on the Pike. They must agree on
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
    pike = pike_reference(pat, ml);
    if (!pike) {
      delete re;
      continue;
    }
    reg::Regex::FindCache cache;
    squeeze_dfa_cache(*re, pat, ml, &cache);
    for (int s = 0; s < 6; s++) {
      int k = U(0, 16);
      std::string subj;
      for (int i = 0; i < k; i++) subj += UNITS[U(0, 11)];
      if (U(0, 3) == 0) subj = with_strays(std::move(subj));
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

// test() on an assert pattern led by a literal, which skips to it
// (look_forward_skip). The skip is a prefilter, so it may change what the
// boolean costs and never what it answers: every subject's test() is
// checked against the same Regex's with the skip off, against search() and
// against the Pike, on bytes that are no UTF-8 too. Literals over a small
// alphabet, so that they occur, overlap and come close to occurring; a left
// context of every kind; tails that end a match at once, at the end of the
// line, never.
void invariant_fuzz_assert_prefix_bool(int iters) {
  static const char *LEAD[] = {"\\b", "\\B", "^", "", "\\b", ""};
  static const char *BODY[] = {"\\w*", "[a-z]*", ".*", ".?", "[^?]+\\?.*",
                               "\\w+", "",      "[a-y]{1,3}", "\\W"};
  static const char *TAIL[] = {"\\b", "$", "\\B", "", "\\b"};
  static const char *UNITS[] = {
      "q", "z", "x", "a", "e", " ", "?", "\n", "_",
      "\xC3\xA9" /*é*/, "\xE6\x97\xA5" /*日*/, "\xCC\x81" /*combining*/,
      // bytes that are no UTF-8: lone leads, a continuation, an invalid byte
      "\xE9", "\xC3", "\xF0", "\x80", "\xBF", "\xFF"};
  for (int it = 0; it < iters; it++) {
    std::string lit;
    for (int i = U(1, 3); i > 0; i--) lit += "qzx"[U(0, 2)];
    std::string pat = std::string(LEAD[U(0, 5)]) + lit + BODY[U(0, 8)] +
                      TAIL[U(0, 4)];
    const unsigned flags = U(0, 2) == 0 ? reg::Multiline : 0u;
    const reg::MatchUnit unit =
        U(0, 3) == 0 ? reg::MatchUnit::CodePoint : reg::MatchUnit::Grapheme;
    reg::Regex *re = nullptr;
    try {
      re = new reg::Regex(pat, flags, unit);
    } catch (...) { continue; }
    squeeze_dfa_cache(*re, pat, flags + (unit == reg::MatchUnit::CodePoint));
    reg::Regex *pike = pike_reference(pat, flags, unit);
    for (int s = 0; s < 8; s++) {
      std::string subj;
      for (int i = U(0, 40); i > 0; i--)
        subj += UNITS[U(0, 17)];
      if (U(0, 3) == 0) // past the boolean's short-subject limits
        subj = std::string(U(60, 200), ' ') + subj + std::string(U(0, 70), 'a');
      try {
        const bool t = re->test(subj);
        if (t != reg::detail::PlanProbe::test_unskipped(*re, subj))
          fail("assert-prefix: test() != test() without the skip", pat, subj);
        if (t != re->search(subj).matched())
          fail("assert-prefix: test() != search", pat, subj);
        if (pike && t != pike->search(subj).matched())
          fail("assert-prefix: test() != Pike", pat, subj);
      } catch (...) {
        fail("assert-prefix: threw", pat, subj);
      }
    }
    delete re;
    delete pike;
  }
}

// test() on the word scan's shapes, where the plan holds the start set
// sparse: the boolean takes the find (Plan::word_scan_sparse), and when the
// walk gives up — its budget spent on walks that run into one another, or a
// CR that a body reading `\s` meets (onepass_walk_bails_cr) — the boolean's
// own scan answers, stopping at the first accept. Bodies that cross a
// separator, so that a walk from one word runs over the next; subjects that
// repeat a token such a walk crosses and fails on, long enough to spend the
// budget, between random units that complete a match now and then. Every
// subject's test() against search() and the Pike.
void invariant_fuzz_word_bool(int iters) {
  static const char *HEAD[] = {"[0-9]", "[x-z]", "\\d", "[xz]", "k", "[0-9]+"};
  static const char *BODY[] = {"",
                               "[a-c]*",
                               "(?: [x-z0-9]+)*",
                               "(?:\\s[0-9]+)*",
                               "(?:\\.[0-9]{1,2})*",
                               "(?:-[a-c]+)*"};
  static const char *TAIL[] = {"\\b", " q\\b", "x\\b", "_", "\\.[0-9]\\b"};
  static const char *TOKENS[] = {"xy ", "1 ", "1.", "1.2.", "1\r", "1\n",
                                 "z-ab-", "7 a", "k1 ", "x\r\n"};
  static const char *UNITS[] = {"x", "z", "1", "7", "k", "a", "q", " ",
                                ".", "-", "_", "\r", "\n", "\r\n", "1.2 q"};
  for (int it = 0; it < iters; it++) {
    const std::string pat =
        std::string("\\b") + HEAD[U(0, 5)] + BODY[U(0, 5)] + TAIL[U(0, 4)];
    reg::Regex *re = nullptr;
    try {
      re = new reg::Regex(pat);
    } catch (...) { continue; }
    if (!reg::detail::PlanProbe::word_scan_sparse(*re)) {
      delete re;
      continue;
    }
    reg::Regex *pike = pike_reference(pat);
    for (int s = 0; s < 4; s++) {
      std::string subj;
      for (int i = U(0, 6); i > 0; i--)
        subj += UNITS[U(0, 14)];
      const char *tok = TOKENS[U(0, 9)];
      for (int i = U(0, 1) ? U(1, 8) : U(20, 400); i > 0; i--)
        subj += tok;
      for (int i = U(0, 12); i > 0; i--)
        subj += UNITS[U(0, 14)];
      if (U(0, 3) == 0) subj = with_strays(std::move(subj));
      try {
        const bool t = re->test(subj);
        if (t != re->search(subj).matched())
          fail("word-bool: test() != search", pat, subj);
        if (pike && t != pike->search(subj).matched())
          fail("word-bool: test() != Pike", pat, subj);
      } catch (...) {
        fail("word-bool: threw", pat, subj);
      }
    }
    delete re;
    delete pike;
  }
}

// --- Cut texts: subjects no family serves whole. ---
//
// A subject with a cluster the plan's family cannot read as the grapheme
// engine does scans as cut texts (Regex::Finder): the family over the
// subject cut at the next such cluster, its match standing if the step read
// nothing at or past the cut, and the Pike around them. gen_alt's patterns
// over gen_subject's pieces with one to three such clusters among them,
// anywhere — side by side, at the ends, by a match: an emoji with its
// selector or a skin tone, a flag, a ZWJ pair, an a, b or c with a mark (a
// base the patterns match), a Thai syllable, a CR-LF and a lone CR or LF
// (for a pattern that could split a pair, and for the CR-LF collapse);
// for one pattern in two, one subject behind or ahead of a kilobyte of
// newlines (a walk's budget, seeded with a short subject's length, hides
// what goes wrong; each newline is a cut for the CR-LF collapse; and the
// Pike reference, which some of gen_alt's patterns keep a thread alive
// across all of them in, at every match, costs a sixteenth of what it does
// over 4 KB). check_pattern compares them with the Pike; and a
// fresh scan placed at a match's end (find_at: Finder::place, which then
// has no segmentation to read the clusters behind it off) goes on as
// find_all does, for up to eight steps.
std::string gen_cut_subject() {
  static const char *const kCuts[] = {
      "\xE2\x9D\xA4\xEF\xB8\x8F",                      // a heart, selector
      "\xF0\x9F\x91\x8D\xF0\x9F\x8F\xBB",              // a skin tone
      "\xF0\x9F\x87\xAF\xF0\x9F\x87\xB5",              // a flag
      "\xF0\x9F\x91\xA8\xE2\x80\x8D\xF0\x9F\x91\xA9",  // a ZWJ pair
      "a\xCC\x81", "b\xCC\xA7", "c\xCC\x8C",           // bases and marks
      "\xE0\xB8\x81\xE0\xB9\x88",                      // Thai ko, mai ek
      "\r\n", "\r", "\n"};
  std::string s = gen_subject();
  for (int k = U(1, 3); k > 0; k--) {
    s.insert(static_cast<size_t>(U(0, static_cast<int>(s.size()))),
             kCuts[U(0, 10)]);
    if (U(0, 1)) s += gen_subject();
  }
  return s;
}

void check_find_at_on(const reg::Regex &re, const std::string &subj,
                      const std::vector<reg::MatchResult> &all,
                      const std::string &pat) {
  // (find_at starts at the end of one of them, drawn at random.)
  std::vector<size_t> nonempty; // indices of the non-empty matches
  for (size_t i = 0; i < all.size(); i++)
    if (all[i].end() > all[i].begin()) nonempty.push_back(i);
  if (nonempty.empty()) return;
  size_t i = nonempty[static_cast<size_t>(
      U(0, static_cast<int>(nonempty.size()) - 1))];
  size_t pos = all[i].end();
  try {
    for (int k = 0; k < 8; k++) {
      const reg::Regex::FindAt r = re.find_at(subj, pos);
      if (++i >= all.size()) {
        if (r.m.matched()) fail("find_at past the last match", pat, subj);
        return;
      }
      if (!r.m.matched()) {
        fail("find_at found none where find_all has one", pat, subj);
        return;
      }
      if (!compare_groups(r.m, all[i], "find_at vs find_all", pat, subj))
        return;
      pos = r.next_pos;
    }
  } catch (...) {
    fail("find_at threw", pat, subj);
  }
}

void invariant_fuzz_cut(int iters) {
  const std::string lines(1024, '\n');
  for (int it = 0; it < iters; it++) {
    const std::string pat = gen_alt(3);
    std::vector<std::string> subjects;
    for (int s = 0; s < 3; s++) {
      std::string subj = gen_cut_subject();
      if (s == 0 && U(0, 1)) subj = U(0, 1) ? lines + subj : subj + lines;
      subjects.push_back(std::move(subj));
    }
    check_pattern(pat, subjects);
    reg::Regex *re = nullptr;
    try {
      re = new reg::Regex(pat);
    } catch (...) {
      continue;
    }
    for (const std::string &subj : subjects) {
      try {
        check_find_at_on(*re, subj, find_all(*re, subj), pat);
      } catch (...) {
        fail("find_all threw", pat, subj);
      }
    }
    delete re;
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
    squeeze_dfa_cache(*re, pat,
                      flags + (unit == reg::MatchUnit::CodePoint ? 1 : 0));
    reg::Regex *pike = pike_reference(pat, flags, unit);
    for (int s = 0; s < 6; s++) {
      std::string subj = gen_au_subject();
      if (U(0, 3) == 0) subj = with_strays(std::move(subj));
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
    squeeze_dfa_cache(*us, pat, f + 1); // the oracle keeps the stock budget
    for (int s = 0; s < 6; s++) {
      std::string subj = gen_us_subject();
      if (U(0, 3) == 0) subj = with_strays(std::move(subj));
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

// Without `compare` (the default: see --std-diff, and the note at the top of
// the file) the searches are left out and everything else is kept — the
// patterns and subjects are still drawn, and both engines still compile each
// pattern, since which patterns std::regex rejects decides how many subjects
// are drawn. So the layers that run after this one draw exactly what they
// draw with the comparison on.
void differential_info(int iters, bool compare) {
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
      if (!compare) continue;
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
                int diff_it, bool std_diff) {
  rng.seed(base ^ static_cast<std::uint32_t>(t));
  auto share = [&](int total) {
    return total / jobs + (t < total % jobs ? 1 : 0);
  };
  invariant_fuzz(share(inv));
  // A fifth of the budget: its subjects are 4 KB, so an iteration costs about
  // what five of invariant_fuzz's do.
  invariant_fuzz_onepass_repeat(share(inv / 5));
  invariant_fuzz_literal(share(inv));
  invariant_fuzz_assert_suffix(share(inv));
  invariant_fuzz_assert_unicode(share(inv));
  invariant_fuzz_unicode(share(inv));
  invariant_fuzz_lookaround(share(inv));
  invariant_fuzz_us(share(inv));
  parser_fuzz(share(parser_it));
  differential_info(share(diff_it), std_diff);
  // Appended LAST so every layer above keeps the RNG stream — and so the
  // exact patterns and subjects — it had before this one existed. A fifth of
  // the budget: 2 KB padded subjects, and each pattern is checked twice (the
  // EGC battery plus the US differential).
  invariant_fuzz_whole_match_capture(share(inv / 5));
  // A tenth: one 3 KB subject per pattern (and a 4 KB one for every fourth)
  // through the Pike reference.
  invariant_fuzz_us_onewalk(share(inv / 10));
  // A quarter: some twenty subjects per pattern, two of them 600 units, and
  // each pattern checked twice (the EGC battery plus the US differential).
  invariant_fuzz_anchor_choice(share(inv / 4));
  // A tenth: three or four subjects of a kilobyte and more per pattern
  // through the Pike reference.
  invariant_fuzz_egc_onewalk(share(inv / 10));
  // A fifth: half a dozen 300-unit subjects per pattern, each pattern
  // checked twice (the EGC battery plus the US differential).
  invariant_fuzz_ladder(share(inv / 5));
  // A fifth: some twenty subjects per pattern, most of them short, each
  // pattern checked twice (the EGC battery plus the US differential).
  invariant_fuzz_multi_literal(share(inv / 5));
  // A tenth: four subjects of up to a few hundred bytes per pattern.
  invariant_fuzz_word_start(share(inv / 10));
  // A tenth: eight subjects of up to a few hundred bytes per pattern, each
  // asked four ways (with the skip, without it, search() and the Pike).
  invariant_fuzz_assert_prefix_bool(share(inv / 10));
  // A tenth: four subjects of up to a kilobyte or so per pattern, about a
  // third of the patterns kept.
  invariant_fuzz_word_bool(share(inv / 10));
  // A tenth: three short subjects with clusters no family serves per
  // pattern, for half of them one behind or ahead of a kilobyte, through
  // the Pike reference and find_at.
  invariant_fuzz_cut(share(inv / 10));
}

int main(int argc, char **argv) {
  std::uint32_t base = 0xC0FFEE; // base seed
  int jobs = 0;                  // 0 => auto-detect cores
  int inv = kDefaultIters;      // per invariant_* function; others scale to it
  bool std_diff = false;        // also compare against std::regex (INFO)

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
    else if (a == "--std-diff")
      std_diff = true;
    else if (a == "-h" || a == "--help") {
      std::printf("usage: regexlib_fuzz [--jobs N] [--seed S] [--iters N] "
                  "[--std-diff]\n"
                  "  --jobs      worker threads (default: detected cores)\n"
                  "  --seed      base RNG seed (default: 0xC0FFEE)\n"
                  "  --iters     per invariant_* function (default: %d%s)\n"
                  "  --std-diff  also count disagreements with std::regex "
                  "(informational;\n"
                  "              slow: std::regex backtracks)\n",
                  kDefaultIters, kAsan ? ", a fifth of the budget under ASan" : "");
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

  std::printf("regexlib_fuzz: jobs=%d seed=0x%X iters=%d%s\n", jobs, base, inv,
              kAsan && inv == kDefaultIters ? " (ASan default)" : "");

  std::vector<std::thread> pool;
  pool.reserve(jobs - 1);
  for (int t = 1; t < jobs; t++)
    pool.emplace_back(run_worker, base, jobs, t, inv, parser_it, diff_it,
                      std_diff);
  // Worker 0 on the main thread.
  run_worker(base, jobs, 0, inv, parser_it, diff_it, std_diff);
  for (auto &th : pool) th.join();

  if (std_diff)
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
