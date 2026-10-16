//
//  regexlib_test.cc
//
//  Self-contained test suite for include/regexlib.h. Depends only on the
//  single, dependency-free regexlib.h, so it travels with the header when it is
//  extracted to the standalone yhirose/cpp-regexlib repository.
//
//  Build (standalone):
//    c++ -std=c++17 -Iinclude \
//        test/regexlib_test.cc -o regexlib_test && ./regexlib_test
//  Or via CMake/ctest: `ctest -R regexlib_test`.
//

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "regexlib.h"

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool cond, const char *expr, int line) {
  if (cond) {
    g_pass++;
  } else {
    g_fail++;
    std::printf("  FAIL (line %d): %s\n", line, expr);
  }
}

#define CHECK(cond) check(static_cast<bool>(cond), #cond, __LINE__)

} // namespace

// The test suite's view into a Regex's plan (the header declares the peer and
// befriends it): which anchor the plan chose to drive the find from, and what
// it estimated each anchor to cost.
namespace reg {
namespace detail {
struct PlanProbe {
  using Choice = Regex::Plan::AnchorChoice;
  static const Choice &choice(const Regex &re) { return re.plan_->anchor_; }
  // 'P' prefix, 'S' suffix, 'I' interior literal, '-' none (the scan).
  static char anchor(const Regex &re) {
    switch (choice(re).kind) {
    case Choice::Kind::Prefix: return 'P';
    case Choice::Kind::Suffix: return 'S';
    case Choice::Kind::Inner: return 'I';
    default: return '-';
    }
  }
  // The lookaround programs the Pike's program runs (the code-point program
  // in CodePoint mode): one per lookaround of the pattern, however many
  // copies of it a counted repeat makes.
  static size_t look_programs(const Regex &re) {
    const auto &p = *re.plan_;
    return (p.us_ ? p.cp_prog_ : p.prog_).subs.size();
  }
  static bool word_scan_after_anchor(const Regex &re) {
    return re.plan_->wop_.ok && re.plan_->wop_after_anchor_;
  }
  // What the lazy DFA's start state skips with — the byte programs' DFAs
  // (`byte`), or the grapheme program's — and what prunes the positions of
  // the one-pass walk's scan. 'P' a literal prefix, 'T' Teddy, 'F' the
  // first-byte set, '-' nothing.
  static char skip_letter(Regex::Plan::StartSkip skip) {
    using Skip = Regex::Plan::StartSkip;
    switch (skip) {
    case Skip::Prefix: return 'P';
    case Skip::Teddy: return 'T';
    case Skip::FirstBytes: return 'F';
    case Skip::None: return '-';
    }
    return '!';
  }
  static char start_skip(const Regex &re, bool byte) {
    return skip_letter(byte ? re.plan_->byte_start_skip_
                            : re.plan_->start_skip_);
  }
  static char walk_skip(const Regex &re, bool byte) {
    return skip_letter(re.plan_->walk_skip(byte));
  }
  // The slots the one-pass table writes: the bits of every step's mask and
  // every accept's, or'd together (-1: the plan has no such table). Group
  // 0's two are the walk's own to write, so they are never among them.
  static int64_t onepass_slots(const Regex &re) {
    const auto &op = re.plan_->cp_onepass_;
    if (!op.ok) return -1;
    uint64_t slots = 0;
    for (const auto &st : op.states) {
      slots |= st.match_mask;
      for (uint64_t m : st.mask)
        slots |= m;
    }
    return static_cast<int64_t>(slots);
  }
  // WordOnePass: whether the plan has the table, and its candidate scan —
  // every candidate at or after `off`, a block at a time as the find takes
  // them, by the scan this build and CPU pick or (`walk`) a position at a
  // time. A set is the nibble table the scan reads.
  static bool word_onepass(const Regex &re) { return re.plan_->wop_.ok; }
  // How many states the walk table of the `^body` tier (or, `word`, of the
  // `\b body` one) has; 0 without the table.
  static size_t walk_states(const Regex &re, bool word) {
    const auto &a = word ? re.plan_->wop_ : re.plan_->aop_;
    return a.ok ? a.states() : 0;
  }
  static std::vector<size_t> word_starts(std::string_view s, size_t off,
                                         const NibbleSet &starts, bool walk) {
    const auto *p = reinterpret_cast<const unsigned char *>(s.data());
    std::vector<size_t> out;
    while (off < s.size()) { // as word_onepass_scan takes them
      Regex::WordStarts ws =
          walk ? Regex::word_start_walk(p, s.size(), off, starts.data())
               : Regex::word_start_block(p, s.size(), off, starts.data());
      off = ws.at + 16;
      for (; ws.mask; ws.pop())
        out.push_back(ws.first());
    }
    return out;
  }
  // Whether the literal prefix scans as a pair of bytes (false: for one
  // byte, or the plan has no prefix).
  static bool prefix_pair(const Regex &re) {
    const auto &pf = re.plan_->byte_prefix_.active() ? re.plan_->byte_prefix_
                                                     : re.plan_->prefix_;
    return pf.active() && pf.probe != pf.probe2;
  }
  // The Teddy searcher: the type (a test deals one straight from a list of
  // fingerprints), and the plan's (ok: the pattern has one).
  using Teddy = Regex::Teddy;
  static const Teddy &teddy(const Regex &re) { return re.plan_->teddy_; }
  // Served by the Pike VM and by nothing else — no literal, DFA or assert
  // tier planned, and none of the Pike rung's own accelerators either (the
  // start filters, the bounded backtracker): what a reference Regex has to
  // be.
  static bool pike_only(const Regex &re) {
    const auto &p = *re.plan_;
    return !p.literal_only_ && p.literal_alt_.empty() && !p.dfa_ok_ &&
           !p.dfa_assert_ok_ && !p.byte_path_ && !p.byte_assert_path_ &&
           !p.lf_prog_.ok() && !p.assert_.anchor_gatefree &&
           !p.aop_.ok && !p.wop_.ok && !p.prefix_.active() && !p.teddy_.ok &&
           !p.first_bytes_.ok && !p.cap_bitstate_;
  }
  // The rung a scan starts on, for a caller that wants matches (`test`
  // false) or only whether there is one. One letter per rung:
  //   L literal   A literal alternation   a assert-literal anchor
  //   ^ the walk from 0   ? the subject decides
  //   i (?i) prefix   S suffix   I interior literal   W the walk
  //   C the chain   c the assert chain   B the boolean scan   P the Pike
  //   F / f the fused prefix / suffix scans (never a start: the subject
  //   has to be looked at first)
  static char start(const Regex &re, bool test) {
    using R = Regex::Rung;
    switch (re.plan_->start_[test ? 1 : 0].rung) {
    case R::Literal: return 'L';
    case R::LiteralAlt: return 'A';
    case R::AssertAnchor: return 'a';
    case R::TextAnchor: return '^';
    case R::Classify: return '?';
    case R::FusedPrefix: return 'F';
    case R::FusedSuffix: return 'f';
    case R::IcasePrefix: return 'i';
    case R::Suffix: return 'S';
    case R::Inner: return 'I';
    case R::Walk: return 'W';
    case R::Chain: return 'C';
    case R::AssertChain: return 'c';
    case R::Bool: return 'B';
    case R::Pike: return 'P';
    }
    return '!';
  }
  // `f(dfa, reverse)` for each lazy DFA a cache has built.
  template <class F> static void each_lazy(const Regex::FindCache &c, F f) {
    const std::pair<const std::optional<Regex::LazyDfa> *, bool> all[] = {
        {&c.fu_, false},  {&c.rv_, true},    {&c.lfu_, false},
        {&c.lfa_, false}, {&c.bfu_, false},  {&c.brv_, true},
        {&c.blfu_, false}, {&c.blfa_, false}, {&c.inrev_, true}};
    for (const auto &[d, reverse] : all)
      if (*d) f(**d, reverse);
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
  // The widest row a lazy DFA of the plan's main programs has: the flags
  // and an entry per byte class.
  static unsigned widest_row(const Regex &re) {
    const auto &p = *re.plan_;
    unsigned w = 0;
    for (const reg::detail::Program *prog :
         {&p.prog_, &p.rev_prog_.prog, &p.lf_prog_.prog, &p.byte_prog_.prog})
      if (!prog->insts.empty())
        w = std::max(w, p.byte_classes(*prog, !p.dfa_ok_).n + 1);
    return w;
  }
  // What the lazy DFAs of a cache came to: how many were built, the refills
  // and give-ups among them, and the largest one's size.
  struct DfaStats {
    int built = 0;
    unsigned clears = 0; // summed
    bool quit = false;   // any
    size_t bytes = 0, states = 0;
    // The largest table, in entries: of the forward DFAs, and of the reverse.
    size_t fwd_entries = 0, rev_entries = 0;
  };
  static DfaStats dfa_stats(const Regex::FindCache &c) {
    DfaStats s;
    each_lazy(c, [&s](const Regex::LazyDfa &d, bool reverse) {
      s.built++;
      s.clears += d.clears;
      s.quit = s.quit || d.quit;
      s.bytes = std::max(s.bytes, d.bytes());
      s.states = std::max(s.states, d.states.size());
      size_t &entries = reverse ? s.rev_entries : s.fwd_entries;
      entries = std::max(entries, d.tr.size());
    });
    return s;
  }
  static DfaStats dfa_stats(const Regex &re) {
    return dfa_stats(re.thread_cache());
  }
};
} // namespace detail
} // namespace reg

namespace {

using reg::detail::PlanProbe;

// `pat` on the grapheme Pike, forced there by an always-true lookahead (the
// next cluster is anything, or the text ends): the same matches and groups,
// and a lookaround is a construct neither DFA family compiles. The
// wrap these tests used to use, `(?:PAT)(?:\b|\B)`, predates the assert
// tiers, which serve it — so it had come to compare a tier with itself. The
// plan is asked, so a reference cannot drift off the Pike unnoticed again.
// The same lookahead in front keeps the Pike rung's own accelerators off it
// (a literal prefix, Teddy or first-byte set to skip to): the twin is the
// VM started at every position, and shares nothing with what it checks.
inline reg::Regex pike_twin(const std::string &pat, unsigned flags = 0,
                            reg::MatchUnit unit = reg::MatchUnit::Grapheme) {
  reg::Regex re("(?=[\\s\\S]|$)(?:" + pat + ")(?=[\\s\\S]|$)", flags, unit);
  check(PlanProbe::pike_only(re), "pike_twin: reference is Pike-only",
        __LINE__);
  return re;
}
using reg::DotAll;
using reg::IgnoreCase;
using reg::Multiline;
using reg::Regex;
using reg::RegexError;

// Construct a Regex in CodePoint (UnicodeScalar) match-unit mode. The mode is a
// process-wide default (set_default_match_unit), frozen into the Regex at
// construction, so flip it, build, and restore Grapheme.
inline Regex make_unit(reg::MatchUnit u, const std::string &pat,
                       unsigned flags) {
  reg::MatchUnit prev = reg::default_match_unit();
  reg::set_default_match_unit(u);
  Regex r(pat, flags);
  reg::set_default_match_unit(prev);
  return r;
}
inline Regex make_us(const std::string &pat, unsigned flags = 0) {
  return make_unit(reg::MatchUnit::CodePoint, pat, flags);
}
// Build in Grapheme (EGC) mode regardless of the surrounding default — for EGC
// assertions interleaved inside the CodePoint-default test_unicode_scalar.
inline Regex make_egc(const std::string &pat, unsigned flags = 0) {
  return make_unit(reg::MatchUnit::Grapheme, pat, flags);
}

// The public bulk API is scan() (lazy) + matches() (eager view); the owning
// vector<MatchResult> collector lives here as a test convenience, built on the
// eager matches() so it stays an oracle independent of scan().
inline std::vector<reg::MatchResult> find_all(const Regex &re,
                                              std::string_view s) {
  std::vector<reg::MatchResult> v;
  for (auto m : re.find_all(s))
    v.push_back(m.to_owned());
  return v;
}

// Byte spans of every group of every match, flattened — from find_all, or
// (`lazy`) from find_iter. A group that did not participate reads as a pair
// of size_t(-1).
inline std::vector<size_t> flat_spans(const Regex &re, std::string_view subj,
                                      bool lazy) {
  std::vector<size_t> out;
  auto add = [&](const reg::Match &m) {
    for (size_t g = 0; g <= m.group_count(); g++) {
      out.push_back(m.group(g).matched() ? m.group(g).begin() : size_t(-1));
      out.push_back(m.group(g).matched() ? m.group(g).end() : size_t(-1));
    }
  };
  if (lazy)
    for (auto m : re.find_iter(subj))
      add(m);
  else
    for (auto m : re.find_all(subj))
      add(m);
  return out;
}

// find_at parity: step find_at from 0 by next_pos and compare the visited
// (begin, end) spans against find_iter over the same subject.
inline bool same_as_iter(const Regex &re, std::string_view s) {
  std::vector<std::pair<size_t, size_t>> want;
  for (auto m : re.find_iter(s)) want.emplace_back(m.begin(), m.end());
  std::vector<std::pair<size_t, size_t>> got;
  size_t pos = 0;
  while (pos <= s.size()) {
    auto r = re.find_at(s, pos);
    if (!r.m.matched()) {
      if (r.next_pos != s.size() + 1) return false; // done sentinel
      break;
    }
    got.emplace_back(r.m.begin(), r.m.end());
    if (r.next_pos <= pos) return false; // a step must always progress
    pos = r.next_pos;
  }
  return got == want;
}

// Whether every find surface of `re` — find_all, find_iter, search, test,
// find_at stepped from 0 — gives `want` on `subj`: the flat_spans of the
// reference.
inline bool finds_agree(const Regex &re, const std::vector<size_t> &want,
                        std::string_view subj) {
  if (flat_spans(re, subj, false) != want) return false;
  if (flat_spans(re, subj, true) != want) return false;
  auto m = re.search(subj);
  if (m.matched() != !want.empty()) return false;
  if (m.matched() && (m.begin() != want[0] || m.end() != want[1])) return false;
  if (re.test(subj) != !want.empty()) return false;
  // find_at stepped from 0: the scan find_iter just took.
  return same_as_iter(re, subj);
}

// Two alternations with more literals than Teddy has buckets.
const char *const kNames16 =
    "Sherlock|Holmes|Watson|Irene|Adler|John|Baker|Street|London|Moriarty|"
    "Lestrade|Hudson|Mycroft|Gregson|Hopkins|Stamford";
const char *const kKeywords16 =
    "return|while|for|if|else|switch|case|break|continue|struct|class|"
    "static|const|void|int|char";

// Returns true if constructing the pattern throws RegexError.
bool rejects(const std::string &pat) {
  try {
    Regex r(pat);
    (void)r;
  } catch (const RegexError &) { return true; }
  return false;
}

// Returns the RegexError message for an invalid pattern (empty if it compiled).
std::string error_of(const std::string &pat) {
  try {
    Regex r(pat);
    (void)r;
  } catch (const RegexError &e) { return e.what(); }
  return "";
}

// True if `haystack` contains `needle`.
bool has(const std::string &haystack, const std::string &needle) {
  return haystack.find(needle) != std::string::npos;
}

void test_literals_and_anchors() {
  CHECK(Regex("abc").test("xxabcxx"));
  CHECK(!Regex("abc").test("ab"));
  CHECK(Regex("^abc$").test("abc"));
  CHECK(!Regex("^abc$").test("abcd"));
  CHECK(!Regex("^abc$").test("zabc"));
  CHECK(Regex("").test(""));  // empty pattern matches empty
  CHECK(Regex("").test("x")); // and the empty prefix of anything
}

// Assert-capture tier (EGC default, ASCII subject): a `$`/`^`/`\b`-anchored
// pattern WITH capture groups is located by the assertion-aware DFA and its
// groups resolved by the assertion-aware bitstate — replacing the grapheme Pike
// VM. Exercises search / match / find_all / scan, which must all agree.
void test_assert_captures() {
  // file extension: `$`-anchored, leading literal, one capture
  {
    auto m = Regex(R"(\.([a-zA-Z0-9]+)$)").search("/var/www/html/index.html");
    CHECK(m.matched() && m.begin() == 19 && m.end() == 24);
    CHECK(m.group(1).str() == "html");
  }
  // trailing-anchored capture (the catastrophic Pike case pre-fix)
  CHECK(Regex(R"((\w+)$)").search("foo bar baz").group(1).str() == "baz");
  // leading-anchored capture
  CHECK(Regex(R"(^(\w+))").search("hello world").group(1).str() == "hello");
  // \b-bounded capture with a trailing literal
  {
    auto m = Regex(R"(\b(\w+)tion\b)").search("the function here");
    CHECK(m.matched() && m.group(1).str() == "func");
  }
  // two groups, fully anchored, leftmost-first
  {
    auto m = Regex(R"(^(\d{3})-(\d{4})$)").search("555-1234");
    CHECK(m.matched() && m.group(1).str() == "555" &&
          m.group(2).str() == "1234");
  }
  CHECK(!Regex(R"(^(\d{3})-(\d{4})$)").search("x555-1234").matched());
  // anchored match() resolves captures
  {
    auto m = Regex(R"((\w+)@(\w+)$)").match("user@host");
    CHECK(m.matched() && m.group(1).str() == "user" &&
          m.group(2).str() == "host");
  }
  // find_all over an assert-capture pattern yields every group set
  {
    auto all = find_all(Regex(R"((\w+)\.)"), "a.b.c.");
    CHECK(all.size() == 3 && all[0].group(1).str() == "a" &&
          all[2].group(1).str() == "c");
  }
  // multiline `$` with a capture, find_all per line
  {
    auto all = find_all(Regex(R"((\w+)$)", reg::Multiline), "foo\nbar\nbaz");
    CHECK(all.size() == 3 && all[0].group(1).str() == "foo" &&
          all[1].group(1).str() == "bar" && all[2].group(1).str() == "baz");
  }
  // lazy scan (find_iter) must agree with eager find_all on groups
  {
    Regex re(R"(\b(\w+)ng\b)");
    std::string subj = "running jumping sleeping";
    auto eager = find_all(re, subj);
    std::vector<std::string> lazy;
    for (auto m : re.find_iter(subj)) lazy.push_back(std::string(m.group(1).str()));
    CHECK(eager.size() == lazy.size() && lazy.size() == 3);
    for (size_t i = 0; i < lazy.size(); i++)
      CHECK(eager[i].group(1).str() == lazy[i]);
  }
}

// Leading-literal prefilter for the assert tier: a `$`/`^`/`\b`-anchored
// pattern whose first consuming atom is a fixed ASCII literal is located by
// memmem of that literal + an anchored assert verify, instead of scanning every
// position. Covers capture-free and capture forms, and the leftmost-first
// obligation (memmem order == start order; the rest is unconstrained).
void test_assert_prefix_prefilter() {
  // capture-free leading literal + trailing `$`
  {
    auto m = Regex(R"(\.[a-zA-Z0-9]+$)").search("/var/www/html/index.html");
    CHECK(m.matched() && m.begin() == 19 && m.end() == 24);
  }
  // leftmost-first across multiple prefix occurrences: only the last `.` run
  // reaches `$`, but an interior `.` occurrence must be rejected, not matched
  CHECK(Regex(R"(\.([a-z]+)$)").search("x.a.b.c").group(1).str() == "c");
  // a `.` whose following text fails `$` is skipped to the next occurrence
  CHECK(Regex(R"(\.([a-z]+)$)").search("a.tmp.bak").group(1).str() == "bak");
  // leading `^` then a fixed literal prefix
  CHECK(Regex(R"(^foo(\w+))").search("foobar baz").group(1).str() == "bar");
  // `\b` + literal prefix: the "ID" in "xID9" has no preceding word boundary
  // ('x' is a word char), so the prefilter must reject that occurrence and find
  // the next one after the space — exercising the anchored `\b` verify.
  CHECK(Regex(R"(\bID([0-9]+))").search("xID9 ID42").group(1).str() == "42");
  // interior-literal-anchored capture (`=` is the first consuming atom)
  {
    auto all = find_all(Regex(R"(=([0-9]+)\b)"), "a=1; b=22; c=333;");
    CHECK(all.size() == 3 && all[0].group(1).str() == "1" &&
          all[2].group(1).str() == "333");
  }
  // no prefix occurrence -> no match
  CHECK(!Regex(R"(\.[a-z]+$)").search("/no/extension/here").matched());
  // find_iter (lazy) agrees with find_all on a prefix-prefiltered pattern
  {
    Regex re(R"(@(\w+)$)");
    std::string subj = "a@x\nb@y\nc@z"; // multiline off: only the last line ends
    auto m = re.search(subj);
    CHECK(m.matched() && m.group(1).str() == "z");
  }
}

// US (CodePoint) mode reuses the SAME byte assert tier as EGC's non-ASCII path
// (the unification): `^ $ \b`-anchored patterns — capture or not — run on the
// code-point-aware byte assert DFA instead of the code-point Pike, on ASCII and
// non-ASCII subjects alike, with the leading-literal prefilter. Results must
// match EGC.
void test_assert_us_unified() {
  // ASCII subjects: same answers as the EGC assert tier
  CHECK(make_us(R"(\.([a-zA-Z0-9]+)$)")
            .search("/var/www/html/index.html")
            .group(1)
            .str() == "html");
  CHECK(make_us(R"((\w+)$)").search("foo bar baz").group(1).str() == "baz");
  CHECK(make_us(R"(^(\w+))").search("hello world").group(1).str() == "hello");
  CHECK(make_us(R"(\b(\w+)tion\b)").search("the function here").group(1).str() ==
        "func");
  CHECK(make_us(R"(\.[a-z]+$)").search("a.txt").matched()); // capture-free
  CHECK(!make_us(R"(\.[a-z]+$)").search("/no/extension/here").matched());
  // anchored match()
  {
    auto m = make_us(R"((\d{3})-(\d{4})$)").match("555-1234");
    CHECK(m.matched() && m.group(1).str() == "555" && m.group(2).str() == "1234");
  }
  // NON-ASCII subject in US mode: the byte assert DFA decodes per code point —
  // this is the path EGC could not take for US before the unification.
  CHECK(make_us(R"(\.([a-zé]+)$)").search("x.café").group(1).str() == "café");
  CHECK(make_us(R"(\bné(\w+))").search("un nédx ici").group(1).str() == "dx");
  CHECK(make_us(R"((\w+)$)").search("café au lait").group(1).str() == "lait");
  // find_all US assert-capture (columnar capture rows)
  {
    auto all = find_all(make_us(R"((\w+)\.)"), "a.bb.ccc.");
    CHECK(all.size() == 3 && all[0].group(1).str() == "a" &&
          all[2].group(1).str() == "ccc");
  }
  // multiline `$` with a capture, per line, in US mode
  {
    auto all = find_all(make_us(R"((\w+)$)", reg::Multiline), "foo\nbar\nbaz");
    CHECK(all.size() == 3 && all[0].group(1).str() == "foo" &&
          all[2].group(1).str() == "baz");
  }
  // US and EGC agree on a non-ASCII assert-capture result
  CHECK(make_us(R"(\.([\w]+)$)").search("dir.naïve").group(1).str() ==
        make_egc(R"(\.([\w]+)$)").search("dir.naïve").group(1).str());

  // Multiline anchors and CR-LF, where the two units part by definition: to
  // the grapheme engine the pair is one cluster and one line break, with no
  // position inside it; in CodePoint mode it is two characters, and the
  // position between them ends one (empty) line and starts the next. The byte
  // assert tier serves both units and kept the grapheme rule for both, so
  // CodePoint `(?m)$` over "a\r\nb" skipped offset 2 — on the released
  // engine, and unseen: the `(?:\b|\B)` reference ran the same tier. The
  // spans are asserted outright, and against a lookahead-forced Pike.
  {
    using V = std::vector<std::pair<size_t, size_t>>;
    auto spans = [](const Regex &re, const std::string &subj) {
      V v;
      for (auto &m : find_all(re, subj)) v.emplace_back(m.begin(), m.end());
      return v;
    };
    auto iter_spans = [](const Regex &re, const std::string &subj) {
      V v;
      for (auto m : re.find_iter(subj)) v.emplace_back(m.begin(), m.end());
      return v;
    };
    const std::string e = "\xc3\xa9";
    struct { const char *pat; std::string subj; V us, egc; } cases[] = {
        {"$", "a\r\nb", {{1, 1}, {2, 2}, {4, 4}}, {{1, 1}, {4, 4}}},
        {"^", "a\r\nb", {{0, 0}, {2, 2}, {3, 3}}, {{0, 0}, {3, 3}}},
        {"$", e + "a\r\nb", {{3, 3}, {4, 4}, {6, 6}}, {{3, 3}, {6, 6}}},
        {"^", e + "a\r\nb", {{0, 0}, {4, 4}, {5, 5}}, {{0, 0}, {5, 5}}},
        {"^\\w?", "\r\nb1", {{0, 0}, {1, 1}, {2, 3}}, {{0, 0}, {2, 3}}},
        {"\\w*$", "ab\r\n", {{0, 2}, {2, 2}, {3, 3}, {4, 4}},
         {{0, 2}, {2, 2}, {4, 4}}},
        // A lone CR and a lone LF are line breaks in both units.
        {"^", "a\rb\nc", {{0, 0}, {2, 2}, {4, 4}}, {{0, 0}, {2, 2}, {4, 4}}},
        {"$", "a\rb\nc", {{1, 1}, {3, 3}, {5, 5}}, {{1, 1}, {3, 3}, {5, 5}}},
    };
    const std::string la = ")(?=[\\s\\S]|$)";
    for (auto &c : cases) {
      Regex us = make_us(c.pat, reg::Multiline);
      Regex egc = make_egc(c.pat, reg::Multiline);
      CHECK(spans(us, c.subj) == c.us);
      CHECK(iter_spans(us, c.subj) == c.us);
      CHECK(spans(egc, c.subj) == c.egc);
      CHECK(iter_spans(egc, c.subj) == c.egc);
      CHECK(spans(make_us("(?:" + std::string(c.pat) + la, reg::Multiline),
                  c.subj) == c.us);
      CHECK(spans(make_egc("(?:" + std::string(c.pat) + la, reg::Multiline),
                  c.subj) == c.egc);
      CHECK(us.test(c.subj) == !c.us.empty());
      CHECK(us.search(c.subj).begin() == c.us[0].first);
    }
  }

  // One-pass capture resolution over a boundary-assert-stripped program: a
  // leading/trailing anchor is zero-width on the located span, so `\.([a-z]+)$`
  // / `^(\w+)` / `(\d{3})$` resolve groups in one forward pass. The captures
  // must match the backtracker exactly; an INTERIOR anchor must NOT be stripped.
  CHECK(make_us(R"(^(\d{3})-(\d{4})$)").search("abc 555-1234 xyz").matched() ==
        false); // not anchored at 0 in this subject -> whole subject fails
  {
    auto m = make_us(R"(^(\d{3})-(\d{4})$)").search("555-1234");
    CHECK(m.group(1).str() == "555" && m.group(2).str() == "1234");
  }
  // interior `\b` between two captures: stripping leading/trailing only, the
  // interior assert keeps the program off the one-pass (backtracker resolves).
  CHECK(make_us(R"((\w+) (\w+)$)").search("alpha beta").group(2).str() ==
        "beta");
  // a `^…$` capture run, find_all per line, one-pass per match
  {
    auto all = find_all(make_us(R"(^(\w)(\w+)$)", reg::Multiline), "ab\ncde");
    CHECK(all.size() == 2 && all[0].group(2).str() == "b" &&
          all[1].group(1).str() == "c" && all[1].group(2).str() == "de");
  }
}

// Construction overloads: bitmask flags, an explicit per-Regex match_unit pin
// (thread-safe, independent of the global default), and both together. The
// MatchUnit overload is selected by type, so it never needs a flags placeholder.
void test_options() {
  using reg::MatchUnit;
  // make the global default EGC, then prove a pinned-US Regex ignores it
  reg::set_default_match_unit(MatchUnit::Grapheme);
  {
    // no unit argument -> follows the global default (EGC here)
    reg::Regex egc(R"(\.([\w]+)$)");
    CHECK(egc.search("dir.café").group(1).str() == "café"); // EGC \w over é
    // unit pinned to CodePoint -> US regardless of the EGC global
    reg::Regex us(R"(\.([a-zA-Z0-9]+)$)", MatchUnit::CodePoint);
    CHECK(us.search("/p/index.html").group(1).str() == "html");
    // a pinned-US Regex and a global-default(EGC) Regex coexist, each frozen
    reg::Regex def(R"(\.([a-zA-Z0-9]+)$)");
    CHECK(us.search("/x.txt").matched() && def.search("/x.txt").matched());
  }
  // the bitmask flags
  CHECK(reg::Regex("café", reg::IgnoreCase).search("CAFÉ").matched());
  {
    auto ml = find_all(reg::Regex("^(\\w+)", reg::Multiline), "foo\nbar");
    CHECK(ml.size() == 2 && ml[0].group(1).str() == "foo" &&
          ml[1].group(1).str() == "bar");
  }
  CHECK(reg::Regex("a.b", reg::DotAll).test("a\nb")); // `.` spans a newline
  CHECK(!reg::Regex("a.b").test("a\nb"));
  // flags + an explicit unit pin together (the third overload)
  CHECK(reg::Regex("café", reg::IgnoreCase, MatchUnit::CodePoint)
            .search("CAFÉ")
            .matched());
  // an explicit pin beats the global even when the global is later changed
  {
    reg::set_default_match_unit(MatchUnit::CodePoint);
    reg::Regex pinned_egc(R"(.)", MatchUnit::Grapheme);
    reg::set_default_match_unit(MatchUnit::Grapheme);
    // pinned EGC matches the whole e+combining cluster, US would match one CP
    std::string ecombining = "e\xCC\x81";
    CHECK(pinned_egc.search(ecombining).str() == ecombining);
  }
  reg::set_default_match_unit(MatchUnit::Grapheme); // restore default
}

void test_any_and_classes() {
  CHECK(Regex("a.c").test("axc"));
  CHECK(!Regex("a.c").test("a\nc")); // . excludes newline
  CHECK(Regex("[a-z]+").test("hello"));
  CHECK(!Regex("^[a-z]+$").test("Hello"));
  CHECK(Regex("[^0-9]+").test("abc"));
  CHECK(Regex("[A-Za-z_][A-Za-z0-9_]*").search("_id42").str() == "_id42");
  CHECK(Regex("[-a-z]").test("-"));  // leading '-' is literal
  CHECK(Regex("[a\\]b]").test("]")); // escaped ']' in class
  CHECK(Regex("\\d+").search("year 2026").str() == "2026");
  CHECK(Regex("\\w+").search("snake_case99").str() == "snake_case99");
  CHECK(Regex("a\\sb").test("a b"));
  CHECK(Regex("\\D+").search("abc123").str() == "abc");
  CHECK(Regex("\\S+").search("  hi  ").str() == "hi");
}

void test_posix_classes() {
  CHECK(Regex("[[:alpha:]]+").search("abcDEF").str() == "abcDEF");
  CHECK(Regex("[[:digit:]]+").search("x123y").str() == "123");
  CHECK(Regex("[[:alnum:]]+").search("a1b2!").str() == "a1b2");
  CHECK(Regex("[[:upper:]]+").search("abCD").str() == "CD");
  CHECK(Regex("[[:lower:]]+").search("ABcd").str() == "cd");
  CHECK(Regex("[[:space:]]+").search("a \t b").str() == " \t ");
  CHECK(Regex("[[:xdigit:]]+").search("zz1aF9zz").str() == "1aF9");
  CHECK(Regex("[[:punct:]]+").search("a,.;b").str() == ",.;");
  CHECK(Regex("[[:blank:]]+").search("a \tb").str() == " \t");
  CHECK(Regex("[[:graph:]]+").search(" a!b ").str() == "a!b");
  // combined with ranges / other members, and outer negation
  CHECK(Regex("[A-Z[:digit:]]+").search("aB7C!").str() == "B7C");
  CHECK(Regex("[[:digit:]x]+").search("12x3y").str() == "12x3");
  CHECK(Regex("[^[:digit:]]+").search("12abc9").str() == "abc");
  // alpha/digit are Unicode-aware (matches an accented letter under code
  // points)
  CHECK(make_us("[[:alpha:]]+").search("caf\xC3\xA9!").str() ==
        "caf\xC3\xA9");
  // an unknown [:name:] is not a POSIX class: '[' stays a literal member, so
  // the bracket is the set {'[',':' ,'z'} and needs a trailing ']'
  // (back-compat).
  CHECK(Regex("[[:zzz:]]").search("z]").str() == "z]");
  CHECK(!Regex("[[:zzz:]]").test(":"));
  // inner negation [:^name:] of a known class throws (not silently literal)
  CHECK(rejects("[[:^digit:]]"));
  // but an unknown [:^name:] stays a harmless literal set (back-compat, no
  // throw): the bracket is {'[',':' ,'^','z'} and still needs a trailing ']'.
  CHECK(!rejects("[[:^zz:]]"));
  CHECK(Regex("[[:^zz:]]").search("^]").str() == "^]");
}

void test_quantifiers() {
  CHECK(Regex("ab*c").test("ac"));
  CHECK(Regex("ab*c").test("abbbbc"));
  CHECK(Regex("ab+c").test("abc"));
  CHECK(!Regex("ab+c").test("ac"));
  CHECK(Regex("ab?c").test("ac"));
  CHECK(Regex("ab?c").test("abc"));
  CHECK(Regex("^a{2,3}$").test("aa"));
  CHECK(Regex("^a{2,3}$").test("aaa"));
  CHECK(!Regex("^a{2,3}$").test("a"));
  CHECK(!Regex("^a{2,3}$").test("aaaa"));
  CHECK(Regex("^a{2}$").test("aa"));
  CHECK(Regex("^a{2,}$").test("aaaaa"));
  CHECK(Regex("a{0}b").test("b")); // zero repetitions
  // greedy vs lazy
  CHECK(Regex("a.*b").search("a_b_b").str() == "a_b_b");
  CHECK(Regex("a.*?b").search("a_b_b").str() == "a_b");
  CHECK(Regex("<.+?>").search("<a><b>").str() == "<a>");
  // a literal '{' that is not a valid counted quantifier
  CHECK(Regex("a{b").test("a{b"));
}

void test_alternation_and_groups() {
  CHECK(Regex("cat|dog|bird").test("I have a dog"));
  CHECK(!Regex("cat|dog").test("fish"));
  CHECK(Regex("(ab)+").search("ababab").str() == "ababab");
  CHECK(Regex("(?:ab)+c").test("ababc")); // non-capturing
  auto m = Regex("(\\d{4})-(\\d{2})-(\\d{2})").search("date: 2026-05-29!");
  CHECK(m);
  CHECK(m.str() == "2026-05-29");
  CHECK(m.group(1).str() == "2026");
  CHECK(m.group(2).str() == "05");
  CHECK(m.group(3).str() == "29");
  CHECK(m.group(4).matched() == false); // no such group
  // unmatched optional group
  auto m2 = Regex("(a)(b)?").search("a");
  CHECK(m2 && m2.group(1).str() == "a" && !m2.group(2).matched());
}

// A disjoint literal alternation (no branch a prefix of another) is
// longest-safe and takes the DFA find path; prefix-related branches stay on the
// Pike VM. Both must report the same Perl leftmost-first span. These pin that
// the DFA path never changes the match length.
void test_literal_alternation() {
  // Disjoint literals -> DFA path. Leftmost-first == only branch that matches.
  CHECK(Regex("fox|dog|cat").search("the dog ran").str() == "dog");
  CHECK(Regex("(?:fox|dog|cat)").search("cataclysm").str() == "cat");
  CHECK(Regex("a|bc|def").search("zzdefzz").str() == "def");
  CHECK(find_all(Regex("(?:fox|dog|cat)"), "fox dog cat fox").size() == 4);
  // Prefix relations -> Pike path; Perl picks the first branch, not the
  // longest.
  CHECK(Regex("foo|foobar").search("foobar").str() == "foo");
  CHECK(Regex("a|ab").search("ab").str() == "a");
  CHECK(Regex("cat|cats").search("cats").str() == "cat");
  CHECK(Regex("foobar|foo").search("foobar").str() == "foobar"); // longest first
  // Case-insensitive: disjoint still safe; a fold-prefix must stay Pike.
  CHECK(Regex("Fox|DOG", IgnoreCase).search("a dog here").str() == "dog");
  CHECK(Regex("(?i:Cat|cats)").search("CATS").str() == "CAT");

  // Pure-literal-alternation fast path (Teddy + ordered memcmp, no DFA): it must
  // equal the grapheme Pike oracle across find_all / find_iter / search, on
  // ASCII and on subjects with a combining mark (Extend), a Prepend, and CRLF —
  // a literal must not match across a grapheme boundary.
  auto egc_ok = [](const std::string &subj, const std::string &pat) {
    Regex bare(pat), pike = pike_twin(pat);
    auto a = find_all(bare, subj), b = find_all(pike, subj);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end()) return false;
    std::vector<std::pair<size_t, size_t>> it;
    for (auto m : bare.find_iter(subj)) it.emplace_back(m.begin(), m.end());
    if (it.size() != a.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (it[i].first != a[i].begin() || it[i].second != a[i].end()) return false;
    auto sr = bare.search(subj);
    return sr.matched() == !a.empty() &&
           (a.empty() || (sr.begin() == a[0].begin() && sr.end() == a[0].end()));
  };
  const std::string nm = "Sherlock|Holmes|Watson|Irene|Adler|John|Baker";
  CHECK(egc_ok("Watson met Holmes and John near Baker St.", nm));
  CHECK(egc_ok("Holmes\xcc\x81 not a match (combining on s)", nm)); // Extend after
  CHECK(egc_ok("\xd8\x80Holmes prepend before", nm));               // Prepend before
  CHECK(egc_ok("Holmes\r\nWatson\r\nJohn", nm));                    // CRLF between
  CHECK(egc_ok("\xc3\xa9 Holmes \xc3\xa9 Watson", nm));             // non-ASCII gaps
  CHECK(egc_ok("HolmesWatsonJohn no spaces", nm));
  // Ordered alternation with prefix relations on the fast path.
  CHECK(egc_ok("the cats sat", "cat|cats")); // -> "cat"
  CHECK(egc_ok("abcabcd", "ab|abc|abcd"));   // leftmost-first "ab" each
}

// The Teddy SIMD prefilter scans for the leading bytes of a literal-alternation
// 16 positions at a time, then the engine confirms from each candidate. It must
// agree with the scalar engine on every alignment: across the 16-byte SIMD
// boundary and the scalar tail, on near-miss false positives the engine has to
// reject, and on fingerprints shorter than the full literal.
void test_teddy_prefilter() {
  // Fingerprint length picks up to 4 leading bytes; "frobnicate" exceeds it, so
  // a "frob..." near-miss must NOT be reported as a match.
  Regex r("(?:xyzzy|plugh|frobnicate)");
  CHECK(!r.test(std::string(1000, '.') + "frobxxxx" + std::string(1000, '.')));
  CHECK(r.test(std::string(1000, '.') + "frobnicate"));
  CHECK(find_all(r, "plugh xyzzy frobnicate plugh").size() == 4);

  // The candidate may land anywhere relative to the SIMD stride: pad with a
  // varying prefix length so a match starts at every byte offset mod 16.
  Regex alt("(?:fox|dog|cat)");
  for (int pad = 0; pad < 40; pad++) {
    std::string s(pad, '.');
    s += "dog";
    CHECK(alt.search(s).begin() == static_cast<size_t>(pad));
    CHECK(find_all(alt, s).size() == 1);
  }

  // Dense matches (every candidate is a real match) and back-to-back hits.
  CHECK(find_all(alt, "foxdogcatfoxdogcat").size() == 6);
  // Short subjects exercise the scalar fallback (below the 16-byte SIMD floor).
  CHECK(find_all(alt, "a dog").size() == 1);
  CHECK(!alt.test("dg ct fx"));
  CHECK(alt.test("cat"));

  // Alternation reachable through an optional prefix: a match can also begin
  // with the trailing literal, so all three leading triples must be candidates.
  Regex opt("(?:fox|dog)?bar");
  CHECK(find_all(opt, "foxbar dogbar bar").size() == 3);
  CHECK(opt.search("zzbar").str() == "bar");
  CHECK(!opt.test("foxbaz"));

  // More literals than buckets: fingerprints share them, and a string that
  // mixes the bytes of two that do is a candidate the scan has to turn
  // down. As the tier itself, as a DFA's start skip (the optional tail), and
  // under a capture; at every offset of a 32-byte block and into the
  // partial block that ends the subject; against the Pike.
  for (const std::string set : {kNames16, kKeywords16}) {
    for (const std::string &pat :
         {set, "(?:" + set + ")s?", "(" + set + ")( ?)"}) {
      const Regex re(pat), pike = pike_twin(pat);
      CHECK(PlanProbe::teddy(re).ok && PlanProbe::teddy(re).shared);
      for (const char *body :
           {"Hudson", "Stamford and Gregson", "Johg Ireg Greh Holmds Wadson",
            "Holmex Watsoz Londom", "void", "if int", "ig vo sn ct ea wr",
            "structs", "structz whilf", "Holmes\xcc\x81",
            "caf\xc3\xa9 for Mycroft\r\nelse",
            // Back to back on the byte tiers: the scan resumes exactly where
            // the next literal begins.
            "\xc3\xa9 HudsonGregsonMycroftStamford ifintvoidcharcase and "
            "then some more, to the end of the line\r\n"}) {
        for (size_t pad = 0; pad < 70; pad += (pad < 36 ? 1 : 7)) {
          const std::string s = std::string(pad, '.') + body + ". ";
          CHECK(finds_agree(re, flat_spans(pike, s, /*lazy=*/false), s));
        }
      }
    }
  }
  // The alternation's order decides between literals that begin alike,
  // whichever bucket each fell into.
  {
    const std::string pat = "ab|abc|abcd|bc|bcd|cd|cde|abd|abe|acd|ace|bce|bd";
    const Regex re(pat), pike = pike_twin(pat);
    CHECK(PlanProbe::teddy(re).ok && PlanProbe::start(re, false) == 'A');
    for (const char *s : {"abcd", "abcde", "xbcdex", "acdabe", "bdcdeabd",
                          "aabbccddee", "abdabeacdacebcebd"})
      CHECK(finds_agree(re, flat_spans(pike, s, false), s));
    // A one-byte literal leaves the alternation without a fingerprint.
    CHECK(!PlanProbe::teddy(Regex(pat + "|b")).ok);
  }
}

// Teddy's scans, each on its own, against a search that knows nothing of
// buckets (every fingerprint compared at every position): the walk, and
// every vector scan this build has. From every start offset of subjects of
// every length up to three 32-byte blocks — so the first block, the carry
// from one block into the next and the partial last block are met at every
// alignment, by a fingerprint that starts in one and ends in the other — and
// over sets from three fingerprints (a bucket each) to sixty-four (eight to
// a bucket, which let through the mixtures the subjects are full of).
void test_teddy_scans() {
  using Teddy = PlanProbe::Teddy;
  // Bytes whose nibbles mix into one another: low nibble 1 or 2 under high
  // nibble 3, 4, 6 or 7. Two fingerprints over them that share a bucket let
  // through other strings over them.
  const std::string mix = "12ABabqr";
  uint32_t seed = 0x2545F491u;
  auto rnd = [&](size_t bound) {
    seed = seed * 1664525u + 1013904223u;
    return static_cast<size_t>(seed >> 8) % bound;
  };
  auto word = [&](size_t len) {
    std::string w;
    for (size_t i = 0; i < len; i++)
      w += mix[rnd(mix.size())];
    return w;
  };
  auto mixed = [&](size_t count, size_t len) {
    std::vector<std::string> prints;
    while (prints.size() < count) {
      std::string w = word(len);
      if (std::find(prints.begin(), prints.end(), w) == prints.end())
        prints.push_back(w);
    }
    return prints;
  };
  struct Set {
    std::vector<std::string> prints;
    int shared, loose; // whether some bucket has to be (-1: the dealing's
                       // to decide)
  };
  const std::vector<Set> sets = {
      // Up to eight: a bucket each — also for two that could share one and
      // let nothing else through, as they would among more than eight.
      {{"fox", "dog", "cat"}, 0, 0},
      {{"<<", "<=", ">>", ">=", "=="}, 0, 0},
      {{"Sher", "Holm", "Wats", "Iren", "Adle", "John", "Bake"}, 0, 0},
      // Nine that differ in one nibble of one byte: whichever of them share
      // a bucket, it lets nothing else through.
      {{"xa", "xb", "xc", "xd", "xe", "xf", "xg", "xh", "xi"}, 1, 0},
      // Nine that differ in both bytes: any two that share let their
      // mixtures through.
      {{"aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "ii"}, 1, 1},
      {{"re", "wh", "fo", "if", "el", "sw", "ca", "br", "co", "st", "cl",
        "vo", "in", "ch"},
       1, -1},
      {{"Sher", "Holm", "Wats", "Iren", "Adle", "John", "Bake", "Stre",
        "Lond", "Mori", "Lest", "Huds", "Mycr", "Greg", "Hopk", "Stam"},
       1, -1},
      {mixed(12, 2), 1, -1},
      {mixed(20, 3), 1, -1},
      {mixed(40, 4), 1, -1},
      {mixed(64, 4), 1, -1},
      // A NUL in a fingerprint: the zero padding of a partial block must
      // not read as one.
      {{std::string("a\0q", 3), std::string("qr\0", 3), std::string(3, '\0')},
       0, 0},
  };
  for (const Set &set : sets) {
    const size_t n = set.prints[0].size();
    std::vector<Teddy::Print> fps;
    for (const std::string &f : set.prints) {
      fps.emplace_back();
      std::copy(f.begin(), f.end(), fps.back().begin());
    }
    Teddy t;
    t.build(fps, static_cast<int>(n));
    CHECK(t.ok && t.count() == set.prints.size());
    CHECK((t.loose & ~t.shared) == 0);
    CHECK(set.shared < 0 || (t.shared != 0) == (set.shared != 0));
    CHECK(set.loose < 0 || (t.loose != 0) == (set.loose != 0));
    for (int round = 0; round < 60; round++) {
      // The fingerprints themselves, whole and cut short, between runs of
      // the mixing bytes.
      std::string s;
      const size_t want_len = rnd(100);
      while (s.size() < want_len) {
        const size_t k = rnd(8);
        const std::string &f = set.prints[rnd(set.prints.size())];
        if (k < 3)
          s += f;
        else if (k == 3)
          s += f.substr(0, n - 1);
        else
          s += word(1 + rnd(3));
      }
      const auto *p = reinterpret_cast<const unsigned char *>(s.data());
      // The fingerprint that id names is what stands at pos.
      auto names = [&](const Teddy::Hit &h) {
        return h.id < t.count() &&
               std::memcmp(&t.key[h.id], p + h.pos, n) == 0;
      };
      for (size_t from = 0; from <= s.size(); from++) {
        size_t want = from;
        auto here = [&](const std::string &f) {
          return s.compare(want, n, f) == 0;
        };
        while (want + n <= s.size() &&
               std::none_of(set.prints.begin(), set.prints.end(), here))
          want++;
        if (want + n > s.size()) want = s.size();
        for (Teddy::Scan scan :
             {Teddy::Scan::Walk, Teddy::Scan::Vec16, Teddy::Scan::Vec32}) {
          if (!Teddy::has(scan)) continue;
          const auto which = t.find_with(scan, p, s.size(), from, t.shared);
          CHECK(which.pos == want && (want == s.size() || names(which)));
          CHECK(t.find_with(scan, p, s.size(), from, t.loose).pos == want);
        }
        const auto which = t.find_print(p, s.size(), from);
        CHECK(which.pos == want && (want == s.size() || names(which)));
        CHECK(t.find(p, s.size(), from) == want);
      }
    }
  }
  // What a plan takes for a pattern: the longest fingerprint its shortest
  // literal allows, and no more than sixty-four of them.
  auto alternation = [](const std::vector<std::string> &lits) {
    std::string pat;
    for (const std::string &l : lits)
      pat += (pat.empty() ? "" : "|") + l;
    return pat;
  };
  struct Taken {
    std::string pat;
    int n;
    unsigned count;
  };
  for (const Taken &want : std::vector<Taken>{
           {"fox|dog|cat", 3, 3},
           {"Sherlock|Holmes|Watson|Irene|Adler|John|Baker", 4, 7},
           {kNames16, 4, 16},
           {kKeywords16, 2, 14},
           {"<<=|>>=|->|==|!=|<=|>=|&&|\\|\\|", 2, 9},
           {alternation(mixed(64, 4)), 4, 64}}) {
    const auto &t = PlanProbe::teddy(Regex(want.pat));
    CHECK(t.ok && t.n == want.n && t.count() == want.count);
  }
  {
    const auto &t = PlanProbe::teddy(Regex(alternation(mixed(65, 4))));
    CHECK(!t.ok || t.n < 4);
  }
}

// WordOnePass's candidate scan against its definition — a byte of the start
// set after a byte that is not a word byte, or a non-ASCII byte — from every
// start offset of subjects of every length up to five blocks, so the first
// block, the lane carried from one block into the next and the partial last
// block are met at every alignment; the vector scan and the walk alike. Then
// the find that rides on it, against the Pike.
void test_word_start_scan() {
  using reg::detail::nibble_set_has;
  using Set = reg::detail::NibbleSet;
  const Set &word_set = reg::detail::kAsciiWordNibbles;
  for (int b = 0; b < 256; b++)
    CHECK(nibble_set_has(word_set.data(), static_cast<unsigned char>(b)) ==
          (b < 128 && reg::detail::is_word_cp(static_cast<char32_t>(b))));
  auto set_of = [](const std::string &members) {
    Set t{};
    for (unsigned char c : members)
      reg::detail::nibble_set_add(t, c);
    return t;
  };
  const Set sets[] = {set_of("0123456789"), set_of("x"), set_of("aZ_9"),
                      word_set};
  uint32_t seed = 0x9E3779B9u;
  auto rnd = [&](size_t bound) {
    seed = seed * 1664525u + 1013904223u;
    return static_cast<size_t>(seed >> 8) % bound;
  };
  // Word bytes in and out of the sets, bytes that are neither — among them
  // the one either side of each range of word bytes (`/`, `:`, `@`, `[`,
  // `` ` ``, `{`) — and now and then a non-ASCII one.
  const std::string word = "ax09Z_", other = " .-\n@[`{/:";
  for (int round = 0; round < 300; round++) {
    std::string s;
    const size_t len = static_cast<size_t>(round) % 82, words = 1 + rnd(8);
    while (s.size() < len) {
      const size_t k = rnd(40);
      s += k == 0   ? '\xC3'
           : k == 1 ? '\x80'
           : k <= 1 + 4 * words ? word[rnd(word.size())]
                                : other[rnd(other.size())];
    }
    bool ok = true;
    for (const Set &set : sets) {
      for (size_t off = 0; off <= s.size(); off++) {
        std::vector<size_t> want;
        for (size_t i = off; i < s.size(); i++) {
          const auto c = static_cast<unsigned char>(s[i]);
          const bool edge =
              i == 0 || !reg::detail::ascii_word_byte(
                            static_cast<unsigned char>(s[i - 1]));
          if (c >= 0x80 || (edge && nibble_set_has(set.data(), c)))
            want.push_back(i);
        }
        for (bool walk : {false, true})
          ok = ok && PlanProbe::word_starts(s, off, set, walk) == want;
      }
    }
    CHECK(ok);
  }

  // The find: a candidate at every offset of a block and into the partial
  // one, behind candidates that fail (a digit run that is not an address, a
  // capital with no lowercase after it), back to back with the match before
  // — the entry ramp's — and far from it.
  for (const char *pat :
       {R"(\b[0-9]+\b)", R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)",
        R"(\b[A-Z][a-z]+\b)", R"(\b[xy][0-9]+\b)", R"(\b[a-c]\w+\b)",
        R"(\b[0-9]{2}x?)"}) {
    const Regex re(pat), pike = pike_twin(pat);
    CHECK(PlanProbe::word_onepass(re) &&
          !PlanProbe::word_scan_after_anchor(re));
    for (const char *body :
         {"42", "10.0.0.1", "Holmes", "x7", "abc", "1.2.3.4.5 6.7.8 9.9.9.9x",
          "10/Oct/2026:13:55:36 +0000 10.20.30.40", "a1 b2 c3 x1 x22 X3 x_4",
          "Ab CD Ef g Hi9 Jk_ Lm", "12 34,56;78\r\n90", "_12 1_2 12_ 99"}) {
      for (size_t pad = 0; pad < 70; pad += (pad < 36 ? 1 : 7)) {
        for (const char *fill : {".", "a", " 7 "}) {
          std::string s;
          while (s.size() < pad)
            s += fill;
          s.resize(pad);
          s += std::string(" ") + body + " " + body + "," + body + "  ..  " +
               body;
          CHECK(finds_agree(re, flat_spans(pike, s, /*lazy=*/false), s));
        }
      }
    }
  }
}

// Columnar matches() container: range-for/operator[], captures/named/unmatched
// groups, the three ownership overloads, and agreement with find_all.
void test_matches() {
  // capture-free, range-for + operator[]
  Regex re(R"(\w+)");
  auto ms = re.find_all("foo bar baz");
  CHECK(ms.size() == 3 && !ms.empty());
  CHECK(ms[0].str() == "foo" && ms[1].str() == "bar" && ms[2].str() == "baz");
  CHECK(ms[1].begin() == 4 && ms[1].end() == 7);
  size_t cnt = 0;
  for (auto m : ms)
    cnt += m.str().size();
  CHECK(cnt == 9);

  // captures + named + unmatched group; group() returns a string_view
  Regex re2(R"((\d+)-(?<w>[a-z]+)|(X))");
  auto ms2 = re2.find_all("12-ab and X here");
  CHECK(ms2.size() == 2 && ms2.group_count() == 3);
  CHECK(ms2[0].str() == "12-ab");
  CHECK(ms2[0].group(1).str() == "12" && ms2[0].group("w").str() == "ab");
  CHECK(ms2[0].group(1).matched() && !ms2[0].group(3).matched());
  CHECK(ms2[1].str() == "X" && ms2[1].group(3).matched() && !ms2[1].group(1).matched());
  CHECK(ms2[1].group(3).str() == "X" && ms2[1].group(1).str().empty());

  // ownership: borrow (lvalue) / move-own (rvalue) / copy. str() must be valid.
  std::string s = "alpha beta";
  CHECK(re.find_all(s)[0].str() == "alpha");                          // borrow
  CHECK(re.find_all(std::string("gamma delta"))[1].str() == "delta"); // move-own
  CHECK(re.find_all_copy("kappa")[0].str() == "kappa");               // copy-own
  // a moved-in temporary's views stay valid after the call
  auto owned = re.find_all(std::string("one two three"));
  CHECK(owned.size() == 3 && owned[2].str() == "three");

  // empty input / no match
  CHECK(re.find_all("").empty() && re.find_all("   ").empty());

  // agreement with find_all (captures, optional group)
  Regex re3(R"((\w)(\w)?)");
  auto fa = find_all(re3, "ab c");
  auto m3 = re3.find_all("ab c");
  CHECK(fa.size() == m3.size());
  for (size_t i = 0; i < fa.size(); i++) {
    CHECK(fa[i].begin() == m3[i].begin() && fa[i].end() == m3[i].end());
    CHECK(fa[i].str() == m3[i].str());
    for (size_t g = 0; g <= re3.group_count(); g++) {
      CHECK(fa[i].group(g).matched() == m3[i].group(g).matched());
      if (fa[i].group(g).matched()) CHECK(fa[i].group(g).str() == m3[i].group(g).str());
    }
  }
}

// The rows a find_all returns and the one a find_iter yields (SpanRows), and
// the walk's part in them: group 0 is the walk's own to write, every other
// group the table's.
void test_match_rows() {
  // A result that outgrows its rows many times over: 20,000 matches, each
  // where the text was built to have it.
  std::string text;
  std::vector<size_t> want; // as flat_spans lays them out
  for (int i = 0; i < 20000; i++) {
    const std::string w(static_cast<size_t>(1 + i % 7),
                        static_cast<char>('a' + i % 26));
    want.insert(want.end(), {text.size(), text.size() + w.size()});
    text += w;
    text += i % 5 ? " " : ", ";
  }
  // (The walk serves both: a CodePoint plan starts on it, a Grapheme one
  // once it has seen that the subject is ASCII.)
  Regex words(R"(\w+)"), words_us = make_us(R"(\w+)");
  CHECK(PlanProbe::start(words_us, false) == 'W');
  for (const Regex *re : {&words, &words_us})
    CHECK(flat_spans(*re, text, false) == want &&
          flat_spans(*re, text, true) == want);

  // A MatchList is a value: a copy has rows of its own, a move takes them,
  // and an assignment replaces what was there.
  {
    auto same_spans = [&](const Regex::MatchList &ms) {
      if (2 * ms.size() != want.size()) return false;
      for (size_t i = 0; i < ms.size(); i++)
        if (ms[i].begin() != want[2 * i] || ms[i].end() != want[2 * i + 1])
          return false;
      return true;
    };
    auto ms = words.find_all(text);
    Regex::MatchList copy = ms;
    ms = words.find_all("x yz");
    CHECK(ms.size() == 2 && ms[1].str() == "yz");
    CHECK(same_spans(copy));
    Regex::MatchList moved = std::move(copy);
    CHECK(same_spans(moved));
    copy = moved;
    CHECK(same_spans(copy) && same_spans(moved));
    ms = std::move(moved);
    CHECK(same_spans(ms));
    Regex::MatchList none, none2 = none;
    CHECK(none2.empty() && none2.size() == 0);
    ms = none;
    CHECK(ms.empty());
  }

  // Groups, one of them unset in some rows and one empty in others, over
  // many rows: `key`, digits or nothing, `=`, a value or nothing.
  {
    std::string kv;
    std::vector<size_t> rows;
    for (int i = 0; i < 3000; i++) {
      const size_t b = kv.size(), none = size_t(-1);
      kv += std::string(static_cast<size_t>(1 + i % 3), 'k');
      const size_t k = kv.size();
      if (i % 3) kv += std::to_string(i);
      const size_t d = kv.size();
      kv += '=';
      const size_t e = kv.size();
      kv += std::string(static_cast<size_t>(i % 4), 'v');
      const size_t v = kv.size();
      kv += i % 2 ? "; " : "\n";
      rows.insert(rows.end(), {b, v, b, k, d > k ? k : none, d > k ? d : none,
                               e, v});
    }
    for (const char *pat :
         {R"(([a-z]+)(\d+)?=([a-z]*))", R"((?:([a-z]+)(\d+)?=([a-z]*)))"}) {
      Regex re(pat);
      CHECK(PlanProbe::onepass_slots(re) == 0b11111100);
      CHECK(finds_agree(re, rows, kv));
      // ... and the single result with its groups (finds_agree reads its
      // span only).
      auto one = re.search(std::string_view(kv).substr(rows[7 * 8]));
      CHECK(one.matched() && one.begin() == 0 && one.group(1).str() == "kk" &&
            one.group(2).str() == "7" && one.group(3).str() == "vvv");
    }
  }

  // The table leaves group 0 to the walk: a capture-free one writes no slot
  // at all, and one with groups writes theirs and no other. (-1 would be a
  // plan with no table.)
  CHECK(PlanProbe::onepass_slots(words) == 0);
  CHECK(PlanProbe::onepass_slots(words_us) == 0);
  CHECK(PlanProbe::onepass_slots(Regex(R"((\w+))")) == 0); // (its twin)
  CHECK(PlanProbe::onepass_slots(Regex(R"((\w+)=(\d+))")) == 0b111100);

  // More groups than the 16 slots the walk clears in one go: the ones a
  // match leaves unset read unset, whatever the match before it set.
  {
    std::string pat;
    for (int g = 0; g < 10; g++)
      pat += std::string("(?:(") + static_cast<char>('a' + g) + ")|(" +
             static_cast<char>('A' + g) + "))";
    Regex re(pat);
    CHECK(PlanProbe::onepass_slots(re) > 0);
    const std::string t = "ABCDEFGHIJ abcdefghij AbCdEfGhIj";
    std::vector<size_t> spans;
    for (size_t at : {size_t(0), size_t(11), size_t(22)}) {
      spans.insert(spans.end(), {at, at + 10});
      for (size_t k = 0; k < 10; k++) {
        const bool upper = t[at + k] < 'a';
        const size_t none = size_t(-1);
        spans.insert(spans.end(), {upper ? none : at + k,
                                   upper ? none : at + k + 1,
                                   upper ? at + k : none,
                                   upper ? at + k + 1 : none});
      }
    }
    CHECK(finds_agree(re, spans, t));
  }
}

// Whole-match captures: every group wraps the entire pattern, so each group's
// span is the match span. Such a pattern is planned and run as its
// capture-free twin (the root groups are peeled off the AST) and the groups
// are written back where a result is handed out — a different place for
// search()/match(), for find_all's rows and for find_iter's row. So: every
// entry point, both units, and bodies that land on different tiers (the
// one-walk driver, the chain, the literal and suffix prefilters, the assert
// tier, the Pike).
void test_whole_match_capture() {
  struct Row {
    size_t b, e;
  };
  auto rows = [](const Regex &re, std::string_view subj,
                 std::initializer_list<Row> want) {
    // find_all, find_iter and search must each give `want`, with every group
    // equal to the whole match.
    auto all = re.find_all(subj);
    bool ok = all.size() == want.size();
    size_t i = 0;
    for (const Row &w : want) {
      if (!ok) break;
      ok = all[i].begin() == w.b && all[i].end() == w.e;
      for (size_t g = 1; ok && g <= re.group_count(); g++)
        ok = all[i].group(g).matched() && all[i].group(g).begin() == w.b &&
             all[i].group(g).end() == w.e;
      i++;
    }
    i = 0;
    for (auto m : re.find_iter(subj)) {
      if (!ok || i >= want.size()) {
        ok = false;
        break;
      }
      const Row &w = *(want.begin() + static_cast<long>(i));
      ok = m.begin() == w.b && m.end() == w.e;
      for (size_t g = 1; ok && g <= re.group_count(); g++)
        ok = m.group(g).matched() && m.group(g).begin() == w.b &&
             m.group(g).end() == w.e;
      i++;
    }
    ok = ok && i == want.size();
    auto one = re.search(subj);
    ok = ok && one.matched() == (want.size() != 0);
    if (ok && one.matched()) {
      const Row &w = *want.begin();
      ok = one.begin() == w.b && one.end() == w.e;
      for (size_t g = 1; ok && g <= re.group_count(); g++)
        ok = one.group(g).matched() && one.group(g).begin() == w.b &&
             one.group(g).end() == w.e;
    }
    return ok;
  };

  for (bool us : {false, true}) {
    auto mk = [&](const std::string &pat, unsigned flags = 0) {
      return us ? make_us(pat, flags) : make_egc(pat, flags);
    };
    // One-walk bodies: the position scan, a nested and a non-capturing
    // wrapper, the literal-prefix driver.
    CHECK(rows(mk(R"((\w+))"), "foo bar_1  baz", {{0, 3}, {4, 9}, {11, 14}}));
    CHECK(rows(mk(R"(((\w+)))"), "foo bar", {{0, 3}, {4, 7}}));
    CHECK(rows(mk(R"((?:(\d+)))"), "a12 b 345", {{1, 3}, {6, 9}}));
    CHECK(rows(mk(R"((/users/\d+))"), "GET /users/42 /users/x /users/7",
               {{4, 13}, {23, 31}}));
    CHECK(rows(mk(R"((\w+))"), "", {}));
    CHECK(rows(mk(R"((\w+))"), " \n ", {}));
    // A match long enough that the walk crosses it with its run skip.
    {
      std::string longs = std::string(700, 'x') + " " + std::string(900, 'y');
      CHECK(rows(mk(R"((\w+))"), longs, {{0, 700}, {701, 1601}}));
      CHECK(rows(mk(R"(([^\n]+))"), longs, {{0, 1601}}));
    }
    // Bodies the walk refuses (lazy, alternation, case-insensitive).
    CHECK(rows(mk(R"((\w+?))"), "ab c", {{0, 1}, {1, 2}, {3, 4}}));
    CHECK(rows(mk(R"((a|ab))"), "ab a", {{0, 1}, {3, 4}}));
    CHECK(rows(mk(R"((holmes))", IgnoreCase), "Holmes HOLMES", {{0, 6}, {7, 13}}));
    // A non-ASCII byte mid-subject (é is 2 bytes).
    CHECK(rows(mk(R"((\w+))"), "ab cd h\xC3\xA9llo ef gh",
               {{0, 2}, {3, 5}, {6, 12}, {13, 15}, {16, 18}}));
    // Bodies whose twin takes a prefilter tier: a pure literal, a literal
    // alternation, a required suffix.
    CHECK(rows(mk(R"((Holmes))"), "Holmes and Holmes", {{0, 6}, {11, 17}}));
    CHECK(rows(mk(R"((fox|dog))"), "a fox, a dog", {{2, 5}, {9, 12}}));
    CHECK(rows(mk(R"(([a-z]+ing))"), "sing a ringing thing",
               {{0, 4}, {7, 14}, {15, 20}}));
    // Assertions and a lookahead inside the wrapper (assert tier / Pike).
    CHECK(rows(mk(R"((\b\w+n\b))"), "on a train in rain", {{0, 2}, {5, 10}, {11, 13}, {14, 18}}));
    CHECK(rows(mk(R"((^\w+))", Multiline), "ab cd\nef", {{0, 2}, {6, 8}}));
    CHECK(rows(mk(R"((a(?=b)))"), "ab ac ab", {{0, 1}, {6, 7}}));
    // A wrapper that can match empty: the groups are empty spans too.
    CHECK(rows(mk(R"((x*))"), "ax", {{0, 0}, {1, 2}, {2, 2}}));
    CHECK(rows(mk(R"(())"), "ab", {{0, 0}, {1, 1}, {2, 2}}));
  }
  // The group count and names are the pattern's, not the twin's.
  {
    Regex named(R"((?<word>\w+))");
    CHECK(named.group_count() == 1 && named.named_groups().size() == 1);
    auto m = named.search("  hello ");
    CHECK(m.matched() && m.group_count() == 1 &&
          m.group("word").str() == "hello" && m.group(1).begin() == 2);
    auto all = named.find_all("ab cd");
    CHECK(all.size() == 2 && all.group_count() == 1 &&
          all[1].group("word").str() == "cd");
    const std::string abcd = "ab cd";
    for (auto it : named.find_iter(abcd))
      CHECK(it.group("word").str() == it.str() && it.group_count() == 1);
    Regex nested(R"(((?<in>\d+)))");
    CHECK(nested.group_count() == 2);
    auto n2 = nested.search("x42");
    CHECK(n2.group(1).str() == "42" && n2.group(2).str() == "42" &&
          n2.group("in").str() == "42" && !n2.group(3).matched());
    CHECK(Regex(R"(\w+)").group_count() == 0);
    CHECK(Regex(R"((?:\w+))").group_count() == 0);
    // Not whole-match (a second group beside the first): real captures.
    auto two = Regex(R"((a)(b)?)").search("a");
    CHECK(two.group_count() == 2 && two.group(1).matched() &&
          !two.group(2).matched());
    // A capturing wrapper AROUND other groups stays a real group (only a
    // non-capturing one comes off there): all three spans are distinct work.
    for (const char *pat : {R"(((a)(b)))", R"((?:((a)(b))))"}) {
      auto m3 = Regex(pat).search("xab");
      CHECK(m3.group_count() == 3 && m3.group(1).begin() == 1 &&
            m3.group(1).end() == 3 && m3.group(2).begin() == 1 &&
            m3.group(2).end() == 2 && m3.group(3).begin() == 2 &&
            m3.group(3).end() == 3);
    }
    auto inner = Regex(R"((?:(a)(b)))").search("xab");
    CHECK(inner.group_count() == 2 && inner.group(1).str() == "a" &&
          inner.group(2).str() == "b");
  }
  // Every consumer of the groups: replace, split, find_at, to_owned.
  {
    Regex re(R"((\d+))");
    CHECK(re.replace_all("a1 b22", "<$1>") == "a<1> b<22>");
    CHECK(Regex(R"((?<n>\d+))").replace_all("a1 b22", "[$<n>]") ==
          "a[1] b[22]");
    std::vector<std::string> pieces;
    const std::string split_subj = "a1b22c";
    for (auto p : re.split(split_subj))
      pieces.emplace_back(p);
    CHECK(pieces.size() == 3 && pieces[0] == "a" && pieces[2] == "c");
    auto fa = re.find_at("a1 b22", 2);
    CHECK(fa.m.matched() && fa.m.group(1).str() == "22" && fa.next_pos == 6);
    std::string subj = "x7";
    reg::MatchResult owned;
    for (auto m : re.find_iter(subj))
      owned = m.to_owned();
    CHECK(owned.matched() && owned.group_count() == 1 &&
          owned.group(1).str() == "7" && owned.group(1).begin() == 1);
  }
  // A non-capturing wrapper is transparent too: same matches as the bare
  // pattern (it used to hide the pattern's shape from the prefilter
  // analyses).
  for (const char *body : {R"([a-z]+ing)", R"(\w+)", R"(Holmes)", R"(a|ab)"}) {
    const std::string subj = "sing Holmes ab a ringing";
    auto a = find_all(Regex(body), subj);
    auto b = find_all(Regex(std::string("(?:") + body + ")"), subj);
    bool same = a.size() == b.size();
    for (size_t i = 0; same && i < a.size(); i++)
      same = a[i].begin() == b[i].begin() && a[i].end() == b[i].end();
    CHECK(same);
  }
  // match(): anchored at 0, groups filled the same way.
  {
    auto m = Regex(R"((\w+))").match("foo bar");
    CHECK(m.matched() && m.end() == 3 && m.group(1).begin() == 0 &&
          m.group(1).end() == 3);
    CHECK(!Regex(R"((\w+))").match(" foo").matched());
  }
}

// The find ladder: search, test, find_all, find_iter and find_at climb the
// same rungs in the same order. These pin where a scan STARTS (so a fast path
// cannot quietly stop being taken) and what the rungs that only some callers
// reach hand back.
void test_find_ladder() {
  auto rows = [](const Regex &re) { return PlanProbe::start(re, false); };
  auto test = [](const Regex &re) { return PlanProbe::start(re, true); };

  // --- where a scan starts ---
  // A plan that is its own locate, for every caller, in either mode: a
  // printable-ASCII literal (under a group that wraps the whole of it or
  // not), and an alternation of them.
  for (const char *pat : {"Sherlock", ">>=", "a", "(Holmes)", "a\\.b c"})
    for (const Regex &re : {Regex(pat), make_us(pat)})
      CHECK(rows(re) == 'L' && test(re) == 'L');
  // (Not a pattern that is more than a literal. Nor, for now, a literal
  // that is not printable ASCII — which only a Grapheme plan has to ask.)
  for (const char *pat : {"ab?", "caf\xC3\xA9", "a\\nb"})
    for (const Regex &re : {Regex(pat), make_us(pat)})
      CHECK(rows(re) != 'L' && test(re) != 'L');
  for (const Regex &re : {Regex("fox|dog|cat"), make_us("fox|dog|cat")})
    CHECK(rows(re) == 'A' && test(re) == 'A');
  // A text-anchored pattern: one walk from 0, before the subject is looked
  // at or the cache fetched — for test() always, for a find when there are
  // no groups to hand out (with groups, the capture walk of the family is
  // the one walk to take).
  CHECK(rows(Regex("^#[0-9a-fA-F]{6}$")) == '^');
  CHECK(test(Regex("^#[0-9a-fA-F]{6}$")) == '^');
  CHECK(rows(make_us("^#[0-9a-fA-F]{6}$")) == '^');
  CHECK(test(make_us("^(\\d+)-(\\d+)$")) == '^');
  CHECK(rows(make_us("^(\\d+)-(\\d+)$")) == 'W');
  CHECK(rows(Regex("^(\\d+)-(\\d+)$")) == '?');
  // CodePoint: the family does not depend on the subject, so the scan
  // starts on its first rung outright.
  CHECK(rows(make_us("\\w+")) == 'W' && test(make_us("\\w+")) == 'B');
  CHECK(rows(make_us("(\\w+)=(\\w+)")) == 'W');
  CHECK(rows(make_us("e[a-z]{3,}q")) == 'S');
  CHECK(rows(make_us("[a-z]+@[a-z]+")) == 'I');
  CHECK(rows(make_us("(?=a)\\w")) == 'P');
  // Grapheme: the subject chooses the family.
  CHECK(rows(Regex("\\w+")) == '?' && test(Regex("\\w+")) == '?');
  // A boolean takes the find's prefilter rungs (each stops at the first
  // accepting state it reaches) and, where the find would walk or chain,
  // the boolean scan.
  CHECK(test(make_us("e[a-z]{3,}q")) == 'S');
  CHECK(test(make_us("[a-z]+@[a-z]+")) == 'I');
  CHECK(test(make_us("(\\w+)=(\\w+)")) == 'B');

  // --- every entry point, against the bare VM ---
  // (The loops below run one pattern over many subjects: its reference and
  // its two units are compiled once.)
  struct Compiled {
    std::string pat;
    std::optional<Regex> pike, unit[2];
  } last;
  auto agree = [&](const std::string &pat, const std::string &subj) {
    if (!last.pike || last.pat != pat) {
      last.pat = pat;
      last.pike.emplace(pike_twin(pat));
      last.unit[0].emplace(pat, 0u, reg::MatchUnit::Grapheme);
      last.unit[1].emplace(pat, 0u, reg::MatchUnit::CodePoint);
    }
    const std::vector<size_t> want = flat_spans(*last.pike, subj, false);
    for (int u = 0; u < 2; u++) {
      // The twin is a Grapheme regex: a CodePoint one agrees with it on a
      // subject with no CR-LF pair and no combining mark.
      if (u == 1 && (subj.find('\r') != std::string::npos ||
                     subj.find("\xCC") != std::string::npos))
        continue;
      if (!finds_agree(*last.unit[u], want, subj)) return false;
    }
    return true;
  };

  // The two answers a first, naive walk on the byte tier got wrong: a class
  // that counts a CR-LF pair as one element where the walk's table counts
  // two, and a class of non-ASCII characters only, whose candidates the walk
  // skipped as bytes no match can start with.
  CHECK(agree("[^c-za]a?", "c\r\n3"));
  CHECK(agree("[\xF0\x9F\x98\x80\xE6\xBC\xA2]{1,}", " \xF0\x9F\x98\x80"));
  CHECK(Regex("[^c-za]a?").search("c\r\n3").str() == "\r\n");
  CHECK(Regex("[\xF0\x9F\x98\x80\xE6\xBC\xA2]{1,}")
            .search(" \xF0\x9F\x98\x80")
            .begin() == 1);

  // The walk and the chain taking turns on the byte tier: the é-bearing
  // words come from the chain, the rest from the walk, for every caller.
  CHECK(agree("\\w+", "ab c\xC3\xA9" "d ef \xC3\xA9 gh"));
  CHECK(agree("(\\w+)", "ab c\xC3\xA9" "d ef \xC3\xA9 gh"));
  CHECK(agree("(\\w+)=(\\w+)", "a=b \xC3\xA9=c d=\xC3\xA9 e=f\r\ng=h"));
  CHECK(agree("\\p{L}+", "ab\r\ncd \xE6\x97\xA5 ef"));
  CHECK(agree("\\w+", "ab\r\ncd\r\n"));

  // A text-anchored find: the match at 0 and nothing after it, an empty
  // match at 0 that does not come back, a byte the walk has no transition
  // for (the families then answer), with and without groups.
  for (const char *pat : {"^ab", "^[a-c]*", "\\Aab", "^[a-c]+$", "^(a)(b)",
                          "^(?:ab)+", "^([a-c]+)-(\\d+)$", "^", "^$", "^a*b?"})
    for (const char *subj :
         {"", "ab", "abab", "ab\nab", "xab", "abc-12", "ab\xC3\xA9",
          "\xC3\xA9" "ab", "a\r\nb", "b", "aab"})
      CHECK(agree(pat, subj));
  CHECK(Regex("^ab").find_all("abab").size() == 1);
  CHECK(Regex("^[a-c]*").find_all("xyz").size() == 1); // the empty match at 0
  CHECK(!Regex("^ab").find_at("abab", 2).m.matched());
  CHECK(!Regex("^").find_at("ab", 1).m.matched());

  // test() through the prefilter rungs, on subjects long enough for their
  // budgets: one without the literal the find is driven from, one that holds
  // it and matches, one that holds it and does not, one that holds it in
  // the other case, one whose only match ends the subject.
  for (size_t pad : {size_t(120), size_t(127), size_t(128), size_t(400)}) {
    const std::string filler(pad, 'e'), tail(pad, 'a');
    for (const char *pat : {"e[a-z]{3,}q", "[a-z]+@[a-z]+", "\\w+ly\\b",
                            "x[a-z]+q|\\d\\d", "(?i)e[a-z]{3,}q", "t\\w+ing$"}) {
      CHECK(agree(pat, filler + tail));                 // no literal
      CHECK(agree(pat, filler + "q" + tail));           // literal, match
      CHECK(agree(pat, filler + " q@ly " + tail));      // literal, mostly none
      CHECK(agree(pat, filler + " EABCQ 12 " + tail));  // the other case
      CHECK(agree(pat, filler + tail + " testing"));    // at the very end
    }
  }
  // The interior-literal rung as a boolean looks back 32 bytes for where a
  // match through the literal could start, and leaves the subject to the
  // scan when the pre-part is still alive there; and it is left out for a
  // subject under 64 bytes. Pre-parts shorter and longer than the look,
  // subjects on both sides of the threshold, the literal absent, first,
  // last, and in a place that completes no match.
  {
    const std::string run40(40, 'a'), run20(20, 'a'), words =
        "the lazy dog jumps over; the lazy dog jumps over; the lazy dog; ";
    for (const char *pat : {"[^?]+\\?.*", "[a-z]+@[a-z]+", "\\w+=\\w+x",
                            "[a-z]+-[0-9]{4}", "([a-z]+)@([a-z]+)"})
      for (const std::string &subj :
           {run20 + "?b", run40 + "?b", run40 + "@b", run20 + "@b",
            words + run40 + "@b " + words, words + run20 + "=bx " + words,
            words + "@" + words, words + "ab@ " + run40 + "@cd",
            words + words + "a-1234", "?" + words, words + "?", std::string("a@"),
            words + words, std::string("x=") + run40 + "x"})
        CHECK(agree(pat, subj));
  }
  // ... and a pre-part that needs more characters than the look holds: no
  // start inside it, one before it. The boolean has to leave such a subject
  // to the scan, not conclude the literal is in no match.
  {
    const std::string run34(34, 'a'), run36(36, 'a'), run90(90, 'a');
    for (const char *pat : {"[a-z]{35,}@x", "[a-z]{35}@x", "\\w{33,40}=[a-z]",
                            "[^?]{35,}\\?"})
      for (const std::string &tail : {"@x", "=c", "?"})
        for (const std::string &run : {run34, run36, run90})
          for (const std::string &lead : {"", " ", "words and words; "}) {
            CHECK(agree(pat, lead + run + tail));
            CHECK(agree(pat, lead + run34 + tail + " " + run + tail + " end"));
          }
    CHECK(Regex("[a-z]{35,}@x").test(" " + run36 + "@x"));
    CHECK(!Regex("[a-z]{35,}@x").test(" " + run34 + "@x"));
    CHECK(make_us("[a-z]{35,}@x").test(" " + run36 + "@x"));
    CHECK(!make_us("[a-z]{35,}@x").test(" " + run34 + "@x"));
  }
  // The fused prefix scan verifies a candidate with the byte DFA, over bytes
  // its eligibility scan has not reached yet. A failed verify that touched
  // a cluster is not "no match here" — the byte engine cannot see the
  // match the cluster is part of. Passed over, the candidate was lost in two
  // ways (both the iterator's alone before the ladder was shared, found by
  // the fuzzer at ten times its default count): the failed-verify budget
  // ran out on a short subject and the scan resumed past it; and a later
  // candidate matched in front of the cluster and was reported.
  {
    const std::string mark = "\xCC\x81", e_acute = "\xC3\xA9";
    for (const char *pat : {"q\\w*\\.", "q[a-z]*\\.", "q\\w+x", "Z\\w{3,},"})
      for (const std::string &subj :
           {"qqqq" + mark + ".", e_acute + " qqqq" + mark + ".",
            e_acute + " qqqqqqqq" + mark + ".", " qqqq" + mark + "qx",
            e_acute + " Z,Z,,ZZZZZ" + mark + "ZZ,Z,,", "q" + mark + ".",
            "qq" + mark + ". qq."})
        CHECK(agree(pat, subj));
    for (const char *pat : {"q(?:a[a-z]+z|b)", "q(?:a\\w+z|b)", "qa[a-z]+z|qb"})
      for (const std::string &subj :
           {"qaqbcd" + mark + "z", e_acute + " qaqbcd" + mark + "z",
            "qaqbcd" + mark + "z and then qb and qaz",
            std::string(200, ' ') + "qaqbcd" + mark + "z" + std::string(200, ' '),
            "qaqb cd" + mark + "z", "qaqbcd" + mark + "y qb"})
        CHECK(agree(pat, subj));
    Regex re("q(?:a[a-z]+z|b)");
    auto m = re.search("qaqbcd" + mark + "z");
    CHECK(m.matched() && m.begin() == 0 && m.end() == 9);
    m = Regex("q\\w*\\.").search("qqqq" + mark + ".");
    CHECK(m.matched() && m.begin() == 0 && m.end() == 7);
  }
  // A literal is its bytes in either unit, but a match of it is a cluster:
  // `q` followed by a combining mark is in the subject and is not a `q`.
  {
    const std::string pad(300, ' ');
    CHECK(!Regex("e[a-z]{3,}q").test(pad + "eabcq\xCC\x81" + pad));
    CHECK(Regex("e[a-z]{3,}q").test(pad + "eabcq" + pad));
    CHECK(agree("e[a-z]{3,}q", pad + "eabcq\xCC\x81 eabcq" + pad));
  }

  // The Pike rung skips to a candidate before it runs, at every entry point
  // (it used to at search() only): a literal prefix in either case, the
  // literals of an alternation, the bytes a match can begin with.
  for (const char *pat : {"abc(?=d)", "(?i)abc(?=d)", "(?:foo|bar)(?=\\d)",
                          "[xy]\\w(?!z)", "(a)(?=b)\\w", "(\\w)\\1"})
    for (const char *subj :
         {"", "abcd abce ABCD", "foo1 bar barz bar2", "xa ybz yc", "ab ac ab",
          "aa bb ab", "abcd\xC3\xA9 ABCD abcd", "x\r\nabcd"})
      CHECK(agree(pat, subj));

  // A caller's FindCache shared by two Regexes is re-bound by every step
  // that can reach a rung reading its DFAs. That includes the step that
  // starts on the walk from 0 and leaves it for the families: a
  // text-anchored, capture-free pattern over a subject with a non-ASCII
  // byte in it. (Bound only once the scan stood past that rung, it ran the
  // other Regex's DFAs — and found nothing.)
  {
    Regex::FindCache cache;
    Regex digits("^\\w+ \\d+$"), words("^\\w+ \\w+$");
    const std::string sd = "ab\xC3\xA9 12", sw = "abc d\xC3\xA9" "f";
    for (int round = 0; round < 2; round++) {
      size_t nd = 0, nw = 0, ni = 0;
      for (auto m : digits.find_all(std::string_view(sd), cache))
        nd += m.begin() == 0 && m.end() == sd.size();
      for (auto m : words.find_all(std::string_view(sw), cache))
        nw += m.begin() == 0 && m.end() == sw.size();
      for (auto m : words.find_iter(sw, cache))
        ni += m.begin() == 0 && m.end() == sw.size();
      CHECK(nd == 1 && nw == 1 && ni == 1);
      CHECK(digits.find_at(sd, 0, cache).m.matched());
      CHECK(words.find_at(sw, 0, cache).m.matched());
      CHECK(!digits.find_at(sw, 0, cache).m.matched());
    }
  }
}

// A non-ASCII byte in a one-walk driver's way is LOCAL: the located-span chain
// serves that one find and the driver is asked again for the next. So one
// subject alternates between the two engines match by match — and, when most
// finds bail, the driver gives up for good partway (the profitability rule).
// None of it may show in the results, on any entry point. CodePoint mode: it
// is where the drivers meet non-ASCII bytes at all.
void test_onewalk_local_bail() {
  auto both = [&](const Regex &re, std::string_view subj,
                  const std::vector<size_t> &want) {
    return flat_spans(re, subj, false) == want &&
           flat_spans(re, subj, true) == want;
  };

  // é is 2 bytes (\xC3\xA9) and a word character; ¡ (\xC2\xA1) is not.
  // Walk, chain, walk, chain, walk: the é-bearing words come from the chain.
  CHECK(both(make_us(R"(\w+)"), "ab c\xC3\xA9" "d ef \xC3\xA9 gh",
             {0, 2, 3, 7, 8, 10, 11, 13, 14, 16}));
  // A non-ASCII byte right AFTER a match (the walk cannot tell it does not
  // extend the word) and right before one.
  CHECK(both(make_us(R"(\w+)"), "ab\xC2\xA1" "cd \xC2\xA1" "ef", {0, 2, 4, 6, 9, 11}));
  // At the very start and the very end of the subject.
  CHECK(both(make_us(R"(\w+)"), "\xC3\xA9 ab \xC3\xA9", {0, 2, 3, 5, 6, 8}));
  // Captures through the scalar chain and the one-pass drivers: groups of
  // the chain-served matches are resolved by the capture engine.
  CHECK(both(make_us(R"((\w+)=(\w+))"), "a=b \xC3\xA9=c d=\xC3\xA9 e=f",
             {0, 3,   0, 1,  2, 3,    4, 8,   4, 6,  7, 8,
              9, 13,  9, 10, 11, 13,  14, 17, 14, 15, 16, 17}));
  CHECK(both(make_us(R"(/users/(\d+))"), "/users/1 \xC3\xA9 /users/22",
             {0, 8, 7, 8, 12, 21, 19, 21}));
  // `body$` on the assert tier: the only match is the last word.
  CHECK(both(make_us(R"((\w+)$)"), "ab \xC3\xA9 cd", {6, 8, 6, 8}));
  CHECK(both(make_us(R"((\w+)$)"), "ab cd\xC3\xA9", {3, 7, 3, 7}));

  // Regime changes inside one subject. 1200 words that each begin with é
  // (every find bails, so the driver is given up partway), then 1200 plain
  // words; and the reverse order, where the driver serves the first half.
  // Every word must be found exactly once either way.
  {
    std::string na, plain;
    std::vector<size_t> want_na_first, want_plain_first;
    for (int i = 0; i < 1200; i++) {
      na += "\xC3\xA9xy ";
      plain += "abc ";
    }
    for (size_t i = 0; i < 1200; i++) { // "éxy " is 5 bytes, "abc " is 4
      want_na_first.push_back(i * 5);
      want_na_first.push_back(i * 5 + 4);
      want_plain_first.push_back(i * 4);
      want_plain_first.push_back(i * 4 + 3);
    }
    for (size_t i = 0; i < 1200; i++) {
      want_na_first.push_back(6000 + i * 4);
      want_na_first.push_back(6000 + i * 4 + 3);
      want_plain_first.push_back(4800 + i * 5);
      want_plain_first.push_back(4800 + i * 5 + 4);
    }
    CHECK(both(make_us(R"(\w+)"), na + plain, want_na_first));
    CHECK(both(make_us(R"(\w+)"), plain + na, want_plain_first));
    // The whole-match capture twin takes the same road.
    auto all = make_us(R"((\w+))").find_all(na + plain);
    CHECK(all.size() == 2400 && all[2399].group(1).begin() == 6000 + 1199 * 4);
  }
}

// UnicodeScalar mode (phase 1): literal patterns compile to a UTF-8 byte
// automaton and run on the byte DFA over non-ASCII subjects with no cliff.
// Code-point (not grapheme) semantics; byte offsets. Non-literal constructs are
// rejected until later phases.
void test_unicode_scalar() {
  // Match unit is a process-wide default now (no per-Regex flag); set CodePoint
  // for this whole function and restore Grapheme at the end. US == 0 so every
  // `Regex(p, US)` / `US | flag` below builds under the global default.
  reg::set_default_match_unit(reg::MatchUnit::CodePoint);
  const unsigned US = 0;
  // literal over non-ASCII; byte offsets (é = 2 bytes)
  Regex re("café", US);
  auto m = re.search("le café du soir");
  CHECK(m.matched() && m.str() == "café" && m.begin() == 3 && m.end() == 8);
  CHECK(re.test("un café") && !re.test("cafe"));
  // disjoint literal alternation (longest-safe, capture-free) over non-ASCII
  auto all =
      find_all(Regex("(?:café|naïve|dog)", US), "a café and a naïve dog");
  CHECK(all.size() == 3 && all[0].str() == "café" && all[1].str() == "naïve" &&
        all[2].str() == "dog");
  // CJK and a 4-byte emoji literal
  CHECK(Regex("日本", US).search("これは日本語").str() == "日本");
  auto fe = find_all(Regex("🦊", US), "🦊x🦊");
  CHECK(fe.size() == 2 && fe[0].begin() == 0 && fe[0].end() == 4 &&
        fe[1].begin() == 5);
  // greedy repeat of a non-ASCII literal
  CHECK(Regex("é+", US).search("aééébb").str() == "ééé");
  // columnar matches() in US mode
  auto ms = Regex("(?:café|naïve)", US).find_all("café naïve");
  CHECK(ms.size() == 2 && ms[0].str() == "café" && ms[1].str() == "naïve");

  // phase 2: explicit ranges and `.` compile to UTF-8 byte automata.
  CHECK(Regex("[α-ω]+", US).search("abc αβγ xyz").str() == "αβγ"); // 2-byte range
  CHECK(Regex("[a-z]+", US).search("XYabcZ").str() == "abc");
  CHECK(Regex("a.c", US).search("aéc").str() == "aéc"); // . = one code point
  CHECK(Regex("a.c", US).test("axc") && !Regex("a.c", US).test("a\nc"));
  CHECK(Regex("[^0-9]+", US).search("12café34").str() == "café"); // negated
  auto la = find_all(Regex("[A-Za-zÀ-ÿ]+", US), "héllo wörld 12");
  CHECK(la.size() == 2 && la[0].str() == "héllo" && la[1].str() == "wörld");
  CHECK(Regex("[一-龿]+", US).search("ab 日本語 cd").str() == "日本語"); // CJK
  CHECK(Regex("[\\x{1F300}-\\x{1FAFF}]+", US).search("x🦊🎉y").str() ==
        "🦊🎉"); // 4-byte emoji range

  // phase 3: \d \w \s \p{...} as Unicode code-point sets (the cliff-free \w+).
  CHECK(Regex("\\w+", US).search("  héllo  ").str() == "héllo");
  CHECK(Regex("\\w+", US).search(" 日本語 ").str() == "日本語");
  CHECK(find_all(Regex("\\w+", US), "héllo wörld 日本 café").size() == 4);
  CHECK(Regex("\\d+", US).search("abc123").str() == "123");
  CHECK(Regex("\\S+", US).search("  café  ").str() == "café");
  CHECK(Regex("\\D+", US).search("12café34").str() == "café"); // negated pred
  CHECK(Regex("\\p{L}+", US).search("12 héllo 34").str() == "héllo");
  CHECK(Regex("\\p{Lu}+", US).search("abcDÉF").str() == "DÉF"); // É uppercase
  CHECK(Regex("[\\w-]+", US).search(" a-b_café ").str() ==
        "a-b_café"); // pred+range

  // phase 4: captures / anchors / lookaround run on the byte Pike VM, with
  // code-point semantics and byte offsets.

  // captures over non-ASCII; group spans are byte offsets
  {
    auto cm = Regex("(\\w+)@(\\w+)", US).search("café@naïve");
    CHECK(cm.matched() && cm.str() == "café@naïve");
    CHECK(cm.group(1).str() == "café" && cm.group(1).begin() == 0 &&
          cm.group(1).end() == 5);                                 // é = 2 bytes
    CHECK(cm.group(2).str() == "naïve" && cm.group(2).begin() == 6); // after '@'
    auto caps = Regex("(é)(\\w)", US).search("xéy");
    CHECK(caps.group(1).str() == "é" && caps.group(2).str() == "y");
  }
  // Dfa/US+cap: the candidate + unbounded one-pass walk drives capture finds
  // in US mode too (search / find_all / find_iter), bailing to the located-
  // span chain at a non-ASCII byte. find_all must keep the rows found before
  // the bail and resume the chain from it — neither drop them nor redo the
  // subject — and every entry point must agree.
  {
    Regex kv("(\\w+)=(\\w+)", US);
    std::string s = "a=b cé=d e=f é g=h";
    auto first = kv.search(s);
    CHECK(first.matched() && first.group(1).str() == "a" &&
          first.group(2).str() == "b");
    auto rows = find_all(kv, s);
    CHECK(rows.size() == 4 && rows[0].str() == "a=b" &&
          rows[1].group(1).str() == "cé" && rows[1].group(2).str() == "d" &&
          rows[2].str() == "e=f" && rows[3].group(2).str() == "h");
    size_t n = 0;
    for (auto it : kv.find_iter(s)) {
      CHECK(n < rows.size() && it.str() == rows[n].str() &&
            it.group(1).begin() == rows[n].group(1).begin());
      n++;
    }
    CHECK(n == rows.size());
    // The per-call shape that motivated the tier: one walk, no reverse pass.
    auto r = Regex("/users/(\\d+)", US).search("/users/123456");
    CHECK(r.matched() && r.group(1).str() == "123456" && r.end() == 13);
  }
  // The position-scan driver's failure paths: over prose, `(\w+)\s+(\d+)`
  // makes every word a candidate whose walk runs the word and fails, so (a)
  // the failed walk's first run skips the rest of the word (restart_ok) and
  // (b) the profitability rule bails to the chain part-way through a long
  // subject, which resumes from the bail point. Sprinkle matches so both the
  // driver's and the chain's halves must find theirs; find_all and find_iter
  // must agree with each other and with the pattern's obvious count.
  {
    std::string prose;
    size_t expect = 0;
    while (prose.size() < 64 * 1024) {
      for (int i = 0; i < 40; i++) prose += "lorem ipsum dolor sit amet ";
      prose += "id 4711 ";
      expect++;
    }
    Regex ws("(\\w+)\\s+(\\d+)", US);
    auto rows = find_all(ws, prose);
    CHECK(rows.size() == expect);
    CHECK(!rows.empty() && rows[0].group(1).str() == "id" &&
          rows[0].group(2).str() == "4711");
    size_t n = 0;
    for (auto it : ws.find_iter(prose)) {
      CHECK(n < rows.size() && it.begin() == rows[n].begin() &&
            it.end() == rows[n].end());
      n++;
    }
    CHECK(n == expect);
    CHECK(find_all(make_egc("(\\w+)\\s+(\\d+)"), prose).size() == expect);
    // A require_end (`body$`) plan: the walk ACCEPTS at a position the
    // trailing `$` rejects, so the driver treats it as a failure and reads
    // the walk's report — the path where `body$` differs from every other
    // pattern shape, and the one no other test drives.
    {
      Regex tail("(\\d{3}) (\\d+)$", US);
      auto m = tail.search("123 456 789 000");
      CHECK(m.matched() && m.begin() == 8 && m.end() == 15 &&
            m.group(1).str() == "789" && m.group(2).str() == "000");
      CHECK(find_all(tail, "123 456 789 000").size() == 1);
      std::string many;
      for (int i = 0; i < 2000; i++) many += "123 456 ";
      many += "999 12345";
      auto big = tail.search(many);
      CHECK(big.matched() && big.begin() == many.size() - 9 &&
            big.end() == many.size());
      CHECK(!tail.search("123 456 789 000x").matched());
    }
  }
  // named captures
  {
    auto nm = Regex("(?<w>\\p{L}+)", US).search("12 héllo");
    CHECK(nm.matched() && nm.group("w").str() == "héllo");
  }
  // one-pass capture engine: multi-group + empty capture, non-ASCII, byte
  // offsets
  {
    auto dm = find_all(Regex("(\\d+)-(\\w+)", US), "12-café 7-naïve");
    CHECK(dm.size() == 2);
    CHECK(dm[0].group(1).str() == "12" && dm[0].group(2).str() == "café");
    CHECK(dm[1].group(1).str() == "7" && dm[1].group(2).str() == "naïve");
    auto em =
        find_all(Regex("(\\w*)", US), "café"); // greedy, one match + empty tail
    CHECK(em.size() == 2 && em[0].group(1).str() == "café" &&
          em[0].group(1).end() == 5);
    auto ms2 =
        Regex("(\\w+)", US).find_all("héllo wörld"); // columnar via one-pass
    CHECK(ms2.size() == 2 && ms2[0].group(1).str() == "héllo" &&
          ms2[1].group(1).str() == "wörld");
  }
  // anchors: ^ $ over the whole subject; \b \B over code points
  CHECK(Regex("^café$", US).test("café"));
  CHECK(!Regex("^café$", US).test("xcafé"));
  CHECK(Regex("\\bworld\\b", US).search("héllo world!").str() == "world");
  CHECK(Regex("\\w+$", US).search("a café").str() == "café");
  // \b sits between a word and a non-word code point, counting code points
  CHECK(Regex("\\bné\\b", US).test("un né ici") &&
        !Regex("\\bné\\b", US).test("uné"));
  // multiline ^/$ anchor at line breaks
  {
    auto ml = find_all(Regex("^\\w+", US | reg::Multiline), "café\nnaïve");
    CHECK(ml.size() == 2 && ml[0].str() == "café" && ml[1].str() == "naïve");
  }
  // lookahead / negative lookahead
  CHECK(Regex("café(?= du)", US).search("le café du soir").str() == "café");
  CHECK(!Regex("café(?= du)", US).test("le café noir"));
  CHECK(Regex("\\w+(?!\\w)", US).search("héllo").str() == "héllo");
  // lookbehind (reverse byte body) over non-ASCII
  CHECK(Regex("(?<=café )\\w+", US).search("le café noir").str() == "noir");
  CHECK(Regex("(?<=é)x", US).test("éx") && !Regex("(?<=e)x", US).test("éx"));
  // negative lookbehind
  CHECK(Regex("(?<!ca)fé", US).test("xfé") &&
        !Regex("(?<!ca)fé", US).test("café"));
  // longest-unsafe alternation (needs the Pike VM) — leftmost-first
  CHECK(Regex("(café|caféteria)", US).search("caféteria").str() == "café");
  // lazy quantifier (longest-unsafe) over non-ASCII
  CHECK(Regex("é.*?é", US).search("éxxéyyé").str() == "éxxé");
  // empty matches advance by a whole code point (no split codepoints)
  {
    auto em = find_all(Regex("(?=\\w)", US), "aé");
    CHECK(em.size() == 2 && em[0].begin() == 0 && em[1].begin() == 1);
  }
  // columnar matches() with captures in US mode
  {
    auto cms = Regex("(\\w)(\\w)", US).find_all("éb");
    CHECK(cms.size() == 1 && cms[0].group(1).str() == "é" && cms[0].group(2).str() == "b");
  }

  // code-point vs grapheme: on a multi-code-point grapheme (e + U+0301
  // combining acute = "é", 3 bytes), US counts code points while EGC counts
  // graphemes.
  {
    std::string ecombining = "e\xCC\x81"; // U+0065 U+0301
    // US `.` and `(\w)` match ONE code point ('e', 1 byte); the capture too.
    CHECK(Regex(".", US).search(ecombining).str() == "e");
    auto cu = Regex("(\\w)", US).search(ecombining);
    CHECK(cu.group(1).str() == "e" && cu.group(1).end() == 1);
    // EGC `.` matches the whole grapheme (all 3 bytes).
    CHECK(make_egc(".").search(ecombining).str() == ecombining);
    // EGC classes classify a cluster by its base code point (Model 2): \w /
    // \p{L} / [a-z] match the whole "e"+◌́ cluster (base 'e' is a letter); US
    // matches only the 'e' code point (the combining mark stops it).
    CHECK(make_egc("\\w+").search(ecombining).str() == ecombining);
    CHECK(make_egc("\\p{L}+").search(ecombining).str() == ecombining);
    CHECK(make_egc("[a-z]+").search(ecombining).str() == ecombining);
    // Escaped literal code points are grapheme-segmented exactly like typed
    // text: an escaped `\r\n` run fuses into the single CR-LF cluster (UAX #29
    // GB3) and matches the indivisible CR-LF cluster a subject presents.
    // Without the fusion pass the escaped run stayed two single-code-point
    // literals, so `\r\n` silently failed to match real CR-LF in EGC mode.
    CHECK(make_egc("\\r\\n").search("\r\n").matched());
    CHECK(make_egc("\\r\\n").search("\r\n").end() == 2);
    CHECK(make_egc("a\\r\\nb").search("a\r\nb").matched());
    // the cpp-httplib status line is CR-LF terminated — matches in EGC mode now
    CHECK(make_egc(R"((HTTP/1\.[01]) (\d{3})(?: (.*?))?\r\n)")
              .search("HTTP/1.1 200 OK\r\n")
              .matched());
    // a quantified trailing escape does NOT fuse (the `\n?` is its own atom):
    // a lone CR is a distinct cluster from CR-LF, so `\r\n?` matches a lone CR
    // but not the CR-LF cluster.
    CHECK(make_egc("\\r\\n?").search("x\ry").begin() == 1);
    CHECK(!make_egc("\\r\\n?").search("\r\n").matched());
    // typed CR-LF already fused via tokenization; escaped now agrees with it
    CHECK(make_egc("\r\n").search("\r\n").matched());
    CHECK(Regex("\\w+", US).search(ecombining).str() == "e");
    // "é" as NFC (single code point U+00E9) and NFD (e+◌́) match \w+
    // identically.
    CHECK(Regex("\\w+").search("\xC3\xA9").str() == "\xC3\xA9");
    // \s matches the CR-LF cluster (it is whitespace); \S does not (it IS
    // space).
    CHECK(Regex("a\\s+b").search("a\r\nb").matched());
    CHECK(!Regex("a\\Sb").search("a\r\nb").matched());
    // a US literal with a combining mark matches it as two code points
    CHECK(Regex("e\xCC\x81", US).search("xe\xCC\x81y").begin() == 1);
  }

  // invalid UTF-8 in a US-Pike (capture) subject: a lone continuation byte is
  // treated as one code point (segment_cp's decode fallback); must stay
  // in-bounds and still find the surrounding valid matches.
  {
    std::string bad = "ab\x80"
                      "cd"; // lone continuation byte -> U+0080 (non-word)
    auto bm = find_all(Regex("(\\w+)", US), bad);
    CHECK(bm.size() == 2 && bm[0].str() == "ab" && bm[1].str() == "cd");
  }

  // IgnoreCase in US mode: the byte automaton bakes case-fold orbits; the Pike
  // folds at match time. Both ASCII and non-ASCII case variants match.
  {
    const unsigned USI = US | reg::IgnoreCase;
    // literal, non-ASCII case folding (é <-> É), via the byte DFA
    CHECK(Regex("café", USI).test("le CAFÉ du soir"));
    CHECK(Regex("CAFÉ", USI).search("un café").str() == "café");
    // explicit range expands to both cases; \w+ unaffected
    CHECK(Regex("[a-z]+", USI).search("ABCdef").str() == "ABCdef");
    CHECK(Regex("[à-ÿ]+", USI).search("ÀÉÏ").str() == "ÀÉÏ"); // non-ASCII range
    // capture under icase (one-pass byte engine), byte offsets preserved
    auto cm = find_all(Regex("(\\w+)", USI), "Héllo WÖRLD");
    CHECK(cm.size() == 2 && cm[0].group(1).str() == "Héllo" &&
          cm[1].group(1).str() == "WÖRLD");
    // fold orbit: /k/i also matches U+212A KELVIN SIGN (folds to 'k')
    CHECK(Regex("k", USI).test("\xE2\x84\xAA")); // U+212A
    // anchors/alternation under icase go through the code-point Pike
    CHECK(Regex("^(héllo|bye)$", USI).test("HÉLLO"));
    // non-matching case-distinct control: a US icase pattern still rejects
    // genuinely different letters
    CHECK(!Regex("café", USI).test("cafe")); // 'e' != 'é' even folded
  }
  reg::set_default_match_unit(reg::MatchUnit::Grapheme); // restore default
  // EGC mode (default) is unchanged
  CHECK(Regex("café").search("le café").str() == "café");
}

void test_named_groups() {
  auto m = Regex("(?<year>\\d{4})-(?<mon>\\d{2})").search("2026-05");
  CHECK(m);
  CHECK(m.group("year").str() == "2026");
  CHECK(m.group("mon").str() == "05");
  CHECK(m.group("nope").matched() == false);
  CHECK(Regex("(?'q'\\d+)").search("x42").group("q").str() == "42"); // (?'name')

  // A name longer than the small-string limit: group(name) looks the
  // string_view up directly, so this must not depend on any per-call copy.
  CHECK(Regex("(?<a_very_long_capture_group_name>\\d+)")
            .search("x42")
            .group("a_very_long_capture_group_name")
            .str() == "42");
}

// named_groups(): introspection of the name -> index mapping. group(name) only
// answers for a name you already know; this is the only way to discover them.
void test_named_groups_introspection() {
  Regex re("(?<year>\\d{4})-(?<mon>\\d{2})-(\\d{2})(?<day>x)?");
  const auto &names = re.named_groups();
  CHECK(names.size() == 3); // group 3 is unnamed -> absent
  CHECK(names.at("year") == 1);
  CHECK(names.at("mon") == 2);
  CHECK(names.at("day") == 4);
  CHECK(names.count("nope") == 0);

  // Indices agree with group(name) on a real match.
  auto m = re.search("2026-05-17");
  for (const auto &kv : names)
    CHECK(m.group(kv.first).begin() ==
          m.group(static_cast<size_t>(kv.second)).begin());

  // Iteration order is deterministic (sorted by name), so callers can list a
  // pattern's groups reproducibly.
  std::vector<std::string> order;
  for (const auto &kv : names)
    order.push_back(kv.first);
  CHECK(order == std::vector<std::string>({"day", "mon", "year"}));

  // No named groups -> empty map (not an error).
  CHECK(Regex("(\\d+)-(\\d+)").named_groups().empty());
  CHECK(Regex("plain").named_groups().empty());

  // Survives materialization into an owning result.
  auto owned = re.search("2026-05-17").group("mon").to_owned();
  CHECK(owned.str() == "05");
}

void test_boundaries_and_flags() {
  CHECK(Regex("\\bcat\\b").test("a cat sat"));
  CHECK(!Regex("\\bcat\\b").test("category"));
  CHECK(Regex("\\Bcat\\B").test("locate"));
  CHECK(!Regex("\\Bcat\\B").test("a cat"));
  CHECK(Regex("(?i)hello").test("HELLO World"));
  CHECK(Regex("(?i)[a-z]+").test("ABC"));
  CHECK(Regex("(?i)STRASSE").test("strasse"));
  CHECK(Regex("(?m)^bar$").test("foo\nbar\nbaz"));
  CHECK(!Regex("^bar$").test("foo\nbar\nbaz")); // without (?m)
}

// Absolute text anchors \A \z \Z (RE2/Rust/PCRE/Python support these; they are
// distinct from ^/$ in that Multiline never turns them into line anchors).
void test_text_anchors() {
  // \A: start of text.
  CHECK(Regex("\\Afoo").search("foo").matched());
  CHECK(!Regex("\\Afoo").search("xfoo").matched());
  // \A is NOT a line anchor under Multiline (unlike ^).
  CHECK(!Regex("\\Abar", Multiline).search("foo\nbar").matched());
  CHECK(Regex("^bar", Multiline).search("foo\nbar").matched());
  // \z: absolute end of text (a trailing newline is part of the text).
  CHECK(Regex("bar\\z").search("bar").matched());
  CHECK(!Regex("bar\\z").search("bar\n").matched());
  CHECK(!Regex("foo\\z", Multiline).search("foo\nbar").matched());
  // \Z: end of text, or just before a single trailing newline.
  CHECK(Regex("bar\\Z").search("bar").matched());
  CHECK(Regex("bar\\Z").search("bar\n").matched());
  CHECK(!Regex("bar\\Z").search("bar\n\n").matched());
  CHECK(!Regex("bar\\Z").search("bar\nx").matched());
  // \A...\z is a whole-text anchor.
  CHECK(Regex("\\A\\d+\\z").search("12345").matched());
  CHECK(!Regex("\\A\\d+\\z").search("12 45").matched());
  // Captures and find_all under an anchor (exactly one anchored match).
  {
    auto v = find_all(Regex("\\A(\\w+)"), "hi there");
    CHECK(v.size() == 1 && std::string(v[0].group(1).str()) == "hi");
  }
  // UnicodeScalar mode and inside a lookaround.
  CHECK(make_us("\\Afoo\\z").search("foo").matched());
  CHECK(!make_us("\\Afoo\\z").search("foox").matched());
  CHECK(Regex("foo(?=\\z)").search("foo").matched());
  CHECK(!Regex("foo(?=\\z)").search("food").matched());
}

void test_constructor_flags() {
  // IgnoreCase via constructor (no inline (?i) needed).
  CHECK(Regex("abc", IgnoreCase).test("xxABCxx"));
  CHECK(Regex("[a-z]+", IgnoreCase).search("ABC").str() == "ABC");
  CHECK(!Regex("abc").test("ABC")); // default is case-sensitive

  // Multiline via constructor.
  CHECK(Regex("^bar$", Multiline).test("foo\nbar\nbaz"));
  CHECK(!Regex("^bar$").test("foo\nbar\nbaz"));

  // DotAll: '.' matches a newline only with the flag (or (?s)).
  CHECK(Regex("a.c", DotAll).test("a\nc"));
  CHECK(!Regex("a.c").test("a\nc"));
  CHECK(Regex("(?s)a.c").test("a\nc")); // inline (?s)
  CHECK(Regex("a.*c", DotAll).search("a\n\nc").str() == "a\n\nc");

  // Combined flags.
  CHECK(Regex("^a.b$", Multiline | DotAll).test("x\na\nb\ny"));
  CHECK(Regex("HELLO", IgnoreCase | DotAll).test("hello"));

  // Constructor flag and inline flag compose (both turn the flag on).
  CHECK(Regex("a(?i)bc", IgnoreCase).test("ABC"));
}

void test_find_all_and_replace() {
  auto ms = find_all(Regex("\\d+"), "a1 bb22 ccc333");
  CHECK(ms.size() == 3);
  if (ms.size() == 3) {
    CHECK(ms[0].str() == "1");
    CHECK(ms[1].str() == "22");
    CHECK(ms[2].str() == "333");
  }
  // captures preserved across many matches
  auto ms2 = find_all(Regex("(\\w)(\\d)"), "a1 b2 c3 d4");
  CHECK(ms2.size() == 4);
  if (ms2.size() == 4) {
    CHECK(ms2[0].group(1).str() == "a" && ms2[0].group(2).str() == "1");
    CHECK(ms2[3].group(1).str() == "d" && ms2[3].group(2).str() == "4");
  }
  // empty-match handling must still advance
  auto ms3 = find_all(Regex("a*"), "aXaa");
  CHECK(!ms3.empty());
  CHECK(Regex("\\d+").replace_all("a1 b22 c333", "#") == "a# b# c#");
  CHECK(Regex("(\\w+)@(\\w+)").replace_all("x@y", "$2.$1") == "y.x");
  CHECK(Regex("(?<g>\\d+)").replace_all("a12b", "[$<g>]") == "a[12]b");
  CHECK(Regex("o").replace_all("foo", "$$") == "f$$"); // $$ -> literal $
  // Unified $-grammar: $&, $`, $', multi-digit $10
  CHECK(Regex("b+").replace_all("abbc", "[$&]") == "a[bb]c"); // whole match
  CHECK(Regex("b+").replace_all("aXbbY", "<$`|$'>") ==
        "aX<aX|Y>Y"); // $` = before, $' = after
  CHECK(Regex("(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)")
            .replace_all("abcdefghij", "g10=$10") == "g10=j"); // two-digit
  // replace_first: only the leftmost
  CHECK(Regex("\\w+").replace_first("one two three", "X") == "X two three");
  CHECK(Regex("\\w+").replace_all("one two three", "X") == "X X X");

  // split: gaps between matches (N matches -> N+1 pieces)
  {
    auto collect = [](const Regex &re, const std::string &s) {
      std::vector<std::string> v;
      for (auto p : re.split(s))
        v.emplace_back(p);
      return v;
    };
    std::string s1 = "a,bb,,ccc";
    auto p1 = collect(Regex(","), s1);
    CHECK(p1.size() == 4 && p1[0] == "a" && p1[1] == "bb" && p1[2] == "" &&
          p1[3] == "ccc");
    std::string s2 = " the quick ";
    auto p2 = collect(Regex("\\s+"), s2);
    CHECK(p2.size() == 4 && p2[0] == "" && p2[1] == "the" && p2[2] == "quick" &&
          p2[3] == ""); // leading/trailing empties
    std::string s3 = "nomatch";
    auto p3 = collect(Regex("Z"), s3);
    CHECK(p3.size() == 1 && p3[0] == "nomatch"); // no match -> whole subject
    // early break really stops scanning
    Regex dash("-");
    std::string s4 = "p-q-r-s";
    int n = 0;
    for (auto p : dash.split(s4)) {
      (void)p;
      if (++n == 2) break;
    }
    CHECK(n == 2);
  }
}

void test_byte_offsets() {
  // é is two bytes in UTF-8, so the match starts at byte offset 2.
  auto m = Regex("café").search("a café here");
  CHECK(m);
  CHECK(m.begin() == 2);
  CHECK(m.str() == "café");
  CHECK(m.end() == m.begin() + std::string("café").size());
}

void test_grapheme_aware() {
  // A family emoji is one extended grapheme cluster (several code points).
  std::string family = "👨‍👩‍👧‍👦";
  CHECK(Regex(".").search(family).str() == family); // one '.' consumes it
  CHECK(Regex("^.$").search(family).str() == family);

  // base 'e' + combining acute is a single grapheme.
  std::string combined = "e\xCC\x81";
  CHECK(Regex("^.$").search(combined).str() == combined);

  // ".." consumes exactly two clusters.
  std::string two = family + family;
  CHECK(Regex("^..$").search(two).str() == two);
  CHECK(Regex(".").search(two).str() == family); // first cluster only

  // A character class matches a multi-code-point grapheme by its base code
  // point (Model 2): the family-emoji base is an emoji, not [a-z].
  CHECK(!Regex("[a-z]").test(family));

  // A Prepend (U+0600) fuses with what follows (GB9b) but not with a control
  // (GB5): `\t` after it starts a cluster of its own, which the fused literal
  // and class scans must not walk past.
  const std::string prepend = "\xD8\x80";
  auto at = [](const reg::MatchResult &m, size_t b, size_t e) {
    return m && m.begin() == b && m.end() == e;
  };
  CHECK(at(Regex("\\tab").search("xx" + prepend + "\tab"), 4, 7));
  CHECK(at(Regex("\\tab\\w*").search("xx" + prepend + "\tabc yy"), 4, 8));
  CHECK(at(Regex("\\w*\\tq").search("zz" + prepend + "\tq"), 4, 6));
  CHECK(at(Regex("[^ab]+[\t;][ab]").search("q " + prepend + "\ta"), 0, 6));
  // ... while U+0600 + `a` is one cluster, so no `ab` starts at the `a`.
  CHECK(!Regex("ab").test(prepend + "ab"));
  CHECK(Regex("b").search(prepend + "ab").begin() == 3);
}

// Regex::find_at(text, pos) is one stateless step of find_iter(): stepping it
// from 0 must visit exactly the same matches, and next_pos must follow the
// engine's empty-match advance rule (one grapheme in Grapheme mode / one code
// point in CodePoint mode) so an external stepper always progresses and never
// resumes mid-cluster.
void test_find_at() {

  // Non-empty match: next_pos == match end.
  {
    Regex re("b+");
    auto r = re.find_at("abba", 0);
    CHECK(r.m.matched() && r.m.begin() == 1 && r.m.end() == 3);
    CHECK(r.m.str() == "bb");
    CHECK(r.next_pos == 3);
    r = re.find_at("abba", 3);
    CHECK(!r.m.matched());
    CHECK(r.next_pos == 5); // size() + 1: no scan positions remain
  }

  // pos at / past end, empty text.
  {
    Regex star("a*");
    auto r = star.find_at("xy", 2); // empty match at end is still found
    CHECK(r.m.matched() && r.m.begin() == 2 && r.m.end() == 2);
    CHECK(r.next_pos == 3);
    CHECK(!star.find_at("xy", 3).m.matched());
    CHECK(star.find_at("xy", 3).next_pos == 3);
    r = star.find_at("", 0);
    CHECK(r.m.matched() && r.m.begin() == 0 && r.m.end() == 0);
    CHECK(r.next_pos == 1);
    CHECK(!Regex("a").find_at("", 0).m.matched());
  }

  // Empty matches over a combining sequence: "xéy" (é as e+◌́) has cluster
  // boundaries 0,1,4,5 — the resume never lands inside e+◌́.
  {
    Regex star("q*");
    std::string s = "xe\xCC\x81y";
    size_t pos = 0;
    std::vector<size_t> starts;
    while (pos <= s.size()) {
      auto r = star.find_at(s, pos);
      if (!r.m.matched()) break;
      starts.push_back(r.m.begin());
      pos = r.next_pos;
    }
    CHECK((starts == std::vector<size_t>{0, 1, 4, 5}));
  }

  // CR-LF fuses: "a\r\nb" scan positions are 0,1,3,4 — an empty match before
  // \r resumes after \n, never between them.
  {
    Regex star("q*");
    std::string s = "a\r\nb";
    auto r = star.find_at(s, 1);
    CHECK(r.m.matched() && r.m.begin() == 1 && r.m.end() == 1);
    CHECK(r.next_pos == 3);
  }

  // Grapheme vs CodePoint divergence on the same subject: e+◌́ is one step in
  // Grapheme mode, two in CodePoint mode.
  {
    std::string s = "e\xCC\x81";
    auto egc = make_egc("q*").find_at(s, 0);
    CHECK(egc.m.matched() && egc.next_pos == 3);
    auto us = make_us("q*").find_at(s, 0);
    CHECK(us.m.matched() && us.next_pos == 1);
    auto us2 = make_us("q*").find_at(s, 1);
    CHECK(us2.m.matched() && us2.m.begin() == 1 && us2.next_pos == 3);
  }

  // Regional-indicator pair: one cluster of 8 bytes in Grapheme mode, one
  // code point (4 bytes) per step in CodePoint mode.
  {
    std::string flag = "\xF0\x9F\x87\xAF\xF0\x9F\x87\xB5"; // 🇯🇵
    auto r = make_egc("q*").find_at(flag, 0);
    CHECK(r.m.matched() && r.next_pos == 8);
    auto us = make_us("q*").find_at(flag, 0);
    CHECK(us.m.matched() && us.next_pos == 4);
  }

  // find_at is a positioned scan of the full subject, not a search of the
  // suffix: ^ only matches at 0, and \b sees the real left context.
  {
    Regex caret("^a");
    CHECK(caret.find_at("aba", 0).m.matched());
    CHECK(!caret.find_at("aba", 2).m.matched());
    Regex wb("\\bx");
    CHECK(!wb.find_at("yx", 1).m.matched()); // y|x is not a word boundary
    CHECK(wb.find_at(" x", 1).m.matched());
  }

  // Captures and named groups come through the owning MatchResult.
  {
    Regex re(R"((\w+)=(?<val>\w+))");
    auto r = re.find_at("k1=v1 k2=v2", 5);
    CHECK(r.m.matched() && r.m.str() == "k2=v2");
    CHECK(r.m.group(1).str() == "k2");
    CHECK(r.m.group("val").str() == "v2");
    CHECK(r.next_pos == 11);
  }

  // Parity with find_iter across tiers: literal, alternation, asserts,
  // captures, nullable patterns, non-ASCII (grapheme Pike), CR-LF subjects,
  // and CodePoint mode.
  std::string prose;
  for (int i = 0; i < 8; i++)
    prose += "Sherlock said e\xCC\x81 to Holmes\r\nkey=value \xF0\x9F\x87\xAF"
             "\xF0\x9F\x87\xB5 done ";
  const char *pats[] = {"Holmes",        "Sherlock|value", "\\bkey\\b",
                        "(\\w+)=(\\w+)", "q*",             "\\w*",
                        "e?",            "said .*?Holmes", "(?:)"};
  for (const char *p : pats) {
    CHECK(same_as_iter(Regex(p), prose));
    CHECK(same_as_iter(make_us(p), prose));
  }
  CHECK(same_as_iter(Regex("a*"), std::string_view{}));
  CHECK(same_as_iter(Regex("^x", Multiline), "x\r\nx\nx"));

  // The FindCache overload steps identically while reusing warm DFAs.
  {
    Regex re("(\\w+)");
    Regex::FindCache cache;
    std::string s = "one two";
    auto r1 = re.find_at(s, 0, cache);
    CHECK(r1.m.matched() && r1.m.str() == "one" && r1.next_pos == 3);
    auto r2 = re.find_at(s, r1.next_pos, cache);
    CHECK(r2.m.matched() && r2.m.str() == "two" && r2.next_pos == 7);
    CHECK(!re.find_at(s, r2.next_pos, cache).m.matched());
  }
}

// The CRLF-tolerant byte path (analyze_crlf_byte_safe) must reproduce the
// grapheme engine on a non-ASCII subject containing CR-LF clusters. We compare
// find_all of the bare pattern (which may take the byte DFA) against the same
// pattern wrapped with an always-true zero-width assertion `(?:\b|\B)`, which
// forces the grapheme Pike VM (the oracle) over identical whole-match spans.
void test_crlf_byte_path() {
  const std::string q = "\xE2\x80\x9C"; // U+201C: forces the non-ASCII path
  // CR-LF appears between words, after words, and adjacent to the curly quote.
  std::string s;
  for (int i = 0; i < 50; i++)
    s += "the fox said " + q + "x" + q +
         " word Holmes\r\nfoo  Holmes here\r\n" +
         "Holmes\r\nWatson and a Holmes\r\n";
  auto same_as_pike = [&](const std::string &pat) {
    Regex bare(pat);
    Regex pike = pike_twin(pat);
    auto a = find_all(bare, s), b = find_all(pike, s);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end() ||
          a[i].str() != b[i].str())
        return false;
    return true;
  };
  // Byte-path-eligible (\s/[^] only in unbounded greedy repeats): must match
  // Pike.
  CHECK(same_as_pike("\\w+\\s+Holmes"));
  CHECK(same_as_pike("Holmes\\s+\\w+"));
  CHECK(same_as_pike("\\w+\\s+\\w+"));
  CHECK(same_as_pike("[^z]+Holmes")); // negated class matches \r and \n (both)
  CHECK(same_as_pike("\\w+(\\s+)Holmes")); // capture of the whole run is fine
  // Not byte-path-eligible (kept on the grapheme Pike): single \s, fixed count,
  // lazy, capture of the single repeated atom. Still must equal Pike
  // (trivially, both ARE the Pike, but this guards the routing decision either
  // way).
  CHECK(same_as_pike("Holmes\\sWatson"));
  CHECK(same_as_pike("Holmes\\s{2}Watson"));
  CHECK(same_as_pike("\\w+\\s+?Holmes"));
  CHECK(same_as_pike("(\\s)+Holmes"));
  CHECK(same_as_pike("Holmes\\r\\nWatson")); // literal \r\n

  // CRLF-collapse: bounded / lazy negated classes that match BOTH \r and \n are
  // not crlf_byte_safe, but the byte programs are rebuilt over the collapsed AST
  // (a CR-LF pair counts as one element) so they take the byte DFA on this
  // paired-CRLF subject and must still equal the grapheme Pike.
  CHECK(same_as_pike("[^z]{13}x"));      // bounded exact count over CR-LF
  CHECK(same_as_pike("[^z]{2,8}o"));     // bounded range
  CHECK(same_as_pike("[^aeiou]+?Holmes")); // lazy +?
  CHECK(same_as_pike("[^ ]{4}"));        // negated space matches \r and \n
  CHECK(same_as_pike("w[^z]{0,20}d"));   // optional bounded with literal anchors
  // Captures with a bounded \r\n-class repeat are gated OUT of the collapse path
  // (resolved on the code-point program); the whole-match span must still equal
  // Pike — a dropped match would change the count.
  CHECK(same_as_pike("([^z]{13})(x)"));
  CHECK(same_as_pike("(w)([^z]{0,20})(d)"));

  // A lone CR or LF disqualifies the collapse path (the pair is consumed
  // atomically; a lone one would be unmatchable). The engine must fall back to
  // the grapheme Pike and still agree.
  auto same_on = [&](const std::string &subj, const std::string &pat) {
    Regex bare(pat);
    Regex pike = pike_twin(pat);
    auto a = find_all(bare, subj), b = find_all(pike, subj);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end() ||
          a[i].str() != b[i].str())
        return false;
    return true;
  };
  const std::string q2 = "\xE2\x80\x9C"; // forces non-ASCII
  CHECK(same_on(q2 + "ab\rcd ef\rgh", "[^z]{3}")); // lone CR
  CHECK(same_on(q2 + "ab\ncd ef\ngh", "[^z]{3}")); // lone LF
  CHECK(same_on(q2 + "a\r\nb\rc\r\nd", "[^z]{2,5}")); // mixed paired + lone CR
  // no_lone_crlf is a SIMD pass over 16-byte blocks with a cross-block CR carry;
  // place paired and lone CR/LF straddling the block boundary so the carry
  // (a CR in the last lane expecting an LF in the next block's first lane) is
  // exercised in both the valid and the disqualifying direction.
  for (int pad = 12; pad <= 20; pad++) {
    std::string base(static_cast<size_t>(pad), 'a');
    CHECK(same_on(q2 + base + "\r\n" + base, "[^z]{2,6}")); // pair across boundary
    CHECK(same_on(q2 + base + "\r" + base, "[^z]{2,6}"));   // lone CR across
    CHECK(same_on(q2 + base + "\n" + base, "[^z]{2,6}"));   // lone LF across
  }
  // CRLF-collapse + ReverseInner: a match that BEGINS on a CR-LF cluster (the
  // class consumes the pair, then a rare interior literal). The byte path's
  // inner prefilter is skipped here (its pre-reverse is non-collapsed and would
  // floor mid-cluster), so the unfiltered collapsed scan must still find it.
  // Oracle = trailing always-true lookahead (grapheme Pike). ASCII (byte path
  // via contains_crlf) and non-ASCII subjects both covered.
  auto same_la2 = [&](const std::string &subj, const std::string &pat) {
    Regex bare(pat), pike = pike_twin(pat);
    auto a = find_all(bare, subj), b = find_all(pike, subj);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end()) return false;
    // lazy scan must match the eager find_all, and search the first match
    std::vector<std::pair<size_t, size_t>> sc;
    for (auto m : bare.find_iter(subj)) sc.emplace_back(m.begin(), m.end());
    if (sc.size() != a.size()) return false;
    auto sr = bare.search(subj);
    return sr.matched() == !a.empty() &&
           (a.empty() || (sr.begin() == a[0].begin() && sr.end() == a[0].end()));
  };
  CHECK(same_la2("BAB\r\nc_2 bb", "[^c-zbb]ca*"));   // match begins on \r\n
  CHECK(same_la2(q2 + "ab\r\nz cd z ef", "[^x]z[^y]+")); // non-ASCII + cluster
  CHECK(same_la2("x\r\nq\r\nqy", "[^q]q[^q]*"));     // multiple cluster-initial
  CHECK(same_la2(" c\rA\rc\rCcC2", "[^c]{2,3}c[c-zc-za]?")); // lone CR -> ASCII tier

  // ASCII-CRLF grapheme consistency: a CR-LF is ONE cluster on a PURE-ASCII
  // subject too (segment() fuses it; the fast paths defer to the grapheme engine
  // via ascii_grapheme_ok unless CRLF-insensitive). Oracle = a trailing always-
  // true LOOKAHEAD, which is neither DFA-able nor a plain assert, so it runs the
  // grapheme Pike VM even on ASCII (unlike \b|\B, which takes the byte assert
  // tier). Pins ASCII == the documented grapheme model — and that `.`-proximity
  // patterns stay on the byte DFA (non-dotall `.` excludes \r\n, so it is
  // CRLF-safe; only nullable / dotall-bounded patterns defer to the Pike).
  auto same_la = [&](const std::string &subj, const std::string &pat) {
    Regex bare(pat);
    Regex pike = pike_twin(pat); // lookahead -> Pike VM
    auto a = find_all(bare, subj), b = find_all(pike, subj);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end() ||
          a[i].str() != b[i].str())
        return false;
    return bare.test(subj) == (b.size() > 0);
  };
  const std::string ac = "\"a\r\nb\" x \"qq\" \"y\r\nz\r\nw\" end\r\n";
  CHECK(same_la(ac, "[\"][^\"]{0,3}[\"]"));   // bounded negated class over CRLF
  CHECK(same_la(ac, "[^ ]{4}"));              // negated space (matches \r,\n)
  CHECK(same_la(ac, "[^z]{2,5}"));            // bounded range
  CHECK(same_la(ac, "([\"])([^\"]{0,3})([\"])")); // captures
  CHECK(same_la("Holmes ab\r\ncd Watson z", "Holmes.{0,25}Watson")); // . stays fast+correct
  CHECK(same_la("x\r\ny\r\nz", "."));         // non-dotall . skips the CR-LF
  CHECK(same_la("a1\r\nb2\r\nc", "(?s)a.{0,4}c")); // dotall . spans the cluster
  CHECK(same_la("ab\r\ncd ef\r\ngh", "[^z]+")); // unbounded greedy (byte path)
  CHECK(same_la("p\r\nq\r\nr", "\\s{1,2}"));  // bounded \s
  // Explicit: the canonical case that was code-point (wrong) on ASCII before.
  CHECK(find_all(Regex("[\"][^\"]{0,3}[\"]"), "\"a\r\nb\"").size() == 1);

  // A pattern whose only CR-LF touch is a PAIRED `\r\n` literal is CRLF-byte-safe
  // (the byte DFA matches the cluster's two bytes exactly), so it runs the fast
  // byte path on a CR-LF subject instead of the grapheme Pike — INCLUDING the
  // pure-ASCII case (the httplib status line). Must equal the Pike, captures too.
  CHECK(same_la("a\r\nb\r\nc", "\\r\\n")); // bare paired CRLF
  CHECK(same_la("HTTP/1.1 200 OK\r\n", R"((HTTP/1\.[01]) (\d{3})(?: (.*?))?\r\n)"));
  {
    Regex sl(R"((HTTP/1\.[01]) (\d{3})(?: (.*?))?\r\n)"); // EGC, capture spans
    auto m = sl.search("HTTP/1.1 200 OK\r\n");
    CHECK(m.matched() && m.begin() == 0 && m.end() == 17);
    CHECK(m.group(1).str() == "HTTP/1.1" && m.group(2).str() == "200" &&
          m.group(3).str() == "OK");
  }
  // A Prepend / combining mark right before the CR breaks the cluster (GB5), so
  // the `\r\n` literal still matches the [\r\n] cluster — the fused-prefix scan's
  // grapheme walk must not over-run it. \xd8\x80 = Prepend U+0600.
  CHECK(same_la("\xd8\x80\r\nx", "\\r\\n"));
  CHECK(same_la("a\xcc\x81\r\nb\xd8\x80\r\n", "\\r\\n"));
}

// Two CR-LF RUNS side by side (an unbounded greedy class repeat that matches
// both `\r` and `\n` is the one consumer the byte tiers let touch a CR-LF
// pair): a byte program can end the first on the `\r` and begin the second on
// the `\n`, a boundary the grapheme engine does not have. Such a pattern is
// not CRLF-byte-safe. All of these were wrong on the released engine — a
// match that needs the pair twice, a group that closes inside it — on ASCII
// subjects too, where a `(?:\b|\B)` reference runs on an assert tier behind
// the same gate; the reference here is a lookahead, which nothing but the
// Pike serves, and the spans are asserted outright.
void test_crlf_adjacent_runs() {
  using Row = std::vector<std::pair<long, long>>; // every group of every match
  auto rows = [](const Regex &re, const std::string &subj) {
    Row v;
    for (auto &m : find_all(re, subj))
      for (size_t g = 0; g <= m.group_count(); g++) {
        auto c = m.group(g);
        v.emplace_back(c.matched() ? static_cast<long>(c.begin()) : -1,
                       c.matched() ? static_cast<long>(c.end()) : -1);
      }
    return v;
  };
  auto iter_rows = [](const Regex &re, const std::string &subj) {
    Row v;
    for (auto m : re.find_iter(subj))
      for (size_t g = 0; g <= m.group_count(); g++) {
        auto c = m.group(g);
        v.emplace_back(c.matched() ? static_cast<long>(c.begin()) : -1,
                       c.matched() ? static_cast<long>(c.end()) : -1);
      }
    return v;
  };
  const std::string e = "\xc3\xa9"; // é: the non-ASCII byte tiers
  struct { const char *pat; std::string subj; Row want; } cases[] = {
      // One cluster cannot feed two `+` (was [0,4) on both subjects).
      {"t[^.]+[^q]+\\.", "t\r\n.", {}},
      {"t[^.]+[^q]+\\.", "t\r\n." + e, {}},
      {"t([^.]+)[^q]+\\.", "t\r\n." + e, {}},
      {"t[^.]+[^q]+\\.", "t\r\n\r\n.", {{0, 6}}},
      // The group closes on a cluster boundary (was [1,2) / [3,4)).
      {"[A-Z]([^.]*)[^.]+,", "Z\r\n,", {{0, 4}, {1, 1}}},
      {"[A-Z]([^.]*)[^.]+,", e + "Z\r\n,", {{2, 6}, {3, 3}}},
      {"s\\s+(\\s+)[^.]*q", "s \r\n\r\nq " + e, {{0, 7}, {4, 6}}},
      {"([^.]*)\\s+\\.", "a\r\n. b \r\n.", {{0, 4}, {0, 1}, {4, 10}, {4, 7}}},
      // Across an element that can match empty.
      {"t[^.]+x?[^q]+\\.", "t\r\n.", {}},
      // A single run is still byte-safe, and still right.
      {"t[^.]+x", "t\r\nx t\r\n\r\nx", {{0, 11}}},
      {"\\w+(\\s+)Holmes", "a\r\n\r\nHolmes", {{0, 11}, {1, 5}}},
  };
  for (auto &c : cases) {
    Regex re(c.pat);
    Regex pike = pike_twin(c.pat);
    CHECK(rows(re, c.subj) == c.want);
    CHECK(iter_rows(re, c.subj) == c.want);
    CHECK(rows(pike, c.subj) == c.want);
    auto m = re.search(c.subj);
    CHECK(m.matched() == !c.want.empty());
    if (m.matched() && !c.want.empty())
      CHECK(static_cast<long>(m.begin()) == c.want[0].first &&
            static_cast<long>(m.end()) == c.want[0].second);
    CHECK(re.test(c.subj) == !c.want.empty());
  }
}

// Required-suffix-literal prefilter: a pattern that begins with a class/`.` (no
// literal prefix to skip on) but ends with a fixed ASCII literal after a
// fixed-length body is found by memmem-ing the rare suffix and reverse-DFA
// verifying each candidate — across find_all / matches / scan / search and on
// ASCII, CRLF and non-ASCII subjects. Must equal the grapheme Pike (forced via a
// trailing always-true lookahead) AND the eager matches() must equal lazy scan().
void test_suffix_prefilter() {
  auto ok = [](const std::string &subj, const std::string &pat) {
    Regex bare(pat);
    Regex pike = pike_twin(pat); // lookahead -> grapheme Pike
    auto a = find_all(bare, subj), b = find_all(pike, subj);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end() ||
          a[i].str() != b[i].str())
        return false;
    // scan (no prefilter) must agree with find_all/matches (prefilter), and
    // search must find the first match's span.
    std::vector<std::pair<size_t, size_t>> sc;
    for (auto m : bare.find_iter(subj)) sc.emplace_back(m.begin(), m.end());
    if (sc.size() != a.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (sc[i].first != a[i].begin() || sc[i].second != a[i].end()) return false;
    auto sr = bare.search(subj);
    if (sr.matched() != (!a.empty())) return false;
    if (!a.empty() && (sr.begin() != a[0].begin() || sr.end() != a[0].end()))
      return false;
    return true;
  };
  // Build subjects: pure ASCII, ASCII+CRLF, and non-ASCII (ñ forces the egc
  // byte path); each repeated so there are many candidates and matches.
  std::string base = "the most extreme zone; quartz fox by qwx; ";
  std::string ascii, acrlf, nonascii = "\xc3\xb1";
  for (int i = 0; i < 60; i++) {
    ascii += base;
    acrlf += base + "\r\n";
    nonascii += base + "\r\n";
  }
  for (const std::string &s : {ascii, acrlf, nonascii}) {
    CHECK(ok(s, "[a-q][^u-z]{13}x")); // the standard bench pattern
    CHECK(ok(s, "[^z]{13}x"));        // dense suffix occurs inside the body too
    CHECK(ok(s, "[a-z]{2}x"));        // short fixed body
    CHECK(ok(s, "..t"));              // `.` body + literal suffix
    CHECK(ok(s, "[a-q][^u-z]{3}zone")); // multi-char suffix
    CHECK(ok(s, "q[a-z]{2}rtz"));     // suffix appears, body fixed
    // Variable-length pre-suffix (rure ReverseSuffix): the reverse scan finds
    // the start, a forward re-expansion takes the greedy leftmost-first end.
    CHECK(ok(s, "[a-z]+x"));     // unbounded greedy body + literal suffix
    CHECK(ok(s, "[a-z]*x"));     // nullable body (a lone suffix matches)
    CHECK(ok(s, "[a-z]+zone"));  // multi-char suffix, unbounded body
    CHECK(ok(s, "[a-z]{2,}rtz")); // {n,} body
    CHECK(ok(s, "[a-q][^u-z]+x")); // unbounded negated-class body
  }
  // US (UnicodeScalar) mode now shares the suffix/ReverseInner literal prefilter
  // (it ran a naked byte-DFA scan before). On a pure-ASCII subject US must equal
  // EGC exactly; the US prefilter result must also match the prefilter-free US
  // reference (a trailing always-true lookahead makes the pattern assert-tier,
  // bypassing byte_suffix_/byte_inner_).
  {
    auto ok_us = [](const std::string &subj, const std::string &pat) {
      auto a = make_us(pat).find_all(subj);
      auto ref = make_us("(?:" + pat + ")(?=[\\s\\S]|$)").find_all(subj);
      auto eg = make_egc(pat).find_all(subj);
      if (a.size() != ref.size() || a.size() != eg.size()) return false;
      for (size_t i = 0; i < a.size(); i++)
        if (a[i].begin() != ref[i].begin() || a[i].end() != ref[i].end() ||
            a[i].begin() != eg[i].begin() || a[i].end() != eg[i].end())
          return false;
      auto sr = make_us(pat).search(subj);
      if (sr.matched() != (!a.empty())) return false;
      if (!a.empty() && (sr.begin() != a[0].begin() || sr.end() != a[0].end()))
        return false;
      return true;
    };
    for (const char *pat : {"[a-q][^u-z]{13}x", "[a-z]+ing", "[a-q][^u-z]+x",
                            "[a-c].\\w+end", "\\w+ Holmes \\w+"})
      CHECK(ok_us(ascii, pat)); // suffix + ReverseInner, US == EGC on ASCII
  }
  // Greedy/overlapping suffix subjects: the suffix literal occurs INSIDE the
  // greedy match (e.g. "ing" twice in "singing"), where trusting the first
  // occurrence as the end would mis-report a short match — the forward
  // re-expansion must take the longest greedy end.
  std::string greedy =
      "singing stringing aaaaing bing ing endend 22end singinging zzz";
  for (const char *p : {"[a-zA-Z]+ing", "[a-z]*ing", "[0-9]*end", "[a-z]+x"})
    CHECK(ok(greedy, p));
  // A literal prefix in front of the suffix (which of the two drives is
  // test_anchor_choice's subject), still equal to the Pike.
  CHECK(ok(ascii, "fox[a-z]{2}"));
  CHECK(ok(acrlf, "the[^z]{0,9}zone"));
  // search() on a CRLF-collapse plan: its suffix rung runs the COLLAPSED byte
  // programs, whose classes count a CR-LF pair as one element, and the scalar
  // verifier counted bytes — so a pair inside the fixed-width body shifted
  // the start (or lost the match), in search() alone: find_all and find_iter
  // take the fused tier, which told the verifier. Wrong on the released
  // engine (`none` and `[2,5)`).
  {
    auto first = [](const char *pat, const std::string &subj) {
      auto m = Regex(pat).search(subj);
      return m.matched() ? std::make_pair(m.begin(), m.end())
                         : std::make_pair(size_t(0), size_t(0));
    };
    CHECK(first("[a-c][^q]{2}q", "a\r\naa \r\nq") == std::make_pair(size_t(4), size_t(9)));
    CHECK(first("[^.]{2}\\.", "\r\n\r\n.@") == std::make_pair(size_t(0), size_t(5)));
    CHECK(first("[^.]{2}\\.", "\xc3\xa9 \r\n\r\n.") ==
          std::make_pair(size_t(3), size_t(8)));
    for (const char *pat : {"[a-c][^q]{2}q", "[^.]{2}\\.", "[^z]{3}x",
                            "[a-q][^u-z]{3}x", "e[^q]{2}q"})
      for (const std::string &subj :
           {std::string("a\r\naa \r\nq e\r\n\r\nq x\r\n.\r\n\r\n.ab\r\nx"),
            std::string("\xc3\xb1 a \r\nq\r\n\r\n.e \r\nq ab\r\n\r\nx")})
        CHECK(ok(subj, pat));
  }
}

// ReverseInner prefilter (rure): a rare literal strictly inside a class-led /
// class-tailed pattern (no usable prefix or suffix). memmem the interior
// literal, recover the start via a reverse DFA over the pre part, then take the
// greedy leftmost-first end from the full forward DFA seeded at that start. Same
// oracle as the suffix test: bare (prefilter) vs grapheme Pike (lookahead, no
// prefilter) vs scan, on ASCII / CRLF / non-ASCII subjects.
void test_inner_prefilter() {
  auto ok = [](const std::string &subj, const std::string &pat) {
    Regex bare(pat);
    Regex pike = pike_twin(pat); // lookahead -> grapheme Pike
    auto a = find_all(bare, subj), b = find_all(pike, subj);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end() ||
          a[i].str() != b[i].str())
        return false;
    std::vector<std::pair<size_t, size_t>> sc;
    for (auto m : bare.find_iter(subj)) sc.emplace_back(m.begin(), m.end());
    if (sc.size() != a.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (sc[i].first != a[i].begin() || sc[i].second != a[i].end()) return false;
    auto sr = bare.search(subj);
    if (sr.matched() != (!a.empty())) return false;
    if (!a.empty() && (sr.begin() != a[0].begin() || sr.end() != a[0].end()))
      return false;
    return true;
  };
  std::string base =
      "said Holmes to Watson; user@host.net; a-b-c; the cat sat on a mat; ";
  std::string ascii, acrlf, nonascii = "\xc3\xb1"; // ñ forces the egc byte path
  for (int i = 0; i < 50; i++) {
    ascii += base;
    acrlf += base + "\r\n";
    nonascii += base + "\r\n";
  }
  for (const std::string &s : {ascii, acrlf, nonascii}) {
    CHECK(ok(s, "\\w+ Holmes \\w+"));    // interior literal, \w+ both sides
    CHECK(ok(s, "\\w+@\\w+"));           // single-char interior literal
    CHECK(ok(s, "[a-z]+ sat [a-z]+"));   // interior literal " sat "
    CHECK(ok(s, "[a-z]+-[a-z]+-[a-z]+")); // two interior literals (pick rarest)
    CHECK(ok(s, "\\w+ Watson \\w+"));    // 0 matches here -> must skip cheaply
    // Greedy pre that can ABSORB the interior literal (the seed is not the end):
    CHECK(ok(s, ".{2,}t"));              // `.` greedy + 't' (recurs in the text)
    CHECK(ok(s, ".{2,}at[a-z]*"));       // absorbable interior + greedy tail
    CHECK(ok(s, "[a-z]{2,}o[a-z]+"));    // interior 'o' inside greedy classes
  }
  // A pre that can absorb the literal AND has gaps in its lengths (a repeat
  // of more than one code point, an optional group): an absorbed occurrence's
  // reverse(pre) can succeed from a floor RIGHT of the leftmost match's start
  // — with the empty pre, here — and the scan from that floor never sees the
  // match. Such a pre is not driven from its interior literal. Both were
  // wrong on the released engine (`[1,2) [2,3)` and `[1,4)`).
  {
    auto spans = [](const Regex &re, const std::string &subj) {
      std::vector<std::pair<size_t, size_t>> v;
      for (auto &m : find_all(re, subj)) v.emplace_back(m.begin(), m.end());
      return v;
    };
    using V = std::vector<std::pair<size_t, size_t>>;
    CHECK(spans(Regex("(?:..)*=x*"), "a==") == (V{{0, 3}}));
    CHECK(spans(make_us("(?:..)*=x*"), "a==") == (V{{0, 3}}));
    CHECK(spans(Regex("(?:[^\\n]+[a-z]{1,2})?=(e{0,3})"), "@=n=") ==
          (V{{0, 4}}));
    CHECK(Regex("(?:..)*=x*").search("a==").end() == 3);
    for (const std::string &s : {ascii, acrlf, nonascii}) {
      CHECK(ok(s, "(?:..)*@x*"));              // multi-code-point repeat pre
      CHECK(ok(s, "(?:[^\\n]+[a-z]{1,2})?-(c?)")); // optional group pre
      CHECK(ok(s, "(?:.[a-z])*-[a-z]"));
      CHECK(ok(s, ".{2,}-c\\d?"));             // step-1 pre: still driven
    }
  }
}

// Which literal anchor drives the find is chosen by estimated cost, not by
// position (Plan::AnchorChoice). Two halves: the choice itself, pinned
// through the plan; and the results of every pattern whose driving anchor is
// one it could not have had before — a suffix or an interior literal behind a
// literal prefix, a prefix in front of an assert-tier suffix — against the
// grapheme Pike, on ASCII / CRLF / non-ASCII subjects and in CodePoint mode.
void test_anchor_choice() {
  auto anchor = [](const char *pat) { return PlanProbe::anchor(Regex(pat)); };

  // --- DFA tiers: prefix vs suffix ---
  // A common letter in front of a rare suffix: the suffix drives.
  CHECK(anchor("e[a-z]{3,}q") == 'S');
  CHECK(anchor("a.{16}z") == 'S');
  CHECK(anchor("a[^.]*\\!") == 'S');
  CHECK(anchor("s[a-z]*\\?") == 'S');
  CHECK(anchor("t[a-z]+ing") == 'S');
  CHECK(anchor("the\\s+\\w+ly") == 'S');
  // A rare prefix keeps the find, whatever follows.
  CHECK(anchor("Sherlock\\s+Holmes") == 'P');
  CHECK(anchor("S[a-z]+\\.") == 'P'); // `.` is five times as common as `S`
  CHECK(anchor("H[a-z]+s") == 'P');
  CHECK(anchor("z[a-z]+e") == 'P');
  CHECK(anchor("T[a-z]+k") == 'P'); // both sparse: the incumbent stays
  // Both dense: no anchor is worth a verify per occurrence.
  CHECK(anchor("e[a-z]+s") == '-');
  CHECK(anchor("a[a-z]*e") == '-');
  // --- class-led: suffix / interior literal vs the start set ---
  CHECK(anchor("[a-q][^u-z]{13}x") == 'S');
  CHECK(anchor("[a-zA-Z]+ing") == 'S');
  CHECK(anchor("[a-z]+e") == 'S');      // dense, but so is the start set
  CHECK(anchor("[A-Z]\\w+ the") == 'S');
  CHECK(anchor("[A-Z][a-z]+s") == '-'); // a capital is rarer than an `s`
  CHECK(anchor("\\w+ Holmes \\w+") == 'I');
  CHECK(anchor("\\w+@\\w+") == 'I');
  // --- the interior literal against the other two ---
  CHECK(anchor("a\\w+@\\w+") == 'I');  // behind a dense prefix
  CHECK(anchor("\\w+@\\w+e") == 'I');  // in front of a dense suffix
  CHECK(anchor("\\w+e\\w+@") == 'S');  // ... and behind a rare one
  CHECK(anchor("Mr\\w+e\\w+") == 'P'); // a rare prefix beats a dense interior
  // --- captures keep the order the capture drivers assume ---
  CHECK(anchor("e(\\w+)q") == 'P');
  CHECK(anchor("(\\w+)=(\\S+)") == 'I');
  // --- CodePoint mode chooses the same way ---
  CHECK(PlanProbe::anchor(make_us("e[a-z]{3,}q")) == 'S');
  CHECK(PlanProbe::anchor(make_us("Sherlock\\s+Holmes")) == 'P');
  CHECK(PlanProbe::anchor(make_us("a\\w+@\\w+")) == 'I');
  // --- assert tiers: leading vs trailing literal ---
  CHECK(anchor("Sherlock [a-z]+e\\b") == 'P');
  CHECK(anchor("H[a-z]+s\\b") == 'P');
  CHECK(anchor("z[a-z]*e$") == 'P');
  CHECK(anchor("(?m)^The [a-z]+ of") == 'P');
  CHECK(anchor("t[a-z]+ly\\b") == 'S');
  CHECK(anchor("\\bthe [a-z]+q\\b") == 'S');
  CHECK(anchor("(?m)e[a-z]+\\.$") == 'S');
  CHECK(anchor("\\b\\w+ing\\b") == 'S'); // the word-suffix shape
  CHECK(anchor("\\bt[a-z]+") == 'P'); // dense, and the assert scan has no skip
  // The word scan runs behind an anchor priced below it, in front otherwise.
  CHECK(PlanProbe::word_scan_after_anchor(Regex("\\bq[a-z]+e\\b")));
  CHECK(PlanProbe::word_scan_after_anchor(Regex("\\bthe [a-z]+q\\b")));
  CHECK(!PlanProbe::word_scan_after_anchor(Regex("\\be[a-z]+s\\b")));
  // ... as the scan's pace prices it (kWordScanNs, which these two pin): a
  // letter one byte in a hundred is already dearer to stop at than the scan
  // is to run.
  CHECK(PlanProbe::word_scan_after_anchor(Regex("\\bj[a-z]+\\b")));
  CHECK(PlanProbe::word_onepass(Regex("\\bk[a-z]+\\b")) &&
        !PlanProbe::word_scan_after_anchor(Regex("\\bk[a-z]+\\b")));
  CHECK(!PlanProbe::word_scan_after_anchor(
      Regex("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b")));

  // The record says why: each anchor the pattern offers has a cost, the one
  // chosen is the cheapest by the rule, and an anchor not offered has none.
  {
    const auto &c = PlanProbe::choice(Regex("e[a-z]{3,}q"));
    CHECK(c.prefix_cost > 0 && c.suffix_cost > 0);
    CHECK(c.suffix_cost * 2 <= c.prefix_cost);
    CHECK(c.inner_cost == PlanProbe::Choice::kNone);
    const auto &d = PlanProbe::choice(Regex("Sherlock\\s+Holmes"));
    CHECK(d.prefix_cost > 0 && d.suffix_cost > 0);
    CHECK(d.suffix_cost * 2 > d.prefix_cost);
    const auto &e = PlanProbe::choice(Regex("[A-Z][a-z]+s"));
    CHECK(e.prefix_cost == PlanProbe::Choice::kNone);
    CHECK(e.scan_cost > 0 && e.scan_cost < e.suffix_cost);
  }

  // What the lazy DFA's start state skips with. Teddy, where the pattern
  // has one — an alternation of literals, whatever follows it, in either
  // mode (the fingerprints are read off the program the plan runs: a
  // CodePoint plan's are the bytes of its byte program). Else the
  // first-byte set, when it is RARE as well as small: capitals are worth
  // jumping to, and the first letters of common words stop the jump every
  // few bytes, where stepping the DFA is the faster way through.
  {
    const char *names =
        "Sherlock|Holmes|Watson|Irene|Adler|John|Baker|Street|London";
    const char *words = "return|while|for|if|else|switch|case|break|continue";
    for (const char *pat : {names, words, "(?:fox|dog|cat)s?",
                            "(?:the|and|for)s?", "(?:Xavier|Zulu)s?"}) {
      CHECK(PlanProbe::start_skip(Regex(pat), false) == 'T');
      CHECK(PlanProbe::start_skip(Regex(pat), true) == 'T');
      CHECK(PlanProbe::start_skip(make_us(pat), true) == 'T');
    }
    for (const char *pat : {names, words}) {
      CHECK(PlanProbe::start(Regex(pat), false) == 'A');
      CHECK(PlanProbe::start(make_us(pat), false) == 'A');
    }
    CHECK(PlanProbe::start_skip(Regex("Sherlock\\s+Holmes"), true) == 'P');
    // A CodePoint plan's fingerprints are bytes, so a literal need not be
    // ASCII there; a Grapheme plan's are one-byte clusters. (The
    // alternation tier's literals are printable ASCII in both.)
    CHECK(PlanProbe::teddy(make_us("\xC3\xA9t\xC3\xA9|\xC3\xBC" "ber")).ok);
    CHECK(!PlanProbe::teddy(Regex("\xC3\xA9t\xC3\xA9|\xC3\xBC" "ber")).ok);
    CHECK(PlanProbe::start(make_us("\xC3\xA9t\xC3\xA9|\xC3\xBC" "ber"), false) !=
          'A');
    // A range is not a fixed byte, in either program. A class of a few
    // single bytes is a choice between them in the byte program, and reads
    // as one: `dox`, `fox`, `cat`.
    CHECK(!PlanProbe::teddy(make_us("[a-f]ox|cat")).ok);
    CHECK(!PlanProbe::teddy(Regex("[fd]ox|cat")).ok);
    CHECK(PlanProbe::teddy(make_us("[fd]ox|cat")).ok);
    CHECK(PlanProbe::start(make_us("[fd]ox|cat"), false) != 'A');
    CHECK(!PlanProbe::teddy(make_us("fox|dogs", IgnoreCase)).ok);
    // A length the shortest literal turns down leaves nothing behind for
    // the next one tried.
    for (const Regex &re : {Regex("abcd|ab"), make_us("abcd|ab")})
      CHECK(PlanProbe::teddy(re).ok && PlanProbe::teddy(re).count() == 1);
    CHECK(PlanProbe::start_skip(Regex("[A-Z][a-z]+s"), false) == 'F');
    CHECK(PlanProbe::start_skip(Regex("[aeiou][a-z]+s"), false) == '-');
    // How common a set may be depends on how the skip scans for it: a set
    // of a few bytes is a SIMD compare per member, and is worth jumping to
    // where a larger one — a table lookup per subject byte — is not. Three
    // first letters at ~9% of prose still pay; at ~20% they do not.
    CHECK(PlanProbe::start_skip(make_us("[fdc][a-z]+"), true) == 'F');
    CHECK(PlanProbe::start_skip(make_us("[taf][a-z]+"), true) == '-');
    CHECK(PlanProbe::start_skip(make_us("[bfgkpvjq][a-z]+"), true) == 'F');
    CHECK(PlanProbe::start_skip(make_us("[bcdfgmpw][a-z]+"), true) == '-');
    // The walk's scan asks only that the set be small — a walk costs more
    // to start than a DFA step — and takes Teddy ahead of it as well; a
    // prefix is a driver of its own there, never this scan's.
    CHECK(PlanProbe::walk_skip(make_us("[taf][a-z]+"), true) == 'F');
    CHECK(PlanProbe::walk_skip(Regex("[aeiou][a-z]+s"), false) == 'F');
    CHECK(PlanProbe::walk_skip(Regex("[aeiou][a-z]+s"), true) == 'F');
    CHECK(PlanProbe::walk_skip(make_us("[a-z]+s"), true) == 'F');
    CHECK(PlanProbe::walk_skip(make_us("\\w+s"), true) == '-');
    CHECK(PlanProbe::walk_skip(make_us("[aeiou]n"), true) == 'T');
    for (bool byte : {false, true}) {
      CHECK(PlanProbe::walk_skip(Regex("(?:fox|dog|cat)s?"), byte) == 'T');
      CHECK(PlanProbe::walk_skip(Regex("Sherlock\\s+Holmes"), byte) != 'P');
    }
    // Each program family by its own set: ASCII letters are few, the lead
    // bytes of everything past ASCII are not.
    CHECK(PlanProbe::walk_skip(Regex("[a-z\\x{80}-\\x{10FFFF}]+\\d"), false) ==
          'F');
    CHECK(PlanProbe::walk_skip(Regex("[a-z\\x{80}-\\x{10FFFF}]+\\d"), true) ==
          '-');
    // Either way the matches are the Pike's.
    const std::string s = "if Holmes and Watson return to Baker Street while "
                          "John waits in London, break the case; caf\xc3\xa9 "
                          "for Irene, else Adler continues";
    for (const char *pat : {names, words}) {
      const auto want = flat_spans(pike_twin(pat), s, /*lazy=*/false);
      CHECK(want.size() >= 12);
      CHECK(finds_agree(Regex(pat), want, s));
      CHECK(finds_agree(make_us(pat), want, s));
    }
    // ... and where the modes differ, each mode's own. A literal's bytes
    // next to a combining mark (after) or a Prepend (before) are part of a
    // longer cluster — no match — and code points of their own in
    // CodePoint mode, where the alternation tier takes the bytes as they
    // are. So does a byte literal's start skip.
    const std::string marks = "fox\xCC\x81 dog \xD8\x80" "cat fox, "
                              "caf\xC3\xA9s na\xC3\xAFve\xCC\x81 fo";
    auto cp_pike = [](const std::string &pat) {
      return pike_twin(pat, 0, reg::MatchUnit::CodePoint);
    };
    for (const char *pat : {"fox", "(cat)", "fo",
                            "fox|dog|cat", "(fox|dog|cat)", "[fd]o[xg]|cat",
                            "(?:caf\xC3\xA9|na\xC3\xAFve|fox)s?"}) {
      const auto want = flat_spans(cp_pike(pat), marks, false);
      CHECK(finds_agree(make_us(pat), want, marks));
      CHECK(finds_agree(Regex(pat), flat_spans(pike_twin(pat), marks, false),
                        marks));
    }
    CHECK(flat_spans(make_us("fox|dog|cat"), marks, false) ==
          (std::vector<size_t>{0, 3, 6, 9, 12, 15, 16, 19}));
    CHECK(flat_spans(Regex("fox|dog|cat"), marks, false) ==
          (std::vector<size_t>{6, 9, 16, 19}));
    CHECK(flat_spans(make_us("fox"), marks, false) ==
          (std::vector<size_t>{0, 3, 16, 19}));
    CHECK(flat_spans(Regex("fox"), marks, false) ==
          (std::vector<size_t>{16, 19}));
    // The one-pass walk's position scan takes its candidates from the
    // same searcher: a literal behind optional bytes (either mode), behind
    // a small class (CodePoint), with a match at the very start and one
    // right behind another.
    const std::string walks = "abc1abc2 xabc7 abcc yab xyabab, The then "
                              "than Holmes said holmes, unto an inn on";
    for (const char *pat : {"x?y?ab(c*)", "[aeiou]n", "[Tt]h[ae]",
                            "([Hh]olmes) (\\w+)", "[xy]?ab(\\d?)"}) {
      CHECK(finds_agree(make_us(pat), flat_spans(cp_pike(pat), walks, false),
                        walks));
      CHECK(finds_agree(Regex(pat), flat_spans(pike_twin(pat), walks, false),
                        walks));
    }
    CHECK(PlanProbe::teddy(make_us("x?y?ab(c*)")).ok);
    CHECK(PlanProbe::start(make_us("x?y?ab(c*)"), false) == 'W');
    CHECK(PlanProbe::start(make_us("[aeiou]n"), false) == 'W');
    // match(), anchored at 0, by the same rule.
    for (const char *pat : {"fox", "fox|dog"}) {
      CHECK(make_us(pat).match("fox\xCC\x81").matched());
      CHECK(!Regex(pat).match("fox\xCC\x81").matched());
      CHECK(make_us(pat).match("fox").end() == 3);
      CHECK(!make_us(pat).match("a fox").matched());
    }
    CHECK(make_us("fox|dog").match("dog").end() == 3);
    CHECK(!make_us("fox|dog").match("a dog").matched());
    // The scans' compare of a candidate, at every length it has a path for
    // (a byte loop, two words, memcmp): the subject is the literal with one
    // byte changed, at each position in turn, and then the literal itself —
    // the only match, whichever bytes the scan probes for.
    const std::string letters = "abcdefghijklmnopqrst";
    for (size_t m = 1; m <= letters.size(); m++) {
      const std::string lit = letters.substr(0, m);
      std::string near;
      for (size_t k = 0; k < m; k++) {
        near += lit + ' ';
        near[near.size() - 1 - m + k] = 'Z';
      }
      const std::vector<size_t> want{near.size(), near.size() + m};
      near += lit;
      for (const std::string &pat : {lit, lit + "|Z!", lit + "\\d*"})
        for (const Regex &re : {Regex(pat), make_us(pat)}) {
          CHECK(flat_spans(re, near, false) == want);
          CHECK(re.search(near).begin() == want[0] && re.test(near));
        }
    }
  }

  // --- results ---
  auto ok = [](const std::string &subj, const std::string &pat) {
    Regex bare(pat);
    Regex pike = pike_twin(pat); // lookahead -> grapheme Pike
    auto a = find_all(bare, subj), b = find_all(pike, subj);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end())
        return false;
    std::vector<std::pair<size_t, size_t>> sc;
    for (auto m : bare.find_iter(subj)) sc.emplace_back(m.begin(), m.end());
    if (sc.size() != a.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (sc[i].first != a[i].begin() || sc[i].second != a[i].end())
        return false;
    auto sr = bare.search(subj);
    if (sr.matched() != (!a.empty())) return false;
    if (!a.empty() && (sr.begin() != a[0].begin() || sr.end() != a[0].end()))
      return false;
    return bare.test(subj) == !a.empty();
  };
  auto ok_us = [](const std::string &subj, const std::string &pat) {
    Regex us = make_us(pat);
    auto a = us.find_all(subj);
    auto ref = make_us("(?:" + pat + ")(?=[\\s\\S]|$)").find_all(subj);
    if (a.size() != ref.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != ref[i].begin() || a[i].end() != ref[i].end())
        return false;
    size_t k = 0;
    for (auto m : us.find_iter(subj)) {
      if (k >= a.size() || m.begin() != a[k].begin() || m.end() != a[k].end())
        return false;
      k++;
    }
    if (k != a.size()) return false;
    auto sr = us.search(subj);
    if (sr.matched() != (!a.empty())) return false;
    if (!a.empty() && (sr.begin() != a[0].begin() || sr.end() != a[0].end()))
      return false;
    return us.test(subj) == !a.empty();
  };
  // Every line holds candidates for both ends of the patterns below: prefix
  // letters that complete no match, suffixes with no prefix behind them,
  // prefix bytes the body absorbs (`eeeelq`, `aaaz`), suffixes inside a
  // match (`singing`), and the assert shapes' word and line edges.
  const std::string base =
      "The end of it: xeeeelq eq eelq, a0123456789abcdefz az aaaz.\n"
      "a b c! and a. no! a yes! is? yes? s? sss? singing string tasting the\n"
      "Sherlock spoke slowly; Holmes hates truly ugly quartz, Mr Jones the\n"
      "user@host.net ua@b a@b.net the  quickly zone ze zzze\n"
      "untie the quaq quote; Sherlock side tally thely unlit zebraq\n";
  std::string ascii, acrlf, nonascii = "\xc3\xb1"; // ñ: the egc byte path
  for (int i = 0; i < 40; i++) {
    ascii += base;
    for (char ch : base) {
      if (ch == '\n') acrlf += '\r', nonascii += '\r';
      acrlf += ch;
      nonascii += ch;
    }
  }
  const char *dfa_pats[] = {
      // suffix-driven behind a literal prefix
      "e[a-z]{3,}q", "a.{16}z", "a[^.]*\\!", "s[a-z]*\\?", "t[a-z]+ing",
      "the\\s+\\w+ly", "a[a-z]+z", "e[a-z]*e[a-z]*q", "q[a-z]*a[a-z]*q",
      "s[a-z]+ing", "a[^!]{2,}z",
      // interior-literal-driven behind a literal prefix / before a suffix
      "a\\w+@\\w+", "u[a-z]*@[a-z]+\\.net", "\\w+@\\w+e", "\\w+e\\w+@",
      // the prefix stays
      "Sherlock\\s+\\w+", "S[a-z]+\\.", "H[a-z]+s", "z[a-z]+e", "T[a-z]+k",
      "Mr\\w+e\\w+",
      // nothing drives: the scan
      "e[a-z]+s", "a[a-z]*e", "[A-Z][a-z]+s", "t[a-z]*e",
  };
  const char *assert_pats[] = {
      "Sherlock [a-z]+e\\b", "H[a-z]+s\\b", "\\bH[a-z]+s\\b", "z[a-z]*e$",
      "(?m)z[a-z]*e$", "(?m)^The [a-z]+ of", "(?m)^[A-Z][a-z]+ the$",
      "t[a-z]+ly\\b", "\\bthe [a-z]+q\\b", "\\bq[a-z]+e\\b",
      "(?m)e[a-z]+\\.$", "\\b\\w+ing\\b", "\\b\\w+ly\\b", "[a-z]+ing\\b",
      "\\bun\\w+\\b", "\\bt[a-z]+", "\\be[a-z]+s\\b", "a[a-z]+d\\b",
      "\\bs[a-z]*ing\\b", "\\b\\w{2,4}ly\\b", "\\Bly\\b", "the\\b [a-z]+q\\b",
  };
  for (const std::string &s : {ascii, acrlf, nonascii}) {
    for (const char *pat : dfa_pats) CHECK(ok(s, pat));
    for (const char *pat : assert_pats) CHECK(ok(s, pat));
  }
  for (const std::string &s : {ascii, nonascii}) {
    for (const char *pat : dfa_pats) CHECK(ok_us(s, pat));
    for (const char *pat : assert_pats) CHECK(ok_us(s, pat));
  }
  // A prefix byte the body absorbs, in front of a suffix that never comes:
  // the failed-walk budget must hand the find back (linear), and what it is
  // handed back to must still be right.
  {
    std::string run(6000, 'a');
    CHECK(ok(run + "z", "a[a-z]+z"));
    CHECK(ok(run + "\xc3\xb1z " + run + "z", "a[a-z]+z"));
    CHECK(ok(run, "a[a-z]+z"));
    CHECK(ok(run + "q" + run + "q", "a[a-z]*q"));
  }
}

// Fixed-text literal prefilter for the assertion tier (rure-style): an assert
// pattern whose matched text is a single fixed literal once zero-width asserts
// are stripped (`(?m)^X|X$`, `^X$`, `\bX\b`) memmems the literal and confirms
// the assertions with an anchored assert-DFA verify. Same oracle: bare
// (prefilter) vs grapheme Pike (lookahead) vs scan, on ASCII / CRLF / non-ASCII.
void test_assert_literal_prefilter() {
  auto ok = [](const std::string &subj, const std::string &pat) {
    Regex bare(pat);
    Regex pike = pike_twin(pat); // lookahead -> grapheme Pike
    auto a = find_all(bare, subj), b = find_all(pike, subj);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end() ||
          a[i].str() != b[i].str())
        return false;
    std::vector<std::pair<size_t, size_t>> sc;
    for (auto m : bare.find_iter(subj)) sc.emplace_back(m.begin(), m.end());
    if (sc.size() != a.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (sc[i].first != a[i].begin() || sc[i].second != a[i].end()) return false;
    auto sr = bare.search(subj);
    if (sr.matched() != (!a.empty())) return false;
    if (!a.empty() && (sr.begin() != a[0].begin() || sr.end() != a[0].end()))
      return false;
    return true;
  };
  // Lines with the names at start / middle / end, plus word-boundary cases.
  std::string base = "Sherlock Holmes here\nthe Sherlock Holmes\nSherlock "
                     "Holmes\na cat and a category; the cat sat\nend\n";
  std::string ascii, nonascii = "\xc3\xb1\n"; // ñ forces the byte assert tier
  for (int i = 0; i < 40; i++) {
    ascii += base;
    nonascii += base;
  }
  for (const std::string &s : {ascii, nonascii}) {
    CHECK(ok(s, "(?m)^Sherlock Holmes|Sherlock Holmes$")); // the bench pattern
    CHECK(ok(s, "(?m)^Sherlock Holmes"));                  // ^ literal
    CHECK(ok(s, "Sherlock Holmes$"));                      // literal $ (\z form)
    CHECK(ok(s, "(?m)^cat"));                              // common-ish literal
    CHECK(ok(s, "(?m)end$"));
    CHECK(ok(s, "\\bcat\\b"));   // word-bounded literal (rejects "category")
    CHECK(ok(s, "\\bHolmes\\b"));
    CHECK(ok(s, "(?m)^end$"));   // whole-line literal
    // Not a single fixed text -> falls back to the full assert scan, still
    // equal to the Pike.
    CHECK(ok(s, "\\bcat\\b|\\bend\\b")); // two distinct literals
    CHECK(ok(s, "\\b\\w+n\\b"));         // variable (\w+) -> no literal
    // Flag-only anchor verify edge cases (each anchor maps to one EmptyFlag bit;
    // the verify evaluates them at the literal's two boundaries, no DFA rescan).
    CHECK(ok(s, "\\Acat"));            // begin-text (matches only at offset 0)
    CHECK(ok(s, "cat\\z"));            // end-text
    CHECK(ok(s, "\\Bcat\\B"));         // both sides NOT a word boundary
    CHECK(ok(s, "\\Bere"));            // interior of "here" -> \B at start
    CHECK(ok(s, "(?m)^Sherlock\\b"));  // leading ^ + trailing \b
    CHECK(ok(s, "(?m)\\bHolmes$"));    // leading \b + trailing $
    CHECK(ok(s, "(?m)^a|a$|\\ba\\b")); // 3-branch alternation, mixed anchors
  }
  // CRLF: the multiline ^ fires after \r and after \n; the flag verify must
  // agree with the Pike on a CR-LF-bearing subject.
  std::string crlf;
  for (int i = 0; i < 30; i++) crlf += "Sherlock Holmes\r\nthe end\r\n";
  CHECK(ok(crlf, "(?m)^Sherlock Holmes|Sherlock Holmes$"));
  CHECK(ok("\xc3\xb1" + crlf, "(?m)^the end$"));
  // Gate-free line/text-anchor path runs on ANY subject (no eligibility scan),
  // including multi-code-point grapheme clusters that the old gate rejected. A
  // line break is its own cluster (GB4/GB5) so the code-point anchors stay
  // grapheme-correct; literal_boundary_ok rejects a literal that a Prepend /
  // combining mark pulls into a neighbouring cluster. Must equal the Pike.
  std::string clus = "cat\xcc\x81 a cat here\n\xd8\x80" "cat starts\ncat\nthe cat"
                     " e\xcc\x81\ncat\xe2\x80\x8d zwj\ncat";   // combining/Prepend/ZWJ
  CHECK(ok(clus, "(?m)^cat|cat$"));
  CHECK(ok(clus, "cat$"));
  CHECK(ok(clus, "(?m)^cat"));
  CHECK(ok(clus, "\\Acat"));
  CHECK(ok("\xcc\x81" + clus, "(?m)^cat$"));
}

// Literal-prefix memmem on the ASCII DFA tier: the lf program's `(?s:.)*?` prefix
// makes the first-byte set universal, so a literal-led pattern relies on the
// rare-byte memmem (find_substr over prefix_) — added to the use_prefilter branch
// of the lf / boolean forward scans. Pin correctness vs the grapheme Pike (forced
// by a trailing always-true lookahead) on PURE-ASCII subjects, across find_all /
// scan / search / test, for sparse, common-first-byte, and near-miss literals.
void test_ascii_literal_prefilter() {
  // A literal of two bytes or more scans as a pair of its bytes, whatever
  // the frequency table says of the rarest one — the table knows prose, and
  // the subject may be anything. One byte has no partner.
  for (const char *lit : {"fox", "Sherlock", "zq", "the", "Mr\\."})
    CHECK(PlanProbe::prefix_pair(Regex(lit)) &&
          PlanProbe::prefix_pair(make_us(lit)));
  CHECK(!PlanProbe::prefix_pair(Regex("x")) &&
        !PlanProbe::prefix_pair(make_us("x")));
  // ... and finds what it found as a single probe, where the "rare" byte is
  // everywhere: at a hit's own distance from a near miss, at the edges.
  {
    const std::string t = "x fox xx fax ox fo foxfox xof f.x fox";
    const std::vector<size_t> want = {2, 5, 19, 22, 22, 25, 34, 37};
    CHECK(finds_agree(Regex("fox"), want, t) &&
          finds_agree(make_us("fox"), want, t));
    CHECK(flat_spans(Regex("fox"), std::string(200, 'x') + "fo", false).empty());
  }
  auto ok = [](const std::string &subj, const std::string &pat) {
    Regex bare(pat);
    Regex pike = pike_twin(pat); // lookahead -> grapheme Pike
    auto a = find_all(bare, subj), b = find_all(pike, subj);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end() ||
          a[i].str() != b[i].str())
        return false;
    std::vector<std::pair<size_t, size_t>> sc;
    for (auto m : bare.find_iter(subj)) sc.emplace_back(m.begin(), m.end());
    if (sc.size() != a.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (sc[i].first != a[i].begin() || sc[i].second != a[i].end()) return false;
    auto sr = bare.search(subj);
    if (sr.matched() != (!a.empty())) return false;
    if (bare.test(subj) != (!a.empty())) return false;
    return true;
  };
  // Pure-ASCII text with the literals and many near-misses (shared first bytes,
  // partial prefixes) to exercise memmem candidate verification.
  std::string s;
  for (int i = 0; i < 40; i++)
    s += "the theatre theme; Sherlock sheriff shelf; zebra zone zeal. SHOUT ";
  CHECK(ok(s, "Sherlock"));        // sparse, rare-ish first byte 'S'
  CHECK(ok(s, "the zebra"));       // common first byte 't', rare byte 'z' inside
  CHECK(ok(s, "theme"));           // common prefix, near-misses "the","theatre"
  CHECK(ok(s, "shelf"));           // shares "she" with sheriff/Sherlock
  CHECK(ok(s, "zqxj"));            // no match (rare bytes)
  CHECK(ok(s, "SHOUT"));           // uppercase literal
  CHECK(ok(s, "Sher[a-z]ock"));    // literal prefix + class (prefix memmem path)
  CHECK(ok(s, "the[a-z]+e"));      // literal prefix + greedy body
  CHECK(ok(s, "z"));               // single rare byte
  CHECK(ok(s, "theatre|zebra"));   // alternation (teddy / no single prefix)
}

// Empty-width assertion patterns (\b \B ^ $ \A \z, incl. multiline) run on the
// cached assertion-aware DFA for find_all/search/match on ASCII subjects. Each
// must match the grapheme Pike, forced via an always-true zero-width assertion
// `(?:\b|\B)` (which makes the program non-DFA-able). \Z and lookaround stay on
// the Pike directly. Some explicit expectations pin the behavior.
// Case-insensitive literal prefix prefilter (Option A): on an ASCII subject the
// lowercased ASCII prefix is found with a case-fold SIMD scan (find_substr_icase
// + ascii case-fold verify). On a non-ASCII subject the prefilter must NOT fire
// (ASCII case folding is unsound over UTF-8 — a fold byte could land inside a
// multi-byte cluster), so the engine falls back to the grapheme Pike unchanged.
// Both must agree with the lookahead-forced grapheme Pike oracle, across all
// entry points (find_all / scan / search / test).
void test_ascii_icase_prefilter() {
  auto ok = [](const std::string &subj, const std::string &pat) {
    Regex bare(pat, reg::IgnoreCase);
    // Lookahead makes the program non-DFA-able -> grapheme Pike oracle.
    Regex pike = pike_twin(pat, reg::IgnoreCase);
    auto a = find_all(bare, subj), b = find_all(pike, subj);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end() ||
          a[i].str() != b[i].str())
        return false;
    std::vector<std::pair<size_t, size_t>> sc;
    for (auto m : bare.find_iter(subj)) sc.emplace_back(m.begin(), m.end());
    if (sc.size() != a.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (sc[i].first != a[i].begin() || sc[i].second != a[i].end()) return false;
    auto sr = bare.search(subj);
    if (sr.matched() != (!a.empty())) return false;
    if (bare.test(subj) != (!a.empty())) return false;
    return true;
  };
  // Pure-ASCII subject with mixed case and many near-misses.
  std::string s;
  for (int i = 0; i < 40; i++)
    s += "the Theatre THEME; Sherlock SHERIFF Shelf; Zebra zone ZEAL. shout ";
  CHECK(ok(s, "sherlock"));   // lowercased pattern, mixed-case matches
  CHECK(ok(s, "SHERLOCK"));   // uppercased pattern
  CHECK(ok(s, "ShErLoCk"));   // mixed-case pattern
  CHECK(ok(s, "theme"));      // common first byte, near-misses the/theatre
  CHECK(ok(s, "shelf"));      // shares "she" with sheriff/sherlock
  CHECK(ok(s, "zebra"));      // rare first byte
  CHECK(ok(s, "qxjk"));       // no match
  CHECK(ok(s, "the zebra"));  // common first byte 't', rare 'z' inside
  CHECK(ok(s, "z"));          // single byte, both cases
  // Non-ASCII subject: the prefilter must stand down and the grapheme Pike must
  // still find every case-insensitive match (this is the exact soundness hole
  // the prefix-skip gating closes — see prefix_.icase).
  std::string ns =
      "\xc3\xa9\xc3\x89""Apple "      // éÉApple
      "\xe6\x97\xa5 Sherlock "        // 日 Sherlock
      "\xce\xb1 SHERLOCK \xc3\xb1""x"; // α SHERLOCK ñx
  CHECK(ok(ns, "sherlock"));
  CHECK(ok(ns, "apple"));
  CHECK(ok(ns, "x"));
  CHECK(ok(ns, "qz"));   // no match on non-ASCII subject
  CHECK(ok(ns, "a"));    // single byte over UTF-8 (no fire inside é/α/ñ bytes)
}

void test_assert_dfa() {
  auto same = [](const std::string &s, const std::string &p) {
    Regex bare(p), pike = pike_twin(p);
    auto a = find_all(bare, s), b = find_all(pike, s);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end() ||
          a[i].str() != b[i].str())
        return false;
    return bare.search(s).str() == pike.search(s).str() &&
           bare.match(s).matched() == pike.match(s).matched();
  };
  const char *pats[] = {
      "\\b\\w+n\\b", "\\b\\w+\\b", "^\\w+", "\\w+$", "^\\w+$", "\\Aabc",
      "abc\\z", "(?m)^\\w+", "(?m)\\w+$", "\\bfoo\\b", "[a-z]+$", "\\B\\w\\B",
      "(?m)^.+$", "\\bfoo\\b|\\bbar\\b",
      // longest-unsafe assert-alternations (leftmost-first != the
      // longest end): before the lf assert tier these fell to the
      // Pike; now the ordered+cut assert DFA serves them.
      "\\ba|\\bab", "\\bab|\\ba", "(?m)^a|b$", "\\bfoo\\b|\\bfo", "^abc|^ab",
      "\\w+ed\\b|\\w+ing\\b"};
  const char *subs[] = {
      "",    "word",      "the word is", "foo bar baz",   "FOO\nbar", "wordn n",
      "abc", "xabcy",     "\nhi\nbye\n", "a b c",         "end.",     "\n\n",
      "ab",  "ab cd\nef", "fo foo",      "talking walked"};
  for (auto p : pats)
    for (auto s : subs)
      CHECK(same(s, p));
  // Explicit leftmost-first: \ba|\bab prefers the FIRST branch ("a"), not the
  // longest ("ab"). The longest-match assert DFA would have returned "ab".
  CHECK(Regex("\\ba|\\bab").search("ab").str() == "a");
  CHECK(Regex("\\bab|\\ba").search("ab").str() ==
        "ab"); // first branch wins (longer)
  CHECK(Regex("\\ba|\\bab").match("ab").str() == "a"); // anchored, same priority

  // Non-ASCII assert byte tier, leftmost-first (Greek/accented letters are \w,
  // so
  // \b fires around them). The longest-unsafe alternations exercise the lf byte
  // assert DFA on a non-ASCII subject (previously the grapheme Pike).
  // Differential vs the forced Pike, plus explicit first-branch-wins checks.
  const char *napats[] = {"\\bμ|\\bμν", "\\bμν|\\bμ", "\\bα\\w*",
                          "\\w+\\b",    "(?m)^\\w+",  "\\w+$"};
  const char *nasubs[] = {"μν x", "αβγ δε",    "café au lait",
                          "λ",    "über\nfoo", "naïve test"};
  for (auto p : napats)
    for (auto s : nasubs)
      CHECK(same(s, p));
  CHECK(Regex("\\bμ|\\bμν").search("μν x").str() == "μ");  // first branch ("μ")
  CHECK(Regex("\\bμν|\\bμ").search("μν x").str() == "μν"); // first branch ("μν")
  // Explicit: \b\w+n\b needs >= 2 chars (\w+ then literal n), so a lone "n"
  // does not match; "seven men in" -> seven, men, in.
  auto v = find_all(Regex("\\b\\w+n\\b"), "seven men in n");
  CHECK(v.size() == 3 && v[0].str() == "seven" && v[2].str() == "in");
  CHECK(find_all(Regex("^\\w+"), "ab\ncd").size() == 1); // ^ = text start only
  CHECK(find_all(Regex("(?m)^\\w+"), "ab\ncd").size() ==
        2); // multiline: each line
  CHECK(Regex("\\w+$").search("ab cd").str() == "cd");

  // Multiline ^/$ fire on any line-break byte (\n \r \v \f), but NOT between a
  // \r and a following \n: a CR-LF is one grapheme cluster (GB3), so it is a
  // single line break — now consistently on ASCII too (segment() fuses it).
  // Differential vs the forced Pike, with the Multiline flag and subjects
  // carrying CR / CRLF / vertical tab.
  auto samef = [](const std::string &s, const std::string &p, unsigned fl) {
    Regex bare(p, fl), pike = pike_twin(p, fl);
    auto a = find_all(bare, s), b = find_all(pike, s);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end() ||
          a[i].str() != b[i].str())
        return false;
    return bare.test(s) == pike.search(s).matched();
  };
  const char *mlpats[] = {"^",     "$",     "(?m)^\\w+", "(?m)\\w+$",
                          "(?m)^", "(?m)$", "(?m)^.",    "(?m)^[^a]"};
  const char *mlsubs[] = {"b\r",  "\r\n\n",  "a\r\nb",   "x\ry\nz",
                          "\v\f", "a\nb\rc", "\r\n\r\n", "abc"};
  for (auto p : mlpats)
    for (auto s : mlsubs) {
      CHECK(samef(s, p, Multiline));
      CHECK(samef(s, p, 0));
    }
  // CRLF is ONE grapheme cluster (UAX #29 GB3), now consistently on ASCII too
  // (segment() fuses it; see ascii_grapheme_ok): (?m)^ does NOT fire between the
  // \r and the \n, so "\r\n\n" has line starts at 0, after the CR-LF (2), and
  // after the lone \n (3) — three, matching a non-ASCII subject.
  CHECK(find_all(Regex("(?m)^", Multiline), "\r\n\n").size() == 3);

  // Assert patterns on non-ASCII subjects take the byte assert tier (the
  // lazy DFAs over the byte programs, with look, forward and reverse — a
  // non-ASCII code point is a step they take whole); they must agree with
  // the forced Pike,
  // including multiline ^/$ across CR-LF and accented letters. é=U+00E9,
  // α=U+03B1.
  const std::string E = "\xC3\xA9", A = "\xCE\xB1";
  const char *bpats[] = {"\\b\\w+n\\b", "\\b\\w+", "(?m)^\\w+", "(?m)\\w+$",
                         "\\w+",        "(?m)^.",  "\\bfoo\\b", "(?m)^[^c]"};
  const std::string bsubs[] = {E + "an\r\nmen " + A,  "the " + E + "nd\r\nin n",
                               A + "\r\n" + E + "x",  E + "foo " + A + "n",
                               "x" + E + "\r\ny" + A, E + A + "\r\n"};
  for (auto p : bpats)
    for (auto &s : bsubs) {
      CHECK(samef(s, p, Multiline));
      CHECK(samef(s, p, 0));
    }
}

void test_lookahead() {
  CHECK(Regex("\\d+(?= USD)").search("price 42 USD").str() == "42");
  CHECK(Regex("foo(?=bar)").test("foobar"));
  CHECK(!Regex("foo(?=bar)").test("foobaz"));
  CHECK(Regex("foo(?!bar)").test("foobaz"));
  CHECK(!Regex("foo(?!bar)").test("foobar"));
  // Perl leftmost-first: \d+ backtracks to a shorter match the lookahead allows
  CHECK(Regex("\\d+(?! USD)").search("42 USD").str() == "4");
  // variable-length lookahead body
  CHECK(Regex("\\w+(?=\\s*;)").search("name   ;").str() == "name");
}

void test_lookaround_linear() {
  // The Pike settles a lookaround at every position in one pass over the
  // subject. Asking the body afresh at each position the Pike reached was
  // O(n^2): `(?=\w*z)\w` exhausted the step budget on 1500 bytes.
  for (auto unit : {reg::MatchUnit::Grapheme, reg::MatchUnit::CodePoint}) {
    const std::string a(20000, 'a');
    CHECK(!make_unit(unit, "(?=\\w*z)\\w", 0).test(a));
    CHECK(make_unit(unit, "(?=\\w*z)\\w", 0).search(a + "z").begin() == 0);
    CHECK(!make_unit(unit, "(?<=z\\w*)a", 0).test(a));
    CHECK(make_unit(unit, "(?<=z\\w*)a", 0).search("z" + a).begin() == 1);
    // find_all shares the answers across its matches: 20001 matches here.
    CHECK(make_unit(unit, "\\w(?=\\w*z)", 0).find_all(a + "z").size() ==
          a.size());
    CHECK(make_unit(unit, "(?<!b\\w*)a", 0).find_all(a).size() == a.size());
    // A lookaround nested in a lookaround body, and one under a repeat.
    CHECK(make_unit(unit, "(?=\\w*(?<=z)y)\\w", 0).search(a + "zy").begin() ==
          0);
    CHECK(!make_unit(unit, "(?=\\w*(?<=z)y)\\w", 0).test(a + "y"));
    CHECK(make_unit(unit, "(?:(?!ab)\\w)+", 0).search("xxab").str() == "xx");
  }
}

void test_unicode_properties() {
  CHECK(Regex("\\p{L}+").test("héllo"));
  CHECK(Regex("^\\p{L}+$").test("café"));
  CHECK(!Regex("^\\p{L}+$").test("ab12"));
  CHECK(Regex("\\p{N}+").search("count 2026").str() == "2026");
  CHECK(Regex("^\\P{L}+$").test("123 !!"));
  CHECK(Regex("[\\p{L}\\p{N}]+").search("abc123 ").str() == "abc123");
  CHECK(Regex("\\p{L}+").search("λόγος42").str() == "λόγος"); // Greek
  CHECK(Regex("\\p{Lu}").search("aBc").str() == "B");         // uppercase
}

void test_lookbehind_fixed() {
  CHECK(Regex("(?<=\\$)\\d+").search("costs $50 or £60").str() == "50");
  CHECK(Regex("(?<=foo)bar").test("foobar"));
  CHECK(!Regex("(?<=foo)bar").test("xxxbar"));
  CHECK(Regex("(?<=foo|baz)X").search("bazX").str() == "X");
  CHECK(Regex("(?<!foo)bar").search("foobar zbar").begin() == 8);
}

void test_lookbehind_variable() {
  CHECK(Regex("(?<=a+)b").search("aaab").begin() == 3);
  CHECK(Regex("(?<=\\d+)px").search("width 1280px").begin() == 10);
  // alternation with branches of different lengths
  CHECK(Regex("(?<=foo|barbar)!").search("barbar!").begin() == 6);
  CHECK(Regex("(?<=foo|barbar)!").search("foo!").begin() == 3);
  // bounded-but-variable
  CHECK(Regex("(?<=x{2,4})y").test("xxxxy"));
  CHECK(!Regex("(?<=x{2,4})y").test("xy"));
  // anchor inside a variable-length lookbehind
  CHECK(Regex("(?<=^\\w+ )\\w+").search("hello world again").str() == "world");
  // negative variable-length lookbehind
  CHECK(Regex("(?<!v\\d*)\\d").search("v12 7").str() == "7");
}

void test_gpt2_tokenizer() {
  // The real GPT-2 pre-tokenizer pattern (needs \p{...} and lookahead).
  Regex re("'s|'t|'re|'ve|'m|'ll|'d| ?\\p{L}+| ?\\p{N}+| ?[^\\s\\p{L}\\p{N}]+|"
           "\\s+(?!\\S)|\\s+");
  auto toks = find_all(re, "I've got 3 cats!");
  CHECK(toks.size() == 6);
  if (toks.size() == 6) {
    CHECK(toks[0].str() == "I");
    CHECK(toks[1].str() == "'ve");
    CHECK(toks[2].str() == " got");
    CHECK(toks[3].str() == " 3");
    CHECK(toks[4].str() == " cats");
    CHECK(toks[5].str() == "!");
  }
}

void test_nullable_quantifiers() {
  // An unbounded quantifier over a body that can match empty must stop after an
  // empty iteration rather than greedily consuming (the empty-iteration guard).
  // These match the empty string at position 0, like Perl/Python/PCRE.
  CHECK(Regex("(.*?)*").search("cc").str() == "");
  CHECK(Regex("(.*?)+").search("cc").str() == "");
  CHECK(Regex("(.*?){2,}").search("cc").str() == "");
  CHECK(Regex("(a*)*").search("bb").str() == "");
  CHECK(Regex("(a|b*){2,}").search("cc").str() == "");
  CHECK(Regex("(x|){2,}").search("ab").str() == "");
  // Non-nullable bodies are unaffected (still consume greedily).
  CHECK(Regex("(.*)*").search("cc").str() == "cc");
  CHECK(Regex("\\w+").search("hello42").str() == "hello42");
  CHECK(Regex("(ab)+").search("ababab").str() == "ababab");
  // A consuming leading branch still consumes.
  CHECK(Regex("(.|a*)*").search("ab").str() == "ab");
  // FUNDAMENTAL LIMITATION (not a fixable bug): an alternation whose FIRST
  // branch is nullable, nested in an unbounded quantifier — e.g. `(a*|b)*` on
  // "ab" yields "ab" where a backtracker yields "a". A second loop iteration
  // would have to re-traverse the nullable branch's instructions at the same
  // position, but the pc-dedup that makes matching linear visits each
  // instruction at most once per position. Honouring the backtracker here
  // would reintroduce the exponential blow-up the engine exists to avoid; this
  // is the same class of divergence RE2 documents. Extremely rare in practice.
  // Characterization (pins the current behaviour so a refactor that changes it
  // is noticed): regexlib yields the POSIX leftmost-longest result here.
  CHECK(Regex("(a*|b)*").search("ab").str() == "ab");
}

void test_dfa_boolean() {
  // test() uses the lazy DFA for regular patterns on ASCII subjects; it must
  // agree with the Pike VM (search().matched()). Mix of matching / non-matching.
  CHECK(Regex("\\d+").test("abc 123"));
  CHECK(!Regex("\\d+").test("no digits here"));
  CHECK(Regex("[a-z]+").test("Hello"));
  CHECK(Regex("(ab|cd)+").test("xxabcdab"));
  CHECK(!Regex("(ab|cd)+e").test("ababab"));
  CHECK(Regex("a.c").test("xayc x abc"));
  CHECK(Regex("\\w+@\\w+").test("mail me at a@b ok"));
  CHECK(Regex("").test(""));   // empty pattern matches
  CHECK(Regex("x*").test("")); // matches empty
  CHECK(!Regex("zzz").test("the quick brown fox"));
  // DFA result must equal the Pike VM result for the same input.
  CHECK(Regex("[0-9]{3}").test("ab123") ==
        Regex("[0-9]{3}").search("ab123").matched());
  // Non-ASCII subject falls back to the Pike VM but stays correct.
  CHECK(Regex("\\w+").test("héllo"));
  CHECK(Regex("café").test("a café"));
  // Patterns with anchors / lookaround are not DFA-able -> Pike VM, still
  // right.
  CHECK(Regex("^abc$").test("abc"));
  CHECK(Regex("foo(?=bar)").test("foobar"));
  // State-heavy "regular" pattern: `.*a.{N}` needs ~2^N DFA states in the
  // limit. A DFA that outgrows its cache budget refills it, or gives up for
  // the Pike VM, which must give the same boolean. This guards the M0 safety
  // net (the answer is identical whether or not the budget is reached on a
  // given input; test_dfa_cache makes sure it is reached).
  {
    Regex heavy(".*a.{18}");
    std::string s = "the quick brown fox a jumps 12345 over xyz a lazy dog; ";
    while (s.size() < 80000)
      s += s;
    CHECK(heavy.test(s) == heavy.search(s).matched());
    std::string none(80000, 'b'); // no 'a' -> no match on either path
    CHECK(heavy.test(none) == heavy.search(none).matched());
  }
}

// The lazy DFA's table and its cache budget (LazyDfa): byte classes, the
// clear-and-refill of a full cache, and the give-up when refilling does not
// pay. Every scan here is checked against the Pike twin — the budget decides
// what a scan costs, never what it answers.
void test_dfa_cache() {
  using Stats = PlanProbe::DfaStats;
  auto spans = [](const Regex &re, std::string_view s,
                  Regex::FindCache *fc = nullptr) {
    std::vector<size_t> v;
    if (fc)
      for (auto m : re.find_all(s, *fc)) {
        v.push_back(m.begin());
        v.push_back(m.end());
      }
    else
      for (auto m : re.find_all(s)) {
        v.push_back(m.begin());
        v.push_back(m.end());
      }
    return v;
  };
  // Letters drawn from `alphabet` by a fixed generator.
  auto noise = [](size_t n, const char *alphabet, unsigned seed) {
    const size_t k = std::strlen(alphabet);
    std::string s;
    unsigned x = seed;
    for (size_t i = 0; i < n; i++) {
      x = x * 1664525u + 1013904223u;
      s += alphabet[(x >> 16) % k];
    }
    return s;
  };

  // A row is as wide as the pattern is varied: the bytes a program does not
  // tell apart share a column. Five kinds of byte here (i, n, g, the other
  // lowercase letters, everything else), where a row used to be 256 wide.
  for (bool us : {false, true}) {
    Regex re = us ? make_us("[a-z]+ing") : Regex("[a-z]+ing");
    Regex::FindCache fc;
    const std::string s = "sing a song of bringing things, king; ring-a-ding";
    CHECK(spans(re, s, &fc) == spans(pike_twin("[a-z]+ing"), s));
    CHECK(PlanProbe::dfa_stats(fc).built > 0);
    const unsigned width = PlanProbe::widest_row(re);
    CHECK(width >= 5 && width <= 24);
  }
  // ... and the classes are exact: `\w` and `\d` overlap, a negated class
  // splits the rest, and every byte of a multi-byte code point keeps its
  // place in the UTF-8 automaton.
  for (const char *pat : {"\\w+\\d[^a-f]", "[^\\W\\d]+_?\\d*", "é+|[à-ÿ]x"}) {
    const std::string s = "ab12_x9z éé àx ÿx c3po r2d2_7! naïve 42q";
    for (bool us : {false, true}) {
      Regex re = us ? make_us(pat) : Regex(pat);
      Regex::FindCache fc;
      CHECK(spans(re, s, &fc) == spans(pike_twin(pat), s));
      CHECK(re.test(s) == pike_twin(pat).test(s));
    }
  }
  // The same, asked of the plan: no instruction of a program tells two bytes
  // of one class apart. The classes of a byte automaton come from the byte
  // ranges the compiler listed while emitting it, so every way it emits one
  // is here — class blocks (cached per class and direction, and shared
  // between Regexes), their copies under a repeat, literal bytes, the folded
  // orbits of (?i), `.` with and without (?s), the any-byte prefix of the
  // unanchored programs, a negated class, an interior literal's pre part.
  for (const char *pat :
       {"[a-z]+ing", "\\w+\\s+\\w+", "\\w{2,5}x", "\\p{Lu}\\p{Ll}+ \\d+",
        "caf\xc3\xa9|na\xc3\xafve|\xe6\xbc\xa2+", "stra\xc3\x9f" "e k\\w+",
        "a.c", "(?s)a.c", "[^a-c\\n]+z", "\\w+@\\w+\\.com", "x*",
        "(\\d+)-(\\d+)", "[\\x00-\\x10\\x7f]+|\\t", "\\S+\\s", "^ab$",
        "\\bfoo\\b"}) {
    CHECK(PlanProbe::classes_exact(Regex(pat)));
    CHECK(PlanProbe::classes_exact(make_us(pat)));
    CHECK(PlanProbe::classes_exact(Regex(pat, IgnoreCase)));
    CHECK(PlanProbe::classes_exact(make_us(pat, IgnoreCase)));
  }

  // A DFA with more states than its cache holds keeps running: the cache is
  // cleared and refilled from the state the scan is in. Over random a-d this
  // one has a state per window of the last eight letters (and, being an
  // alternation of two shapes, is not one-pass: the chain's DFAs serve it).
  {
    const char *pat = "b[a-d]{7}c|a[a-d]{7}d";
    const std::string s = noise(6000, "abcd", 1);
    const std::vector<size_t> want = spans(pike_twin(pat), s);
    CHECK(!want.empty());
    for (bool us : {false, true}) {
      Regex re = us ? make_us(pat) : Regex(pat);
      Regex::FindCache roomy;
      CHECK(spans(re, s, &roomy) == want);
      Stats full = PlanProbe::dfa_stats(roomy);
      CHECK(full.states > 200 && full.clears == 0 && !full.quit);

      // Room for a fraction of them, and refills without limit: the same
      // matches, the cache within its budget, never given up.
      Regex::FindCache tight;
      PlanProbe::dfa_cache(re, tight, /*bytes=*/4096, /*min_clears=*/~0u);
      CHECK(spans(re, s, &tight) == want);
      Stats st = PlanProbe::dfa_stats(tight);
      CHECK(st.clears > 3 && !st.quit);
      CHECK(st.bytes <= 4096);
      CHECK(spans(re, s, &tight) == want); // and again, over what is left

      // The stock rule: nearly every byte needs a state built, so once the
      // free refills are spent the DFA gives up — and the Pike answers.
      Regex::FindCache thrash;
      PlanProbe::dfa_cache(re, thrash, 4096, reg::limits::kDfaMinClears);
      CHECK(spans(re, s, &thrash) == want);
      st = PlanProbe::dfa_stats(thrash);
      CHECK(st.quit && st.clears == reg::limits::kDfaMinClears);
      CHECK(spans(re, s, &thrash) == want); // a cache that gave up stays right

      // The same through the thread's cache, which the one-shot entry
      // points draw on.
      for (uint32_t clears : {~0u, 0u}) {
        Regex r2 = us ? make_us(pat) : Regex(pat);
        PlanProbe::dfa_cache(r2, 1024, clears);
        CHECK(r2.test(s));
        auto m = r2.search(s);
        CHECK(m.matched() && m.begin() == want[0] && m.end() == want[1]);
        CHECK(flat_spans(r2, s, /*lazy=*/true) == want);
        CHECK(same_as_iter(r2, s));
        CHECK(r2.match(s).matched() == (want[0] == 0));
        st = PlanProbe::dfa_stats(r2);
        CHECK(clears ? (st.clears > 0 && !st.quit) : st.quit);
      }
    }
  }

  // A table of more entries than sixteen bits could index: a state is the
  // offset of its row, and a scan carries it whole. The first pattern's
  // forward DFA has a state per window of fifteen bytes; the second one's
  // reverse DFA has (its one match ends at the `z`, and the scan back from
  // there to the leftmost start passes every window of the subject).
  for (bool reverse : {false, true}) {
    const char *pat = reverse ? "[ab][a-e ]{14}[a-d][a-e ]*z"
                              : "(?:[ab]|[bc])[a-e ]{14}[a-d]";
    const std::string s = noise(40000, "abcd e", 2) + "z";
    const std::vector<size_t> want = spans(pike_twin(pat), s);
    CHECK(!want.empty());
    for (bool us : {false, true}) {
      Regex re = us ? make_us(pat) : Regex(pat);
      Regex::FindCache fc;
      CHECK(spans(re, s, &fc) == want);
      Stats st = PlanProbe::dfa_stats(fc);
      CHECK((reverse ? st.rev_entries : st.fwd_entries) > 65536);
      CHECK(st.clears == 0 && !st.quit);
    }
  }

  // An assert plan's DFAs are the same DFAs, under the same budget. The
  // pattern has a state per window of fifteen bytes, more than a cache of
  // 64 KB has room for: the scans that overflow it agree with the Pike, and
  // so do the scans of another subject after, on whatever the first left.
  {
    const char *pat = R"(\b[ab]*a[ab]{14}\b)";
    const size_t budget = size_t{64} << 10;
    const std::string s = noise(4000, "aaaaaaabbbbbbbb ", 3);
    const std::string s2 = noise(4000, "aaaaaaabbbbbbbb ", 4);
    const Regex pike = pike_twin(pat);
    const std::vector<size_t> want = spans(pike, s), want2 = spans(pike, s2);
    CHECK(!want.empty() && !want2.empty() && want != want2);
    for (bool us : {false, true}) {
      Regex re = us ? make_us(pat) : Regex(pat);
      Regex::FindCache fc;
      PlanProbe::dfa_cache(re, fc, budget, 3);
      CHECK(spans(re, s, &fc) == want);
      const Stats st = PlanProbe::dfa_stats(fc);
      CHECK(st.clears > 0 || st.quit);
      CHECK(spans(re, s2, &fc) == want2);
    }
  }

  // Refilling that PAYS is not given up on, however often it happens. Each
  // letter's run is one state, entered once and stepped through for 60
  // bytes: a cache with room for a few of them refills every few runs, and
  // every fill has covered far more than kDfaMinBytesPerState per state.
  {
    std::string pat, s;
    for (char c = 'a'; c <= 'p'; c++) {
      if (!pat.empty()) pat += '|';
      pat += std::string(1, c) + "+" + std::string(1, 'A' + (c - 'a'));
    }
    for (int rep = 0; rep < 6; rep++)
      for (char c = 'a'; c <= 'p'; c++) {
        s += std::string(60, c);
        if ((c - 'a' + rep) % 5 == 0) s += static_cast<char>('A' + (c - 'a'));
        s += ' ';
      }
    const std::vector<size_t> want = spans(pike_twin(pat), s);
    CHECK(want.size() > 20);
    for (bool us : {false, true}) {
      Regex re = us ? make_us(pat) : Regex(pat);
      Regex::FindCache roomy;
      CHECK(spans(re, s, &roomy) == want);
      Stats full = PlanProbe::dfa_stats(roomy);
      Regex::FindCache tight;
      // Room for about a third of the states the roomy cache came to.
      PlanProbe::dfa_cache(re, tight, 256 + full.bytes / 3,
                           reg::limits::kDfaMinClears);
      CHECK(spans(re, s, &tight) == want);
      Stats st = PlanProbe::dfa_stats(tight);
      CHECK(st.clears > reg::limits::kDfaMinClears && !st.quit);
    }
  }

  // A cache bound to another Regex goes back to the stock budget: the
  // settings above belong to the test, not to the cache.
  {
    Regex a("b[a-d]{7}c|a[a-d]{7}d"), b("b[a-d]{7}c|a[a-d]{7}d");
    const std::string s = noise(3000, "abcd", 2);
    Regex::FindCache fc;
    PlanProbe::dfa_cache(a, fc, 2048, 0);
    CHECK(spans(a, s, &fc) == spans(b, s));
    CHECK(PlanProbe::dfa_stats(fc).quit);
    CHECK(spans(b, s, &fc) == spans(a, s));
    Stats st = PlanProbe::dfa_stats(fc);
    CHECK(!st.quit && st.clears == 0);
  }
}

void test_dfa_match() {
  // match() takes a forward-DFA fast path for capture-free, longest-safe,
  // ASCII patterns (M1 tier 1). It must return the same anchored longest match
  // as the Pike VM.
  CHECK(Regex("\\w+").match("hello world").str() == "hello");
  CHECK(Regex("\\d+").match("123abc").str() == "123");
  CHECK(!Regex("\\d+").match("abc").matched()); // no match at position 0
  CHECK(Regex("a.c").match("abc").end() == 3);
  CHECK(Regex("a{2,3}").match("aaaa").str() == "aaa"); // greedy = longest
  CHECK(Regex("ab?c").match("abc").matched());
  CHECK(Regex("ab?c").match("ac").matched()); // greedy optional skipped
  CHECK(Regex("[a-z]+").match("abcXYZ").str() == "abc");
  Regex star("x*");
  CHECK(star.match("yyy").matched()); // empty match at 0
  CHECK(star.match("yyy").str() == "");
  CHECK(star.match("xxy").str() == "xx");
  // group 0 is populated even on the DFA path.
  CHECK(Regex("\\w+").match("foo bar").group(0).str() == "foo");
  // Not longest-safe (alternation) -> Pike path, still correct.
  CHECK(Regex("cat|dog").match("dog").str() == "dog");
  CHECK(Regex("a|ab").match("ab").str() == "a"); // leftmost-first, not "ab"
  // Non-ASCII subject -> Pike fallback, still correct.
  CHECK(Regex("\\w+").match("héllo").matched());
  // State-heavy but longest-safe: cap may force a Pike fallback; result equals
  // the Pike VM either way (compare against search at position 0).
  {
    Regex heavy(".*a.{18}");
    std::string s = "aaa bbb a 1234567890123456789 ccc";
    while (s.size() < 70000)
      s += s;
    auto m = heavy.match(s);
    auto sr = heavy.search(s);
    CHECK(m.matched() == (sr.matched() && sr.begin() == 0));
    if (m.matched()) CHECK(m.end() == sr.end());
  }
}

void test_dfa_search() {
  // search() takes the 3-stage pure-DFA path for capture-free, longest-safe,
  // ASCII patterns (M1-step2): unanchored forward finds an end, reverse finds
  // the leftmost start, anchored forward confirms the longest end. It must
  // match the Pike VM (which still backs find_all).
  auto m = Regex("\\d+").search("abc 123 def");
  CHECK(m.matched() && m.str() == "123" && m.begin() == 4 && m.end() == 7);
  m = Regex("\\w+").search("  hello world");
  CHECK(m.str() == "hello" && m.begin() == 2);
  m = Regex("fox").search("the quick fox"); // literal prefix path + DFA
  CHECK(m.str() == "fox" && m.begin() == 10);
  m = Regex("[a-z]+").search("ABCdef");
  CHECK(m.str() == "def" && m.begin() == 3);
  m = Regex("a+").search("bbaaab");
  CHECK(m.str() == "aaa" && m.begin() == 2);
  CHECK(!Regex("\\d+").search("abc").matched());
  CHECK(Regex("\\w+").search("a").str() == "a");
  // Empty-match pattern: leftmost match is the empty string at 0.
  m = Regex("x*").search("yyy");
  CHECK(m.matched() && m.str() == "" && m.begin() == 0 && m.end() == 0);
  m = Regex("x*").search("axxb"); // empty at 0 (leftmost-first)
  CHECK(m.matched() && m.begin() == 0 && m.str() == "");
  // DFA search() must equal Pike find_all()[0] across a spread of inputs.
  const char *pats[] = {"\\w+", "\\d+", "[a-z]+", "ab?c", "a.c", "foo", "x*y"};
  const char *subs[] = {"", "a", "  12ab cd34  ", "xxxyy", "foofoo", "a1!b2?"};
  for (const char *pp : pats)
    for (const char *ss : subs) {
      Regex re(pp);
      auto s = re.search(ss);
      auto all = find_all(re, ss);
      if (s.matched()) {
        CHECK(!all.empty());
        CHECK(all[0].begin() == s.begin() && all[0].end() == s.end() &&
              all[0].str() == s.str());
      } else {
        CHECK(all.empty());
      }
    }
}

void test_longest_safe_repeat() {
  // Regression: a greedy re-entrant repeat whose body holds a *nested*
  // variable-length quantifier (here `.{0,4}`) is NOT longest-safe — the
  // leftmost-first (greedy) end is shorter than the leftmost-longest (DFA) end,
  // so the DFA must bow out to the Pike VM rather than report the longer span.
  // Fuzzer-found: `(?:[a-cb].{0,4})+` on "bbc 23_\n_2" once gave [0,7) ("bbc
  // 23_") where greedy yields only [0,5) ("bbc 2").
  auto agrees_with_pike = [](const std::string &pat, const std::string &sub) {
    Regex re(pat);
    Regex pike = pike_twin(pat);
    auto all = find_all(re, sub);
    auto ref = find_all(pike, sub);
    CHECK(all.size() == ref.size());
    for (size_t i = 0; i < all.size() && i < ref.size(); i++)
      CHECK(all[i].begin() == ref[i].begin() && all[i].end() == ref[i].end() &&
            all[i].str() == ref[i].str());
  };
  auto m = Regex("(?:[a-cb].{0,4})+").search("bbc 23_\n_2");
  CHECK(m.matched() && m.begin() == 0 && m.end() == 5 && m.str() == "bbc 2");
  agrees_with_pike("(?:[a-cb].{0,4})+", "bbc 23_\n_2");
  agrees_with_pike("(?:[a-cb]${0}.{0,4})+",
                   "bbc 23_\n_2"); // exact fuzzer pattern
  agrees_with_pike("(?:\\w+\\s*)+", "a b  c d");
  agrees_with_pike("(?:ab?)+", "abab aab");
  // Simple greedy quantifiers stay on the (correct) DFA path — no
  // over-rejection.
  CHECK(Regex("\\w+").search("snake_case").str() == "snake_case");
  CHECK(Regex("\\d+").search("x 42 y").str() == "42");
}

void test_linear_time() {
  // `(a+)+$` against all-'a' + a trailing mismatch is the classic ReDoS bomb
  // that hangs backtracking engines. The Pike VM stays linear, so this must
  // complete near-instantly and report no match. We assert correctness (not a
  // hard time bound, to stay portable in CI) but also print the timing.
  Regex re("(a+)+$");
  std::string bomb(50000, 'a');
  bomb += 'X';
  auto t0 = std::chrono::steady_clock::now();
  bool matched = re.test(bomb);
  double dt = std::chrono::duration<double, std::milli>(
                  std::chrono::steady_clock::now() - t0)
                  .count();
  CHECK(!matched);
  std::printf("  [info] ReDoS bomb n=50000 completed in %.1f ms\n", dt);
}

void test_walk_budget_linearity() {
  // Candidate+verify prefilters (literal prefix / ReverseInner / icase prefix
  // / assert prefix / assert suffix / unbounded one-pass) re-verify from each
  // literal candidate. When the pattern's repeat can absorb its own candidate
  // byte, failed verifies re-walk overlapping tails — O(n^2) without the
  // failed-walk budget (kWalkBail), which bails to the linear machinery.
  // Assert correctness; print timings (no hard bound, CI-portable). Each case
  // would take minutes at these sizes if quadratic.
  struct Case {
    const char *name;
    const char *pat;
    std::string subj;
    size_t want;
  };
  std::vector<Case> cases;
  { // fused EGC prefix tier (capture-free, non-ASCII subject). The prefix
    // has to be one the plan keeps the find on — rare by the table, however
    // dense this subject makes it — or the suffix would drive instead.
    std::string s(200000, 'Z');
    s += "\xc3\xa9";
    CHECK(PlanProbe::anchor(Regex("Z[A-Z]+0")) == 'P');
    cases.push_back({"fused-prefix", "Z[A-Z]+0", s, 0});
  }
  { // the suffix driving from behind a literal prefix: the body absorbs the
    // suffix byte, so every failing reverse verify re-walks to the floor
    std::string s(1000, 'b');
    s += std::string(100000, '0');
    CHECK(PlanProbe::anchor(Regex("a[a-z0]+0")) == 'S');
    cases.push_back({"suffix-behind-prefix", "a[a-z0]+0", s + "\xc3\xa9", 0});
    cases.push_back({"suffix-bail-match", "a[a-z0]+0", s + " ab0\xc3\xa9", 1});
    cases.push_back({"suffix-bail-ascii", "a[a-z0]+0", s + " ab0", 1});
  }
  { // ReverseInner non-absorbing verify (the post part absorbs '=')
    std::string s;
    for (int i = 0; i < 100000; i++)
      s += "a=";
    cases.push_back({"inner-nonabsorbing", R"(\w+=[\w=]+\d)", s, 0});
  }
  { // (?i) prefix prefilter (non-ASCII subject; not decased: not a literal)
    std::string s(200000, 'a');
    s += "\xc3\xa9";
    cases.push_back({"icase-prefix", "(?i)a[a-z]+0", s, 0});
  }
  { // assert tier literal prefix (trailing $ makes it an assert pattern)
    cases.push_back({"assert-prefix", "#[#a-z]+0$", std::string(200000, '#'), 0});
  }
  { // assert tier suffix: failing reverse verifies re-walk to the floor
    std::string s = "Z" + std::string(1000, 'a');
    for (int i = 0; i < 30000; i++)
      s += "ing";
    cases.push_back({"assert-suffix", "(?m)^[a-z]+ing", s, 0});
  }
  { // unbounded one-pass prefix driver (captures)
    cases.push_back({"onepass-prefix", "a([a-z]+)0", std::string(200000, 'a'), 0});
  }
  { // budget exhaustion mid-subject must still find the later real match via
    // the linear fallback (correctness through the bail path)
    std::string s(100000, 'Z');
    s += "9ZB0\xc3\xa9";
    cases.push_back({"bail-then-match", "Z[A-Z]+0", s, 1});
  }
  { // capture chain: the right-side \S+ absorbs every later '=' anchor, so
    // each failed candidate re-walks the tail without the chain's budget
    std::string s;
    for (int i = 0; i < 70000; i++)
      s += "ab=";
    cases.push_back({"chain-capture", R"((\w+)=(\S+) (\w+))", s, 0});
  }
  { // suffix scalar verify: the absorb right-walk runs to the trailing
    // non-ASCII byte and bails to the DFA from EVERY "ing" occurrence
    std::string s;
    for (int i = 0; i < 70000; i++)
      s += "ing";
    s += "\xc3\xa9";
    cases.push_back({"suffix-absorb-bail", "[A-Z][a-z]+ing", s, 0});
  }
  { // the word scan: a body that runs on over spaces, so the walk from every
    // word's start reaches the same dead end. The words begin past the
    // scan's entry ramp, so it is the block scan the budget stops.
    const char *pat = R"(\b[a-c]+(?: [a-c]+)* [0-9]\b)";
    CHECK(PlanProbe::word_onepass(Regex(pat)) &&
          !PlanProbe::word_scan_after_anchor(Regex(pat)));
    std::string s = "-------- ";
    for (int i = 0; i < 200000; i++)
      s += "ab ";
    cases.push_back({"word-scan", pat, s + "ab.", 0});
    cases.push_back({"word-scan-bail-match", pat, s + "ab. ab 7", 1});
  }
  for (auto &c : cases) {
    Regex re(c.pat);
    auto t0 = std::chrono::steady_clock::now();
    size_t n = 0;
    for (auto m : re.find_all(c.subj))
      (void)m, n++;
    for (auto m : re.find_iter(c.subj))
      (void)m, n++;
    double dt = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0)
                    .count();
    CHECK(n == 2 * c.want);
    std::printf("  [info] walk-budget %-18s n=%zu completed in %.1f ms\n",
                c.name, c.subj.size(), dt);
  }

  // The assert prefilters again, over a FULL table (see
  // limits::kDfaCacheBytes; the cache's budget is shrunk to fill one in a few
  // dozen states). Every verify then leaves the DFA within a few bytes of
  // its candidate, for the uncached scan — which starts over, and walks as
  // far as the DFA would have. It is that walk the budget is charged:
  // charged for the DFA's few bytes, these never bail, and take minutes.
  {
    auto random_of = [](const char *alphabet, size_t n) {
      const size_t k = std::strlen(alphabet);
      std::string s;
      unsigned x = 12345;
      for (size_t i = 0; i < n; i++) {
        x = x * 1664525u + 1013904223u;
        s += alphabet[(x >> 16) % k];
      }
      return s;
    };
    const std::string ab = random_of("ab", 100000);
    const std::string abing = "Z" + random_of("abing", 100000);
    Case full[] = {
        // every `a` a candidate, every forward verify a walk to the end
        {"full-prefix", R"(a[ab]*a[ab]{12}\d\b)", ab, 0},
        {"full-prefix-byte", R"(a[ab]*a[ab]{12}\d\b)", ab + "\xc3\xa9", 0},
        // every `ing` a candidate, every reverse verify a walk to the floor
        {"full-suffix", "(?m)^[abing]{12}a[abing]*ing", abing, 0},
        {"full-suffix-byte", "(?m)^[abing]{12}a[abing]*ing",
         abing + "\xc3\xa9", 0},
    };
    for (auto &c : full) {
      Regex re(c.pat);
      Regex::FindCache fc;
      PlanProbe::dfa_cache(re, fc, size_t{64} << 10, 3);
      auto t0 = std::chrono::steady_clock::now();
      size_t n = 0;
      for (auto m : re.find_all(c.subj, fc))
        (void)m, n++;
      double dt = std::chrono::duration<double, std::milli>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
      CHECK(n == c.want);
      const auto st = PlanProbe::dfa_stats(fc);
      CHECK(st.clears > 0 || st.quit);
      std::printf("  [info] walk-budget %-18s n=%zu completed in %.1f ms\n",
                  c.name, c.subj.size(), dt);
    }
  }
}

// The one-pass walk tiers must be exactly leftmost-first, not longest-match.
// Two ways the old "greedy walk == leftmost-first" lemma failed: adjacent
// nullable greedy repeats commit BEFORE the longest accept ((x)(?:ab)?(?:abc)?
// on "xabc" ends at 3, not 4 — fixed by the leftmost-first cut in
// build_cp_onepass), and a trailing \b checked only at the last accept drops
// matches whose shorter accept satisfies it (fixed by the accepting-state
// word-only-outgoing admission in plan_word_onepass). Subjects are padded:
// on tiny subjects the failed-walk budget exhausts and falls back to the
// (correct) assert chain, masking the defect.
// Regressions for the scalar forced-parse tiers (suffix chain / class
// anchors / capture chain). Each was a confirmed wrong-result bug: subjects
// are padded past the walk budget per the masking lesson, and every pattern
// is checked against a Pike-forced twin (a lookahead defeats every prefilter
// tier) on spans AND group spans.
void test_scalar_chain_soundness() {
  auto spans_agree = [](const Regex &bare, const Regex &pike,
                        const std::string &subj) {
    auto a = find_all(bare, subj), b = find_all(pike, subj);
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
      if (a[i].begin() != b[i].begin() || a[i].end() != b[i].end())
        return false;
      for (size_t g = 1; g <= 4; g++) { // past ngroups -> unmatched in both
        reg::Match ga = a[i].group(g), gb = b[i].group(g);
        if (ga.matched() != gb.matched()) return false;
        if (ga.matched() &&
            (ga.begin() != gb.begin() || ga.end() != gb.end()))
          return false;
      }
    }
    return true;
  };
  auto ok = [&](const std::string &pat, const std::string &subj) {
    Regex bare(pat);
    Regex pike = pike_twin(pat);
    return spans_agree(bare, pike, subj);
  };
  const std::string pad(4096, 'q');

  // Class-anchor end rule: overlapping anchor classes let the greedy parse
  // slide one byte past the scanned adjacency ([ab]+[bc][cd] on "abcd" must
  // be "abcd", not "abc"). Such patterns are now rejected at admission and
  // must answer through the DFA identically to the Pike.
  {
    Regex re("[ab]+[bc][cd]");
    auto m = re.search("xabcd.");
    CHECK(m.matched() && m.str() == "abcd");
    auto m2 = re.search("aabcd");
    CHECK(m2.matched() && m2.str() == "aabcd");
    CHECK(ok("[ab]+[bc][cd]", pad + "xabcd." + pad));
    CHECK(ok("[ab]+[bc][cd]", pad + "abccd abcd aabcc" + pad));
    // The motivating class-anchor shape must still work (disjoint classes).
    CHECK(ok("[\"'][^\"']{0,30}[?!.][\"']",
             pad + " \"Quite so!\" he said. 'why?' " + pad));
  }

  // Transitive min==0 adjacency: with BOTH middle repeats empty the two
  // [ad]+ runs touch, the right one stole the whole run and the match was
  // silently missed.
  {
    std::string subj = pad + "aaax" + pad;
    Regex re("[ad]+[b]*[c]*[ad]+x");
    auto m = re.search(subj);
    CHECK(m.matched() && m.str() == "aaax");
    CHECK(ok("[ad]+[b]*[c]*[ad]+x", subj));
    CHECK(ok("[ad]+[b]*[c]*[ad]+x", pad + "adbcadx dax abcx" + pad));
  }

  // Capture chain: spans AND group spans must agree with the Pike on dense,
  // adversarial and bail-path subjects.
  {
    std::string dense;
    for (int i = 0; i < 500; i++)
      dense += "key" + std::to_string(i) + "=value" + std::to_string(i) + " ";
    CHECK(ok("(\\w+)=(\\S+)", dense));
    CHECK(ok("(\\w+)=(\\S+)", pad + "a=b" + pad));
    // Non-ASCII near a candidate: the chain bails per call and the automaton
    // drivers must produce the same answer.
    CHECK(ok("(\\w+)=(\\S+)", "x=\xc3\xa9y a=b"));
    // Chain-only reachability: a counted repeat handled natively by the
    // chain regardless of one-pass admission; search() and find_all() answer
    // through the same dispatch.
    Regex cnt("([a-z]{2,4})=([0-9]+)");
    auto m = cnt.search(pad + " abcdef=123 " + pad);
    CHECK(m.matched() && m.group(1).str() == "cdef" &&
          m.group(2).str() == "123");
    CHECK(ok("([a-z]{2,4})=([0-9]+)", pad + " abcdef=123 ab=9 " + pad));
  }
}

void test_onepass_leftmost_first() {
  const std::string pad(4096, ' ');
  { // unbounded one-pass capture find (prefix driver), match(), iterator
    Regex re(R"((x)(?:ab)?(?:abc)?)");
    auto m = re.search("xabc");
    CHECK(m.matched() && m.begin() == 0 && m.end() == 3 &&
          m.group(1).str() == "x");
    auto mm = re.match("xabc");
    CHECK(mm.matched() && mm.end() == 3);
    auto all = find_all(re, "xabc");
    CHECK(all.size() == 1 && all[0].end() == 3); // "xab"; no x remains after
    size_t k = 0, e0 = 0;
    const std::string subj = "xabc";
    for (auto it : re.find_iter(subj)) {
      if (k == 0) e0 = it.end();
      k++;
    }
    CHECK(k == 1 && e0 == 3);
  }
  { // A repeat that can run MORE THAN ONCE over a VARIABLE-width body has an
    // accept per iteration count, and the walk's last accept is then the
    // LONGEST parse, not the leftmost-first one. `(?:[a-cb].{0,4})+` over
    // "bbc 23_\n_2" is [0,5) (one iteration, `.{0,4}` greedy); the walk
    // reported [0,7) (a shorter first iteration letting a second run). This
    // shipped in AnchoredOnePass, whose `^body` table is built with the same
    // cut, so the anchored form was wrong on the released engine.
    const std::string subj = "bbc 23_\n_2";
    struct { const char *pat; size_t b, e; } cases[] = {
        {R"(^(?:[a-cb].{0,4})+)", 0, 5},   // AnchoredOnePass (was [0,7))
        {R"((?:[a-cb].{0,4})+)", 0, 5},    // unanchored capture-free
        {R"(^(?:a.{0,2})+)", 0, 0},        // control: no match at 0 here
        {R"((?:[a-cb].{0,4})+$)", 0, 0},   // body$ admission, same body
    };
    for (auto &c : cases) {
      for (int us = 0; us < 2; us++) {
        Regex re = us ? make_us(c.pat) : make_egc(c.pat);
        auto m = re.search(subj);
        if (c.e == 0) continue; // shape kept only to exercise the admission
        CHECK(m.matched() && m.begin() == c.b && m.end() == c.e);
        CHECK(re.test(subj) == m.matched());
        auto all = find_all(re, subj);
        CHECK(!all.empty() && all[0].begin() == c.b && all[0].end() == c.e);
      }
    }
    // A repeat that can be SKIPPED, of several instructions, behind a
    // variable-width one: a thread that left the earlier repeat sooner sits
    // inside it at a LOWER pc than the higher-priority thread that stayed,
    // skipped it and moved on, so the cut (which walks entries in pc order)
    // keeps it, and its later accept wins. All three were wrong on the
    // released engine, on every find surface, and agreed with one another —
    // the spans are asserted outright.
    {
      struct { const char *pat, *subj; size_t b, e; } skip[] = {
          {R"([a-z]{3,}(?:\w{2}-)?s)", "hssys-s", 0, 5},          // was [0,7)
          {R"(s[a-z]{3,}(?:\w{2}[^\n]*)?s)", "shssys-s", 0, 6},   // was [0,8)
          {R"(x(?:ab)?(?:abc)?[a-z])", "xabcd", 0, 4},            // was [0,5)
          {R"(\bx(?:ab)?(?:abc)?[a-z])", "xabcd", 0, 4},          // WordOnePass
          {R"(^x(?:ab)?(?:abc)?[a-z])", "xabcd", 0, 4},           // AnchoredOnePass
          // Still admitted, and still right: nothing but nullable constructs
          // follows the repeat, or no earlier atom can read its first byte.
          {R"(x(?:ab)?(?:abc)?)", "xabc", 0, 3},
          {R"([a-z]+(?:ing)?)", "singing ", 0, 7},
          {R"(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?x)", "3.14e-10x", 0, 9},
          {R"(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?x)", "3.1x", 0, 4},
      };
      for (auto &c : skip)
        for (int us = 0; us < 2; us++)
          for (int padded = 0; padded < 2; padded++) {
            Regex re = us ? make_us(c.pat) : make_egc(c.pat);
            // Padded past the walk budget, as above: on a short subject a
            // couple of failed candidates hand the find to the chain. (Not
            // for the `^` row: the pad would move the only candidate.)
            if (padded && c.pat[0] == '^') continue;
            const std::string subj =
                std::string(c.subj) + (padded ? "\n" + pad : "");
            auto m = re.search(subj);
            CHECK(m.matched() && m.begin() == c.b && m.end() == c.e);
            auto all = find_all(re, subj);
            CHECK(!all.empty() && all[0].begin() == c.b &&
                  all[0].end() == c.e);
            size_t k = 0;
            for (auto it : re.find_iter(subj)) {
              if (k++ == 0) CHECK(it.begin() == c.b && it.end() == c.e);
            }
            CHECK(k == all.size());
          }
    }
    // Fixed-width bodies stay admitted (the wins this guard must not undo).
    CHECK(make_us(R"([A-Za-z_]\w*)").search("  getElementById").end() == 16);
    CHECK(make_us(R"(//[^\n]*)").search("x // c").end() == 6);
    CHECK(make_us(R"(\d+(?:\.\d+)?)").search("v3.14").end() == 5);
    // The same lemma on the THIRD tier that reads a cut table's last accept:
    // WordOnePass without a trailing `\b`. It needs three top-level elements,
    // so a bare `\b<repeat>` never reached it and the first fix missed it —
    // `\b(?:[a-cb].{0,4})+x?` read [0,7) here on the released engine.
    // scan_diff cannot see this one: every surface shares the tier and they
    // agree with each other while all being wrong, so the spans are asserted
    // outright (against std::regex ECMAScript, which is leftmost-first).
    struct { const char *pat; size_t b, e; } wop[] = {
        {R"(\b(?:[a-cb].{0,4})+x?)", 0, 5},
        {R"(\b(?:[a-cb].{0,4})+z?)", 0, 5},
        {R"(\b(?:[a-c].{0,4})+[0-9]?)", 0, 6},
        {R"(\b(?:\w\w.?)+x?)", 0, 3},
        {R"(\b(?:[a-c]x?y?)+\b)", 0, 3}, // trailing `\b`: uncut, unaffected
    };
    for (auto &c : wop) {
      for (int us = 0; us < 2; us++) {
        Regex re = us ? make_us(c.pat) : make_egc(c.pat);
        auto m = re.search(subj);
        CHECK(m.matched() && m.begin() == c.b && m.end() == c.e);
        auto all = find_all(re, subj);
        CHECK(!all.empty() && all[0].begin() == c.b && all[0].end() == c.e);
      }
    }
  }
  { // Alternation under a table built UNCUT. `^body$` reads accept == n and
    // WordOnePass reads the accept its trailing `\b` allows, so the end is
    // forced and thread priority never enters — the cut's Alt-free rule does
    // not apply and these shapes belong on the one walk. They had been taking
    // the assert DFA: test() on `^(a|aa)+$` over 30 a's measured 574 ns
    // against 36 with the walk (-O3 -DNDEBUG, median of 25x200 calls, US).
    struct { const char *pat, *subj; size_t b, e; int g1b, g1e; } cases[] = {
        {R"(^(a|aa)+$)", "aaaa", 0, 4, 3, 4},
        {R"(^(?:a|a)*$)", "aaaa", 0, 4, -1, -1},
        {R"(^(?:abc|ab|a)+$)", "abcab", 0, 5, -1, -1},
        {R"(^(\w|\d\d)+$)", "a1b", 0, 3, 2, 3},
        {R"((?:a|ab)+$)", "xxabab", 2, 6, -1, -1},
        {R"(\b\w+(?:ab|cd)\b)", "zz qqcd rr", 3, 7, -1, -1},
        {R"(^(a|aa)+)", "aaaa", 0, 4, 3, 4}, // the cut twin: still barred
    };
    for (auto &c : cases) {
      for (int us = 0; us < 2; us++) {
        Regex re = us ? make_us(c.pat) : make_egc(c.pat);
        auto m = re.search(c.subj);
        CHECK(m.matched() && m.begin() == c.b && m.end() == c.e);
        CHECK(re.test(c.subj));
        if (c.g1b >= 0)
          CHECK(m.group(1).matched() &&
                m.group(1).begin() == static_cast<size_t>(c.g1b) &&
                m.group(1).end() == static_cast<size_t>(c.g1e));
        auto all = find_all(re, c.subj);
        CHECK(!all.empty() && all[0].begin() == c.b && all[0].end() == c.e);
      }
    }
    // A failing input must still fail (the accept-at-n condition is what the
    // uncut table is read through).
    for (int us = 0; us < 2; us++) {
      Regex re = us ? make_us(R"(^(a|aa)+$)") : make_egc(R"(^(a|aa)+$)");
      CHECK(!re.search("aaab").matched() && !re.test("aaab"));
      CHECK(!re.search(std::string(30, 'a') + "!").matched());
    }
  }
  { // Capture-free find_all AND find_iter take the same one-walk driver, so
    // all three entry points must report the same rows. The long-line subject
    // is the shape the tier exists for (each match is a whole line, where the
    // located-span chain walks it twice), and the non-ASCII one forces the
    // walk to bail mid-subject: the rows found before the bail are kept and
    // the chain continues from there, which is where a resume bug would show
    // up as a dropped or duplicated match.
    const std::string lines =
        std::string(1000, 'a') + "\n" + std::string(999, 'b') + "\n" + "c";
    const std::string mixed =
        "alpha beta \xc3\xa9 gamma delta " + std::string(600, 'z');
    for (int us = 0; us < 2; us++) {
      for (const char *pat : {R"(\w+)", R"([^\n]+)", R"([a-z]+)"}) {
        Regex re = us ? make_us(pat) : make_egc(pat);
        for (const std::string *s : {&lines, &mixed}) {
          auto all = find_all(re, *s);
          // find_iter must agree row for row with find_all
          size_t i = 0;
          for (auto it : re.find_iter(*s)) {
            CHECK(i < all.size() && it.begin() == all[i].begin() &&
                  it.end() == all[i].end());
            i++;
          }
          CHECK(i == all.size());
          // and search() must be find_all's first row
          auto m = re.search(*s);
          CHECK(m.matched() == !all.empty());
          if (!all.empty())
            CHECK(m.begin() == all[0].begin() && m.end() == all[0].end());
          CHECK(re.test(*s) == m.matched());
          // every row is non-empty, in order, and non-overlapping
          size_t prev = 0;
          for (size_t k = 0; k < all.size(); k++) {
            CHECK(all[k].end() > all[k].begin() && all[k].begin() >= prev);
            prev = all[k].end();
          }
        }
      }
    }
  }
  { // CAPTURE-FREE US search() takes the same drivers, for the span alone
    // (saves 0/1). Every answer must equal what the located-span chain gives,
    // so each case is checked against find_all's first row - the chain still
    // serves find_all - and against test().
    const std::string long_pad(4096, 'x');
    struct { const char *pat; std::string subj; size_t b, e; } cases[] = {
        {R"([A-Za-z_]\w*)", "  getElementById()", 2, 16},
        {R"(//[^\n]*)", "x = 1; // trailing\nnext", 7, 18},
        {R"(/users/\d+)", "GET /users/123456 HTTP", 4, 17},
        {R"(\d+(?:\.\d+)?)", "v3.14159x", 1, 8},
        // the walk's own run-skip must not overshoot the leftmost match
        {R"(\w+)", "  ab cd", 2, 4},
        // no match: the driver must report it definitively, not fall through
        {R"([A-Za-z_]\w*)", "1234 5678", 0, 0},
        // long subject: the walk is O(match), the chain was O(subject) twice
        {R"([A-Za-z_]\w*)", long_pad + " tail", 0, 4096},
    };
    for (auto &c : cases) {
      Regex re = make_us(c.pat);
      auto m = re.search(c.subj);
      auto all = find_all(re, c.subj);
      if (c.b == 0 && c.e == 0) {
        CHECK(!m.matched() && all.empty() && !re.test(c.subj));
      } else {
        CHECK(m.matched() && m.begin() == c.b && m.end() == c.e);
        CHECK(!all.empty() && all[0].begin() == c.b && all[0].end() == c.e);
        CHECK(re.test(c.subj));
      }
    }
    // Non-ASCII bails the walk to the chain; both must agree, and a match
    // starting after the non-ASCII byte is the case the bail must not lose.
    Regex re_na = make_us(R"([A-Za-z_]\w*)");
    const std::string na = "\xc3\xa9 abc";
    auto m_na = re_na.search(na);
    CHECK(m_na.matched() && m_na.begin() == 3 && m_na.end() == 6);
    CHECK(find_all(re_na, na).size() == 1);
  }
  { // US (CodePoint) mode routes through the same drivers
    Regex re = make_us(R"((x)(?:ab)?(?:abc)?)");
    auto m = re.search("xabc");
    CHECK(m.matched() && m.end() == 3);
  }
  { // A walk table of more states than sixteen bits could number rows for:
    // a state is the offset of its row, in bytes. The `^body` tier in
    // both units, and the `\b body` one.
    for (auto unit : {reg::MatchUnit::Grapheme, reg::MatchUnit::CodePoint}) {
      const Regex re(R"(^[0-9]{600}x?$)", 0, unit);
      CHECK(PlanProbe::walk_states(re, /*word=*/false) > 600);
      const std::string d(600, '7');
      CHECK(re.test(d) && re.test(d + "x") && re.search(d).end() == 600);
      CHECK(!re.test(d + "7") && !re.test(d.substr(1)) && !re.test(d + "xx"));
      CHECK(!re.test(std::string(599, '7') + "a"));
    }
    const Regex word(R"(\b[0-9]{600}\b)");
    CHECK(PlanProbe::walk_states(word, /*word=*/true) > 600);
    const std::string d(600, '7'), s = "x " + d + " " + d + "7 " + d + ".";
    CHECK(finds_agree(word, {2, 602, 1205, 1805}, s));
  }
  { // The capture walk's table at the same size: a step holds its next
    // state as an offset in bytes, and 600 states are 1.5 MB of them.
    for (auto unit : {reg::MatchUnit::Grapheme, reg::MatchUnit::CodePoint}) {
      const Regex re(R"(^([0-9]{600})(x?)$)", 0, unit);
      CHECK(PlanProbe::onepass_slots(re) > 0);
      const std::string d(600, '7');
      CHECK(finds_agree(re, {0, 601, 0, 600, 600, 601}, d + "x"));
      CHECK(finds_agree(re, {0, 600, 0, 600, 600, 600}, d));
      CHECK(finds_agree(re, {}, d + "7") && finds_agree(re, {}, d + "xx"));
    }
  }
  { // AnchoredOnePass `^body` (no $): cut table -> leftmost-first end
    Regex re(R"(^x(?:ab)?(?:abc)?)");
    auto m = re.search("xabc");
    CHECK(m.matched() && m.begin() == 0 && m.end() == 3);
    CHECK(re.match("xabc").end() == 3);
    CHECK(re.test("xabc") && !re.test("yabc"));
    // grapheme cluster right after the would-be end: the walk bails to the
    // (cluster-aware) ladder instead of reporting a mid-cluster end —
    // 'b'+combining is one cluster, so neither optional matches: end == 1
    CHECK(re.match("xab\xcc\x81 tail").end() == 1);
  }
  { // EGC fuses CR-LF into one cluster: a CRLF-splitting pattern's byte walk
    // must bail on '\r' (fuzz 0xC0FFEE repro: [^a-ca] consumes the WHOLE
    // \r\n cluster in EGC, so \w+ starts at 'A' — the byte walk would die on
    // the lone '\n' and wrongly report no match from match()/test())
    Regex re(R"(^[^a-ca]\w+)");
    std::string s = "\r\nAB2AB\r";
    auto m = re.search(s);
    CHECK(m.matched() && m.begin() == 0 && m.end() == 7);
    CHECK(re.test(s) == m.matched());
    CHECK(re.match(s).matched() && re.match(s).end() == 7);
  }
  { // `^body$` (require_end): the FULL accept set must still reach n
    Regex re(R"(^x(?:ab)?(?:abc)?$)");
    auto m = re.search("xabc");
    CHECK(m.matched() && m.begin() == 0 && m.end() == 4);
    CHECK(re.match("xabc").matched());
    CHECK(re.search("xab").matched()); // the shorter parse also reaches $
    CHECK(re.test("xabc") && re.test("xab") && !re.test("xa") &&
          !re.test("xabcz"));
  }
  { // body$ capture one-pass (require_end): accept-at-n picks the $-end
    Regex re(R"((x)(?:ab)?(?:abc)?$)");
    auto m = re.search("xabc");
    CHECK(m.matched() && m.end() == 4 && m.group(1).str() == "x");
  }
  { // `^body$` WITH captures (the validate-and-extract shape): one one-pass
    // walk from 0 yields the end and the groups, in both modes and at every
    // entry point — and every no-match (wrong char, short, trailing junk)
    // is decided by the same walk / the capture-stripped AnchoredOnePass.
    for (int us = 0; us < 2; us++) {
      // Pin the unit on BOTH legs: a bare Regex would build in whatever the
      // ambient default happens to be, so the "EGC" half would only be EGC by
      // convention.
      auto make = [&](const char *p) { return us ? make_us(p) : make_egc(p); };
      Regex re = make(R"(^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$)");
      const std::string ok = "2026-06-08T12:34";
      auto m = re.search(ok);
      CHECK(m.matched() && m.begin() == 0 && m.end() == ok.size() &&
            m.group(1).str() == "2026" && m.group(3).str() == "08" &&
            m.group(5).str() == "34");
      auto mm = re.match(ok);
      CHECK(mm.matched() && mm.end() == ok.size() &&
            mm.group(2).str() == "06" && mm.group(4).str() == "12");
      CHECK(re.test(ok));
      auto all = find_all(re, ok);
      CHECK(all.size() == 1 && all[0].group(5).str() == "34");
      size_t k = 0;
      for (auto it : re.find_iter(ok)) {
        CHECK(it.group(1).str() == "2026");
        k++;
      }
      CHECK(k == 1);
      for (const char *bad : {"2026-06-08T12:3", "2026-06-08T12:345",
                              "x026-06-08T12:34", "2026-06-08 12:34", ""}) {
        CHECK(!re.test(bad));
        CHECK(!re.search(bad).matched());
        CHECK(!re.match(bad).matched());
        CHECK(find_all(re, bad).empty());
      }
      // Not at 0 -> not a match (the anchor); the padded tail keeps the
      // walk budget from masking a driver that scans past 0.
      const std::string shifted = " " + ok + pad;
      CHECK(!re.test(shifted) && !re.search(shifted).matched());
      // Non-ASCII in the subject: the walk bails to the chain, which must
      // agree with the ASCII answer on the same shape.
      const std::string nonascii = "2026-06-08T12:3\xc3\xa9";
      CHECK(!re.test(nonascii) && !re.search(nonascii).matched());
      Regex re2 = make(R"(^(\S+)@(\S+)$)");
      auto m2 = re2.search("caf\xc3\xa9@x.\xc3\xa9");
      CHECK(m2.matched() && m2.group(1).str() == "caf\xc3\xa9" &&
            m2.group(2).str() == "x.\xc3\xa9");
      CHECK(re2.test("caf\xc3\xa9@x.\xc3\xa9") && !re2.test("caf\xc3\xa9@ "));
    }
  }
  { // `^body` (no $) WITH captures: the capture-stripped AnchoredOnePass
    // walk decides every no-match; a match falls to the ladder for the
    // groups, and all entry points agree on the leftmost-first end.
    Regex re(R"(^(x)(?:ab)?(?:abc)?)");
    auto m = re.search("xabc");
    CHECK(m.matched() && m.begin() == 0 && m.end() == 3 &&
          m.group(1).str() == "x");
    CHECK(re.match("xabc").end() == 3 && re.match("xabc").group(1).str() == "x");
    CHECK(re.test("xabc") && !re.test("yabc") && !re.match("yabc").matched());
    CHECK(find_all(re, "xabc").size() == 1);
    // grapheme cluster right after the would-be end (see the ncap == 0 twin
    // above): the walk bails; the ladder reports the cluster-aware end.
    CHECK(re.match("xab\xcc\x81 tail").end() == 1);
  }
  { // ReDoS shapes with a capture. `^(a+)+$` / `^(\d+)*$` get the compact walk
    // for the miss (previously the assert DFA — captures barred the table);
    // `^(a|aa)+$` holds an Alt, which onepass_body_ok rejects, so it stays on
    // the assert chain — it is here to keep the two tiers answering alike.
    // The hit still resolves its group; test()/search()/match() agree.
    for (const char *p : {R"(^(a+)+$)", R"(^(a|aa)+$)", R"(^(\d+)*$)"}) {
      Regex re(p);
      const std::string miss = std::string(28, 'a') + "!";
      CHECK(!re.test(miss) && !re.search(miss).matched() &&
            !re.match(miss).matched());
    }
    Regex re(R"(^(a+)+$)");
    const std::string hit(28, 'a');
    auto m = re.search(hit);
    CHECK(m.matched() && m.end() == 28 && m.group(1).matched());
    CHECK(re.test(hit) && re.match(hit).matched());
  }
  { // Trailing-\b bodies whose accepting states continue on a non-word byte
    // must reject the WordOnePass shortcut and take the assert chain, which
    // backtracks to the shorter accept. test()/search() must agree.
    Regex re(R"(\b(?:a\.)+a\b)");
    std::string s = "a.a.aX" + pad;
    auto m = re.search(s);
    CHECK(m.matched() && m.begin() == 0 && m.end() == 3); // "a.a"
    CHECK(re.test(s));
    CHECK(find_all(re, s).size() == 1);

    Regex re2(R"(\ba+[.]*a+\b)");
    std::string s2 = "aa.aab" + std::string(4096, ';');
    auto m2 = re2.search(s2);
    CHECK(m2.matched() && m2.begin() == 0 && m2.end() == 2); // "aa"
    CHECK(re2.test(s2));

    Regex re3(R"(\b[0-9]+\.?[0-9]+\b)");
    std::string s3 = "12.34x" + pad + "99 end";
    auto m3 = re3.search(s3);
    CHECK(m3.matched() && m3.begin() == 0 && m3.end() == 2); // "12"
  }
  { // WordOnePass stays admitted for word-only-accept bodies (IPv4)
    Regex re(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)");
    std::string s = "ip 10.0.0.1 and 192.168.10.255." + pad;
    auto all = find_all(re, s);
    CHECK(all.size() == 2 && all[0].str() == "10.0.0.1" &&
          all[1].str() == "192.168.10.255");
  }
  { // WordOnePass without a trailing \b: leftmost-first end via the cut table
    Regex re(R"(\bx(?:ab)?(?:abc)?)");
    std::string s = "xabc " + pad;
    auto m = re.search(s);
    CHECK(m.matched() && m.begin() == 0 && m.end() == 3);
  }
}

// A trailing `$` (`body$`) is the one pattern shape whose one-pass walk can
// ACCEPT somewhere the caller rejects — the require_end plan demands the accept
// land at n — so every driver, every entry point and both match units have to
// agree about a rejected accept. Neither the suite nor the differential dump
// had a single trailing-`$` pattern until this function; the throughput bench's
// `(\d{3}) (\d+)$` row matches nothing, so a wrong none read as a win there.
//
// Each case asserts the four public entry points against each other: search()
// is find_all()'s first row, test() is "find_all is non-empty", and find_iter()
// (lazy) is find_all() (eager). A tier that serves only one of them — as the
// iterator's byte-assert rung once did — shows up here and nowhere else.
void test_body_dollar() {
  // spans + group 1 of every match, from all four entry points; they must be
  // one answer. Returns find_all's rows for the caller to check against the
  // pattern's obvious meaning.
  auto rows = [](const Regex &re, const std::string &s) {
    std::vector<std::string> all, iter;
    for (auto m : re.find_all(s))
      all.push_back(std::to_string(m.begin()) + "," + std::to_string(m.end()) +
                    "=" + std::string(m.group(1).str()));
    for (auto m : re.find_iter(s))
      iter.push_back(std::to_string(m.begin()) + "," + std::to_string(m.end()) +
                     "=" + std::string(m.group(1).str()));
    CHECK(all == iter);
    CHECK(re.test(s) == !all.empty());
    auto one = re.search(s);
    CHECK(one.matched() == !all.empty());
    // !all.empty() too: CHECK records and returns, so on the very divergence
    // this function hunts (search matches, find_all does not) the line above
    // reports and execution continues into all[0].
    if (one.matched() && !all.empty())
      CHECK(all[0] == std::to_string(one.begin()) + "," +
                          std::to_string(one.end()) + "=" +
                          std::string(one.group(1).str()));
    return all;
  };
  // The shapes from the original report, in both units. Padding puts the match
  // past WalkBudget's kMinScan window, where a driver that bails behaves
  // differently from one that does not (see test_onepass_leftmost_first).
  const std::string pad(4096, ' '), qpad(4096, 'q');
  for (const std::string &lead : {std::string(), pad, qpad}) {
    const size_t k = lead.size();
    for (int us = 0; us < 2; us++) {
      auto re = [&](const char *p) { return us ? make_us(p) : make_egc(p); };
      { // the reported case: only the LAST group of digits reaches $
        auto v = rows(re(R"((\d{3}) (\d+)$)"), lead + "123 456 789 000");
        CHECK(v.size() == 1 && v[0] == std::to_string(k + 8) + "," +
                                           std::to_string(k + 15) + "=789");
      }
      { // the greedy run from the first word ends short of n and is rejected
        auto v = rows(re(R"((\w+)$)"), lead + "aa bb");
        CHECK(v.size() == 1 && v[0] == std::to_string(k + 3) + "," +
                                           std::to_string(k + 5) + "=bb");
      }
      { // two greedy runs, the leftmost start that still reaches n
        auto v = rows(re(R"((a+)(b+)$)"), lead + "ab aabb");
        CHECK(v.size() == 1 && v[0] == std::to_string(k + 3) + "," +
                                           std::to_string(k + 7) + "=aa");
      }
      { // dense candidates, none of which reach n but the last
        auto v = rows(re(R"((\w+) (\d+)$)"), lead + "aa 11 bb 22 cc 33");
        CHECK(v.size() == 1 && v[0] == std::to_string(k + 12) + "," +
                                           std::to_string(k + 17) + "=cc");
      }
      { // a body$ that matches nothing: every candidate accepts short of n
        CHECK(rows(re(R"((\d+)$)"), lead + "12 34 xy").empty());
      }
      // \z is the same hard text anchor as a non-multiline $: the same row
      CHECK(rows(re(R"((\w+)\z)"), lead + "aa bb") ==
            std::vector<std::string>{std::to_string(k + 3) + "," +
                                     std::to_string(k + 5) + "=bb"});
    }
  }
  { // Regression: the iterator's byte-assert rung served EGC capture patterns
    // on a non-ASCII subject, a tier search() and find_all() reserve for
    // capture-FREE patterns (assert_cap_ compiles for an ASCII subject only).
    // A subject ending in a lone UTF-8 lead byte is where the two engines part:
    // the grapheme engine gives the invalid byte its own cluster and matches,
    // the byte automaton wants a continuation byte and does not — so find_iter
    // reported no match where search() and find_all() reported one.
    for (const char *pat : {R"(([^ ]+)$)", R"((\w+)$)", R"((.)$)"}) {
      Regex re = make_egc(pat);
      const std::string s = "ab\xc3"; // \xc3 with no continuation byte
      CHECK(rows(re, s).size() == 1);
      CHECK(rows(re, std::string(4096, 'q') + " ab\xc3").size() == 1);
    }
  }
  { // Regression: a Multiline anchor binds AT the line terminator, i.e. BETWEEN
    // the CR and the LF of a cluster the grapheme engine cannot break — so it
    // must clear crlf_byte_safe_, which admits CRLF subjects to the byte and
    // assert tiers. "ab\r\n01 x\r\n" has ONE match ($ at end of text, the
    // trailing cluster): the byte engine saw two and stopped `\s+` inside the
    // first cluster, and an alternation form returned none at all.
    const std::string s = "ab\r\n01 x\r\n";
    for (const char *pat : {R"((?m)(\s+)$)", R"((?m)(\s+)$|zq)",
                            R"((?m)zq|(\s+)$)", R"((?m)[abc]*(\s+)[abc]*$)"}) {
      // The group is the WHOLE trailing cluster: the byte engine stopped `\s+`
      // inside it, so pinning the span alone would not have caught that.
      CHECK(rows(make_egc(pat), s) ==
            std::vector<std::string>{"8,10=\r\n"});
    }
    // Without Multiline the anchors are text anchors and CRLF safety stands —
    // and the answer is the same row, not merely "some row".
    CHECK(rows(make_egc(R"((\s+)$)"), s) ==
          std::vector<std::string>{"8,10=\r\n"});
  }
  { // The same divergence at its smallest, on a PURE-ASCII CRLF subject (the
    // ASCII assert tier, which is where the extra anchor positions live — a
    // non-ASCII subject takes the byte tier, whose kCtxPrevCR already excludes
    // the cluster interior). "a\r\nb" is a=0 \r=1 \n=2 b=3.
    const std::string s = "a\r\nb";
    // Before the fix this matched [2,4) — a match STARTING inside the cluster.
    CHECK(rows(make_egc(R"((?m)^([^a]+)$)"), s) ==
          std::vector<std::string>{"3,4=b"});
    // Before the fix this matched [1,2) — the CR alone, splitting the cluster.
    CHECK(rows(make_egc(R"((?m)(\s+)$)"), s).empty());
    // Before the fix: [2,3) and [5,6), both cluster interiors.
    CHECK(rows(make_egc(R"((?m)^([^ ]+))"), " \r\n \r\n").empty());
    // A crlf_inert pattern keeps the fast tiers AND the right answer: `\w`
    // refuses \r and \n, so no match can reach a cluster interior.
    CHECK(rows(make_egc(R"((?m)^(\w+))"), "ab\r\ncd") ==
          (std::vector<std::string>{"0,2=ab", "4,6=cd"}));
  }
  { // A parser-fused CR-LF LITERAL is the other half of the same asymmetry:
    // the byte programs match it as its own two bytes (which is why
    // crlf_byte_safe admits the pair, and why the byte tiers keep it), but the
    // grapheme programs hold it as ONE two-code-point unit that a byte-stepping
    // DFA cannot consume at all — so ascii_grapheme_ok must not route such a
    // pattern onto them for a CRLF subject. "x\r\n" is x=0 \r=1 \n=2.
    const std::string s = "x\r\n";
    CHECK(rows(make_egc(R"(\r\n$)"), s) ==
          std::vector<std::string>{"1,3="});          // was no-match
    CHECK(rows(make_egc(R"(\r\n\z)"), s) ==
          std::vector<std::string>{"1,3="});          // was no-match
    CHECK(rows(make_egc(R"(x\r\n$)"), s) ==
          std::vector<std::string>{"0,3="});          // was no-match
    // The capture form split the entry points instead of failing outright:
    // search / find_all / find_iter matched [1,3) and test() said no.
    CHECK(rows(make_egc(R"((\r\n)$)"), s) ==
          (std::vector<std::string>{"1,3=\r\n"}));
    // The literal need not end the match, and the anchor need not be `$`.
    CHECK(rows(make_egc(R"(\r\nz$)"), "x\r\nz") ==
          std::vector<std::string>{"1,4="});          // was no-match
    // A non-multiline `$` is EndText, so a cluster that is not at the end does
    // NOT match — the fix must not turn that into a false positive.
    CHECK(rows(make_egc(R"(\r\n$)"), "x\r\ny").empty());
    // Controls that were always right and must stay right: no anchor at all,
    // and a class (matched by the cluster's base code point) instead of a
    // literal.
    CHECK(rows(make_egc(R"(\r\n)"), s) == std::vector<std::string>{"1,3="});
    CHECK(rows(make_egc(R"([\r\n]+$)"), s) ==
          std::vector<std::string>{"1,3="});
    // An assert pattern has no byte_path_, so it cannot take egc_byte_path's
    // pure-ASCII CRLF rung; assert_byte_path_ok grows the matching one, or
    // these fall to the grapheme Pike over the whole subject. Drive that on a
    // real-sized pure-ASCII header block so the routing, not just the answer,
    // is exercised — and check the LAST match, which is where a tier that
    // cannot consume the fused literal stops early.
    {
      std::string hdr;
      for (int i = 0; i < 400; i++) hdr += "Header-Name: value\r\n";
      const size_t n = hdr.size();
      auto tail = rows(make_egc(R"(\r\n$)"), hdr);
      CHECK(tail == std::vector<std::string>{std::to_string(n - 2) + "," +
                                             std::to_string(n) + "="});
      CHECK(rows(make_egc(R"(\b\w+\r\n)"), hdr).size() == 400);
      CHECK(rows(make_egc(R"(\r\n\z)"), hdr).size() == 1);
      // Non-ASCII keeps taking the byte tier it always did.
      std::string mixed;
      for (int i = 0; i < 400; i++) mixed += "café: v\r\n";
      CHECK(rows(make_egc(R"(\r\n$)"), mixed).size() == 1);
    }
  }
}

// A user-supplied FindCache may be shared across Regexes and across
// interleaved iterators; every cached-DFA consumer must re-bind it before
// reading (a stale binding serves another Regex's DFAs — wrong results, and a
// use-after-free once that Regex dies). Regression for the assert-tier
// find_iter path, which skipped the bind.
void test_findcache_shared_rebind() {
  reg::Regex::FindCache cache;
  const std::string ta = "a cat here", tb = "a dog here";
  { // assert tier (\b...), capture-free: warm with a, then iterate b
    Regex a(R"(\b(?:cat|cow)\w*\b)"), b(R"(\b(?:dog|pig)\w*\b)");
    size_t na = 0, nb = 0;
    for (auto m : a.find_iter(ta, cache))
      (void)m, na++;
    for (auto m : b.find_iter(tb, cache))
      (void)m, nb++;
    CHECK(na == 1 && nb == 1);
    // interleaved iterators over the same shared cache
    auto ita = a.find_iter(ta, cache);
    auto itb = b.find_iter(tb, cache);
    auto ia = ita.begin();
    auto ib = itb.begin();
    CHECK(ia != ita.end() && ib != itb.end() && (*ia).str() == "cat" &&
          (*ib).str() == "dog");
  }
  { // dangling-Regex reuse: the cache must revalidate, not serve a dead DFA
    size_t n = 0;
    {
      Regex tmp(R"(\b(?:cat|cow)\w*\b)");
      for (auto m : tmp.find_iter(ta, cache))
        (void)m, n++;
    } // tmp destroyed; cache still holds its generation
    Regex b2(R"(\b(?:dog|pig)\w*\b)");
    for (auto m : b2.find_iter(tb, cache))
      (void)m, n++;
    CHECK(n == 2);
  }
  { // Dfa tier with captures through the same shared cache (already bound
    // correctly; pins the contract for every tier)
    Regex a(R"((c\w+))"), b(R"((d\w+))");
    auto ita = a.find_iter(ta, cache);
    auto itb = b.find_iter(tb, cache);
    auto ma = ita.begin();
    auto mb = itb.begin();
    CHECK(ma != ita.end() && mb != itb.end() &&
          (*ma).group(1).str() == "cat" && (*mb).group(1).str() == "dog");
  }
}

// A scan that outlives the call that started it (find_iter, split) holds its
// entry of the thread's cache map across the caller's loop body — and the
// map evicts when it passes 1024 entries. The entry of a live scan has to
// survive that: the 1025th other Regex used inside a find_iter loop used to
// free the iterator's cache, and its next ++ read freed memory (reported by
// ASan; here the scan must simply go on to the right matches).
void test_iterator_survives_cache_eviction() {
  std::string subj;
  for (int i = 0; i < 60; i++) subj += "x ab@cd  ";
  auto churn = [](std::vector<std::unique_ptr<Regex>> &others, int n) {
    for (int k = 0; k < n; k++) {
      others.push_back(std::make_unique<Regex>(
          "q" + std::to_string(others.size()) + "[0-9]+z"));
      (void)others.back()->test("zzz q12 zzz"); // lands in the thread's map
    }
  };
  {
    Regex re("[a-z]+@[a-z]+"); // a DFA family: every step reads the cache
    std::vector<std::unique_ptr<Regex>> others;
    size_t n = 0, bytes = 0;
    for (auto m : re.find_iter(subj)) {
      n++;
      bytes += m.end() - m.begin();
      if (others.size() < 1200) churn(others, 40);
    }
    CHECK(n == 60 && bytes == 60 * 5);
    CHECK(others.size() >= 1200);
  }
  {
    Regex re("[a-z]+@[a-z]+");
    std::vector<std::unique_ptr<Regex>> others;
    size_t pieces = 0;
    for (auto piece : re.split(subj)) {
      (void)piece;
      pieces++;
      if (others.size() < 1200) churn(others, 40);
    }
    CHECK(pieces == 61);
  }
  // Two scans alive at once, one of them moved: each keeps its own entry.
  {
    Regex a("[a-z]+@[a-z]+"), b("ab@c[a-z]");
    std::vector<std::unique_ptr<Regex>> others;
    auto ia = a.find_iter(subj);
    auto moved = std::move(ia);
    size_t na = 0, nb = 0;
    for (auto m : moved) {
      (void)m;
      na++;
      if (na == 1)
        for (auto mb : b.find_iter(subj)) {
          (void)mb;
          nb++;
          if (others.size() < 1200) churn(others, 60);
        }
    }
    CHECK(na == 60 && nb == 60);
  }
}

void test_invalid_patterns() {
  CHECK(rejects("(abc"));     // unmatched '('
  CHECK(rejects("abc)"));     // unmatched ')'
  CHECK(rejects("*abc"));     // nothing to repeat
  CHECK(rejects("[abc"));     // unterminated class
  CHECK(rejects("\\"));       // trailing backslash
  CHECK(rejects("[a-\\"));    // class range ending in a trailing backslash
  CHECK(rejects("[\\"));      // class with a trailing backslash
  CHECK(rejects("(?P<x>a)")); // unsupported group construct
  // valid patterns must NOT throw
  CHECK(!rejects("(?<=a+)b")); // variable lookbehind is supported now
  CHECK(!rejects("a{2,3}"));
  CHECK(!rejects("(?<name>x)"));
}

void test_resource_limits() {
  // Adversarial patterns must be rejected with RegexError, not crash or OOM.
  CHECK(rejects("a{1000000}")); // repetition blow-up -> program too big
  {
    std::string p; // nested bounded repetition: (((((a){50}){50})...){50}
    for (int i = 0; i < 6; i++)
      p = "(" + p + "a){50}";
    CHECK(rejects(p));
  }
  {
    std::string p(50000, '('); // deep nesting -> would overflow the stack
    p += "a";
    p += std::string(50000, ')');
    CHECK(rejects(p));
  }
  {
    std::string p(40000, 'a'); // exceeds the source-length cap
    CHECK(rejects(p));
  }
  // A wide alternation that fits under the caps still compiles and matches
  // without overflowing the matcher.
  {
    std::string p;
    for (int i = 0; i < 8000; i++)
      p += "a|";
    p += "b";
    auto m = Regex(p).search("xb");
    CHECK(m && m.str() == "b");
  }
  // A long zero-width chain compiles, but matching it must not overflow the
  // stack (the closure is iterative) — it raises the match step budget on a
  // long subject instead. `(a?){9000}` used to segfault.
  {
    bool threw = false;
    try {
      Regex("(a?){9000}").search(std::string(6000, 'a'));
    } catch (const RegexError &) { threw = true; }
    CHECK(threw);
  }
  // The same dense pattern on a short subject stays under budget and matches.
  CHECK(Regex("(a?){9000}").search("aaa").matched());
  // A repeat of a body that compiles to nothing emits nothing, at once: the
  // nested counts used to run lo*lo empty emits and never reach the limit.
  {
    auto t0 = std::chrono::steady_clock::now();
    CHECK(Regex("(?:(?:){1000000}){1000000}x").search("ax").begin() == 1);
    CHECK(Regex("(?:a{0}){1000000}").search("b").matched());
    CHECK(Regex("(?:(?i)){1000000}").test(""));
    CHECK(rejects("(?:(?:a{1000}){1000}){1000}"));
    double dt = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0)
                    .count();
    CHECK(dt < 5000);
  }
}

// A lookaround is one program however many times a counted repeat copies it,
// and the size limit counts the lookaround programs a program runs. A repeat
// used to compile its lookaround once per copy, outside the limit: 25 bytes
// of `(?:(?=[ab]{20000})a){400}` took a gigabyte and seconds to compile, and
// `(?:(?=[ab]{50})a){100}` settled the same assertion a hundred times over
// every subject and ran out of step budget on 20 KB.
void test_lookaround_programs() {
  for (auto unit : {reg::MatchUnit::Grapheme, reg::MatchUnit::CodePoint}) {
    const auto rejected = [unit](const std::string &pat) {
      try {
        make_unit(unit, pat, 0);
      } catch (const RegexError &e) {
        return e.code() == RegexError::Code::ProgramTooLarge;
      }
      return false;
    };
    // One program per lookaround, whatever the repeats around it.
    CHECK(PlanProbe::look_programs(make_unit(unit, "(?:(?=a)b){50}", 0)) == 1);
    CHECK(PlanProbe::look_programs(make_unit(unit, "(?=a)b(?=a)", 0)) == 2);
    CHECK(PlanProbe::look_programs(
              make_unit(unit, "(?:(?<=a)(?:(?!b)c){3}){4}", 0)) == 2);
    {
      auto t0 = std::chrono::steady_clock::now();
      CHECK(PlanProbe::look_programs(
                make_unit(unit, "(?:(?=[ab]{20000})a){400}", 0)) == 1);
      CHECK(std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                          t0)
                .count() < 10);
      const Regex re = make_unit(unit, "(?:(?=[ab]{200})a){400}", 0);
      CHECK(re.search(std::string(600, 'a')).end() == 400);
      CHECK(!re.test(std::string(598, 'a')));
    }
    // ... and settled over a subject once: a hundred copies cost one.
    const std::string subj = std::string(20000, 'a') + "b";
    for (const char *pat : {"(?:(?=[ab]{50})a){100}", "(?:(?<=a{9})a){1000}",
                            "(?:a(?![^a]{3})){500}"}) {
      bool threw = false;
      try {
        CHECK(make_unit(unit, pat, 0).search(subj).matched());
      } catch (const RegexError &) { threw = true; }
      CHECK(!threw);
    }
    // The limit counts what a program runs: lookarounds that are not copies
    // of one another each hold their own instructions — written alike or not.
    CHECK(!rejected("(?=[ab]{100000})a"));
    CHECK(!rejected("(?=[ab]{100000})(?=[ab]{100000})a"));
    CHECK(rejected("(?=[ab]{100000}0)(?=[ab]{100000}1)(?=[ab]{100000}2)a"));
    std::string q;
    for (int i = 0; i < 60; i++)
      q += "(?=[ab]{20000}" + std::to_string(i % 10) + std::string(i / 10, 'x') +
           ")";
    CHECK(rejected(q + "a"));
    // A lookaround in a lookaround is counted against the one around it.
    CHECK(rejected("(?=(?=[ab]{200000})(?=[ab]{100000}x))a"));
  }
}

void test_out_of_range_utf8() {
  // A four-byte form past U+10FFFF (an F4 90.. or F5..F7 lead) is not UTF-8:
  // each of its bytes is a lone byte, never a code point indexing past the end
  // of a property table (ASan: global-buffer-overflow).
  using reg::unicode::GeneralCategory;
  CHECK(reg::unicode::general_category(0x110000) == GeneralCategory::Cn);
  CHECK(reg::unicode::general_category(0x1FFFFF) == GeneralCategory::Cn);
  CHECK(!reg::unicode::is_letter(0x1FFFFF));
  for (auto unit : {reg::MatchUnit::Grapheme, reg::MatchUnit::CodePoint}) {
    for (const char *bad : {"\xF4\x90\x80\x80", "\xF5\x80\x80\x80",
                            "\xF7\xBF\xBF\xBF"}) {
      const std::string s = std::string(bad) + "b1";
      CHECK(!make_unit(unit, "^.$", 0).test(bad));
      CHECK(make_unit(unit, "^.{4}$", 0).test(bad)); // four stray bytes
      auto m = make_unit(unit, "b\\d", 0).search(s);
      CHECK(m && m.begin() == 4 && m.end() == 6);
      CHECK(make_unit(unit, "(?<=\\W)b", 0).search(s).begin() == 4);
    }
  }
  // U+10FFFF itself is the last code point, and still one.
  CHECK(Regex("^.$").test("\xF4\x8F\xBF\xBF"));
}

// The decoder takes exactly well-formed UTF-8 (RFC 3629).
void test_utf8_decoder_strict() {
  using reg::unicode::utf8::decode_before;
  using reg::unicode::utf8::decode_codepoint;
  using reg::unicode::utf8::decode_or_byte;
  const auto decodes = [](const std::string &s, char32_t want) {
    size_t bytes = 0;
    char32_t cp = 0;
    return decode_codepoint(s.data(), s.size(), bytes, cp) && cp == want &&
           bytes == s.size();
  };
  const auto rejects_bytes = [](const std::string &s) {
    size_t bytes = 0;
    char32_t cp = 0;
    return !decode_codepoint(s.data(), s.size(), bytes, cp);
  };
  CHECK(decodes("a", 'a'));
  CHECK(decodes("\xC2\x80", 0x80));
  CHECK(decodes("\xDF\xBF", 0x7FF));
  CHECK(decodes("\xE0\xA0\x80", 0x800));
  CHECK(decodes("\xED\x9F\xBF", 0xD7FF));
  CHECK(decodes("\xEE\x80\x80", 0xE000));
  CHECK(decodes("\xEF\xBF\xBF", 0xFFFF));
  CHECK(decodes("\xF0\x90\x80\x80", 0x10000));
  CHECK(decodes("\xF4\x8F\xBF\xBF", 0x10FFFF));
  // A lone continuation byte, and a lead without its continuation bytes.
  CHECK(rejects_bytes("\x80"));
  CHECK(rejects_bytes("\xBF"));
  CHECK(rejects_bytes("\xC3"));
  CHECK(rejects_bytes("\xC3" "a"));
  CHECK(rejects_bytes("\xE3\x81"));
  CHECK(rejects_bytes("\xE3" "ab"));
  CHECK(rejects_bytes("\xF0\x9F\x98"));
  CHECK(rejects_bytes("\xF0\x9F" "ab"));
  // Overlong forms.
  CHECK(rejects_bytes("\xC0\xAF"));
  CHECK(rejects_bytes("\xC1\xBF"));
  CHECK(rejects_bytes("\xE0\x9F\xBF"));
  CHECK(rejects_bytes("\xF0\x8F\xBF\xBF"));
  // Surrogates, and past U+10FFFF.
  CHECK(rejects_bytes("\xED\xA0\x80"));
  CHECK(rejects_bytes("\xED\xBF\xBF"));
  CHECK(rejects_bytes("\xF4\x90\x80\x80"));
  CHECK(rejects_bytes("\xF5\x80\x80\x80"));
  CHECK(rejects_bytes("\xF8\x88\x80\x80\x80"));
  CHECK(rejects_bytes("\xFE"));
  CHECK(rejects_bytes("\xFF"));
  CHECK(rejects_bytes(""));
  // A bad sequence is a byte of its own, and the next byte starts afresh.
  {
    const std::string s = "\xE3" "ab";
    char32_t cp;
    CHECK(decode_or_byte(s.data(), s.size(), cp) == 1 && cp == 0xE3);
    CHECK(decode_or_byte(s.data() + 1, s.size() - 1, cp) == 1 && cp == 'a');
  }
  // valid_from is the same test as a decode_codepoint walk: every string of up
  // to three bytes drawn from the bytes where the rules change, and long random
  // ones around every length boundary.
  {
    const auto walk = [](const std::string &s) {
      for (size_t off = 0; off < s.size();) {
        size_t bytes;
        char32_t cp;
        if (!decode_codepoint(s.data() + off, s.size() - off, bytes, cp))
          return false;
        off += bytes;
      }
      return true;
    };
    const unsigned char edge[] = {0x00, 0x41, 0x7F, 0x80, 0x8F, 0x90, 0x9F,
                                  0xA0, 0xBF, 0xC0, 0xC1, 0xC2, 0xDF, 0xE0,
                                  0xE1, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1,
                                  0xF3, 0xF4, 0xF5, 0xF7, 0xF8, 0xFF};
    size_t strings = 0;
    std::string s;
    const auto each = [&](auto &&self, size_t depth) -> void {
      if (!s.empty() || depth == 0) {
        strings++;
        CHECK(reg::unicode::utf8::valid_from(s.data(), s.size()) == walk(s));
      }
      if (depth == 0) return;
      for (unsigned char b : edge) {
        s.push_back(static_cast<char>(b));
        self(self, depth - 1);
        s.pop_back();
      }
    };
    each(each, 4); // 27^4 = 531441 strings of one to four of the edge bytes
    CHECK(strings > 500000);
    unsigned x = 12345;
    for (int i = 0; i < 20000; i++) {
      std::string r(1 + (i % 40), 'a');
      for (char &c : r) {
        x = x * 1664525u + 1013904223u;
        c = (x >> 24) % 4 ? static_cast<char>('a' + (x >> 16) % 26)
                          : static_cast<char>(edge[(x >> 8) % sizeof edge]);
      }
      CHECK(reg::unicode::utf8::valid_from(r.data(), r.size()) == walk(r));
    }
    // From a code-point boundary part-way in.
    const std::string t = "ab\xC3\xA9\xFFcd";
    CHECK(!reg::unicode::utf8::valid_from(t.data(), t.size(), 2));
    CHECK(reg::unicode::utf8::valid_from(t.data(), t.size(), 5));
  }
  // The element ending at a byte, read as a left-to-right scan reads it.
  {
    char32_t cp;
    const std::string a = "x\xD8\x80\xBF"; // U+0600, then a stray BF
    CHECK(decode_before(a.data(), 4, cp) == 1 && cp == 0xBF);
    CHECK(decode_before(a.data(), 3, cp) == 2 && cp == 0x600);
    const std::string b = "\xC3\xA9\x80"; // é, then a stray continuation
    CHECK(decode_before(b.data(), 3, cp) == 1 && cp == 0x80);
    CHECK(decode_before(b.data(), 2, cp) == 2 && cp == 0xE9);
    const std::string c = "\xF0\x9F\x98\x80"; // one four-byte code point
    CHECK(decode_before(c.data(), 4, cp) == 4 && cp == 0x1F600);
    CHECK(decode_before(c.data(), 3, cp) == 1 && cp == 0x98);
    const std::string d = "\xE3\x81"; // a truncated lead
    CHECK(decode_before(d.data(), 2, cp) == 1 && cp == 0x81);
  }
}

// A subject that is not UTF-8 reads as the Pike reads it — a stray byte is an
// element of its own, and the next byte starts afresh — whichever tier a plan
// would serve a well-formed one with. The byte automata cannot match a stray
// byte, so every such subject has to reach the Pike; each pattern is checked
// against its Pike-only twin on every short run of well- and ill-formed pieces.
void test_invalid_utf8_tiers() {
  const char *const pieces[] = {
      "a",          "b",          "x",
      "ing",        " ",          "\n",
      "\r\n",       "\xC3\xA9",   "\xE3\x81\x82",
      "\xD8\x80",   "\xCC\x81",   "\xF0\x9F\x98\x80",
      "\xC3",        "\x80",        "\xE3\x81",
      "\xBF",        "\xC0\xAF",   "\xED\xA0\x80",
      "\xF4\x90\x80\x80", "\xFF",
  };
  const size_t np = sizeof pieces / sizeof *pieces;
  const char *const pats[] = {
      "x[^ ]",    "[^ ]+",      "\\bx",        "a\\b",        "\\B.",
      "..",       "(.)(.*)",    "\\w+ing\\b",  "\\b\\w+ing\\b", "^.+$",
      "x*",       "a|b|ing",    "abc|abx",    "(?i)ING",     "(a)(b)?",
      "\\p{L}+",  "(?<=a)b",    "x(?=b)",     "(?m)^.",      "[a-z]+$",
  };
  std::vector<std::string> subjects{""};
  for (size_t i = 0; i < np; i++) {
    subjects.push_back(pieces[i]);
    for (size_t j = 0; j < np; j++) {
      subjects.push_back(std::string(pieces[i]) + pieces[j]);
      for (size_t k = 0; k < np; k += 3)
        subjects.push_back(std::string(pieces[i]) + pieces[j] + pieces[k]);
    }
  }
  const auto spans = [](const Regex &re, const std::string &s) {
    std::vector<size_t> v;
    for (auto m : re.find_all(s)) {
      v.push_back(m.begin());
      v.push_back(m.end());
    }
    return v;
  };
  size_t bad = 0;
  for (auto unit : {reg::MatchUnit::Grapheme, reg::MatchUnit::CodePoint}) {
    for (const char *pat : pats) {
      const Regex re = make_unit(unit, pat, 0);
      const Regex pike = pike_twin(pat, 0, unit);
      for (const std::string &s : subjects) {
        const auto a = re.search(s), b = pike.search(s);
        const bool ok =
            re.test(s) == pike.test(s) && a.matched() == b.matched() &&
            (!a || (a.begin() == b.begin() && a.end() == b.end())) &&
            spans(re, s) == spans(pike, s) &&
            re.match(s).matched() == pike.match(s).matched();
        if (!ok && bad++ < 5)
          std::printf("  invalid UTF-8: %s pattern %s, %zu-byte subject\n",
                      unit == reg::MatchUnit::Grapheme ? "Grapheme"
                                                       : "CodePoint",
                      pat, s.size());
        CHECK(ok);
      }
    }
  }
  // The cases that showed it: a byte automaton reading a stray byte as
  // nothing, or a bad sequence as swallowing the byte after it.
  for (auto unit : {reg::MatchUnit::Grapheme, reg::MatchUnit::CodePoint}) {
    CHECK(make_unit(unit, "x[^ ]", 0).test("x\x80\xC3\xA9"));
    CHECK(make_unit(unit, "^.+$", 0).test("x\xE3x"));
    CHECK(make_unit(unit, "a\\b", 0).test("a\x80"));
    CHECK(spans(make_unit(unit, "a", 0), "\xC3" "a" "\xE3" "a") ==
          (std::vector<size_t>{1, 2, 3, 4}));
  }
  // A literal sits on a cluster boundary after a stray byte that follows a
  // Prepend: U+0600 BF is one cluster, and the `abc` after it starts a new one.
  CHECK(spans(Regex("abc"), "abc\xD8\x80\xBF" "abc") ==
        (std::vector<size_t>{0, 3, 6, 9}));
}

// Under IgnoreCase a class range holds a code point when ANY of its case
// variants lies in the range. (Comparing the folds of the range's ends was no
// such test: fold is not monotonic, so `(?i)[@-Z]` took `_` and `(?i)[Z-a]`
// lost `A`, and the engines that bake the variants into bytes disagreed with
// those that fold at match time.) The oracle is built from the fold table
// itself, over every code point.
void test_icase_class_ranges() {
  std::unordered_map<char32_t, std::vector<char32_t>> orbit; // fold -> members
  for (char32_t c = 0; c <= 0x10FFFF; c++)
    orbit[reg::unicode::simple_case_folding(c)].push_back(c);
  // The orbits the engine uses (built from the fold table's entries) are the
  // ones a scan of every code point finds.
  {
    std::vector<std::vector<char32_t>> want;
    for (auto &kv : orbit)
      if (kv.second.size() >= 2) want.push_back(kv.second);
    std::vector<std::vector<char32_t>> got = reg::detail::case_fold_groups();
    std::sort(want.begin(), want.end());
    std::sort(got.begin(), got.end());
    CHECK(got == want);
    CHECK(got.size() > 1000);
    for (const auto &grp : got)
      for (char32_t m : grp)
        CHECK(reg::detail::case_fold_orbit(m) != nullptr);
    CHECK(reg::detail::case_fold_orbit('1') == nullptr);
    CHECK(reg::detail::case_fold_orbit(0x10FFFF) == nullptr);
  }
  struct Range {
    char32_t lo, hi;
  };
  const auto expected = [&](char32_t cp, const std::vector<Range> &rs,
                            bool negate) {
    bool in = false;
    for (char32_t m : orbit[reg::unicode::simple_case_folding(cp)])
      for (const Range &r : rs)
        in = in || (m >= r.lo && m <= r.hi);
    return negate ? !in : in;
  };
  const auto hex = [](char32_t c) {
    char b[24];
    std::snprintf(b, sizeof b, "\\x{%X}", static_cast<unsigned>(c));
    return std::string(b);
  };
  struct Case {
    std::vector<Range> rs;
    bool negate;
  };
  const Case cases[] = {
      {{{'@', 'Z'}}, false},          {{{'Z', 'a'}}, false},
      {{{'0', 'Z'}}, false},          {{{'4', 't'}}, false},
      {{{'3', 'E'}}, false},          {{{'a', 'z'}}, false},
      {{{'A', 'Z'}}, false},          {{{'[', '`'}}, false},
      {{{'R', '~'}}, true},           {{{'a', 'c'}, {'X', 'Z'}}, false},
      {{{0x100, 0x17F}}, false},      {{{0x17F, 0x17F}}, false},
      {{{0x212A, 0x212A}}, false},    {{{0x3A3, 0x3A3}}, false},
      {{{0x1C4, 0x1CC}}, true},       {{{0x1E9E, 0x1E9E}}, false},
      {{{'k', 'k'}}, true},           {{{0x0, 0x7F}}, false},
  };
  std::vector<char32_t> probe;
  for (char32_t c = 0x20; c < 0x7F; c++) probe.push_back(c);
  for (char32_t c : {0xDFu, 0xE9u, 0x100u, 0x130u, 0x131u, 0x17Fu, 0x1C4u,
                     0x1C5u, 0x1C6u, 0x1CBu, 0x3A3u, 0x3C2u, 0x3C3u, 0x1E9Eu,
                     0x212Au, 0x2126u, 0x3A9u, 0x3C9u, 0x10400u, 0x10428u})
    probe.push_back(c);
  for (auto unit : {reg::MatchUnit::Grapheme, reg::MatchUnit::CodePoint}) {
    for (const Case &cs : cases) {
      std::string cls = cs.negate ? "[^" : "[";
      for (const Range &r : cs.rs) cls += hex(r.lo) + "-" + hex(r.hi);
      cls += "]";
      const Regex whole = make_unit(unit, "^" + cls + "$", reg::IgnoreCase);
      const Regex part = make_unit(unit, cls, reg::IgnoreCase);
      for (char32_t cp : probe) {
        const bool want = expected(cp, cs.rs, cs.negate);
        const std::string s = reg::unicode::utf8::encode_codepoint(cp);
        const bool a = whole.test(s), b = part.test(s);
        if ((a != want || b != want) && cp < 0x80)
          std::printf("  icase class %s on U+%04X: want %d, got ^$ %d / bare %d\n",
                      cls.c_str(), static_cast<unsigned>(cp), want, a, b);
        CHECK(a == want);
        CHECK(b == want);
      }
    }
  }
  // The cases that showed it.
  CHECK(!make_us("[@-Z]", IgnoreCase).test("_"));
  CHECK(!Regex("(?i)[@-Z]").test("_"));
  CHECK(Regex("(?i)[Z-a]").test("A"));
  CHECK(Regex("(?i)[4-t]").test("w"));
  CHECK(Regex("(?i)^[4-t]+$").test("wW"));
}

void test_error_messages() {
  // Errors carry the offending position and a caret line.
  std::string e = error_of("ab**");
  CHECK(has(e, "nothing to repeat"));
  CHECK(has(e, "position 3"));               // the second '*' (a=0 b=1 *=2 *=3)
  CHECK(has(e, "^"));                        // caret line present
  CHECK(has(error_of("ab)"), "position 2")); // the ')'
  CHECK(has(error_of("a(b|c"), "position 5")); // EOF, missing ')'
  CHECK(has(error_of("x(?P<n>y)"), "position 3"));
  CHECK(has(error_of("[a-z"), "unterminated character class"));
}

} // namespace

int main() {
  test_literals_and_anchors();
  test_assert_captures();
  test_assert_prefix_prefilter();
  test_assert_us_unified();
  test_options();
  test_any_and_classes();
  test_posix_classes();
  test_quantifiers();
  test_alternation_and_groups();
  test_literal_alternation();
  test_teddy_prefilter();
  test_teddy_scans();
  test_word_start_scan();
  test_matches();
  test_match_rows();
  test_whole_match_capture();
  test_onewalk_local_bail();
  test_find_ladder();
  test_unicode_scalar();
  test_named_groups();
  test_named_groups_introspection();
  test_boundaries_and_flags();
  test_text_anchors();
  test_constructor_flags();
  test_find_all_and_replace();
  test_byte_offsets();
  test_grapheme_aware();
  test_find_at();
  test_crlf_byte_path();
  test_crlf_adjacent_runs();
  test_suffix_prefilter();
  test_inner_prefilter();
  test_anchor_choice();
  test_assert_literal_prefilter();
  test_ascii_literal_prefilter();
  test_ascii_icase_prefilter();
  test_assert_dfa();
  test_lookahead();
  test_lookaround_linear();
  test_unicode_properties();
  test_lookbehind_fixed();
  test_lookbehind_variable();
  test_gpt2_tokenizer();
  test_nullable_quantifiers();
  test_dfa_boolean();
  test_dfa_cache();
  test_dfa_match();
  test_dfa_search();
  test_longest_safe_repeat();
  test_linear_time();
  test_walk_budget_linearity();
  test_scalar_chain_soundness();
  test_onepass_leftmost_first();
  test_body_dollar();
  test_findcache_shared_rebind();
  test_iterator_survives_cache_eviction();
  test_invalid_patterns();
  test_resource_limits();
  test_lookaround_programs();
  test_out_of_range_utf8();
  test_utf8_decoder_strict();
  test_invalid_utf8_tiers();
  test_icase_class_ranges();
  test_error_messages();

  std::printf("\nregexlib: %d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
