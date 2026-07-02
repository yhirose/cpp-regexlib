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

#include <chrono>
#include <cstdio>
#include <string>

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
    Regex bare(pat), pike("(?:" + pat + ")(?=[\\s\\S]|$)");
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
}

// Regex::find_at(text, pos) is one stateless step of find_iter(): stepping it
// from 0 must visit exactly the same matches, and next_pos must follow the
// engine's empty-match advance rule (one grapheme in Grapheme mode / one code
// point in CodePoint mode) so an external stepper always progresses and never
// resumes mid-cluster.
void test_find_at() {
  // Parity harness: step find_at from 0 and compare the visited (begin, end)
  // spans against find_iter over the same subject.
  auto same_as_iter = [](const Regex &re, std::string_view s) {
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
  };

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
    Regex pike("(?:" + pat + ")(?:\\b|\\B)"); // always-true; forces Pike
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
    Regex pike("(?:" + pat + ")(?:\\b|\\B)");
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
    Regex bare(pat), pike("(?:" + pat + ")(?=[\\s\\S]|$)");
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
    Regex pike("(?:" + pat + ")(?=[\\s\\S]|$)"); // lookahead -> Pike VM
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

// Required-suffix-literal prefilter: a pattern that begins with a class/`.` (no
// literal prefix to skip on) but ends with a fixed ASCII literal after a
// fixed-length body is found by memmem-ing the rare suffix and reverse-DFA
// verifying each candidate — across find_all / matches / scan / search and on
// ASCII, CRLF and non-ASCII subjects. Must equal the grapheme Pike (forced via a
// trailing always-true lookahead) AND the eager matches() must equal lazy scan().
void test_suffix_prefilter() {
  auto ok = [](const std::string &subj, const std::string &pat) {
    Regex bare(pat);
    Regex pike("(?:" + pat + ")(?=[\\s\\S]|$)"); // lookahead -> grapheme Pike
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
  // Patterns that keep the literal-PREFIX memmem instead (prefix path), still
  // equal to the Pike.
  CHECK(ok(ascii, "fox[a-z]{2}"));      // literal prefix -> prefix path
  CHECK(ok(acrlf, "the[^z]{0,9}zone")); // literal prefix -> prefix path
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
    Regex pike("(?:" + pat + ")(?=[\\s\\S]|$)"); // lookahead -> grapheme Pike
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
}

// Fixed-text literal prefilter for the assertion tier (rure-style): an assert
// pattern whose matched text is a single fixed literal once zero-width asserts
// are stripped (`(?m)^X|X$`, `^X$`, `\bX\b`) memmems the literal and confirms
// the assertions with an anchored assert-DFA verify. Same oracle: bare
// (prefilter) vs grapheme Pike (lookahead) vs scan, on ASCII / CRLF / non-ASCII.
void test_assert_literal_prefilter() {
  auto ok = [](const std::string &subj, const std::string &pat) {
    Regex bare(pat);
    Regex pike("(?:" + pat + ")(?=[\\s\\S]|$)"); // lookahead -> grapheme Pike
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
  auto ok = [](const std::string &subj, const std::string &pat) {
    Regex bare(pat);
    Regex pike("(?:" + pat + ")(?=[\\s\\S]|$)"); // lookahead -> grapheme Pike
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
    Regex pike("(?:" + pat + ")(?=[\\s\\S]|$)", reg::IgnoreCase);
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
    Regex bare(p), pike("(?:" + p + ")(?:\\b|\\B)");
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
    Regex bare(p, fl), pike("(?:" + p + ")(?:\\b|\\B)", fl);
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

  // Assert patterns on non-ASCII subjects take the cached byte assert tier
  // (ByteAssertDfa / ByteAssertRevDfa); they must agree with the forced Pike,
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
  // limit. The state cap abandons the DFA and falls back to the Pike VM, which
  // must give the same boolean. This guards the M0 safety net (the answer is
  // identical whether or not the cap trips on a given input).
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
    Regex pike("(?:" + pat + ")(?:\\b|\\B)"); // wrap forces the full Pike VM
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
  { // fused EGC prefix tier (capture-free, non-ASCII subject)
    std::string s(200000, 'a');
    s += "\xc3\xa9";
    cases.push_back({"fused-prefix", "a[a-z]+0", s, 0});
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
    std::string s(100000, 'a');
    s += "9ab0\xc3\xa9";
    cases.push_back({"bail-then-match", "a[a-z]+0", s, 1});
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
    Regex pike("(?:" + pat + ")(?=[\\s\\S]|$)");
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
  { // US (CodePoint) mode routes through the same drivers
    Regex re = make_us(R"((x)(?:ab)?(?:abc)?)");
    auto m = re.search("xabc");
    CHECK(m.matched() && m.end() == 3);
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
  test_matches();
  test_unicode_scalar();
  test_named_groups();
  test_boundaries_and_flags();
  test_text_anchors();
  test_constructor_flags();
  test_find_all_and_replace();
  test_byte_offsets();
  test_grapheme_aware();
  test_find_at();
  test_crlf_byte_path();
  test_suffix_prefilter();
  test_inner_prefilter();
  test_assert_literal_prefilter();
  test_ascii_literal_prefilter();
  test_ascii_icase_prefilter();
  test_assert_dfa();
  test_lookahead();
  test_unicode_properties();
  test_lookbehind_fixed();
  test_lookbehind_variable();
  test_gpt2_tokenizer();
  test_nullable_quantifiers();
  test_dfa_boolean();
  test_dfa_match();
  test_dfa_search();
  test_longest_safe_repeat();
  test_linear_time();
  test_walk_budget_linearity();
  test_scalar_chain_soundness();
  test_onepass_leftmost_first();
  test_findcache_shared_rebind();
  test_invalid_patterns();
  test_resource_limits();
  test_error_messages();

  std::printf("\nregexlib: %d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
