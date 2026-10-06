// Differential: Regex::scan() (lazy) must yield exactly the same match sequence
// (whole-match spans AND every capture-group span) as Regex::find_all()
// (eager), across tiers (US / EGC byte / ASCII DFA / assert / Pike), captures,
// empty matches, non-ASCII and CRLF subjects. Also checks early-break = prefix
// of the full sequence, and Match::to_owned().
#include <cstdio>
#include <string>
#include <vector>

#include "regexlib.h"

using namespace reg;

static int g_pass = 0, g_fail = 0;

static void check(bool c, const std::string &msg) {
  if (c)
    g_pass++;
  else {
    g_fail++;
    std::printf("  FAIL: %s\n", msg.c_str());
  }
}

// The eager find_all(), collected as owning results. It climbs the same
// ladder as the lazy scan but runs it to the end in one call — each rung
// goes on to its next match in place, and the walk has a loop of its own —
// where the scan re-enters the ladder once per match: the two ways of driving
// the rungs are what this file compares.
static std::vector<MatchResult> find_all(const Regex &re, std::string_view s) {
  std::vector<MatchResult> v;
  for (auto m : re.find_all(s))
    v.push_back(m.to_owned());
  return v;
}

// Flatten one match's groups onto `out`: begin/end per group, or the sentinel
// pair for an unmatched one.
template <class M>
static void append_spans(const M &m, std::vector<uint32_t> &out) {
  for (size_t g = 0; g <= m.group_count(); g++) {
    reg::Match c = m.group(g);
    if (c.matched()) {
      out.push_back(static_cast<uint32_t>(c.begin()));
      out.push_back(static_cast<uint32_t>(c.end()));
    } else {
      out.push_back(0xffffffffu);
      out.push_back(0xffffffffu);
    }
  }
}

// Collect scan() as a flat span list: [b0,e0, b1,e1, ...] over all
// groups/matches.
static std::vector<uint32_t> scan_spans(const Regex &re, std::string_view t) {
  std::vector<uint32_t> out;
  for (auto m : re.find_iter(t))
    append_spans(m, out);
  return out;
}

static std::vector<uint32_t> find_all_spans(const Regex &re,
                                            std::string_view t) {
  std::vector<uint32_t> out;
  for (auto &m : find_all(re, t))
    append_spans(m, out);
  return out;
}

// Test-only sentinel: the match unit is a process-wide default now, not a
// per-Regex flag. A `kUS` bit in a case's flags means "build this one in
// CodePoint mode" — flip the global default, construct, restore Grapheme.
static constexpr unsigned kUS = 1u << 16;

static void diff(const char *pat, unsigned flags, const std::string &subj) {
  bool us = (flags & kUS) != 0;
  if (us) reg::set_default_match_unit(reg::MatchUnit::CodePoint);
  Regex re(pat, flags & ~kUS);
  if (us) reg::set_default_match_unit(reg::MatchUnit::Grapheme);
  auto a = scan_spans(re, subj);
  auto b = find_all_spans(re, subj);
  std::string tag = std::string("/") + pat +
                    "/ flags=" + std::to_string(flags) + " on " +
                    std::to_string(subj.size()) + "B";
  check(a == b, "span mismatch " + tag);

  // search() and test() are two more tier ladders over the same question, and
  // a tier wired into one but not the others shows up only by comparing them:
  // search() is find_all()'s first row and test() is "there is a row".
  auto one = re.search(subj);
  std::vector<uint32_t> first;
  if (one.matched()) append_spans(one, first);
  check(one.matched() == !b.empty(), "search vs find_all (matched) " + tag);
  if (one.matched() && first.size() <= b.size())
    check(first == std::vector<uint32_t>(
                       b.begin(), b.begin() + static_cast<long>(first.size())),
          "search vs find_all (first row) " + tag);
  check(re.test(subj) == !b.empty(), "test vs find_all " + tag);

  // Early break: the first k matches from scan must equal find_all's first k.
  auto full = find_all(re, subj);
  size_t k = 0, want = full.size() / 2;
  for (auto m : re.find_iter(subj)) {
    if (k >= want) break;
    check(m.begin() == full[k].begin() && m.end() == full[k].end(),
          "early-break prefix " + tag);
    k++;
  }
}

int main() {
  struct Case {
    const char *pat;
    unsigned flags;
  };

  const Case cases[] = {
      {"a", 0},
      {"abc", 0},
      {"a|bb|ccc", 0},
      {"\\w+", 0},
      {"\\d+", 0},
      {"a*", 0},
      {"x*", 0},
      {"(a)(b)?", 0},
      {"(\\w+)=(\\w+)", 0},
      {"\\b\\w+\\b", 0},
      {"^\\w+", Flag::Multiline},
      {"\\w+$", Flag::Multiline},
      {"colou?r", 0},
      {"(?:ab)+", 0},
      {"\\s+", 0},
      {"a.c", 0},
      {".", 0},
      {"", 0}, // empty pattern (matches empty at every position)
      {"\\w+", kUS},
      {"\\p{L}+", kUS},
      {"(\\w+)", kUS},
      {".", kUS},
      {"café", 0},
      {"\\w+", 0},
      {"[a-z]+", 0},
      {"a+?", 0},
      {"(a|b)*", 0},
      {"Holmes", 0},
      {"\\w+\\s+\\w+", 0},
      // `body$`: a trailing text anchor makes the one-pass walk's accept a
      // match only when it lands at n, the one shape where an ACCEPTING walk
      // is a failure to its caller. Nothing here carried a trailing `$` before
      // (only the Multiline `\w+$` above, which is a different anchor), so a
      // require_end tier wired into one entry point and not another went
      // unseen. Both units where the shape has a unit-specific driver; the two
      // Multiline rows are EGC-only on purpose (`crlf_byte_safe` is an EGC
      // gate, and US never fuses CR-LF).
      {"(\\w+)$", 0},
      {"(\\w+)$", kUS},
      {"(\\d{3}) (\\d+)$", 0},
      {"(\\d{3}) (\\d+)$", kUS},
      {"(\\w+) (\\d+)$", 0},
      {"(\\w+) (\\d+)$", kUS},
      {"(a+)(b+)$", 0},
      {"(a+)(b+)$", kUS},
      {"([^ ]+)$", 0},
      {"([^ ]+)$", kUS},
      {"(\\w+)\\z", 0},
      {"(\\w+)\\z", kUS},
      {"\\.([a-z]+)$", 0},
      {"\\.([a-z]+)$", kUS},
      {"^(\\w+)$", 0},
      {"^(\\w+)$", kUS},
      {"(\\s+)$", Flag::Multiline},
      {"(\\s+)$|zq", Flag::Multiline},
      // A parser-fused CR-LF literal: byte-matchable as its own two bytes,
      // NOT consumable by a byte-stepping DFA over a grapheme program. No
      // pattern here held one, so the tier that cannot run it went unnoticed
      // even though the CRLF subjects above would have exposed it.
      {"\\r\\n", 0},
      {"\\r\\n$", 0},
      {"(\\r\\n)$", 0},
      {"(\\r\\n)$", kUS},
      {"(\\w+)\\r\\n", 0},
      {"(\\w+)\\r\\n$", 0},
      {"\\r\\nline2", 0},
      {"^(\\w+): (.*)\\r\\n", 0},
      {"[\\r\\n]+$", 0},
      // A repeat that can run MORE THAN ONCE over a VARIABLE-width body: the
      // walk accepts once per iteration count, so its LAST accept is the
      // longest parse and not the leftmost-first end. Every pattern here was
      // fixed-width under its repeats, so the tiers reading a cut table's last
      // accept (AnchoredOnePass's `^body`, the unbounded walk) agreed with the
      // Pike by luck of the corpus. `^(?:[a-cb].{0,4})+` shipped WRONG.
      {"(?:[a-cb].{0,4})+", 0},
      {"(?:[a-cb].{0,4})+", kUS},
      {"^(?:[a-cb].{0,4})+", 0},
      {"^(?:[a-cb].{0,4})+", kUS},
      {"(?:a.{0,2})+", 0},
      {"(?:\\w.?)+", 0},
      {"(?:[ab]x?)+", 0},
      {"((?:[a-cb].{0,4})+)", 0}, // the capture twin: must stay on the chain
      {"(?:[a-cb].{0,4})+$", 0},  // uncut (require_end): admission must differ
      {"\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b", 0}, // WordOnePass, also uncut
      // The same shape on WordOnePass WITHOUT a trailing `\b`, whose table
      // also carries the cut. Nothing above reached it: the tier needs three
      // top-level elements, so a bare `\b<repeat>` is out and only a repeat
      // followed by something lands there. `\b(?:[a-cb].{0,4})+x?` shipped
      // WRONG (it read [0,7) on "bbc 23_\n_2" for [0,5)).
      {"\\b(?:[a-cb].{0,4})+x?", 0},
      {"\\b(?:[a-cb].{0,4})+x?", kUS},
      {"\\b(?:\\w\\w.?)+x?", 0},
      {"\\b(?:\\w.?)+\\d?", 0},
      {"\\b(?:[a-c]x?y?)+\\b", 0}, // the trailing-`\b` twin: uncut, unaffected
      // Alternation under a table built UNCUT. The end is forced there (an
      // accept at n, or the one accept a trailing `\b` allows), so priority
      // never enters and the cut rules do not apply — these took the assert
      // DFA until onepass_body_ok started asking which flavour it was for.
      {"^(a|aa)+$", 0},
      {"^(a|aa)+$", kUS},
      {"^(?:a|a)*$", 0},
      {"^(?:abc|ab|a)+$", 0},
      {"^(\\w|\\d\\d)+$", 0},
      {"(?:a|ab)+$", 0},
      {"\\b\\w+(?:ab|cd)\\b", 0},
      {"^(a|aa)+", 0}, // the cut twin: still barred, still correct
      // Capture-FREE shapes the one-walk driver now serves at every entry
      // point (search / find_all / find_iter), including one whose match is
      // long enough that the walk's SIMD run skip is what runs.
      {"[^\\n]+", 0},
      {"[^\\n]+", kUS},
      {"[a-z]+", kUS},
      {"//[^\\n]*", 0},
      {"/users/\\d+", kUS},
      // Whole-match captures: every group IS the match. The pattern runs as
      // its capture-free twin (root groups peeled off the AST) and the groups
      // are written back at three different places — search()'s result,
      // find_all's rows, find_iter's row — which is exactly what this file
      // compares. Bodies that put the twin on different tiers (the one-walk
      // drivers, the chain for lazy / alternating / nullable ones, the
      // literal, suffix and assert tiers), nested / non-capturing / named
      // wrappers, both units.
      {"(\\w+)", 0},
      {"([^\\n]+)", 0},
      {"([^\\n]+)", kUS},
      {"([a-z]+)", 0},
      {"((\\w+))", 0},
      {"((\\w+))", kUS},
      {"(?:(\\d+))", 0},
      {"(\\w+\\s+\\w+)", 0},
      {"(\\w+\\s+\\w+)", kUS},
      {"(/users/\\d+)", 0},
      {"(/users/\\d+)", kUS},
      {"(a+b?)", 0},
      {"(\\w+?)", 0},
      {"(\\w+?)", kUS},
      {"(a|ab)", 0},
      {"(a|ab)", kUS},
      {"(x*)", 0},
      {"(holmes)", Flag::IgnoreCase},
      {"(\\w+)", Flag::IgnoreCase},
      {"(Holmes)", 0},
      {"(abc|line2)", 0},
      {"([a-z]+ing)", 0},
      {"([a-z]+ne\\d)", kUS},
      {"(\\b\\w+\\b)", 0},
      {"(^\\w+)", Flag::Multiline},
      {"(\\w+$)", kUS},
      {"(?<w>\\w+)", 0},
      {"((?<w>\\d+))", kUS},
      {"(?:[a-z]+)", 0},
      {"(?:(?:\\w+\\s+\\w+))", kUS},
      {"()", 0},
      // US one-walk drivers over subjects that put non-ASCII bytes in their
      // way (the "local bail" subjects below): each such find is served by
      // the chain and the driver resumes, in find_all's loop and in
      // find_iter's separately — the two must still agree row for row.
      {"(\\w+)=(\\w+)", kUS},
      {"(\\w+)=(\\S+)", kUS},
      {"(\\d+)\\s+(\\w+)", kUS},
      {"/users/(\\d+)", kUS},
      {"[a-z]+\\d?", kUS},
      {"(\\w+) (\\w+)$", kUS},
      // The anchor a find is driven from is chosen by estimated cost, so a
      // pattern with a literal at BOTH ends takes a rung per entry point that
      // none of the rows above reached: the suffix or the interior literal
      // from behind a literal prefix (search, find_all and find_iter each
      // order their rungs separately, and test() skips them), the scan in
      // place of a dense prefix, and on the assert tiers the leading literal
      // in front of a trailing one, with the word scan before or behind it.
      {"e[a-z]{3,}q", 0},
      {"e[a-z]{3,}q", kUS},
      // The walk from 0: a text-anchored, capture-free pattern is one walk
      // and nothing after it, whether the ladder is stepped or run to its
      // end — including an empty match at 0, which must not come back.
      {"^[a-z]+", 0},
      {"^[a-z]+", kUS},
      {"^[a-z]*", 0},
      {"^\\w+ \\w+$", 0},
      {"^(\\w+) (\\w+)$", kUS},
      // The walk on the byte tier (Grapheme, a subject that is not plain
      // ASCII): candidate + one walk per match, the chain for the one find
      // whose walk meets a non-ASCII byte. (`\\w+`, `(\\w+)` and
      // `(\\w+)=(\\w+)` above take it too.)
      {"\\p{L}+", 0},
      {"a[^.]*!", 0},
      {"a[^.]*!", kUS},
      {"s[a-z]*\\?", 0},
      {"a.{4}z", 0},
      {"a.{4}z", kUS},
      {"t[a-z]+ing", 0},
      {"a\\w+@\\w+", 0},
      {"a\\w+@\\w+", kUS},
      {"\\w+@\\w+e", 0},
      {"e[a-z]+s", 0},
      {"e[a-z]+s", kUS},
      {"[A-Z][a-z]+s", 0},
      {"[A-Z][a-z]+s", kUS},
      {"H[a-z]+s", 0},
      {"H[a-z]+s\\b", 0},
      {"H[a-z]+s\\b", kUS},
      {"\\bH[a-z]+s\\b", 0},
      {"Sherlock [a-z]+e\\b", 0},
      {"t[a-z]+ly\\b", 0},
      {"t[a-z]+ly\\b", kUS},
      {"\\bthe [a-z]+q\\b", 0},
      {"\\bq[a-z]+e\\b", 0},
      {"\\b\\w+ing\\b", 0},
      {"\\b\\w+ing\\b", kUS},
      {"\\be[a-z]+s\\b", 0},
      {"z[a-z]*e$", 0},
      {"^The [a-z]+ of", Flag::Multiline},
      {"e[a-z]+\\.$", Flag::Multiline},
  };
  const std::string subjects[] = {
      "",
      "a",
      "abc abc abc",
      "the quick brown fox jumps over",
      "a1b2c3 foo=bar baz=qux",
      "Hello, World!\nSecond line\nThird",
      "café résumé naïve",       // non-ASCII (NFC)
      "line1\r\nline2\r\nline3", // CRLF
      "Sherlock Holmes and Dr Watson",
      std::string(500, 'a') + " end",
      "x x x x x x x x",
      "  spaced   out  words  ",
      "café Holmes café Watson", // mixed ASCII/non-ASCII
      "123 456 789 000",         // only the last group reaches a trailing $
      "aa 11 bb 22 cc 33",       // dense candidates, one match at the end
      "ab\xc3",                  // truncated UTF-8: a lone lead byte at the end
      std::string(4096, 'q') + " ab\xc3", // the same, past the walk budget
      std::string(4096, ' ') + "123 456 789 000",
      "x\r\n",                            // a CR-LF cluster at the very end
      "HTTP/1.1 200 OK\r\nHost: a\r\n\r\n", // pure-ASCII CRLF, the httplib shape
      "bbc 23_\n_2", // the cut-lemma repro: one iteration ends at 5, two at 7
      "abcabc x abcabc",
      "aaaaaaaa",  // the overlapping-alternation validators' matching input
      "aaaaaaaab", // and the one that fails only at the trailing anchor
      std::string(1000, 'a') + "\n" + std::string(999, 'b'), // long matches
      "GET /users/42 then /users/7x and /users/ alone", // literal-prefix hits
      // Local bails: a non-ASCII byte inside, right after, right before a
      // match, at both ends of the subject, and in every other token.
      "ab c\xC3\xA9" "d ef \xC3\xA9 gh a=b \xC3\xA9=c d=\xC3\xA9 e=f",
      "\xC3\xA9 ab\xC2\xA1" "cd \xC2\xA1" "ef 12 gh /users/7 \xC3\xA9",
      "k=v \xC3\xA9 12 ab \xC3\xA9=w 34 cd x=y \xC3\xA9 56 ef z=\xC3\xA9 /users/1",
      // Both ends of the anchor-choice rows: prefix bytes with no suffix
      // behind them and suffixes with no prefix in front, a body that absorbs
      // either, on ASCII, CRLF and non-ASCII text.
      "The eeeelq eq Holmes hates the singing tasting; a no! a yes! is? sss?\n"
      "The zone of ua@be a@b Sherlock spoke truly, thely quaq quote azzzz.\n"
      "Homes Hs testing the easiest eases zebra ze aaaaaz a1234z yes.",
      "The easy eelq! ends.\r\nHis as? a@host abcdz singing tally.\r\n"
      "Sherlock rode the quaq truly\r\nThe house of Holmes is.\r\n",
      "\xC3\xA9 eeeelq a yes! is? Holmes \xC3\xA9 tasting a@be truly the quaq "
      "quote Hs \xC3\xA9s. Sherlock spoke\r\nThe end of eases.\r\n",
      std::string(3000, 'e') + "q " + std::string(3000, 'a') + "! Hs truly",
  };

  for (const auto &c : cases)
    for (const auto &s : subjects)
      diff(c.pat, c.flags, s);

  // to_owned(): the owned copy survives and carries the right text + groups.
  {
    Regex re("(\\w+)=(\\w+)");
    std::string subj = "foo=bar baz=qux";
    std::vector<MatchResult> owned;
    for (auto m : re.find_iter(subj))
      owned.push_back(m.to_owned());
    check(owned.size() == 2, "to_owned count");
    if (owned.size() == 2) {
      check(owned[0].str() == "foo=bar", "to_owned whole");
      check(owned[0].group(1).str() == "foo" && owned[0].group(2).str() == "bar",
            "to_owned groups");
      check(owned[1].group(1).str() == "baz", "to_owned second");
    }
  }
  // Early break really stops (no full scan): break after the first match.
  {
    Regex re("\\w+");
    std::string subj = "alpha beta gamma delta";
    int seen = 0;
    for (auto m : re.find_iter(subj)) {
      (void)m;
      if (++seen == 1) break;
    }
    check(seen == 1, "break after first");
  }
  // FindCache overload agrees too.
  {
    Regex re("\\w+");
    Regex::FindCache fc;
    std::string subj = "one two three";
    std::vector<uint32_t> a;
    for (auto m : re.find_iter(subj, fc)) {
      a.push_back(m.begin());
      a.push_back(m.end());
    }
    auto b = scan_spans(re, subj);
    // scan_spans uses no-cache; both must match find_all whole spans. `\w+` has
    // no capture groups, so the two span vectors have the same shape.
    check(!a.empty(), "cache overload nonempty");
    check(a == b, "cache overload spans");
  }

  std::printf("\nscan_diff: %d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
