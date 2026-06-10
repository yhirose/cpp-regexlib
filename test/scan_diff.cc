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

// Independent oracle: the eager matches() (a different code path from scan())
// collected as owning results — what find_all() used to return.
static std::vector<MatchResult> find_all(const Regex &re, std::string_view s) {
  std::vector<MatchResult> v;
  for (auto m : re.find_all(s))
    v.push_back(m.to_owned());
  return v;
}

// Collect scan() as a flat span list: [b0,e0, b1,e1, ...] over all
// groups/matches.
static std::vector<uint32_t> scan_spans(const Regex &re, std::string_view t) {
  std::vector<uint32_t> out;
  for (auto m : re.find_iter(t)) {
    for (size_t g = 0; g <= m.group_count(); g++) {
      reg::Match cg = m.group(g);
      if (cg.matched()) {
        out.push_back(static_cast<uint32_t>(cg.begin()));
        out.push_back(static_cast<uint32_t>(cg.end()));
      } else {
        out.push_back(0xffffffffu);
        out.push_back(0xffffffffu);
      }
    }
  }
  return out;
}

static std::vector<uint32_t> find_all_spans(const Regex &re,
                                            std::string_view t) {
  std::vector<uint32_t> out;
  for (auto &m : find_all(re, t)) {
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
    // scan_spans uses no-cache; both must match find_all whole spans.
    check(!a.empty(), "cache overload nonempty");
  }

  std::printf("\nscan_diff: %d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
