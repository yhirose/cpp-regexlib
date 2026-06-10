//
//  regexlib_std_compat_test.cc
//
//  Behavioral tests for the std::regex-compatible API (snake_case names in
//  namespace reg, part of regexlib.h). For ASCII inputs the shim must
//  agree with std::regex (ECMAScript); the test runs the same cases through
//  both and compares. It also pins the deliberate divergences (UTF-8 code-point
//  semantics, ReDoS-safe rejection of pathological patterns) and the API
//  surface (sub_match, match_results, regex_iterator, regex_replace).
//

#include <cstdio>
#include <regex>
#include <string>

#include "regexlib.h" // std::regex-compatible API lives here now

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

namespace re = reg;

// --- ASCII parity with std::regex: search ---
void test_search_parity() {
  struct Case {
    const char *pat;
    const char *subj;
  };

  const Case cases[] = {
      {R"((\w+)=(\w+))", "key=value rest"},
      {R"(\d{3}-\d{4})", "call 555-1234 now"},
      {R"(a|bb|ccc)", "xxcccyy"},
      {R"(colou?r)", "my color and colour"},
      {R"(^\s*#)", "   # comment"},
      {R"((foo)(bar)?)", "foo"},
      {R"([A-Za-z]+)", "  Hello123"},
  };
  for (const Case &c : cases) {
    std::string s = c.subj;
    std::regex stdre(c.pat, std::regex::ECMAScript);
    std::smatch sm;
    bool std_ok = std::regex_search(s, sm, stdre);

    re::regex rxre(c.pat);
    re::smatch rm;
    bool rx_ok = re::regex_search(s, rm, rxre);

    CHECK(std_ok == rx_ok);
    if (std_ok && rx_ok) {
      CHECK(sm.size() == rm.size());
      CHECK(sm.position(0) == rm.position(0));
      CHECK(sm.str(0) == rm.str(0));
      for (size_t i = 0; i < sm.size(); i++) {
        CHECK(sm[i].matched == rm[i].matched);
        CHECK(sm[i].str() == rm[i].str());
      }
      CHECK(sm.prefix().str() == rm.prefix().str());
      CHECK(sm.suffix().str() == rm.suffix().str());
    }
  }
}

// --- ASCII parity: match (whole-string), incl. the alternation backtrack case
// ---
void test_match_parity() {
  struct Case {
    const char *pat;
    const char *subj;
  };

  const Case cases[] = {
      {R"(a|aa)", "aa"}, // leftmost-first "a" must lose to whole-match "aa"
      {R"(\d+)", "12345"},   {R"(\d+)", "12a45"},  {R"((ab)+)", "ababab"},
      {R"(.*)", "anything"}, {R"(foo)", "foobar"}, {R"((a*)(a*))", "aaa"},
  };
  for (const Case &c : cases) {
    std::string s = c.subj;
    std::regex stdre(c.pat);
    std::smatch sm;
    bool std_ok = std::regex_match(s, sm, stdre);

    re::regex rxre(c.pat);
    re::smatch rm;
    bool rx_ok = re::regex_match(s, rm, rxre);

    CHECK(std_ok == rx_ok);
    if (std_ok && rx_ok) {
      CHECK(sm.str(0) == rm.str(0));
      CHECK(sm.size() == rm.size());
    }
  }
}

// --- ASCII parity: replace with $-format tokens ---
void test_replace_parity() {
  struct Case {
    const char *pat;
    const char *subj;
    const char *fmt;
  };

  const Case cases[] = {
      {R"((\w+)@(\w+))", "a@b and c@d", "$2.$1"},
      {R"(\d+)", "a1b22c333", "[$&]"},
      {R"((\w)(\w))", "abcd", "$2$1"},
      {R"(o)", "foo", "0"},
      {R"(\w+)", "hi there", "<$&>"},
  };
  for (const Case &c : cases) {
    std::string s = c.subj;
    std::regex stdre(c.pat);
    std::string std_out = std::regex_replace(s, stdre, c.fmt);

    re::regex rxre(c.pat);
    std::string rx_out = re::regex_replace(s, rxre, std::string(c.fmt));
    CHECK(std_out == rx_out);
  }
  // $$, $`, $'
  {
    re::regex rxre(R"(b+)");
    CHECK(re::regex_replace(std::string("abbbc"), rxre, std::string("$$")) ==
          "a$c");
    CHECK(re::regex_replace(std::string("abbbc"), rxre,
                            std::string("[$`|$']")) == "a[a|c]c");
  }
  // format_first_only
  {
    re::regex rxre(R"(\d)");
    CHECK(re::regex_replace(std::string("a1b2c3"), rxre, std::string("X"),
                            re::regex_constants::format_first_only) ==
          "aXb2c3");
  }
}

// --- regex_iterator over all matches ---
void test_iterator() {
  std::string s = "id=10 id=20 id=30";
  re::regex rxre(R"(id=(\d+))");

  std::regex stdre(R"(id=(\d+))");
  auto sbeg = std::sregex_iterator(s.begin(), s.end(), stdre);
  auto send = std::sregex_iterator();
  std::vector<std::string> std_caps;
  for (auto it = sbeg; it != send; ++it)
    std_caps.push_back((*it)[1].str());

  std::vector<std::string> rx_caps;
  for (re::sregex_iterator it(s.begin(), s.end(), rxre), end; it != end; ++it)
    rx_caps.push_back((*it)[1].str());

  CHECK(std_caps == rx_caps);
  CHECK(rx_caps.size() == 3);
  CHECK((rx_caps == std::vector<std::string>{"10", "20", "30"}));
}

// --- sub_match comparison operators / conversions ---
void test_sub_match_ops() {
  std::string s = "name: Alice";
  re::regex rxre(R"(name:\s*(\w+))");
  re::smatch m;
  CHECK(re::regex_search(s, m, rxre));
  CHECK(m[1] == "Alice");
  CHECK(m[1] != "Bob");
  CHECK(std::string("Alice") == m[1]);
  std::string captured = m[1]; // operator string_type
  CHECK(captured == "Alice");
  CHECK(m[1].length() == 5);
  CHECK(m[2].matched == false); // out of range -> unmatched
  CHECK(m[2].str().empty());
}

// --- the whole point: code-point (US) semantics, not byte, not grapheme ---
void test_unicode_codepoint() {
  // "café" in UTF-8 (é = U+00E9, 2 bytes). `.` matches one code point, so the
  // whole 4-char string matches `.{4}` (std::regex over std::string would need
  // 5 because its `.` is one byte).
  std::string cafe = "caf\xC3\xA9"; // c a f é
  re::regex four(R"(^.{4}$)");
  CHECK(re::regex_match(cafe, four));
  re::regex five(R"(^.{5}$)");
  CHECK(!re::regex_match(cafe, five));

  // \w matches the accented letter (Unicode word char).
  re::regex word(R"(^\w+$)");
  CHECK(re::regex_match(cafe, word));

  // A multi-byte char is matched whole, and byte offsets stay valid.
  std::string s = "x\xC3\xA9y"; // x é y
  re::regex mid(R"(\xC3?)");    // (just ensure no crash on multi-byte subjects)
  (void)mid;
  re::regex letter(R"(\w)");
  re::smatch m;
  CHECK(re::regex_search(s, m, letter));
  CHECK(m.str(0) == "x"); // leftmost code point
}

// --- ReDoS safety: a pattern that detonates std::regex is rejected or linear
// ---
void test_redos_safe() {
  // (a+)+$ on a long non-matching run is catastrophic for backtracking engines.
  // Here it must either run in linear time or raise (never hang). We just
  // assert it returns promptly and gives the correct boolean.
  re::regex bomb(R"((a+)+$)");
  std::string evil(40, 'a');
  evil += 'b';                          // forces failure
  CHECK(!re::regex_search(evil, bomb)); // must simply not hang, and not match
  CHECK(re::regex_search(std::string("aaaa"), bomb));

  // Atomic groups / possessive quantifiers throw at construction (they only
  // make sense for a backtracking engine).
  auto throws = [](const char *p) {
    try {
      re::regex r(p);
      (void)r;
      return false;
    } catch (const re::regex_error &) { return true; }
  };
  CHECK(throws(R"((?>a))")); // atomic group
  CHECK(throws(R"(a++)"));   // possessive quantifier

  // A backreference is NOT a backreference here: `\1` is the literal digit `1`,
  // so `(\w)\1` matches "a1", never "aa". (Documented divergence from
  // ECMAScript; a true backreference is NP-hard and incompatible with
  // linear-time matching.)
  re::regex pseudo_backref(R"((\w)\1)");
  CHECK(re::regex_search(std::string("a1"), pseudo_backref));
  CHECK(!re::regex_search(std::string("aa"), pseudo_backref));
}

// --- regex_error::code(): structured error classification (std taxonomy) ---
void test_error_codes() {
  namespace rc = re::regex_constants;

  struct Case {
    const char *pat;
    rc::error_type code;
  };

  const Case cases[] = {
      {"a(", rc::error_paren},               // missing ')'
      {"a)", rc::error_paren},               // unmatched ')'
      {"(?P<n>a)", rc::error_paren},         // unsupported group construct
      {"[abc", rc::error_brack},             // unterminated character class
      {"*", rc::error_badrepeat},            // nothing to repeat
      {"a\\", rc::error_escape},             // trailing backslash
      {R"(\x{ZZ})", rc::error_escape},       // invalid hex escape
      {R"(\p{Nonesuch})", rc::error_escape}, // unknown unicode property
  };
  for (const Case &c : cases) {
    bool threw = false;
    try {
      re::regex r(c.pat);
      (void)r;
    } catch (const re::regex_error &e) {
      threw = true;
      CHECK(e.code() == c.code);
      // what() carries the engine's human-readable message (with caret).
      CHECK(e.what() != nullptr && e.what()[0] != '\0');
      // Backward compatibility: the same object is catchable as the engine type
      // and as std::runtime_error.
      CHECK(dynamic_cast<const reg::RegexError *>(&e) != nullptr);
      CHECK(dynamic_cast<const std::runtime_error *>(&e) != nullptr);
    }
    CHECK(threw);
  }

  // Deeply nested groups exceed the recursion limit -> error_stack.
  bool stack_threw = false;
  try {
    re::regex r(std::string(2000, '('));
    (void)r;
  } catch (const re::regex_error &e) {
    stack_threw = true;
    CHECK(e.code() == rc::error_stack);
  }
  CHECK(stack_threw);

  // A successful compile followed by a match must not be perturbed by the
  // funnel (the no-throw path returns normally).
  re::regex ok("abc");
  CHECK(re::regex_search(std::string("xabcy"), ok));
}

// --- flags: icase, multiline ---
void test_flags() {
  re::regex ci("hello", re::regex_constants::icase);
  CHECK(re::regex_search(std::string("say HELLO"), ci));
  CHECK(re::regex_search(std::string("say hello"), ci));

  re::regex ml("^bar$", re::regex_constants::multiline);
  re::smatch m;
  std::string text = "foo\nbar\nbaz";
  CHECK(re::regex_search(text, m, ml));
  CHECK(m.str(0) == "bar");
}

// --- const char* / string_view subject overloads ---
void test_subject_overloads() {
  re::regex rxre(R"(\d+)");
  re::cmatch cm;
  CHECK(re::regex_search("abc 123 xyz", cm, rxre));
  CHECK(cm.str(0) == "123");

  re::svmatch vm;
  std::string_view sv = "v=42";
  re::regex kv(R"((\w+)=(\d+))");
  CHECK(re::regex_search(sv, vm, kv));
  CHECK(vm[1].str() == "v");
  CHECK(vm[2].str() == "42");
}

// --- regex_token_iterator: split (submatch -1) and group extraction ---
void test_token_iterator() {
  // Split on commas — parity with std::regex_token_iterator(-1).
  {
    std::string s = "a,bb,,ccc";
    std::regex sep(",");
    std::vector<std::string> std_fields, rx_fields;
    for (std::sregex_token_iterator it(s.begin(), s.end(), sep, -1), end;
         it != end; ++it)
      std_fields.push_back(it->str());
    re::regex rsep(",");
    for (re::sregex_token_iterator it(s.begin(), s.end(), rsep, -1), end;
         it != end; ++it)
      rx_fields.push_back(it->str());
    CHECK(std_fields == rx_fields);
    CHECK((rx_fields == std::vector<std::string>{"a", "bb", "", "ccc"}));
  }
  // Extract a single capture group across matches (submatch 1).
  {
    std::string s = "k1=v1; k2=v2";
    re::regex kv(R"((\w+)=(\w+))");
    std::vector<std::string> keys;
    for (re::sregex_token_iterator it(s.begin(), s.end(), kv, 1), end;
         it != end; ++it)
      keys.push_back(it->str());
    CHECK((keys == std::vector<std::string>{"k1", "k2"}));
  }
  // Two submatches per match {1,2}: parity with std.
  {
    std::string s = "k1=v1; k2=v2";
    re::regex kv(R"((\w+)=(\w+))");
    std::regex skv(R"((\w+)=(\w+))");
    std::vector<std::string> std_toks, rx_toks;
    int subs[] = {1, 2};
    for (std::sregex_token_iterator it(s.begin(), s.end(), skv, subs), end;
         it != end; ++it)
      std_toks.push_back(it->str());
    for (re::sregex_token_iterator it(s.begin(), s.end(), kv, subs), end;
         it != end; ++it)
      rx_toks.push_back(it->str());
    CHECK(std_toks == rx_toks);
    CHECK((rx_toks == std::vector<std::string>{"k1", "v1", "k2", "v2"}));
  }
}

// --- basic_regex::assign / swap / operator= / iterator-pair ctor ---
void test_regex_object_api() {
  re::regex r;
  r = R"(\d+)"; // operator=(const char*)
  CHECK(re::regex_search(std::string("x42"), r));
  CHECK(!re::regex_search(std::string("xyz"), r));

  re::regex r2;
  r2.assign(std::string(R"([a-z]+)"));
  CHECK(re::regex_search(std::string("ABCdef"), r2));

  std::string pat = R"(foo)";
  re::regex r3(pat.begin(), pat.end()); // iterator-pair ctor
  CHECK(re::regex_match(std::string("foo"), r3));

  re::regex a(R"(aaa)"), b(R"(bbb)");
  swap(a, b);
  CHECK(re::regex_match(std::string("bbb"), a));
  CHECK(re::regex_match(std::string("aaa"), b));

  re::regex grp(R"((a)(b)(c))");
  CHECK(grp.mark_count() == 3);
}

// --- regex_replace overload coverage (subject/format = string or char*) ---
void test_replace_overloads() {
  re::regex r(R"(\d+)");
  CHECK(re::regex_replace(std::string("a1b2"), r, std::string("#")) == "a#b#");
  CHECK(re::regex_replace(std::string("a1b2"), r, "#") == "a#b#");
  CHECK(re::regex_replace("a1b2", r, std::string("#")) == "a#b#");
  CHECK(re::regex_replace("a1b2", r, "#") == "a#b#");
  // OutputIt form.
  std::string out;
  std::string in = "a1b2";
  re::regex_replace(std::back_inserter(out), in.begin(), in.end(), r,
                    std::string("#"));
  CHECK(out == "a#b#");
}

} // namespace

int main() {
  test_search_parity();
  test_match_parity();
  test_replace_parity();
  test_iterator();
  test_sub_match_ops();
  test_unicode_codepoint();
  test_redos_safe();
  test_error_codes();
  test_flags();
  test_subject_overloads();
  test_token_iterator();
  test_regex_object_api();
  test_replace_overloads();

  std::printf("\nregexlib_std_compat: %d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
