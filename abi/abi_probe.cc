// ABI probe for cpp-regexlib.
//
// cpp-regexlib is a header-only library, so there is no shared object to diff
// directly. This translation unit anchors the public ABI surface: by taking
// the address of / out-of-lining uses of the public types, the compiler emits
// their DWARF type info and out-of-line symbol copies into a shared library.
// `abidiff` then compares that library between the previous release and the
// current tree to detect ABI-breaking changes to the public types.
//
// Keep this file conservative: it must compile against older releases too
// (the CI copies the current probe over the previous checkout), so only
// reference long-standing public API.

#include "../regexlib.h"

#include <string>
#include <string_view>

namespace regexlib_abi_probe {

// reg::Regex itself, plus the flag and match-unit constructors.
reg::Regex *make_regex() { return new reg::Regex(R"((\w+)@(\w+))", reg::IgnoreCase); }

reg::Regex *make_regex_cp() {
  return new reg::Regex(R"((\w+)@(\w+))", reg::MatchUnit::CodePoint);
}

// reg::MatchResult / reg::Match, returned and inspected by value.
reg::MatchResult run_search(const reg::Regex &re, std::string_view text) {
  return re.search(text);
}

reg::MatchResult run_match(const reg::Regex &re, std::string_view text) {
  return re.match(text);
}

bool run_test(const reg::Regex &re, std::string_view text) { return re.test(text); }

std::string group_str(const reg::MatchResult &m, size_t i) {
  return std::string(m.group(i).str());
}

// The iterator / list surfaces and the cache type they thread through.
size_t count_find_iter(const reg::Regex &re, std::string_view text) {
  size_t n = 0;
  for (auto m : re.find_iter(text)) {
    (void)m;
    ++n;
  }
  return n;
}

size_t count_find_all(const reg::Regex &re, std::string_view text) {
  return re.find_all(text).size();
}

size_t count_with_cache(const reg::Regex &re, std::string_view text,
                        reg::Regex::FindCache &cache) {
  return re.find_all(text, cache).size();
}

reg::Regex::FindCache *make_cache() { return new reg::Regex::FindCache(); }

std::string replace(const reg::Regex &re, std::string_view text,
                    std::string_view repl) {
  return re.replace_all(text, repl);
}

// Process-wide match unit.
void set_unit(reg::MatchUnit u) { reg::set_default_match_unit(u); }

reg::MatchUnit get_unit() { return reg::default_match_unit(); }

// The std::regex-compatible facade ships in the same header and is part of the
// public surface.
bool compat_search(const reg::regex &re, const std::string &text) {
  reg::smatch m;
  return reg::regex_search(text, m, re);
}

reg::regex *make_compat_regex() { return new reg::regex("a+"); }

} // namespace regexlib_abi_probe
