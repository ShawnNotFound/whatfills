#include "glob.hpp"

#include <string>
#include <vector>

namespace wf {

bool has_glob_chars(std::string_view s) {
  for (char c : s) {
    if (c == '*' || c == '?' || c == '[' || c == '\\') return true;
  }
  return false;
}

namespace {

// Try to match a character class starting at pat[i] == '['.
// Returns the index just past the class, or std::string_view::npos if the
// class is not closed (then '[' is a literal). Sets `matched`.
size_t match_class(std::string_view pat, size_t i, unsigned char c, bool& matched) {
  size_t j = i + 1;
  bool negate = false;
  if (j < pat.size() && (pat[j] == '!' || pat[j] == '^')) {
    negate = true;
    ++j;
  }
  bool hit = false;
  bool first = true;
  while (j < pat.size()) {
    unsigned char lo = static_cast<unsigned char>(pat[j]);
    if (lo == ']' && !first) {
      matched = (hit != negate);
      return j + 1;
    }
    first = false;
    if (lo == '\\' && j + 1 < pat.size()) {
      ++j;
      lo = static_cast<unsigned char>(pat[j]);
    }
    unsigned char hi = lo;
    if (j + 2 < pat.size() && pat[j + 1] == '-' && pat[j + 2] != ']') {
      hi = static_cast<unsigned char>(pat[j + 2]);
      if (hi == '\\' && j + 3 < pat.size()) {
        hi = static_cast<unsigned char>(pat[j + 3]);
        ++j;
      }
      j += 2;
    }
    if (lo <= c && c <= hi) hit = true;
    ++j;
  }
  return std::string_view::npos;
}

}  // namespace

bool glob_match_name(std::string_view pat, std::string_view s) {
  // Iterative matcher with single-star backtracking: O(len(pat) * len(s)).
  size_t p = 0, i = 0;
  size_t star_p = std::string_view::npos, star_i = 0;
  while (i < s.size()) {
    if (p < pat.size()) {
      char pc = pat[p];
      if (pc == '*') {
        while (p < pat.size() && pat[p] == '*') ++p;
        if (p == pat.size()) return true;
        star_p = p;
        star_i = i;
        continue;
      }
      if (pc == '?') {
        ++p;
        ++i;
        continue;
      }
      if (pc == '[') {
        bool matched = false;
        size_t next = match_class(pat, p, static_cast<unsigned char>(s[i]), matched);
        if (next != std::string_view::npos) {
          if (matched) {
            p = next;
            ++i;
            continue;
          }
        } else if (s[i] == '[') {
          ++p;
          ++i;
          continue;
        }
      } else {
        if (pc == '\\' && p + 1 < pat.size()) {
          if (pat[p + 1] == s[i]) {
            p += 2;
            ++i;
            continue;
          }
        } else if (pc == s[i]) {
          ++p;
          ++i;
          continue;
        }
      }
    }
    if (star_p != std::string_view::npos) {
      p = star_p;
      i = ++star_i;
      continue;
    }
    return false;
  }
  while (p < pat.size() && pat[p] == '*') ++p;
  return p == pat.size();
}

namespace {

// Path matching uses a memoised recursion (patterns and paths are short and
// path patterns are only used for user exclusions).
struct PathMatcher {
  std::string_view pat, s;
  std::vector<signed char>& memo;  // -1 unknown, 0 false, 1 true

  bool run(size_t p, size_t i) {
    size_t key = p * (s.size() + 1) + i;
    if (memo[key] >= 0) return memo[key] == 1;
    bool r = step(p, i);
    memo[key] = r ? 1 : 0;
    return r;
  }

  bool step(size_t p, size_t i) {
    if (p == pat.size()) return i == s.size();
    char pc = pat[p];
    if (pc == '*') {
      bool dbl = (p + 1 < pat.size() && pat[p + 1] == '*');
      if (dbl) {
        size_t q = p;
        while (q < pat.size() && pat[q] == '*') ++q;
        // "**/" may also match nothing at all, so "a/**/b" matches "a/b".
        bool at_comp_start = (p == 0 || pat[p - 1] == '/');
        if (at_comp_start && q < pat.size() && pat[q] == '/' && run(q + 1, i)) return true;
        for (size_t k = i; k <= s.size(); ++k) {
          if (run(q, k)) return true;
        }
        return false;
      }
      for (size_t k = i; k <= s.size(); ++k) {
        if (run(p + 1, k)) return true;
        if (k < s.size() && s[k] == '/') break;
      }
      return false;
    }
    if (i == s.size()) return false;
    if (pc == '?') return s[i] != '/' && run(p + 1, i + 1);
    if (pc == '[') {
      bool matched = false;
      size_t next = match_class(pat, p, static_cast<unsigned char>(s[i]), matched);
      if (next != std::string_view::npos) return matched && s[i] != '/' && run(next, i + 1);
      return s[i] == '[' && run(p + 1, i + 1);
    }
    if (pc == '\\' && p + 1 < pat.size()) return pat[p + 1] == s[i] && run(p + 2, i + 1);
    return pc == s[i] && run(p + 1, i + 1);
  }
};

}  // namespace

bool glob_match_path(std::string_view pat, std::string_view s) {
  // Buffers are reused between calls: this runs for every entry when the
  // user gives path patterns.
  thread_local std::string anchored;
  thread_local std::vector<signed char> memo;
  if (pat.empty() || pat[0] != '/') {
    anchored.assign("/**/");
    anchored.append(pat.data(), pat.size());
    pat = anchored;
  }
  memo.assign((pat.size() + 1) * (s.size() + 1), -1);
  PathMatcher m{pat, s, memo};
  return m.run(0, 0);
}

std::string glob_longest_literal(std::string_view pat) {
  // Text inside [...] is not literal, and escapes would need unescaping, so
  // such patterns get no hint.
  if (pat.find('[') != std::string_view::npos || pat.find('\\') != std::string_view::npos) return std::string();
  std::string_view best;
  size_t start = 0;
  for (size_t i = 0; i <= pat.size(); ++i) {
    if (i == pat.size() || pat[i] == '*' || pat[i] == '?') {
      if (i - start > best.size()) best = pat.substr(start, i - start);
      start = i + 1;
    }
  }
  return std::string(best);
}

std::string glob_literal_tail(std::string_view pat) {
  size_t i = pat.size();
  while (i > 0) {
    const char c = pat[i - 1];
    if (c == '*' || c == '?' || c == '[' || c == ']' || c == '\\') break;
    --i;
  }
  return std::string(pat.substr(i));
}

}  // namespace wf
