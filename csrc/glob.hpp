// Shell-style pattern matching on raw byte strings (Linux file names are bytes).
#pragma once

#include <string>
#include <string_view>

namespace wf {

// True if `s` contains characters that make it a pattern rather than a literal.
bool has_glob_chars(std::string_view s);

// Match a single name (no '/' handling): '*' any run, '?' one byte,
// '[abc]', '[a-z]', '[!abc]' or '[^abc]' classes, '\x' a literal x.
// An unclosed '[' is matched literally.
bool glob_match_name(std::string_view pat, std::string_view s);

// Match a full path. Like glob_match_name, except that '*' and '?' never
// match '/', and '**' matches any run including '/'. "a/**/b" also matches
// "a/b". Patterns that do not start with '/' match at any depth, as if they
// started with "**/".
bool glob_match_path(std::string_view pat, std::string_view s);

// The literal text at the end of a pattern (after its last pattern
// character). Any string the pattern matches ends with it, so it is a cheap
// first check before the full match.
std::string glob_literal_tail(std::string_view pat);

// The longest run of literal text in a pattern; every string the pattern
// matches contains it. Empty when the pattern has classes or escapes.
std::string glob_longest_literal(std::string_view pat);

}  // namespace wf
