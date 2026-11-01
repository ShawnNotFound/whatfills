// Python bindings for the scanning core. Paths and names cross the boundary as
// bytes, so file names that are not valid UTF-8 survive the round trip
// (Python decodes them with os.fsdecode).
#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>

#include <algorithm>
#include <unordered_map>

#include "core.hpp"
#include "glob.hpp"

namespace nb = nanobind;
using namespace nb::literals;

namespace {

std::string to_bytes(nb::handle h, const char* what) {
  if (nb::isinstance<nb::bytes>(h)) {
    nb::bytes b = nb::borrow<nb::bytes>(h);
    return std::string(b.c_str(), b.size());
  }
  throw nb::type_error((std::string(what) + " must be bytes (use os.fsencode)").c_str());
}

std::vector<std::string> bytes_list(const nb::dict& d, const char* key) {
  std::vector<std::string> out;
  if (!d.contains(key)) return out;
  for (nb::handle h : d[key]) out.push_back(to_bytes(h, key));
  return out;
}

template <class T>
T get(const nb::dict& d, const char* key, T def) {
  if (!d.contains(key)) return def;
  return nb::cast<T>(d[key]);
}

std::vector<int> int_list(const nb::dict& d, const char* key) {
  std::vector<int> out;
  if (!d.contains(key)) return out;
  for (nb::handle h : d[key]) out.push_back(nb::cast<int>(h));
  return out;
}

wf::Options parse_options(const nb::dict& d) {
  static const char* known[] = {"root", "threads", "one_file_system", "cross_subvolumes", "dont_sync",
                                "collect_ext", "by_apparent", "io_class", "nice", "keep_dir_min",
                                "keep_small_children", "big_file_min",
                                "top_files", "matches_per_rule", "files_per_rule", "max_errors", "max_skips", "max_links",
                                "dents_buffer", "now", "exclude_paths", "exclude_names", "exclude_globs",
                                "mount_points", "dir_rules", "file_rules", "opaque_rules", "max_rule_id"};
  for (auto [k, v] : d) {
    std::string key = nb::cast<std::string>(k);
    if (std::find_if(std::begin(known), std::end(known), [&](const char* s) { return key == s; }) == std::end(known))
      throw nb::value_error(("unknown scanner option: " + key).c_str());
  }
  wf::Options o;
  if (!d.contains("root")) throw nb::value_error("scanner option 'root' is required");
  o.root = to_bytes(d["root"], "root");
  o.threads = get<int>(d, "threads", o.threads);
  o.one_file_system = get<bool>(d, "one_file_system", o.one_file_system);
  o.cross_subvolumes = get<bool>(d, "cross_subvolumes", o.cross_subvolumes);
  o.dont_sync = get<bool>(d, "dont_sync", o.dont_sync);
  o.collect_ext = get<bool>(d, "collect_ext", o.collect_ext);
  o.by_apparent = get<bool>(d, "by_apparent", o.by_apparent);
  o.keep_small_children = get<size_t>(d, "keep_small_children", o.keep_small_children);
  o.io_class = get<int>(d, "io_class", o.io_class);
  o.nice = get<int>(d, "nice", o.nice);
  o.keep_dir_min = get<uint64_t>(d, "keep_dir_min", o.keep_dir_min);
  o.big_file_min = get<uint64_t>(d, "big_file_min", o.big_file_min);
  o.top_files = get<size_t>(d, "top_files", o.top_files);
  o.matches_per_rule = get<size_t>(d, "matches_per_rule", o.matches_per_rule);
  o.files_per_rule = get<size_t>(d, "files_per_rule", o.files_per_rule);
  o.max_errors = get<size_t>(d, "max_errors", o.max_errors);
  o.max_skips = get<size_t>(d, "max_skips", o.max_skips);
  o.max_links = get<size_t>(d, "max_links", o.max_links);
  o.dents_buffer = get<size_t>(d, "dents_buffer", o.dents_buffer);
  o.now = get<int64_t>(d, "now", o.now);
  o.exclude_paths = bytes_list(d, "exclude_paths");
  o.exclude_names = bytes_list(d, "exclude_names");
  o.exclude_globs = bytes_list(d, "exclude_globs");
  o.mount_points = bytes_list(d, "mount_points");
  o.max_rule_id = get<int>(d, "max_rule_id", 0);
  o.opaque_rules = int_list(d, "opaque_rules");
  if (d.contains("dir_rules")) {
    for (nb::handle h : d["dir_rules"]) {
      nb::dict r = nb::cast<nb::dict>(h);
      wf::DirRule dr;
      dr.id = get<int>(r, "id", 0);
      dr.order = get<int>(r, "order", 0);
      dr.anchored = get<bool>(r, "anchored", false);
      dr.comps = bytes_list(r, "comps");
      for (const auto& c : dr.comps) dr.comp_glob.push_back(wf::has_glob_chars(c));
      dr.require_child = bytes_list(r, "require_child");
      dr.require_sibling = bytes_list(r, "require_sibling");
      o.dir_rules.push_back(std::move(dr));
    }
  }
  if (d.contains("file_rules")) {
    for (nb::handle h : d["file_rules"]) {
      nb::dict r = nb::cast<nb::dict>(h);
      wf::FileRule fr;
      fr.id = get<int>(r, "id", 0);
      fr.order = get<int>(r, "order", 0);
      fr.globs = bytes_list(r, "globs");
      fr.min_size = get<uint64_t>(r, "min_size", 0);
      fr.within = int_list(r, "within");
      fr.not_within = int_list(r, "not_within");
      fr.in_dirs = bytes_list(r, "in_dirs");
      o.file_rules.push_back(std::move(fr));
    }
  }
  return o;
}

nb::bytes B(const std::string& s) { return nb::bytes(s.data(), s.size()); }

nb::dict build_result(wf::Scanner& s) {
  if (!s.finished()) throw std::runtime_error("the scan has not finished yet; call wait() first");
  const wf::Options& opt = s.options();
  nb::dict out;

  // Retained folder tree, flattened in depth-first order (parents first).
  nb::list nodes, big_files;
  std::vector<std::pair<const wf::Node*, long>> stack{{s.root(), -1}};
  long next = 0;
  while (!stack.empty()) {
    auto [n, parent] = stack.back();
    stack.pop_back();
    const long idx = next++;
    nodes.append(nb::make_tuple(parent, B(n->name), n->alloc.load(), n->apparent.load(), n->files.load(),
                                n->dirs.load(), n->mtime_max.load(), n->flags, n->sub_flags.load(), n->err,
                                n->eff_rule, n->match_rule));
    for (const auto& f : n->big_files)
      big_files.append(nb::make_tuple(idx, B(f.name), f.alloc, f.apparent, f.mtime, f.atime, f.uid, f.rule));
    for (auto it = n->children.rbegin(); it != n->children.rend(); ++it) stack.emplace_back(*it, idx);
  }
  out["nodes"] = nodes;
  out["big_files"] = big_files;

  const size_t nrules = static_cast<size_t>(opt.max_rule_id) + 1;
  std::vector<wf::RuleAcc> rules(nrules);
  std::vector<std::vector<wf::MatchRec>> matches(nrules);
  std::vector<std::vector<wf::TopFile>> rule_files(nrules);
  std::vector<wf::TopFile> top_files;
  std::unordered_map<uint32_t, wf::UidAcc> uids;
  std::unordered_map<std::string, wf::UidAcc> exts;
  nb::list errors, skips;
  std::unordered_map<int, uint64_t> errnos;
  uint64_t n_errors = 0, n_skips = 0, n_excluded = 0, hardlink_dupes = 0, vanished = 0;
  size_t kept_errors = 0, kept_skips = 0;

  for (wf::ThreadState* ts : s.states()) {
    for (size_t r = 0; r < nrules; ++r) {
      wf::RuleAcc& a = rules[r];
      const wf::RuleAcc& b = ts->rules[r];
      a.alloc += b.alloc;
      a.apparent += b.apparent;
      a.files += b.files;
      a.matches += b.matches;
      for (int i = 0; i < wf::kAgeBuckets; ++i) {
        a.age_mtime[i] += b.age_mtime[i];
        a.age_atime[i] += b.age_atime[i];
      }
      for (auto& m : ts->match_top[r].items()) matches[r].push_back(m);
      for (auto& f : ts->rule_files[r].items()) rule_files[r].push_back(f);
    }
    for (auto& f : ts->top_files.items()) top_files.push_back(f);
    for (const auto& [k, v] : ts->uids) {
      uids[k].alloc += v.alloc;
      uids[k].files += v.files;
    }
    for (const auto& [k, v] : ts->exts) {
      exts[k].alloc += v.alloc;
      exts[k].files += v.files;
    }
    for (const auto& e : ts->errors) {
      if (kept_errors++ < opt.max_errors) errors.append(nb::make_tuple(B(e.path), e.err, e.op));
    }
    for (const auto& [k, v] : ts->errnos) errnos[k] += v;
    for (const auto& sk : ts->skips) {
      if (kept_skips++ < opt.max_skips) skips.append(nb::make_tuple(B(sk.path), sk.reason, sk.dev));
    }
    n_errors += ts->n_errors;
    n_skips += ts->n_skips;
    n_excluded += ts->n_excluded;
    hardlink_dupes += ts->hardlink_dupes;
    vanished += ts->vanished;
  }

  auto by_alloc = [](const auto& a, const auto& b) {
    if (a.key != b.key) return a.key > b.key;
    return a.path < b.path;
  };
  std::vector<uint64_t> shared_by_rule;
  const wf::LinkSummary links = s.link_summary(shared_by_rule);
  nb::list rule_list, match_list, rule_file_list, top_list;
  for (size_t r = 0; r < nrules; ++r) {
    const wf::RuleAcc& a = rules[r];
    nb::list am, aa;
    for (int i = 0; i < wf::kAgeBuckets; ++i) {
      am.append(a.age_mtime[i]);
      aa.append(a.age_atime[i]);
    }
    rule_list.append(nb::make_tuple(a.alloc, a.apparent, a.files, a.matches, am, aa, shared_by_rule[r]));
    auto& ms = matches[r];
    std::sort(ms.begin(), ms.end(), by_alloc);
    if (ms.size() > opt.matches_per_rule) ms.resize(opt.matches_per_rule);
    for (const auto& m : ms)
      match_list.append(nb::make_tuple(m.rule, m.outer, B(m.path), m.alloc, m.apparent, m.files, m.mtime, m.flags));
    auto& fs = rule_files[r];
    std::sort(fs.begin(), fs.end(), by_alloc);
    if (fs.size() > opt.files_per_rule) fs.resize(opt.files_per_rule);
    for (const auto& f : fs)
      rule_file_list.append(nb::make_tuple(f.rule, B(f.path), f.alloc, f.apparent, f.mtime, f.atime, f.uid));
  }
  std::sort(top_files.begin(), top_files.end(), by_alloc);
  if (top_files.size() > opt.top_files) top_files.resize(opt.top_files);
  for (const auto& f : top_files)
    top_list.append(nb::make_tuple(B(f.path), f.alloc, f.apparent, f.mtime, f.atime, f.uid, f.rule));

  nb::dict uid_dict, ext_dict, errno_dict;
  for (const auto& [k, v] : uids) uid_dict[nb::int_(k)] = nb::make_tuple(v.alloc, v.files);
  for (const auto& [k, v] : exts) ext_dict[B(k)] = nb::make_tuple(v.alloc, v.files);
  for (const auto& [k, v] : errnos) errno_dict[nb::int_(k)] = v;

  out["rules"] = rule_list;
  out["matches"] = match_list;
  out["rule_files"] = rule_file_list;
  out["top_files"] = top_list;
  out["uids"] = uid_dict;
  out["exts"] = ext_dict;
  out["errors"] = errors;
  out["errnos"] = errno_dict;
  out["skips"] = skips;

  nb::dict stats;
  stats["errors"] = n_errors;
  stats["skips"] = n_skips;
  stats["excluded_names"] = n_excluded;
  stats["hardlink_dupes"] = hardlink_dupes;
  stats["vanished"] = vanished;
  stats["elapsed"] = s.elapsed();
  stats["threads"] = s.threads();
  stats["statx"] = s.used_statx();
  stats["stopped"] = s.was_stopped();
  out["stats"] = stats;

  nb::dict ld;
  ld["files"] = links.files;
  ld["bytes"] = links.alloc;
  ld["shared_files"] = links.shared_files;
  ld["shared_bytes"] = links.shared_alloc;
  ld["cross_cause_bytes"] = links.cross_rule_alloc;
  ld["linked_inside_bytes"] = links.inside_alloc;
  ld["untracked"] = links.untracked;
  ld["table_limit"] = opt.max_links;
  out["links"] = ld;
  return out;
}

}  // namespace

NB_MODULE(_core, m) {
  m.doc() = "whatfills scanning core";
  m.def(
      "glob_match_name",
      [](nb::bytes pat, nb::bytes s) {
        return wf::glob_match_name(std::string_view(pat.c_str(), pat.size()), std::string_view(s.c_str(), s.size()));
      },
      "pattern"_a, "name"_a);
  m.def(
      "glob_match_path",
      [](nb::bytes pat, nb::bytes s) {
        return wf::glob_match_path(std::string_view(pat.c_str(), pat.size()), std::string_view(s.c_str(), s.size()));
      },
      "pattern"_a, "path"_a);
  m.attr("AGE_BUCKETS") = wf::kAgeBuckets;
  m.attr("F_UNREADABLE") = static_cast<int>(wf::F_UNREADABLE);
  m.attr("F_PARTIAL") = static_cast<int>(wf::F_PARTIAL);
  m.attr("F_INCOMPLETE") = static_cast<int>(wf::F_INCOMPLETE);
  m.attr("F_PRUNED") = static_cast<int>(wf::F_PRUNED);
  m.attr("F_MATCH") = static_cast<int>(wf::F_MATCH);
  m.attr("F_CHANGED") = static_cast<int>(wf::F_CHANGED);

  nb::class_<wf::Scanner>(m, "Scanner")
      .def("__init__", [](wf::Scanner* self, nb::dict opts) { new (self) wf::Scanner(parse_options(opts)); })
      .def("start", &wf::Scanner::start)
      .def(
          "wait",
          [](wf::Scanner& s, double timeout) {
            nb::gil_scoped_release release;
            return s.wait(timeout);
          },
          "timeout"_a = -1.0)
      .def("cancel", &wf::Scanner::cancel)
      .def("progress",
           [](wf::Scanner& s) {
             wf::Progress p = s.progress();
             nb::dict d;
             d["files"] = p.files;
             d["dirs"] = p.dirs;
             d["alloc"] = p.alloc;
             d["apparent"] = p.apparent;
             d["errors"] = p.errors;
             d["done"] = p.done;
             d["stopping"] = p.stopping;
             return d;
           })
      .def("result", &build_result);
}
