#include <dirent.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <stdexcept>

#include "core.hpp"
#include "glob.hpp"

namespace wf {

namespace {

// statx is declared locally so the module builds against old kernel headers
// (manylinux images) and still uses it at run time when the kernel has it.
struct wf_statx_ts {
  int64_t tv_sec;
  uint32_t tv_nsec;
  int32_t reserved;
};
struct wf_statx {
  uint32_t stx_mask;
  uint32_t stx_blksize;
  uint64_t stx_attributes;
  uint32_t stx_nlink;
  uint32_t stx_uid;
  uint32_t stx_gid;
  uint16_t stx_mode;
  uint16_t spare0;
  uint64_t stx_ino;
  uint64_t stx_size;
  uint64_t stx_blocks;
  uint64_t stx_attributes_mask;
  wf_statx_ts stx_atime, stx_btime, stx_ctime, stx_mtime;
  uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
  uint64_t spare2[14];
};
static_assert(sizeof(wf_statx) == 256, "unexpected statx layout");

constexpr unsigned kStatxMask = 0x1 /*TYPE*/ | 0x2 /*MODE*/ | 0x4 /*NLINK*/ | 0x8 /*UID*/ | 0x20 /*ATIME*/ |
                                0x40 /*MTIME*/ | 0x100 /*INO*/ | 0x200 /*SIZE*/ | 0x400 /*BLOCKS*/;
constexpr unsigned kStatxBlocks = 0x400;
constexpr int kAtStatxDontSync = 0x4000;
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800
#endif

#if defined(SYS_statx)
constexpr long kSysStatx = SYS_statx;
#elif defined(__x86_64__)
constexpr long kSysStatx = 332;
#elif defined(__aarch64__) || defined(__riscv)
constexpr long kSysStatx = 291;
#else
constexpr long kSysStatx = -1;
#endif

struct wf_dirent64 {
  uint64_t d_ino;
  int64_t d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[1];
};

int age_bucket(int64_t now, int64_t t) {
  const int64_t d = now - t;
  constexpr int64_t day = 86400;
  if (d < day) return 0;
  if (d < 7 * day) return 1;
  if (d < 30 * day) return 2;
  if (d < 90 * day) return 3;
  if (d < 365 * day) return 4;
  if (d < 3 * 365 * day) return 5;
  return 6;
}

void atomic_max(std::atomic<int64_t>& a, int64_t v) {
  int64_t cur = a.load(std::memory_order_relaxed);
  while (v > cur && !a.compare_exchange_weak(cur, v, std::memory_order_relaxed)) {
  }
}

std::string join(const std::string& dir, std::string_view name) {
  std::string out;
  out.reserve(dir.size() + 1 + name.size());
  out = dir;
  if (out.empty() || out.back() != '/') out += '/';
  out.append(name.data(), name.size());
  return out;
}

std::string lower_ascii(std::string_view s) {
  std::string out(s);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

std::string strip_trailing_slash(std::string p) {
  while (p.size() > 1 && p.back() == '/') p.pop_back();
  return p;
}

// "*.ext" (or "*.tar.gz") with no other pattern characters: such patterns are
// matched through a case-insensitive extension index instead of one by one.
bool simple_ext_glob(const std::string& g, std::string& suffix, std::string& key) {
  if (g.size() < 3 || g[0] != '*' || g[1] != '.') return false;
  std::string_view rest(g.data() + 1, g.size() - 1);  // ".ext"
  if (has_glob_chars(rest.substr(1))) return false;
  suffix = lower_ascii(rest);
  size_t dot = suffix.rfind('.');
  key = suffix.substr(dot + 1);
  return !key.empty();
}

}  // namespace

template <class T>
void TopK<T>::push(T&& item) {
  auto cmp = [](const T& a, const T& b) { return a.key > b.key; };
  if (heap_.size() < k_) {
    heap_.push_back(std::move(item));
    std::push_heap(heap_.begin(), heap_.end(), cmp);
  } else {
    std::pop_heap(heap_.begin(), heap_.end(), cmp);
    heap_.back() = std::move(item);
    std::push_heap(heap_.begin(), heap_.end(), cmp);
  }
}

Scanner::Scanner(Options opt) : opt_(std::move(opt)) {
  if (opt_.root.empty() || opt_.root[0] != '/') throw std::invalid_argument("root must be an absolute path");
  opt_.root = strip_trailing_slash(opt_.root);
  if (opt_.threads < 1) opt_.threads = 1;
  if (opt_.threads > 256) opt_.threads = 256;
  if (opt_.dents_buffer < 4096) opt_.dents_buffer = 4096;
  if (kSysStatx < 0) use_statx_ = false;

  size_t start = 1;
  while (start < opt_.root.size()) {
    size_t end = opt_.root.find('/', start);
    if (end == std::string::npos) end = opt_.root.size();
    if (end > start) root_comps_.push_back(opt_.root.substr(start, end - start));
    start = end + 1;
  }

  for (const auto& n : opt_.exclude_names) {
    if (has_glob_chars(n)) {
      excl_names_glob_.push_back(n);
    } else {
      excl_names_lit_.insert(n);
    }
  }
  for (const auto& g : opt_.exclude_globs) {
    PathGlob pg;
    pg.pat = (!g.empty() && g[0] == '/') ? g : "/**/" + g;
    pg.tail = glob_literal_tail(pg.pat);
    pg.core = glob_longest_literal(pg.pat);
    if (pg.core.size() <= pg.tail.size() || pg.core.size() < 3) pg.core.clear();  // no better than the tail check
    excl_globs_.push_back(std::move(pg));
  }
  for (const auto& p : opt_.exclude_paths) {
    std::string q = strip_trailing_slash(p);
    excl_paths_.insert(q);
    excl_path_bases_.insert(q.substr(q.rfind('/') + 1));
  }
  for (const auto& m : opt_.mount_points) mount_points_.insert(strip_trailing_slash(m));

  for (const auto& r : opt_.dir_rules) {
    if (r.id < 1 || r.id > opt_.max_rule_id) throw std::invalid_argument("dir rule id out of range");
    if (r.comps.empty() || r.comp_glob.size() != r.comps.size())
      throw std::invalid_argument("dir rule needs at least one path component");
  }
  for (const auto& r : opt_.file_rules) {
    if (r.id < 1 || r.id > opt_.max_rule_id) throw std::invalid_argument("file rule id out of range");
  }
  for (const auto& r : opt_.dir_rules) {
    if (r.comp_glob.back()) {
      dir_wild_.push_back(&r);
    } else {
      dir_by_last_[r.comps.back()].push_back(&r);
    }
  }
  auto by_order = [](const DirRule* a, const DirRule* b) { return a->order < b->order; };
  std::sort(dir_wild_.begin(), dir_wild_.end(), by_order);
  for (auto& kv : dir_by_last_) std::sort(kv.second.begin(), kv.second.end(), by_order);

  for (const auto& r : opt_.file_rules) {
    for (const auto& g : r.globs) {
      std::string suffix, key;
      if (simple_ext_glob(g, suffix, key)) {
        file_by_ext_[key].emplace_back(suffix, &r);
      } else {
        file_generic_.emplace_back(g, &r);
      }
      any_file_rules_ = true;
    }
  }
  auto file_order = [](const std::pair<std::string, const FileRule*>& a,
                       const std::pair<std::string, const FileRule*>& b) { return a.second->order < b.second->order; };
  std::sort(file_generic_.begin(), file_generic_.end(), file_order);
  for (auto& kv : file_by_ext_) std::sort(kv.second.begin(), kv.second.end(), file_order);
}

Scanner::~Scanner() {
  if (started_) {
    cancel();
    wait(-1);
  }
  if (root_ != nullptr) {
    free_children(root_);
    delete root_;
  }
}

std::vector<ThreadState*> Scanner::states() const {
  std::vector<ThreadState*> out;
  for (const auto& s : states_) out.push_back(s.get());
  return out;
}

std::string Scanner::build_path(const Node* n) const {
  thread_local std::vector<const Node*> chain;
  chain.clear();
  for (const Node* x = n; x->parent != nullptr; x = x->parent) chain.push_back(x);
  std::string p = root_->name;
  for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
    if (p.back() != '/') p += '/';
    p += (*it)->name;
  }
  return p;
}

bool Scanner::link_first(uint64_t dev, uint64_t ino, uint32_t nlink, uint64_t alloc, int32_t rule,
                         ThreadState& ts) {
  InoKey k{dev, ino};
  Shard& s = hardlinks_[InoHash()(k) % kShards];
  std::lock_guard<std::mutex> lk(s.mu);
  auto it = s.map.find(k);
  if (it != s.map.end()) {
    LinkRec& r = it->second;
    ++r.seen;
    if (r.rule != rule) r.other_rule = true;
    return false;
  }
  if (links_tracked_.load(std::memory_order_relaxed) >= opt_.max_links) {
    ++ts.links_untracked;  // table full: count this link as if it were the only one
    return true;
  }
  links_tracked_.fetch_add(1, std::memory_order_relaxed);
  LinkRec r;
  r.alloc = alloc;
  r.nlink = nlink;
  r.seen = 1;
  r.rule = rule;
  s.map.emplace(k, r);
  return true;
}

LinkSummary Scanner::link_summary(std::vector<uint64_t>& shared_by_rule) const {
  LinkSummary out;
  shared_by_rule.assign(static_cast<size_t>(opt_.max_rule_id) + 1, 0);
  if (!hardlinks_) return out;
  for (int i = 0; i < kShards; ++i) {
    for (const auto& kv : hardlinks_[i].map) {
      const LinkRec& r = kv.second;
      ++out.files;
      out.alloc += r.alloc;
      if (r.seen < r.nlink || r.other_rule) {
        ++out.shared_files;
        out.shared_alloc += r.alloc;
        shared_by_rule[static_cast<size_t>(r.rule)] += r.alloc;
      }
      if (r.other_rule) out.cross_rule_alloc += r.alloc;
    }
  }
  for (const auto& ts : states_) out.untracked += ts->links_untracked;
  return out;
}

int Scanner::do_stat(int dirfd, const char* name, Stat& st) {
  if (use_statx_.load(std::memory_order_relaxed)) {
    wf_statx sx;
    int flags = AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | (opt_.dont_sync ? kAtStatxDontSync : 0);
    long r = syscall(kSysStatx, dirfd, name, flags, kStatxMask, &sx);
    if (r == 0) {
      st.mode = sx.stx_mode;
      st.nlink = sx.stx_nlink;
      st.uid = sx.stx_uid;
      st.ino = sx.stx_ino;
      st.size = sx.stx_size;
      st.blocks = (sx.stx_mask & kStatxBlocks) ? sx.stx_blocks : (sx.stx_size + 511) / 512;
      st.dev = makedev(sx.stx_dev_major, sx.stx_dev_minor);
      st.mtime = sx.stx_mtime.tv_sec;
      st.atime = sx.stx_atime.tv_sec;
      return 0;
    }
    int e = errno;
    if (e == ENOSYS) {
      use_statx_.store(false, std::memory_order_relaxed);
    } else if (e != EPERM) {
      return e;
    }
    // EPERM can come from seccomp filters that block statx; try fstatat.
  }
  struct stat s;
  if (fstatat(dirfd, name, &s, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT) != 0) return errno;
  st.mode = s.st_mode;
  st.nlink = static_cast<uint32_t>(s.st_nlink);
  st.uid = s.st_uid;
  st.ino = s.st_ino;
  st.size = static_cast<uint64_t>(s.st_size);
  st.blocks = static_cast<uint64_t>(s.st_blocks);
  st.dev = s.st_dev;
  st.mtime = s.st_mtime;
  st.atime = s.st_atime;
  return 0;
}

int Scanner::open_dir(const Node* n, const std::string& path) {
  int flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY;
  if (n->parent != nullptr) flags |= O_NOFOLLOW;
  if (noatime_) flags |= O_NOATIME;
  if (path.size() < PATH_MAX - 1) {
    int fd = open(path.c_str(), flags);
    if (fd < 0 && errno == EPERM && (flags & O_NOATIME)) fd = open(path.c_str(), flags & ~O_NOATIME);
    if (fd >= 0 || errno != ENAMETOOLONG) return fd;
  }
  // Path longer than PATH_MAX: walk down from the root one component at a time.
  std::vector<const Node*> chain;
  for (const Node* x = n; x->parent != nullptr; x = x->parent) chain.push_back(x);
  int fd = open(root_->name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  for (auto it = chain.rbegin(); fd >= 0 && it != chain.rend(); ++it) {
    int next = openat(fd, (*it)->name.c_str(), (flags & ~O_NOATIME) | O_NOFOLLOW);
    int saved = errno;
    close(fd);
    fd = next;
    errno = saved;
  }
  return fd;
}

bool Scanner::excluded_name(std::string_view name) const {
  if (!excl_names_lit_.empty() && excl_names_lit_.count(std::string(name))) return true;
  for (const auto& g : excl_names_glob_) {
    if (glob_match_name(g, name)) return true;
  }
  return false;
}

bool Scanner::excluded_path(const std::string& dir_path, std::string_view name, bool& built, std::string& full) const {
  if (!excl_path_bases_.count(std::string(name))) return false;
  if (!built) {
    full = join(dir_path, name);
    built = true;
  }
  return excl_paths_.count(full) > 0;
}

bool Scanner::dir_rule_matches(const DirRule& r, const Node* c) const {
  const size_t k = r.comps.size();
  const size_t total = root_comps_.size() + c->depth;  // components in c's absolute path
  if (r.anchored ? (k != total) : (k > total)) return false;
  const Node* n = c;
  size_t ri = root_comps_.size();
  for (size_t i = k; i-- > 0;) {
    std::string_view comp;
    if (n != nullptr && n->parent != nullptr) {
      comp = n->name;
      n = n->parent;
    } else {
      comp = root_comps_[--ri];
      n = nullptr;
    }
    if (r.comp_glob[i] ? !glob_match_name(r.comps[i], comp) : (r.comps[i] != comp)) return false;
  }
  return true;
}

bool Scanner::context_ok(const DirRule& r, int parent_fd, const std::string& parent_path, std::string_view name) const {
  struct stat st;
  if (!r.require_child.empty()) {
    bool any = false;
    for (const auto& ch : r.require_child) {
      std::string rel(name);
      rel += '/';
      rel += ch;
      if (fstatat(parent_fd, rel.c_str(), &st, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT) == 0) {
        any = true;
        break;
      }
    }
    if (!any) return false;
  }
  if (!r.require_sibling.empty()) {
    bool any = false;
    for (const auto& sib : r.require_sibling) {
      std::string p = (parent_fd == AT_FDCWD) ? join(parent_path, sib) : sib;
      if (fstatat(parent_fd, p.c_str(), &st, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT) == 0) {
        any = true;
        break;
      }
    }
    if (!any) return false;
  }
  return true;
}

void Scanner::match_dir(Node* c, const Node* p, int parent_fd, const std::string& parent_path) {
  const int parent_eff = p ? p->eff_rule : 0;
  std::string_view last = p ? std::string_view(c->name)
                            : (root_comps_.empty() ? std::string_view() : std::string_view(root_comps_.back()));
  // For the root node c->name is the full path, so context checks (made
  // relative to AT_FDCWD) use absolute paths.
  const std::string& ctx_name = c->name;
  const DirRule* best = nullptr;
  auto consider = [&](const DirRule* r) {
    if (best != nullptr && r->order >= best->order) return false;
    if (!dir_rule_matches(*r, c)) return false;
    if (!context_ok(*r, parent_fd, parent_path, ctx_name)) return false;
    best = r;
    return true;
  };
  if (!dir_by_last_.empty() && !last.empty()) {
    auto it = dir_by_last_.find(std::string(last));
    if (it != dir_by_last_.end()) {
      for (const DirRule* r : it->second) {
        if (consider(r)) break;
      }
    }
  }
  for (const DirRule* r : dir_wild_) {
    if (best != nullptr && r->order >= best->order) break;
    if (glob_match_name(r->comps.back(), last) && consider(r)) break;
  }
  if (best != nullptr && best->id != parent_eff) {
    c->match_rule = best->id;
    c->outer_rule = parent_eff;
    c->eff_rule = best->id;
    c->match_root = c;
    c->flags |= F_MATCH;
  } else {
    c->eff_rule = parent_eff;
    c->match_root = p ? p->match_root : nullptr;
  }
}

int Scanner::match_file(std::string_view name, uint64_t alloc, int dir_rule, const std::string& dir_path) const {
  const FileRule* best = nullptr;
  auto ok = [&](const FileRule* r) {
    if (alloc < r->min_size) return false;
    if (!r->within.empty() && std::find(r->within.begin(), r->within.end(), dir_rule) == r->within.end()) return false;
    if (!r->not_within.empty() &&
        std::find(r->not_within.begin(), r->not_within.end(), dir_rule) != r->not_within.end())
      return false;
    if (!r->in_dirs.empty() && std::find(r->in_dirs.begin(), r->in_dirs.end(), dir_path) == r->in_dirs.end())
      return false;
    return true;
  };
  if (!file_by_ext_.empty()) {
    size_t dot = name.rfind('.');
    if (dot != std::string_view::npos && dot > 0 && dot + 1 < name.size() && name.size() - dot <= 17) {
      std::string ext = lower_ascii(name.substr(dot + 1));
      auto it = file_by_ext_.find(ext);
      if (it != file_by_ext_.end()) {
        for (const auto& [suffix, r] : it->second) {
          if (best != nullptr && r->order >= best->order) break;
          if (!ok(r)) continue;
          if (suffix.size() > ext.size() + 1) {
            if (name.size() < suffix.size()) continue;
            if (lower_ascii(name.substr(name.size() - suffix.size())) != suffix) continue;
          }
          best = r;
          break;
        }
      }
    }
  }
  for (const auto& [g, r] : file_generic_) {
    if (best != nullptr && r->order >= best->order) break;
    if (ok(r) && glob_match_name(g, name)) {
      best = r;
      break;
    }
  }
  return best ? best->id : 0;
}

void Scanner::account(ThreadState& ts, int rule, const Stat& st, bool is_file) {
  RuleAcc& a = ts.rules[rule];
  const uint64_t alloc = st.blocks * 512;
  a.alloc += alloc;
  a.apparent += st.size;
  if (is_file) {
    ++a.files;
    a.age_mtime[age_bucket(opt_.now, st.mtime)] += alloc;
    a.age_atime[age_bucket(opt_.now, st.atime)] += alloc;
  }
}

void Scanner::add_error(ThreadState& ts, std::string path, int err, const char* op) {
  ++ts.n_errors;
  ++ts.errnos[err];
  p_errors_.fetch_add(1, std::memory_order_relaxed);
  if (ts.errors.size() < opt_.max_errors) ts.errors.push_back(ErrRec{std::move(path), err, op});
}

void Scanner::add_skip(ThreadState& ts, std::string path, const char* reason, uint64_t dev) {
  ++ts.n_skips;
  if (ts.skips.size() < opt_.max_skips) ts.skips.push_back(SkipRec{std::move(path), reason, dev});
}

void Scanner::start() {
  if (started_) throw std::runtime_error("this scanner was already started");
  struct stat st;
  if (stat(opt_.root.c_str(), &st) != 0) {
    int e = errno;
    throw std::runtime_error("cannot read " + opt_.root + ": " + std::strerror(e));
  }
  if (!S_ISDIR(st.st_mode)) throw std::runtime_error(opt_.root + " is not a folder");
  {
    int fd = open(opt_.root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
      int e = errno;
      throw std::runtime_error("cannot open " + opt_.root + ": " + std::strerror(e));
    }
    close(fd);
  }
  started_ = true;
  noatime_ = (geteuid() == 0);
  hardlinks_.reset(new Shard[kShards]);
  const size_t nrules = static_cast<size_t>(opt_.max_rule_id) + 1;
  for (int i = 0; i < opt_.threads; ++i) {
    auto ts = std::make_unique<ThreadState>();
    ts->buf.resize(opt_.dents_buffer);
    ts->rules.resize(nrules);
    ts->match_top.assign(nrules, TopK<MatchRec>(opt_.matches_per_rule));
    ts->rule_files.assign(nrules, TopK<TopFile>(opt_.files_per_rule));
    ts->top_files.set_k(opt_.top_files);
    states_.push_back(std::move(ts));
  }

  root_ = new Node();
  root_->name = opt_.root;
  root_->dev = st.st_dev;
  root_->ino = st.st_ino;
  root_->alloc.store(static_cast<uint64_t>(st.st_blocks) * 512);
  root_->apparent.store(0);
  root_->mtime_max.store(st.st_mtime);
  {
    std::string parent_path = opt_.root.substr(0, std::max<size_t>(1, opt_.root.rfind('/')));
    match_dir(root_, nullptr, AT_FDCWD, parent_path);
    Stat rs;
    rs.blocks = static_cast<uint64_t>(st.st_blocks);
    rs.size = 0;
    account(*states_[0], root_->eff_rule, rs, false);
    if (root_->match_root == root_) {
      root_->attr_alloc.store(rs.blocks * 512);
      root_->attr_apparent.store(rs.size);
    }
  }

  t0_ = std::chrono::steady_clock::now();
  outstanding_.store(1);
  queue_.push_back(root_);
  running_workers_.store(opt_.threads);
  for (int i = 0; i < opt_.threads; ++i) threads_.emplace_back(&Scanner::worker, this, i);
}

bool Scanner::wait(double timeout_s) {
  if (!started_) return true;
  bool fin;
  {
    std::unique_lock<std::mutex> lk(done_mu_);
    auto pred = [this] { return finished_.load(); };
    if (timeout_s < 0) {
      done_cv_.wait(lk, pred);
    } else {
      done_cv_.wait_for(lk, std::chrono::duration<double>(timeout_s), pred);
    }
    fin = finished_.load();
    if (fin && !joined_) {
      for (auto& t : threads_) t.join();
      joined_ = true;
    }
  }
  return fin;
}

void Scanner::cancel() {
  stop_.store(true);
  std::lock_guard<std::mutex> lk(qmu_);
  qcv_.notify_all();
}

Progress Scanner::progress() const {
  return Progress{p_files_.load(), p_dirs_.load(), p_alloc_.load(), p_apparent_.load(), p_errors_.load(),
                  finished_.load(), stop_.load()};
}

void Scanner::worker(int idx) {
  ThreadState& ts = *states_[idx];
#ifdef SYS_ioprio_set
  if (opt_.io_class == 2 || opt_.io_class == 3) {
    const int prio = (opt_.io_class == 3) ? (3 << 13) : ((2 << 13) | 7);
    syscall(SYS_ioprio_set, 1 /* IOPRIO_WHO_PROCESS */, 0 /* this thread */, prio);
  }
#endif
  if (opt_.nice != 0) setpriority(PRIO_PROCESS, static_cast<id_t>(syscall(SYS_gettid)), opt_.nice);

  while (Node* n = next_task(ts)) {
    if (stop_.load(std::memory_order_relaxed)) {
      n->flags |= F_INCOMPLETE;
    } else {
      process_dir(n, ts);
    }
    finish(n, ts);
    if (outstanding_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
      std::lock_guard<std::mutex> lk(qmu_);
      done_ = true;
      qcv_.notify_all();
    } else if (idle_.load(std::memory_order_relaxed) > 0 && ts.local.size() >= 2) {
      share_work(ts);
    }
  }
  if (running_workers_.fetch_sub(1) == 1) {
    std::lock_guard<std::mutex> lk(done_mu_);
    elapsed_ = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0_).count();
    finished_.store(true);
    done_cv_.notify_all();
  }
}

Node* Scanner::next_task(ThreadState& ts) {
  if (!ts.local.empty()) {
    Node* n = ts.local.back();
    ts.local.pop_back();
    return n;
  }
  std::unique_lock<std::mutex> lk(qmu_);
  for (;;) {
    if (!queue_.empty()) {
      Node* n = queue_.front();
      queue_.pop_front();
      return n;
    }
    if (done_) return nullptr;
    idle_.fetch_add(1, std::memory_order_relaxed);
    qcv_.wait(lk);
    idle_.fetch_sub(1, std::memory_order_relaxed);
  }
}

void Scanner::share_work(ThreadState& ts) {
  // Give away the oldest half of the local stack: those are the shallowest
  // folders and usually the biggest pieces of remaining work.
  const size_t give = ts.local.size() / 2;
  if (give == 0) return;
  {
    std::lock_guard<std::mutex> lk(qmu_);
    for (size_t i = 0; i < give; ++i) queue_.push_back(ts.local[i]);
  }
  ts.local.erase(ts.local.begin(), ts.local.begin() + static_cast<std::ptrdiff_t>(give));
  qcv_.notify_all();
}

void Scanner::process_dir(Node* n, ThreadState& ts) {
  const std::string path = build_path(n);
  const int fd = open_dir(n, path);
  if (fd < 0) {
    const int e = errno;
    if (n->parent != nullptr && (e == ENOENT || e == ENOTDIR || e == ELOOP)) {
      n->flags |= F_CHANGED;
      ++ts.vanished;
    } else {
      n->flags |= F_UNREADABLE;
      n->err = e;
      add_error(ts, path, e, "open");
    }
    return;
  }
  if (n->parent != nullptr) {
    struct stat st;
    if (fstat(fd, &st) == 0 && (st.st_ino != n->ino || st.st_dev != n->dev)) {
      close(fd);
      n->flags |= F_CHANGED;
      ++ts.vanished;
      return;
    }
  }

  uint64_t l_alloc = 0, l_app = 0, l_files = 0;  // files directly in this folder
  int64_t l_mtime = INT64_MIN;
  uint64_t a_alloc = 0, a_app = 0, a_files = 0;  // bytes attributed to n->match_root
  uint64_t pf_files = 0, pf_alloc = 0, pf_app = 0;  // progress not yet published
  uint64_t since_check = 0;
  const bool has_name_excl = !excl_names_lit_.empty() || !excl_names_glob_.empty();
  const bool has_path_excl = !excl_path_bases_.empty();
  const bool has_globs = !excl_globs_.empty();
  char* buf = ts.buf.data();
  const size_t bufsz = ts.buf.size();
  bool stopped = false;

  for (;;) {
    const long nread = syscall(SYS_getdents64, fd, buf, bufsz);
    if (nread < 0) {
      const int e = errno;
      if (e == EINTR) continue;
      n->flags |= F_PARTIAL;
      n->err = e;
      add_error(ts, path, e, "list");
      break;
    }
    if (nread == 0) break;
    for (long pos = 0; pos < nread;) {
      auto* d = reinterpret_cast<wf_dirent64*>(buf + pos);
      pos += d->d_reclen;
      const char* nm = d->d_name;
      if (nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0'))) continue;
      if (stop_.load(std::memory_order_relaxed)) {
        stopped = true;
        break;
      }
      const std::string_view name(nm);
      if (has_name_excl && excluded_name(name)) {
        ++ts.n_excluded;
        continue;
      }
      std::string full;
      bool built = false;
      if (has_path_excl && excluded_path(path, name, built, full)) {
        add_skip(ts, full, "excluded", 0);
        continue;
      }
      if (has_globs) {
        if (!built) {
          full = join(path, name);
          built = true;
        }
        bool hit = false;
        for (const auto& g : excl_globs_) {
          const size_t t = g.tail.size();
          if (t != 0 && (full.size() < t || full.compare(full.size() - t, t, g.tail) != 0)) continue;
          if (!g.core.empty() && full.find(g.core) == std::string::npos) continue;
          if (glob_match_path(g.pat, full)) {
            hit = true;
            break;
          }
        }
        if (hit) {
          add_skip(ts, full, "excluded", 0);
          continue;
        }
      }

      Stat st;
      const int r = do_stat(fd, nm, st);
      if (r != 0) {
        if (r == ENOENT) {
          ++ts.vanished;
          continue;
        }
        n->flags |= F_PARTIAL;
        add_error(ts, built ? full : join(path, name), r, "stat");
        continue;
      }
      const uint64_t alloc = st.blocks * 512;

      if (S_ISDIR(st.mode)) {
        st.size = 0;  // like GNU du, a folder's own st_size is not part of the apparent size
        if (st.dev != n->dev) {
          if (!built) {
            full = join(path, name);
            built = true;
          }
          const bool is_mount = mount_points_.count(full) > 0;
          if (is_mount ? opt_.one_file_system : !opt_.cross_subvolumes) {
            add_skip(ts, full, is_mount ? "mount" : "subvolume", st.dev);
            continue;
          }
        }
        Node* c = new Node();
        c->parent = n;
        c->name.assign(name.data(), name.size());
        c->dev = st.dev;
        c->ino = st.ino;
        c->depth = n->depth + 1;
        c->alloc.store(alloc, std::memory_order_relaxed);
        c->apparent.store(st.size, std::memory_order_relaxed);
        c->mtime_max.store(st.mtime, std::memory_order_relaxed);
        match_dir(c, n, fd, path);
        account(ts, c->eff_rule, st, false);
        if (c->match_root == c) {
          c->attr_alloc.store(alloc, std::memory_order_relaxed);
          c->attr_apparent.store(st.size, std::memory_order_relaxed);
        } else if (c->match_root != nullptr) {
          a_alloc += alloc;
          a_app += st.size;
        }
        n->children.push_back(c);
        n->pending.fetch_add(1, std::memory_order_relaxed);
        outstanding_.fetch_add(1, std::memory_order_relaxed);
        ts.local.push_back(c);
        pf_alloc += alloc;
        pf_app += st.size;
      } else {
        const int fr = any_file_rules_ ? match_file(name, alloc, n->eff_rule, path) : 0;
        const int rule = fr != 0 ? fr : n->eff_rule;
        if (st.nlink > 1 && !link_first(st.dev, st.ino, st.nlink, alloc, rule, ts)) {
          ++ts.hardlink_dupes;
          continue;
        }
        const uint64_t key = opt_.by_apparent ? st.size : alloc;
        ++l_files;
        l_alloc += alloc;
        l_app += st.size;
        if (st.mtime > l_mtime) l_mtime = st.mtime;
        ++pf_files;
        pf_alloc += alloc;
        pf_app += st.size;

        if (fr != 0) {
          auto& tk = ts.rule_files[fr];
          if (tk.accepts(key))
            tk.push(TopFile{key, alloc, st.size, st.mtime, st.atime, st.uid, fr, built ? full : join(path, name)});
        } else if (n->match_root != nullptr) {
          a_alloc += alloc;
          a_app += st.size;
          ++a_files;
        }
        account(ts, rule, st, true);
        UidAcc& u = ts.uids[st.uid];
        u.alloc += alloc;
        ++u.files;
        if (opt_.collect_ext) {
          const size_t dot = name.rfind('.');
          std::string ext;
          if (dot != std::string_view::npos && dot > 0 && dot + 1 < name.size() && name.size() - dot <= 11)
            ext = lower_ascii(name.substr(dot + 1));
          UidAcc& x = ts.exts[ext];
          x.alloc += alloc;
          ++x.files;
        }
        if (ts.top_files.accepts(key))
          ts.top_files.push(TopFile{key, alloc, st.size, st.mtime, st.atime, st.uid, rule, built ? full : join(path, name)});
        if (key >= opt_.big_file_min)
          n->big_files.push_back(FileRec{std::string(name), alloc, st.size, st.mtime, st.atime, st.uid, rule});
      }

      if (++since_check >= 512) {
        since_check = 0;
        p_files_.fetch_add(pf_files, std::memory_order_relaxed);
        p_alloc_.fetch_add(pf_alloc, std::memory_order_relaxed);
        p_apparent_.fetch_add(pf_app, std::memory_order_relaxed);
        pf_files = pf_alloc = pf_app = 0;
        if (idle_.load(std::memory_order_relaxed) > 0 && ts.local.size() >= 2) share_work(ts);
      }
    }
    if (stopped) break;
  }
  close(fd);
  if (stopped) n->flags |= F_INCOMPLETE;

  if (l_files != 0) {
    n->alloc.fetch_add(l_alloc, std::memory_order_relaxed);
    n->apparent.fetch_add(l_app, std::memory_order_relaxed);
    n->files.fetch_add(l_files, std::memory_order_relaxed);
    atomic_max(n->mtime_max, l_mtime);
  }
  if (n->match_root != nullptr && (a_alloc | a_app | a_files) != 0) {
    n->match_root->attr_alloc.fetch_add(a_alloc, std::memory_order_relaxed);
    n->match_root->attr_apparent.fetch_add(a_app, std::memory_order_relaxed);
    n->match_root->attr_files.fetch_add(a_files, std::memory_order_relaxed);
  }
  p_files_.fetch_add(pf_files, std::memory_order_relaxed);
  p_alloc_.fetch_add(pf_alloc, std::memory_order_relaxed);
  p_apparent_.fetch_add(pf_app, std::memory_order_relaxed);
  p_dirs_.fetch_add(1, std::memory_order_relaxed);
}

void Scanner::finish(Node* n, ThreadState& ts) {
  while (n != nullptr) {
    if (n->pending.fetch_sub(1, std::memory_order_acq_rel) != 1) return;
    finalize(n, ts);
    Node* p = n->parent;
    if (p == nullptr) return;
    p->alloc.fetch_add(n->alloc.load(std::memory_order_relaxed), std::memory_order_relaxed);
    p->apparent.fetch_add(n->apparent.load(std::memory_order_relaxed), std::memory_order_relaxed);
    p->files.fetch_add(n->files.load(std::memory_order_relaxed), std::memory_order_relaxed);
    p->dirs.fetch_add(n->dirs.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
    atomic_max(p->mtime_max, n->mtime_max.load(std::memory_order_relaxed));
    const uint32_t f = (n->flags | n->sub_flags.load(std::memory_order_relaxed)) & kProblemFlags;
    if (f != 0) p->sub_flags.fetch_or(f, std::memory_order_relaxed);
    n = p;
  }
}

void Scanner::finalize(Node* n, ThreadState& ts) {
  if (n->flags & F_MATCH) {
    RuleAcc& acc = ts.rules[n->match_rule];
    ++acc.matches;
    auto& tk = ts.match_top[n->match_rule];
    const uint64_t a = n->attr_alloc.load(std::memory_order_relaxed);
    const uint64_t ap = n->attr_apparent.load(std::memory_order_relaxed);
    const uint64_t key = opt_.by_apparent ? ap : a;
    if (tk.accepts(key)) {
      tk.push(MatchRec{key, n->match_rule, n->outer_rule, a, ap,
                       n->attr_files.load(std::memory_order_relaxed), n->mtime_max.load(std::memory_order_relaxed),
                       n->flags | n->sub_flags.load(std::memory_order_relaxed), build_path(n)});
    }
  }
  if (n->children.empty() || opt_.keep_dir_min == 0) return;
  auto size_of = [this](const Node* x) {
    return opt_.by_apparent ? x->apparent.load(std::memory_order_relaxed) : x->alloc.load(std::memory_order_relaxed);
  };
  if (n->parent != nullptr && size_of(n) < opt_.keep_dir_min) {
    // Small folder: keep only its totals.
    free_children(n);
    n->flags |= F_PRUNED;
    return;
  }
  // Kept folder: list sub-folders that are big enough to matter, plus its
  // largest few small ones so small scans still show some structure. The
  // others are already finished, and their sizes are in this folder's totals.
  auto big_end = std::stable_partition(n->children.begin(), n->children.end(),
                                       [&](Node* c) { return size_of(c) >= opt_.keep_dir_min; });
  const size_t n_small = static_cast<size_t>(n->children.end() - big_end);
  if (n_small > opt_.keep_small_children) {
    auto keep_end = big_end + static_cast<std::ptrdiff_t>(opt_.keep_small_children);
    std::nth_element(big_end, keep_end, n->children.end(),
                     [&](Node* a, Node* b) { return size_of(a) > size_of(b); });
    std::vector<Node*> drop(keep_end, n->children.end());
    n->children.erase(keep_end, n->children.end());
    for (Node* c : drop) {
      free_children(c);
      delete c;
    }
  }
}

void Scanner::free_children(Node* n) {
  std::vector<Node*> stack(n->children.begin(), n->children.end());
  n->children.clear();
  n->children.shrink_to_fit();
  while (!stack.empty()) {
    Node* x = stack.back();
    stack.pop_back();
    stack.insert(stack.end(), x->children.begin(), x->children.end());
    delete x;
  }
}

}  // namespace wf
