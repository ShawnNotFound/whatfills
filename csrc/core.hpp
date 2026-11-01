// whatfills scanning core: a parallel, bounded-memory directory walker for Linux.
//
// Design notes (see docs/design.md for the full picture):
//  * Directories are tasks. Workers keep a local LIFO stack (depth first, good
//    locality, low memory) and hand the oldest half to a shared FIFO queue when
//    another worker is idle.
//  * Entries are read with getdents64 into a large buffer and stat'ed with
//    statx (only the fields we need, AT_NO_AUTOMOUNT so autofs mounts are not
//    triggered), falling back to fstatat on kernels or sandboxes without statx.
//  * Sizes are aggregated bottom-up without locks: every folder counts its
//    unfinished children, and the last child to finish folds the totals into
//    its parent. Small finished folders drop their sub-folders, so memory stays
//    bounded on trees with tens of millions of entries.
//  * Rule matching (what a folder or file *is*) happens inline, so totals per
//    cause are exact even for folders that are later dropped from the tree.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace wf {

constexpr int kAgeBuckets = 7;  // <1 day, <1 week, <30 days, <90 days, <1 year, <3 years, older

// Node flags.
enum : uint32_t {
  F_UNREADABLE = 1u << 0,  // folder could not be opened or listed
  F_PARTIAL = 1u << 1,     // some entries could not be read
  F_INCOMPLETE = 1u << 2,  // scan stopped before this folder was finished
  F_PRUNED = 1u << 3,      // small folder; its sub-folders were not kept
  F_MATCH = 1u << 4,       // a folder rule matched here
  F_CHANGED = 1u << 5,     // folder vanished or was replaced during the scan
};
constexpr uint32_t kProblemFlags = F_UNREADABLE | F_PARTIAL | F_INCOMPLETE | F_CHANGED;

// A folder rule pattern. One rule may contribute several patterns.
struct DirRule {
  int id = 0;                     // rule id, >= 1
  int order = 0;                  // lower wins when several rules match one folder
  bool anchored = false;          // components start at '/'; otherwise they match a path suffix
  std::vector<std::string> comps;  // path components, may contain glob characters
  std::vector<bool> comp_glob;
  std::vector<std::string> require_child;    // any of these names must exist inside the folder
  std::vector<std::string> require_sibling;  // any of these names must exist next to the folder
};

// A file rule pattern.
struct FileRule {
  int id = 0;
  int order = 0;
  std::vector<std::string> globs;   // matched against the file name
  uint64_t min_size = 0;            // allocated bytes
  std::vector<int> within;          // only inside folders of these rules (empty = anywhere)
  std::vector<int> not_within;      // never inside folders of these rules
  std::vector<std::string> in_dirs;  // only directly inside these absolute folders (empty = anywhere)
};

struct Options {
  std::string root;
  int threads = 4;
  bool one_file_system = true;
  bool cross_subvolumes = false;
  bool dont_sync = false;     // AT_STATX_DONT_SYNC: use cached attributes on network filesystems
  bool collect_ext = true;
  bool by_apparent = false;   // rank and keep by apparent size instead of disk usage
  int io_class = 0;           // 0 leave as is, 2 best-effort lowest, 3 idle
  int nice = 0;               // 0 leave as is, otherwise setpriority() value for workers
  uint64_t keep_dir_min = 1ull << 20;
  size_t keep_small_children = 20;  // per kept folder, also keep this many of its largest small sub-folders
  uint64_t big_file_min = 64ull << 20;
  size_t top_files = 200;
  size_t matches_per_rule = 100;
  size_t files_per_rule = 20;
  size_t max_errors = 500;
  size_t max_skips = 500;
  size_t max_links = 16u << 20;  // files with several hard links tracked to count them once (~64 bytes each)
  size_t dents_buffer = 128 * 1024;
  int64_t now = 0;  // reference time for age buckets (unix seconds)
  std::vector<std::string> exclude_paths;
  std::vector<std::string> exclude_names;
  std::vector<std::string> exclude_globs;
  std::vector<std::string> mount_points;  // mount points under root, to tell mounts from btrfs subvolumes
  std::vector<DirRule> dir_rules;
  std::vector<FileRule> file_rules;
  std::vector<int> opaque_rules;  // folder rules that own everything inside: no folder rule matches below them
  int max_rule_id = 0;
};

struct FileRec {
  std::string name;
  uint64_t alloc = 0, apparent = 0;
  int64_t mtime = 0, atime = 0;
  uint32_t uid = 0;
  int32_t rule = 0;
};

struct Node {
  Node* parent = nullptr;
  Node* match_root = nullptr;  // nearest folder (self or ancestor) where a folder rule matched
  std::string name;            // the root node holds the full root path
  std::vector<Node*> children;
  std::vector<FileRec> big_files;
  uint64_t dev = 0, ino = 0;
  std::atomic<uint64_t> alloc{0}, apparent{0}, files{0}, dirs{0};
  std::atomic<int64_t> mtime_max{INT64_MIN};
  std::atomic<int32_t> pending{1};
  std::atomic<uint32_t> sub_flags{0};
  std::atomic<uint64_t> attr_alloc{0}, attr_apparent{0}, attr_files{0};
  uint32_t flags = 0;
  int32_t err = 0;
  int32_t eff_rule = 0, match_rule = 0, outer_rule = 0;
  uint32_t depth = 0;
};

struct TopFile {
  uint64_t key = 0;  // ranking size (disk usage or apparent size)
  uint64_t alloc = 0, apparent = 0;
  int64_t mtime = 0, atime = 0;
  uint32_t uid = 0;
  int32_t rule = 0;
  std::string path;
};

struct MatchRec {
  uint64_t key = 0;
  int32_t rule = 0, outer = 0;
  uint64_t alloc = 0, apparent = 0, files = 0;
  int64_t mtime = 0;
  uint32_t flags = 0;
  std::string path;
};

struct ErrRec {
  std::string path;
  int err = 0;
  const char* op = "";
};

struct SkipRec {
  std::string path;
  const char* reason = "";
  uint64_t dev = 0;
};

// Keeps the k items with the largest `key` (zero-sized items are ignored).
template <class T>
class TopK {
 public:
  explicit TopK(size_t k = 0) : k_(k) {}
  void set_k(size_t k) { k_ = k; }
  bool accepts(uint64_t key) const { return k_ > 0 && key > 0 && (heap_.size() < k_ || key > heap_.front().key); }
  void push(T&& item);
  std::vector<T>& items() { return heap_; }

 private:
  size_t k_;
  std::vector<T> heap_;  // min-heap on key
};

struct RuleAcc {
  uint64_t alloc = 0, apparent = 0, files = 0, matches = 0;
  uint64_t age_mtime[kAgeBuckets] = {};
  uint64_t age_atime[kAgeBuckets] = {};
};

struct UidAcc {
  uint64_t alloc = 0, files = 0;
};

// Files with several hard links, after the scan.
struct LinkSummary {
  uint64_t files = 0, alloc = 0;                // counted once each
  uint64_t shared_files = 0, shared_alloc = 0;  // some links outside the scan, or under another cause
  uint64_t cross_rule_alloc = 0;                // links under different causes
  uint64_t inside_alloc = 0;                    // more than one link inside the scan
  uint64_t untracked = 0;                       // links counted without the table (it was full)
};

struct ThreadState {
  std::vector<char> buf;
  std::vector<Node*> local;
  std::vector<RuleAcc> rules;
  std::vector<TopK<MatchRec>> match_top;
  std::vector<TopK<TopFile>> rule_files;
  TopK<TopFile> top_files;
  std::unordered_map<uint32_t, UidAcc> uids;
  std::unordered_map<std::string, UidAcc> exts;
  std::vector<ErrRec> errors;
  std::unordered_map<int, uint64_t> errnos;
  std::vector<SkipRec> skips;
  uint64_t n_errors = 0, n_skips = 0, n_excluded = 0;
  uint64_t hardlink_dupes = 0, vanished = 0, links_untracked = 0;
};

struct Progress {
  uint64_t files, dirs, alloc, apparent, errors;
  bool done;
  bool stopping;
};

class Scanner {
 public:
  explicit Scanner(Options opt);
  ~Scanner();
  Scanner(const Scanner&) = delete;
  Scanner& operator=(const Scanner&) = delete;

  void start();                    // throws std::runtime_error with a clear message
  bool wait(double timeout_s);     // true when finished
  void cancel();                   // stop as soon as possible; results become partial
  Progress progress() const;
  bool finished() const { return finished_.load(); }

  // Valid after wait() returned true.
  Node* root() const { return root_; }
  std::vector<ThreadState*> states() const;
  double elapsed() const { return elapsed_; }
  bool used_statx() const { return use_statx_.load(); }
  int threads() const { return opt_.threads; }
  bool was_stopped() const { return stop_.load(); }
  const Options& options() const { return opt_; }
  std::string build_path(const Node* n) const;
  // Bytes in multiply-linked files that deleting their cause would not free,
  // per rule (indexed by rule id), plus totals.
  LinkSummary link_summary(std::vector<uint64_t>& shared_by_rule) const;

 private:
  struct Stat {
    uint32_t mode = 0, nlink = 0, uid = 0;
    uint64_t ino = 0, size = 0, blocks = 0, dev = 0;
    int64_t mtime = 0, atime = 0;
  };

  void worker(int idx);
  Node* next_task(ThreadState& ts);
  void share_work(ThreadState& ts);
  void process_dir(Node* n, ThreadState& ts);
  void finish(Node* n, ThreadState& ts);
  void finalize(Node* n, ThreadState& ts);
  void free_children(Node* n);
  int open_dir(const Node* n, const std::string& path);
  int do_stat(int dirfd, const char* name, Stat& st);
  void match_dir(Node* c, const Node* parent, int parent_fd, const std::string& parent_path);
  long match_markers(Node* n, int fd, char* buf, size_t bufsz, bool& eof, ThreadState& ts);
  const DirRule* markers_in(const char* buf, long len, const Node* n, int limit, int inherited) const;
  bool marker_applies(const DirRule& r, const Node* n, int limit, int inherited) const;
  void claim_by_marker(Node* n, const DirRule& r, ThreadState& ts);
  bool dir_rule_matches(const DirRule& r, const Node* c) const;
  bool context_ok(const DirRule& r, int parent_fd, const std::string& parent_path, std::string_view name) const;
  int match_file(std::string_view name, uint64_t alloc, int dir_rule, const std::string& dir_path) const;
  bool excluded_name(std::string_view name) const;
  bool excluded_path(const std::string& dir_path, std::string_view name, bool& built, std::string& full) const;
  void account(ThreadState& ts, int rule, const Stat& st, bool is_file);
  void add_error(ThreadState& ts, std::string path, int err, const char* op);
  void add_skip(ThreadState& ts, std::string path, const char* reason, uint64_t dev);

  Options opt_;
  Node* root_ = nullptr;
  std::vector<std::string> root_comps_;
  std::vector<std::unique_ptr<ThreadState>> states_;
  std::vector<std::thread> threads_;

  // Exclusions and rule indexes.
  struct PathGlob {
    std::string pat;   // starts with '/'
    std::string tail;  // literal end of the pattern, checked first
    std::string core;  // longest literal part, checked next
  };
  std::unordered_set<std::string> excl_names_lit_;
  std::vector<std::string> excl_names_glob_;
  std::vector<PathGlob> excl_globs_;
  std::unordered_set<std::string> excl_paths_;
  std::unordered_set<std::string> excl_path_bases_;
  std::unordered_set<std::string> mount_points_;
  std::unordered_map<std::string, std::vector<const DirRule*>> dir_by_last_;
  std::vector<const DirRule*> dir_wild_;
  // Rules for "any folder that holds one of these names" (dirs = ["*"] with
  // require_child). They are checked against the entries of a folder as it is
  // read, so they cost no lookups.
  std::vector<const DirRule*> dir_marker_;
  std::vector<std::pair<std::string, const DirRule*>> marker_names_;
  bool marker_first_[256] = {};  // first bytes of marker names, a cheap filter
  std::vector<int> rule_order_;  // best order of each folder rule's patterns, by rule id
  std::vector<char> opaque_;     // by rule id
  std::unordered_map<std::string, std::vector<std::pair<std::string, const FileRule*>>> file_by_ext_;
  std::vector<std::pair<std::string, const FileRule*>> file_generic_;
  bool any_file_rules_ = false;

  // Scheduling.
  std::mutex qmu_;
  std::condition_variable qcv_;
  std::deque<Node*> queue_;
  std::atomic<int64_t> outstanding_{0};
  std::atomic<int> idle_{0};
  bool done_ = false;  // guarded by qmu_

  std::mutex done_mu_;
  std::condition_variable done_cv_;
  std::atomic<bool> finished_{false};
  std::atomic<bool> stop_{false};
  std::atomic<int> running_workers_{0};
  bool started_ = false;
  bool joined_ = false;
  double elapsed_ = 0;
  std::chrono::steady_clock::time_point t0_;

  std::atomic<bool> use_statx_{true};
  bool noatime_ = false;

  // Progress counters.
  std::atomic<uint64_t> p_files_{0}, p_dirs_{0}, p_alloc_{0}, p_apparent_{0}, p_errors_{0};

  // Hard links: multiply-linked files already counted, keyed by (dev, ino).
  struct InoKey {
    uint64_t dev, ino;
    bool operator==(const InoKey& o) const { return dev == o.dev && ino == o.ino; }
  };
  struct InoHash {
    size_t operator()(const InoKey& k) const { return std::hash<uint64_t>()(k.ino * 0x9E3779B97F4A7C15ull ^ k.dev); }
  };
  struct LinkRec {
    uint64_t alloc = 0;
    uint32_t nlink = 0;  // links the filesystem reports
    uint32_t seen = 0;   // links this scan found
    int32_t rule = 0;    // cause credited with the bytes (where the first link was found)
    bool other_rule = false;
  };
  static constexpr int kShards = 64;
  struct Shard {
    std::mutex mu;
    std::unordered_map<InoKey, LinkRec, InoHash> map;
  };
  std::unique_ptr<Shard[]> hardlinks_;
  std::atomic<uint64_t> links_tracked_{0};
  // True for the first link found to a file (count its bytes then).
  bool link_first(uint64_t dev, uint64_t ino, uint32_t nlink, uint64_t alloc, int32_t rule, ThreadState& ts);
};

}  // namespace wf
