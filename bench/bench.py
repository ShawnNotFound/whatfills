"""Time whatfills against other disk usage tools on the same folder.

    python bench/bench.py /tmp/wf-bench --runs 3

Each tool runs `--runs` times on a warm cache; the best time and the peak
memory (RSS) of that run are reported. Cold-cache numbers need root: pass
--drop-caches to flush the page cache before every run
(sync; echo 3 > /proc/sys/vm/drop_caches). Tools that are not installed are
skipped.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time


def tools(root: str, threads: int | None) -> dict:
    j = [f"-j{threads}"] if threads else []
    t = {
        "whatfills": [sys.executable, "-m", "whatfills", root, "--no-config", "-q", "--json", os.devnull, "--color", "never"] + j,
        "du -sx": ["du", "-sxB1", root],
        "gdu": ["gdu", "-n", "-x", "-p", root],
        "dua": ["dua", "-f", "bytes", root],
        "dust": ["dust", "-x", "-n", "1", root],
        "ncdu -o": ["ncdu", "-x", "-0", "-o", os.devnull, root],
    }
    return {name: cmd for name, cmd in t.items() if shutil.which(cmd[0]) or cmd[0] == sys.executable}


# A child's peak RSS (ru_maxrss) includes the memory of the process that
# started it, so measuring straight from Python adds Python's own ~13 MiB.
# This small launcher keeps that floor near 1 MiB.
_LAUNCHER = r"""
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
  pid_t pid = fork();
  if (pid == 0) { execvp(argv[1], argv + 1); _exit(127); }
  int st; struct rusage ru;
  if (pid < 0 || wait4(pid, &st, 0, &ru) < 0) return 126;
  fprintf(stderr, "\n@@maxrss %ld\n", ru.ru_maxrss);
  return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}
"""


def build_launcher(tmp: str) -> str | None:
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        return None
    src, exe = os.path.join(tmp, "launch.c"), os.path.join(tmp, "launch")
    with open(src, "w") as f:
        f.write(_LAUNCHER)
    r = subprocess.run([cc, "-O2", "-o", exe, src], capture_output=True)
    return exe if r.returncode == 0 else None


def run_once(cmd: list, launcher: str | None) -> tuple:
    """Run a command; return (seconds, peak RSS in KiB, exit code, stderr)."""
    t = time.perf_counter()
    if launcher:
        r = subprocess.run([launcher, *cmd], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        el = time.perf_counter() - t
        err, _, tail = r.stderr.decode(errors="replace").rpartition("\n@@maxrss ")
        return el, int(tail.split()[0]) if tail.strip() else 0, r.returncode, err
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    err = p.stderr.read()
    p.stderr.close()
    _, status, usage = os.wait4(p.pid, 0)
    el = time.perf_counter() - t
    p.returncode = os.waitstatus_to_exitcode(status)
    return el, usage.ru_maxrss, p.returncode, err.decode(errors="replace")


def drop_caches() -> None:
    subprocess.run(["sync"], check=False)
    with open("/proc/sys/vm/drop_caches", "w") as f:
        f.write("3\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--threads", type=int, help="threads for whatfills (default: automatic)")
    ap.add_argument("--drop-caches", action="store_true", help="flush the page cache before each run (root)")
    ap.add_argument("--only", action="append", help="run only these tools")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    tmp = tempfile.mkdtemp(prefix="bench-")
    launcher = build_launcher(tmp)
    if launcher is None:
        print("no C compiler: peak memory includes about 13 MiB of Python's own", file=sys.stderr)
    results = {}
    for name, cmd in tools(a.root, a.threads).items():
        if a.only and name not in a.only:
            continue
        best = None
        for _ in range(a.runs):
            if a.drop_caches:
                drop_caches()
            el, rss, code, err = run_once(cmd, launcher)
            if code not in (0, 130):
                print(f"{name}: failed (exit {code}): {err[:200]}", file=sys.stderr)
                best = None
                break
            if best is None or el < best[0]:
                best = (el, rss)
        if best is not None:
            results[name] = {"seconds": round(best[0], 3), "peak_rss_mib": round(best[1] / 1024, 1)}
            print(f"{name:<10} {best[0]:8.2f} s  {best[1] / 1024:8.1f} MiB", file=sys.stderr)
    shutil.rmtree(tmp, ignore_errors=True)
    if a.json:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
