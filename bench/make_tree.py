"""Create a synthetic folder tree for benchmarks.

The shape mimics a busy machine: a few deep project trees with many small
files (node_modules-like), some wide flat folders (dataset-like), and a
spread of file sizes. Files are sparse or tiny so the tree costs inodes, not
disk space.

    python bench/make_tree.py /tmp/wf-bench --files 2000000
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time


def build(root: str, files: int, seed: int = 42) -> tuple[int, int]:
    rnd = random.Random(seed)
    os.makedirs(root, exist_ok=True)
    made_files = made_dirs = 0
    t0 = time.time()

    def mkfile(path: str, size: int) -> None:
        nonlocal made_files
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            if size:
                os.ftruncate(fd, size)  # sparse: apparent size only
        finally:
            os.close(fd)
        made_files += 1

    budget = files
    # 1) Wide dataset folders: 10% of files, 5,000 per folder.
    wide = budget // 10
    for i in range(max(1, wide // 5000)):
        d = os.path.join(root, "datasets", f"shard{i:03d}")
        os.makedirs(d, exist_ok=True)
        made_dirs += 1
        for j in range(min(5000, wide)):
            mkfile(os.path.join(d, f"img{j:05d}.jpg"), rnd.randrange(20_000, 400_000))
    # 2) Deep project trees: the rest, in folders of ~12 files, 3-6 levels deep.
    remaining = files - made_files
    proj = 0
    while remaining > 0:
        base = os.path.join(root, "projects", f"p{proj:04d}", "node_modules")
        proj += 1
        pkgs = rnd.randrange(50, 400)
        for k in range(pkgs):
            depth = rnd.randrange(1, 5)
            parts = [f"pkg{k}"] + [rnd.choice(["lib", "dist", "src", "esm", "cjs", "types"]) for _ in range(depth)]
            d = os.path.join(base, *parts)
            os.makedirs(d, exist_ok=True)
            made_dirs += depth + 1
            n = min(remaining, rnd.randrange(4, 20))
            for j in range(n):
                mkfile(os.path.join(d, f"f{j}.js"), rnd.choice([0, 120, 800, 3_000, 15_000, 90_000]))
            remaining -= n
            if remaining <= 0:
                break
        if made_files and made_files % 200_000 < 400:
            rate = made_files / max(1e-9, time.time() - t0)
            print(f"  {made_files:,} files ({rate:,.0f}/s)", file=sys.stderr)
    return made_files, made_dirs


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--files", type=int, default=1_000_000)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    if os.path.exists(a.root) and os.listdir(a.root):
        sys.exit(f"{a.root} is not empty; pick a new folder")
    t = time.time()
    f, d = build(a.root, a.files, a.seed)
    print(f"created {f:,} files in about {d:,} folders under {a.root} in {time.time() - t:.0f} s")


if __name__ == "__main__":
    main()
