#!/usr/bin/env python3
"""Cull a wordlist by greedily removing the word with the smallest
nearest-neighbour Levenshtein distance, maximising the minimum edit
distance of the surviving set.

Usage:
    python scripts/cull_wordlist.py data/bip39_english.txt 1024 data/wordlist_1024.txt
    python scripts/cull_wordlist.py data/bip39_english.txt 512  data/wordlist_512.txt

    # Just print stats without writing:
    python scripts/cull_wordlist.py data/bip39_english.txt --stats
"""

import sys
import time
import numpy as np
from pathlib import Path


def levenshtein(a: str, b: str) -> int:
    """Pure-Python Levenshtein distance."""
    m, n = len(a), len(b)
    if abs(m - n) > 10:
        return abs(m - n)
    prev = list(range(n + 1))
    curr = [0] * (n + 1)
    for i in range(1, m + 1):
        curr[0] = i
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev, curr = curr, prev
    return prev[n]


def compute_distance_matrix(words: list[str]) -> np.ndarray:
    """Compute full NxN Levenshtein distance matrix (uint8)."""
    n = len(words)
    dist = np.zeros((n, n), dtype=np.uint8)
    total = n * (n - 1) // 2
    done = 0
    t0 = time.time()
    report_interval = max(total // 20, 1)

    for i in range(n):
        for j in range(i + 1, n):
            d = levenshtein(words[i], words[j])
            dist[i, j] = d
            dist[j, i] = d
            done += 1
            if done % report_interval == 0:
                elapsed = time.time() - t0
                pct = done / total * 100
                rate = done / elapsed if elapsed > 0 else 0
                eta = (total - done) / rate if rate > 0 else 0
                print(
                    f"  distance matrix: {pct:5.1f}%  ({done}/{total})  "
                    f"elapsed {elapsed:.0f}s  eta {eta:.0f}s",
                    file=sys.stderr,
                )

    np.fill_diagonal(dist, 255)  # Self-distance = large sentinel
    elapsed = time.time() - t0
    print(f"  distance matrix complete in {elapsed:.1f}s", file=sys.stderr)
    return dist


def cull(
    words: list[str], dist: np.ndarray, target: int, stats_only: bool = False
) -> list[str]:
    """Greedily remove words until `target` remain."""
    n = len(words)
    active = np.ones(n, dtype=bool)
    current_size = n

    # Milestones to report.
    milestones = sorted(
        {2048, 1792, 1536, 1280, 1024, 896, 768, 640, 512, 384, 256, 128, target}
        & set(range(1, n + 1)),
        reverse=True,
    )
    next_milestone_idx = 0

    def min_dists_active():
        """For each active word, its min distance to any other active word."""
        idx = np.where(active)[0]
        sub = dist[np.ix_(idx, idx)]
        return idx, sub.min(axis=1)

    def report(size, min_d, avg_min_d, median_min_d):
        print(
            f"  size={size:>5}  min_edit_dist={min_d}  "
            f"avg_nearest={avg_min_d:.2f}  median_nearest={median_min_d:.1f}",
            file=sys.stderr,
        )

    t0 = time.time()

    while current_size > target:
        idx, md = min_dists_active()
        global_min = md.min()

        # Report at milestones.
        while (
            next_milestone_idx < len(milestones)
            and current_size <= milestones[next_milestone_idx]
        ):
            report(current_size, int(global_min), float(md.mean()), float(np.median(md)))
            next_milestone_idx += 1

        # Find all words at global minimum distance.
        candidates = np.where(md == global_min)[0]

        if len(candidates) == 1:
            remove_local = candidates[0]
        else:
            # Tie-break: among candidates, find the one with the smallest
            # second-nearest distance (most crowded neighborhood).
            worst = None
            worst_second = 999
            for c in candidates:
                row = dist[idx[c], idx]
                row_sorted = np.sort(row)
                # row_sorted[0] is self (255 sentinel won't appear after masking)
                # Actually sub already excludes self via fill_diagonal(255).
                # So row_sorted[0]=global_min, row_sorted[1]=second-nearest.
                second = int(row_sorted[1]) if len(row_sorted) > 1 else 999
                if second < worst_second or (
                    second == worst_second and (worst is None or idx[c] < idx[worst])
                ):
                    worst_second = second
                    worst = c
            remove_local = worst

        active[idx[remove_local]] = False
        current_size -= 1

    # Final report.
    idx, md = min_dists_active()
    report(current_size, int(md.min()), float(md.mean()), float(np.median(md)))

    elapsed = time.time() - t0
    print(f"  culling complete in {elapsed:.1f}s", file=sys.stderr)

    return [words[i] for i in np.where(active)[0]]


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    input_file = Path(sys.argv[1])
    words = input_file.read_text().strip().splitlines()
    words = [w.strip().lower() for w in words if w.strip()]
    print(f"loaded {len(words)} words from {input_file}", file=sys.stderr)

    stats_only = sys.argv[2] == "--stats"
    target = 256 if stats_only else int(sys.argv[2])

    if target >= len(words):
        print(f"target {target} >= input size {len(words)}, nothing to do", file=sys.stderr)
        sys.exit(0)

    print("computing distance matrix...", file=sys.stderr)
    dist = compute_distance_matrix(words)

    # Show initial stats.
    idx = np.where(np.ones(len(words), dtype=bool))[0]
    md_all = dist.min(axis=1)
    print(
        f"  full list: min_edit_dist={int(md_all.min())}  "
        f"closest pair: {words[md_all.argmin()]} <-> ???",
        file=sys.stderr,
    )
    worst_i = int(md_all.argmin())
    row = dist[worst_i]
    worst_j = int(row.argmin())
    print(
        f"  closest pair: '{words[worst_i]}' <-> '{words[worst_j]}' "
        f"(distance {int(dist[worst_i, worst_j])})",
        file=sys.stderr,
    )

    print(f"\nculling from {len(words)} to {target}...", file=sys.stderr)
    result = cull(words, dist, target, stats_only)

    if not stats_only and len(sys.argv) >= 4:
        output_file = Path(sys.argv[3])
        output_file.write_text("\n".join(sorted(result)) + "\n")
        print(f"wrote {len(result)} words to {output_file}", file=sys.stderr)
    elif not stats_only:
        for w in sorted(result):
            print(w)


if __name__ == "__main__":
    main()
