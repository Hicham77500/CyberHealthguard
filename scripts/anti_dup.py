#!/usr/bin/env python3
"""Static duplicate scanner for CyberHealthGuard.

Features
--------
1. Detects byte-identical files (hash collisions) across the repo.
2. Detects repeated text blocks across files (default chunks of 6 lines).
3. Emits a remediation plan (JSON) when duplicates are found, so refactors can
   be scheduled explicitly ("anti-régression").

Exit codes
----------
0 → no duplicates detected
1 → duplicates found (details printed)
2 → runtime error (bad args, unreadable files, etc.)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".mjs",
    ".cjs",
    ".json",
    ".md",
    ".yml",
    ".yaml",
    ".sh",
    ".toml",
    ".lock",
}
SKIP_DIRS = {".git", "node_modules", "dist", "build", "__pycache__", ".next", ".vercel"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect duplicate files/blocks.")
    parser.add_argument(
        "paths",
        nargs="*",
        default=[str(REPO_ROOT)],
        help="Files or directories to scan (default: repo root)",
    )
    parser.add_argument(
        "--extensions",
        nargs="*",
        default=sorted(DEFAULT_EXTENSIONS),
        help="File extensions to include (default: common text/code formats)",
    )
    parser.add_argument(
        "--min-lines",
        type=int,
        default=6,
        help="Sliding window size for duplicate block detection",
    )
    parser.add_argument(
        "--plan",
        type=Path,
        default=REPO_ROOT / "scripts/.anti_dup_plan.json",
        help="Where to store the remediation plan when duplicates are found",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail when no eligible files are scanned (safety net for CI).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every file as it is scanned",
    )
    return parser.parse_args()


def iter_candidate_files(paths: Sequence[str], extensions: Sequence[str]) -> Iterable[Path]:
    allowed = {ext.lower() for ext in extensions}
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            if allowed and path.suffix.lower() not in allowed:
                continue
            yield path
            continue
        if path.is_dir():
            for file in path.rglob("*"):
                if file.is_dir():
                    if file.name in SKIP_DIRS:
                        # Skip entire sub-tree
                        dir_path = file
                        for child in dir_path.iterdir():
                            # just touching to ensure generator continues
                            break
                    continue
                if allowed and file.suffix.lower() not in allowed:
                    continue
                if any(part in SKIP_DIRS for part in file.parts):
                    continue
                yield file


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_duplicate_files(files: Iterable[Path]) -> Dict[str, List[str]]:
    buckets: Dict[str, List[str]] = {}
    for file in files:
        try:
            digest = file_hash(file)
        except OSError as exc:  # unreadable file
            print(f"[anti-dup] ⚠️  Impossible de lire {file}: {exc}")
            continue
        buckets.setdefault(digest, []).append(str(file.relative_to(REPO_ROOT)))
    return {h: paths for h, paths in buckets.items() if len(paths) > 1}


def detect_duplicate_blocks(files: Iterable[Path], window: int) -> Dict[str, List[Tuple[str, int]]]:
    duplicates: Dict[str, List[Tuple[str, int]]] = {}
    for file in files:
        try:
            text = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        if len(lines) < window:
            continue
        normalized = [line.strip() for line in lines]
        for idx in range(len(lines) - window + 1):
            block = normalized[idx : idx + window]
            if not any(block):
                continue
            key = "\n".join(block)
            duplicates.setdefault(key, []).append((str(file.relative_to(REPO_ROOT)), idx + 1))
    return {k: v for k, v in duplicates.items() if len(v) > 1}


def main() -> int:
    args = parse_args()
    paths = list(iter_candidate_files(args.paths, args.extensions))
    if args.strict and not paths:
        print("[anti-dup] Aucun fichier éligible détecté avec ce filtre.")
        return 2
    if args.verbose:
        for path in paths:
            print(f"[anti-dup] Scanning {path}")
    duplicate_files = detect_duplicate_files(paths)
    duplicate_blocks = detect_duplicate_blocks(paths, args.min_lines)
    findings = {
        "duplicate_files": duplicate_files,
        "duplicate_blocks": {
            block: occurrences[:20]  # cap output to keep plan readable
            for block, occurrences in duplicate_blocks.items()
        },
    }
    has_findings = bool(duplicate_files or duplicate_blocks)
    if has_findings:
        args.plan.parent.mkdir(parents=True, exist_ok=True)
        args.plan.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
        print(f"[anti-dup] ❌ doublons détectés. Plan écrit dans {args.plan}.")
        if duplicate_files:
            print("\n== Fichiers identiques ==")
            for digest, files in duplicate_files.items():
                print(f"hash={digest[:12]} → {len(files)} fichiers")
                for file in files:
                    print(f"  - {file}")
        if duplicate_blocks:
            print("\n== Blocs répétés ==")
            for snippet, occurrences in list(duplicate_blocks.items())[:5]:
                preview = snippet.splitlines()[0][:80]
                print(f"Bloc '{preview}...' trouvé {len(occurrences)} fois")
    else:
        if args.plan.exists():
            args.plan.unlink()
        print("[anti-dup] ✅ aucun doublon critique.")
    return 1 if has_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
