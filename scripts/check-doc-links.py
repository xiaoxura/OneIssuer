#!/usr/bin/env python3
"""Reject broken or escaping local links in maintained Markdown files."""

from __future__ import annotations

import os
import pathlib
import re
import sys
import urllib.parse


ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRECTORIES = {
    ".git",
    ".tools",
    ".artifacts",
    ".oneissuer-dev",
    "bin",
    "coverage",
    "dist",
    "node_modules",
}
INLINE_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def markdown_files() -> list[pathlib.Path]:
    result: list[pathlib.Path] = []
    for current, directories, files in os.walk(ROOT):
        directories[:] = sorted(name for name in directories if name not in SKIP_DIRECTORIES)
        base = pathlib.Path(current)
        result.extend(base / name for name in sorted(files) if name.endswith(".md"))
    return result


def destination(raw: str) -> str:
    value = raw.strip()
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    # Markdown permits an optional title after whitespace. Repository-local link
    # paths intentionally contain no unescaped whitespace, so split safely here.
    return value.split(maxsplit=1)[0] if value else ""


problems: list[str] = []
files = markdown_files()
links_checked = 0
for source in files:
    try:
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        problems.append(f"{source.relative_to(ROOT)}: could not read UTF-8 Markdown: {error}")
        continue
    for match in INLINE_LINK.finditer(text):
        target = destination(match.group(1))
        if not target or target.startswith("#"):
            continue
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme or parsed.netloc or target.startswith("//"):
            continue
        path_text = urllib.parse.unquote(parsed.path)
        if not path_text:
            continue
        links_checked += 1
        candidate = (source.parent / path_text).resolve()
        try:
            candidate.relative_to(ROOT)
        except ValueError:
            problems.append(
                f"{source.relative_to(ROOT)}:{text.count(chr(10), 0, match.start()) + 1}: "
                f"local link escapes repository: {target}"
            )
            continue
        if not candidate.exists():
            problems.append(
                f"{source.relative_to(ROOT)}:{text.count(chr(10), 0, match.start()) + 1}: "
                f"missing local link target: {target}"
            )

if problems:
    print("documentation link check failed:", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    raise SystemExit(1)

print(f"documentation links valid: {links_checked} local links across {len(files)} Markdown files")
