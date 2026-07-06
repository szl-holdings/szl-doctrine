#!/usr/bin/env python3
"""check_naming_canon.py — internal-consistency guard for NAMING_CANON.md.

NAMING_CANON.md is the canonical codename->repo glossary (single source of
truth). This stdlib-only guard enforces the INTERNAL integrity of that registry:

  1. every registry row has all 3 columns non-empty;
  2. no codename is defined by more than one row (no duplicate codename);
  3. each Repo cell is a well-formed repo slug / path (or the explicit "n/a"),
     accepting a multi-value cell like `khipu` / `khipu-consensus`;
  4. every codename the prose explicitly declares in a "codenames (...)" list
     (in NAMING_CANON.md or README.md) resolves to a row in the glossary;
  5. no live link targets the SUNSET domain a11oy.net (canonical: a-11-oy.com) —
     a11oy.net is redirect-only and is allowed only in a line that explicitly
     documents the sunset/redirect rule itself.

Honesty boundary: this validates INTERNAL doc consistency only. It does NOT
check whether a repo actually exists on GitHub — that would need a token and
network access the guard workflow does not have. No third-party deps: stdlib.

Usage:
  python3 scripts/check_naming_canon.py            # check the real docs
  python3 scripts/check_naming_canon.py --self-test # positive + negative fixtures
"""

from __future__ import annotations

import argparse
import os
import re
import sys

BACKTICK_RE = re.compile(r"`([^`]+)`")
# Sunset domain: a11oy.net is retired (redirect-only). Canonical is a-11-oy.com.
CANONICAL_DOMAIN = "a-11-oy.com"
SUNSET_DOMAIN = "a11oy.net"
# a11oy.net used as a live link target: markdown link "](...a11oy.net)" or a
# bare "http(s)://...a11oy.net" URL. A plain-text mention (no scheme, not a link
# target) does NOT match — that is where a sunset-definition sentence lives.
SUNSET_LINK_RE = re.compile(r"(?:\]\(\s*|https?://)[^)\s]*a11oy\.net", re.IGNORECASE)
# A line that explicitly documents the sunset/redirect rule itself.
SUNSET_STATEMENT_RE = re.compile(r"sunset|redirect", re.IGNORECASE)
# A codename list the prose explicitly declares, e.g. "... codenames (a, b, c)".
CODENAME_LIST_RE = re.compile(r"codenames?\s*\(([^)]*)\)", re.IGNORECASE)
# Well-formed repo slug or path segment(s): letters/digits/._- joined by "/".
REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
# Content that counts as "non-empty" once markdown decoration is stripped.
CONTENT_RE = re.compile(r"[*`_~\s]")

REGISTRY_HEADERS = {"codename", "term"}


def strip_md(text: str) -> str:
    """Drop bold/italic markers and surrounding whitespace."""
    return text.replace("**", "").replace("*", "").strip()


def has_content(cell: str) -> bool:
    """True if the cell has real content after markdown decoration is removed."""
    return CONTENT_RE.sub("", cell) != ""


def split_row(line: str) -> list[str]:
    """Split a markdown table row into its cell strings."""
    return [c.strip() for c in line.strip().strip("|").split("|")]


def is_separator(cells: list[str]) -> bool:
    """True if every non-empty cell is a markdown header separator (---, :--:)."""
    seen = False
    for c in cells:
        c = c.strip()
        if not c:
            continue
        seen = True
        if not re.fullmatch(r":?-{1,}:?", c):
            return False
    return seen


def extract_codenames(cell: str) -> list[str]:
    """Codenames declared in a first-column cell (multi split on '/')."""
    text = strip_md(cell)
    return [part.strip() for part in text.split("/") if part.strip()]


def iter_registry_rows(md_text: str):
    """Yield (line_no, cells) for each data row of every 3-column registry table.

    A registry table is one whose header's first cell is "Codename" or "Term".
    """
    lines = md_text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if line.strip().startswith("|") and line.strip().endswith("|"):
            # Start of a candidate table block.
            block = []
            start = i
            while i < n and lines[i].strip().startswith("|") and lines[i].strip().endswith("|"):
                block.append((i + 1, lines[i]))
                i += 1
            if len(block) >= 2:
                header_cells = split_row(block[0][1])
                sep_cells = split_row(block[1][1])
                first = strip_md(header_cells[0]).lower() if header_cells else ""
                if first in REGISTRY_HEADERS and len(header_cells) == 3 and is_separator(sep_cells):
                    for line_no, row_line in block[2:]:
                        yield line_no, split_row(row_line)
            continue
        i += 1


def check_domains(label: str, text: str, violations: list[str]) -> None:
    """Forbid live links to the sunset domain a11oy.net.

    a11oy.net is the SUNSET domain (redirect-only); the canonical domain is
    a-11-oy.com. A bare/live link to a11oy.net is a violation. It is allowed
    ONLY in a line that explicitly documents the sunset/redirect rule itself.
    """
    for i, line in enumerate(text.splitlines(), 1):
        if SUNSET_DOMAIN not in line.lower():
            continue
        if not SUNSET_LINK_RE.search(line):
            continue  # plain-text mention, not a live link target
        if SUNSET_STATEMENT_RE.search(line):
            continue  # explicit sunset/redirect canon statement
        violations.append(
            f"SUNSET_DOMAIN: {label}: line {i}: live link to sunset domain "
            f"'{SUNSET_DOMAIN}' -> use canonical https://{CANONICAL_DOMAIN} "
            f"(a11oy.net is allowed only in an explicit sunset/redirect statement)"
        )


def check_canon(canon_text: str, readme_text: str | None = None) -> list[str]:
    """Return a list of violation messages; empty list means the canon is clean."""
    violations: list[str] = []
    defined: dict[str, int] = {}  # codename(lower) -> first line it was defined on
    row_count = 0

    for line_no, cells in iter_registry_rows(canon_text):
        row_count += 1
        if len(cells) != 3:
            violations.append(
                f"MISSING_COLUMN: line {line_no}: registry row has {len(cells)} "
                f"column(s), expected 3 -> {cells!r}"
            )
            continue

        codename_cell, role_cell, repo_cell = cells

        # Rule 1: all three columns non-empty.
        for label, cell in (("codename", codename_cell), ("role", role_cell), ("repo", repo_cell)):
            if not has_content(cell):
                violations.append(
                    f"MISSING_COLUMN: line {line_no}: empty {label} column -> {cells!r}"
                )

        # Rule 2: no duplicate codename.
        for name in extract_codenames(codename_cell):
            key = name.lower()
            if key in defined:
                violations.append(
                    f"DUPLICATE: line {line_no}: codename '{name}' already defined "
                    f"on line {defined[key]}"
                )
            else:
                defined[key] = line_no

        # Rule 3: repo cell is a well-formed slug / path (or explicit n/a).
        if has_content(repo_cell):
            tokens = BACKTICK_RE.findall(repo_cell)
            if not tokens:
                if strip_md(repo_cell).lower() != "n/a":
                    violations.append(
                        f"BAD_REPO: line {line_no}: repo cell is not a backtick-quoted "
                        f"slug nor 'n/a' -> {repo_cell!r}"
                    )
            else:
                for tok in tokens:
                    if not REPO_SLUG_RE.fullmatch(tok):
                        violations.append(
                            f"BAD_REPO: line {line_no}: malformed repo slug "
                            f"'{tok}' -> {repo_cell!r}"
                        )

    if row_count == 0:
        violations.append("STRUCTURE: no registry table found in NAMING_CANON.md")

    # Rule 4: every prose-declared codename resolves to a glossary row.
    def resolves(candidate: str) -> bool:
        key = candidate.lower()
        if key in defined:
            return True
        # prefix alias, e.g. "hatun" resolves to the "hatun-mcp" row
        return any(name.startswith(key + "-") for name in defined)

    for label, text in (("NAMING_CANON.md", canon_text), ("README.md", readme_text or "")):
        for match in CODENAME_LIST_RE.finditer(text):
            for candidate in match.group(1).split(","):
                candidate = candidate.strip()
                if not candidate:
                    continue
                if not resolves(candidate):
                    violations.append(
                        f"UNDEFINED_CODENAME: {label}: prose declares codename "
                        f"'{candidate}' but it is absent from the glossary table"
                    )

    # Rule 5: no live link to the sunset domain a11oy.net (canonical: a-11-oy.com).
    check_domains("NAMING_CANON.md", canon_text, violations)
    if readme_text:
        check_domains("README.md", readme_text, violations)

    return violations


def run_real(root: str, canon_path: str | None, readme_path: str | None) -> int:
    canon_path = canon_path or os.path.join(root, "NAMING_CANON.md")
    readme_path = readme_path or os.path.join(root, "README.md")
    if not os.path.isfile(canon_path):
        print(f"ERROR: NAMING_CANON not found at {canon_path}", file=sys.stderr)
        return 2
    with open(canon_path, encoding="utf-8") as fh:
        canon_text = fh.read()
    readme_text = ""
    if os.path.isfile(readme_path):
        with open(readme_path, encoding="utf-8") as fh:
            readme_text = fh.read()

    violations = check_canon(canon_text, readme_text)
    if violations:
        print(f"NAMING_CANON guard: {len(violations)} violation(s) found:\n")
        for v in violations:
            print(f"  - {v}")
        print("\nFAIL: fix the glossary (bounded edit); never loosen the guard.")
        return 1
    print("NAMING_CANON guard: OK — registry is internally consistent.")
    return 0


POSITIVE_FIXTURE_HINT = "the real NAMING_CANON.md parses clean"


def self_test(root: str) -> int:
    ok = True

    # POSITIVE: the real NAMING_CANON.md (+ README.md) must be clean.
    canon_path = os.path.join(root, "NAMING_CANON.md")
    readme_path = os.path.join(root, "README.md")
    with open(canon_path, encoding="utf-8") as fh:
        real_canon = fh.read()
    real_readme = ""
    if os.path.isfile(readme_path):
        with open(readme_path, encoding="utf-8") as fh:
            real_readme = fh.read()
    real_violations = check_canon(real_canon, real_readme)
    if real_violations:
        ok = False
        print("SELF-TEST positive FAILED (expected the real canon to be clean):")
        for v in real_violations:
            print(f"  - {v}")
    else:
        print(f"SELF-TEST positive OK ({POSITIVE_FIXTURE_HINT}).")

    # NEGATIVE: a crafted bad canon must be caught on every rule.
    bad_canon = (
        "# bad canon\n"
        "\n"
        "Intro prose with Andean codenames (foo, bar).\n"
        "\n"
        "## Glossary\n"
        "| Codename | Plain-English role | Repo |\n"
        "|---|---|---|\n"
        "| **foo** | role foo | `foo` |\n"
        "| **foo** | duplicate codename foo | `foo-two` |\n"
        "| **baz** |  | `baz` |\n"
        "| **qux** | role qux | not a slug!! |\n"
        "\n"
        "Footer with a live [SZL Holdings](https://a11oy.net) link.\n"
    )
    bad_violations = check_canon(bad_canon)
    tags = {v.split(":", 1)[0] for v in bad_violations}
    expected = {"DUPLICATE", "MISSING_COLUMN", "BAD_REPO", "UNDEFINED_CODENAME", "SUNSET_DOMAIN"}
    missing = expected - tags
    if missing:
        ok = False
        print(f"SELF-TEST negative FAILED — did not catch: {sorted(missing)}")
        for v in bad_violations:
            print(f"  - {v}")
    else:
        print("SELF-TEST negative OK (missing column, duplicate codename, "
              "malformed repo, undeclared codename, sunset domain all caught).")

    # NEGATIVE #2: an explicit sunset/redirect statement mentioning a11oy.net
    # (even as a link) must be ALLOWED — it documents the canon rule itself.
    sunset_ok = (
        "# canon\n"
        "\n"
        "Domain canon: a11oy.net is the sunset domain and redirects to "
        "https://a-11-oy.com — do not link it as live.\n"
    )
    sunset_violations = [v for v in check_canon(sunset_ok) if v.startswith("SUNSET_DOMAIN")]
    if sunset_violations:
        ok = False
        print("SELF-TEST sunset-exception FAILED (sunset statement wrongly flagged):")
        for v in sunset_violations:
            print(f"  - {v}")
    else:
        print("SELF-TEST sunset-exception OK (explicit sunset/redirect statement allowed).")

    if ok:
        print("\nSELF-TEST: PASS")
        return 0
    print("\nSELF-TEST: FAIL")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run positive + negative fixtures")
    parser.add_argument("--canon", default=None, help="path to NAMING_CANON.md")
    parser.add_argument("--readme", default=None, help="path to README.md")
    args = parser.parse_args(argv)

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if args.self_test:
        return self_test(root)
    return run_real(root, args.canon, args.readme)


if __name__ == "__main__":
    raise SystemExit(main())
