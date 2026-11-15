#!/usr/bin/env python3
"""Fail-closed DCO validation for every commit in a pull request."""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


API_VERSION = "2022-11-28"
COMMITS_PER_PAGE = 100
MAX_PULL_REQUEST_COMMITS = 250
REQUEST_TIMEOUT_SECONDS = 30
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PATCH_DIVIDER_PATTERN = re.compile(r"^---(?:[ \t\r]|$)")

# Audited horizontal separators: TAB, SPACE, and every Unicode Zs code point.
# Name and email tokens separately reject C0/C1 controls plus Unicode line and
# paragraph separators, so no broad whitespace class can admit a line break.
HORIZONTAL_SEPARATOR_PATTERN = (
    r"[\x09\x20\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]"
)
NAME_TOKEN_PATTERN = (
    r"[^<>\x00-\x20\x7f-\x9f\u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000]+"
)
EMAIL_PART_PATTERN = (
    r"[^<>@\x00-\x20\x7f-\x9f\u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000]+"
)
SIGNED_OFF_BY_PATTERN = re.compile(
    rf"^Signed-off-by:{HORIZONTAL_SEPARATOR_PATTERN}+"
    rf"(?P<name>{NAME_TOKEN_PATTERN}(?:{HORIZONTAL_SEPARATOR_PATTERN}+"
    rf"{NAME_TOKEN_PATTERN})*){HORIZONTAL_SEPARATOR_PATTERN}+"
    rf"<(?P<email>{EMAIL_PART_PATTERN}@{EMAIL_PART_PATTERN})>"
    rf"{HORIZONTAL_SEPARATOR_PATTERN}*$",
    re.IGNORECASE,
)
HORIZONTAL_ONLY_PATTERN = re.compile(
    rf"^{HORIZONTAL_SEPARATOR_PATTERN}*$"
)
SAFE_TRAILER_TEXT_PATTERN = (
    r"[^\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029]*"
)
TRAILER_TOKEN_PATTERN = r"-*[A-Za-z0-9][A-Za-z0-9-]*"
TRAILER_TOKEN_FULL_PATTERN = re.compile(rf"^{TRAILER_TOKEN_PATTERN}$")
TRAILER_LINE_PATTERN = re.compile(
    rf"^(?P<token>{TRAILER_TOKEN_PATTERN})[ \t]*:"
    rf"(?P<value>{SAFE_TRAILER_TEXT_PATTERN})$"
)
CONTINUATION_LINE_PATTERN = re.compile(
    rf"^{HORIZONTAL_SEPARATOR_PATTERN}+{SAFE_TRAILER_TEXT_PATTERN}$"
)
POTENTIAL_TRAILER_LINE_PATTERN = re.compile(
    rf"^{TRAILER_TOKEN_PATTERN}(?:{HORIZONTAL_SEPARATOR_PATTERN}|"
    r"[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029])*:"
)
HORIZONTAL_PREFIX_PATTERN = re.compile(
    rf"^{HORIZONTAL_SEPARATOR_PATTERN}"
)

# Git's mixed-group heuristic recognizes this exact generated prefix. Project
# DCO matching is intentionally broader and is applied only after admission.
GIT_RECOGNIZED_SIGNOFF_PREFIX = "Signed-off-by: "


class DcoContractError(RuntimeError):
    """Raised when the API response cannot prove complete DCO coverage."""


def _validate_sha(value: str, *, label: str) -> str:
    if not SHA_PATTERN.fullmatch(value):
        raise DcoContractError(f"{label} was not a full lowercase commit SHA")
    return value


def _request_json(
    url: str,
    token: str,
    *,
    resource: str,
    opener: Any = None,
) -> Any:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
        },
    )
    open_request = opener or urlopen

    try:
        with open_request(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", None)
            if status is None and hasattr(response, "getcode"):
                status = response.getcode()
            if status != 200:
                raise DcoContractError(
                    f"{resource} retrieval failed with HTTP status {status}"
                )
            body = response.read()
    except DcoContractError:
        raise
    except (OSError, TimeoutError, URLError) as exc:
        raise DcoContractError(f"{resource} retrieval failed: {exc}") from exc

    try:
        return json.loads(body.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DcoContractError(f"{resource} response was not valid JSON") from exc


def fetch_pr_metadata(
    api_url: str,
    repository: str,
    pr_number: int,
    token: str,
    expected_head_sha: str,
    expected_base_sha: str,
    *,
    opener: Any = None,
) -> tuple[int, str, str]:
    """Retrieve PR metadata bound to the exact expected base and head."""
    expected_head_sha = _validate_sha(
        expected_head_sha,
        label="expected pull-request head",
    )
    expected_base_sha = _validate_sha(
        expected_base_sha,
        label="expected pull-request base",
    )
    url = f"{api_url.rstrip('/')}/repos/{repository}/pulls/{pr_number}"
    payload = _request_json(
        url,
        token,
        resource="pull-request metadata",
        opener=opener,
    )

    if not isinstance(payload, dict):
        raise DcoContractError("pull-request metadata response was not an object")

    declared_count = payload.get("commits")
    if (
        isinstance(declared_count, bool)
        or not isinstance(declared_count, int)
        or declared_count <= 0
    ):
        raise DcoContractError(
            "pull-request metadata did not declare a positive integer commit count"
        )

    head = payload.get("head")
    head_sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(head_sha, str) or not SHA_PATTERN.fullmatch(head_sha):
        raise DcoContractError(
            "pull-request metadata did not declare a valid head SHA"
        )
    if head_sha != expected_head_sha:
        raise DcoContractError(
            "pull-request head mismatch: "
            f"metadata returned {head_sha}, expected {expected_head_sha}"
        )

    base = payload.get("base")
    base_sha = base.get("sha") if isinstance(base, dict) else None
    if not isinstance(base_sha, str) or not SHA_PATTERN.fullmatch(base_sha):
        raise DcoContractError(
            "pull-request metadata did not declare a valid base SHA"
        )
    if base_sha != expected_base_sha:
        raise DcoContractError(
            "pull-request base mismatch: "
            f"metadata returned {base_sha}, expected {expected_base_sha}"
        )
    if declared_count > MAX_PULL_REQUEST_COMMITS:
        raise DcoContractError(
            f"pull request declares {declared_count} commits; "
            f"the pull-request commits endpoint is capped at "
            f"{MAX_PULL_REQUEST_COMMITS}, so complete DCO coverage cannot be proven"
        )

    return declared_count, head_sha, base_sha


def fetch_pr_commits(
    api_url: str,
    repository: str,
    pr_number: int,
    token: str,
    declared_count: int,
    *,
    opener: Any = None,
) -> list[dict[str, Any]]:
    """Retrieve exactly the declared commits and prove the page boundary is empty."""
    if (
        isinstance(declared_count, bool)
        or not isinstance(declared_count, int)
        or declared_count <= 0
        or declared_count > MAX_PULL_REQUEST_COMMITS
    ):
        raise DcoContractError("declared commit count is outside the supported range")

    commits: list[dict[str, Any]] = []
    seen_shas: set[str] = set()
    page_count = (declared_count + COMMITS_PER_PAGE - 1) // COMMITS_PER_PAGE
    endpoint = f"{api_url.rstrip('/')}/repos/{repository}/pulls/{pr_number}/commits"

    for page in range(1, page_count + 1):
        payload = _request_json(
            f"{endpoint}?per_page={COMMITS_PER_PAGE}&page={page}",
            token,
            resource=f"pull-request commits page {page}",
            opener=opener,
        )
        if not isinstance(payload, list):
            raise DcoContractError(
                f"pull-request commits page {page} response was not a list"
            )

        expected_page_size = min(
            COMMITS_PER_PAGE,
            declared_count - len(commits),
        )
        if len(payload) != expected_page_size:
            raise DcoContractError(
                "pull-request commit count mismatch: "
                f"page {page} returned {len(payload)} commits, "
                f"expected {expected_page_size}"
            )
        for index, item in enumerate(payload, start=1):
            if not isinstance(item, dict):
                raise DcoContractError(
                    f"pull-request commits page {page} entry {index} was not an object"
                )
            sha = item.get("sha")
            if not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha):
                raise DcoContractError(
                    f"pull-request commits page {page} entry {index} had an invalid SHA"
                )
            if sha in seen_shas:
                raise DcoContractError(
                    f"pull-request commits response contained duplicate SHA {sha}"
                )
            seen_shas.add(sha)
            commits.append(item)

    boundary_page = page_count + 1
    boundary_payload = _request_json(
        f"{endpoint}?per_page={COMMITS_PER_PAGE}&page={boundary_page}",
        token,
        resource=f"pull-request commits boundary page {boundary_page}",
        opener=opener,
    )
    if not isinstance(boundary_payload, list):
        raise DcoContractError(
            f"pull-request commits boundary page {boundary_page} response was not a list"
        )
    if boundary_payload:
        raise DcoContractError(
            "pull-request commit count mismatch: "
            f"boundary page {boundary_page} unexpectedly returned "
            f"{len(boundary_payload)} commits"
        )
    if len(commits) != declared_count:
        raise DcoContractError(
            "pull-request commit count mismatch: "
            f"retrieved {len(commits)}, metadata declared {declared_count}"
        )

    return commits


def fetch_authoritative_pr_commits(
    api_url: str,
    repository: str,
    pr_number: int,
    token: str,
    expected_head_sha: str,
    expected_base_sha: str,
    *,
    opener: Any = None,
) -> tuple[int, list[dict[str, Any]]]:
    """Bind stable complete pagination to the exact event base and head."""
    expected_head_sha = _validate_sha(
        expected_head_sha,
        label="expected pull-request head",
    )
    expected_base_sha = _validate_sha(
        expected_base_sha,
        label="expected pull-request base",
    )
    declared_count, initial_head_sha, initial_base_sha = fetch_pr_metadata(
        api_url,
        repository,
        pr_number,
        token,
        expected_head_sha,
        expected_base_sha,
        opener=opener,
    )
    initial_commits = fetch_pr_commits(
        api_url,
        repository,
        pr_number,
        token,
        declared_count,
        opener=opener,
    )
    if initial_commits[-1]["sha"] != expected_head_sha:
        raise DcoContractError(
            "pull-request retrieved head mismatch: "
            f"final commit was {initial_commits[-1]['sha']}, "
            f"expected {expected_head_sha}"
        )

    middle_count, middle_head_sha, middle_base_sha = fetch_pr_metadata(
        api_url,
        repository,
        pr_number,
        token,
        expected_head_sha,
        expected_base_sha,
        opener=opener,
    )
    if (
        middle_count != declared_count
        or middle_head_sha != initial_head_sha
        or middle_base_sha != initial_base_sha
    ):
        raise DcoContractError(
            "pull-request metadata drifted during commit retrieval: "
            "initial base/head/count "
            f"{initial_base_sha}/{initial_head_sha}/{declared_count}, "
            "middle base/head/count "
            f"{middle_base_sha}/{middle_head_sha}/{middle_count}"
        )

    final_commits = fetch_pr_commits(
        api_url,
        repository,
        pr_number,
        token,
        declared_count,
        opener=opener,
    )
    if final_commits[-1]["sha"] != expected_head_sha:
        raise DcoContractError(
            "pull-request retrieved head mismatch: "
            f"final commit was {final_commits[-1]['sha']}, "
            f"expected {expected_head_sha}"
        )

    final_count, final_head_sha, final_base_sha = fetch_pr_metadata(
        api_url,
        repository,
        pr_number,
        token,
        expected_head_sha,
        expected_base_sha,
        opener=opener,
    )
    if (
        final_count != declared_count
        or final_head_sha != initial_head_sha
        or final_base_sha != initial_base_sha
    ):
        raise DcoContractError(
            "pull-request metadata drifted during commit retrieval: "
            "initial base/head/count "
            f"{initial_base_sha}/{initial_head_sha}/{declared_count}, "
            "final base/head/count "
            f"{final_base_sha}/{final_head_sha}/{final_count}"
        )

    initial_shas = [item["sha"] for item in initial_commits]
    final_shas = [item["sha"] for item in final_commits]
    if final_shas != initial_shas:
        raise DcoContractError(
            "pull-request commit pagination was not stable across "
            "complete traversals"
        )
    return declared_count, final_commits


def _is_horizontal_blank(line: str) -> bool:
    """Return whether a physical line is blank under the audited grammar."""
    return HORIZONTAL_ONLY_PATTERN.fullmatch(line) is not None


def _is_patch_divider(lines: list[str], index: int) -> bool:
    """Apply the audited physical-line boundary for a Git patch divider."""
    line = lines[index]
    if PATCH_DIVIDER_PATTERN.match(line) is None:
        return False
    if line != "---":
        return True

    # split("\n") leaves one terminal empty element for a final line ending;
    # that is not a physical line following the exact marker. Two line endings
    # do create a following empty physical line. A terminal exact marker must
    # remain message text so it cannot erase an invalid final postscript.
    remaining = lines[index + 1 :]
    return bool(remaining and remaining != [""])


def _final_nonblank_group(message: str) -> list[str]:
    """Return the complete final nonblank group after a body boundary."""
    lines = message.split("\n")
    divider_index = next(
        (
            index
            for index, line in enumerate(lines)
            if _is_patch_divider(lines, index)
        ),
        None,
    )
    if divider_index is not None:
        # Git starts the patch area at the first column-zero `---` followed by
        # space, tab, CR, or end-of-line; trailers there are not in the message.
        lines = lines[:divider_index]
    while lines and _is_horizontal_blank(lines[-1]):
        lines.pop()
    if not lines:
        return []

    boundary_index = next(
        (
            index
            for index in range(len(lines) - 1, -1, -1)
            if _is_horizontal_blank(lines[index])
        ),
        None,
    )
    if boundary_index is None:
        return []

    final_paragraph = lines[boundary_index + 1 :]
    if not final_paragraph:
        return []
    return final_paragraph


def _admitted_trailer_group(
    message: str,
) -> list[tuple[str, str | None, str]] | None:
    """Classify and admit the complete final group using Git's counters."""
    final_group = _final_nonblank_group(message)
    if not final_group:
        return None

    classified_lines: list[tuple[str, str | None, str]] = []
    current_token: str | None = None
    trailer_count = 0
    non_trailer_count = 0
    has_recognized_prefix = False

    for line in final_group:
        if CONTINUATION_LINE_PATTERN.fullmatch(line):
            if current_token is None:
                non_trailer_count += 1
                classified_lines.append(("orphan-continuation", None, line))
            else:
                classified_lines.append(("continuation", current_token, line))
            continue

        trailer_match = TRAILER_LINE_PATTERN.fullmatch(line)
        if trailer_match is not None:
            current_token = trailer_match.group("token").lower()
            trailer_count += 1
            has_recognized_prefix = (
                has_recognized_prefix
                or line.startswith(GIT_RECOGNIZED_SIGNOFF_PREFIX)
            )
            classified_lines.append(("trailer", current_token, line))
            continue

        if (
            POTENTIAL_TRAILER_LINE_PATTERN.match(line)
            or HORIZONTAL_PREFIX_PATTERN.match(line)
        ):
            current_token = None
            non_trailer_count += 1
            classified_lines.append(("malformed", None, line))
            continue

        current_token = None
        non_trailer_count += 1
        classified_lines.append(("body", None, line))

    if trailer_count == 0:
        return None
    if non_trailer_count and (
        not has_recognized_prefix
        or trailer_count * 4 < trailer_count + non_trailer_count
    ):
        return None

    return classified_lines


def valid_dco_identities(message: str) -> set[tuple[str, str]]:
    """Return exact identities from a valid physical-line DCO trailer block."""
    classified_lines = _admitted_trailer_group(message)
    if classified_lines is None:
        return set()

    identities: set[tuple[str, str]] = set()
    current_token = None
    for line_kind, token, line in classified_lines:
        if line_kind == "body":
            current_token = None
            continue
        if line_kind in {"orphan-continuation", "malformed"}:
            return set()
        if line_kind == "continuation":
            if current_token is None or current_token == "signed-off-by":
                return set()
            continue

        current_token = token
        if current_token == "signed-off-by":
            signoff_match = SIGNED_OFF_BY_PATTERN.fullmatch(line)
            if signoff_match is None:
                return set()
            identities.add(
                (signoff_match.group("name"), signoff_match.group("email"))
            )

    return identities


def has_valid_dco_trailer(message: str) -> bool:
    """Admit Git-compatible trailers, then apply stricter project DCO rules."""
    return bool(valid_dco_identities(message))


def unsigned_commit_shas(commits: list[dict[str, Any]]) -> list[str]:
    """Return every commit that lacks a syntactically valid DCO trailer."""
    unsigned: list[str] = []

    for index, item in enumerate(commits, start=1):
        if not isinstance(item, dict):
            raise DcoContractError(f"commit entry {index} was not an object")
        sha = item.get("sha")
        commit = item.get("commit")
        if not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha):
            raise DcoContractError(f"commit entry {index} had an invalid SHA")
        if not isinstance(commit, dict) or not isinstance(commit.get("message"), str):
            raise DcoContractError(f"commit {sha} had no valid commit message")
        author = commit.get("author")
        if not isinstance(author, dict):
            raise DcoContractError(f"commit {sha} had no valid author identity")
        author_name = author.get("name")
        author_email = author.get("email")
        if not isinstance(author_name, str) or not isinstance(author_email, str):
            raise DcoContractError(f"commit {sha} had no valid author identity")
        identities = valid_dco_identities(commit["message"])
        if (author_name, author_email) not in identities:
            unsigned.append(sha)

    return unsigned


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise DcoContractError(f"required environment variable {name} is empty")
    return value


def main() -> int:
    try:
        api_url = _required_environment("GITHUB_API_URL")
        repository = _required_environment("GITHUB_REPOSITORY")
        token = _required_environment("GITHUB_TOKEN")
        pr_number_text = _required_environment("PR_NUMBER")
        expected_head_sha = _required_environment("EXPECTED_HEAD_SHA")
        expected_base_sha = _required_environment("EXPECTED_BASE_SHA")
        try:
            pr_number = int(pr_number_text)
        except ValueError as exc:
            raise DcoContractError("PR_NUMBER must be an integer") from exc
        if pr_number <= 0:
            raise DcoContractError("PR_NUMBER must be positive")

        declared_count, commits = fetch_authoritative_pr_commits(
            api_url,
            repository,
            pr_number,
            token,
            expected_head_sha,
            expected_base_sha,
        )
        unsigned = unsigned_commit_shas(commits)
        if unsigned:
            print(
                "DCO check failed: commits without a Signed-off-by trailer:",
                file=sys.stderr,
            )
            for sha in unsigned:
                print(f"  {sha}", file=sys.stderr)
            return 1

        print(f"DCO check passed for all {declared_count} pull-request commits")
        return 0
    except DcoContractError as exc:
        print(f"DCO check failed closed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
