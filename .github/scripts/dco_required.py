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
    r"[^<>\x00-\x20\x7f-\x9f\u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000]+"
)
SIGNED_OFF_BY_PATTERN = re.compile(
    rf"^Signed-off-by:{HORIZONTAL_SEPARATOR_PATTERN}+{NAME_TOKEN_PATTERN}"
    rf"(?:{HORIZONTAL_SEPARATOR_PATTERN}+{NAME_TOKEN_PATTERN})*"
    rf"{HORIZONTAL_SEPARATOR_PATTERN}+<{EMAIL_PART_PATTERN}@"
    rf"{EMAIL_PART_PATTERN}>{HORIZONTAL_SEPARATOR_PATTERN}*$",
    re.IGNORECASE,
)
HORIZONTAL_ONLY_PATTERN = re.compile(
    rf"^{HORIZONTAL_SEPARATOR_PATTERN}*$"
)
SAFE_TRAILER_TEXT_PATTERN = (
    r"[^\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029]*"
)
TRAILER_LINE_PATTERN = re.compile(
    rf"^(?P<token>[A-Za-z0-9][A-Za-z0-9-]*):"
    rf"(?P<value>{SAFE_TRAILER_TEXT_PATTERN})$"
)
CONTINUATION_LINE_PATTERN = re.compile(
    rf"^{HORIZONTAL_SEPARATOR_PATTERN}+{SAFE_TRAILER_TEXT_PATTERN}$"
)


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
    *,
    opener: Any = None,
) -> tuple[int, str]:
    """Retrieve an authoritative commit count bound to the expected PR head."""
    expected_head_sha = _validate_sha(
        expected_head_sha,
        label="expected pull-request head",
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
    if declared_count > MAX_PULL_REQUEST_COMMITS:
        raise DcoContractError(
            f"pull request declares {declared_count} commits; "
            f"the pull-request commits endpoint is capped at "
            f"{MAX_PULL_REQUEST_COMMITS}, so complete DCO coverage cannot be proven"
        )

    return declared_count, head_sha


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
    *,
    opener: Any = None,
) -> tuple[int, list[dict[str, Any]]]:
    """Bind complete pagination to stable metadata and the exact event head."""
    expected_head_sha = _validate_sha(
        expected_head_sha,
        label="expected pull-request head",
    )
    declared_count, initial_head_sha = fetch_pr_metadata(
        api_url,
        repository,
        pr_number,
        token,
        expected_head_sha,
        opener=opener,
    )
    commits = fetch_pr_commits(
        api_url,
        repository,
        pr_number,
        token,
        declared_count,
        opener=opener,
    )
    final_count, final_head_sha = fetch_pr_metadata(
        api_url,
        repository,
        pr_number,
        token,
        expected_head_sha,
        opener=opener,
    )
    if final_count != declared_count or final_head_sha != initial_head_sha:
        raise DcoContractError(
            "pull-request metadata drifted during commit retrieval: "
            f"initial head/count {initial_head_sha}/{declared_count}, "
            f"final head/count {final_head_sha}/{final_count}"
        )
    if len(commits) != declared_count:
        raise DcoContractError(
            "pull-request commit count mismatch after retrieval: "
            f"retrieved {len(commits)}, metadata declared {declared_count}"
        )
    retrieved_head_sha = commits[-1]["sha"]
    if retrieved_head_sha != expected_head_sha:
        raise DcoContractError(
            "pull-request retrieved head mismatch: "
            f"final commit was {retrieved_head_sha}, expected {expected_head_sha}"
        )
    return declared_count, commits


def _is_horizontal_blank(line: str) -> bool:
    """Return whether a physical line is blank under the audited grammar."""
    return HORIZONTAL_ONLY_PATTERN.fullmatch(line) is not None


def _final_trailer_region(message: str) -> list[str]:
    """Return the final contiguous trailer-shaped suffix after a body boundary."""
    lines = message.split("\n")
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

    block_start = 0
    for index, line in enumerate(final_paragraph):
        is_trailer = TRAILER_LINE_PATTERN.fullmatch(line) is not None
        is_continuation = CONTINUATION_LINE_PATTERN.fullmatch(line) is not None
        if not is_trailer and not is_continuation:
            block_start = index + 1

    return final_paragraph[block_start:]


def has_valid_dco_trailer(message: str) -> bool:
    """Validate a one-line sign-off inside the final structured trailer block."""
    trailer_lines = _final_trailer_region(message)
    if not trailer_lines:
        return False

    current_token: str | None = None
    found_signed_off_by = False

    for line in trailer_lines:
        if CONTINUATION_LINE_PATTERN.fullmatch(line):
            if current_token is None or current_token == "signed-off-by":
                return False
            continue

        trailer_match = TRAILER_LINE_PATTERN.fullmatch(line)
        if trailer_match is None:
            return False

        current_token = trailer_match.group("token").lower()
        if current_token == "signed-off-by":
            if SIGNED_OFF_BY_PATTERN.fullmatch(line) is None:
                return False
            found_signed_off_by = True

    return found_signed_off_by


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
        if not has_valid_dco_trailer(commit["message"]):
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
