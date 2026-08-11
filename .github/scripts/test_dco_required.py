#!/usr/bin/env python3
"""Focused regression tests for the fail-closed DCO checker."""

from __future__ import annotations

import json
import io
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

import dco_required as dco_check


API_URL = "https://api.github.test"
REPOSITORY = "szl-holdings/example"
PR_NUMBER = 399
TOKEN = "test-token"
EXPECTED_BASE_SHA = "f" * 40


def _commit(
    index: int,
    message: str | None = None,
    *,
    author_name: str = "Test User",
    author_email: str = "test@example.com",
) -> dict[str, object]:
    if message is None:
        message = f"fix: commit {index}\n\nSigned-off-by: Test User <test@example.com>"
    return {
        "sha": f"{index:040x}",
        "commit": {
            "message": message,
            "author": {"name": author_name, "email": author_email},
        },
    }


def _signed_commits(count: int, *, start: int = 1) -> list[dict[str, object]]:
    return [_commit(index) for index in range(start, start + count)]


def _commit_pages(commits: list[dict[str, object]]) -> list[list[dict[str, object]]]:
    return [
        commits[index : index + dco_check.COMMITS_PER_PAGE]
        for index in range(0, len(commits), dco_check.COMMITS_PER_PAGE)
    ]


def _head_sha(commits: list[dict[str, object]]) -> str:
    sha = commits[-1]["sha"]
    if not isinstance(sha, str):
        raise AssertionError("fixture SHA was not a string")
    return sha


def _metadata(
    count: int,
    head_sha: str,
    base_sha: str = EXPECTED_BASE_SHA,
) -> dict[str, object]:
    return {
        "commits": count,
        "head": {"sha": head_sha},
        "base": {"sha": base_sha},
    }


def _density_message(
    body_line_count: int,
    signoff_line: str = "Signed-off-by: Test User <test@example.com>",
) -> str:
    body = "\n".join(
        f"ordinary body line {index}" for index in range(1, body_line_count + 1)
    )
    return (
        "fix: density boundary\n\n"
        f"{body}\n"
        f"{signoff_line}"
    )


def _two_trailer_density_message(
    body_line_count: int,
    *,
    include_orphan: bool = False,
) -> str:
    body = "\n".join(
        f"ordinary body line {index}" for index in range(1, body_line_count + 1)
    )
    orphan = "\n orphan continuation" if include_orphan else ""
    return (
        "fix: continuation density\n\n"
        f"{body}{orphan}\n"
        "Reviewed-by: Reviewer <reviewer@example.com>\n"
        " folded one\n"
        "\tfolded two\n"
        " folded three\n"
        "\tfolded four\n"
        "Signed-off-by: Test User <test@example.com>"
    )


def _stable_responses(
    commits: list[dict[str, object]],
) -> tuple[str, list[object]]:
    count = len(commits)
    head_sha = _head_sha(commits)
    metadata = _metadata(count, head_sha)
    pages = [*_commit_pages(commits), []]
    return head_sha, [metadata, *pages, metadata, *pages, metadata]


def _real_commit(
    message: str,
    *,
    author_name: str = "Test User",
    author_email: str = "test@example.com",
) -> dict[str, object]:
    """Create a real commit and return its exact GitHub API-shaped identity."""
    git = shutil.which("git")
    if git is None:
        raise unittest.SkipTest("git is unavailable for real-commit fixtures")

    with tempfile.TemporaryDirectory(prefix="dco-real-commit-") as root:
        subprocess.run(
            [git, "-C", root, "init", "--quiet"],
            check=True,
            capture_output=True,
            timeout=5,
        )
        tree = subprocess.run(
            [git, "-C", root, "mktree"],
            input=b"",
            check=True,
            capture_output=True,
            timeout=5,
        ).stdout.strip().decode("ascii")
        commit_env = os.environ.copy()
        commit_env.update(
            {
                "GIT_AUTHOR_NAME": author_name,
                "GIT_AUTHOR_EMAIL": author_email,
                "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
                "GIT_COMMITTER_NAME": "DCO Test Committer",
                "GIT_COMMITTER_EMAIL": "committer@example.com",
                "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
            }
        )
        sha = subprocess.run(
            [git, "-C", root, "commit-tree", tree],
            input=message.encode("utf-8"),
            env=commit_env,
            check=True,
            capture_output=True,
            timeout=5,
        ).stdout.strip().decode("ascii")
        raw_commit = subprocess.run(
            [git, "-C", root, "cat-file", "commit", sha],
            check=True,
            capture_output=True,
            timeout=5,
        ).stdout
        raw_message = raw_commit.split(b"\n\n", 1)[1]
        api_message = raw_message.decode("utf-8").rstrip("\n")
        identity = subprocess.run(
            [git, "-C", root, "show", "-s", "--format=%an%x00%ae", sha],
            check=True,
            capture_output=True,
            timeout=5,
        ).stdout.decode("utf-8").rstrip("\n").split("\x00", 1)

    return {
        "sha": sha,
        "commit": {
            "message": api_message,
            "author": {"name": identity[0], "email": identity[1]},
        },
    }


def _run_production_entry(
    commit: dict[str, object],
) -> tuple[int, str, str, list[str]]:
    expected_head, responses = _stable_responses([commit])
    opener = _SequenceOpener(*responses)
    environment = {
        "GITHUB_API_URL": API_URL,
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_TOKEN": TOKEN,
        "PR_NUMBER": str(PR_NUMBER),
        "EXPECTED_HEAD_SHA": expected_head,
        "EXPECTED_BASE_SHA": EXPECTED_BASE_SHA,
    }
    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        patch.dict(os.environ, environment, clear=False),
        patch.object(dco_check, "urlopen", opener),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        result = dco_check.main()
    return result, stdout.getvalue(), stderr.getvalue(), opener.urls


UNSIGNED_EMPTY_COMMIT = _commit(1, "chore: intentionally empty commit")
UNSIGNED_MERGE_COMMIT = _commit(
    2,
    "Merge substantive policy update\n\nThis commit changes governed behavior.",
)
SIGNED_MULTI_COMMIT_PR = [_commit(3), _commit(4)]


class _Response:
    def __init__(self, payload: object, status: int = 200) -> None:
        self.status = status
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class _SequenceOpener:
    def __init__(self, *responses: object) -> None:
        self._responses = list(responses)
        self.urls: list[str] = []

    def __call__(self, request: object, timeout: int) -> _Response:
        del timeout
        self.urls.append(request.full_url)  # type: ignore[attr-defined]
        if not self._responses:
            raise AssertionError("unexpected API request")
        response = self._responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        if isinstance(response, _Response):
            return response
        return _Response(response)


class RealCommitProductionEntryTests(unittest.TestCase):
    def _assert_result(
        self,
        message: str,
        *,
        accepted: bool,
        author_name: str = "Test User",
        author_email: str = "test@example.com",
    ) -> None:
        commit = _real_commit(
            message,
            author_name=author_name,
            author_email=author_email,
        )
        result, stdout, stderr, urls = _run_production_entry(commit)
        self.assertEqual(len(urls), 7)
        if accepted:
            self.assertEqual(result, 0, stderr)
            self.assertIn("DCO check passed", stdout)
        else:
            self.assertEqual(result, 1, stdout)
            self.assertIn(str(commit["sha"]), stderr)

    def test_folded_signoff_is_rejected_by_production_entry(self) -> None:
        messages = (
            "fix: folded signoff\n\nSigned-off-by:\n Test User <test@example.com>",
            "fix: folded identity\n\nSigned-off-by: Test\n User <test@example.com>",
        )
        for message in messages:
            with self.subTest(message=message):
                self._assert_result(message, accepted=False)

    def test_terminal_exact_marker_cannot_erase_invalid_postscript(self) -> None:
        self._assert_result(
            "fix: terminal exact marker\n\n"
            "Signed-off-by: Test User <test@example.com>\n"
            "non-trailer postscript\n\n---",
            accepted=False,
        )

    def test_nonterminal_exact_patch_divider_policy(self) -> None:
        self._assert_result(
            "fix: signed patch\n\n"
            "Signed-off-by: Test User <test@example.com>\n"
            "---\n"
            "diff --git a/file b/file",
            accepted=True,
        )
        self._assert_result(
            "fix: unsigned patch\n\n"
            "Body without a sign-off.\n"
            "---\n"
            "Signed-off-by: Test User <test@example.com>",
            accepted=False,
        )

    def test_terminal_padded_suffix_and_cr_markers_remain_dividers(self) -> None:
        for marker in (
            "--- ",
            "---\t",
            "--- patch follows",
            "---\tpatch follows",
            "---\r",
            "---\rjunk",
        ):
            with self.subTest(marker=repr(marker)):
                self._assert_result(
                    "fix: terminal governed divider\n\n"
                    "Signed-off-by: Test User <test@example.com>\n"
                    "Git admits this group at fifty percent density.\n\n"
                    f"{marker}",
                    accepted=True,
                )

    def test_non_divider_controls_do_not_truncate_message(self) -> None:
        for marker in ("---x", "----", " ---"):
            with self.subTest(marker=marker):
                self._assert_result(
                    "fix: terminal non-divider\n\n"
                    "Signed-off-by: Test User <test@example.com>\n"
                    "non-trailer postscript\n\n"
                    f"{marker}",
                    accepted=False,
                )

    def test_author_name_and_email_must_match_exactly(self) -> None:
        message = "fix: identity\n\nSigned-off-by: Test User <test@example.com>"
        self._assert_result(message, accepted=True)
        self._assert_result(
            message,
            accepted=False,
            author_name="Different User",
        )
        self._assert_result(
            message,
            accepted=False,
            author_email="different@example.com",
        )

    def test_merge_prefixed_unsigned_real_commit_is_rejected(self) -> None:
        self._assert_result(
            "Merge substantive policy update\n\n"
            "This commit changes governed behavior without a sign-off.",
            accepted=False,
        )


class DcoCheckTests(unittest.TestCase):
    def test_metadata_api_retrieval_failure_fails_closed(self) -> None:
        expected_head = _head_sha(_signed_commits(1))
        opener = _SequenceOpener(URLError("metadata unavailable"))

        with self.assertRaisesRegex(dco_check.DcoContractError, "retrieval failed"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

    def test_commits_api_retrieval_failure_fails_closed(self) -> None:
        expected_head = _head_sha(_signed_commits(1))
        opener = _SequenceOpener(
            _metadata(1, expected_head), URLError("commits unavailable")
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "retrieval failed"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

    def test_unexpectedly_empty_commit_list_fails_closed(self) -> None:
        expected_head = _head_sha(_signed_commits(1))
        opener = _SequenceOpener(_metadata(1, expected_head), [])

        with self.assertRaisesRegex(dco_check.DcoContractError, "count mismatch"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

    def test_unsigned_empty_commit_is_rejected(self) -> None:
        self.assertEqual(
            dco_check.unsigned_commit_shas([UNSIGNED_EMPTY_COMMIT]),
            [UNSIGNED_EMPTY_COMMIT["sha"]],
        )

    def test_unsigned_substantive_merge_prefixed_commit_is_rejected(self) -> None:
        self.assertEqual(
            dco_check.unsigned_commit_shas([UNSIGNED_MERGE_COMMIT]),
            [UNSIGNED_MERGE_COMMIT["sha"]],
        )

    def test_fully_signed_multi_commit_pr_passes(self) -> None:
        self.assertEqual(dco_check.unsigned_commit_shas(SIGNED_MULTI_COMMIT_PR), [])

    def test_multiline_sign_off_values_are_rejected(self) -> None:
        malformed = [
            _commit(5, "fix: split name\n\nSigned-off-by: Test User\n<test@example.com>"),
            _commit(6, "fix: split trailer\n\nSigned-off-by:\nTest User <test@example.com>"),
        ]

        self.assertEqual(
            dco_check.unsigned_commit_shas(malformed),
            [commit["sha"] for commit in malformed],
        )

    def test_whitespace_only_signer_names_are_rejected(self) -> None:
        malformed = [
            _commit(7, "fix: blank name\n\nSigned-off-by:   <test@example.com>"),
            _commit(8, "fix: tab name\n\nSigned-off-by:\t\t<test@example.com>"),
        ]

        self.assertEqual(
            dco_check.unsigned_commit_shas(malformed),
            [commit["sha"] for commit in malformed],
        )

    def test_vertical_whitespace_in_signer_names_is_rejected(self) -> None:
        separators = ("\r", "\n", "\v", "\f", "\x85", "\u2028", "\u2029")
        malformed = [
            _commit(
                index,
                f"fix: vertical name\n\nSigned-off-by: A{separator}B <test@example.com>",
            )
            for index, separator in enumerate(separators, start=9)
        ]

        self.assertEqual(
            dco_check.unsigned_commit_shas(malformed),
            [commit["sha"] for commit in malformed],
        )

    def test_other_control_characters_in_signer_names_are_rejected(self) -> None:
        controls = ("\x00", "\x01", "\x1c", "\x1f", "\x7f", "\x80", "\x9f")
        malformed = [
            _commit(
                index,
                f"fix: control name\n\nSigned-off-by: A{control}B <test@example.com>",
            )
            for index, control in enumerate(controls, start=20)
        ]

        self.assertEqual(
            dco_check.unsigned_commit_shas(malformed),
            [commit["sha"] for commit in malformed],
        )

    def test_one_character_signer_name_is_accepted(self) -> None:
        commit = _commit(
            14,
            "fix: short signer\n\nSigned-off-by: X <x@example.com>",
            author_name="X",
            author_email="x@example.com",
        )

        self.assertEqual(dco_check.unsigned_commit_shas([commit]), [])

    def test_email_components_reject_additional_at_signs(self) -> None:
        malformed = [
            _commit(
                index,
                "fix: malformed email\n\n"
                f"Signed-off-by: Test User <{email}>",
            )
            for index, email in enumerate(
                ("a@@b", "a@b@c", "a@b@"),
                start=93,
            )
        ]

        self.assertEqual(
            dco_check.unsigned_commit_shas(malformed),
            [commit["sha"] for commit in malformed],
        )

    def test_audited_horizontal_separators_are_accepted(self) -> None:
        separators = (
            "\t",
            "\x20",
            "\u00a0",
            "\u1680",
            "\u2000",
            "\u2001",
            "\u2002",
            "\u2003",
            "\u2004",
            "\u2005",
            "\u2006",
            "\u2007",
            "\u2008",
            "\u2009",
            "\u200a",
            "\u202f",
            "\u205f",
            "\u3000",
        )
        signed = [
            _commit(
                index,
                "fix: horizontal signer\n\n"
                f"Signed-off-by:{separator}A{separator}B{separator}"
                f"<test@example.com>{separator}",
                author_name=f"A{separator}B",
            )
            for index, separator in enumerate(separators, start=30)
        ]

        self.assertEqual(dco_check.unsigned_commit_shas(signed), [])

    def test_preceding_folded_non_dco_trailers_are_accepted(self) -> None:
        signed = [
            _commit(
                50,
                "fix: reviewed change\n\n"
                "Reviewed-by: Reviewer <reviewer@example.com>\n"
                " review context\n"
                "Signed-off-by: Test User <test@example.com>",
            ),
            _commit(
                51,
                "fix: co-authored change\n\n"
                "Co-authored-by: Contributor <contributor@example.com>\n"
                " first continuation\n"
                "\tsecond continuation\n"
                "Signed-off-by: Test User <test@example.com>",
            ),
        ]

        self.assertEqual(dco_check.unsigned_commit_shas(signed), [])

    def test_body_signoff_outside_final_trailer_block_is_rejected(self) -> None:
        malformed = _commit(
            52,
            "fix: body signoff\n\n"
            "Signed-off-by: Test User <test@example.com>\n\n"
            "A final body paragraph is not a trailer block.",
        )

        self.assertEqual(
            dco_check.unsigned_commit_shas([malformed]),
            [malformed["sha"]],
        )

    def test_continuation_after_signed_off_by_is_rejected(self) -> None:
        malformed = _commit(
            53,
            "fix: folded identity\n\n"
            "Signed-off-by: Test User <test@example.com>\n"
            " attacker-controlled identity extension",
        )

        self.assertEqual(
            dco_check.unsigned_commit_shas([malformed]),
            [malformed["sha"]],
        )

    def test_folded_signoff_name_or_email_is_rejected(self) -> None:
        malformed = [
            _commit(
                54,
                "fix: folded name\n\n"
                "Signed-off-by: Test\n"
                " User <test@example.com>",
            ),
            _commit(
                55,
                "fix: folded email\n\n"
                "Signed-off-by: Test User <test@\n"
                " example.com>",
            ),
        ]

        self.assertEqual(
            dco_check.unsigned_commit_shas(malformed),
            [commit["sha"] for commit in malformed],
        )

    def test_orphan_continuation_in_trailer_region_is_rejected(self) -> None:
        malformed = _commit(
            56,
            "fix: orphan continuation\n\n"
            " continuation without a preceding trailer\n"
            "Signed-off-by: Test User <test@example.com>",
        )

        self.assertEqual(
            dco_check.unsigned_commit_shas([malformed]),
            [malformed["sha"]],
        )

    def test_trailer_block_body_boundaries_match_git_semantics(self) -> None:
        accepted = [
            _commit(
                57,
                "fix: final trailer suffix\n\n"
                "Body text may precede the final structured suffix.\n"
                "Signed-off-by: Test User <test@example.com>",
            ),
            _commit(
                59,
                "fix: admitted body after trailer\n\n"
                "Signed-off-by: Test User <test@example.com>\n"
                "Git admits this complete group at fifty percent density.",
            ),
        ]
        rejected = [
            _commit(
                58,
                "fix: missing boundary\n"
                "Signed-off-by: Test User <test@example.com>",
            ),
        ]

        self.assertEqual(dco_check.unsigned_commit_shas(accepted), [])
        self.assertEqual(
            dco_check.unsigned_commit_shas(rejected),
            [commit["sha"] for commit in rejected],
        )

    def test_signoff_after_exact_patch_divider_is_rejected(self) -> None:
        unsigned = _commit(
            97,
            "fix: unsigned patch message\n\n"
            "Body without a sign-off.\n"
            "---\n"
            "Signed-off-by: Test User <test@example.com>",
        )

        self.assertEqual(
            dco_check.unsigned_commit_shas([unsigned]),
            [unsigned["sha"]],
        )

    def test_padded_patch_dividers_match_git_trailer_parsing(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.skipTest("git is unavailable for differential fixtures")

        fixtures: list[tuple[str, str, bool]] = []
        for divider in (
            "---",
            "--- ",
            "---\t",
            "--- \t",
            "--- patch follows",
            "---\tpatch follows",
            "---\r",
            "---\rjunk",
        ):
            fixtures.extend(
                (
                    (
                        f"valid sign-off before {divider!r}",
                        "fix: signed patch message\n\n"
                        "Signed-off-by: Test User <test@example.com>\n"
                        f"{divider}\n"
                        "diff --git a/file b/file\n"
                        "+patch content",
                        True,
                    ),
                    (
                        f"sign-off only after {divider!r}",
                        "fix: unsigned patch message\n\n"
                        "Body without a sign-off.\n"
                        f"{divider}\n"
                        "Signed-off-by: Test User <test@example.com>",
                        False,
                    ),
                )
            )
        fixtures.extend(
            (
                (
                    "first divider wins",
                    "fix: first divider wins\n\n"
                    "Body without a sign-off.\n"
                    "--- \t\n"
                    "Signed-off-by: Test User <test@example.com>\n"
                    "---\n"
                    "diff --git a/file b/file",
                    False,
                ),
            )
        )
        for non_divider in ("---x", "----", " ---"):
            fixtures.append(
                (
                    f"{non_divider!r} is not a divider",
                    "fix: non-divider suffix\n\n"
                    "Reviewed-by: Reviewer <reviewer@example.com>\n"
                    f"{non_divider}\n"
                    "Signed-off-by: Test User <test@example.com>",
                    True,
                )
            )
        for label, message, expected in fixtures:
            with self.subTest(label=label):
                parsed = subprocess.run(
                    [git, "interpret-trailers", "--parse"],
                    input=message.encode("utf-8"),
                    capture_output=True,
                    check=True,
                    timeout=5,
                ).stdout.decode("utf-8")
                git_accepts = any(
                    line.lower().startswith("signed-off-by:")
                    for line in parsed.splitlines()
                )
                policy_accepts = not dco_check.unsigned_commit_shas(
                    [_commit(98, message)]
                )

                self.assertEqual(git_accepts, expected, parsed)
                self.assertEqual(policy_accepts, git_accepts)

    def test_git_density_admission_boundaries_are_deterministic(self) -> None:
        density_20 = _commit(70, _density_message(4))
        density_25 = _commit(71, _density_message(3))
        density_50 = _commit(72, _density_message(1))

        self.assertEqual(
            dco_check.unsigned_commit_shas([density_20]),
            [density_20["sha"]],
        )
        self.assertEqual(
            dco_check.unsigned_commit_shas([density_25, density_50]),
            [],
        )

    def test_git_density_admission_matches_interpret_trailers(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.skipTest("git is unavailable for differential fixtures")

        fixtures = (
            (4, False),
            (3, True),
            (1, True),
        )
        for body_line_count, expected in fixtures:
            with self.subTest(body_line_count=body_line_count):
                message = _density_message(body_line_count)
                parsed = subprocess.run(
                    [git, "interpret-trailers", "--parse"],
                    input=message,
                    text=True,
                    capture_output=True,
                    check=True,
                    timeout=5,
                ).stdout
                git_accepts = any(
                    line.lower().startswith("signed-off-by:")
                    for line in parsed.splitlines()
                )
                policy_accepts = not dco_check.unsigned_commit_shas(
                    [_commit(73, message)]
                )

                self.assertEqual(git_accepts, expected)
                self.assertEqual(policy_accepts, git_accepts)

    def test_mixed_group_recognition_requires_exact_git_prefix(self) -> None:
        variants = {
            "canonical": (
                "Signed-off-by: Test User <test@example.com>",
                (False, True, True),
                (False, True, True),
            ),
            "tab": (
                "Signed-off-by:\tTest User <test@example.com>",
                (False, False, False),
                (False, False, False),
            ),
            "nbsp": (
                "Signed-off-by:\u00a0Test User <test@example.com>",
                (False, False, False),
                (False, False, False),
            ),
            "lowercase": (
                "signed-off-by: Test User <test@example.com>",
                (False, False, False),
                (False, False, False),
            ),
            "uppercase": (
                "SIGNED-OFF-BY: Test User <test@example.com>",
                (False, False, False),
                (False, False, False),
            ),
            "malformed": (
                "Signed-off-by: malformed",
                (False, True, True),
                (False, False, False),
            ),
        }
        body_counts = (4, 3, 1)

        for name, (line, admission_results, policy_results) in variants.items():
            for body_count, admitted, accepted in zip(
                body_counts,
                admission_results,
                policy_results,
                strict=True,
            ):
                with self.subTest(name=name, body_count=body_count):
                    message = _density_message(body_count, line)
                    self.assertEqual(
                        dco_check._admitted_trailer_group(message) is not None,
                        admitted,
                    )
                    policy_accepts = not dco_check.unsigned_commit_shas(
                        [_commit(80, message)]
                    )
                    self.assertEqual(policy_accepts, accepted)

    def test_mixed_group_prefix_admission_matches_interpret_trailers(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.skipTest("git is unavailable for differential fixtures")

        variants = (
            "Signed-off-by: Test User <test@example.com>",
            "Signed-off-by:\tTest User <test@example.com>",
            "Signed-off-by:\u00a0Test User <test@example.com>",
            "signed-off-by: Test User <test@example.com>",
            "SIGNED-OFF-BY: Test User <test@example.com>",
            "Signed-off-by: malformed",
        )
        for line in variants:
            for body_count in (4, 3, 1):
                with self.subTest(line=line, body_count=body_count):
                    message = _density_message(body_count, line)
                    parsed = subprocess.run(
                        [git, "interpret-trailers", "--parse"],
                        input=message,
                        text=True,
                        capture_output=True,
                        check=True,
                        timeout=5,
                    ).stdout
                    git_admits = bool(parsed.strip())
                    policy_admits = (
                        dco_check._admitted_trailer_group(message) is not None
                    )

                    self.assertEqual(policy_admits, git_admits)

    def test_project_signoff_variants_pass_in_all_trailer_groups(self) -> None:
        signoff_lines = (
            "Signed-off-by:\tTest User <test@example.com>",
            "Signed-off-by:\u00a0Test User <test@example.com>",
            "signed-off-by: Test User <test@example.com>",
            "SIGNED-OFF-BY: Test User <test@example.com>",
        )
        signed = [
            _commit(
                index,
                "fix: fully structured trailer group\n\n"
                "Reviewed-by: Reviewer <reviewer@example.com>\n"
                f"{line}",
            )
            for index, line in enumerate(signoff_lines, start=81)
        ]

        self.assertEqual(dco_check.unsigned_commit_shas(signed), [])

    def test_density_counters_ignore_attached_continuations(self) -> None:
        admitted_at_25 = _two_trailer_density_message(6)
        rejected_below_25 = _two_trailer_density_message(7)
        rejected_with_orphan = _two_trailer_density_message(
            6,
            include_orphan=True,
        )

        self.assertIsNotNone(
            dco_check._admitted_trailer_group(admitted_at_25)
        )
        self.assertIsNone(
            dco_check._admitted_trailer_group(rejected_below_25)
        )
        self.assertIsNone(
            dco_check._admitted_trailer_group(rejected_with_orphan)
        )
        self.assertEqual(
            dco_check.unsigned_commit_shas(
                [
                    _commit(90, admitted_at_25),
                    _commit(91, rejected_below_25),
                    _commit(92, rejected_with_orphan),
                ]
            ),
            [f"{91:040x}", f"{92:040x}"],
        )

    def test_density_counters_match_interpret_trailers(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.skipTest("git is unavailable for differential fixtures")

        fixtures = (
            _two_trailer_density_message(6),
            _two_trailer_density_message(7),
            _two_trailer_density_message(6, include_orphan=True),
        )
        for message in fixtures:
            with self.subTest(message=message):
                parsed = subprocess.run(
                    [git, "interpret-trailers", "--parse"],
                    input=message,
                    text=True,
                    capture_output=True,
                    check=True,
                    timeout=5,
                ).stdout
                git_admits = bool(parsed.strip())
                policy_admits = (
                    dco_check._admitted_trailer_group(message) is not None
                )

                self.assertEqual(policy_admits, git_admits)

    def test_complete_group_does_not_discard_malformed_material(self) -> None:
        malformed = [
            _commit(
                74,
                "fix: malformed generic trailer\n\n"
                "Reviewed-by: Reviewer\x1cName <reviewer@example.com>\n"
                "Signed-off-by: Test User <test@example.com>",
            ),
            _commit(
                75,
                "fix: malformed key spacing\n\n"
                "Reviewed-by\x1c: Reviewer <reviewer@example.com>\n"
                "Signed-off-by: Test User <test@example.com>",
            ),
        ]

        self.assertEqual(
            dco_check.unsigned_commit_shas(malformed),
            [commit["sha"] for commit in malformed],
        )

    def test_generic_key_to_colon_spacing_and_folds_are_accepted(self) -> None:
        signed = [
            _commit(
                76,
                "fix: spaced trailer before DCO\n\n"
                "Reviewed-by \t : Reviewer <reviewer@example.com>\n"
                " first folded value\n"
                "\tsecond folded value\n"
                "Signed-off-by: Test User <test@example.com>",
            ),
            _commit(
                77,
                "fix: spaced trailer after DCO\n\n"
                "Signed-off-by: Test User <test@example.com>\n"
                "Reviewed-by\t: Reviewer <reviewer@example.com>\n"
                " folded value belonging to Reviewed-by",
            ),
        ]

        self.assertEqual(dco_check.unsigned_commit_shas(signed), [])

    def test_leading_hyphen_generic_trailer_matches_git_with_fold(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.skipTest("git is unavailable for differential fixtures")

        message = (
            "fix: leading-hyphen generic trailer\n\n"
            "-Foo: x\n"
            " folded continuation\n"
            "Signed-off-by: Test User <test@example.com>"
        )
        parsed = subprocess.run(
            [git, "interpret-trailers", "--parse"],
            input=message,
            text=True,
            capture_output=True,
            check=True,
            timeout=5,
        ).stdout

        self.assertTrue(
            any(line.startswith("-Foo:") for line in parsed.splitlines()),
            parsed,
        )
        self.assertEqual(
            dco_check.unsigned_commit_shas([_commit(96, message)]),
            [],
        )

    def test_generic_trailer_token_keeps_strict_character_boundary(self) -> None:
        self.assertIsNotNone(
            dco_check.TRAILER_TOKEN_FULL_PATTERN.fullmatch("-Foo")
        )
        for token in ("-Fo:o", "-Fo o", "-Fo\x1co"):
            with self.subTest(token=token):
                self.assertIsNone(
                    dco_check.TRAILER_TOKEN_FULL_PATTERN.fullmatch(token)
                )

    def test_trailing_blank_line_variants_are_accepted(self) -> None:
        endings = ("", "\n", "\n\n", "\n \t\n")
        signed = [
            _commit(
                index,
                "fix: trailing blanks\n\n"
                "Signed-off-by: Test User <test@example.com>"
                f"{ending}",
            )
            for index, ending in enumerate(endings, start=60)
        ]

        self.assertEqual(dco_check.unsigned_commit_shas(signed), [])

    def test_valid_stable_pagination_passes(self) -> None:
        commits = _signed_commits(3)
        expected_head, responses = _stable_responses(commits)
        opener = _SequenceOpener(*responses)

        declared, retrieved = dco_check.fetch_authoritative_pr_commits(
            API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
        )

        self.assertEqual(declared, 3)
        self.assertEqual(retrieved, commits)
        self.assertEqual(len(opener.urls), 7)

    def test_249_commits_are_retrieved_completely(self) -> None:
        commits = _signed_commits(249)
        expected_head, responses = _stable_responses(commits)
        opener = _SequenceOpener(*responses)

        declared, retrieved = dco_check.fetch_authoritative_pr_commits(
            API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
        )

        self.assertEqual(declared, 249)
        self.assertEqual(len(retrieved), 249)
        self.assertTrue(opener.urls[-2].endswith("per_page=100&page=4"))

    def test_exactly_250_commits_are_retrieved_completely(self) -> None:
        commits = _signed_commits(250)
        expected_head, responses = _stable_responses(commits)
        opener = _SequenceOpener(*responses)

        declared, retrieved = dco_check.fetch_authoritative_pr_commits(
            API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
        )

        self.assertEqual(declared, 250)
        self.assertEqual(len(retrieved), 250)
        self.assertTrue(opener.urls[-2].endswith("per_page=100&page=4"))

    def test_251_commits_are_rejected_before_commit_pagination(self) -> None:
        expected_head = _head_sha(_signed_commits(251))
        opener = _SequenceOpener(_metadata(251, expected_head))

        with self.assertRaisesRegex(dco_check.DcoContractError, "capped at 250"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

        self.assertEqual(len(opener.urls), 1)

    def test_declared_and_retrieved_short_count_mismatch_is_rejected(self) -> None:
        commits = _signed_commits(248)
        expected_head = _head_sha(_signed_commits(249))
        opener = _SequenceOpener(
            _metadata(249, expected_head), *_commit_pages(commits)
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "count mismatch"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

    def test_nonempty_boundary_page_count_mismatch_is_rejected(self) -> None:
        commits = _signed_commits(249)
        expected_head = _head_sha(commits)
        opener = _SequenceOpener(
            _metadata(249, expected_head), *_commit_pages(commits), [_commit(250)]
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "count mismatch"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

    def test_duplicate_entries_within_page_are_rejected(self) -> None:
        first = _commit(1)
        expected_head = _head_sha(_signed_commits(2))
        opener = _SequenceOpener(_metadata(2, expected_head), [first, first])

        with self.assertRaisesRegex(dco_check.DcoContractError, "duplicate SHA"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

    def test_duplicate_sha_across_pages_is_rejected(self) -> None:
        first_page = _signed_commits(100)
        expected_head = _head_sha(_signed_commits(101))
        opener = _SequenceOpener(
            _metadata(101, expected_head), first_page, [first_page[0]]
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "duplicate SHA"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

    def test_initial_metadata_head_mismatch_is_rejected(self) -> None:
        expected_head = _head_sha(_signed_commits(2))
        replacement_head = _head_sha(_signed_commits(3))
        opener = _SequenceOpener(_metadata(2, replacement_head))

        with self.assertRaisesRegex(dco_check.DcoContractError, "head mismatch"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

    def test_same_count_head_replacement_during_pagination_is_rejected(self) -> None:
        commits = _signed_commits(2)
        expected_head = _head_sha(commits)
        replacement_head = _head_sha(_signed_commits(3))
        opener = _SequenceOpener(
            _metadata(2, expected_head),
            commits,
            [],
            _metadata(2, replacement_head),
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "head mismatch"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

    def test_metadata_count_drift_after_pagination_is_rejected(self) -> None:
        commits = _signed_commits(2)
        expected_head = _head_sha(commits)
        opener = _SequenceOpener(
            _metadata(2, expected_head), commits, [], _metadata(3, expected_head)
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "metadata drifted"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

    def test_final_retrieved_sha_must_equal_expected_head(self) -> None:
        expected_head = _head_sha(_signed_commits(2))
        replacement_commits = [_commit(1), _commit(3)]
        stable_metadata = _metadata(2, expected_head)
        opener = _SequenceOpener(
            stable_metadata, replacement_commits, [], stable_metadata
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "retrieved head mismatch"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, EXPECTED_BASE_SHA, opener=opener
            )

    def test_initial_metadata_base_mismatch_is_rejected(self) -> None:
        commits = _signed_commits(2)
        expected_head = _head_sha(commits)
        replacement_base = "e" * 40
        opener = _SequenceOpener(
            _metadata(2, expected_head, replacement_base)
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "base mismatch"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head,
                EXPECTED_BASE_SHA, opener=opener
            )

    def test_base_retarget_during_pagination_is_rejected(self) -> None:
        commits = _signed_commits(2)
        expected_head = _head_sha(commits)
        replacement_base = "e" * 40
        opener = _SequenceOpener(
            _metadata(2, expected_head),
            commits,
            [],
            _metadata(2, expected_head, replacement_base),
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "base mismatch"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head,
                EXPECTED_BASE_SHA, opener=opener
            )

    def test_hybrid_page_omission_is_rejected(self) -> None:
        commits = _signed_commits(101)
        expected_head = _head_sha(commits)
        hybrid = [*commits[:99], _commit(202), commits[-1]]
        metadata = _metadata(len(commits), expected_head)
        opener = _SequenceOpener(
            metadata,
            *_commit_pages(hybrid),
            [],
            metadata,
            *_commit_pages(commits),
            [],
            metadata,
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "not stable"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head,
                EXPECTED_BASE_SHA, opener=opener
            )

    def test_workflow_binds_exact_pull_request_and_runs_authoritative_checker(self) -> None:
        workflow_path = Path(__file__).parents[1] / "workflows" / "dco-required.yml"
        workflow = workflow_path.read_text(encoding="utf-8")

        self.assertIn("types: [opened, synchronize, reopened]", workflow)
        self.assertNotIn("ready_for_review", workflow)
        self.assertIn("if: github.event_name == 'pull_request'", workflow)
        self.assertIn(
            "EVENT_REPOSITORY: ${{ github.event.repository.full_name }}", workflow
        )
        self.assertIn(
            "EVENT_REPOSITORY_ID: ${{ github.event.repository.id }}", workflow
        )
        self.assertIn("WORKFLOW_REPOSITORY: ${{ github.repository }}", workflow)
        self.assertIn(
            "WORKFLOW_REPOSITORY_ID: ${{ github.repository_id }}", workflow
        )
        self.assertIn(
            'test "$EVENT_REPOSITORY" = "$WORKFLOW_REPOSITORY"', workflow
        )
        self.assertIn(
            'test "$EVENT_REPOSITORY_ID" = "$WORKFLOW_REPOSITORY_ID"', workflow
        )
        self.assertIn(
            "EXPECTED_BASE_REF: ${{ github.event.pull_request.base.ref }}", workflow
        )
        self.assertIn('test "$EXPECTED_BASE_REF" = "main"', workflow)
        self.assertIn(
            "EXPECTED_HEAD_SHA: ${{ github.event.pull_request.head.sha }}", workflow
        )
        self.assertIn(
            "EXPECTED_BASE_SHA: ${{ github.event.pull_request.base.sha }}", workflow
        )
        self.assertRegex(
            workflow,
            r"(?m)^\s*python3\s+policy/\.github/scripts/dco_required\.py\s*$",
        )
        compile_command = "python3 -m py_compile policy/.github/scripts/dco_required.py"
        test_command = "python3 policy/.github/scripts/test_dco_required.py"
        enforce_command = "python3 policy/.github/scripts/dco_required.py"
        self.assertIn(compile_command, workflow)
        self.assertIn(test_command, workflow)
        self.assertLess(workflow.index(compile_command), workflow.index(test_command))
        self.assertLess(workflow.index(test_command), workflow.index(enforce_command))
        self.assertIn(".github/workflows/dco-required.yml", workflow)

    def test_workflow_publishes_two_unique_contexts_and_propagates_failure(self) -> None:
        workflow_path = Path(__file__).parents[1] / "workflows" / "dco-required.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        jobs = workflow.split("\njobs:\n", 1)[1]
        job_ids = re.findall(r"(?m)^  ([a-z][a-z0-9-]*):\s*$", jobs)
        job_names = re.findall(r"(?m)^    name: ([^\n]+)$", jobs)

        self.assertEqual(job_ids, ["enforce-policy", "status-compatibility"])
        self.assertEqual(
            job_names,
            ["Required DCO enforcement", "DCO sign-off check"],
        )
        self.assertEqual(
            job_names.count("Required DCO enforcement"),
            1,
        )
        self.assertEqual(
            job_names.count("DCO sign-off check"),
            1,
        )
        compatibility = jobs.split("  status-compatibility:\n", 1)[1]
        self.assertIn("needs: [enforce-policy]", compatibility)
        self.assertIn("if: always()", compatibility)
        self.assertIn("permissions: {}", compatibility)
        self.assertIn(
            "REQUIRED_DCO_RESULT: ${{ needs.enforce-policy.result }}",
            compatibility,
        )
        self.assertIn(
            'test "$REQUIRED_DCO_RESULT" = "success"', compatibility
        )
        self.assertNotIn("continue-on-error", workflow)
        self.assertNotIn("|| true", workflow)

    def test_workflow_binds_merge_group_and_states_truth_boundary(self) -> None:
        workflow_path = Path(__file__).parents[1] / "workflows" / "dco-required.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        statement = (
            "This merge-group result is an admission continuation of the required "
            "pull-request DCO decision. It is not independent DCO evidence."
        )

        self.assertIn("if: github.event_name == 'merge_group'", workflow)
        self.assertIn(
            "EVENT_REPOSITORY: ${{ github.event.repository.full_name }}", workflow
        )
        self.assertIn(
            "EVENT_REPOSITORY_ID: ${{ github.event.repository.id }}", workflow
        )
        self.assertIn(
            "EVENT_HEAD_SHA: ${{ github.event.merge_group.head_sha }}", workflow
        )
        self.assertIn(
            "EVENT_BASE_SHA: ${{ github.event.merge_group.base_sha }}", workflow
        )
        self.assertIn(
            "EVENT_HEAD_REF: ${{ github.event.merge_group.head_ref }}", workflow
        )
        self.assertIn(
            "EVENT_BASE_REF: ${{ github.event.merge_group.base_ref }}", workflow
        )
        self.assertIn("WORKFLOW_SHA: ${{ github.sha }}", workflow)
        self.assertIn('test "$WORKFLOW_SHA" = "$EVENT_HEAD_SHA"', workflow)
        self.assertIn('test "$EVENT_BASE_SHA" != "$EVENT_HEAD_SHA"', workflow)
        self.assertIn(
            'test "$EVENT_BASE_REF" = "refs/heads/main"', workflow
        )
        self.assertIn("refs/heads/gh-readonly-queue/main/*", workflow)
        self.assertEqual(workflow.count(statement), 1)

    def test_workflow_has_no_historical_bypass(self) -> None:
        workflow_path = Path(__file__).parents[1] / "workflows" / "dco-required.yml"
        workflow = workflow_path.read_text(encoding="utf-8")

        self.assertNotIn("The active ruleset requires this workflow", workflow)
        forbidden_patterns = (
            r"(?i)\bfile_count\b",
            r"(?i)\bchanged_files\b",
            r"(?i)\bgit\s+show\b",
            r"(?im)\bgrep\b[^\n]*\^Merge",
            r"(?is)(?:file_count|changed_files).{0,200}(?:-eq|==)\s*0"
            r".{0,200}(?:exit\s+0|success|pass)",
            r"head_commit\.message",
        )
        for pattern in forbidden_patterns:
            self.assertIsNone(re.search(pattern, workflow), pattern)


if __name__ == "__main__":
    unittest.main()
