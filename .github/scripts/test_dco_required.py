#!/usr/bin/env python3
"""Focused regression tests for the fail-closed DCO checker."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from urllib.error import URLError

import dco_required as dco_check


API_URL = "https://api.github.test"
REPOSITORY = "szl-holdings/example"
PR_NUMBER = 399
TOKEN = "test-token"


def _commit(index: int, message: str | None = None) -> dict[str, object]:
    if message is None:
        message = f"fix: commit {index}\n\nSigned-off-by: Test User <test@example.com>"
    return {"sha": f"{index:040x}", "commit": {"message": message}}


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


def _metadata(count: int, head_sha: str) -> dict[str, object]:
    return {"commits": count, "head": {"sha": head_sha}}


def _stable_responses(
    commits: list[dict[str, object]],
) -> tuple[str, list[object]]:
    count = len(commits)
    head_sha = _head_sha(commits)
    metadata = _metadata(count, head_sha)
    return head_sha, [metadata, *_commit_pages(commits), [], metadata]


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


class DcoCheckTests(unittest.TestCase):
    def test_metadata_api_retrieval_failure_fails_closed(self) -> None:
        expected_head = _head_sha(_signed_commits(1))
        opener = _SequenceOpener(URLError("metadata unavailable"))

        with self.assertRaisesRegex(dco_check.DcoContractError, "retrieval failed"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
            )

    def test_commits_api_retrieval_failure_fails_closed(self) -> None:
        expected_head = _head_sha(_signed_commits(1))
        opener = _SequenceOpener(
            _metadata(1, expected_head), URLError("commits unavailable")
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "retrieval failed"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
            )

    def test_unexpectedly_empty_commit_list_fails_closed(self) -> None:
        expected_head = _head_sha(_signed_commits(1))
        opener = _SequenceOpener(_metadata(1, expected_head), [])

        with self.assertRaisesRegex(dco_check.DcoContractError, "count mismatch"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
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
        commit = _commit(14, "fix: short signer\n\nSigned-off-by: X <x@example.com>")

        self.assertEqual(dco_check.unsigned_commit_shas([commit]), [])

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
        accepted = _commit(
            57,
            "fix: final trailer suffix\n\n"
            "Body text may precede the final structured suffix.\n"
            "Signed-off-by: Test User <test@example.com>",
        )
        rejected = [
            _commit(
                58,
                "fix: missing boundary\n"
                "Signed-off-by: Test User <test@example.com>",
            ),
            _commit(
                59,
                "fix: body after trailer\n\n"
                "Signed-off-by: Test User <test@example.com>\n"
                "This body line terminates the trailer block.",
            ),
        ]

        self.assertEqual(dco_check.unsigned_commit_shas([accepted]), [])
        self.assertEqual(
            dco_check.unsigned_commit_shas(rejected),
            [commit["sha"] for commit in rejected],
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
            API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
        )

        self.assertEqual(declared, 3)
        self.assertEqual(retrieved, commits)
        self.assertEqual(len(opener.urls), 4)

    def test_249_commits_are_retrieved_completely(self) -> None:
        commits = _signed_commits(249)
        expected_head, responses = _stable_responses(commits)
        opener = _SequenceOpener(*responses)

        declared, retrieved = dco_check.fetch_authoritative_pr_commits(
            API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
        )

        self.assertEqual(declared, 249)
        self.assertEqual(len(retrieved), 249)
        self.assertTrue(opener.urls[-2].endswith("per_page=100&page=4"))

    def test_exactly_250_commits_are_retrieved_completely(self) -> None:
        commits = _signed_commits(250)
        expected_head, responses = _stable_responses(commits)
        opener = _SequenceOpener(*responses)

        declared, retrieved = dco_check.fetch_authoritative_pr_commits(
            API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
        )

        self.assertEqual(declared, 250)
        self.assertEqual(len(retrieved), 250)
        self.assertTrue(opener.urls[-2].endswith("per_page=100&page=4"))

    def test_251_commits_are_rejected_before_commit_pagination(self) -> None:
        expected_head = _head_sha(_signed_commits(251))
        opener = _SequenceOpener(_metadata(251, expected_head))

        with self.assertRaisesRegex(dco_check.DcoContractError, "capped at 250"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
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
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
            )

    def test_nonempty_boundary_page_count_mismatch_is_rejected(self) -> None:
        commits = _signed_commits(249)
        expected_head = _head_sha(commits)
        opener = _SequenceOpener(
            _metadata(249, expected_head), *_commit_pages(commits), [_commit(250)]
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "count mismatch"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
            )

    def test_duplicate_entries_within_page_are_rejected(self) -> None:
        first = _commit(1)
        expected_head = _head_sha(_signed_commits(2))
        opener = _SequenceOpener(_metadata(2, expected_head), [first, first])

        with self.assertRaisesRegex(dco_check.DcoContractError, "duplicate SHA"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
            )

    def test_duplicate_sha_across_pages_is_rejected(self) -> None:
        first_page = _signed_commits(100)
        expected_head = _head_sha(_signed_commits(101))
        opener = _SequenceOpener(
            _metadata(101, expected_head), first_page, [first_page[0]]
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "duplicate SHA"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
            )

    def test_initial_metadata_head_mismatch_is_rejected(self) -> None:
        expected_head = _head_sha(_signed_commits(2))
        replacement_head = _head_sha(_signed_commits(3))
        opener = _SequenceOpener(_metadata(2, replacement_head))

        with self.assertRaisesRegex(dco_check.DcoContractError, "head mismatch"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
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
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
            )

    def test_metadata_count_drift_after_pagination_is_rejected(self) -> None:
        commits = _signed_commits(2)
        expected_head = _head_sha(commits)
        opener = _SequenceOpener(
            _metadata(2, expected_head), commits, [], _metadata(3, expected_head)
        )

        with self.assertRaisesRegex(dco_check.DcoContractError, "metadata drifted"):
            dco_check.fetch_authoritative_pr_commits(
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
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
                API_URL, REPOSITORY, PR_NUMBER, TOKEN, expected_head, opener=opener
            )

    def test_workflow_binds_head_and_has_no_historical_bypass(self) -> None:
        workflow_path = Path(__file__).parents[1] / "workflows" / "dco-required.yml"
        workflow = workflow_path.read_text(encoding="utf-8")

        self.assertIn(
            "EXPECTED_HEAD_SHA: ${{ github.event.pull_request.head.sha }}", workflow
        )
        self.assertRegex(
            workflow,
            r"(?m)^\s*python3\s+policy/\.github/scripts/dco_required\.py\s*$",
        )
        self.assertIn(".github/workflows/dco-required.yml", workflow)
        self.assertNotIn("ready_for_review", workflow)
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
