#!/usr/bin/env python3
"""Network-free regression tests for the secret-health auditor."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("secret_health.py")
SPEC = importlib.util.spec_from_file_location("secret_health", MODULE_PATH)
assert SPEC and SPEC.loader
secret_health = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = secret_health
SPEC.loader.exec_module(secret_health)


class SecretHealthTests(unittest.TestCase):
    def test_policy_is_versioned_unique_and_explicit(self) -> None:
        policy = {
            "schema": "szl.required-actions-secrets/v1",
            "organization": "szl-holdings",
            "requirements": [
                {"repository": "a11oy", "secret": "HF_TOKEN"},
                {"repository": "killinchu", "secret": "HF_WRITE_TOKEN"},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            organization, requirements = secret_health.load_policy(path)
        self.assertEqual(organization, "szl-holdings")
        self.assertEqual(
            [(item.repository, item.secret) for item in requirements],
            [("a11oy", "HF_TOKEN"), ("killinchu", "HF_WRITE_TOKEN")],
        )

    def test_duplicate_policy_requirement_is_rejected(self) -> None:
        policy = {
            "schema": "szl.required-actions-secrets/v1",
            "organization": "szl-holdings",
            "requirements": [
                {"repository": "a11oy", "secret": "HF_TOKEN"},
                {"repository": "a11oy", "secret": "HF_TOKEN"},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                secret_health.load_policy(path)

    def test_repository_or_governed_org_name_satisfies_requirement(self) -> None:
        requirements = [
            secret_health.Requirement("a11oy", "HF_TOKEN"),
            secret_health.Requirement("killinchu", "HF_WRITE_TOKEN"),
        ]

        def fetch_names(endpoint: str) -> set[str]:
            if "/a11oy/actions/secrets" in endpoint:
                return {"HF_TOKEN"}
            if "/killinchu/actions/organization-secrets" in endpoint:
                return {"HF_WRITE_TOKEN"}
            return set()

        results, exit_code = secret_health.audit_requirements(
            "szl-holdings", requirements, fetch_names
        )
        self.assertEqual(exit_code, secret_health.EXIT_OK)
        self.assertEqual([item["state"] for item in results], ["PRESENT", "PRESENT"])

    def test_missing_name_is_distinct_from_unavailable_audit(self) -> None:
        requirement = [secret_health.Requirement("a11oy", "HF_TOKEN")]
        missing, missing_code = secret_health.audit_requirements(
            "szl-holdings", requirement, lambda _endpoint: set()
        )
        self.assertEqual(missing_code, secret_health.EXIT_MISSING)
        self.assertEqual(missing[0]["state"], "MISSING")

        def unavailable(_endpoint: str) -> set[str]:
            raise secret_health.AuditUnavailable("HTTP_403")

        unknown, unknown_code = secret_health.audit_requirements(
            "szl-holdings", requirement, unavailable
        )
        self.assertEqual(unknown_code, secret_health.EXIT_UNAVAILABLE)
        self.assertEqual(unknown[0]["state"], "UNAVAILABLE")
        self.assertEqual(unknown[0]["error_class"], "HTTP_403")

    def test_receipt_structurally_excludes_secret_and_token_material(self) -> None:
        report = secret_health.build_report(
            organization="szl-holdings",
            auth_source="governed-fallback",
            results=[
                {
                    "repository": "a11oy",
                    "required_secret": "HF_TOKEN",
                    "state": "PRESENT",
                    "error_class": None,
                }
            ],
            exit_code=secret_health.EXIT_OK,
        )
        encoded = json.dumps(report, sort_keys=True)
        self.assertEqual(report["state"], "VERIFIED")
        self.assertFalse(report["secret_values_requested"])
        self.assertFalse(report["secret_values_recorded"])
        self.assertFalse(report["token_value_recorded"])
        self.assertFalse(report["token_metadata_recorded"])
        self.assertNotIn("Bearer ", encoded)
        self.assertNotIn("ghp_", encoded)
        self.assertNotIn("github_pat_", encoded)

    def test_pagination_rejects_non_github_next_url(self) -> None:
        self.assertIsNone(secret_health._next_link(""))
        self.assertEqual(
            secret_health._next_link(
                '<https://api.github.com/resource?page=2>; rel="next", '
                '<https://api.github.com/resource?page=3>; rel="last"'
            ),
            "https://api.github.com/resource?page=2",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
