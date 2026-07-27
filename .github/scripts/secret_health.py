#!/usr/bin/env python3
"""Audit required GitHub Actions secret names without accessing secret values."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

API = "https://api.github.com"
SCHEMA = "szl.actions-secret-health/v2"
EXIT_OK = 0
EXIT_MISSING = 1
EXIT_UNAVAILABLE = 2


class AuditUnavailable(RuntimeError):
    """Raised when the audit cannot enumerate secret names authoritatively."""


@dataclass(frozen=True)
class Requirement:
    repository: str
    secret: str


def load_policy(path: Path) -> tuple[str, list[Requirement]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "szl.required-actions-secrets/v1":
        raise ValueError("unsupported required-secret policy schema")
    organization = payload.get("organization")
    if not isinstance(organization, str) or not organization.strip():
        raise ValueError("policy organization must be a non-empty string")
    requirements: list[Requirement] = []
    for item in payload.get("requirements", []):
        if not isinstance(item, dict):
            raise ValueError("policy requirements must be objects")
        repository = item.get("repository")
        secret = item.get("secret")
        if not isinstance(repository, str) or not repository.strip():
            raise ValueError("requirement repository must be non-empty")
        if not isinstance(secret, str) or not secret.strip():
            raise ValueError("requirement secret must be non-empty")
        requirements.append(Requirement(repository.strip(), secret.strip()))
    if not requirements:
        raise ValueError("policy must contain at least one requirement")
    if len({(item.repository, item.secret) for item in requirements}) != len(requirements):
        raise ValueError("policy contains duplicate requirements")
    return organization.strip(), requirements


def _next_link(header: str) -> str | None:
    for part in header.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        if section.startswith("<") and ">" in section:
            return section[1 : section.index(">")]
    return None


def github_secret_names(token: str, endpoint: str) -> set[str]:
    """Return secret names from one GitHub listing endpoint.

    GitHub never returns secret values from these endpoints. Response bodies are
    not included in raised errors so token-adjacent diagnostics cannot be logged.
    """

    names: set[str] = set()
    url: str | None = f"{API}{endpoint}"
    while url:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "szl-secret-health/2",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
                link = response.headers.get("Link", "")
        except urllib.error.HTTPError as exc:
            raise AuditUnavailable(f"HTTP_{exc.code}") from exc
        except Exception as exc:  # noqa: BLE001 - reduced to a class-only receipt
            raise AuditUnavailable(type(exc).__name__) from exc
        if not isinstance(payload, dict):
            raise AuditUnavailable("INVALID_RESPONSE")
        secrets = payload.get("secrets")
        if not isinstance(secrets, list):
            raise AuditUnavailable("INVALID_RESPONSE")
        for item in secrets:
            name = item.get("name") if isinstance(item, dict) else None
            if not isinstance(name, str) or not name:
                raise AuditUnavailable("INVALID_SECRET_NAME")
            names.add(name)
        next_url = _next_link(link)
        if next_url is not None and not next_url.startswith(f"{API}/"):
            raise AuditUnavailable("INVALID_PAGINATION")
        url = next_url
    return names


def audit_requirements(
    organization: str,
    requirements: Iterable[Requirement],
    fetch_names: Callable[[str], set[str]],
) -> tuple[list[dict[str, Any]], int]:
    results: list[dict[str, Any]] = []
    exit_code = EXIT_OK
    for requirement in requirements:
        encoded_org = urllib.parse.quote(organization, safe="")
        encoded_repo = urllib.parse.quote(requirement.repository, safe="")
        repo_endpoint = (
            f"/repos/{encoded_org}/{encoded_repo}/actions/secrets?per_page=100"
        )
        org_endpoint = (
            f"/repos/{encoded_org}/{encoded_repo}/actions/organization-secrets"
            "?per_page=100"
        )
        try:
            repository_names = fetch_names(repo_endpoint)
            organization_names = fetch_names(org_endpoint)
        except AuditUnavailable as exc:
            results.append(
                {
                    "repository": requirement.repository,
                    "required_secret": requirement.secret,
                    "state": "UNAVAILABLE",
                    "error_class": str(exc),
                }
            )
            exit_code = EXIT_UNAVAILABLE
            continue

        present = requirement.secret in repository_names | organization_names
        results.append(
            {
                "repository": requirement.repository,
                "required_secret": requirement.secret,
                "state": "PRESENT" if present else "MISSING",
                "error_class": None,
            }
        )
        if not present and exit_code != EXIT_UNAVAILABLE:
            exit_code = EXIT_MISSING
    return results, exit_code


def build_report(
    *,
    organization: str,
    auth_source: str,
    results: list[dict[str, Any]],
    exit_code: int,
) -> dict[str, Any]:
    counts = {"PRESENT": 0, "MISSING": 0, "UNAVAILABLE": 0}
    for item in results:
        counts[item["state"]] += 1
    return {
        "schema": SCHEMA,
        "organization": organization,
        "auth_source": auth_source,
        "state": (
            "VERIFIED"
            if exit_code == EXIT_OK
            else "MISSING"
            if exit_code == EXIT_MISSING
            else "UNAVAILABLE"
        ),
        "counts": counts,
        "requirements": results,
        "secret_values_requested": False,
        "secret_values_recorded": False,
        "token_value_recorded": False,
        "token_metadata_recorded": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        default=".github/data/required_actions_secrets.json",
        type=Path,
    )
    parser.add_argument("--report", default="reports/secret-health.json", type=Path)
    args = parser.parse_args()

    token = os.environ.get("GH_TOKEN", "")
    auth_source = os.environ.get("SECRET_HEALTH_AUTH_SOURCE", "UNAVAILABLE")
    try:
        organization, requirements = load_policy(args.policy)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"secret-health policy invalid: {type(exc).__name__}", file=sys.stderr)
        return EXIT_UNAVAILABLE

    if not token:
        results = [
            {
                "repository": item.repository,
                "required_secret": item.secret,
                "state": "UNAVAILABLE",
                "error_class": "NO_MACHINE_IDENTITY",
            }
            for item in requirements
        ]
        exit_code = EXIT_UNAVAILABLE
    else:
        results, exit_code = audit_requirements(
            organization,
            requirements,
            lambda endpoint: github_secret_names(token, endpoint),
        )

    report = build_report(
        organization=organization,
        auth_source=auth_source,
        results=results,
        exit_code=exit_code,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
