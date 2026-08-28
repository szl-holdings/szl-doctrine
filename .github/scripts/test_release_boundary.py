#!/usr/bin/env python3
"""Regression tests for the doctrine-owned external release boundary."""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch
from urllib.parse import unquote


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("release_boundary", HERE / "release_boundary.py")
RB = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RB)
MANIFEST_PATH = HERE.parent / "release-boundary" / "manifest.json"
WORKFLOW_PATH = HERE.parent / "workflows" / "release-boundary-required.yml"
REPOSITORY = "szl-holdings/lambda-gate-holo"
REPOSITORY_ID = 1295931629
HEAD, BASE, TREE = "1" * 40, "2" * 40, "3" * 40


WORKFLOW = (
    HERE.parent / "release-boundary" / "fixtures" / "hf-static-space.yml"
).read_text(encoding="utf-8")
KERNEL_WORKFLOW = (
    HERE.parent / "release-boundary" / "fixtures" / "hf-kernel-space.yml"
).read_text(encoding="utf-8")

PUBLISHER = b"""import json
governed_schema = "szl.github-governed-merge/v3"
pr_body_schema = "szl.pr-head/v1"
authorization = load_governed_merge(source_sha, config_path)
required_workflow = authorization
parent_commit=before_sha
delete_patterns="*"
verify_live_tree(bundle, tree, allowed)
_fetch_public_index(origin, source_sha)
failure_output_path = output
final_authorization = require_governed_main(source_sha, config_path)
public_main_freshness = require_public_main_fresh(source_sha, output_path, config_path)
governance_authorization = publisher_environment = measurement_evidence_upload = True
run_attempt = check_suite_id = 1
publisher_executable_rebind = True
OIDC_ATTESTED_DEPLOYMENT = WORKFLOW_STAGE_FAILURE = receipt_minted = False
"""
LOCK = b"huggingface_hub==1.2.3 --hash=sha256:" + b"a" * 64 + b"\n"
for index in range(22):
    LOCK += f"package-{index}==1.0 --hash=sha256:{index:064x}\n".encode()
VALIDATOR_LOCK = b"PyYAML==6.0.3 --hash=sha256:" + b"b" * 64 + b"\n"
TEST_RUNTIME = b"from unittest import TestCase\n"
CONFIG = json.dumps({"source_repository": REPOSITORY, "target": "SZLHOLDINGS/lambda-gate-holo"}).encode()
KERNEL_CONFIG = json.dumps({"source_repository": "szl-holdings/szl-kernels-live", "target": "SZLHOLDINGS/szl-kernels-live"}).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def manifest_fixture() -> dict:
    entry = {
        "repository_id": REPOSITORY_ID,
        "state": "ACTIVE",
        "observed_candidate_sha": HEAD,
        "pending_reason": None,
        "workflow_files": {".github/workflows/hf-static-space.yml": digest(WORKFLOW.encode())},
        "secret_execution_files": {".hf-space.json": digest(CONFIG), "requirements/hf-publisher.lock": digest(LOCK), "requirements/hf-validator.lock": digest(VALIDATOR_LOCK), "scripts/hf_static_space.py": digest(PUBLISHER), "tests/test_hf_static_space.py": digest(TEST_RUNTIME)},
        "mutable_public_assets": ["LICENSE", "README.md", "index.html"],
        "publisher_contract": {
            "publisher_workflow": ".github/workflows/hf-static-space.yml",
            "publisher_script": "scripts/hf_static_space.py",
            "dependency_lock": "requirements/hf-publisher.lock",
            "protected_execution_roots": ["scripts", "tests"],
            "isolated_invocation": "/usr/bin/env -i",
            "identities": [{"kind": "json", "path": ".hf-space.json", "source_repository": REPOSITORY, "target": "SZLHOLDINGS/lambda-gate-holo"}],
            "required_workflow_markers": ["on:", "push:", "branches: [main]", "permissions: {}", "contents: read", "id-token: write", "attestations: write", "concurrency:", "cancel-in-progress: false", "authorize-exact-governed-merge", "publish-exact-protected-main", "measure-exact-publication", "attest-exact-publication", "needs.authorize.result == 'success'", "include-hidden-files: true", "Rebind five publisher inputs before interpretation or credentials", "Reconfirm public main at exact source revision without credentials", "publisher-freshness", "github.run_attempt", "PATH=\"$RUNNER_TEMP/hf-publisher-venv/bin:/usr/bin:/bin\"", "Rebind five measurement inputs before interpretation or credentials", "/usr/bin/env -i", "terminal_synthesizer_bootstrap", "ACTIONS_ID_TOKEN_REQUEST_TOKEN: \"\"", "GITHUB_TOKEN: ${{ github.token }}", "HF_TOKEN: ${{ secrets.HF_TOKEN }}"],
            "required_publisher_markers": ["parent_commit=before_sha", "delete_patterns=\"*\"", "szl.github-governed-merge/v3", "szl.pr-head/v1", "load_governed_merge", "required_workflow", "final_authorization = require_governed_main", "require_public_main_fresh", "verify_live_tree", "_fetch_public_index", "failure_output_path", "run_attempt", "check_suite_id", "publisher_executable_rebind", "governance_authorization", "publisher_environment", "measurement_evidence_upload", "OIDC_ATTESTED_DEPLOYMENT", "WORKFLOW_STAGE_FAILURE", "receipt_minted"],
        },
    }
    targets = {}
    for repository, repository_id in RB.TARGET_IDS.items():
        value = copy.deepcopy(entry)
        value["repository_id"] = repository_id
        value["state"], value["observed_candidate_sha"], value["pending_reason"] = "PENDING", None, "fixture pending"
        value["workflow_files"] = {path: "PENDING" for path in value["workflow_files"]}
        value["secret_execution_files"] = {path: "PENDING" for path in value["secret_execution_files"]}
        value["publisher_contract"]["identities"][0]["source_repository"] = repository
        value["publisher_contract"]["identities"][0]["target"] = repository.replace("szl-holdings/", "SZLHOLDINGS/")
        targets[repository] = value
    targets[REPOSITORY] = entry
    if "szl-holdings/szl-kernels-live" in RB.TARGET_IDS:
        kernel = copy.deepcopy(entry)
        kernel["repository_id"] = RB.TARGET_IDS["szl-holdings/szl-kernels-live"]
        kernel["state"] = "ACTIVE"
        kernel["observed_candidate_sha"] = "f" * 40
        kernel["pending_reason"] = None
        kernel["workflow_files"] = {
            ".github/workflows/hf-space-deploy.yml": digest(KERNEL_WORKFLOW.encode()),
            ".github/workflows/kernel-contracts.yml": digest(KERNEL_WORKFLOW.encode()),
        }
        kernel["publisher_contract"]["publisher_workflow"] = ".github/workflows/hf-space-deploy.yml"
        kernel["publisher_contract"]["isolated_invocation"] = (
            '"$RUNNER_TEMP/hf-publisher-venv/bin/python" -I -P '
            'scripts/deploy_hf_space.py'
        )
        kernel["publisher_contract"]["required_workflow_markers"] = [
            "name: hf-space-deploy",
            "on:",
            "push:",
            "branches: [main]",
            "concurrency:",
            "cancel-in-progress: false",
            "authorize-exact-governed-merge",
            "publish-exact-protected-main",
            "measure-and-reauthorize-publication",
        ]
        kernel["publisher_contract"]["identities"][0]["source_repository"] = "szl-holdings/szl-kernels-live"
        kernel["publisher_contract"]["identities"][0]["target"] = "SZLHOLDINGS/szl-kernels-live"
        kernel["secret_execution_files"][".hf-space.json"] = digest(KERNEL_CONFIG)
        targets["szl-holdings/szl-kernels-live"] = kernel
    return {"schema": RB.SCHEMA, "source_repository": RB.SOURCE_REPOSITORY, "targets": targets}


def blob_values() -> dict[str, bytes]:
    return {".github/workflows/hf-static-space.yml": WORKFLOW.encode(), ".hf-space.json": CONFIG, "requirements/hf-publisher.lock": LOCK, "requirements/hf-validator.lock": VALIDATOR_LOCK, "scripts/hf_static_space.py": PUBLISHER, "tests/test_hf_static_space.py": TEST_RUNTIME, "LICENSE": b"license", "README.md": b"readme", "index.html": b"<p>public</p>"}


def kernel_blob_values() -> dict[str, bytes]:
    return {
        ".github/workflows/hf-space-deploy.yml": KERNEL_WORKFLOW.encode(),
        ".github/workflows/kernel-contracts.yml": KERNEL_WORKFLOW.encode(),
    }


class FakeAPI:
    def __init__(self, values: dict[str, bytes] | None = None, changed: int = 101) -> None:
        values = values or blob_values()
        self.values, self.changed, self.calls = values, changed, []
        kernel_values = dict(values)
        kernel_values.pop(".github/workflows/hf-static-space.yml", None)
        kernel_values.update({".hf-space.json": KERNEL_CONFIG}, **kernel_blob_values())
        self.values_by_repo = {
            REPOSITORY: values,
            "szl-holdings/szl-kernels-live": kernel_values,
        }
        self.pull_heads, self.pull_bases, self.pull_reads = [HEAD, HEAD, HEAD], [BASE, BASE, BASE], 0
        self.ref_heads = {"heads/gh-readonly-queue/main/pr-1": HEAD, "heads/main": BASE}
        self.tree_extra, self.fail_path, self.duplicate_page = [], None, False

    def _repo_values(self, repository: str) -> dict[str, bytes]:
        return self.values_by_repo.get(repository, self.values)

    def _repository_from_path(self, path: str) -> str:
        return path.removeprefix("/repos/").split("/git/", 1)[0]

    def _pull(self) -> dict:
        head = self.pull_heads[min(self.pull_reads, len(self.pull_heads) - 1)]
        base = self.pull_bases[min(self.pull_reads, len(self.pull_bases) - 1)]
        self.pull_reads += 1
        repo = {"id": REPOSITORY_ID, "full_name": REPOSITORY}
        return {"number": 7, "state": "open", "changed_files": self.changed, "head": {"sha": head, "repo": repo}, "base": {"sha": base, "ref": "main", "repo": repo}}

    def get(self, path: str) -> object:
        self.calls.append(path)
        if self.fail_path and self.fail_path in path:
            raise RB.BoundaryError("fixture API failure")
        if path == f"/repos/{REPOSITORY}":
            return {"id": REPOSITORY_ID, "full_name": REPOSITORY, "default_branch": "main"}
        if path.startswith("/repos/"):
            repository = path.removeprefix("/repos/")
            if repository in RB.TARGET_IDS:
                return {
                    "id": RB.TARGET_IDS[repository],
                    "full_name": repository,
                    "default_branch": "main",
                }
        if "/git/commits/" in path:
            sha = path.rsplit("/", 1)[1]
            return {"sha": sha, "tree": {"sha": TREE}}
        if "/git/trees/" in path:
            repository = self._repository_from_path(path)
            values = self._repo_values(repository)
            _, sha_fragment = path.split("/git/trees/", 1)
            sha = sha_fragment.split("?", 1)[0]
            rows = [{"path": name, "mode": "100644", "type": "blob", "sha": f"{index:040x}", "size": len(value)} for index, (name, value) in enumerate(values.items(), 10)]
            return {"sha": sha, "truncated": False, "tree": rows + self.tree_extra}
        if path == f"/repos/{REPOSITORY}/pulls/7":
            return self._pull()
        if "/pulls/7/files?" in path:
            page = int(path.rsplit("=", 1)[1])
            pages = (self.changed + 99) // 100
            if page > pages or self.changed == 0:
                return []
            count = 100 if page < pages else self.changed - 100 * (pages - 1)
            rows = [{"filename": f"docs/file-{page}-{index}.txt"} for index in range(count)]
            if self.duplicate_page and page == 2 and rows:
                rows[0]["filename"] = "docs/file-1-0.txt"
            return rows
        if path == f"/repos/{REPOSITORY}/git/trees/{TREE}?recursive=1":
            rows = [{"path": name, "mode": "100644", "type": "blob", "sha": f"{index:040x}", "size": len(value)} for index, (name, value) in enumerate(self.values.items(), 10)]
            return {"sha": TREE, "truncated": False, "tree": rows + self.tree_extra}
        if "/git/blobs/" in path:
            sha = path.rsplit("/", 1)[1]
            repository = self._repository_from_path(path)
            values = self._repo_values(repository)
            value = list(values.values())[int(sha, 16) - 10]
            return {"sha": sha, "encoding": "base64", "size": len(value), "content": base64.b64encode(value).decode()}
        if "/git/ref/" in path:
            return {"object": {"sha": self.ref_heads[unquote(path.split("/git/ref/", 1)[1])]}}
        raise AssertionError(f"unexpected API path: {path}")


def pr_event() -> dict:
    return {"number": 7, "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY}, "pull_request": {"head": {"sha": HEAD}, "base": {"sha": BASE}}}


def remove_named_step(workflow: str, job_id: str, name: str) -> str:
    job = re.search(rf"(?m)^  {re.escape(job_id)}:\r?$", workflow)
    if job is None:
        raise AssertionError(f"fixture job not found: {job_id}")
    next_job = re.search(r"(?m)^  [a-z][a-z0-9_-]*:\r?$", workflow[job.end() :])
    job_end = job.end() + next_job.start() if next_job is not None else len(workflow)
    job_text = workflow[job.start() : job_end]
    match = re.search(
        rf"(?ms)^      - name: {re.escape(name)}\r?\n.*?"
        r"(?=^      - name: |\Z)",
        job_text,
    )
    if match is None:
        raise AssertionError(f"fixture step not found: {job_id}/{name}")
    start, end = job.start() + match.start(), job.start() + match.end()
    return workflow[:start] + workflow[end:]


def merge_event() -> dict:
    return {"repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY}, "merge_group": {"head_sha": HEAD, "base_sha": BASE, "head_ref": "refs/heads/gh-readonly-queue/main/pr-1", "base_ref": "refs/heads/main"}}


class BoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = manifest_fixture()
        self.entry = self.manifest["targets"][REPOSITORY]
        self.env = {"EVENT_REPOSITORY": REPOSITORY, "EVENT_REPOSITORY_ID": str(REPOSITORY_ID), "EVENT_HEAD_SHA": HEAD, "GITHUB_SHA": HEAD}
        self.pending_targets = sorted(
            name for name, item in self.manifest["targets"].items() if item["state"] == "PENDING"
        )
        self.active_targets = sorted(
            name for name, item in self.manifest["targets"].items() if item["state"] == "ACTIVE"
        )

    def test_repository_manifest_activates_exact_signed_successor_heads(self) -> None:
        manifest = RB.load_manifest(MANIFEST_PATH)
        active_targets = sorted(
            name for name, item in manifest["targets"].items() if item["state"] == "ACTIVE"
        )
        self.assertEqual(
            {name: item["observed_candidate_sha"] for name, item in manifest["targets"].items() if item["state"] == "ACTIVE"},
            {
                "szl-holdings/energy-attest-holo": "6851c00110b275d8207c8038ffc78886cdff55fb",
                "szl-holdings/governed-norm-holo": "7015294225f8edcfe1e14a9afe464f18d63dd7c3",
                "szl-holdings/lambda-gate-holo": "a907f9c012154511459cfc56d55fbbb6f0ff7b1e",
                "szl-holdings/receipt-chain-live": "787891967b412fd3211856ffc0b2e6e4bf6da205",
                "szl-holdings/szl-kernels-live": "6c48224a8e8a4ddd05b8e1e46b4948a61634ee66",
                "szl-holdings/szl-provctl-live": "bf0903cdad0a78d06542fd5457db8d1daf82ea43",
            },
        )
        self.assertEqual(
            set(active_targets),
            set(manifest["targets"]),
        )
        kernel = manifest["targets"]["szl-holdings/szl-kernels-live"]
        self.assertIsNotNone(kernel["observed_candidate_sha"])
        for name, item in manifest["targets"].items():
            self.assertEqual(item["state"], "ACTIVE")
            self.assertIsNone(item["pending_reason"])
            for digest in (
                list(item["workflow_files"].values())
                + list(item["secret_execution_files"].values())
            ):
                self.assertIsNotNone(re.fullmatch(r"[0-9a-f]{64}", digest))
            markers = set(item["publisher_contract"]["required_workflow_markers"])
            if name != "szl-holdings/szl-kernels-live":
                self.assertIn("permissions: {}", markers)
                self.assertIn("authorize-exact-governed-merge", markers)
                self.assertIn("measure-exact-publication", markers)
                self.assertIn("attest-exact-publication", markers)
                self.assertIn("HF_TOKEN: ${{ secrets.HF_TOKEN }}", markers)
            self.assertNotIn("QILLQAQ_PRIVATE_KEY", markers)
            self.assertNotIn("permission-administration: read", markers)
            self.assertNotIn("actions/create-github-app-token@", "\n".join(markers))
        self.assertEqual(
            set(kernel["workflow_files"]),
            {".github/workflows/hf-space-deploy.yml", ".github/workflows/kernel-contracts.yml"},
        )
        self.assertEqual(
            set(kernel["secret_execution_files"]),
            {
                "requirements/hf-publisher.lock",
                "scripts/build_hf_space_bundle.py",
                "scripts/deploy_hf_space.py",
                "scripts/github_governed_merge.py",
                "scripts/kernel_portfolio_truth.mjs",
                "scripts/snapshot_kernel_contracts.py",
                "scripts/verify_kernel_registry.py",
                "tests/fixtures/hf-static-window-huggingface-injection.html",
                "tests/test_github_governed_merge.py",
                "tests/test_hf_space_bundle.py",
                "tests/test_hf_space_workflow_contract.py",
                "tests/test_kernel_portfolio_truth.mjs",
                "tests/test_kernel_registry.py",
            },
        )
        kernel_markers = set(kernel["publisher_contract"]["required_workflow_markers"])
        self.assertIn(
            "uses: actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32",
            kernel_markers,
        )
        self.assertIn(
            "subject-path: ${{ runner.temp }}/kernel-terminal-candidate/hf-canonical-success-receipt.json",
            kernel_markers,
        )
        self.assertNotIn("--action attest-build-provenance", kernel_markers)
        self.assertTrue(all(
            re.fullmatch(r"[0-9a-f]{64}", value)
            for value in kernel["workflow_files"].values()
        ))
        self.assertTrue(all(
            re.fullmatch(r"[0-9a-f]{64}", value)
            for value in kernel["secret_execution_files"].values()
        ))

    def test_kernel_manifest_is_exactly_active(self) -> None:
        kernel = RB.load_manifest(MANIFEST_PATH)["targets"]["szl-holdings/szl-kernels-live"]
        self.assertEqual(kernel["state"], "ACTIVE")
        self.assertEqual(
            kernel["observed_candidate_sha"],
            "6c48224a8e8a4ddd05b8e1e46b4948a61634ee66",
        )
        self.assertIsNone(kernel["pending_reason"])
        for digest in (
            list(kernel["workflow_files"].values())
            + list(kernel["secret_execution_files"].values())
        ):
            self.assertIsNotNone(re.fullmatch(r"[0-9a-f]{64}", digest))

    def test_kernel_workflow_governance_profile_is_exact(self) -> None:
        RB._kernel_workflow_governance_contract(KERNEL_WORKFLOW)
        mutations = (
            ("name: hf-space-deploy", "name: other", "identity"),
            ("branches: [main]", "branches: [develop]", "trigger"),
            ("cancel-in-progress: false", "cancel-in-progress: true", "concurrency"),
            (
                "name: publish-exact-protected-main",
                "name: publish-unreviewed-main",
                "execution profile",
            ),
            ("needs: authorize", "needs: attest", "execution profile"),
            ("id-token: write", "id-token: read", "permissions"),
            (
                "node-version: \"24.19.0\"",
                "node-version: \"24.18.0\"",
                "action bindings",
            ),
            (
                '"$input/scripts/deploy_hf_space.py" publish',
                '"$input/scripts/deploy_hf_space.py" guard',
                "mutation command",
            ),
            (
                "GITHUB_TOKEN: ${{ github.token }}",
                "GITHUB_TOKEN: ''",
                "GitHub token consumption",
            ),
            (
                "HF_TOKEN: ${{ secrets.HF_TOKEN }}",
                "HF_TOKEN: ''",
                "HF secret consumption",
            ),
            (
                "needs.attest.outputs.terminal_evidence_completed != 'true'",
                "needs.attest.result == 'success'",
                "execution profile",
            ),
        )
        for old, new, message in mutations:
            with self.subTest(old=old), self.assertRaisesRegex(
                RB.BoundaryError, message
            ):
                RB._kernel_workflow_governance_contract(
                    KERNEL_WORKFLOW.replace(old, new, 1)
                )

        inserted = KERNEL_WORKFLOW.replace(
            "      - name: Record bounded publisher evidence deadline\n",
            "      - name: Unreviewed publisher hook\n"
            "        shell: bash\n"
            "        run: echo unsafe\n"
            "      - name: Record bounded publisher evidence deadline\n",
            1,
        )
        with self.assertRaisesRegex(RB.BoundaryError, "canonical steps"):
            RB._kernel_workflow_governance_contract(inserted)

        fail_open_run_step_mutations = (
            (
                "      - name: Record terminal evidence completion\n"
                "        id: terminal-evidence-completion\n"
                "        if: success()\n",
                "      - name: Record terminal evidence completion\n"
                "        id: terminal-evidence-completion\n"
                "        if: always()\n",
            ),
            (
                '          python -I -P "$input/scripts/deploy_hf_space.py" '
                "enforce-terminal \\\n",
                "          echo enforce-terminal \\\n",
            ),
            (
                "      - name: Synthesize canonical success receipt candidate\n"
                "        id: candidate-receipt\n"
                "        if: needs.deploy.outputs.publish_outcome == 'success' && "
                "needs.measure.outputs.measurement_outcome == 'success'\n"
                "        continue-on-error: true\n"
                "        env:\n"
                "          ACTIONS_ID_TOKEN_REQUEST_TOKEN: \"\"\n"
                "          ACTIONS_ID_TOKEN_REQUEST_URL: \"\"\n"
                "          ACTIONS_RUNTIME_TOKEN: \"\"\n"
                "          ACTIONS_RUNTIME_URL: \"\"\n"
                "          ACTIONS_RESULTS_URL: \"\"\n"
                "          ACTIONS_CACHE_URL: \"\"\n",
                "      - name: Synthesize canonical success receipt candidate\n"
                "        id: candidate-receipt\n"
                "        if: needs.deploy.outputs.publish_outcome == 'success' && "
                "needs.measure.outputs.measurement_outcome == 'success'\n"
                "        continue-on-error: true\n",
            ),
        )
        for old, new in fail_open_run_step_mutations:
            self.assertIn(old, KERNEL_WORKFLOW)
            with self.subTest(old=old), self.assertRaisesRegex(
                RB.BoundaryError, "run-step fields"
            ):
                RB._kernel_workflow_governance_contract(
                    KERNEL_WORKFLOW.replace(old, new, 1)
                )

        output_drift = KERNEL_WORKFLOW.replace(
            "      source_sha: ${{ steps.source.outputs.sha }}\n",
            "      source_sha: ${{ github.sha }}\n",
            1,
        )
        self.assertNotEqual(output_drift, KERNEL_WORKFLOW)
        with self.assertRaisesRegex(RB.BoundaryError, "exact canonical contract"):
            RB._kernel_workflow_governance_contract(output_drift)

    def test_static_attestation_failure_artifacts_remain_downloadable(self) -> None:
        RB._workflow_governance_contract(WORKFLOW)
        mutations = (
            (
                "if: always() && needs.deploy.outputs.publication-artifact-name != ''",
                "if: needs.deploy.result == 'success'",
            ),
            (
                "if: always() && needs.measure.outputs.measurement-artifact-name != ''",
                "if: needs.measure.result == 'success'",
            ),
        )
        for old, new in mutations:
            with self.subTest(old=old), self.assertRaisesRegex(
                RB.BoundaryError, "step condition"
            ):
                RB._workflow_governance_contract(WORKFLOW.replace(old, new, 1))

    def test_all_active_verification_reports_verified_static_before_pending(self) -> None:
        result = RB.verify_all_active(self.manifest, FakeAPI())
        self.assertEqual(result["status"], "MANIFEST_INCOMPLETE_PENDING_TARGETS")
        self.assertFalse(result["authorization_complete"])
        self.assertEqual(result["targets"][0]["status"], "MANIFEST_TARGET_VERIFIED")
        self.assertEqual(result["pending_targets"], self.pending_targets)

    def test_pending_fails_before_api(self) -> None:
        pending = copy.deepcopy(self.manifest)
        pending["targets"][REPOSITORY]["state"] = "PENDING"
        api = FakeAPI()
        with patch.dict(os.environ, self.env, clear=True), self.assertRaisesRegex(RB.BoundaryError, "PENDING"):
            RB.enforce(pending, pr_event(), api)
        self.assertEqual(api.calls, [])

    def test_valid_pr_has_stable_pagination_and_final_metadata(self) -> None:
        api = FakeAPI()
        with patch.dict(os.environ, self.env, clear=True):
            result = RB.enforce(self.manifest, pr_event(), api)
        self.assertEqual(result["status"], "AUTHORIZED_FOR_MERGE")
        self.assertFalse(result["publication_proved"])
        self.assertEqual(api.pull_reads, 3)

    def test_valid_merge_group_binds_refs_before_and_after(self) -> None:
        api = FakeAPI()
        with patch.dict(os.environ, self.env, clear=True):
            result = RB.enforce(self.manifest, merge_event(), api)
        self.assertEqual(result["event"], "merge_group")
        self.assertGreaterEqual(sum("/git/ref/" in call for call in api.calls), 4)

    def test_same_count_head_replacement_fails(self) -> None:
        api = FakeAPI()
        api.pull_heads = [HEAD, "9" * 40, "9" * 40]
        with patch.dict(os.environ, self.env, clear=True), self.assertRaisesRegex(RB.BoundaryError, "drifted"):
            RB.enforce(self.manifest, pr_event(), api)

    def test_same_count_base_replacement_fails_at_each_reread(self) -> None:
        for bases in ([BASE, "8" * 40, "8" * 40], [BASE, BASE, "8" * 40]):
            api = FakeAPI()
            api.pull_bases = bases
            with self.subTest(bases=bases), patch.dict(os.environ, self.env, clear=True), self.assertRaisesRegex(RB.BoundaryError, "drifted"):
                RB.enforce(self.manifest, pr_event(), api)

    def test_duplicate_and_count_mismatch_fail(self) -> None:
        duplicate = FakeAPI()
        duplicate.duplicate_page = True
        with patch.dict(os.environ, self.env, clear=True), self.assertRaisesRegex(RB.BoundaryError, "duplicate"):
            RB.enforce(self.manifest, pr_event(), duplicate)
        mismatch = FakeAPI()
        original = mismatch.get
        def short(path: str):
            value = original(path)
            return value[:-1] if "page=2" in path and isinstance(value, list) else value
        mismatch.get = short
        with patch.dict(os.environ, self.env, clear=True), self.assertRaisesRegex(RB.BoundaryError, "incomplete"):
            RB.enforce(self.manifest, pr_event(), mismatch)

    def test_missing_extra_workflow_and_altered_sensitive_blob_fail(self) -> None:
        missing = blob_values()
        del missing[".github/workflows/hf-static-space.yml"]
        with self.assertRaisesRegex(RB.BoundaryError, "workflow path set"):
            RB.verify_candidate(FakeAPI(missing), REPOSITORY, HEAD, self.entry)
        extra = blob_values()
        extra[".github/workflows/escape.yml"] = b"on: push"
        with self.assertRaisesRegex(RB.BoundaryError, "workflow path set"):
            RB.verify_candidate(FakeAPI(extra), REPOSITORY, HEAD, self.entry)
        altered = blob_values()
        altered["scripts/hf_static_space.py"] += b"\n# changed"
        with self.assertRaisesRegex(RB.BoundaryError, "digest differs"):
            RB.verify_candidate(FakeAPI(altered), REPOSITORY, HEAD, self.entry)

    def test_extra_executable_symlink_submodule_and_bad_blob_fail(self) -> None:
        extra = blob_values()
        extra["scripts/sitecustomize.py"] = b"raise SystemExit"
        with self.assertRaisesRegex(RB.BoundaryError, "execution path set"):
            RB.verify_candidate(FakeAPI(extra), REPOSITORY, HEAD, self.entry)
        for mode, kind in (("120000", "blob"), ("160000", "commit")):
            api = FakeAPI()
            api.tree_extra = [{"path": "escape", "mode": mode, "type": kind, "sha": "8" * 40, "size": 1}]
            with self.assertRaisesRegex(RB.BoundaryError, "symlink or submodule"):
                RB.verify_candidate(api, REPOSITORY, HEAD, self.entry)
        api = FakeAPI()
        original = api.get
        def malformed(path: str):
            value = original(path)
            if "/git/blobs/" in path:
                value["content"] = "%%%"
            return value
        api.get = malformed
        with self.assertRaisesRegex(RB.BoundaryError, "base64"):
            RB.verify_candidate(api, REPOSITORY, HEAD, self.entry)

    def test_wrong_repo_id_identity_api_and_isolation_fail_closed(self) -> None:
        event = pr_event()
        event["repository"]["id"] = 1
        with patch.dict(os.environ, self.env, clear=True), self.assertRaisesRegex(RB.BoundaryError, "event payload"):
            RB.enforce(self.manifest, event, FakeAPI())
        bad = blob_values()
        bad[".hf-space.json"] = json.dumps({"source_repository": "szl-holdings/wrong", "target": "SZLHOLDINGS/lambda-gate-holo"}).encode()
        entry = copy.deepcopy(self.entry)
        entry["secret_execution_files"][".hf-space.json"] = digest(bad[".hf-space.json"])
        with self.assertRaisesRegex(RB.BoundaryError, "identity"):
            RB.verify_candidate(FakeAPI(bad), REPOSITORY, HEAD, entry)
        api = FakeAPI()
        api.fail_path = "/git/trees/"
        with self.assertRaisesRegex(RB.BoundaryError, "API failure"):
            RB.verify_candidate(api, REPOSITORY, HEAD, self.entry)
        with self.assertRaisesRegex(RB.BoundaryError, "GITHUB_TOKEN"):
            RB.GitHubAPI("")
        changed = blob_values()
        changed[".github/workflows/hf-static-space.yml"] = WORKFLOW.replace(
            '"$PUBLISHER_PYTHON" -I "$RUNNER_TEMP/publisher-input/scripts/hf_static_space.py" deploy',
            '"$PUBLISHER_PYTHON" "$RUNNER_TEMP/publisher-input/scripts/hf_static_space.py" deploy',
            1,
        ).encode()
        entry = copy.deepcopy(self.entry)
        entry["workflow_files"][".github/workflows/hf-static-space.yml"] = digest(changed[".github/workflows/hf-static-space.yml"])
        with self.assertRaisesRegex(
            RB.BoundaryError, "publisher mutation command|isolated"
        ):
            RB.verify_candidate(FakeAPI(changed), REPOSITORY, HEAD, entry)

    def test_python_identities_bind_source_and_target_constant_groups(self) -> None:
        identity = {
            "kind": "python_constants",
            "path": "publisher.py",
            "source_repository": REPOSITORY,
            "target": "SZLHOLDINGS/lambda-gate-holo",
        }
        contract = {"identities": [identity]}
        valid = (
            f'SOURCE_REPO = "{REPOSITORY}"\n'
            f'HF_REPO = "{identity["target"]}"\n'
        ).encode()
        RB._identities(REPOSITORY, contract, {"publisher.py": valid})

        bypasses = [
            valid + b'HF_REPO = choose_target()\n',
            valid + b'if enabled:\n    HF_REPO = "SZLHOLDINGS/wrong-target"\n',
            valid + b'if (HF_REPO := "SZLHOLDINGS/wrong-target"):\n    pass\n',
            valid + b'HF_REPO += "-wrong"\n',
            valid + f'HF_REPO = "{identity["target"]}"\n'.encode(),
            valid + b'import wrong_target as HF_REPO\n',
            valid + b'def operation(HF_REPO):\n    return HF_REPO\n',
        ]
        for bypass in bypasses:
            with self.subTest(bypass=bypass), self.assertRaisesRegex(
                RB.BoundaryError,
                "rebound|literal",
            ):
                RB._identities(REPOSITORY, contract, {"publisher.py": bypass})

        misdirected_target = (
            f'SOURCE_REPO = "{REPOSITORY}"\n'
            'HF_REPO = "SZLHOLDINGS/wrong-target"\n'
            f'TARGET = "{identity["target"]}"\n'
        ).encode()
        with self.assertRaisesRegex(RB.BoundaryError, "identity constants"):
            RB._identities(
                REPOSITORY,
                contract,
                {"publisher.py": misdirected_target},
            )

        misdirected_source = (
            'SOURCE_REPOSITORY = "szl-holdings/wrong-source"\n'
            f'SOURCE_REPO = "{REPOSITORY}"\n'
            f'HF_REPO = "{identity["target"]}"\n'
        ).encode()
        with self.assertRaisesRegex(RB.BoundaryError, "identity constants"):
            RB._identities(
                REPOSITORY,
                contract,
                {"publisher.py": misdirected_source},
            )

        missing_target = f'SOURCE_REPO = "{REPOSITORY}"\n'.encode()
        with self.assertRaisesRegex(RB.BoundaryError, "identity constants"):
            RB._identities(REPOSITORY, contract, {"publisher.py": missing_target})

    def test_legacy_governance_credentials_fail_closed(self) -> None:
        workflow_path = ".github/workflows/hf-static-space.yml"
        baseline = blob_values()
        RB._publisher_contract(REPOSITORY, self.entry, baseline)

        for marker in RB.LEGACY_GOVERNANCE_CREDENTIAL_MARKERS:
            altered = dict(baseline)
            altered[workflow_path] = (WORKFLOW + f"\n# {marker}\n").encode()
            with self.subTest(marker=marker), self.assertRaisesRegex(
                RB.BoundaryError, "legacy privileged governance credential"
            ):
                RB._publisher_contract(REPOSITORY, self.entry, altered)

        secret_alias = dict(baseline)
        secret_alias[workflow_path] = WORKFLOW.replace(
            "GITHUB_TOKEN: ${{ github.token }}",
            "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
        ).encode()
        with self.assertRaisesRegex(
            RB.BoundaryError, "legacy privileged governance credential"
        ):
            RB._publisher_contract(REPOSITORY, self.entry, secret_alias)

    def test_structural_privilege_domains_fail_closed(self) -> None:
        workflow_path = ".github/workflows/hf-static-space.yml"
        baseline = blob_values()

        def rejected(workflow: str, message: str) -> None:
            altered = dict(baseline)
            altered[workflow_path] = workflow.encode()
            with self.assertRaisesRegex(RB.BoundaryError, message):
                RB._publisher_contract(REPOSITORY, self.entry, altered)

        rejected(
            WORKFLOW.replace(
                "    permissions: {}\n",
                "    permissions:\n      id-token: write\n",
                1,
            ),
            "publisher job permissions",
        )
        rejected(
            WORKFLOW.replace(
                "          GITHUB_TOKEN: \"\"\n          GH_TOKEN: \"\"",
                "          GITHUB_TOKEN: ${{ github.token }}\n          GH_TOKEN: \"\"",
                1,
            ),
            "publisher mutation credential boundary|publisher job contains a GitHub repository credential",
        )
        rejected(
            WORKFLOW.replace(
                "          HF_TOKEN: \"\"\n          SOURCE_SHA:",
                "          HF_TOKEN: ${{ secrets.HF_TOKEN }}\n          SOURCE_SHA:",
                1,
            ),
            "measurement credential boundary|HF secret consumption",
        )
        rejected(
            WORKFLOW.replace(
                "    if: always() && github.event_name == 'push' && github.ref == 'refs/heads/main'",
                "    if: always()",
                1,
            ),
            "attestation job is not protected-main-push only",
        )
        rejected(
            WORKFLOW.replace(
                "hf-static-space-publication-${{ github.sha }}",
                "hf-static-space-publication-stale",
                1,
            ),
            "output map|artifact input|action binding",
        )

    def test_publisher_freshness_and_attempt_boundaries_fail_closed(self) -> None:
        workflow_path = ".github/workflows/hf-static-space.yml"
        baseline = blob_values()

        def rejected(workflow: str, message: str) -> None:
            altered = dict(baseline)
            altered[workflow_path] = workflow.encode()
            with self.assertRaisesRegex(RB.BoundaryError, message):
                RB._publisher_contract(REPOSITORY, self.entry, altered)

        rejected(
            WORKFLOW.replace(
                "hf-static-space-publisher-input-${{ github.sha }}-${{ github.run_attempt }}",
                "hf-static-space-publisher-input-${{ github.sha }}",
                1,
            ),
            "output map|action binding|artifact input map",
        )
        rejected(
            WORKFLOW.replace(
                "${{ needs.authorize.outputs.publisher-input-artifact-name }}",
                "hf-static-space-publisher-input-${{ github.sha }}-${{ github.run_attempt }}",
                1,
            ),
            "action binding|artifact input map",
        )
        rejected(
            WORKFLOW.replace(
                'PATH="$RUNNER_TEMP/hf-publisher-venv/bin:/usr/bin:/bin"',
                'PATH="$PUBLISHER_VENV/bin:/usr/bin:/bin"',
                1,
            ),
            "publisher freshness command",
        )
        rejected(
            WORKFLOW.replace(
                '"$PUBLISHER_PYTHON" -I "$RUNNER_TEMP/publisher-input/scripts/hf_static_space.py" fresh-main',
                '"$PUBLISHER_PYTHON" -I "$RUNNER_TEMP/publisher-input/scripts/hf_static_space.py" deploy',
                1,
            ),
            "publisher freshness command",
        )
        rejected(
            WORKFLOW.replace(
                "github-main-preflight-freshness.json",
                "github-main-freshness.json",
                1,
            ),
            "publisher freshness command",
        )
        rejected(
            WORKFLOW.replace(
                "--stage publisher_freshness",
                "--stage publisher_environment",
                1,
            ),
            "publisher freshness failure command",
        )
        rejected(
            WORKFLOW.replace(
                "        if: steps.publisher-rebind.outcome == 'success' && steps.publisher-environment.outcome == 'success' && steps.publisher-freshness.outcome == 'success'\n",
                "        if: steps.publisher-rebind.outcome == 'success' && steps.publisher-environment.outcome == 'success'\n",
                1,
            ),
            "step condition",
        )
        publish_name = "      - name: Publish exact bundle with only the Hugging Face credential\n"
        before_publish, publish_and_after = WORKFLOW.split(publish_name, 1)
        rejected(
            before_publish
            + publish_name
            + publish_and_after.replace(
                'PATH="$RUNNER_TEMP/hf-publisher-venv/bin:/usr/bin:/bin"',
                'PATH="$PUBLISHER_VENV/bin:/usr/bin:/bin"',
                1,
            ),
            "publisher mutation|dangling shell continuation",
        )
        rejected(
            WORKFLOW.replace(
                '            --freshness-output "$RUNNER_TEMP/publication-evidence/github-main-freshness.json"\n',
                "",
                1,
            ),
            "publisher mutation|dangling shell continuation",
        )
        rejected(
            WORKFLOW.replace(
                '            --bundle-outcome "${{ needs.authorize.outputs.bundle-outcome }}" \\\n',
                "",
                1,
            ),
            "terminal outcome synthesis",
        )
        rejected(
            WORKFLOW.replace(
                '          test "${{ steps.publisher-freshness.outcome }}" = "success"\n',
                "",
                1,
            ),
            "publisher success command",
        )

    def test_yaml_and_expression_bypasses_fail_closed(self) -> None:
        workflow_path = ".github/workflows/hf-static-space.yml"
        baseline = blob_values()

        def rejected(workflow: str, message: str) -> None:
            altered = dict(baseline)
            altered[workflow_path] = workflow.encode()
            with self.assertRaisesRegex(RB.BoundaryError, message):
                RB._publisher_contract(REPOSITORY, self.entry, altered)

        rejected(
            WORKFLOW.replace(
                "    permissions: {}\n",
                '    "permissio\\u006es":\n      contents: write\n',
                1,
            ),
            "publisher job permissions",
        )
        rejected(
            WORKFLOW.replace(
                "${{ secrets.HF_TOKEN }}",
                "${{ secrets['HF_TOKEN'] }}",
                1,
            ),
            "credential boundary|HF secret consumption",
        )
        for expression in ("${{ toJSON(secrets) }}", "${{ secrets[env.HF_SECRET_NAME] }}"):
            rejected(
                WORKFLOW.replace("${{ secrets.HF_TOKEN }}", expression, 1),
                "HF secret consumption",
            )
        rejected(
            WORKFLOW.replace("${{ github.token }}", "${{ github['token'] }}", 1),
            "GitHub token consumption",
        )
        rejected(
            WORKFLOW.replace(
                '            --failure-output "$RUNNER_TEMP/governed-merge-failure.json"',
                '            --failure-output "$RUNNER_TEMP/governed-merge-failure.json" || true',
                1,
            ),
            "authorization command is not exact and mandatory",
        )
        rejected(
            WORKFLOW.replace(
                "permissions:\n  contents: read\n",
                "permissions:\n  contents: read\npermissions:\n  contents: write\n",
                1,
            ),
            "duplicate YAML key",
        )
        rejected(
            WORKFLOW.replace(
                "        uses: actions/upload-artifact@",
                '        "us\\u0065s": actions/upload-artifact@',
                1,
            ),
            "decoded action inventory",
        )
        rejected(
            WORKFLOW.replace(
                "          path: ${{ runner.temp }}/publisher-input\n",
                "          path: ${{ runner.temp }}/publisher-input\n          run-id: 1\n",
                1,
            ),
            "action binding|artifact input map",
        )
        rejected(
            WORKFLOW.replace(
                "  deploy:\n",
                "  deploy:\n    container: ubuntu:latest\n",
                1,
            ),
            "job fields",
        )
        rejected(
            WORKFLOW.replace(
                "      authorization-outcome: ${{ steps.authorization.outcome }}",
                "      authorization-outcome: ${{ steps.bundle.outcome }}",
                1,
            ),
            "output map",
        )
        rejected(
            WORKFLOW.replace(
                "      - name: Download exact publisher outcome\n"
                "        id: publisher-evidence-download\n"
                "        if: always() && needs.deploy.outputs.publication-artifact-name != ''\n"
                "        continue-on-error: true\n"
                "        uses:",
                "      - name: Download exact publisher outcome\n"
                "        id: publisher-evidence-download\n"
                "        if: always()\n"
                "        continue-on-error: true\n"
                "        uses:",
                1,
            ),
            "step condition",
        )

        document = RB._workflow_document(WORKFLOW)
        for job_id, job in document["jobs"].items():
            for step in job["steps"]:
                with self.subTest(job=job_id, missing_step=step["name"]):
                    rejected(
                        remove_named_step(WORKFLOW, job_id, step["name"]),
                        "canonical steps",
                    )

    def test_boundary_never_executes_target_and_source_workflow_is_pinned(self) -> None:
        tree = ast.parse((HERE / "release_boundary.py").read_text(encoding="utf-8"))
        forbidden = {"subprocess", "importlib", "runpy"}
        self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom)) and any(alias.name.split(".")[0] in forbidden for alias in node.names) for node in ast.walk(tree)))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval", "compile"} for node in ast.walk(tree)))
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertEqual(workflow.count("repository: szl-holdings/szl-doctrine"), 2)
        self.assertNotIn("repository: ${{ github.repository }}", workflow)
        self.assertEqual(
            workflow.count(".github/requirements/release-boundary.lock"), 5
        )
        self.assertEqual(
            workflow.count(
                ".github/release-boundary/fixtures/hf-kernel-space.yml"
            ),
            2,
        )
        self.assertEqual(workflow.count("Install exact structural YAML parser"), 3)
        self.assertEqual(workflow.count("--require-hashes --only-binary=:all:"), 3)
        self.assertNotIn("python -I .github/scripts/release_boundary.py", workflow)
        uses = RB.ANY_USES.findall(workflow)
        self.assertTrue(uses)
        self.assertTrue(all(RB.PINNED_USES.fullmatch(value) for value in uses))


if __name__ == "__main__":
    unittest.main()
