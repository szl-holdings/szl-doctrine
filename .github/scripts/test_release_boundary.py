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


WORKFLOW = """name: Governed static Space release
on:
  pull_request:
    types: [opened, synchronize, reopened, edited, ready_for_review]
  push:
    branches: [main]
permissions:
  contents: read
concurrency:
  group: hf-static-space-${{ github.repository }}-${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number) || 'production' }}
  cancel-in-progress: false
jobs:
  validate:
    name: validate-static-space
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Verify exact checkout and release contracts
        env:
          SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}
          VALIDATOR_VENV: ${{ runner.temp }}/hf-validator-venv
        run: echo validated
  dco:
    name: DCO
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Validate every exact-range commit DCO trailer
        env:
          DCO_BASE_SHA: ${{ github.event.pull_request.base.sha || github.event.before }}
          DCO_HEAD_SHA: ${{ github.event.pull_request.head.sha || github.sha }}
        run: echo checked
  authorize:
    name: authorize-exact-governed-merge
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    needs: [validate, dco]
    permissions:
      actions: read
      checks: read
      contents: read
      pull-requests: read
    runs-on: ubuntu-latest
    timeout-minutes: 10
    outputs:
      authorization-outcome: ${{ steps.authorization.outcome }}
      authorization-evidence-outcome: ${{ steps.authorization-evidence.outcome }}
      bundle-outcome: ${{ steps.bundle.outcome }}
      publisher-input-outcome: ${{ steps.publisher-input.outcome }}
      publisher-digests-outcome: ${{ steps.publisher-digests.outcome }}
      publisher-input-evidence-outcome: ${{ steps.publisher-input-evidence.outcome }}
      publisher_script_sha256: ${{ steps.publisher-digests.outputs.publisher_script_sha256 }}
      publisher_lock_sha256: ${{ steps.publisher-digests.outputs.publisher_lock_sha256 }}
      publisher_config_sha256: ${{ steps.publisher-digests.outputs.publisher_config_sha256 }}
      authorization_sha256: ${{ steps.publisher-digests.outputs.authorization_sha256 }}
      bundle_manifest_sha256: ${{ steps.publisher-digests.outputs.bundle_manifest_sha256 }}
    steps:
      - name: Authorize the exact governed merge without HF credentials
        id: authorization
        continue-on-error: true
        env:
          GITHUB_TOKEN: ${{ github.token }}
          SOURCE_SHA: ${{ github.sha }}
        run: |
          set -euo pipefail
          test "$(git rev-parse HEAD)" = "$SOURCE_SHA"
          python -I scripts/hf_static_space.py guard \
            --source-sha "$SOURCE_SHA" \
            --event "$GITHUB_EVENT_PATH" \
            --output "$RUNNER_TEMP/governed-merge.json" \
            --failure-output "$RUNNER_TEMP/governed-merge-failure.json"
      - name: Upload exact publisher input
        id: publisher-input-evidence
        if: steps.publisher-input.outcome == 'success' && steps.publisher-digests.outcome == 'success'
        continue-on-error: true
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with:
          name: hf-static-space-publisher-input-${{ github.sha }}
          path: ${{ runner.temp }}/publisher-input
          if-no-files-found: error
          include-hidden-files: true
          retention-days: 1
  deploy:
    name: publish-exact-protected-main
    if: always() && needs.authorize.result == 'success' && needs.authorize.outputs.authorization-outcome == 'success' && needs.authorize.outputs.authorization-evidence-outcome == 'success' && needs.authorize.outputs.publisher-digests-outcome == 'success' && needs.authorize.outputs.publisher-input-evidence-outcome == 'success'
    needs: [authorize]
    permissions: {}
    runs-on: ubuntu-latest
    timeout-minutes: 10
    env:
      PUBLISHER_PYTHON: python
      SOURCE_SHA: ${{ github.sha }}
    outputs:
      publisher-input-outcome: ${{ steps.publisher-input.outcome }}
      publisher-rebind-outcome: ${{ steps.publisher-rebind.outcome }}
      publisher-environment-outcome: ${{ steps.publisher-environment.outcome }}
      publish-outcome: ${{ steps.publish.outcome }}
      publisher-evidence-outcome: ${{ steps.publisher-evidence.outcome }}
    steps:
      - name: Download exact authorized publisher input
        id: publisher-input
        continue-on-error: true
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
        with:
          name: hf-static-space-publisher-input-${{ github.sha }}
          path: ${{ runner.temp }}/publisher-input
      - name: Rebind five publisher inputs before interpretation or credentials
        id: publisher-rebind
        if: steps.publisher-input.outcome == 'success'
        continue-on-error: true
        env:
          GITHUB_TOKEN: ""
          GH_TOKEN: ""
        run: echo rebound
      - name: Install pinned Hugging Face client without repository credentials
        id: publisher-environment
        if: steps.publisher-rebind.outcome == 'success'
        continue-on-error: true
        env:
          PUBLISHER_VENV: ${{ runner.temp }}/hf-publisher-venv
        run: echo installed
      - name: Publish exact bundle with only the Hugging Face credential
        id: publish
        if: steps.publisher-rebind.outcome == 'success' && steps.publisher-environment.outcome == 'success'
        continue-on-error: true
        env:
          GITHUB_TOKEN: ""
          GH_TOKEN: ""
          HF_TOKEN: ${{ secrets.HF_TOKEN }}
        run: |
          set -euo pipefail
          "$PUBLISHER_PYTHON" -I "$RUNNER_TEMP/publisher-input/scripts/hf_static_space.py" deploy \
            --source-sha "$SOURCE_SHA" \
            --bundle "$RUNNER_TEMP/publisher-input/hf-static-space" \
            --authorization "$RUNNER_TEMP/publisher-input/governed-merge.json" \
            --result "$RUNNER_TEMP/publication-evidence/hf-deploy-result.json" \
            --failure-output "$RUNNER_TEMP/publication-evidence/hf-publication-failure.json"
      - name: Upload publisher outcome before any OIDC privilege exists
        id: publisher-evidence
        if: always()
        continue-on-error: true
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with:
          name: hf-static-space-publication-${{ github.sha }}
          path: ${{ runner.temp }}/publication-evidence
          if-no-files-found: error
          retention-days: 90
  measure:
    name: measure-exact-publication
    if: always() && needs.deploy.outputs.publish-outcome == 'success' && needs.deploy.outputs.publisher-evidence-outcome == 'success'
    needs: [deploy]
    permissions:
      actions: read
      checks: read
      contents: read
      pull-requests: read
    runs-on: ubuntu-latest
    timeout-minutes: 20
    outputs:
      measurement-outcome: ${{ steps.measurement.outcome }}
      measurement-evidence-outcome: ${{ steps.measurement-evidence.outcome }}
    steps:
      - name: Download exact authorized publisher input
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
        with:
          name: hf-static-space-publisher-input-${{ github.sha }}
          path: ${{ runner.temp }}/publisher-input
      - name: Download exact publisher outcome
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
        with:
          name: hf-static-space-publication-${{ github.sha }}
          path: ${{ runner.temp }}/publication-evidence
      - name: Measure public bytes and reauthorize current main without HF credentials
        id: measurement
        continue-on-error: true
        env:
          GITHUB_TOKEN: ${{ github.token }}
          HF_TOKEN: ""
          SOURCE_SHA: ${{ github.sha }}
        run: |
          set -euo pipefail
          python -I "$RUNNER_TEMP/publisher-input/scripts/hf_static_space.py" attest \
            --source-sha "$SOURCE_SHA" \
            --bundle "$RUNNER_TEMP/publisher-input/hf-static-space" \
            --authorization "$RUNNER_TEMP/publisher-input/governed-merge.json" \
            --event "$GITHUB_EVENT_PATH" \
            --authorization-output "$RUNNER_TEMP/measurement-evidence/post-readback-governed-merge.json" \
            --result "$RUNNER_TEMP/publication-evidence/hf-deploy-result.json" \
            --output "$RUNNER_TEMP/measurement-evidence/hf-live-attestation.json" \
            --failure-output "$RUNNER_TEMP/measurement-evidence/hf-publication-partial.json"
      - name: Upload exact public measurement before OIDC
        id: measurement-evidence
        if: always()
        continue-on-error: true
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with:
          name: hf-static-space-measurement-${{ github.sha }}
          path: ${{ runner.temp }}/measurement-evidence
          if-no-files-found: error
          retention-days: 90
  attest:
    name: attest-exact-publication
    if: always() && github.event_name == 'push' && github.ref == 'refs/heads/main'
    needs: [authorize, deploy, measure]
    permissions:
      attestations: write
      contents: read
      id-token: write
    runs-on: ubuntu-latest
    timeout-minutes: 10
    env:
      SOURCE_SHA: ${{ github.sha }}
    steps:
      - name: Download exact publisher outcome
        id: publisher-evidence-download
        continue-on-error: true
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
        with:
          name: hf-static-space-publication-${{ github.sha }}
          path: ${{ runner.temp }}/publication-evidence
      - name: Download exact public measurement
        id: measurement-evidence-download
        continue-on-error: true
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
        with:
          name: hf-static-space-measurement-${{ github.sha }}
          path: ${{ runner.temp }}/measurement-evidence
      - name: Attest canonical exact-revision measurement with GitHub OIDC
        id: oidc
        if: needs.measure.outputs.measurement-outcome == 'success' && needs.measure.outputs.measurement-evidence-outcome == 'success' && steps.publisher-evidence-download.outcome == 'success' && steps.measurement-evidence-download.outcome == 'success'
        continue-on-error: true
        uses: actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32
        with:
          subject-path: ${{ runner.temp }}/measurement-evidence/hf-live-attestation.json
"""
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
            "isolated_invocation": "\"$PUBLISHER_PYTHON\" -I \"$RUNNER_TEMP/publisher-input/scripts/hf_static_space.py\"",
            "identities": [{"kind": "json", "path": ".hf-space.json", "source_repository": REPOSITORY, "target": "SZLHOLDINGS/lambda-gate-holo"}],
            "required_workflow_markers": ["on:", "push:", "branches: [main]", "permissions: {}", "contents: read", "id-token: write", "attestations: write", "concurrency:", "cancel-in-progress: false", "authorize-exact-governed-merge", "publish-exact-protected-main", "measure-exact-publication", "attest-exact-publication", "needs.authorize.result == 'success'", "include-hidden-files: true", "Rebind five publisher inputs before interpretation or credentials", "GITHUB_TOKEN: ${{ github.token }}", "HF_TOKEN: ${{ secrets.HF_TOKEN }}"],
            "required_publisher_markers": ["parent_commit=before_sha", "delete_patterns=\"*\"", "szl.github-governed-merge/v3", "szl.pr-head/v1", "load_governed_merge", "required_workflow", "final_authorization = require_governed_main", "verify_live_tree", "_fetch_public_index", "failure_output_path", "run_attempt", "check_suite_id", "publisher_executable_rebind", "governance_authorization", "publisher_environment", "measurement_evidence_upload", "OIDC_ATTESTED_DEPLOYMENT", "WORKFLOW_STAGE_FAILURE", "receipt_minted"],
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
    return {"schema": RB.SCHEMA, "source_repository": RB.SOURCE_REPOSITORY, "targets": targets}


def blob_values() -> dict[str, bytes]:
    return {".github/workflows/hf-static-space.yml": WORKFLOW.encode(), ".hf-space.json": CONFIG, "requirements/hf-publisher.lock": LOCK, "requirements/hf-validator.lock": VALIDATOR_LOCK, "scripts/hf_static_space.py": PUBLISHER, "tests/test_hf_static_space.py": TEST_RUNTIME, "LICENSE": b"license", "README.md": b"readme", "index.html": b"<p>public</p>"}


class FakeAPI:
    def __init__(self, values: dict[str, bytes] | None = None, changed: int = 101) -> None:
        self.values, self.changed, self.calls = values or blob_values(), changed, []
        self.pull_heads, self.pull_reads = [HEAD, HEAD, HEAD], 0
        self.ref_heads = {"heads/gh-readonly-queue/main/pr-1": HEAD, "heads/main": BASE}
        self.tree_extra, self.fail_path, self.duplicate_page = [], None, False

    def _pull(self) -> dict:
        head = self.pull_heads[min(self.pull_reads, len(self.pull_heads) - 1)]
        self.pull_reads += 1
        repo = {"id": REPOSITORY_ID, "full_name": REPOSITORY}
        return {"number": 7, "state": "open", "changed_files": self.changed, "head": {"sha": head, "repo": repo}, "base": {"sha": BASE, "ref": "main", "repo": repo}}

    def get(self, path: str) -> object:
        self.calls.append(path)
        if self.fail_path and self.fail_path in path:
            raise RB.BoundaryError("fixture API failure")
        if path == f"/repos/{REPOSITORY}":
            return {"id": REPOSITORY_ID, "full_name": REPOSITORY, "default_branch": "main"}
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
        if path == f"/repos/{REPOSITORY}/git/commits/{HEAD}":
            return {"sha": HEAD, "tree": {"sha": TREE}}
        if path == f"/repos/{REPOSITORY}/git/trees/{TREE}?recursive=1":
            rows = [{"path": name, "mode": "100644", "type": "blob", "sha": f"{index:040x}", "size": len(value)} for index, (name, value) in enumerate(self.values.items(), 10)]
            return {"sha": TREE, "truncated": False, "tree": rows + self.tree_extra}
        if "/git/blobs/" in path:
            sha = path.rsplit("/", 1)[1]
            value = list(self.values.values())[int(sha, 16) - 10]
            return {"sha": sha, "encoding": "base64", "size": len(value), "content": base64.b64encode(value).decode()}
        if "/git/ref/" in path:
            return {"object": {"sha": self.ref_heads[unquote(path.split("/git/ref/", 1)[1])]}}
        raise AssertionError(f"unexpected API path: {path}")


def pr_event() -> dict:
    return {"number": 7, "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY}, "pull_request": {"head": {"sha": HEAD}}}


def merge_event() -> dict:
    return {"repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY}, "merge_group": {"head_sha": HEAD, "base_sha": BASE, "head_ref": "refs/heads/gh-readonly-queue/main/pr-1", "base_ref": "refs/heads/main"}}


class BoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = manifest_fixture()
        self.entry = self.manifest["targets"][REPOSITORY]
        self.env = {"EVENT_REPOSITORY": REPOSITORY, "EVENT_REPOSITORY_ID": str(REPOSITORY_ID), "EVENT_HEAD_SHA": HEAD, "GITHUB_SHA": HEAD}

    def test_repository_manifest_has_five_active_heads_and_frozen_kernel(self) -> None:
        manifest = RB.load_manifest(MANIFEST_PATH)
        self.assertEqual(
            {name for name, item in manifest["targets"].items() if item["state"] == "ACTIVE"},
            set(RB.TARGET_IDS) - {"szl-holdings/szl-kernels-live"},
        )
        kernel = manifest["targets"]["szl-holdings/szl-kernels-live"]
        self.assertEqual(kernel["state"], "PENDING")
        self.assertEqual(
            {
                name: item["observed_candidate_sha"]
                for name, item in manifest["targets"].items()
            },
            {
                "szl-holdings/energy-attest-holo": "1e5a73c839f753a7b4a79e0081c6e426134350a1",
                "szl-holdings/governed-norm-holo": "1b9ecce9f68584061ceeac24d091b16bfc76c4d3",
                "szl-holdings/lambda-gate-holo": "293b28d544dddef09244f3c1f9650ace12d4452d",
                "szl-holdings/receipt-chain-live": "343c169c80239689bb3fd0dfc250fc912be3e551",
                "szl-holdings/szl-kernels-live": None,
                "szl-holdings/szl-provctl-live": "c1af1889d846aa2865c8689a7b8893edee25cca3",
            },
        )
        for name, item in manifest["targets"].items():
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
        self.assertIn("separately supplied and reviewed v3 kernel publisher receipt", kernel["pending_reason"])
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
                "scripts/kernel_portfolio_truth.mjs",
                "scripts/snapshot_kernel_contracts.py",
                "scripts/verify_kernel_registry.py",
                "tests/fixtures/hf-static-window-huggingface-injection.html",
                "tests/test_hf_space_bundle.py",
                "tests/test_kernel_portfolio_truth.mjs",
                "tests/test_kernel_registry.py",
            },
        )
        self.assertEqual(set(kernel["workflow_files"].values()), {"PENDING"})
        self.assertEqual(set(kernel["secret_execution_files"].values()), {"PENDING"})
        all_pending = copy.deepcopy(self.manifest)
        active = all_pending["targets"][REPOSITORY]
        active["state"] = "PENDING"
        active["observed_candidate_sha"] = None
        active["pending_reason"] = "fixture pending"
        active["workflow_files"] = {path: "PENDING" for path in active["workflow_files"]}
        active["secret_execution_files"] = {path: "PENDING" for path in active["secret_execution_files"]}
        with self.assertRaisesRegex(RB.BoundaryError, "no ACTIVE"):
            RB.verify_all_active(all_pending, FakeAPI())

    def test_kernel_manifest_is_explicitly_fail_closed(self) -> None:
        kernel = RB.load_manifest(MANIFEST_PATH)["targets"]["szl-holdings/szl-kernels-live"]
        self.assertEqual(kernel["state"], "PENDING")
        self.assertIsNone(kernel["observed_candidate_sha"])
        self.assertTrue(kernel["pending_reason"])
        self.assertEqual(set(kernel["workflow_files"].values()), {"PENDING"})
        self.assertEqual(set(kernel["secret_execution_files"].values()), {"PENDING"})

    def test_all_active_verification_reports_verified_static_before_pending(self) -> None:
        result = RB.verify_all_active(self.manifest, FakeAPI())
        self.assertEqual(result["status"], "MANIFEST_INCOMPLETE_PENDING_TARGETS")
        self.assertFalse(result["authorization_complete"])
        self.assertEqual(result["targets"][0]["status"], "MANIFEST_TARGET_VERIFIED")
        self.assertEqual(len(result["pending_targets"]), 5)

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
        changed[".github/workflows/hf-static-space.yml"] = WORKFLOW.replace("\"$PUBLISHER_PYTHON\" -I", "\"$PUBLISHER_PYTHON\"").encode()
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
            "artifact input|action binding",
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
                "      - name: Download exact publisher outcome\n        uses:",
                "      - name: Download exact publisher outcome\n        if: always()\n        uses:",
                1,
            ),
            "step fields",
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
        self.assertEqual(workflow.count("Install exact structural YAML parser"), 3)
        self.assertEqual(workflow.count("--require-hashes --only-binary=:all:"), 3)
        self.assertNotIn("python -I .github/scripts/release_boundary.py", workflow)
        uses = RB.ANY_USES.findall(workflow)
        self.assertTrue(uses)
        self.assertTrue(all(RB.PINNED_USES.fullmatch(value) for value in uses))


if __name__ == "__main__":
    unittest.main()
