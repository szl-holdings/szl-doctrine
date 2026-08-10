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
  push:
    branches: [main]
permissions:
  contents: read
  id-token: write
  attestations: write
concurrency:
  cancel-in-progress: false
jobs:
  deploy:
    name: publish-exact-protected-main
    timeout-minutes: 20
    env:
      PUBLISHER_PYTHON: python
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97
      - run: python -I -m venv "$RUNNER_TEMP/venv"
      - run: pip install --require-hashes --only-binary=:all: -r requirements/hf-publisher.lock
      - name: Reauthorize exact governed main without HF credentials
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: test -n "$GITHUB_TOKEN"
      - env:
          HF_TOKEN: ${{ secrets.HF_TOKEN }}
        run: "$PUBLISHER_PYTHON" -I scripts/hf_static_space.py
"""
PUBLISHER = b"""import json
authorization = require_governed_main(source_sha, config_path)
parent_commit=before_sha
delete_patterns="*"
verify_live_tree(bundle, tree, allowed)
_fetch_public_index(origin, source_sha)
failure_output_path = output
final_authorization = require_governed_main(source_sha, config_path)
"""
LOCK = b"huggingface_hub==1.2.3 --hash=sha256:" + b"a" * 64 + b"\n"
for index in range(22):
    LOCK += f"package-{index}==1.0 --hash=sha256:{index:064x}\n".encode()
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
        "secret_execution_files": {".hf-space.json": digest(CONFIG), "requirements/hf-publisher.lock": digest(LOCK), "scripts/hf_static_space.py": digest(PUBLISHER)},
        "mutable_public_assets": ["LICENSE", "README.md", "index.html"],
        "publisher_contract": {
            "publisher_workflow": ".github/workflows/hf-static-space.yml",
            "publisher_script": "scripts/hf_static_space.py",
            "dependency_lock": "requirements/hf-publisher.lock",
            "protected_execution_roots": ["scripts"],
            "isolated_invocation": "\"$PUBLISHER_PYTHON\" -I scripts/hf_static_space.py",
            "identities": [{"kind": "json", "path": ".hf-space.json", "source_repository": REPOSITORY, "target": "SZLHOLDINGS/lambda-gate-holo"}],
            "required_workflow_markers": ["on:", "push:", "branches: [main]", "permissions:", "contents: read", "id-token: write", "attestations: write", "concurrency:", "cancel-in-progress: false", "GITHUB_TOKEN: ${{ github.token }}", "PUBLISHER_PYTHON: python", "Reauthorize exact governed main without HF credentials", "HF_TOKEN", "python -I -m venv", "--require-hashes", "--only-binary=:all:", "publish-exact-protected-main"],
            "required_publisher_markers": ["parent_commit=before_sha", "delete_patterns=\"*\"", "authorization = require_governed_main", "final_authorization = require_governed_main", "verify_live_tree", "_fetch_public_index", "failure_output_path"],
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
    return {".github/workflows/hf-static-space.yml": WORKFLOW.encode(), ".hf-space.json": CONFIG, "requirements/hf-publisher.lock": LOCK, "scripts/hf_static_space.py": PUBLISHER, "LICENSE": b"license", "README.md": b"readme", "index.html": b"<p>public</p>"}


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

    def test_repository_manifest_has_six_active_heads(self) -> None:
        manifest = RB.load_manifest(MANIFEST_PATH)
        self.assertEqual(
            {name for name, item in manifest["targets"].items() if item["state"] == "ACTIVE"},
            set(RB.TARGET_IDS),
        )
        kernel = manifest["targets"]["szl-holdings/szl-kernels-live"]
        self.assertEqual(kernel["state"], "ACTIVE")
        self.assertEqual(
            {
                name: item["observed_candidate_sha"]
                for name, item in manifest["targets"].items()
            },
            {
                "szl-holdings/energy-attest-holo": "9d2685daaef16c023236783016c1530428ac4fca",
                "szl-holdings/governed-norm-holo": "7a8ff3a6a2926e1b9924bec44007186abdb8e3ea",
                "szl-holdings/lambda-gate-holo": "a30bdd9cf7cbf5467363530c2a81dd762bd6a09e",
                "szl-holdings/receipt-chain-live": "16d0ce2d076f4c5dcb9170aeb340912d579c5de4",
                "szl-holdings/szl-kernels-live": "dcb9f4237dbb32bf6b0f74fa8673fec7e7537494",
                "szl-holdings/szl-provctl-live": "bb6920536e9b9acc5791dae7ad9cc89a984ba2fb",
            },
        )
        for name, item in manifest["targets"].items():
            markers = set(item["publisher_contract"]["required_workflow_markers"])
            if name == "szl-holdings/szl-kernels-live":
                self.assertIn("GOVERNANCE_TOKEN: ${{ github.token }}", markers)
                self.assertIn("Reauthorize exact protected main before credential use", markers)
                self.assertIn("timeout-minutes: 60", markers)
                self.assertIn("$((started_at + 3300))", markers)
                self.assertIn("max_pre_mutation_seconds=900", markers)
                self.assertIn("operation_remaining < 1800", markers)
                self.assertIn("id: deployment-failure-receipt", markers)
                self.assertNotIn("timeout-minutes: 90", markers)
                self.assertNotIn("id: deployment-failure-json", markers)
            else:
                self.assertIn("GITHUB_TOKEN: ${{ github.token }}", markers)
                self.assertIn("PUBLISHER_PYTHON: python", markers)
                self.assertIn("Reauthorize exact governed main without HF credentials", markers)
            self.assertNotIn("QILLQAQ_PRIVATE_KEY", markers)
            self.assertNotIn("permission-administration: read", markers)
            self.assertNotIn("actions/create-github-app-token@", "\n".join(markers))
        self.assertIsNone(kernel["pending_reason"])
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
        self.assertTrue(all(RB.HEX64.fullmatch(value) for value in kernel["workflow_files"].values()))
        self.assertTrue(all(RB.HEX64.fullmatch(value) for value in kernel["secret_execution_files"].values()))
        all_pending = copy.deepcopy(self.manifest)
        active = all_pending["targets"][REPOSITORY]
        active["state"] = "PENDING"
        active["observed_candidate_sha"] = None
        active["pending_reason"] = "fixture pending"
        active["workflow_files"] = {path: "PENDING" for path in active["workflow_files"]}
        active["secret_execution_files"] = {path: "PENDING" for path in active["secret_execution_files"]}
        with self.assertRaisesRegex(RB.BoundaryError, "no ACTIVE"):
            RB.verify_all_active(all_pending, FakeAPI())

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
        with self.assertRaisesRegex(RB.BoundaryError, "isolated"):
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

    def test_native_governance_contract_fails_closed(self) -> None:
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

        missing_guard = dict(baseline)
        missing_guard[workflow_path] = WORKFLOW.replace(
            "Reauthorize exact governed main without HF credentials",
            "Untrusted delayed readback",
        ).encode()
        with self.assertRaisesRegex(
            RB.BoundaryError, "does not bind native governance reauthorization"
        ):
            RB._publisher_contract(REPOSITORY, self.entry, missing_guard)

        guard_block = """      - name: Reauthorize exact governed main without HF credentials
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: test -n "$GITHUB_TOKEN"
"""
        delayed_guard = dict(baseline)
        delayed_guard[workflow_path] = (
            WORKFLOW.replace(guard_block, "") + guard_block
        ).encode()
        with self.assertRaisesRegex(
            RB.BoundaryError, "not ordered before the HF secret"
        ):
            RB._publisher_contract(REPOSITORY, self.entry, delayed_guard)

    def test_boundary_never_executes_target_and_source_workflow_is_pinned(self) -> None:
        tree = ast.parse((HERE / "release_boundary.py").read_text(encoding="utf-8"))
        forbidden = {"subprocess", "importlib", "runpy"}
        self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom)) and any(alias.name.split(".")[0] in forbidden for alias in node.names) for node in ast.walk(tree)))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval", "compile"} for node in ast.walk(tree)))
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertEqual(workflow.count("repository: szl-holdings/szl-doctrine"), 2)
        self.assertNotIn("repository: ${{ github.repository }}", workflow)
        uses = RB.ANY_USES.findall(workflow)
        self.assertTrue(uses)
        self.assertTrue(all(RB.PINNED_USES.fullmatch(value) for value in uses))


if __name__ == "__main__":
    unittest.main()
