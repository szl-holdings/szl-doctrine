#!/usr/bin/env python3
"""Fail-closed external release authorization without target checkout/execution."""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


SCHEMA = "szl.release-boundary-manifest/v1"
SOURCE_REPOSITORY = "szl-holdings/szl-doctrine"
TARGET_IDS = {
    "szl-holdings/energy-attest-holo": 1295929955,
    "szl-holdings/governed-norm-holo": 1295931607,
    "szl-holdings/lambda-gate-holo": 1295931629,
    "szl-holdings/receipt-chain-live": 1295940016,
    "szl-holdings/szl-kernels-live": 1295941334,
    "szl-holdings/szl-provctl-live": 1295941247,
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ANY_USES = re.compile(
    r"^\s*(?:-\s+)?uses:\s*([^\s#]+)(?:\s+#.*)?$", re.MULTILINE
)
PINNED_USES = re.compile(r"^([^@\s]+)@([0-9a-f]{40})$")
NATIVE_GOVERNANCE_TOKEN_BINDINGS = (
    "GITHUB_TOKEN: ${{ github.token }}",
    "GOVERNANCE_TOKEN: ${{ github.token }}",
)
GOVERNANCE_REAUTHORIZATION_STEPS = (
    "Reauthorize exact governed main without HF credentials",
    "Reauthorize exact protected main before credential use",
)
LEGACY_GOVERNANCE_CREDENTIAL_MARKERS = (
    "actions/create-github-app-token@",
    "QILLQAQ_CLIENT_ID",
    "QILLQAQ_PRIVATE_KEY",
    "permission-administration:",
    "permission-contents:",
    "steps.governance-token.outputs.token",
    "secrets.GITHUB_TOKEN",
)
REGULAR_MODES = {"100644", "100755"}
MAX_TREE_ENTRIES = 20000
MAX_BLOB_BYTES = 4 * 1024 * 1024
MUTABLE_SUFFIXES = {"", ".html", ".json", ".md", ".txt"}


class BoundaryError(RuntimeError):
    """The candidate cannot be externally authorized."""


def _exact_sha(value: object, label: str) -> str:
    normalized = str(value or "").lower()
    if not HEX40.fullmatch(normalized):
        raise BoundaryError(f"{label} must be an exact lowercase 40-character SHA")
    return normalized


def _safe_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise BoundaryError(f"unsafe repository path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) in {"", "."}:
        raise BoundaryError(f"unsafe repository path: {value!r}")
    return str(path)


def _exact_keys(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise BoundaryError(f"{label} fields are not exact")
    return value


def _hash_map(value: object, state: str, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise BoundaryError(f"{label} must be a non-empty path/hash map")
    result = {}
    for raw_path, digest in value.items():
        path = _safe_path(raw_path)
        if path in result or not isinstance(digest, str):
            raise BoundaryError(f"{label} contains a malformed entry")
        if state == "ACTIVE" and not HEX64.fullmatch(digest):
            raise BoundaryError(f"active {label} hash is not exact: {path}")
        if state == "PENDING" and digest != "PENDING":
            raise BoundaryError(f"pending {label} must use literal PENDING: {path}")
        result[path] = digest
    return result


def load_manifest(path: Path) -> dict:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BoundaryError("release-boundary manifest is unavailable or malformed") from error
    _exact_keys(manifest, {"schema", "source_repository", "targets"}, "manifest")
    if manifest["schema"] != SCHEMA or manifest["source_repository"] != SOURCE_REPOSITORY:
        raise BoundaryError("manifest schema or protected source repository is wrong")
    if not isinstance(manifest["targets"], dict) or set(manifest["targets"]) != set(TARGET_IDS):
        raise BoundaryError("manifest target allowlist is not exact")
    for repository, entry in manifest["targets"].items():
        _validate_entry(repository, entry)
    return manifest


def _validate_entry(repository: str, value: object) -> None:
    entry = _exact_keys(value, {"repository_id", "state", "observed_candidate_sha", "pending_reason", "workflow_files", "secret_execution_files", "mutable_public_assets", "publisher_contract"}, f"manifest entry {repository}")
    if entry["repository_id"] != TARGET_IDS[repository]:
        raise BoundaryError(f"repository ID allowlist mismatch: {repository}")
    state = entry["state"]
    if state not in {"ACTIVE", "PENDING"}:
        raise BoundaryError(f"invalid manifest state: {repository}")
    if state == "ACTIVE":
        _exact_sha(entry["observed_candidate_sha"], f"{repository} observed candidate")
        if entry["pending_reason"] is not None:
            raise BoundaryError(f"active target has a pending reason: {repository}")
    elif entry["observed_candidate_sha"] is not None or not isinstance(entry["pending_reason"], str) or not entry["pending_reason"].strip():
        raise BoundaryError(f"pending target is not explicitly fail-closed: {repository}")
    workflows = _hash_map(entry["workflow_files"], state, "workflow files")
    closure = _hash_map(entry["secret_execution_files"], state, "secret execution files")
    if set(workflows) & set(closure) or any(not path.startswith(".github/workflows/") for path in workflows):
        raise BoundaryError(f"workflow and secret closure path sets are invalid: {repository}")
    assets = entry["mutable_public_assets"]
    if not isinstance(assets, list) or assets != sorted(set(assets)):
        raise BoundaryError(f"mutable public assets are not sorted and unique: {repository}")
    for raw_path in assets:
        path = _safe_path(raw_path)
        if path.startswith(".github/") or path.startswith("scripts/") or path.startswith("tests/") or PurePosixPath(path).suffix.lower() not in MUTABLE_SUFFIXES or path in workflows or path in closure:
            raise BoundaryError(f"mutable asset could execute on the CI host: {path}")
    contract = _exact_keys(entry["publisher_contract"], {"publisher_workflow", "publisher_script", "dependency_lock", "protected_execution_roots", "isolated_invocation", "identities", "required_workflow_markers", "required_publisher_markers"}, f"publisher contract {repository}")
    if contract["publisher_workflow"] not in workflows or contract["publisher_script"] not in closure or contract["dependency_lock"] not in closure:
        raise BoundaryError(f"publisher runtime is outside the protected path sets: {repository}")
    roots = contract["protected_execution_roots"]
    if not isinstance(roots, list) or roots != sorted(set(roots)) or not roots:
        raise BoundaryError(f"protected execution roots are malformed: {repository}")
    for root in roots:
        _safe_path(root)
        if "/" in root:
            raise BoundaryError(f"protected execution root must be top-level: {repository}")
    if not isinstance(contract["isolated_invocation"], str) or not contract["isolated_invocation"]:
        raise BoundaryError(f"isolated publisher invocation is missing: {repository}")
    identities = contract["identities"]
    if not isinstance(identities, list) or not identities:
        raise BoundaryError(f"publisher identities are missing: {repository}")
    for identity in identities:
        identity = _exact_keys(identity, {"kind", "path", "source_repository", "target"}, f"identity {repository}")
        if identity["kind"] not in {"json", "python_constants"} or identity["path"] not in closure or identity["source_repository"] != repository or identity["target"] != repository.replace("szl-holdings/", "SZLHOLDINGS/"):
            raise BoundaryError(f"publisher identity is outside the closure or wrong: {repository}")
    for key in ("required_workflow_markers", "required_publisher_markers"):
        markers = contract[key]
        if not isinstance(markers, list) or not markers or any(not isinstance(marker, str) or not marker for marker in markers):
            raise BoundaryError(f"{key} is incomplete: {repository}")


class GitHubAPI:
    def __init__(self, token: str, api_root: str = "https://api.github.com") -> None:
        if not token:
            raise BoundaryError("GITHUB_TOKEN is unavailable")
        self.token = token
        self.api_root = api_root.rstrip("/")

    def get(self, path: str) -> object:
        request = urllib.request.Request(self.api_root + path, headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self.token}", "User-Agent": "szl-doctrine-release-boundary/1.0", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status != 200:
                    raise BoundaryError(f"GitHub API failed closed with HTTP {response.status}")
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise BoundaryError(f"GitHub API failed closed with HTTP {error.code}") from error
        except (TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as error:
            raise BoundaryError("GitHub API retrieval failed closed") from error


def _repository_identity(api: GitHubAPI, repository: str, expected_id: int) -> None:
    metadata = api.get(f"/repos/{repository}")
    if not isinstance(metadata, dict) or metadata.get("id") != expected_id or metadata.get("full_name") != repository or metadata.get("default_branch") != "main":
        raise BoundaryError("event repository identity or default branch is not exact")


def _pull_binding(value: object, repository: str, repository_id: int, number: int) -> tuple[str, int]:
    if not isinstance(value, dict) or value.get("number") != number or value.get("state") != "open":
        raise BoundaryError("pull request metadata is unavailable or not open")
    head, base = value.get("head"), value.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict) or not isinstance(head.get("repo"), dict) or not isinstance(base.get("repo"), dict):
        raise BoundaryError("pull request head/base metadata is malformed")
    if head["repo"].get("id") != repository_id or base["repo"].get("id") != repository_id or head["repo"].get("full_name") != repository or base["repo"].get("full_name") != repository:
        raise BoundaryError("forked or cross-repository candidates are not authorized")
    if base.get("ref") != "main":
        raise BoundaryError("pull request base is not the exact default branch")
    head_sha = _exact_sha(head.get("sha"), "pull request head")
    _exact_sha(base.get("sha"), "pull request base")
    changed = value.get("changed_files")
    if not isinstance(changed, int) or isinstance(changed, bool) or changed < 0 or changed > 3000:
        raise BoundaryError("pull request changed-file count is unavailable or unbounded")
    return head_sha, changed


def _pull_files(api: GitHubAPI, repository: str, number: int, declared: int) -> list[str]:
    pages = (declared + 99) // 100
    paths, seen = [], set()
    for page in range(1, pages + 1):
        rows = api.get(f"/repos/{repository}/pulls/{number}/files?per_page=100&page={page}")
        expected = 100 if page < pages else declared - 100 * (pages - 1)
        if not isinstance(rows, list) or len(rows) != expected:
            raise BoundaryError("pull request files pagination is incomplete")
        for row in rows:
            if not isinstance(row, dict):
                raise BoundaryError("pull request file metadata is malformed")
            path = _safe_path(row.get("filename"))
            if path in seen:
                raise BoundaryError(f"duplicate pull request file entry: {path}")
            seen.add(path)
            paths.append(path)
    boundary = api.get(f"/repos/{repository}/pulls/{number}/files?per_page=100&page={pages + 1 if pages else 1}")
    if not isinstance(boundary, list) or boundary or len(paths) != declared:
        raise BoundaryError("pull request file count/boundary page is incomplete")
    return paths


def _ref_sha(api: GitHubAPI, repository: str, ref: str) -> str:
    encoded = urllib.parse.quote(ref.removeprefix("refs/"), safe="")
    value = api.get(f"/repos/{repository}/git/ref/{encoded}")
    if not isinstance(value, dict) or not isinstance(value.get("object"), dict):
        raise BoundaryError("Git ref metadata is malformed")
    return _exact_sha(value["object"].get("sha"), f"ref {ref}")


def _event_binding(api: GitHubAPI, event: dict, repository: str, repository_id: int) -> tuple[str, tuple[object, ...]]:
    event_repo = event.get("repository")
    if not isinstance(event_repo, dict) or event_repo.get("full_name") != repository or event_repo.get("id") != repository_id:
        raise BoundaryError("event payload repository identity is wrong")
    if "pull_request" in event:
        pull = event.get("pull_request")
        number = event.get("number")
        if not isinstance(pull, dict) or not isinstance(number, int):
            raise BoundaryError("pull request event payload is malformed")
        event_head = _exact_sha((pull.get("head") or {}).get("sha"), "event pull request head")
        first = api.get(f"/repos/{repository}/pulls/{number}")
        head_sha, changed = _pull_binding(first, repository, repository_id, number)
        if head_sha != event_head:
            raise BoundaryError("event and authoritative pull request heads differ")
        _pull_files(api, repository, number, changed)
        second = api.get(f"/repos/{repository}/pulls/{number}")
        if _pull_binding(second, repository, repository_id, number) != (head_sha, changed):
            raise BoundaryError("pull request head/count drifted during pagination")
        return head_sha, ("pull_request", number, head_sha, changed)
    group = event.get("merge_group")
    if not isinstance(group, dict):
        raise BoundaryError("only pull_request and merge_group events are supported")
    head_sha = _exact_sha(group.get("head_sha"), "merge-group head")
    base_sha = _exact_sha(group.get("base_sha"), "merge-group base")
    head_ref, base_ref = str(group.get("head_ref") or ""), str(group.get("base_ref") or "")
    if not head_ref.startswith("refs/heads/gh-readonly-queue/main/") or base_ref != "refs/heads/main" or _exact_sha(os.environ.get("GITHUB_SHA"), "GITHUB_SHA") != head_sha:
        raise BoundaryError("merge-group event is not an exact default-branch queue binding")
    if _ref_sha(api, repository, head_ref) != head_sha or _ref_sha(api, repository, base_ref) != base_sha:
        raise BoundaryError("merge-group refs do not resolve to event SHAs")
    return head_sha, ("merge_group", head_ref, head_sha, base_ref, base_sha)


def _tree(api: GitHubAPI, repository: str, head_sha: str) -> dict[str, dict]:
    commit = api.get(f"/repos/{repository}/git/commits/{head_sha}")
    if not isinstance(commit, dict) or commit.get("sha") != head_sha or not isinstance(commit.get("tree"), dict):
        raise BoundaryError("candidate commit metadata is malformed")
    tree_sha = _exact_sha(commit["tree"].get("sha"), "candidate tree")
    value = api.get(f"/repos/{repository}/git/trees/{tree_sha}?recursive=1")
    if not isinstance(value, dict) or value.get("sha") != tree_sha or value.get("truncated") is not False or not isinstance(value.get("tree"), list) or len(value["tree"]) > MAX_TREE_ENTRIES:
        raise BoundaryError("candidate recursive tree is unavailable, truncated, or unbounded")
    entries = {}
    for raw in value["tree"]:
        if not isinstance(raw, dict):
            raise BoundaryError("candidate tree entry is malformed")
        path = _safe_path(raw.get("path"))
        if path in entries:
            raise BoundaryError(f"duplicate candidate tree path: {path}")
        mode, kind = raw.get("mode"), raw.get("type")
        if mode in {"120000", "160000"} or kind == "commit":
            raise BoundaryError(f"symlink or submodule is forbidden: {path}")
        if kind == "blob" and mode not in REGULAR_MODES:
            raise BoundaryError(f"non-regular blob mode is forbidden: {path}")
        entries[path] = raw
    return entries


def _blob(api: GitHubAPI, repository: str, entry: dict) -> bytes:
    sha = _exact_sha(entry.get("sha"), "blob SHA")
    value = api.get(f"/repos/{repository}/git/blobs/{sha}")
    if not isinstance(value, dict) or value.get("sha") != sha or value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
        raise BoundaryError("required Git blob is malformed")
    try:
        data = base64.b64decode("".join(value["content"].split()), validate=True)
    except (ValueError, TypeError) as error:
        raise BoundaryError("required Git blob base64 is malformed") from error
    if len(data) > MAX_BLOB_BYTES or value.get("size") != len(data) or entry.get("size") != len(data):
        raise BoundaryError("required Git blob size is wrong or unbounded")
    return data


def _identities(repository: str, contract: dict, blobs: dict[str, bytes]) -> None:
    for identity in contract["identities"]:
        data = blobs[identity["path"]]
        if identity["kind"] == "json":
            try:
                value = json.loads(data.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as error:
                raise BoundaryError("publisher identity JSON is malformed") from error
            if not isinstance(value, dict) or value.get("source_repository") != repository or value.get("target") != identity["target"]:
                raise BoundaryError("publisher config identity is wrong")
        else:
            try:
                module = ast.parse(data.decode("utf-8"))
            except (UnicodeError, SyntaxError) as error:
                raise BoundaryError("publisher identity Python is malformed") from error
            governed_names = {
                "SOURCE_REPO",
                "SOURCE_REPOSITORY",
                "HF_REPO",
                "TARGET",
            }
            literals = {}
            allowed_stores = set()
            for node in module.body:
                target = None
                value = None
                if (
                    isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                ):
                    target, value = node.targets[0], node.value
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    target, value = node.target, node.value
                if target is None or target.id not in governed_names:
                    continue
                if target.id in literals or value is None:
                    raise BoundaryError("publisher Python identity constant is rebound")
                try:
                    literals[target.id] = ast.literal_eval(value)
                except (ValueError, TypeError) as error:
                    raise BoundaryError(
                        "publisher Python identity constant is not a literal"
                    ) from error
                allowed_stores.add(id(target))
            for node in ast.walk(module):
                if (
                    isinstance(node, ast.Name)
                    and node.id in governed_names
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and id(node) not in allowed_stores
                ):
                    raise BoundaryError(
                        "publisher Python identity constant is rebound"
                    )
                bound_names = []
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    bound_names.append(node.name)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    arguments = node.args
                    bound_names.extend(
                        argument.arg
                        for argument in (
                            list(arguments.posonlyargs)
                            + list(arguments.args)
                            + list(arguments.kwonlyargs)
                        )
                    )
                    if arguments.vararg is not None:
                        bound_names.append(arguments.vararg.arg)
                    if arguments.kwarg is not None:
                        bound_names.append(arguments.kwarg.arg)
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    bound_names.extend(
                        alias.asname or alias.name.split(".", 1)[0]
                        for alias in node.names
                    )
                if isinstance(node, ast.ExceptHandler) and node.name:
                    bound_names.append(node.name)
                if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                    bound_names.append(node.name)
                if isinstance(node, ast.MatchMapping) and node.rest:
                    bound_names.append(node.rest)
                if any(name in governed_names for name in bound_names):
                    raise BoundaryError(
                        "publisher Python identity constant is rebound"
                    )
            source_literals = {
                name: literals[name]
                for name in ("SOURCE_REPO", "SOURCE_REPOSITORY")
                if name in literals
            }
            target_literals = {
                name: literals[name]
                for name in ("HF_REPO", "TARGET")
                if name in literals
            }
            if (
                not source_literals
                or any(value != identity["source_repository"] for value in source_literals.values())
                or not target_literals
                or any(value != identity["target"] for value in target_literals.values())
            ):
                raise BoundaryError("publisher Python identity constants are wrong")


def _publisher_contract(repository: str, entry: dict, blobs: dict[str, bytes]) -> None:
    contract = entry["publisher_contract"]
    try:
        workflow = blobs[contract["publisher_workflow"]].decode("utf-8")
        publisher = blobs[contract["publisher_script"]].decode("utf-8")
        lock = blobs[contract["dependency_lock"]].decode("utf-8")
    except UnicodeError as error:
        raise BoundaryError("workflow or protected runtime is not UTF-8") from error
    uses = ANY_USES.findall(workflow)
    if not uses or any(value.startswith("./") or PINNED_USES.fullmatch(value) is None for value in uses):
        raise BoundaryError("publisher workflow contains an unpinned or local action")
    if any(marker in workflow for marker in LEGACY_GOVERNANCE_CREDENTIAL_MARKERS):
        raise BoundaryError("publisher workflow retains a legacy privileged governance credential")
    if "permission-actions:" in workflow or "secrets: inherit" in workflow:
        raise BoundaryError("publisher workflow expands permissions or inherits secrets")
    native_positions = [
        workflow.find(binding)
        for binding in NATIVE_GOVERNANCE_TOKEN_BINDINGS
        if binding in workflow
    ]
    guards = [
        step for step in GOVERNANCE_REAUTHORIZATION_STEPS if step in workflow
    ]
    hf_at = workflow.find("HF_TOKEN")
    if len(guards) != 1 or not native_positions or hf_at < 0:
        raise BoundaryError("publisher workflow does not bind native governance reauthorization")
    guard_at = workflow.find(guards[0])
    native_at = min(native_positions)
    if not guard_at < native_at < hf_at:
        raise BoundaryError("native governance reauthorization is not ordered before the HF secret")
    if contract["isolated_invocation"] not in workflow:
        raise BoundaryError("publisher invocation is not isolated from repository modules")
    for marker in contract["required_workflow_markers"]:
        if marker not in workflow:
            raise BoundaryError(f"publisher workflow marker is missing: {marker}")
    for marker in contract["required_publisher_markers"]:
        if marker not in publisher:
            raise BoundaryError(f"publisher runtime marker is missing: {marker}")
    lines = [line.strip() for line in lock.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    packages = set()
    for line in lines:
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s]+)(?:\s+--hash=sha256:[0-9a-f]{64})+", line)
        if not match or match.group(1).lower() in packages:
            raise BoundaryError("dependency lock is not exact, hashed, and duplicate-free")
        packages.add(match.group(1).lower())
    if len(packages) != 23 or "huggingface_hub" not in packages:
        raise BoundaryError("publisher dependency lock is not the reviewed 23-package closure")
    try:
        module = ast.parse(publisher)
    except SyntaxError as error:
        raise BoundaryError("publisher script is malformed") from error
    allowed = set(sys.stdlib_module_names) | {"huggingface_hub", "__future__"}
    imported = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    if imported - allowed:
        raise BoundaryError(f"publisher imports repository or unapproved modules: {sorted(imported - allowed)}")
    _identities(repository, contract, blobs)


def verify_candidate(api: GitHubAPI, repository: str, head_sha: str, entry: dict) -> dict:
    if entry["state"] != "ACTIVE":
        raise BoundaryError(f"release boundary is PENDING and cannot authorize {repository}")
    entries = _tree(api, repository, head_sha)
    expected_workflows = set(entry["workflow_files"])
    actual_workflows = {path for path, row in entries.items() if row.get("type") == "blob" and path.startswith(".github/workflows/")}
    if actual_workflows != expected_workflows:
        raise BoundaryError(f"workflow path set differs: expected={sorted(expected_workflows)} actual={sorted(actual_workflows)}")
    closure = set(entry["secret_execution_files"])
    for root in entry["publisher_contract"]["protected_execution_roots"]:
        actual_root = {path for path, row in entries.items() if row.get("type") == "blob" and path.startswith(root + "/")}
        expected_root = {path for path in closure if path.startswith(root + "/")}
        if actual_root != expected_root:
            raise BoundaryError(f"protected execution path set differs under {root}")
    required = expected_workflows | closure | set(entry["mutable_public_assets"])
    if required - set(entries):
        raise BoundaryError(f"required candidate paths are missing: {sorted(required - set(entries))}")
    blobs = {}
    for path in sorted(expected_workflows | closure):
        row = entries[path]
        if row.get("type") != "blob" or row.get("mode") not in REGULAR_MODES:
            raise BoundaryError(f"protected path is not a regular blob: {path}")
        data = _blob(api, repository, row)
        expected = entry["workflow_files"].get(path, entry["secret_execution_files"].get(path))
        if hashlib.sha256(data).hexdigest() != expected:
            raise BoundaryError(f"protected blob digest differs: {path}")
        blobs[path] = data
    for path in entry["mutable_public_assets"]:
        row = entries[path]
        if row.get("type") != "blob" or row.get("mode") not in REGULAR_MODES:
            raise BoundaryError(f"mutable public asset is not a regular blob: {path}")
    _publisher_contract(repository, entry, blobs)
    return {"status": "AUTHORIZED_FOR_MERGE", "repository": repository, "repository_id": entry["repository_id"], "candidate_sha": head_sha, "manifest_evidence_sha": entry["observed_candidate_sha"], "workflow_files": sorted(expected_workflows), "secret_execution_files": sorted(closure), "publication_proved": False}


def enforce(manifest: dict, event: dict, api: GitHubAPI) -> dict:
    repository = os.environ.get("EVENT_REPOSITORY", "")
    try:
        repository_id = int(os.environ.get("EVENT_REPOSITORY_ID", ""))
    except ValueError as error:
        raise BoundaryError("EVENT_REPOSITORY_ID is malformed") from error
    if repository not in TARGET_IDS or TARGET_IDS[repository] != repository_id:
        raise BoundaryError("event repository is outside the exact allowlist")
    entry = manifest["targets"][repository]
    if entry["state"] != "ACTIVE":
        raise BoundaryError(f"release boundary is PENDING and cannot authorize {repository}")
    _repository_identity(api, repository, repository_id)
    head_sha, binding = _event_binding(api, event, repository, repository_id)
    if _exact_sha(os.environ.get("EVENT_HEAD_SHA"), "EVENT_HEAD_SHA") != head_sha:
        raise BoundaryError("workflow expression and authoritative event head differ")
    result = verify_candidate(api, repository, head_sha, entry)
    if binding[0] == "pull_request":
        current = api.get(f"/repos/{repository}/pulls/{binding[1]}")
        if _pull_binding(current, repository, repository_id, int(binding[1])) != (binding[2], binding[3]):
            raise BoundaryError("pull request metadata drifted after candidate verification")
    elif _ref_sha(api, repository, str(binding[1])) != binding[2] or _ref_sha(api, repository, str(binding[3])) != binding[4]:
        raise BoundaryError("merge-group refs drifted after candidate verification")
    result["event"] = binding[0]
    return result


def verify_manifest_target(manifest: dict, repository: str, head_sha: str, api: GitHubAPI) -> dict:
    if repository not in TARGET_IDS:
        raise BoundaryError("verification target is outside the exact allowlist")
    entry = manifest["targets"][repository]
    if entry["state"] != "ACTIVE" or entry["observed_candidate_sha"] != head_sha:
        raise BoundaryError("verification SHA is not the active manifest evidence SHA")
    _repository_identity(api, repository, entry["repository_id"])
    result = verify_candidate(api, repository, head_sha, entry)
    result["status"] = "MANIFEST_TARGET_VERIFIED"
    return result


def verify_all_active(manifest: dict, api: GitHubAPI) -> dict:
    active = [
        (repository, entry)
        for repository, entry in sorted(manifest["targets"].items())
        if entry["state"] == "ACTIVE"
    ]
    if not active:
        raise BoundaryError("no ACTIVE manifest targets exist; final heads are not authorized")
    pending = sorted(
        repository
        for repository, entry in manifest["targets"].items()
        if entry["state"] == "PENDING"
    )
    return {
        "status": (
            "MANIFEST_INCOMPLETE_PENDING_TARGETS"
            if pending
            else "ALL_ACTIVE_MANIFEST_TARGETS_VERIFIED"
        ),
        "targets": [
            verify_manifest_target(manifest, repository, entry["observed_candidate_sha"], api)
            for repository, entry in active
        ],
        "pending_targets": pending,
        "authorization_complete": not pending,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--event", type=Path)
    parser.add_argument("--validate-manifest-only", action="store_true")
    parser.add_argument("--verify-target")
    parser.add_argument("--head-sha")
    parser.add_argument("--verify-all-active", action="store_true")
    args = parser.parse_args()
    modes = sum((bool(args.event), args.validate_manifest_only, bool(args.verify_target), args.verify_all_active))
    if modes != 1:
        raise BoundaryError("select exactly one enforcement, manifest, or target verification mode")
    manifest = load_manifest(args.manifest)
    exit_code = 0
    if args.validate_manifest_only:
        result = {"status": "MANIFEST_STRUCTURALLY_VALID", "active_targets": sorted(name for name, value in manifest["targets"].items() if value["state"] == "ACTIVE"), "pending_targets": sorted(name for name, value in manifest["targets"].items() if value["state"] == "PENDING")}
    else:
        api = GitHubAPI(os.environ.get("GITHUB_TOKEN", ""))
        if args.verify_target:
            result = verify_manifest_target(manifest, args.verify_target, _exact_sha(args.head_sha, "verification head"), api)
        elif args.verify_all_active:
            result = verify_all_active(manifest, api)
            if not result["authorization_complete"]:
                exit_code = 1
        else:
            try:
                event = json.loads(args.event.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise BoundaryError("event payload is unavailable or malformed") from error
            if not isinstance(event, dict):
                raise BoundaryError("event payload must be an object")
            result = enforce(manifest, event, api)
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FAIL-CLOSED: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
