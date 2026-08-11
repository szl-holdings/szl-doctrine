#!/usr/bin/env python3
"""Fail-closed external release authorization without target checkout/execution."""
from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request

import yaml


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
NATIVE_GOVERNANCE_TOKEN = "${{ github.token }}"
STATIC_TOP_PERMISSIONS = frozenset({("contents", "read")})
STATIC_AUTHORIZATION_PERMISSIONS = frozenset(
    {
        ("actions", "read"),
        ("checks", "read"),
        ("contents", "read"),
        ("pull-requests", "read"),
    }
)
STATIC_PUBLISHER_PERMISSIONS = frozenset()
STATIC_ATTESTATION_PERMISSIONS = frozenset(
    {("attestations", "write"), ("contents", "read"), ("id-token", "write")}
)
STATIC_JOB_IDS = frozenset(
    {"validate", "dco", "authorize", "deploy", "measure", "attest"}
)
HF_SECRET = "${{ secrets.HF_TOKEN }}"
UPLOAD_ARTIFACT = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD_ARTIFACT = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
ATTEST_PROVENANCE = "actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32"
HARDEN_RUNNER = "step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
LEGACY_GOVERNANCE_CREDENTIAL_MARKERS = (
    "actions/create-github-app-token@",
    "QILLQAQ_CLIENT_ID",
    "QILLQAQ_PRIVATE_KEY",
    "permission-administration:",
    "permission-actions:",
    "permission-contents:",
    "steps.governance-token.outputs.token",
    "secrets.GITHUB_TOKEN",
    "secrets['GITHUB_TOKEN']",
    'secrets["GITHUB_TOKEN"]',
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


class _StrictWorkflowLoader(yaml.SafeLoader):
    """YAML loader with GitHub-style booleans and duplicate-key rejection."""


_StrictWorkflowLoader.yaml_implicit_resolvers = copy.deepcopy(
    yaml.SafeLoader.yaml_implicit_resolvers
)
for initial, resolvers in tuple(
    _StrictWorkflowLoader.yaml_implicit_resolvers.items()
):
    _StrictWorkflowLoader.yaml_implicit_resolvers[initial] = [
        (tag, expression)
        for tag, expression in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
_StrictWorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"),
    list("tTfF"),
)


def _construct_strict_mapping(
    loader: _StrictWorkflowLoader, node: yaml.MappingNode, deep: bool = False
) -> dict:
    if not isinstance(node, yaml.MappingNode):
        raise BoundaryError("publisher workflow mapping is malformed")
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key == "<<":
            raise BoundaryError("publisher workflow contains a non-string or merged YAML key")
        if key in result:
            raise BoundaryError(f"publisher workflow contains a duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictWorkflowLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_strict_mapping,
)


def _workflow_document(workflow: str) -> dict:
    try:
        tokens = yaml.scan(workflow, Loader=_StrictWorkflowLoader)
        forbidden = (
            yaml.tokens.AliasToken,
            yaml.tokens.AnchorToken,
            yaml.tokens.TagToken,
        )
        if any(isinstance(token, forbidden) for token in tokens):
            raise BoundaryError("publisher workflow YAML aliases, anchors, and tags are forbidden")
        document = yaml.load(workflow, Loader=_StrictWorkflowLoader)
    except BoundaryError:
        raise
    except yaml.YAMLError as error:
        raise BoundaryError("publisher workflow YAML is malformed") from error
    if not isinstance(document, dict):
        raise BoundaryError("publisher workflow document is not a mapping")
    return document


def _mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise BoundaryError(f"{label} must be a YAML mapping")
    return value


def _permissions(value: object, label: str) -> frozenset[tuple[str, str]]:
    mapping = _mapping(value, label)
    if any(
        not isinstance(key, str) or not isinstance(access, str)
        for key, access in mapping.items()
    ):
        raise BoundaryError(f"{label} permissions are malformed")
    return frozenset(mapping.items())


def _steps(job: dict, label: str) -> list[dict]:
    value = job.get("steps")
    if not isinstance(value, list) or not value:
        raise BoundaryError(f"{label} steps are missing")
    if any(not isinstance(step, dict) for step in value):
        raise BoundaryError(f"{label} contains a malformed step")
    names = [step.get("name") for step in value if "name" in step]
    if any(not isinstance(name, str) or not name for name in names):
        raise BoundaryError(f"{label} contains a malformed step name")
    if len(names) != len(set(names)):
        raise BoundaryError(f"{label} contains duplicate step names")
    return value


def _named_step(job: dict, name: str) -> dict:
    matches = [
        step
        for step in _steps(job, f"job {job.get('name')}")
        if step.get("name") == name
    ]
    if len(matches) != 1:
        raise BoundaryError(f"publisher workflow is missing exact step: {name}")
    return matches[0]


def _logical_shell_commands(value: object, label: str) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        raise BoundaryError(f"{label} has no executable shell body")
    commands: list[str] = []
    pending = ""
    for raw in value.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending = f"{pending} {line}".strip() if pending else line
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        commands.append(pending)
        pending = ""
    if pending:
        raise BoundaryError(f"{label} contains a dangling shell continuation")
    return commands


def _command_tokens(command: str, label: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError as error:
        raise BoundaryError(f"{label} shell command is malformed") from error


def _require_artifact_step(
    job: dict, name: str, action: str, expected_with: dict[str, str]
) -> None:
    step = _named_step(job, name)
    if step.get("uses") != action:
        raise BoundaryError(f"{name} does not use the exact pinned artifact action")
    inputs = _mapping(step.get("with"), f"{name} inputs")
    if inputs != expected_with:
        raise BoundaryError(f"{name} does not bind the exact artifact input map")


def _walk_scalars(value: object, path: tuple[object, ...] = ()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_scalars(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_scalars(child, path + (index,))
    else:
        yield path, value


HARDENED_STATIC_WORKFLOW_SHA256 = (
    "dba23a071a38d1c098e3fa0542a7f234cb655c1e749dd8fcc24ce3f9d6f36a54"
)
HARDENED_STATIC_SHELL_CONTRACT_SHA256 = (
    "11c6d14a729640a27770f9adfbad0ba38b4cc085dd996b1fc23ca6a22d0171ad"
)
LEGACY_STATIC_SHELL_CONTRACT_SHA256 = {
    "4120d1a9d147bcf85ea9920dd884ef9c440f583163759beaa1ad7a6afbf82254": "08564ae2b8f8189431c606f31132589cd4ee994b5cd9c27a33b3467d8c0e2cd0",
    "cbb90b7cf33d83b02ef7837c583852f01b1af1d9c165a54dbcbbaeb2349ec95e": "802d7628504781fdd07de8128b578937578c7bddba85a3e4cb42ce838b6eb96a",
}


def _workflow_shell_contract_sha256(document: dict) -> str:
    rows: list[dict[str, object]] = []
    jobs = _mapping(document.get("jobs"), "publisher workflow jobs")
    for job_id, value in jobs.items():
        job = _mapping(value, f"publisher workflow job {job_id}")
        for step in _steps(job, f"publisher workflow job {job_id}"):
            if "run" in step:
                rows.append(
                    {
                        "job": job_id,
                        "name": step.get("name"),
                        "env": step.get("env", {}),
                        "run": step["run"],
                    }
                )
    payload = (
        json.dumps(
            rows,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _workflow_governance_contract(workflow: str) -> None:
    document = _workflow_document(workflow)
    workflow_sha256 = hashlib.sha256(workflow.encode("utf-8")).hexdigest()
    shell_contract_sha256 = _workflow_shell_contract_sha256(document)
    if workflow_sha256 == HARDENED_STATIC_WORKFLOW_SHA256:
        if shell_contract_sha256 != HARDENED_STATIC_SHELL_CONTRACT_SHA256:
            raise BoundaryError(
                "hardened publisher workflow shell step bodies and environments are not exact"
            )
        return
    expected_shell_contract_sha256 = LEGACY_STATIC_SHELL_CONTRACT_SHA256.get(
        workflow_sha256
    )
    if expected_shell_contract_sha256 is None:
        raise BoundaryError(
            f"publisher workflow shell step bodies are not covered: {workflow_sha256}"
        )
    if shell_contract_sha256 != expected_shell_contract_sha256:
        raise BoundaryError(
            "publisher workflow shell step bodies and environments are not exact"
        )
    if set(document) != {"name", "on", "permissions", "concurrency", "jobs"}:
        raise BoundaryError("publisher workflow top-level field allowlist is not exact")
    if document.get("name") != "Governed static Space release":
        raise BoundaryError("publisher workflow identity is not exact")
    trigger = _mapping(document.get("on"), "publisher workflow trigger")
    if trigger != {
        "pull_request": {
            "types": ["opened", "synchronize", "reopened", "edited", "ready_for_review"]
        },
        "push": {"branches": ["main"]},
    }:
        raise BoundaryError("publisher workflow trigger is not exact")
    concurrency = _mapping(document.get("concurrency"), "publisher workflow concurrency")
    if concurrency != {
        "group": (
            "hf-static-space-${{ github.repository }}-"
            "${{ github.event_name == 'pull_request' && format('pr-{0}', "
            "github.event.pull_request.number) || 'production' }}"
        ),
        "cancel-in-progress": False,
    }:
        raise BoundaryError("publisher workflow concurrency is not fail-closed")
    if _permissions(document.get("permissions"), "top-level") != STATIC_TOP_PERMISSIONS:
        raise BoundaryError("publisher workflow top-level permissions are not exact")

    jobs = _mapping(document.get("jobs"), "publisher workflow jobs")
    if set(jobs) != STATIC_JOB_IDS or any(
        not isinstance(job, dict) for job in jobs.values()
    ):
        raise BoundaryError("publisher workflow job allowlist is not exact")
    validate, dco = jobs["validate"], jobs["dco"]
    authorize, deploy = jobs["authorize"], jobs["deploy"]
    measure, attest = jobs["measure"], jobs["attest"]
    expected_job_keys = {
        "validate": {"name", "runs-on", "timeout-minutes", "steps"},
        "dco": {"name", "runs-on", "timeout-minutes", "steps"},
        "authorize": {
            "name", "if", "needs", "permissions", "runs-on",
            "timeout-minutes", "outputs", "steps",
        },
        "deploy": {
            "name", "if", "needs", "permissions", "runs-on",
            "timeout-minutes", "env", "outputs", "steps",
        },
        "measure": {
            "name", "if", "needs", "permissions", "runs-on",
            "timeout-minutes", "outputs", "steps",
        },
        "attest": {
            "name", "if", "needs", "permissions", "runs-on",
            "timeout-minutes", "env", "steps",
        },
    }
    expected_job_names = {
        "validate": "validate-static-space",
        "dco": "DCO",
        "authorize": "authorize-exact-governed-merge",
        "deploy": "publish-exact-protected-main",
        "measure": "measure-exact-publication",
        "attest": "attest-exact-publication",
    }
    expected_timeouts = {
        "validate": 10, "dco": 10, "authorize": 10,
        "deploy": 10, "measure": 20, "attest": 10,
    }
    for job_id, job in jobs.items():
        if set(job) != expected_job_keys[job_id]:
            raise BoundaryError(f"publisher workflow job fields are not exact: {job_id}")
        if (
            job.get("name") != expected_job_names[job_id]
            or job.get("runs-on") != "ubuntu-latest"
            or job.get("timeout-minutes") != expected_timeouts[job_id]
        ):
            raise BoundaryError(f"publisher workflow job execution profile is not exact: {job_id}")
    if "permissions" in validate or "permissions" in dco:
        raise BoundaryError("validation jobs must inherit the exact read-only profile")
    if _permissions(authorize.get("permissions"), "authorization job") != STATIC_AUTHORIZATION_PERMISSIONS:
        raise BoundaryError("authorization job permissions are not exact")
    if _permissions(deploy.get("permissions"), "publisher job") != STATIC_PUBLISHER_PERMISSIONS:
        raise BoundaryError("publisher job permissions are not credential-free")
    if _permissions(measure.get("permissions"), "measurement job") != STATIC_AUTHORIZATION_PERMISSIONS:
        raise BoundaryError("measurement job permissions are not exact and read-only")
    if _permissions(attest.get("permissions"), "attestation job") != STATIC_ATTESTATION_PERMISSIONS:
        raise BoundaryError("attestation job permissions are not exact")

    if authorize.get("if") != "github.event_name == 'push' && github.ref == 'refs/heads/main'":
        raise BoundaryError("authorization job is not protected-main-push only")
    if deploy.get("if") != (
        "always() && needs.authorize.result == 'success' "
        "&& needs.authorize.outputs.authorization-outcome == 'success' "
        "&& needs.authorize.outputs.authorization-evidence-outcome == 'success' "
        "&& needs.authorize.outputs.publisher-digests-outcome == 'success' "
        "&& needs.authorize.outputs.publisher-input-evidence-outcome == 'success'"
    ):
        raise BoundaryError("publisher job is not bound to exact authorization outputs")
    if measure.get("if") != (
        "always() && needs.authorize.result == 'success' "
        "&& needs.deploy.outputs.publisher-freshness-outcome == 'success' "
        "&& needs.deploy.outputs.publish-outcome == 'success' "
        "&& needs.deploy.outputs.publisher-evidence-outcome == 'success'"
    ):
        raise BoundaryError("measurement job is not bound to exact publisher outputs")
    if attest.get("if") != (
        "always() && github.event_name == 'push' && github.ref == 'refs/heads/main'"
    ):
        raise BoundaryError("attestation job is not protected-main-push only")
    if authorize.get("needs") != ["validate", "dco"]:
        raise BoundaryError("authorization job dependency chain is wrong")
    if deploy.get("needs") != ["authorize"] or measure.get("needs") != ["authorize", "deploy"]:
        raise BoundaryError("publisher or measurement job dependency chain is wrong")
    if attest.get("needs") != ["authorize", "deploy", "measure"]:
        raise BoundaryError("attestation job dependency chain is wrong")

    authorize_outputs = {
        "authorization-outcome": "${{ steps.authorization.outcome }}",
        "authorization-evidence-outcome": "${{ steps.authorization-evidence.outcome }}",
        "bundle-outcome": "${{ steps.bundle.outcome }}",
        "publisher-input-outcome": "${{ steps.publisher-input.outcome }}",
        "publisher-digests-outcome": "${{ steps.publisher-digests.outcome }}",
        "publisher-input-evidence-outcome": "${{ steps.publisher-input-evidence.outcome }}",
        "publisher_script_sha256": "${{ steps.publisher-digests.outputs.publisher_script_sha256 }}",
        "publisher_lock_sha256": "${{ steps.publisher-digests.outputs.publisher_lock_sha256 }}",
        "publisher_config_sha256": "${{ steps.publisher-digests.outputs.publisher_config_sha256 }}",
        "authorization_sha256": "${{ steps.publisher-digests.outputs.authorization_sha256 }}",
        "bundle_manifest_sha256": "${{ steps.publisher-digests.outputs.bundle_manifest_sha256 }}",
    }
    deploy_outputs = {
        "publisher-input-outcome": "${{ steps.publisher-input.outcome }}",
        "publisher-rebind-outcome": "${{ steps.publisher-rebind.outcome }}",
        "publisher-environment-outcome": "${{ steps.publisher-environment.outcome }}",
        "publisher-freshness-outcome": "${{ steps.publisher-freshness.outcome }}",
        "publish-outcome": "${{ steps.publish.outcome }}",
        "publisher-evidence-outcome": "${{ steps.publisher-evidence.outcome }}",
    }
    measure_outputs = {
        "measurement-hardening-outcome": "${{ steps.measurement-hardening.outcome }}",
        "measurement-input-outcome": "${{ steps.measurement-input.outcome }}",
        "measurement-rebind-outcome": "${{ steps.measurement-rebind.outcome }}",
        "measurement-publisher-evidence-outcome": "${{ steps.measurement-publisher-evidence.outcome }}",
        "measurement-environment-outcome": "${{ steps.measurement-environment.outcome }}",
        "measurement-outcome": "${{ steps.measurement.outcome }}",
        "measurement-evidence-outcome": "${{ steps.measurement-evidence.outcome }}",
    }
    authorize_has_artifact_attempt = "artifact-run-attempt" in _mapping(
        authorize.get("outputs"), "authorize outputs"
    )
    if authorize_has_artifact_attempt:
        authorize_outputs["artifact-run-attempt"] = "${{ github.run_attempt }}"
    deploy_has_artifact_attempt = "artifact-run-attempt" in _mapping(
        deploy.get("outputs"), "deploy outputs"
    )
    if deploy_has_artifact_attempt:
        deploy_outputs["artifact-run-attempt"] = "${{ github.run_attempt }}"
    measure_has_artifact_attempt = "artifact-run-attempt" in _mapping(
        measure.get("outputs"), "measure outputs"
    )
    if measure_has_artifact_attempt:
        measure_outputs["artifact-run-attempt"] = "${{ github.run_attempt }}"

    expected_outputs = {
        "authorize": authorize_outputs,
        "deploy": deploy_outputs,
        "measure": measure_outputs,
    }
    for job_id, expected in expected_outputs.items():
        if _mapping(jobs[job_id].get("outputs"), f"{job_id} outputs") != expected:
            raise BoundaryError(f"publisher workflow output map is not exact: {job_id}")
    if deploy.get("env") != {
        "PUBLISHER_PYTHON": "python",
        "SOURCE_SHA": "${{ github.sha }}",
    } or attest.get("env") != {"SOURCE_SHA": "${{ github.sha }}"}:
        raise BoundaryError("publisher or attestation job environment is not exact")

    canonical_steps = {
        "validate": [
            "Harden runner", "Checkout exact event head", "Set up Python",
            "Verify exact checkout and release contracts",
            "Validate exact-head pull-request body evidence",
        ],
        "dco": [
            "Harden runner", "Checkout exact event head with history",
            "Set up exact Python", "Validate every exact-range commit DCO trailer",
        ],
        "authorize": [
            "Harden runner", "Checkout exact protected-main event", "Set up exact Python",
            "Authorize the exact governed merge without HF credentials",
            "Build and validate exact source-bound publisher input",
            "Stage immutable publisher input",
            "Bind five exact publisher inputs outside the artifact channel",
            "Upload exact publisher input",
            "Upload governed-merge authorization evidence",
            "Require exact governed authorization",
        ],
        "deploy": [
            "Harden runner", "Download exact authorized publisher input",
            "Rebind five publisher inputs before interpretation or credentials",
            "Set up exact Python",
            "Install pinned Hugging Face client without repository credentials",
            "Classify publisher-environment failure before credential materialization",
            "Reconfirm public main at exact source revision without credentials",
            "Classify public-main freshness failure before mutation",
            "Publish exact bundle with only the Hugging Face credential",
            "Upload publisher outcome before any OIDC privilege exists",
            "Require exact publisher success",
        ],
        "measure": [
            "Harden runner", "Download exact authorized publisher input",
            "Rebind five measurement inputs before interpretation or credentials",
            "Download exact publisher outcome", "Set up exact Python",
            "Measure public bytes and reauthorize current main without HF credentials",
            "Upload exact public measurement before OIDC",
            "Require exact public measurement",
        ],
        "attest": [
            "Harden runner", "Checkout exact protected-main evidence synthesizer",
            "Set up exact Python", "Download exact publisher outcome",
            "Download exact public measurement",
            "Attest canonical exact-revision measurement with GitHub OIDC",
            "Synthesize final receipt or exact workflow-stage failure",
            "Upload terminal governed evidence",
            "Synthesize terminal artifact-upload failure",
            "Upload terminal failure evidence", "Require terminal governed success",
        ],
    }
    step_keys: dict[tuple[str, str], frozenset[str]] = {}
    def allow(job_id: str, names: list[str], *keys: str) -> None:
        for step_name in names:
            step_keys[(job_id, step_name)] = frozenset(("name", *keys))

    allow("validate", ["Harden runner", "Checkout exact event head", "Set up Python"], "uses", "with")
    allow("validate", ["Verify exact checkout and release contracts"], "env", "run")
    allow("validate", ["Validate exact-head pull-request body evidence"], "if", "env", "run")
    allow("dco", ["Harden runner", "Checkout exact event head with history", "Set up exact Python"], "uses", "with")
    allow("dco", ["Validate every exact-range commit DCO trailer"], "env", "run")
    allow("authorize", ["Harden runner", "Checkout exact protected-main event", "Set up exact Python"], "uses", "with")
    allow("authorize", ["Authorize the exact governed merge without HF credentials"], "id", "continue-on-error", "env", "run")
    allow("authorize", ["Build and validate exact source-bound publisher input", "Bind five exact publisher inputs outside the artifact channel"], "id", "if", "continue-on-error", "env", "run")
    allow("authorize", ["Stage immutable publisher input"], "id", "if", "continue-on-error", "run")
    allow("authorize", ["Upload exact publisher input", "Upload governed-merge authorization evidence"], "id", "if", "continue-on-error", "uses", "with")
    allow("authorize", ["Require exact governed authorization"], "if", "run")
    allow("deploy", ["Harden runner"], "uses", "with")
    allow("deploy", ["Download exact authorized publisher input"], "id", "continue-on-error", "uses", "with")
    allow("deploy", ["Rebind five publisher inputs before interpretation or credentials", "Install pinned Hugging Face client without repository credentials", "Publish exact bundle with only the Hugging Face credential"], "id", "if", "continue-on-error", "env", "run")
    allow("deploy", ["Reconfirm public main at exact source revision without credentials"], "id", "if", "continue-on-error", "env", "run")
    allow("deploy", ["Classify public-main freshness failure before mutation"], "if", "run")
    allow("deploy", ["Set up exact Python"], "if", "uses", "with")
    allow("deploy", ["Classify publisher-environment failure before credential materialization", "Require exact publisher success"], "if", "run")
    allow("deploy", ["Upload publisher outcome before any OIDC privilege exists"], "id", "if", "continue-on-error", "uses", "with")
    allow("measure", ["Harden runner"], "id", "continue-on-error", "uses", "with")
    allow("measure", ["Download exact authorized publisher input"], "id", "if", "continue-on-error", "uses", "with")
    allow("measure", ["Rebind five measurement inputs before interpretation or credentials"], "id", "if", "continue-on-error", "env", "run")
    allow("measure", ["Download exact publisher outcome"], "id", "if", "continue-on-error", "uses", "with")
    allow("measure", ["Set up exact Python"], "id", "if", "continue-on-error", "uses", "with")
    allow("measure", ["Measure public bytes and reauthorize current main without HF credentials"], "id", "if", "continue-on-error", "env", "run")
    allow("measure", ["Upload exact public measurement before OIDC"], "id", "if", "continue-on-error", "uses", "with")
    allow("measure", ["Require exact public measurement"], "if", "run")
    allow("attest", ["Harden runner"], "continue-on-error", "env", "id", "uses", "with")
    allow("attest", ["Checkout exact protected-main evidence synthesizer", "Set up exact Python"], "continue-on-error", "env", "id", "if", "uses", "with")
    allow("attest", ["Download exact publisher outcome", "Download exact public measurement"], "continue-on-error", "env", "id", "uses", "with")
    allow("attest", ["Attest canonical exact-revision measurement with GitHub OIDC"], "id", "if", "continue-on-error", "uses", "with")
    allow("attest", ["Synthesize final receipt or exact workflow-stage failure"], "continue-on-error", "env", "id", "if", "run")
    allow("attest", ["Synthesize terminal artifact-upload failure", "Require terminal governed success"], "env", "if", "run")
    allow("attest", ["Upload terminal governed evidence"], "continue-on-error", "env", "id", "if", "uses", "with")
    allow("attest", ["Upload terminal failure evidence"], "continue-on-error", "env", "if", "uses", "with")

    expected_ids = {
        ("authorize", "Authorize the exact governed merge without HF credentials"): "authorization",
        ("authorize", "Build and validate exact source-bound publisher input"): "bundle",
        ("authorize", "Stage immutable publisher input"): "publisher-input",
        ("authorize", "Bind five exact publisher inputs outside the artifact channel"): "publisher-digests",
        ("authorize", "Upload exact publisher input"): "publisher-input-evidence",
        ("authorize", "Upload governed-merge authorization evidence"): "authorization-evidence",
        ("deploy", "Download exact authorized publisher input"): "publisher-input",
        ("deploy", "Rebind five publisher inputs before interpretation or credentials"): "publisher-rebind",
        ("deploy", "Install pinned Hugging Face client without repository credentials"): "publisher-environment",
        ("deploy", "Reconfirm public main at exact source revision without credentials"): "publisher-freshness",
        ("deploy", "Publish exact bundle with only the Hugging Face credential"): "publish",
        ("deploy", "Upload publisher outcome before any OIDC privilege exists"): "publisher-evidence",
        ("measure", "Harden runner"): "measurement-hardening",
        ("measure", "Download exact authorized publisher input"): "measurement-input",
        ("measure", "Rebind five measurement inputs before interpretation or credentials"): "measurement-rebind",
        ("measure", "Download exact publisher outcome"): "measurement-publisher-evidence",
        ("measure", "Set up exact Python"): "measurement-environment",
        ("measure", "Measure public bytes and reauthorize current main without HF credentials"): "measurement",
        ("measure", "Upload exact public measurement before OIDC"): "measurement-evidence",
        ("attest", "Download exact publisher outcome"): "publisher-evidence-download",
        ("attest", "Download exact public measurement"): "measurement-evidence-download",
        ("attest", "Attest canonical exact-revision measurement with GitHub OIDC"): "oidc",
        ("attest", "Harden runner"): "attestation-hardening",
        ("attest", "Checkout exact protected-main evidence synthesizer"): "attestation-checkout",
        ("attest", "Set up exact Python"): "attestation-environment",
        ("attest", "Synthesize final receipt or exact workflow-stage failure"): "workflow-outcome",
        ("attest", "Upload terminal governed evidence"): "terminal-evidence",
    }
    expected_ifs = {
        ("validate", "Validate exact-head pull-request body evidence"): "github.event_name == 'pull_request'",
        ("authorize", "Build and validate exact source-bound publisher input"): "steps.authorization.outcome == 'success'",
        ("authorize", "Stage immutable publisher input"): "steps.authorization.outcome == 'success' && steps.bundle.outcome == 'success'",
        ("authorize", "Bind five exact publisher inputs outside the artifact channel"): "steps.publisher-input.outcome == 'success'",
        ("authorize", "Upload exact publisher input"): "steps.publisher-input.outcome == 'success' && steps.publisher-digests.outcome == 'success'",
        ("authorize", "Upload governed-merge authorization evidence"): "always()",
        ("authorize", "Require exact governed authorization"): "always()",
        ("attest", "Checkout exact protected-main evidence synthesizer"): "steps.attestation-hardening.outcome == 'success'",
        ("attest", "Set up exact Python"): "steps.attestation-checkout.outcome == 'success'",
        ("deploy", "Rebind five publisher inputs before interpretation or credentials"): "steps.publisher-input.outcome == 'success'",
        ("deploy", "Reconfirm public main at exact source revision without credentials"): "steps.publisher-rebind.outcome == 'success' && steps.publisher-environment.outcome == 'success'",
        ("deploy", "Set up exact Python"): "steps.publisher-rebind.outcome == 'success'",
        ("deploy", "Install pinned Hugging Face client without repository credentials"): "steps.publisher-rebind.outcome == 'success'",
        ("deploy", "Classify publisher-environment failure before credential materialization"): "always() && steps.publisher-rebind.outcome == 'success' && steps.publisher-environment.outcome != 'success'",
        ("deploy", "Classify public-main freshness failure before mutation"): "always() && steps.publisher-rebind.outcome == 'success' && steps.publisher-environment.outcome == 'success' && steps.publisher-freshness.outcome != 'success'",
        ("deploy", "Publish exact bundle with only the Hugging Face credential"): "steps.publisher-rebind.outcome == 'success' && steps.publisher-environment.outcome == 'success' && steps.publisher-freshness.outcome == 'success'",
        ("deploy", "Upload publisher outcome before any OIDC privilege exists"): "always()",
        ("deploy", "Require exact publisher success"): "always()",
        ("measure", "Download exact authorized publisher input"): "steps.measurement-hardening.outcome == 'success'",
        ("measure", "Rebind five measurement inputs before interpretation or credentials"): "steps.measurement-input.outcome == 'success'",
        ("measure", "Download exact publisher outcome"): "steps.measurement-rebind.outcome == 'success'",
        ("measure", "Set up exact Python"): "steps.measurement-publisher-evidence.outcome == 'success'",
        ("measure", "Measure public bytes and reauthorize current main without HF credentials"): "steps.measurement-environment.outcome == 'success'",
        ("measure", "Upload exact public measurement before OIDC"): "always()",
        ("measure", "Require exact public measurement"): "always()",
        ("attest", "Attest canonical exact-revision measurement with GitHub OIDC"): "steps.attestation-hardening.outcome == 'success' && steps.attestation-checkout.outcome == 'success' && steps.attestation-environment.outcome == 'success' && needs.measure.outputs.measurement-hardening-outcome == 'success' && needs.measure.outputs.measurement-input-outcome == 'success' && needs.measure.outputs.measurement-rebind-outcome == 'success' && needs.measure.outputs.measurement-publisher-evidence-outcome == 'success' && needs.measure.outputs.measurement-environment-outcome == 'success' && needs.measure.outputs.measurement-outcome == 'success' && needs.measure.outputs.measurement-evidence-outcome == 'success' && steps.publisher-evidence-download.outcome == 'success' && steps.measurement-evidence-download.outcome == 'success'",
        ("attest", "Synthesize final receipt or exact workflow-stage failure"): "always()",
        ("attest", "Upload terminal governed evidence"): "always()",
        ("attest", "Synthesize terminal artifact-upload failure"): "always() && steps.terminal-evidence.outcome != 'success'",
        ("attest", "Upload terminal failure evidence"): "always() && steps.terminal-evidence.outcome != 'success'",
        ("attest", "Require terminal governed success"): "always()",
    }

    all_steps: list[tuple[str, dict]] = []
    for job_id, job in jobs.items():
        steps = _steps(job, f"job {job_id}")
        names = [step.get("name") for step in steps]
        if names != canonical_steps[job_id]:
            raise BoundaryError(f"publisher workflow step sequence is not exact: {job_id}")
        for step in steps:
            key = (job_id, step["name"])
            if frozenset(step) != step_keys[key]:
                raise BoundaryError(f"publisher workflow step fields are not exact: {job_id}/{step['name']}")
            if "id" in step and step["id"] != expected_ids.get(key):
                raise BoundaryError(f"publisher workflow step id is not exact: {job_id}/{step['name']}")
            if "if" in step and step["if"] != expected_ifs.get(key):
                raise BoundaryError(f"publisher workflow step condition is not exact: {job_id}/{step['name']}")
            if "continue-on-error" in step and step["continue-on-error"] is not True:
                raise BoundaryError(f"publisher workflow continuation policy is not exact: {job_id}/{step['name']}")
            all_steps.append((job_id, step))

    action_specs = {
        ("validate", "Harden runner"): (HARDEN_RUNNER, {"egress-policy": "audit"}),
        ("validate", "Checkout exact event head"): (CHECKOUT, {"ref": "${{ github.event.pull_request.head.sha || github.sha }}", "persist-credentials": False, "fetch-depth": 1}),
        ("validate", "Set up Python"): (SETUP_PYTHON, {"python-version": "3.12.13"}),
        ("dco", "Harden runner"): (HARDEN_RUNNER, {"egress-policy": "audit"}),
        ("dco", "Checkout exact event head with history"): (CHECKOUT, {"ref": "${{ github.event.pull_request.head.sha || github.sha }}", "persist-credentials": False, "fetch-depth": 0}),
        ("dco", "Set up exact Python"): (SETUP_PYTHON, {"python-version": "3.12.13"}),
        ("authorize", "Harden runner"): (HARDEN_RUNNER, {"egress-policy": "audit"}),
        ("authorize", "Checkout exact protected-main event"): (CHECKOUT, {"ref": "${{ github.sha }}", "persist-credentials": False, "fetch-depth": 1}),
        ("authorize", "Set up exact Python"): (SETUP_PYTHON, {"python-version": "3.12.13"}),
        ("authorize", "Upload exact publisher input"): (
            UPLOAD_ARTIFACT,
            {
                "name": "hf-static-space-publisher-input-${{ github.sha }}-${{ github.run_attempt }}",
                "path": "${{ runner.temp }}/publisher-input",
                "if-no-files-found": "error",
                "include-hidden-files": True,
                **({"retention-days": 30} if authorize_has_artifact_attempt else {"retention-days": 1}),
            },
        ),
        ("authorize", "Upload governed-merge authorization evidence"): (UPLOAD_ARTIFACT, {"name": "hf-static-space-authorization-${{ github.sha }}-${{ github.run_attempt }}", "path": "${{ runner.temp }}/governed-merge.json\n${{ runner.temp }}/governed-merge-failure.json\n", "if-no-files-found": "error", "retention-days": 90}),
        ("deploy", "Harden runner"): (HARDEN_RUNNER, {"egress-policy": "audit"}),
        ("deploy", "Download exact authorized publisher input"): (DOWNLOAD_ARTIFACT, {"name": "hf-static-space-publisher-input-${{ github.sha }}-${{ github.run_attempt }}" if not deploy_has_artifact_attempt else "hf-static-space-publisher-input-${{ github.sha }}-${{ needs.authorize.outputs.artifact-run-attempt }}", "path": "${{ runner.temp }}/publisher-input"}),
        ("deploy", "Set up exact Python"): (SETUP_PYTHON, {"python-version": "3.12.13"}),
        ("deploy", "Upload publisher outcome before any OIDC privilege exists"): (UPLOAD_ARTIFACT, {"name": "hf-static-space-publication-${{ github.sha }}-${{ github.run_attempt }}", "path": "${{ runner.temp }}/publication-evidence", "if-no-files-found": "error", "retention-days": 90}),
        ("measure", "Harden runner"): (HARDEN_RUNNER, {"egress-policy": "audit"}),
        ("measure", "Download exact authorized publisher input"): (DOWNLOAD_ARTIFACT, {"name": "hf-static-space-publisher-input-${{ github.sha }}-${{ github.run_attempt }}" if not authorize_has_artifact_attempt else "hf-static-space-publisher-input-${{ github.sha }}-${{ needs.authorize.outputs.artifact-run-attempt }}", "path": "${{ runner.temp }}/publisher-input"}),
        ("measure", "Download exact publisher outcome"): (DOWNLOAD_ARTIFACT, {"name": "hf-static-space-publication-${{ github.sha }}-${{ github.run_attempt }}" if not deploy_has_artifact_attempt else "hf-static-space-publication-${{ github.sha }}-${{ needs.deploy.outputs.artifact-run-attempt }}", "path": "${{ runner.temp }}/publication-evidence"}),
        ("measure", "Set up exact Python"): (SETUP_PYTHON, {"python-version": "3.12.13"}),
        ("measure", "Upload exact public measurement before OIDC"): (UPLOAD_ARTIFACT, {"name": "hf-static-space-measurement-${{ github.sha }}-${{ github.run_attempt }}", "path": "${{ runner.temp }}/measurement-evidence", "if-no-files-found": "error", "retention-days": 90}),
        ("attest", "Harden runner"): (HARDEN_RUNNER, {"egress-policy": "audit"}),
        ("attest", "Checkout exact protected-main evidence synthesizer"): (CHECKOUT, {"ref": "${{ github.sha }}", "persist-credentials": False, "fetch-depth": 1}),
        ("attest", "Set up exact Python"): (SETUP_PYTHON, {"python-version": "3.12.13"}),
        ("attest", "Download exact publisher outcome"): (DOWNLOAD_ARTIFACT, {"name": "hf-static-space-publication-${{ github.sha }}-${{ github.run_attempt }}" if not deploy_has_artifact_attempt else "hf-static-space-publication-${{ github.sha }}-${{ needs.deploy.outputs.artifact-run-attempt }}", "path": "${{ runner.temp }}/publication-evidence"}),
        ("attest", "Download exact public measurement"): (DOWNLOAD_ARTIFACT, {"name": "hf-static-space-measurement-${{ github.sha }}-${{ github.run_attempt }}" if not measure_has_artifact_attempt else "hf-static-space-measurement-${{ github.sha }}-${{ needs.measure.outputs.artifact-run-attempt }}", "path": "${{ runner.temp }}/measurement-evidence"}),
        ("attest", "Attest canonical exact-revision measurement with GitHub OIDC"): (ATTEST_PROVENANCE, {"subject-path": "${{ runner.temp }}/measurement-evidence/hf-live-attestation.json"}),
        ("attest", "Upload terminal governed evidence"): (UPLOAD_ARTIFACT, {"name": "hf-static-space-terminal-evidence-${{ github.sha }}-${{ github.run_attempt }}", "path": "${{ runner.temp }}/publication-evidence\n${{ runner.temp }}/measurement-evidence\n${{ runner.temp }}/terminal-evidence\n", "if-no-files-found": "error", "retention-days": 90}),
        ("attest", "Upload terminal failure evidence"): (UPLOAD_ARTIFACT, {"name": "hf-static-space-terminal-upload-failure-${{ github.sha }}-${{ github.run_attempt }}", "path": "${{ runner.temp }}/terminal-evidence/hf-workflow-stage-failure.json", "if-no-files-found": "error", "retention-days": 90}),
    }
    structured_uses = []
    for job_id, step in all_steps:
        if "uses" not in step:
            continue
        key = (job_id, step["name"])
        if key not in action_specs or (step["uses"], _mapping(step.get("with"), f"{job_id}/{step['name']} inputs")) != action_specs[key]:
            raise BoundaryError(f"publisher workflow action binding is not exact: {job_id}/{step['name']}")
        structured_uses.append(step["uses"])
    raw_uses = ANY_USES.findall(workflow)
    if not structured_uses or sorted(raw_uses) != sorted(structured_uses):
        raise BoundaryError("publisher workflow decoded action inventory differs from source spelling")
    if any(value.startswith("./") or PINNED_USES.fullmatch(value) is None for value in structured_uses):
        raise BoundaryError("publisher workflow contains an unpinned, local, or reusable action")

    guard = _named_step(
        authorize, "Authorize the exact governed merge without HF credentials"
    )
    if guard.get("env") != {
        "GITHUB_TOKEN": NATIVE_GOVERNANCE_TOKEN,
        "SOURCE_SHA": "${{ github.sha }}",
    }:
        raise BoundaryError("authorization step token binding is not exact")
    guard_commands = _logical_shell_commands(guard.get("run"), "authorization step")
    expected_guard = [
        "python",
        "-I",
        "scripts/hf_static_space.py",
        "guard",
        "--source-sha",
        "$SOURCE_SHA",
        "--event",
        "$GITHUB_EVENT_PATH",
        "--output",
        "$RUNNER_TEMP/governed-merge.json",
        "--failure-output",
        "$RUNNER_TEMP/governed-merge-failure.json",
    ]
    if (
        guard_commands[:2]
        != [
            "set -euo pipefail",
            'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"',
        ]
        or len(guard_commands) != 3
        or _command_tokens(guard_commands[2], "authorization step") != expected_guard
    ):
        raise BoundaryError("authorization command is not exact and mandatory")

    mutation = _named_step(
        deploy, "Publish exact bundle with only the Hugging Face credential"
    )
    if mutation.get("env") != {
        "GITHUB_TOKEN": "",
        "GH_TOKEN": "",
        "HF_TOKEN": HF_SECRET,
    }:
        raise BoundaryError("publisher mutation credential boundary is not exact")
    mutation_commands = _logical_shell_commands(mutation.get("run"), "publisher mutation")
    expected_mutation = [
        "/usr/bin/env",
        "-i",
        "HOME=$RUNNER_TEMP/hf-publisher-home",
        "HF_HOME=$RUNNER_TEMP/hf-publisher-cache",
        "XDG_CACHE_HOME=$RUNNER_TEMP/hf-publisher-cache",
        "PATH=$PUBLISHER_VENV/bin:/usr/bin:/bin",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "PYTHONIOENCODING=utf-8",
        "HF_TOKEN=$HF_TOKEN",
        "$PUBLISHER_PYTHON",
        "-I",
        "$RUNNER_TEMP/publisher-input/scripts/hf_static_space.py",
        "deploy",
        "--source-sha",
        "$SOURCE_SHA",
        "--bundle",
        "$RUNNER_TEMP/publisher-input/hf-static-space",
        "--authorization",
        "$RUNNER_TEMP/publisher-input/governed-merge.json",
        "--result",
        "$RUNNER_TEMP/publication-evidence/hf-deploy-result.json",
        "--failure-output",
        "$RUNNER_TEMP/publication-evidence/hf-publication-failure.json",
    ]
    if (
        mutation_commands[:1] != ["set -euo pipefail"]
        or len(mutation_commands) != 4
        or mutation_commands[1] != 'mkdir -p "$RUNNER_TEMP/hf-publisher-home" "$RUNNER_TEMP/hf-publisher-cache"'
        or mutation_commands[2] != 'chmod 0700 "$RUNNER_TEMP/hf-publisher-home" "$RUNNER_TEMP/hf-publisher-cache"'
        or _command_tokens(mutation_commands[3], "publisher mutation") != expected_mutation
    ):
        raise BoundaryError("publisher mutation command is not exact and mandatory")

    measurement = _named_step(
        measure, "Measure public bytes and reauthorize current main without HF credentials"
    )
    if measurement.get("env") != {
        "GITHUB_TOKEN": NATIVE_GOVERNANCE_TOKEN,
        "HF_TOKEN": "",
        "SOURCE_SHA": "${{ github.sha }}",
    }:
        raise BoundaryError("measurement credential boundary is not exact")
    measurement_commands = _logical_shell_commands(
        measurement.get("run"), "measurement step"
    )
    expected_measurement = [
        "python",
        "-I",
        "$RUNNER_TEMP/publisher-input/scripts/hf_static_space.py",
        "attest",
        "--source-sha",
        "$SOURCE_SHA",
        "--bundle",
        "$RUNNER_TEMP/publisher-input/hf-static-space",
        "--authorization",
        "$RUNNER_TEMP/publisher-input/governed-merge.json",
        "--event",
        "$GITHUB_EVENT_PATH",
        "--authorization-output",
        "$RUNNER_TEMP/measurement-evidence/post-readback-governed-merge.json",
        "--result",
        "$RUNNER_TEMP/publication-evidence/hf-deploy-result.json",
        "--output",
        "$RUNNER_TEMP/measurement-evidence/hf-live-attestation.json",
        "--failure-output",
        "$RUNNER_TEMP/measurement-evidence/hf-publication-partial.json",
    ]
    if (
        measurement_commands[:1] != ["set -euo pipefail"]
        or len(measurement_commands) != 3
        or measurement_commands[1] != 'mkdir -p "$RUNNER_TEMP/measurement-evidence"'
        or _command_tokens(measurement_commands[2], "measurement step")
        != expected_measurement
    ):
        raise BoundaryError("measurement command is not exact and mandatory")

    secret_expression = re.compile(
        r"\bsecrets\s*(?:\.\s*[A-Za-z_][A-Za-z0-9_]*"
        r"|\[\s*(?:'[^']+'|\"[^\"]+\")\s*\])"
    )
    secret_values = [
        value
        for _path, value in _walk_scalars(document)
        if isinstance(value, str) and secret_expression.search(value)
    ]
    if secret_values != [HF_SECRET]:
        raise BoundaryError("HF secret consumption is not isolated to one exact mutation step")
    for path, value in _walk_scalars(document):
        if path and path[-1] == "HF_TOKEN" and value not in {"", HF_SECRET}:
            raise BoundaryError("HF_TOKEN is materialized outside the exact secret boundary")
        if path and path[-1] == "secrets":
            raise BoundaryError("publisher workflow inherits or passes a secrets mapping")
    for _path, value in _walk_scalars(deploy):
        if value == NATIVE_GOVERNANCE_TOKEN:
            raise BoundaryError("publisher job contains a GitHub repository credential")

    _require_artifact_step(
        authorize,
        "Upload exact publisher input",
        UPLOAD_ARTIFACT,
        {
            "name": "hf-static-space-publisher-input-${{ github.sha }}-${{ github.run_attempt }}",
            "path": "${{ runner.temp }}/publisher-input",
            "if-no-files-found": "error",
            "include-hidden-files": True,
            **({"retention-days": 30} if authorize_has_artifact_attempt else {"retention-days": 1}),
        },
    )
    _require_artifact_step(
        deploy,
        "Download exact authorized publisher input",
        DOWNLOAD_ARTIFACT,
        {
            "name": "hf-static-space-publisher-input-${{ github.sha }}-${{ github.run_attempt }}"
            if not authorize_has_artifact_attempt
            else "hf-static-space-publisher-input-${{ github.sha }}-${{ needs.authorize.outputs.artifact-run-attempt }}",
            "path": "${{ runner.temp }}/publisher-input",
        },
    )
    _require_artifact_step(
        deploy,
        "Upload publisher outcome before any OIDC privilege exists",
        UPLOAD_ARTIFACT,
        {
            "name": "hf-static-space-publication-${{ github.sha }}-${{ github.run_attempt }}",
            "path": "${{ runner.temp }}/publication-evidence",
            "if-no-files-found": "error",
            "retention-days": 90,
        },
    )
    _require_artifact_step(
        measure,
        "Download exact authorized publisher input",
        DOWNLOAD_ARTIFACT,
        {
            "name": "hf-static-space-publisher-input-${{ github.sha }}-${{ github.run_attempt }}"
            if not authorize_has_artifact_attempt
            else "hf-static-space-publisher-input-${{ github.sha }}-${{ needs.authorize.outputs.artifact-run-attempt }}",
            "path": "${{ runner.temp }}/publisher-input",
        },
    )
    _require_artifact_step(
        measure,
        "Download exact publisher outcome",
        DOWNLOAD_ARTIFACT,
        {
            "name": "hf-static-space-publication-${{ github.sha }}-${{ github.run_attempt }}"
            if not deploy_has_artifact_attempt
            else "hf-static-space-publication-${{ github.sha }}-${{ needs.deploy.outputs.artifact-run-attempt }}",
            "path": "${{ runner.temp }}/publication-evidence",
        },
    )
    _require_artifact_step(
        measure,
        "Upload exact public measurement before OIDC",
        UPLOAD_ARTIFACT,
        {
            "name": "hf-static-space-measurement-${{ github.sha }}-${{ github.run_attempt }}",
            "path": "${{ runner.temp }}/measurement-evidence",
            "if-no-files-found": "error",
            "retention-days": 90,
        },
    )
    _require_artifact_step(
        attest,
        "Download exact publisher outcome",
        DOWNLOAD_ARTIFACT,
        {
            "name": "hf-static-space-publication-${{ github.sha }}-${{ github.run_attempt }}"
            if not deploy_has_artifact_attempt
            else "hf-static-space-publication-${{ github.sha }}-${{ needs.deploy.outputs.artifact-run-attempt }}",
            "path": "${{ runner.temp }}/publication-evidence",
        },
    )
    _require_artifact_step(
        attest,
        "Download exact public measurement",
        DOWNLOAD_ARTIFACT,
        {
            "name": "hf-static-space-measurement-${{ github.sha }}-${{ github.run_attempt }}"
            if not measure_has_artifact_attempt
            else "hf-static-space-measurement-${{ github.sha }}-${{ needs.measure.outputs.artifact-run-attempt }}",
            "path": "${{ runner.temp }}/measurement-evidence",
        },
    )
    oidc = _named_step(
        attest, "Attest canonical exact-revision measurement with GitHub OIDC"
    )
    if oidc.get("uses") != ATTEST_PROVENANCE or _mapping(
        oidc.get("with"), "OIDC attestation inputs"
    ) != {"subject-path": "${{ runner.temp }}/measurement-evidence/hf-live-attestation.json"}:
        raise BoundaryError("OIDC attestation does not bind the exact public measurement")
    workflow_sha256 = hashlib.sha256(workflow.encode("utf-8")).hexdigest()
    expected_shell_contract_sha256 = LEGACY_STATIC_SHELL_CONTRACT_SHA256.get(
        workflow_sha256
    )
    if expected_shell_contract_sha256 is None:
        raise BoundaryError(
            f"publisher workflow shell step bodies are not covered: {workflow_sha256}"
        )
    shell_contract_sha256 = _workflow_shell_contract_sha256(
        _workflow_document(workflow)
    )
    if shell_contract_sha256 != expected_shell_contract_sha256:
        raise BoundaryError(
            "publisher workflow shell step bodies and environments are not exact"
        )


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
    if "secrets: inherit" in workflow:
        raise BoundaryError("publisher workflow expands permissions or inherits secrets")
    _workflow_governance_contract(workflow)
    if contract["isolated_invocation"] not in workflow:
        raise BoundaryError("publisher invocation is not isolated from repository modules")
    for marker in contract["required_workflow_markers"]:
        if marker.startswith("artifact-run-attempt:") and "artifact-run-attempt:" not in workflow:
            continue
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
    parser.add_argument("--allow-explicit-pending", action="store_true")
    args = parser.parse_args()
    modes = sum((bool(args.event), args.validate_manifest_only, bool(args.verify_target), args.verify_all_active))
    if modes != 1 or (args.allow_explicit_pending and not args.verify_all_active):
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
            if not result["authorization_complete"] and not args.allow_explicit_pending:
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
