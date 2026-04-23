"""Automatic entrypoint detection.

Populates ``CodeGraph.entrypoints`` so that ``attack_surface()``, taint
propagation, entrypoint enumeration, and privilege-boundary crossing
produce meaningful results.

Detection layers (later layers override earlier ones):
1. Universal heuristics — functions named ``main``, ``[project.scripts]``
   entries in pyproject.toml.
2. Repo-local override file — ``.trailmark/entrypoints.toml`` at the
   repository root.

Framework-specific detection (Flask ``@app.route``, FastAPI, Django URL
patterns, Solidity ``external``/``public``, etc.) requires per-language
parser support for decorators/visibility and is planned for a follow-up.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from trailmark.models.annotations import (
    AssetValue,
    EntrypointKind,
    EntrypointTag,
    TrustLevel,
)
from trailmark.models.graph import CodeGraph
from trailmark.models.nodes import CodeUnit

OVERRIDE_FILE = ".trailmark/entrypoints.toml"

# How many lines above start_line to scan for decorators/attributes.
_DECORATOR_LOOKBACK = 12

# Python HTTP web-framework decorator suffix on any receiver.
#   Matches: @app.route(...), @router.get(...), @bp.post(...), @routes.put(...)
#   (Flask, FastAPI, aiohttp, Sanic all share this shape.)
_PY_HTTP_DECORATOR = re.compile(
    r"^\s*@\s*[A-Za-z_][\w.]*\.(route|get|post|put|patch|delete|head|options|"
    r"websocket|api_route)\s*\(",
)

# @click.command / @click.group / @typer_app.command
_PY_CLI_DECORATOR = re.compile(
    r"^\s*@\s*(click\.(command|group)|[A-Za-z_][\w.]*\.command)\s*\(",
)

# @celery_app.task, @shared_task, @app.task
_PY_TASK_DECORATOR = re.compile(
    r"^\s*@\s*([A-Za-z_][\w.]*\.task|shared_task)\b",
)

# Rust proc-macro handler attributes: #[get("/")], #[post("/")], etc.
_RS_HTTP_ATTR = re.compile(
    r"^\s*#\[\s*(get|post|put|delete|patch|head|options|connect|trace)\s*\(",
)

# Rust #[tokio::main] / #[async_std::main] / #[actix_web::main]
_RS_ASYNC_MAIN_ATTR = re.compile(r"^\s*#\[\s*\w+::main\s*\]\s*$")

# Rust FFI export: #[no_mangle] or `pub extern "C" fn`
_RS_NO_MANGLE = re.compile(r"^\s*#\[\s*no_mangle\s*\]\s*$")
_RS_EXTERN_C_FN = re.compile(r"\bpub\s+extern\s+\"C\"\s+fn\b")

# Solidity function visibility — scan the signature line itself.
_SOL_VISIBILITY = re.compile(
    r"\bfunction\s+\w+\s*\([^)]*\)\s*(?:[\w\s]*?\b)?(external|public)\b",
)
_SOL_SPECIAL = re.compile(r"^\s*(fallback|receive)\s*\(\s*\)")

_KIND_BY_NAME = {k.value: k for k in EntrypointKind}
_TRUST_BY_NAME = {t.value: t for t in TrustLevel}
_ASSET_BY_NAME = {a.value: a for a in AssetValue}


def detect_entrypoints(graph: CodeGraph, root_path: str) -> dict[str, EntrypointTag]:
    """Return detected entrypoints for ``graph`` rooted at ``root_path``.

    Callers typically merge the result into ``graph.entrypoints``:

        graph.entrypoints.update(detect_entrypoints(graph, path))

    Args:
        graph: The parsed code graph.
        root_path: Absolute or repository-relative path the parser walked.

    Returns:
        Mapping of node id -> EntrypointTag. Empty dict if no entrypoints
        are detected.
    """
    root = Path(root_path).resolve()
    repo_root = _find_repo_root(root)

    # Priority (least to most specific, later layers override earlier):
    #   1. Generic `main` functions — fallback heuristic.
    #   2. Framework-aware decorator/attribute scan.
    #   3. pyproject.toml [project.scripts] — explicitly-declared CLI targets.
    #   4. Override file — hand-curated, authoritative.
    detected: dict[str, EntrypointTag] = {}
    detected.update(_detect_main_functions(graph))
    detected.update(_detect_framework_entrypoints(graph))
    detected.update(_detect_pyproject_scripts(graph, repo_root))
    detected.update(_load_override_file(graph, repo_root))
    return detected


def _detect_framework_entrypoints(graph: CodeGraph) -> dict[str, EntrypointTag]:
    """Scan source files for framework-specific entrypoint markers.

    Covers Python web/task/CLI decorators, Rust handler/FFI attributes,
    and Solidity visibility. Designed to be additive: each node is checked
    against every language's detectors because files of mixed languages
    are rare but possible (embedded DSLs, templates).
    """
    cache = _SourceCache()
    result: dict[str, EntrypointTag] = {}
    for node_id, unit in graph.nodes.items():
        if unit.kind.value not in {"function", "method"}:
            continue
        path = unit.location.file_path
        if not path:
            continue

        tag = _detect_for_unit(cache, unit, path)
        if tag is not None:
            result[node_id] = tag
    return result


def _detect_for_unit(
    cache: _SourceCache,
    unit: CodeUnit,
    path: str,
) -> EntrypointTag | None:
    if path.endswith(".py"):
        return _detect_python(cache, unit, path)
    if path.endswith(".rs"):
        return _detect_rust(cache, unit, path)
    if path.endswith(".sol"):
        return _detect_solidity(cache, unit, path)
    return None


def _detect_python(
    cache: _SourceCache,
    unit: CodeUnit,
    path: str,
) -> EntrypointTag | None:
    decorators = cache.decorators_above(path, unit.location.start_line)
    for line in decorators:
        if _PY_HTTP_DECORATOR.match(line):
            return EntrypointTag(
                kind=EntrypointKind.API,
                trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
                description="Python HTTP route decorator",
                asset_value=AssetValue.HIGH,
            )
        if _PY_CLI_DECORATOR.match(line):
            return EntrypointTag(
                kind=EntrypointKind.USER_INPUT,
                trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
                description="Python CLI command (Click/Typer)",
                asset_value=AssetValue.MEDIUM,
            )
        if _PY_TASK_DECORATOR.match(line):
            return EntrypointTag(
                kind=EntrypointKind.THIRD_PARTY,
                trust_level=TrustLevel.SEMI_TRUSTED_EXTERNAL,
                description="Python task queue handler (Celery)",
                asset_value=AssetValue.MEDIUM,
            )
    return None


def _detect_rust(
    cache: _SourceCache,
    unit: CodeUnit,
    path: str,
) -> EntrypointTag | None:
    decorators = cache.decorators_above(path, unit.location.start_line)
    signature = cache.line(path, unit.location.start_line)

    for line in decorators:
        if _RS_HTTP_ATTR.match(line):
            return EntrypointTag(
                kind=EntrypointKind.API,
                trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
                description="Rust HTTP handler attribute",
                asset_value=AssetValue.HIGH,
            )
        if _RS_NO_MANGLE.match(line):
            return EntrypointTag(
                kind=EntrypointKind.API,
                trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
                description="Rust FFI export (#[no_mangle])",
                asset_value=AssetValue.HIGH,
            )
        if _RS_ASYNC_MAIN_ATTR.match(line) and unit.name == "main":
            return EntrypointTag(
                kind=EntrypointKind.USER_INPUT,
                trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
                description="Rust async main (tokio/actix/async-std)",
                asset_value=AssetValue.HIGH,
            )
    if signature and _RS_EXTERN_C_FN.search(signature):
        return EntrypointTag(
            kind=EntrypointKind.API,
            trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
            description='Rust FFI export (pub extern "C")',
            asset_value=AssetValue.HIGH,
        )
    return None


def _detect_solidity(
    cache: _SourceCache,
    unit: CodeUnit,
    path: str,
) -> EntrypointTag | None:
    signature = cache.signature_block(path, unit.location.start_line)
    if signature is None:
        return None
    if _SOL_SPECIAL.search(signature):
        return EntrypointTag(
            kind=EntrypointKind.API,
            trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
            description="Solidity fallback/receive",
            asset_value=AssetValue.HIGH,
        )
    if _SOL_VISIBILITY.search(signature):
        return EntrypointTag(
            kind=EntrypointKind.API,
            trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
            description="Solidity external/public function",
            asset_value=AssetValue.HIGH,
        )
    return None


class _SourceCache:
    """Lazily reads and caches source files during a detection pass."""

    def __init__(self) -> None:
        self._lines: dict[str, list[str]] = {}

    def _read(self, path: str) -> list[str]:
        cached = self._lines.get(path)
        if cached is not None:
            return cached
        try:
            text = Path(path).read_text()
        except (OSError, UnicodeDecodeError):
            text = ""
        lines = text.splitlines()
        self._lines[path] = lines
        return lines

    def line(self, path: str, one_indexed: int) -> str | None:
        lines = self._read(path)
        idx = one_indexed - 1
        if 0 <= idx < len(lines):
            return lines[idx]
        return None

    def decorators_above(self, path: str, start_line: int) -> list[str]:
        """Return contiguous non-blank lines immediately above ``start_line``.

        Walks backwards until a blank line or a non-decorator-looking line
        is hit. Returns the collected lines in reading order (top-down).
        """
        lines = self._read(path)
        start_idx = start_line - 1
        collected: list[str] = []
        i = start_idx - 1
        while i >= 0:
            candidate = lines[i]
            stripped = candidate.strip()
            if not stripped:
                break
            if not (stripped.startswith("@") or stripped.startswith("#[")):
                break
            collected.append(candidate)
            i -= 1
            if len(collected) >= _DECORATOR_LOOKBACK:
                break
        collected.reverse()
        return collected

    def signature_block(self, path: str, start_line: int) -> str | None:
        """Return the function signature as a single line.

        Solidity / Rust signatures can wrap across several lines. Join
        up to 8 lines starting at ``start_line`` and stop at the first
        line containing an opening brace.
        """
        lines = self._read(path)
        idx = start_line - 1
        if idx < 0 or idx >= len(lines):
            return None
        parts: list[str] = []
        for offset in range(8):
            if idx + offset >= len(lines):
                break
            parts.append(lines[idx + offset])
            if "{" in lines[idx + offset]:
                break
        return " ".join(parts)


def _find_repo_root(start: Path) -> Path:
    """Walk up until we find a directory with pyproject.toml, or give up.

    Falls back to ``start`` if nothing is found so the caller still has a
    sensible base path for the override file lookup.
    """
    for candidate in (start, *start.parents):
        if (candidate / "pyproject.toml").exists():
            return candidate
        if (candidate / OVERRIDE_FILE).exists():
            return candidate
    return start


def _detect_main_functions(graph: CodeGraph) -> dict[str, EntrypointTag]:
    """Mark any top-level function named ``main`` as a CLI entrypoint.

    Uses TRUSTED_INTERNAL because the developer explicitly invoked it —
    it's an API boundary but not an external attacker surface by default.
    Users who want a stricter posture can override via the override file.
    """
    result: dict[str, EntrypointTag] = {}
    for node_id, unit in graph.nodes.items():
        if unit.name != "main":
            continue
        if unit.kind.value not in {"function", "method"}:
            continue
        result[node_id] = EntrypointTag(
            kind=EntrypointKind.USER_INPUT,
            trust_level=TrustLevel.TRUSTED_INTERNAL,
            description="CLI main() entrypoint",
            asset_value=AssetValue.LOW,
        )
    return result


def _detect_pyproject_scripts(
    graph: CodeGraph,
    repo_root: Path,
) -> dict[str, EntrypointTag]:
    """Read ``[project.scripts]`` from pyproject.toml and tag each target.

    Entries take the form ``name = "module.path:function"``. We locate the
    matching node by (file path suffix, function name) because Trailmark's
    node IDs use file basenames rather than full module paths.
    """
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.exists():
        return {}

    try:
        data = tomllib.loads(pyproject.read_text())
    except (OSError, ValueError):
        return {}

    project = data.get("project")
    if not isinstance(project, dict):
        return {}
    scripts_raw = project.get("scripts")
    if not isinstance(scripts_raw, dict):
        return {}

    result: dict[str, EntrypointTag] = {}
    for _script_name, target in scripts_raw.items():
        if not isinstance(target, str) or ":" not in target:
            continue
        module_path, func_name = target.rsplit(":", 1)
        node_id = _resolve_script_target(graph, module_path, func_name)
        if node_id is None:
            continue
        result[node_id] = EntrypointTag(
            kind=EntrypointKind.USER_INPUT,
            trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
            description=f"pyproject.toml [project.scripts] entry ({target})",
            asset_value=AssetValue.MEDIUM,
        )
    return result


def _resolve_script_target(
    graph: CodeGraph,
    module_path: str,
    func_name: str,
) -> str | None:
    """Find the node id matching a ``module.path:function`` script target."""
    suffix = module_path.replace(".", "/") + ".py"
    for node_id, unit in graph.nodes.items():
        if unit.name != func_name:
            continue
        if unit.location.file_path.endswith(suffix):
            return node_id
    return None


def _load_override_file(
    graph: CodeGraph,
    repo_root: Path,
) -> dict[str, EntrypointTag]:
    """Parse ``.trailmark/entrypoints.toml`` into EntrypointTag entries.

    Expected schema:

        [[entrypoint]]
        node = "cli:main"          # node id OR "module.path:function"
        kind = "api"               # EntrypointKind value
        trust = "untrusted_external"  # TrustLevel value (optional)
        asset_value = "high"       # AssetValue value (optional)
        description = "HTTP handler"  # optional
    """
    path = repo_root / OVERRIDE_FILE
    if not path.exists():
        return {}

    try:
        data = tomllib.loads(path.read_text())
    except (OSError, ValueError):
        return {}

    entries = data.get("entrypoint")
    if not isinstance(entries, list):
        return {}

    result: dict[str, EntrypointTag] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        tag_and_id = _entry_to_tag(graph, entry)
        if tag_and_id is None:
            continue
        node_id, tag = tag_and_id
        result[node_id] = tag
    return result


def _entry_to_tag(
    graph: CodeGraph,
    entry: dict[str, Any],
) -> tuple[str, EntrypointTag] | None:
    node_ref = entry.get("node")
    if not isinstance(node_ref, str):
        return None
    node_id = _resolve_override_node(graph, node_ref)
    if node_id is None:
        return None

    kind_name = entry.get("kind", "user_input")
    trust_name = entry.get("trust", "untrusted_external")
    asset_name = entry.get("asset_value", "medium")
    description = entry.get("description")

    kind = _KIND_BY_NAME.get(kind_name)
    trust = _TRUST_BY_NAME.get(trust_name)
    asset = _ASSET_BY_NAME.get(asset_name)
    if kind is None or trust is None or asset is None:
        return None

    return node_id, EntrypointTag(
        kind=kind,
        trust_level=trust,
        description=description if isinstance(description, str) else None,
        asset_value=asset,
    )


def _resolve_override_node(graph: CodeGraph, reference: str) -> str | None:
    """Resolve an override reference to a concrete node id.

    Accepts either a literal node id (``cli:main``) or a Python-style
    ``module.path:function`` reference, which we resolve the same way
    pyproject.toml scripts are resolved.
    """
    if reference in graph.nodes:
        return reference
    if ":" in reference:
        module_path, func_name = reference.rsplit(":", 1)
        return _resolve_script_target(graph, module_path, func_name)
    return None
