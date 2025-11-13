from __future__ import annotations

import re
import shlex
from collections.abc import Iterable
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from rtx.utils import read_json, read_toml, read_yaml

__all__ = [
    "normalize_version",
    "load_json_dependencies",
    "load_lock_dependencies",
    "read_poetry_lock",
    "read_requirements",
    "read_uv_lock",
    "read_pnpm_lock",
    "read_toml",
    "read_yaml",
    "read_json",
    "merge_dependency_version",
]

_INLINE_COMMENT_PATTERN = re.compile(r"\s+#.*$")


def _strip_inline_comment(line: str) -> str:
    """Remove trailing inline comments that are prefixed by whitespace."""
    return _INLINE_COMMENT_PATTERN.sub("", line).strip()


def _parse_requirement_line(line: str) -> tuple[str, str] | None:
    cleaned = _strip_inline_comment(line)
    if not cleaned or cleaned.startswith("#"):
        return None
    if cleaned.startswith("-"):
        return None
    if "==" in cleaned and cleaned.endswith("=="):
        return None
    try:
        requirement = Requirement(cleaned)
    except InvalidRequirement:
        if "==" in cleaned:
            name, version = cleaned.split("==", 1)
            return name.strip(), version.strip() or "*"
        return None
    name = requirement.name
    if requirement.url:
        version = f"@ {requirement.url}"
    else:
        specifier = requirement.specifier
        if specifier:
            specs = sorted(list(specifier), key=lambda s: s.version)
            if len(specs) == 1 and specs[0].operator == "==":
                version = specs[0].version
            else:
                version = ",".join(str(s) for s in specs)
        else:
            version = "*"
    return name, version


def _parse_requirement_lines(lines: Iterable[str]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for raw_line in lines:
        parsed = _parse_requirement_line(raw_line)
        if parsed is None:
            continue
        name, version = parsed
        merge_dependency_version(resolved, name, version)
    return resolved


_SPECIFICITY_TOKENS = frozenset("<>=!~^")


def _is_more_specific(candidate: str, baseline: str) -> bool:
    return _specificity_rank(candidate) > _specificity_rank(baseline)


def _specificity_rank(specifier: str) -> int:
    normalized = specifier.strip()
    if not normalized or normalized == "*":
        return 0
    if normalized.startswith("@"):
        return 5
    if any(token in normalized for token in _SPECIFICITY_TOKENS):
        if normalized.startswith("=="):
            return 4
        return 2
    return 4 if normalized else 0


def _normalize_specifier(specifier: str | None) -> str:
    if specifier is None:
        return "*"
    cleaned = specifier.strip()
    return cleaned or "*"


def merge_dependency_version(store: dict[str, str], name: str, candidate: str) -> bool:
    """Merge ``candidate`` into ``store`` ensuring the most specific specifier wins.

    Returns ``True`` when the stored version changed (including initial insert).
    """

    normalized_candidate = _normalize_specifier(candidate)
    existing = store.get(name)
    if existing is None:
        store[name] = normalized_candidate
        return True

    normalized_existing = _normalize_specifier(existing)
    if normalized_candidate == normalized_existing:
        return False

    if _is_more_specific(normalized_candidate, normalized_existing):
        store[name] = normalized_candidate
        return True

    if _is_more_specific(normalized_existing, normalized_candidate):
        return False

    if normalized_existing in {"*", ""} and normalized_candidate not in {"*", ""}:
        store[name] = normalized_candidate
        return True

    return False


def _parse_conda_dependency(entry: str) -> tuple[str, str] | None:
    candidate = entry.strip()
    if not candidate or candidate.startswith("#"):
        return None
    if "::" in candidate:
        _, candidate = candidate.split("::", 1)
        candidate = candidate.strip()
    try:
        requirement = Requirement(candidate)
    except InvalidRequirement:
        pass
    else:
        if requirement.url:
            version = f"@ {requirement.url}"
        else:
            specifier = requirement.specifier
            if specifier:
                specs = list(specifier)
                if len(specs) == 1 and specs[0].operator == "==":
                    version = specs[0].version
                else:
                    version = str(specifier)
            else:
                version = "*"
        return requirement.name, version
    if "=" in candidate:
        parts = [segment.strip() for segment in candidate.split("=") if segment.strip()]
        if not parts:
            return None
        name = parts[0]
        version = parts[1] if len(parts) >= 2 else "*"
        return name, version or "*"
    pieces = candidate.split()
    if not pieces:
        return None
    name = pieces[0]
    version = " ".join(pieces[1:]) if len(pieces) > 1 else "*"
    return name, version or "*"


def normalize_version(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return "0.0.0"
    try:
        return str(Version(raw))
    except InvalidVersion:
        return raw


def load_json_dependencies(path: Path, key: str = "dependencies") -> dict[str, str]:
    data = read_json(path)
    section = data.get(key, {}) if isinstance(data, dict) else {}
    return {name: str(spec) for name, spec in section.items()}


def load_lock_dependencies(path: Path) -> dict[str, str]:
    data = read_json(path)
    if isinstance(data, dict) and "packages" in data:
        return {
            _normalize_lock_name(name): str(meta.get("version", "0.0.0"))
            for name, meta in data["packages"].items()
            if isinstance(meta, dict)
        }
    if isinstance(data, dict) and "dependencies" in data:
        out: dict[str, str] = {}
        for name, info in data["dependencies"].items():
            if isinstance(info, dict) and "version" in info:
                out[_normalize_lock_name(name)] = str(info["version"])
        return out
    return {}


def _normalize_lock_name(name: str) -> str:
    if name.startswith("./"):
        name = name[2:]
    if name.startswith("node_modules/"):
        name = name.split("/", 1)[1]
    return name


def read_poetry_lock(path: Path) -> dict[str, str]:
    content = read_toml(path)
    out: dict[str, str] = {}
    for package in content.get("package", []):
        if isinstance(package, dict):
            name = package.get("name")
            version = package.get("version")
            if isinstance(name, str) and isinstance(version, str):
                out[name] = version
    return out


def read_uv_lock(path: Path) -> dict[str, str]:
    data = read_toml(path)
    packages = data.get("package", [])
    if isinstance(packages, dict):
        packages = [packages]

    catalog: dict[str, dict[str, object]] = {}
    for package in packages:
        if isinstance(package, dict):
            name = package.get("name")
            if isinstance(name, str):
                catalog[name] = package

    direct_names: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            continue
        source = package.get("source")
        if isinstance(source, dict) and source.get("virtual") == ".":
            for entry in package.get("dependencies", []) or []:
                if isinstance(entry, dict):
                    dep_name = entry.get("name")
                    if isinstance(dep_name, str):
                        direct_names.add(dep_name)

    if not direct_names:
        project = data.get("project")
        if isinstance(project, dict):
            for dep in project.get("dependencies", []) or []:
                if isinstance(dep, str):
                    try:
                        req = Requirement(dep)
                    except InvalidRequirement:
                        continue
                    direct_names.add(req.name)

        dependency_groups = data.get("dependency-groups", {})
        if isinstance(dependency_groups, dict):
            for group_deps in dependency_groups.values():
                if isinstance(group_deps, list):
                    for dep in group_deps:
                        if isinstance(dep, str):
                            try:
                                req = Requirement(dep)
                            except InvalidRequirement:
                                continue
                            direct_names.add(req.name)

    results: dict[str, str] = {}
    for name in sorted(direct_names):
        version = "*"
        package = catalog.get(name)
        if isinstance(package, dict):
            extracted = package.get("version")
            if isinstance(extracted, str) and extracted:
                version = extracted
            else:
                metadata = package.get("metadata")
                if isinstance(metadata, dict):
                    requires_dist = metadata.get("requires-dist")
                    if isinstance(requires_dist, list):
                        for item in requires_dist:
                            if isinstance(item, dict) and item.get("name") == name:
                                spec = item.get("specifier")
                                if isinstance(spec, str) and spec:
                                    version = spec
                                break
        results[name] = version

    if not results:
        for name, package in catalog.items():
            if not isinstance(package, dict):
                continue
            source = package.get("source")
            if isinstance(source, dict) and source.get("virtual") == ".":
                continue
            extracted = package.get("version")
            version = extracted if isinstance(extracted, str) and extracted else "*"
            results[name] = version

    return results


def _parse_pnpm_package_key(key: str) -> tuple[str | None, str | None]:
    if not isinstance(key, str):
        return None, None

    # Remove leading '/' and 'node_modules/'
    trimmed = key.lstrip("/")
    if trimmed.startswith("node_modules/"):
        trimmed = trimmed[len("node_modules/"):]

    if not trimmed:
        return None, None

    base = trimmed.split("(", 1)[0]
    name: str | None = None
    version: str | None = None

    if base.startswith("@"):
        # Scoped package: @scope/name/version or @scope/name@version
        parts = base.split("/")
        if len(parts) > 1:
            name = f"{parts[0]}/{parts[1]}"
            if len(parts) > 2:
                version = parts[2]
            elif "@" in parts[1]: # Handle @scope/name@version
                scope_name, ver = parts[1].split("@", 1)
                name = f"{parts[0]}/{scope_name}"
                version = ver
        else:
            name = base
    elif "@" in base:
        # Non-scoped package with @version: name@version
        name, version = base.split("@", 1)
    elif "/" in base:
        # Non-scoped package with /version: name/version
        parts = base.split("/")
        name = parts[0]
        version = parts[1] if len(parts) > 1 else None
    else:
        # Just a name
        name = base

    cleaned_name = name.strip() if name else None
    cleaned_version = version.strip() if version else None
    return (cleaned_name or None, cleaned_version or None)


def _clean_pnpm_version(raw: str | None) -> str | None:
    if not isinstance(raw, str):
        return None
    candidate = raw.split("(", 1)[0].strip()
    if not candidate:
        return None
    if candidate.startswith(("link:", "workspace:", "file:", "github:", "git+")):
        return None
    if candidate.startswith("npm:"):
        remainder = candidate.split(":", 1)[1]
        _, version = _parse_pnpm_package_key(remainder)
        return version
    return candidate


def read_pnpm_lock(path: Path) -> dict[str, str]:
    data = read_yaml(path) or {}
    direct: dict[str, str] = {}

    def capture(section_data: dict[str, object]) -> None:
        for name, info in section_data.items():
            if not isinstance(name, str):
                continue
            raw_version: str | None = None
            if isinstance(info, dict):
                raw_version = info.get("version") or info.get("specifier")
            elif isinstance(info, str):
                raw_version = info
            version = _clean_pnpm_version(raw_version)
            if version:
                merge_dependency_version(direct, name, version)

    importers = data.get("importers", {})
    if isinstance(importers, dict):
        for importer in importers.values():
            if not isinstance(importer, dict):
                continue
            for section in (
                "dependencies",
                "optionalDependencies",
                "devDependencies",
                "peerDependencies",
            ):
                section_data = importer.get(section)
                if isinstance(section_data, dict):
                    capture(section_data)

    if not direct:
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for key, meta in packages.items():
                name, version = _parse_pnpm_package_key(key)
                if name and version:
                    merge_dependency_version(direct, name, version)
                if isinstance(meta, dict):
                    meta_name = meta.get("name")
                    meta_version = _clean_pnpm_version(meta.get("version"))
                    if isinstance(meta_name, str) and meta_version:
                        merge_dependency_version(direct, meta_name, meta_version)

    return direct


_INCLUDE_FLAGS = {
    "-r": "requirement",
    "--requirement": "requirement",
    "-c": "constraint",
    "--constraint": "constraint",
}

_INCLUDE_PREFIXES = {
    "--requirement=": "requirement",
    "--constraint=": "constraint",
}


def _extract_include_directives(tokens: list[str]) -> list[tuple[str, str]]:
    directives: list[tuple[str, str]] = []
    index = 0
    length = len(tokens)
    while index < length:
        token = tokens[index]
        directive = _INCLUDE_FLAGS.get(token)
        if directive is not None:
            if index + 1 < length:
                directives.append((directive, tokens[index + 1]))
            index += 2
            continue
        for prefix, kind in _INCLUDE_PREFIXES.items():
            if token.startswith(prefix):
                value = token[len(prefix) :]
                if value:
                    directives.append((kind, value))
                break
        index += 1
    return directives


def read_requirements(
    path: Path,
    *,
    _seen: set[Path] | None = None,
    context: dict[str, set[str]] | None = None,
    kind: str = "requirement",
) -> dict[str, str]:
    if _seen is None:
        _seen = set()
    resolved: dict[str, str] = {}
    absolute_path = path.resolve()
    if absolute_path in _seen:
        return resolved
    _seen.add(absolute_path)

    raw_lines = path.read_text(encoding="utf-8").splitlines()
    direct_lines: list[str] = []

    for raw_line in raw_lines:
        stripped = raw_line.lstrip()
        if not stripped or stripped.startswith("#"):
            direct_lines.append(raw_line)
            continue

        cleaned = _strip_inline_comment(raw_line)
        try:
            tokens = shlex.split(cleaned) if cleaned else []
        except ValueError:
            tokens = []

        directives = _extract_include_directives(tokens)
        if directives:
            for directive_kind, target in directives:
                candidate = (absolute_path.parent / target).resolve()
                if not candidate.exists():
                    continue
                nested = read_requirements(
                    candidate,
                    _seen=_seen,
                    context=context,
                    kind=directive_kind,
                )
                for name, version in nested.items():
                    merge_dependency_version(resolved, name, version)
                    if context is not None:
                        context.setdefault(name, set()).add(directive_kind)
            continue

        direct_lines.append(raw_line)

    for name, version in _parse_requirement_lines(direct_lines).items():
        merge_dependency_version(resolved, name, version)
        if context is not None:
            context.setdefault(name, set()).add(kind)

    return resolved


def read_gemfile_lock(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(" ") or line.startswith("-"):
            continue
        if " (" in line and ")" in line:
            name, version = line.split(" (", 1)
            out[name.strip()] = version.rstrip(")")
    return out


def read_maven_pom(path: Path) -> dict[str, str]:
    import xml.etree.ElementTree as ET

    tree = ET.parse(path)  # noqa: S314 - parsing local project metadata
    root = tree.getroot()
    namespace = "" if not root.tag.startswith("{") else root.tag.split("}", 1)[0] + "}"
    deps: dict[str, str] = {}
    for dependency in root.findall(f".//{namespace}dependency"):
        group = dependency.findtext(f"{namespace}groupId") or ""
        artifact = dependency.findtext(f"{namespace}artifactId") or ""
        version = dependency.findtext(f"{namespace}version") or "0.0.0"
        if group and artifact:
            deps[f"{group}:{artifact}"] = version
    return deps


def read_go_mod(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    in_block = False
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith(("module", "//", "replace", "go")):
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line.startswith(")"):
            in_block = False
            continue
        if line.startswith("require") and not line.endswith("("):
            parts = line.split()
            if len(parts) >= 3:
                _, module, version = parts[:3]
                out[module] = version
            continue
        if in_block and " " in line:
            module, version = line.split()[:2]
            out[module] = version
        elif " " in line:
            module, version = line.split()[:2]
            out[module] = version
    return out


def read_cargo_lock(path: Path) -> dict[str, str]:
    content = read_toml(path)
    out: dict[str, str] = {}
    for package in content.get("package", []):
        if isinstance(package, dict):
            name = package.get("name")
            version = package.get("version")
            if isinstance(name, str) and isinstance(version, str):
                out[name] = version
    return out


def read_composer_lock(path: Path) -> dict[str, str]:
    data = read_json(path)
    out: dict[str, str] = {}
    for section in ("packages", "packages-dev"):
        for package in data.get(section, []):
            if isinstance(package, dict):
                name = package.get("name")
                version = package.get("version")
                if isinstance(name, str) and isinstance(version, str):
                    out[name] = version
    return out


def read_environment_yml(path: Path) -> dict[str, str]:
    data = read_yaml(path) or {}
    deps = data.get("dependencies", [])
    out: dict[str, str] = {}
    for entry in deps:
        if isinstance(entry, str):
            parsed = _parse_conda_dependency(entry)
            if parsed is None:
                continue
            name, version = parsed
            out.setdefault(name, version)
        elif isinstance(entry, dict):
            pip_section = entry.get("pip")
            if isinstance(pip_section, list):
                pip_requirements = _parse_requirement_lines(pip_section)
                for name, version in pip_requirements.items():
                    out.setdefault(name, version)
    return out


def read_brewfile(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("brew"):
            parts = line.split(",")
            name = parts[0].split()[1].strip("'\"")
            version = "latest"
            if len(parts) > 1 and "version" in parts[1]:
                version = parts[1].split(":")[1].strip(" \"'")
            out[name] = version
    return out


def read_packages_lock(path: Path) -> dict[str, str]:
    data = read_json(path)
    out: dict[str, str] = {}
    dependencies = data.get("dependencies", {})
    if isinstance(dependencies, dict):
        for name, info in dependencies.items():
            if isinstance(info, dict) and "resolved" in info:
                version = info.get("resolved", "0.0.0")
            else:
                version = info.get("version", "0.0.0") if isinstance(info, dict) else "0.0.0"
            out[name] = version
    return out


def read_dockerfile(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    commands: list[str] = []
    in_continuation = False
    current: list[str] = []

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if in_continuation:
            fragment = stripped.rstrip("\\").strip()
            if fragment:
                current.append(fragment)
            if not stripped.endswith("\\"):
                commands.append(" ".join(current))
                current = []
                in_continuation = False
            continue
        parts = stripped.split(maxsplit=1)
        if parts and parts[0].lower() == "run":
            body = parts[1] if len(parts) > 1 else ""
            body = body.strip()
            if stripped.endswith("\\"):
                in_continuation = True
                current = [body.rstrip("\\").strip()]
            else:
                commands.append(body)

    if current:
        commands.append(" ".join(current))

    for command in commands:
        for segment in re.split(r"&&|;", command):
            segment = segment.strip()
            if not segment:
                continue
            tokens = shlex.split(segment)
            if not tokens:
                continue

            pip_start = _pip_install_start(tokens)
            if pip_start is not None:
                idx = pip_start
                while idx < len(tokens):
                    token = tokens[idx]
                    if token.startswith("-"):
                        if token in _PIP_FLAGS_WITH_ARGS and idx + 1 < len(tokens):
                            idx += 2
                        else:
                            idx += 1
                        continue
                    parsed = _parse_requirement_line(token)
                    idx += 1
                    if parsed is None:
                        continue
                    name, version = parsed
                    if name:
                        out.setdefault(f"pypi:{name}", version)
                continue

            npm_start = _npm_install_start(tokens)
            if npm_start is not None:
                idx = npm_start
                while idx < len(tokens):
                    token = tokens[idx]
                    if token.startswith("-"):
                        if token in _NPM_FLAGS_WITH_ARGS and idx + 1 < len(tokens):
                            idx += 2
                        else:
                            idx += 1
                        continue
                    npm_parsed = _parse_npm_token(token)
                    idx += 1
                    if npm_parsed is None:
                        continue
                    name, version = npm_parsed
                    out.setdefault(f"npm:{name}", version)

    return out


def _pip_install_start(tokens: list[str]) -> int | None:
    if len(tokens) >= 2 and tokens[0] in {"pip", "pip3"} and tokens[1] == "install":
        return 2
    if (
        len(tokens) >= 4
        and tokens[0].startswith("python")
        and tokens[1] == "-m"
        and tokens[2] == "pip"
        and tokens[3] == "install"
    ):
        return 4
    return None


def _npm_install_start(tokens: list[str]) -> int | None:
    if len(tokens) >= 2 and tokens[0] == "npm" and tokens[1] == "install":
        return 2
    return None


def _parse_npm_token(token: str) -> tuple[str, str] | None:
    cleaned = token.strip()
    if not cleaned or cleaned.startswith("-"):
        return None
    if cleaned.startswith((".", "/")):
        return None
    if cleaned.startswith(("file:", "git+", "http://", "https://")):
        return None
    name = cleaned
    version = "*"
    if cleaned.startswith("@"):
        index = cleaned.rfind("@")
        if index > 0:
            name = cleaned[:index]
            remainder = cleaned[index + 1 :]
            version = remainder or "*"
    elif "@" in cleaned:
        name, remainder = cleaned.split("@", 1)
        version = remainder or "*"
    return name, version


_PIP_FLAGS_WITH_ARGS = {
    "-r",
    "--requirement",
    "--requirements",
    "-c",
    "--constraint",
    "--trusted-host",
    "--index-url",
    "--extra-index-url",
    "--find-links",
}


_NPM_FLAGS_WITH_ARGS = {
    "--prefix",
    "--registry",
}
