from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from rtx.utils import detect_files, read_json, read_toml, read_yaml


def normalize_version(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return "0.0.0"
    try:
        return str(Version(raw))
    except InvalidVersion:
        return raw


def load_json_dependencies(path: Path, key: str = "dependencies") -> Dict[str, str]:
    data = read_json(path)
    section = data.get(key, {}) if isinstance(data, dict) else {}
    return {name: str(spec) for name, spec in section.items()}


def load_lock_dependencies(path: Path) -> Dict[str, str]:
    data = read_json(path)
    if isinstance(data, dict) and "packages" in data:
        return {
            _normalize_lock_name(name): str(meta.get("version", "0.0.0"))
            for name, meta in data["packages"].items()
            if isinstance(meta, dict)
        }
    if isinstance(data, dict) and "dependencies" in data:
        out: Dict[str, str] = {}
        for name, info in data["dependencies"].items():
            if isinstance(info, dict) and "version" in info:
                out[_normalize_lock_name(name)] = str(info["version"])
        return out
    return {}


def _normalize_lock_name(name: str) -> str:
    if name.startswith('./'):
        name = name[2:]
    if name.startswith('node_modules/'):
        name = name.split('/', 1)[1]
    return name


def read_poetry_lock(path: Path) -> Dict[str, str]:
    content = read_toml(path)
    out: Dict[str, str] = {}
    for package in content.get("package", []):
        if isinstance(package, dict):
            name = package.get("name")
            version = package.get("version")
            if isinstance(name, str) and isinstance(version, str):
                out[name] = version
    return out


def read_uv_lock(path: Path) -> Dict[str, str]:
    data = read_toml(path)
    packages = data.get("package", [])
    if isinstance(packages, dict):
        packages = [packages]

    catalog: Dict[str, Dict[str, object]] = {}
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

    results: Dict[str, str] = {}
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


def _parse_pnpm_package_key(key: str) -> Tuple[str | None, str | None]:
    if not isinstance(key, str):
        return None, None
    trimmed = key.lstrip("/")
    if not trimmed:
        return None, None
    base = trimmed.split("(", 1)[0]
    if base.startswith("@"):
        index = base.rfind("@")
        if index <= 0:
            return None, None
        name = base[:index]
        version = base[index + 1 :]
    else:
        if "@" not in base:
            return base or None, None
        name, version = base.split("@", 1)
    name = name.strip() if name else None
    version = version.strip() if version else None
    return (name or None, version or None)


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


def read_pnpm_lock(path: Path) -> Dict[str, str]:
    data = read_yaml(path) or {}
    direct: Dict[str, str] = {}

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
                if not isinstance(section_data, dict):
                    continue
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
                        direct.setdefault(name, version)

    if not direct:
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for key, meta in packages.items():
                name, version = _parse_pnpm_package_key(key)
                if name and version:
                    direct.setdefault(name, version)
                if isinstance(meta, dict):
                    meta_name = meta.get("name")
                    meta_version = _clean_pnpm_version(meta.get("version"))
                    if isinstance(meta_name, str) and meta_version:
                        direct.setdefault(meta_name, meta_version)

    return direct


def read_requirements(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            out[name.strip()] = version.strip()
        else:
            out[line] = "*"
    return out


def read_gemfile_lock(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(" ") or line.startswith("-"):
            continue
        if " (" in line and ")" in line:
            name, version = line.split(" (", 1)
            out[name.strip()] = version.rstrip(")")
    return out


def read_maven_pom(path: Path) -> Dict[str, str]:
    import xml.etree.ElementTree as ET

    tree = ET.parse(path)
    root = tree.getroot()
    namespace = "" if not root.tag.startswith("{") else root.tag.split("}", 1)[0] + "}"
    deps: Dict[str, str] = {}
    for dependency in root.findall(f".//{namespace}dependency"):
        group = dependency.findtext(f"{namespace}groupId") or ""
        artifact = dependency.findtext(f"{namespace}artifactId") or ""
        version = dependency.findtext(f"{namespace}version") or "0.0.0"
        if group and artifact:
            deps[f"{group}:{artifact}"] = version
    return deps


def read_go_mod(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    in_block = False
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith(("module", "//", "replace")):
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


def read_cargo_lock(path: Path) -> Dict[str, str]:
    content = read_toml(path)
    out: Dict[str, str] = {}
    for package in content.get("package", []):
        if isinstance(package, dict):
            name = package.get("name")
            version = package.get("version")
            if isinstance(name, str) and isinstance(version, str):
                out[name] = version
    return out


def read_composer_lock(path: Path) -> Dict[str, str]:
    data = read_json(path)
    out: Dict[str, str] = {}
    for section in ("packages", "packages-dev"):
        for package in data.get(section, []):
            if isinstance(package, dict):
                name = package.get("name")
                version = package.get("version")
                if isinstance(name, str) and isinstance(version, str):
                    out[name] = version
    return out


def read_environment_yml(path: Path) -> Dict[str, str]:
    data = read_yaml(path) or {}
    deps = data.get("dependencies", [])
    out: Dict[str, str] = {}
    for entry in deps:
        if isinstance(entry, str) and "=" in entry:
            name, version = entry.split("=", 1)
            out[name] = version
        elif isinstance(entry, dict) and "pip" in entry:
            for package in entry["pip"]:
                if "==" in package:
                    name, version = package.split("==", 1)
                    out[name] = version
                else:
                    out[package] = "*"
    return out


def read_brewfile(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
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


def read_packages_lock(path: Path) -> Dict[str, str]:
    data = read_json(path)
    out: Dict[str, str] = {}
    dependencies = data.get("dependencies", {})
    if isinstance(dependencies, dict):
        for name, info in dependencies.items():
            if isinstance(info, dict) and "resolved" in info:
                version = info.get("resolved", "0.0.0")
            else:
                version = info.get("version", "0.0.0") if isinstance(info, dict) else "0.0.0"
            out[name] = version
    return out


def read_dockerfile(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("RUN"):
            for segment in line.split("&&"):
                segment = segment.strip()
                if "pip install" in segment:
                    packages = segment.split("pip install", 1)[1].strip().split()
                    for package in packages:
                        if "==" in package:
                            name, version = package.split("==", 1)
                            out[f"pypi:{name}"] = version
                if "npm install" in segment:
                    packages = segment.split("npm install", 1)[1].strip().split()
                    for package in packages:
                        if "@" in package:
                            name, version = package.split("@", 1)
                            out[f"npm:{name}"] = version
    return out
