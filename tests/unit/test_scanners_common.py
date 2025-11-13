from __future__ import annotations

from pathlib import Path

import pytest

from rtx.scanners.common import (
    _extract_include_directives,
    _is_more_specific,
    _normalize_lock_name,
    _normalize_specifier,
    _parse_conda_dependency,
    _parse_requirement_line,
    load_json_dependencies,
    load_lock_dependencies,
    merge_dependency_version,
    normalize_version,
    read_dockerfile,
    read_gemfile_lock,
    read_go_mod,
    read_pnpm_lock,
    read_poetry_lock,
    read_requirements,
    read_uv_lock,
    read_cargo_lock,
)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("", None),
        ("# comment", None),
        ("-r requirements.txt", None),
        ("name==", None),
        ("name == 1.2.3", ("name", "1.2.3")),
        ("name==1.2.3", ("name", "1.2.3")),
        ("name", ("name", "*")),
        ("name==1.2.3 # comment", ("name", "1.2.3")),
        ("name @ https://example.com/pkg.zip", ("name", "@ https://example.com/pkg.zip")),
        ("name>=1.2.3", ("name", ">=1.2.3")),
        ("name<2.0.0,>=1.2.3", ("name", ">=1.2.3,<2.0.0")),
        ("invalid-package-name>", None),
        ("name==1.2.3.", ("name", "1.2.3.")),
        ("==1.2.3", None),
    ],
)
def test_parse_requirement_line(line: str, expected: tuple[str, str] | None) -> None:
    assert _parse_requirement_line(line) == expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("", None),
        ("# comment", None),
        ("conda-forge::name", ("name", "*")),
        ("conda-forge::name=1.2.3", ("name", "1.2.3")),
        ("name=1.2.3", ("name", "1.2.3")),
        ("name", ("name", "*")),
        ("name 1.2.3", ("name", "1.2.3")),
        ("name @ https://example.com/pkg.zip", ("name", "@ https://example.com/pkg.zip")),
        ("name>=1.0.0", ("name", ">=1.0.0")),
        ("name=", ("name", "*")),
        ("   ", None),
    ],
)
def test_parse_conda_dependency(line: str, expected: tuple[str, str] | None) -> None:
    assert _parse_conda_dependency(line) == expected


def test_merge_dependency_version() -> None:
    store: dict[str, str] = {}
    assert merge_dependency_version(store, "name", "1.2.3") is True
    assert store["name"] == "1.2.3"
    assert merge_dependency_version(store, "name", "1.2.3") is False
    assert store["name"] == "1.2.3"
    assert merge_dependency_version(store, "name", "*") is False
    assert store["name"] == "1.2.3"
    assert merge_dependency_version(store, "name", ">=1.2.3") is False
    assert store["name"] == "1.2.3"
    assert merge_dependency_version(store, "name", "@ https://example.com/pkg.zip") is True
    assert store["name"] == "@ https://example.com/pkg.zip"

    # Test case for existing being more specific
    store = {"name": "==2.0.0"}
    assert merge_dependency_version(store, "name", ">1.0.0") is False
    assert store["name"] == "==2.0.0"

    # Test case for both being unspecific
    store = {"name": "*"}
    assert merge_dependency_version(store, "name", "*") is False
    assert store["name"] == "*"

    # Test case for existing being a version, candidate being unspecific
    store = {"name": "1.0.0"}
    assert merge_dependency_version(store, "name", "*") is False
    assert store["name"] == "1.0.0"

    # New test case: candidate is more specific than existing (>1.0.0 vs ==2.0.0)
    store = {"name": ">1.0.0"}
    assert merge_dependency_version(store, "name", "==2.0.0") is True
    assert store["name"] == "==2.0.0"

    # Test case for existing being unspecific and candidate being specific
    store = {"name": "*"}
    assert merge_dependency_version(store, "name", "1.2.3") is True
    assert store["name"] == "1.2.3"

    # New test case: normalized_candidate == normalized_existing
    store = {"name": "==1.2.3"}
    assert merge_dependency_version(store, "name", "==1.2.3") is False
    assert store["name"] == "==1.2.3"


def test_merge_dependency_version_unspecific_to_specific() -> None:
    store = {"name": ""}
    assert merge_dependency_version(store, "name", "1.2.3") is True
    assert store["name"] == "1.2.3"


def test_is_more_specific() -> None:
    assert _is_more_specific("==2.0.0", ">1.0.0") is True
    assert _is_more_specific(">1.0.0", "==2.0.0") is False
    assert _is_more_specific("1.0.0", "*") is True
    assert _is_more_specific("*", "1.0.0") is False
    assert _is_more_specific("==1.0.0", "==1.0.0") is False


@pytest.mark.parametrize(
    ("specifier", "expected"),
    [
        (None, "*"),
        ("", "*"),
        ("   ", "*"),
        ("1.2.3", "1.2.3"),
        ("==1.2.3", "==1.2.3"),
    ],
)
def test_normalize_specifier(specifier: str | None, expected: str) -> None:
    assert _normalize_specifier(specifier) == expected


@pytest.mark.parametrize(
    ("raw_version", "expected"),
    [
        ("", "0.0.0"),
        ("   ", "0.0.0"),
        ("1.2.3", "1.2.3"),
        ("invalid-version", "invalid-version"),
        (None, "0.0.0"),
    ],
)
def test_normalize_version(raw_version: str, expected: str) -> None:
    assert normalize_version(raw_version) == expected


def test_load_json_dependencies(tmp_path: Path) -> None:
    # Test case for a JSON file that is a dictionary and contains the key
    (tmp_path / "deps.json").write_text('{"dependencies": {"name": "1.2.3"}}')
    assert load_json_dependencies(tmp_path / "deps.json") == {"name": "1.2.3"}

    # Test case for a JSON file that is a dictionary but does not contain the key
    (tmp_path / "empty.json").write_text('{"other": "value"}')
    assert load_json_dependencies(tmp_path / "empty.json") == {}

    # Test case for a JSON file that is not a dictionary (e.g., a JSON array)
    (tmp_path / "array.json").write_text('["name", "1.2.3"]')
    assert load_json_dependencies(tmp_path / "array.json") == {}

    # Test case for a JSON file that is not a dictionary (e.g., a primitive value)
    (tmp_path / "primitive.json").write_text('"just_a_string"')
    assert load_json_dependencies(tmp_path / "primitive.json") == {}


def test_load_lock_dependencies(tmp_path: Path) -> None:
    # Test case for a lock file with "packages" key and valid metadata
    (tmp_path / "lock1.json").write_text(
        """
        {
            "packages": {
                "name": {"version": "1.2.3"},
                "other": {"version": "4.5.6"}
            }
        }
        """
    )
    assert load_lock_dependencies(tmp_path / "lock1.json") == {"name": "1.2.3", "other": "4.5.6"}

    # Test case for a lock file with "packages" key but empty
    (tmp_path / "lock2.json").write_text(
        """
        {
            "packages": {}
        }
        """
    )
    assert load_lock_dependencies(tmp_path / "lock2.json") == {}

    # Test case for a lock file with "packages" key but non-dict metadata
    (tmp_path / "lock3.json").write_text(
        """
        {
            "packages": {
                "name": "1.2.3"
            }
        }
        """
    )
    assert load_lock_dependencies(tmp_path / "lock3.json") == {"name": "0.0.0"}

    # Test case for a lock file with "dependencies" key and valid metadata
    (tmp_path / "lock4.json").write_text(
        """
        {
            "dependencies": {
                "name": {"version": "1.2.3"},
                "other": {"version": "4.5.6"}
            }
        }
        """
    )
    assert load_lock_dependencies(tmp_path / "lock4.json") == {"name": "1.2.3", "other": "4.5.6"}

    # Test case for package with resolved field
    packages_lock = tmp_path / "packages.lock.json"
    packages_lock.write_text(
        """
        {
            "dependencies": {
                "name": {
                    "resolved": "1.2.3"
                }
            }
        }
        """
    )
    dependencies = load_lock_dependencies(packages_lock)
    assert dependencies == {"name": "1.2.3"}

    # Test case for a lock file with "dependencies" key but empty
    (tmp_path / "lock5.json").write_text(
        """
        {
            "dependencies": {}
        }
        """
    )
    assert load_lock_dependencies(tmp_path / "lock5.json") == {}

    # Test case for a lock file with "dependencies" key but non-dict metadata
    (tmp_path / "lock6.json").write_text(
        """
        {
            "dependencies": {
                "name": "1.2.3"
            }
        }
        """
    )
    assert load_lock_dependencies(tmp_path / "lock6.json") == {"name": "0.0.0"}
    # Test case for a lock file that is not a dictionary (e.g., a JSON array)
    (tmp_path / "lock7.json").write_text("[1, 2, 3]")
    assert load_lock_dependencies(tmp_path / "lock7.json") == {}

    # Test case for a dictionary lock file without "packages" or "dependencies" keys
    (tmp_path / "lock8.json").write_text('{"foo": "bar"}')
    assert load_lock_dependencies(tmp_path / "lock8.json") == {}


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("name", "name"),
        ("./name", "name"),
        ("node_modules/name", "name"),
        ("node_modules/@scope/name", "@scope/name"),
    ],
)
def test_normalize_lock_name(name: str, expected: str) -> None:
    assert _normalize_lock_name(name) == expected


def test_read_poetry_lock(tmp_path: Path) -> None:
    # Test case for a poetry.lock file with valid packages
    (tmp_path / "poetry.lock").write_text(
        """
        [[package]]
        name = "name"
        version = "1.2.3"

        [[package]]
        name = "other"
        version = "4.5.6"
        """
    )
    assert read_poetry_lock(tmp_path / "poetry.lock") == {"name": "1.2.3", "other": "4.5.6"}

    # Test case for a poetry.lock file with an empty [[package]] section
    (tmp_path / "empty_poetry.lock").write_text(
        """
        # Empty lock file
        """
    )
    assert read_poetry_lock(tmp_path / "empty_poetry.lock") == {}

    # Test case for a poetry.lock file where package is not a dictionary
    (tmp_path / "invalid_package.lock").write_text(
        """
        [[package]]
        "just_a_string"
        """
    )
    assert read_poetry_lock(tmp_path / "invalid_package.lock") == {}

    # Test case for a poetry.lock file where name or version are not strings
    (tmp_path / "invalid_name_version.lock").write_text(
        """
        [[package]]
        name = 123
        version = 4.5
        """
    )
    assert read_poetry_lock(tmp_path / "invalid_name_version.lock") == {}


def test_read_uv_lock_initial_parsing(tmp_path: Path) -> None:
    # Test case for a uv.lock file where the "package" key contains a single dictionary
    (tmp_path / "single_package.lock").write_text(
        """
        version = 1

        [[package]]
        name = "single-name"
        version = "1.0.0"
        """
    )
    assert read_uv_lock(tmp_path / "single_package.lock") == {"single-name": "1.0.0"}

    # Test case for a uv.lock file where the "package" list contains a non-dictionary item
    (tmp_path / "non_dict_package.lock").write_text(
        """
        version = 1

        [[package]]
        name = "name1"
        version = "1.0.0"

        [[package]]
        "just_a_string"

        [[package]]
        name = "name2"
        version = "2.0.0"
        """
    )
    assert read_uv_lock(tmp_path / "non_dict_package.lock") == {}


def test_read_uv_lock_direct_names_virtual_source(tmp_path: Path) -> None:
    # Test case for direct_names population when source.get("virtual") == "."
    (tmp_path / "virtual_source.lock").write_text(
        """
        version = 1

        [[package]]
        name = "transitive-dep"
        version = "1.0.0"
        source = { virtual = "." }
        dependencies = [ { name = "transitive-dep" } ]

        [[package]]
        name = "dep2"
        version = "2.0.0"
        """
    )
    assert read_uv_lock(tmp_path / "virtual_source.lock") == {"transitive-dep": "1.0.0"}


def test_read_uv_lock_direct_names_project_dependencies(tmp_path: Path) -> None:
    # Test case for direct_names population when not direct_names and project dependencies exist
    (tmp_path / "project_deps.lock").write_text(
        """
        version = 1

        [project]
        dependencies = ["project-dep1==1.0.0", "project-dep2"]

        [[package]]
        name = "project-dep1"
        version = "1.0.0"

        [[package]]
        name = "project-dep2"
        version = "2.0.0"
        """
    )
    assert read_uv_lock(tmp_path / "project_deps.lock") == {
        "project-dep1": "1.0.0",
        "project-dep2": "2.0.0",
    }


def test_read_uv_lock_direct_names_dependency_groups(tmp_path: Path) -> None:
    # Test case for direct_names population when not direct_names and dependency_groups exist
    (tmp_path / "group_deps.lock").write_text(
        """
        version = 1

        [dependency-groups.dev]
        dependencies = ["dev-dep1==1.0.0", "dev-dep2"]

        [[package]]
        name = "dev-dep1"
        version = "1.0.0"

        [[package]]
        name = "dev-dep2"
        version = "2.0.0"
        """
    )
    assert read_uv_lock(tmp_path / "group_deps.lock") == {"dev-dep1": "1.0.0", "dev-dep2": "2.0.0"}


def test_read_uv_lock_no_direct_names_fallback(tmp_path: Path) -> None:
    # Test case for results population when no direct_names are found, falling back to all packages
    (tmp_path / "fallback.lock").write_text(
        """
        version = 1

        [[package]]
        name = "fallback-name1"
        version = "1.0.0"

        [[package]]
        name = "fallback-name2"
        version = "2.0.0"
        """
    )
    assert read_uv_lock(tmp_path / "fallback.lock") == {
        "fallback-name1": "1.0.0",
        "fallback-name2": "2.0.0",
    }


def test_read_dockerfile_continuation(tmp_path: Path) -> None:
    # Test case covering multiline RUN commands with continuations and empty lines
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
        FROM python:3.9
        RUN apt-get update && \
            apt-get install -y cowsay \
            && rm -rf /var/lib/apt/lists/*
        RUN pip install name1==1.0.0 && \
            name2==2.0.0 \
            && name3==3.0.0
        RUN pip install name4
        """
    )
    dependencies = read_dockerfile(dockerfile)
    assert dependencies == {"pypi:name1": "1.0.0", "pypi:name2": "2.0.0", "pypi:name3": "3.0.0", "pypi:name4": "*"}


def test_read_dockerfile_empty_segment(tmp_path: Path) -> None:
    # Test case covering empty segments in RUN commands (line 497)
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
        FROM python:3.9
        RUN pip install name==1.0.0 && ; && pip install other==2.0.0
        """
    )
    dependencies = read_dockerfile(dockerfile)
    assert dependencies == {"pypi:name": "1.0.0", "pypi:other": "2.0.0"}


def test_read_dockerfile_pip_no_name(tmp_path: Path) -> None:
    # Test case covering pip install without a package name (line 525)
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
        FROM python:3.9
        RUN pip install -r requirements.txt
        """
    )
    dependencies = read_dockerfile(dockerfile)
    assert dependencies == {}


def test_read_dockerfile_npm_flags_with_args(tmp_path: Path) -> None:
    # Test case covering npm install with flags that have arguments (line 543->539)
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
        FROM node:16
        RUN npm install --prefix /app name@1.0.0 --registry https://registry.npmjs.org/ other@2.0.0 another
        """
    )
    dependencies = read_dockerfile(dockerfile)
    assert dependencies == {"npm:name": "1.0.0", "npm:other": "2.0.0", "npm:another": "*"}


def test_read_dockerfile_npm_parsed_none(tmp_path: Path) -> None:
    # Test case covering npm install where _parse_npm_token returns None (lines 571-573)
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
        FROM node:16
        RUN npm install --prefix
        """
    )
    dependencies = read_dockerfile(dockerfile)
    assert dependencies == {}


def test_read_dockerfile_npm_scoped_package_with_version(tmp_path: Path) -> None:
    # Test case covering npm install with a scoped package and version that hits 581->580
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
        FROM node:16
        RUN npm install @scope/pkg@1.2.3 @scope/pkg2
        """
    )
    dependencies = read_dockerfile(dockerfile)
    assert dependencies == {"npm:@scope/pkg": "1.2.3", "npm:@scope/pkg2": "*"}


def test_read_dockerfile_npm_package_without_version(tmp_path: Path) -> None:
    # Test case covering npm install with a package name but no version (line 594->593, 597->593)
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
        FROM node:16
        RUN npm install pkg
        """
    )
    dependencies = read_dockerfile(dockerfile)
    assert dependencies == {"npm:pkg": "*"}


def test_extract_include_directives_prefixed_flags(tmp_path: Path) -> None:
    # Test case for _extract_include_directives with prefixed flags
    tokens = ["--requirement=req.txt", "--constraint=con.txt"]
    directives = _extract_include_directives(tokens)
    assert directives == [("requirement", "req.txt"), ("constraint", "con.txt")]

    # Test case for -r flag with no value
    tokens = ["-r"]
    directives = _extract_include_directives(tokens)
    assert directives == []


def test_extract_include_directives_empty_value(tmp_path: Path) -> None:
    # Test case covering _extract_include_directives when value is empty (line 628->624)
    tokens = ["--requirement="]
    directives = _extract_include_directives(tokens)
    assert directives == []


def test_read_requirements(tmp_path: Path) -> None:
    (tmp_path / "base.txt").write_text("name==1.2.3")
    (tmp_path / "constraints.txt").write_text("name==1.2.3\nother==4.5.6")
    (tmp_path / "requirements.txt").write_text("-r base.txt\n-c constraints.txt")
    requirements = read_requirements(tmp_path / "requirements.txt")
    assert requirements == {"name": "1.2.3", "other": "4.5.6"}

    # Test case for absolute_path in _seen (lines 346-347)
    (tmp_path / "seen.txt").write_text("seen-name==1.0.0")
    seen_path = tmp_path / "seen.txt"
    _seen_set = {seen_path.resolve()}
    assert read_requirements(seen_path, _seen=_seen_set) == {}

    # Test case for empty or comment-only line (lines 354-355)
    (tmp_path / "empty_comment.txt").write_text("""# comment\n\nname==1.0.0""")
    assert read_requirements(tmp_path / "empty_comment.txt") == {"name": "1.0.0"}

    # Test case for ValueError in shlex.split (lines 361-362)
    (tmp_path / "shlex_error.txt").write_text('name==1.0.0 "unclosed_quote')
    assert read_requirements(tmp_path / "shlex_error.txt") == {"name": '1.0.0 "unclosed_quote'}

    # Test case for not candidate.exists() (lines 369-370)
    (tmp_path / "non_existent_include.txt").write_text("""-r non_existent.txt
name==1.0.0""")
    assert read_requirements(tmp_path / "non_existent_include.txt") == {"name": "1.0.0"}

    # Test case for invalid package name
    (tmp_path / "invalid_package.txt").write_text("invalid-package-name>")
    assert read_requirements(tmp_path / "invalid_package.txt") == {}


def test_read_go_mod_single_require(tmp_path: Path) -> None:
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        """
        module example.com/my/module
        go 1.18
        require example.com/other/module v1.2.3
        """
    )
    dependencies = read_go_mod(go_mod)
    assert dependencies == {
        "example.com/other/module": "v1.2.3",
    }

    # Test case for line without version
    go_mod.write_text(
        """
        module example.com/my/module
        go 1.18
        require example.com/other/module
        """
    )
    dependencies = read_go_mod(go_mod)
    assert dependencies == {}


def test_read_gemfile_lock(tmp_path: Path) -> None:
    gemfile_lock = tmp_path / "Gemfile.lock"
    gemfile_lock.write_text(
        """
        GEM
          remote: https://rubygems.org/
          specs:
            name (1.2.3)
            other (4.5.6)
        """
    )
    dependencies = read_gemfile_lock(gemfile_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}

    # Test case for line starting with a space
    gemfile_lock_space = tmp_path / "Gemfile.lock_space"
    gemfile_lock_space.write_text(
        """
        GEM
          remote: https://rubygems.org/
          specs:
             name (1.2.3)
        """
    )
    dependencies = read_gemfile_lock(gemfile_lock_space)
    assert dependencies == {"name": "1.2.3"}

    # Test case for line without version
    gemfile_lock_no_version = tmp_path / "Gemfile.lock_no_version"
    gemfile_lock_no_version.write_text(
        """
        GEM
          remote: https://rubygems.org/
          specs:
            name
        """
    )
    dependencies = read_gemfile_lock(gemfile_lock_no_version)
    assert dependencies == {}


def test_read_pnpm_lock(tmp_path: Path) -> None:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    # Test case for a pnpm-lock.yaml file with valid packages
    pnpm_lock.write_text(
        """
        packages:
          /name/1.2.3:
            resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}
            dev: false
        """
    )
    dependencies = read_pnpm_lock(pnpm_lock)
    assert dependencies == {"name": "1.2.3"}

    # Test case for package with specifier field
    pnpm_lock.write_text(
        """
        packages:
          /name/1.2.3:
            specifier: "1.2.3"
            resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}
            dev: false
        """
    )
    dependencies = read_pnpm_lock(pnpm_lock)
    assert dependencies == {"name": "1.2.3"}

    # Test case for package missing version
    pnpm_lock.write_text(
        """
        packages:
          /name/:
            resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}
            dev: false
        """
    )
    dependencies = read_pnpm_lock(pnpm_lock)
    assert dependencies == {}
def test_read_cargo_lock(tmp_path: Path) -> None:
    cargo_lock = tmp_path / "Cargo.lock"
    cargo_lock.write_text(
        """
        [[package]]
        name = "name"
        version = "1.2.3"

        [[package]]
        name = "other"
        version = "4.5.6"
        """
    )
    dependencies = read_cargo_lock(cargo_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}

    # Test case for package missing version
    cargo_lock.write_text(
        """
        [[package]]
        name = "name"
        """
    )
    dependencies = read_cargo_lock(cargo_lock)
    assert dependencies == {}
