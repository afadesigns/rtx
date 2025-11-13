from __future__ import annotations

from pathlib import Path

import pytest

from rtx.scanners.common import (
    _clean_pnpm_version,
    _extract_include_directives,
    _npm_install_start,
    _parse_conda_dependency,
    _parse_npm_token,
    _parse_pnpm_package_key,
    _parse_requirement_line,
    _pip_install_start,
    _specificity_rank,
    _is_more_specific,
    _normalize_specifier,
    merge_dependency_version,
    normalize_version,
    load_json_dependencies,
    load_lock_dependencies,
    _normalize_lock_name,
    read_brewfile,
    read_cargo_lock,
    read_composer_lock,
    read_dockerfile,
    read_environment_yml,
    read_gemfile_lock,
    read_go_mod,
    read_maven_pom,
    read_packages_lock,
    read_pnpm_lock,
    read_poetry_lock,
    read_requirements,
    read_uv_lock,
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

    # New test case: candidate is more specific than existing (e.g., existing >1.0.0, candidate ==2.0.0)
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
        '''
        {
            "packages": {
                "name": {"version": "1.2.3"},
                "other": {"version": "4.5.6"}
            }
        }
        '''
    )
    assert load_lock_dependencies(tmp_path / "lock1.json") == {"name": "1.2.3", "other": "4.5.6"}

    # Test case for a lock file with "packages" key but empty
    (tmp_path / "lock2.json").write_text(
        '''
        {
            "packages": {}
        }
        '''
    )
    assert load_lock_dependencies(tmp_path / "lock2.json") == {}

    # Test case for a lock file with "packages" key but non-dict metadata
    (tmp_path / "lock3.json").write_text(
        '''
        {
            "packages": {
                "name": "1.2.3"
            }
        }
        '''
    )
    assert load_lock_dependencies(tmp_path / "lock3.json") == {"name": "0.0.0"}

    # Test case for a lock file with "dependencies" key and valid metadata
    (tmp_path / "lock4.json").write_text(
        '''
        {
            "dependencies": {
                "name": {"version": "1.2.3"},
                "other": {"version": "4.5.6"}
            }
        }
        '''
    )
    assert load_lock_dependencies(tmp_path / "lock4.json") == {"name": "1.2.3", "other": "4.5.6"}

    # Test case for a lock file with "dependencies" key but empty
    (tmp_path / "lock5.json").write_text(
        '''
        {
            "dependencies": {}
        }
        '''
    )
    assert load_lock_dependencies(tmp_path / "lock5.json") == {}

    # Test case for a lock file with "dependencies" key but non-dict metadata
    (tmp_path / "lock6.json").write_text(
        '''
        {
            "dependencies": {
                "name": "1.2.3"
            }
        }
        '''
    )
    assert load_lock_dependencies(tmp_path / "lock6.json") == {}

    # Test case for a lock file that is not a dictionary (e.g., a JSON array)
    (tmp_path / "lock7.json").write_text('[1, 2, 3]')
    assert load_lock_dependencies(tmp_path / "lock7.json") == {}

    # Test case for a lock file that is a dictionary but contains neither "packages" nor "dependencies" keys
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
        '''
        [[package]]
        name = "name"
        version = "1.2.3"

        [[package]]
        name = "other"
        version = "4.5.6"
        '''
    )
    assert read_poetry_lock(tmp_path / "poetry.lock") == {"name": "1.2.3", "other": "4.5.6"}

    # Test case for a poetry.lock file with an empty [[package]] section
    (tmp_path / "empty_poetry.lock").write_text(
        '''
        # Empty lock file
        '''
    )
    assert read_poetry_lock(tmp_path / "empty_poetry.lock") == {}

    # Test case for a poetry.lock file where package is not a dictionary
    (tmp_path / "invalid_package.lock").write_text(
        '''
        [[package]]
        "just_a_string"
        '''
    )
    assert read_poetry_lock(tmp_path / "invalid_package.lock") == {}

    # Test case for a poetry.lock file where name or version are not strings
    (tmp_path / "invalid_name_version.lock").write_text(
        '''
        [[package]]
        name = 123
        version = 4.5
        '''
    )
    assert read_poetry_lock(tmp_path / "invalid_name_version.lock") == {}


def test_read_uv_lock_initial_parsing(tmp_path: Path) -> None:
    # Test case for a uv.lock file where the "package" key contains a single dictionary
    (tmp_path / "single_package.lock").write_text(
        '''
        version = 1

        [[package]]
        name = "single-name"
        version = "1.0.0"
        '''
    )
    assert read_uv_lock(tmp_path / "single_package.lock") == {"single-name": "1.0.0"}

    # Test case for a uv.lock file where the "package" list contains a non-dictionary item
    (tmp_path / "non_dict_package.lock").write_text(
        '''
        version = 1

        [[package]]
        name = "name1"
        version = "1.0.0"

        [[package]]
        "just_a_string"

        [[package]]
        name = "name2"
        version = "2.0.0"
        '''
    )
    assert read_uv_lock(tmp_path / "non_dict_package.lock") == {}


def test_read_uv_lock_direct_names_virtual_source(tmp_path: Path) -> None:
    # Test case for direct_names population when source.get("virtual") == "."
    (tmp_path / "virtual_source.lock").write_text(
        '''
        version = 1

        [[package]]
        name = "dep1"
        version = "1.0.0"
        source = { virtual = "." }
        dependencies = [ { name = "transitive-dep" } ]

        [[package]]
        name = "dep2"
        version = "2.0.0"
        '''
    )
    assert read_uv_lock(tmp_path / "virtual_source.lock") == {"transitive-dep": "*"}


def test_read_uv_lock_direct_names_project_dependencies(tmp_path: Path) -> None:
    # Test case for direct_names population when not direct_names and project dependencies exist
    (tmp_path / "project_deps.lock").write_text(
        '''
        version = 1

        [project]
        dependencies = ["project-dep1==1.0.0", "project-dep2"]

        [[package]]
        name = "project-dep1"
        version = "1.0.0"

        [[package]]
        name = "project-dep2"
        version = "2.0.0"
        '''
    )
    assert read_uv_lock(tmp_path / "project_deps.lock") == {"project-dep1": "1.0.0", "project-dep2": "2.0.0"}


def test_read_uv_lock_direct_names_dependency_groups(tmp_path: Path) -> None:
    # Test case for direct_names population when not direct_names and dependency_groups exist
    (tmp_path / "group_deps.lock").write_text(
        '''
        version = 1

        [dependency-groups.dev]
        dependencies = ["dev-dep1==1.0.0", "dev-dep2"]

        [[package]]
        name = "dev-dep1"
        version = "1.0.0"

        [[package]]
        name = "dev-dep2"
        version = "2.0.0"
        '''
    )
    assert read_uv_lock(tmp_path / "group_deps.lock") == {"dev-dep1": "1.0.0", "dev-dep2": "2.0.0"}


def test_read_uv_lock_no_direct_names_fallback(tmp_path: Path) -> None:
    # Test case for results population when no direct_names are found, falling back to all packages
    (tmp_path / "fallback.lock").write_text(
        '''
        version = 1

        [[package]]
        name = "fallback-name1"
        version = "1.0.0"

        [[package]]
        name = "fallback-name2"
        version = "2.0.0"
        '''
    )
    assert read_uv_lock(tmp_path / "fallback.lock") == {"fallback-name1": "1.0.0", "fallback-name2": "2.0.0"}


def test_read_requirements(tmp_path: Path) -> None:
    (tmp_path / "base.txt").write_text("name==1.2.3")
    (tmp_path / "constraints.txt").write_text("name==1.2.3\nother==4.5.6")
    (tmp_path / "requirements.txt").write_text("-r base.txt\n-c constraints.txt")
    requirements = read_requirements(tmp_path / "requirements.txt")
    assert requirements == {"name": "1.2.3", "other": "4.5.6"}


def test_read_dockerfile(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
        FROM python:3.11
        RUN pip install name==1.2.3
        RUN npm install other@4.5.6 && \
            pip install another==7.8.9
        """
    )
    dependencies = read_dockerfile(dockerfile)
    assert dependencies == {
        "pypi:name": "1.2.3",
        "npm:other": "4.5.6",
        "pypi:another": "7.8.9",
    }


def test_read_go_mod(tmp_path: Path) -> None:
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        """
        module example.com/my/module
        go 1.18
        require (
            example.com/other/module v1.2.3
            example.com/another/module v4.5.6
        )
        """
    )
    dependencies = read_go_mod(go_mod)
    assert dependencies == {
        "example.com/other/module": "v1.2.3",
        "example.com/another/module": "v4.5.6",
    }


def test_read_brewfile(tmp_path: Path) -> None:
    brewfile = tmp_path / "Brewfile"
    brewfile.write_text(
        """
        brew "name"
        brew "other", version: "1.2.3"
        """
    )
    dependencies = read_brewfile(brewfile)
    assert dependencies == {"name": "latest", "other": "1.2.3"}


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


def test_read_composer_lock(tmp_path: Path) -> None:
    composer_lock = tmp_path / "composer.lock"
    composer_lock.write_text(
        """
        {
            "packages": [
                {
                    "name": "name",
                    "version": "1.2.3"
                },
                {
                    "name": "other",
                    "version": "4.5.6"
                }
            ]
        }
        """
    )
    dependencies = read_composer_lock(composer_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}


def test_read_maven_pom(tmp_path: Path) -> None:
    pom_xml = tmp_path / "pom.xml"
    pom_xml.write_text(
        """
        <project>
            <dependencies>
                <dependency>
                    <groupId>group</groupId>
                    <artifactId>name</artifactId>
                    <version>1.2.3</version>
                </dependency>
                <dependency>
                    <groupId>group</groupId>
                    <artifactId>other</artifactId>
                    <version>4.5.6</version>
                </dependency>
            </dependencies>
        </project>
        """
    )
    dependencies = read_maven_pom(pom_xml)
    assert dependencies == {"group:name": "1.2.3", "group:other": "4.5.6"}


def test_read_environment_yml(tmp_path: Path) -> None:
    environment_yml = tmp_path / "environment.yml"
    environment_yml.write_text(
        """
        dependencies:
          - conda-forge::name=1.2.3
          - other==4.5.6
          - pip:
            - pip-name==7.8.9
        """
    )
    dependencies = read_environment_yml(environment_yml)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6", "pip-name": "7.8.9"}


def test_read_packages_lock(tmp_path: Path) -> None:
    packages_lock = tmp_path / "packages.lock.json"
    packages_lock.write_text(
        """
        {
            "dependencies": {
                "name": {
                    "version": "1.2.3"
                },
                "other": {
                    "resolved": "4.5.6"
                }
            }
        }
        """
    )
    dependencies = read_packages_lock(packages_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}


def test_read_uv_lock(tmp_path: Path) -> None:
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        """
        version = 1

        [[package]]
        name = "name"
        version = "1.2.3"

        [[package]]
        name = "other"
        version = "4.5.6"
        """
    )
    dependencies = read_uv_lock(uv_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}


def test_read_pnpm_lock(tmp_path: Path) -> None:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        """
        packages:
          /name/1.2.3:
            resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}
            dev: false
          /other/4.5.6:
            resolution: {integrity: sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=}
            dev: true
        """
    )
    dependencies = read_pnpm_lock(pnpm_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}


@pytest.mark.parametrize(
    ("key", "expected_name", "expected_version"),
    [
        ("", None, None),
        ("/name/1.2.3", "name", "1.2.3"),
        ("/@scope/name/1.2.3", "@scope/name", "1.2.3"),
        ("name@1.2.3", "name", "1.2.3"),
        ("@scope/name@1.2.3", "@scope/name", "1.2.3"),
        ("node_modules/name", "name", None),
        ("node_modules/@scope/name", "@scope/name", None),
        ("name", "name", None),
        ("@scope/name", "@scope/name", None),
        ("/name", "name", None),
        ("/@scope/name", "@scope/name", None),
        ("name/1.2.3", "name", "1.2.3"),
        ("@scope/name/1.2.3", "@scope/name", "1.2.3"),
        # Additional cases for robustness
        ("name@^1.0.0", "name", "^1.0.0"),
        ("@scope/name@~1.0.0", "@scope/name", "~1.0.0"),
        ("name@latest", "name", "latest"),
        ("/name", "name", None),
        ("/@scope/name", "@scope/name", None),
        ("node_modules/name/1.2.3", "name", "1.2.3"),
        ("node_modules/@scope/name/1.2.3", "@scope/name", "1.2.3"),
    ],
)
def test_parse_pnpm_package_key(key: str, expected_name: str | None, expected_version: str | None) -> None:
    name, version = _parse_pnpm_package_key(key)
    assert name == expected_name
    assert version == expected_version


@pytest.mark.parametrize(
    ("raw_version", "expected_version"),
    [
        (None, None),
        ("", None),
        ("1.2.3", "1.2.3"),
        ("1.2.3 (some-hash)", "1.2.3"),
        ("link:../foo", None),
        ("workspace:^1.0.0", None),
        ("file:../foo.tgz", None),
        ("github:user/repo", None),
        ("git+ssh://git@github.com/user/repo.git", None),
        ("npm:name@1.2.3", "1.2.3"),
        ("npm:@scope/name@1.2.3", "1.2.3"),
    ],
)
def test_clean_pnpm_version(raw_version: str | None, expected_version: str | None) -> None:
    assert _clean_pnpm_version(raw_version) == expected_version


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        ([], None),
        (["pip", "install"], 2),
        (["pip3", "install"], 2),
        (["python", "-m", "pip", "install"], 4),
        (["python3", "-m", "pip", "install"], 4),
        (["pip", "uninstall"], None),
        (["npm", "install"], 2),
        (["npm", "uninstall"], None),
    ],
)
def test_pip_npm_install_start(tokens: list[str], expected: int | None) -> None:
    if tokens and tokens[0] in {"pip", "pip3", "python", "python3"}:
        assert _pip_install_start(tokens) == expected
        assert _npm_install_start(tokens) is None
    elif tokens and tokens[0] == "npm":
        assert _npm_install_start(tokens) == expected
        assert _pip_install_start(tokens) is None
    else:
        assert _pip_install_start(tokens) == expected
        assert _npm_install_start(tokens) == expected


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        ([], []),
        (["-r", "requirements.txt"], [("requirement", "requirements.txt")]),
        (["--requirement", "base.txt"], [("requirement", "base.txt")]),
        (["-c", "constraints.txt"], [("constraint", "constraints.txt")]),
        (["--constraint", "other.txt"], [("constraint", "other.txt")]),
        (["--requirement=dev.txt"], [("requirement", "dev.txt")]),
        (["--constraint=test.txt"], [("constraint", "test.txt")]),
        (["--requirement="], []),
        (["--constraint="], []),
        (["name==1.2.3"], []),
        (["-r", "req.txt", "-c", "con.txt"], [("requirement", "req.txt"), ("constraint", "con.txt")]),
        (["--requirement=req.txt", "--constraint=con.txt"], [("requirement", "req.txt"), ("constraint", "con.txt")]),
        (["-r", "req.txt", "name==1.2.3"], [("requirement", "req.txt")]),
    ],
)
def test_extract_include_directives(tokens: list[str], expected: list[tuple[str, str]]) -> None:
    assert _extract_include_directives(tokens) == expected


@pytest.mark.parametrize(
    ("specifier", "expected_rank"),
    [
        ("", 0),
        ("*", 0),
        ("@url", 5),
        ("==1.2.3", 4),
        (">1.0.0", 2),
        ("<2.0.0", 2),
        ("~1.0.0", 2),
        ("!1.0.0", 2),
        ("1.2.3", 4),
        ("   ", 0),
    ],
)
def test_specificity_rank(specifier: str, expected_rank: int) -> None:
    assert _specificity_rank(specifier) == expected_rank
