from __future__ import annotations

from pathlib import Path

from rtx.scanners.maven import MavenScanner


def test_maven_scanner_supports_gradle_named_arguments(tmp_path: Path) -> None:
    build_gradle = tmp_path / "build.gradle"
    build_gradle.write_text(
        """
        plugins {
            id("java-library")
        }

        dependencies {
            implementation group: 'com.example', name: 'demo', version: '1.2.3'
            compileOnly(group = "org.sample", name = "sample-kt", version = "0.9.0")
            api("org.legacy:legacy-core:4.5.6")
            implementation project(":internal") // ignored because not an external coordinate
            runtimeOnly group: 'missing', name: 'without-version'
        }
        """,
        encoding="utf-8",
    )

    scanner = MavenScanner()
    result = scanner.scan(tmp_path)

    by_name = {dependency.name: dependency for dependency in result}

    assert "com.example:demo" in by_name
    assert by_name["com.example:demo"].version == "1.2.3"
    assert by_name["com.example:demo"].metadata["source"] == "build.gradle"

    assert "org.sample:sample-kt" in by_name
    assert by_name["org.sample:sample-kt"].version == "0.9.0"

    assert "org.legacy:legacy-core" in by_name
    assert by_name["org.legacy:legacy-core"].version == "4.5.6"

    assert "missing:without-version" not in by_name
