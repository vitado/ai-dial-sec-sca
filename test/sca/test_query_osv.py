"""Tests for actions/sca_query_osv/query_osv.py (synthetic data, fake commands)."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import query_osv as qo

NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)


# --- fakes and builders -------------------------------------------------------


def component(purl: str | None, kind: str = "library") -> dict[str, Any]:
    last = (purl or "lockfile").split("/")[-1]
    name, _, version = last.partition("@")
    return {
        "type": kind,
        "name": name,
        **({"version": version.split("?")[0]} if version else {}),
        **({"purl": purl} if purl else {}),
    }


BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"component": {"type": "container", "name": "image"}},
    "components": [
        component("pkg:npm/lodash@4.17.0"),
        component("pkg:pypi/requests@2.0.0"),
        component("pkg:deb/debian/zlib@1.2?distro=debian-12"),
        component("pkg:apk/alpine/musl@1.2.4-r0"),
        component("pkg:rpm/redhat/glibc@2.34"),
        component(None),
        component(None, kind="application"),
        component("pkg:oci/image@sha256:0", kind="container"),
    ],
    "dependencies": [{"ref": "a", "dependsOn": ["b"]}],
    "vulnerabilities": [{"id": "CVE-2030-1"}],
}


def osv_output(*packages: tuple[str, str, str], vulnerable: bool = False) -> dict:
    """An osv-scanner result (``--format json --all-packages``) of one BOM."""
    entries = []
    for ecosystem, name, version in packages:
        entry: dict[str, Any] = {
            "package": {"ecosystem": ecosystem, "name": name, "version": version}
        }
        if vulnerable:
            entry["vulnerabilities"] = [{"id": "GHSA-aaaa-aaaa-aaaa"}]
            entry["groups"] = [{"ids": ["GHSA-aaaa-aaaa-aaaa"], "max_severity": "7.5"}]
        entries.append(entry)
    source = {"path": "x.cdx.json", "type": "sbom"}
    return {"results": [{"source": source, "packages": entries}] if entries else []}


PACKAGES = (("npm", "lodash", "4.17.0"), ("PyPI", "requests", "2.0.0"))


class FakeCommands:
    """Stands in for ``trivy``, ``osv-scanner`` and ``docker``; records every command.

    ``scanner_exit``/``scanner_output``: what osv-scanner does (an output of
    False writes nothing; a string is written as is).
    """

    def __init__(
        self,
        bom: Any = BOM,
        convert_exit: int = 0,
        scanner_exit: int = 1,
        scanner_output: Any = None,
        scanner_stderr: str = "",
        image_exit: int | None = None,
        image_output: Any = None,
        docker_exit: int = 0,
    ) -> None:
        self.bom = bom
        self.convert_exit = convert_exit
        self.scanner_exit = scanner_exit
        self.scanner_output = (
            osv_output(*PACKAGES, vulnerable=True)
            if scanner_output is None
            else scanner_output
        )
        self.scanner_stderr = scanner_stderr
        self.image_exit = scanner_exit if image_exit is None else image_exit
        self.image_output = (
            osv_output(*PACKAGES, vulnerable=True)
            if image_output is None
            else image_output
        )
        self.docker_exit = docker_exit
        self.calls: list[list[str]] = []
        self.scanned_boms: list[dict[str, Any]] = []

    def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command = list(command)
        self.calls.append(command)
        if command[0] == "docker":
            return subprocess.CompletedProcess(command, self.docker_exit, "", "")
        if command[1] == "--version":
            out = "osv-scanner version: 2.6.0\nosv-scalibr version: 0.4.8\n"
            return subprocess.CompletedProcess(command, 0, out, "")
        if command[1] == "convert":
            if self.convert_exit:
                return subprocess.CompletedProcess(
                    command, self.convert_exit, "", "boom"
                )
            Path(command[command.index("--output") + 1]).write_text(
                json.dumps(self.bom), encoding="utf-8"
            )
            return subprocess.CompletedProcess(command, 0, "", "")
        output = Path(command[command.index("--output-file") + 1])
        if command[1:3] == ["scan", "image"]:
            if self.image_output is not False:
                output.write_text(json.dumps(self.image_output), encoding="utf-8")
            return subprocess.CompletedProcess(
                command, self.image_exit, "", self.scanner_stderr
            )
        bom_path = Path(command[command.index("-L") + 1])
        self.scanned_boms.append(json.loads(bom_path.read_text(encoding="utf-8")))
        if self.scanner_output is not False:
            text = (
                self.scanner_output
                if isinstance(self.scanner_output, str)
                else json.dumps(self.scanner_output)
            )
            output.write_text(text, encoding="utf-8")
        return subprocess.CompletedProcess(
            command, self.scanner_exit, "", self.scanner_stderr
        )

    def scans(self, kind: str = "source") -> list[list[str]]:
        return [c for c in self.calls if c[1:3] == ["scan", kind]]

    def docker(self) -> list[list[str]]:
        return [c for c in self.calls if c[0] == "docker"]


class Workspace:
    """targets.json (one Trivy target and its OSV twin) and the Trivy parts."""

    def __init__(
        self,
        tmp_path: Path,
        trivy_status: str | None = "ok",
        kind: str = "fs",
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.targets_file = tmp_path / "targets.json"
        self.parts_dir = tmp_path / "parts"
        self.output_dir = tmp_path / "out"
        trivy = self.parts_dir / "trivy"
        trivy.mkdir(parents=True)
        tid = "app-development" if kind == "image" else "source-development"
        target = {
            "id": tid,
            "kind": kind,
            "status": "pending",
            "ref": "ghcr.io/example/app:development" if kind == "image" else None,
            **(extra or {}),
        }
        self.targets_file.write_text(
            json.dumps(
                {
                    "targets": [
                        {**target, "scanner": "trivy"},
                        {**target, "scanner": "osv"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        if trivy_status is not None:
            (trivy / f"{tid}.status.json").write_text(
                json.dumps({"id": tid, "status": trivy_status}), encoding="utf-8"
            )
        if trivy_status == "ok":
            (trivy / f"{tid}.json").write_text(
                json.dumps({"Results": []}), encoding="utf-8"
            )
        self.tid = tid

    def run(self, commands: FakeCommands) -> None:
        args = argparse.Namespace(
            targets_file=self.targets_file,
            parts_dir=self.parts_dir,
            output_dir=self.output_dir,
        )
        qo.run_all(args, commands, NOW)

    @property
    def osv_dir(self) -> Path:
        return self.output_dir / "osv"

    def status(self) -> dict[str, Any]:
        path = self.osv_dir / f"{self.tid}.status.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def result(self) -> Path:
        return self.osv_dir / f"{self.tid}.json"


# --- the BOM ------------------------------------------------------------------


def test_filter_bom_keeps_language_packages() -> None:
    bom = qo.filter_bom(BOM)
    # the library without a purl and the lockfile (application) are no packages
    assert [c["purl"] for c in bom["components"]] == [
        "pkg:npm/lodash@4.17.0",
        "pkg:pypi/requests@2.0.0",
        "pkg:oci/image@sha256:0",
    ]
    # the graph and the Trivy findings are of no use to osv-scanner
    assert (bom["dependencies"], bom["vulnerabilities"]) == ([], [])
    assert bom["bomFormat"] == "CycloneDX"


@pytest.mark.parametrize("purl_type", ["deb", "apk", "rpm", "DEB"])
def test_filter_bom_removes_os_packages(purl_type: str) -> None:
    bom = qo.filter_bom({"components": [component(f"pkg:{purl_type}/distro/pkg@1")]})
    assert bom["components"] == []


def test_filter_bom_folds_the_group_into_the_name_as_osv_writes_it() -> None:
    maven = {**component("pkg:maven/org.example/lib@1.0"), "group": "org.example"}
    scoped = {**component("pkg:npm/%40scope/pkg@1.0"), "group": "@scope"}
    plain = component("pkg:npm/plain@1.0")
    bom = qo.filter_bom({"components": [maven, scoped, plain]})
    assert [(c["name"], "group" in c) for c in bom["components"]] == [
        ("org.example:lib", False),
        ("@scope/pkg", False),
        ("plain", False),
    ]
    assert "group" in maven  # the input is not modified


def test_filter_bom_removes_components_without_a_version() -> None:
    no_version = {"type": "library", "name": "ws", "purl": "pkg:npm/ws"}
    empty = {**no_version, "version": "", "purl": "pkg:npm/ws@"}
    blank_purl = {**no_version, "version": "1.0"}
    keep = component("pkg:npm/lodash@4.17.0")
    bom = qo.filter_bom({"components": [no_version, empty, blank_purl, keep]})
    assert bom["components"] == [keep]


def test_filter_bom_without_components() -> None:
    assert qo.filter_bom({})["components"] == []


# --- a target -------------------------------------------------------------------


def test_osv_scanner_is_run_on_the_filtered_bom_with_the_documented_flags(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path)
    commands = FakeCommands()
    ws.run(commands)
    convert = commands.calls[1]
    assert convert[:5] == ["trivy", "convert", "--format", "cyclonedx", "--output"]
    assert convert[-1] == str(ws.parts_dir / "trivy" / "source-development.json")
    (scan,) = commands.scans()
    assert scan[:3] == ["osv-scanner", "scan", "source"]
    # osv-scanner takes the format of a BOM from its file name
    assert scan[scan.index("-L") + 1].endswith(".cdx.json")
    assert "--all-packages" in scan
    assert scan[scan.index("--format") + 1] == "json"
    assert scan[scan.index("--output-file") + 1] == str(ws.result())
    assert len(commands.scanned_boms[0]["components"]) == 3


@pytest.mark.parametrize(("exit_code", "vulnerable"), [(0, False), (1, True)])
def test_exit_0_and_1_are_ok_and_the_output_is_kept_as_is(
    tmp_path: Path, exit_code: int, vulnerable: bool
) -> None:
    ws = Workspace(tmp_path)
    output = osv_output(*PACKAGES, vulnerable=vulnerable)
    ws.run(FakeCommands(scanner_exit=exit_code, scanner_output=output))
    assert json.loads(ws.result().read_text(encoding="utf-8")) == output
    assert ws.status() == {
        "status": "ok",
        "reason": None,
        "queried_at": "2030-01-01T12:00:00Z",
        "scanner_version": "2.6.0",
    }


@pytest.mark.parametrize("exit_code", [2, 127, 128, 130])
def test_any_other_exit_code_is_a_failure_even_with_an_empty_json(
    tmp_path: Path, exit_code: int
) -> None:
    ws = Workspace(tmp_path)
    # a clean-looking output next to a failure must not count as clean
    commands = FakeCommands(
        scanner_exit=exit_code,
        scanner_output=osv_output(),
        scanner_stderr="Error during extraction:\nmax retries exceeded",
    )
    ws.run(commands)
    assert ws.status()["status"] == "failed"
    assert ws.status()["reason"] == (
        f"osv-scanner failed (exit {exit_code}): "
        "Error during extraction: max retries exceeded"
    )


def test_a_missing_osv_scanner_is_exit_127(tmp_path: Path) -> None:
    result = qo.run_command([str(tmp_path / "no-such-binary"), "--version"])
    assert result.returncode == 127
    assert result.stderr


def record_timeouts(monkeypatch: pytest.MonkeyPatch) -> list[float | None]:
    seen: list[float | None] = []

    def fake_run(command: Sequence[str], **kwargs: Any) -> Any:
        seen.append(kwargs.get("timeout"))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(qo.subprocess, "run", fake_run)
    return seen


def test_every_command_has_a_timeout_and_an_image_scan_a_longer_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = record_timeouts(monkeypatch)
    qo.run_command(["trivy", "convert"])
    qo.run_command(["osv-scanner", "scan", "source", "-L", "x"])
    qo.run_command(["docker", "image", "rm", "ref"])
    qo.run_command(["osv-scanner", "scan", "image", "ref"])
    assert seen == [
        qo.COMMAND_TIMEOUT_SECONDS,
        qo.COMMAND_TIMEOUT_SECONDS,
        qo.COMMAND_TIMEOUT_SECONDS,
        qo.IMAGE_SCAN_TIMEOUT_SECONDS,
    ]
    assert qo.IMAGE_SCAN_TIMEOUT_SECONDS > qo.COMMAND_TIMEOUT_SECONDS


def test_a_command_that_times_out_is_exit_124(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command: Sequence[str], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(qo.subprocess, "run", fake_run)
    result = qo.run_command(["osv-scanner", "scan", "image", "ref"])
    assert result.returncode == 124
    assert "timed out" in result.stderr


def test_a_scan_that_times_out_fails_its_target_and_the_loop_goes_on(
    tmp_path: Path,
) -> None:
    class Hanging(FakeCommands):
        def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
            if list(command[1:3]) == ["scan", "source"]:
                return subprocess.CompletedProcess(command, 124, "", "timed out")
            return super().__call__(command)

    ws = Workspace(tmp_path)
    ws.run(Hanging())
    status = ws.status()
    assert status["status"] == "failed"
    assert "exit 124" in status["reason"]
    assert "timed out" in status["reason"]


def test_the_reason_is_the_end_of_stderr_and_is_cut(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    ws.run(FakeCommands(scanner_exit=2, scanner_stderr="x" * 5000 + " the end"))
    reason = ws.status()["reason"]
    assert reason.endswith("the end")
    assert len(reason) < 500


def test_trivy_convert_failure_is_a_failed_target(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    commands = FakeCommands(convert_exit=1)
    ws.run(commands)
    assert ws.status()["reason"] == "trivy convert failed (exit 1): boom"
    assert commands.scans() == []


def test_an_unreadable_bom_is_a_failed_target(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    ws.run(FakeCommands(bom=["not", "a", "bom"]))
    assert ws.status()["reason"].startswith("trivy convert wrote no valid BOM")


def test_a_target_without_language_packages_is_ok_without_running_osv_scanner(
    tmp_path: Path,
) -> None:
    ws = Workspace(tmp_path)
    commands = FakeCommands(bom={"components": [component("pkg:deb/debian/a@1")]})
    ws.run(commands)
    assert commands.scans() == []
    assert json.loads(ws.result().read_text(encoding="utf-8")) == {"results": []}
    assert ws.status()["status"] == "ok"


@pytest.mark.parametrize("trivy_status", ["failed", "not_applicable", None, "ok-ish"])
def test_a_target_whose_trivy_target_was_not_scanned_is_not_applicable(
    tmp_path: Path, trivy_status: str | None
) -> None:
    ws = Workspace(tmp_path, trivy_status)
    commands = FakeCommands()
    ws.run(commands)
    assert ws.status()["status"] == "not_applicable"
    assert ws.status()["reason"] == f"trivy target {trivy_status or 'failed'}"
    assert not ws.result().exists()
    assert commands.scans() == []


def test_only_pending_osv_targets_are_processed(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    doc = json.loads(ws.targets_file.read_text(encoding="utf-8"))
    doc["targets"][1]["status"] = "failed"
    ws.targets_file.write_text(json.dumps(doc), encoding="utf-8")
    commands = FakeCommands()
    ws.run(commands)
    assert commands.scans() == []
    assert not (ws.osv_dir / "source-development.status.json").exists()


# --- an image target ----------------------------------------------------------


def image_workspace(tmp_path: Path, **extra: Any) -> Workspace:
    return Workspace(tmp_path, kind="image", extra=extra)


def test_an_image_target_is_scanned_by_bom_and_by_image(tmp_path: Path) -> None:
    ws = image_workspace(tmp_path)
    commands = FakeCommands()
    ws.run(commands)
    bom, image = commands.scans("source")[0], commands.scans("image")[0]
    assert image[:3] == ["osv-scanner", "scan", "image"]
    assert image[3] == "ghcr.io/example/app:development"
    assert "--all-packages" in image
    assert image[image.index("--format") + 1] == "json"
    # the image scan writes to its own file, not over the BOM output
    assert image[image.index("--output-file") + 1] != str(ws.result())
    # the results of both are concatenated into the one output, the BOM query's
    # first (the file is the audit artifact read in order)
    merged = json.loads(ws.result().read_text(encoding="utf-8"))
    bom_names = [p["package"]["name"] for p in commands.scanner_output["results"][0]["packages"]]
    image_names = [p["package"]["name"] for p in commands.image_output["results"][0]["packages"]]
    assert [p["package"]["name"] for p in merged["results"][0]["packages"]] == bom_names
    assert [p["package"]["name"] for p in merged["results"][1]["packages"]] == image_names
    assert len(merged["results"]) == 2
    sources = {r["source"]["type"] for r in merged["results"]}
    assert sources == {"sbom"}
    assert commands.docker() == [["docker", "image", "rm", image[3]]]


def test_a_docker_image_rm_failure_does_not_fail_the_target(tmp_path: Path) -> None:
    ws = image_workspace(tmp_path)
    ws.run(FakeCommands(docker_exit=1))
    assert ws.status()["status"] == "ok"


@pytest.mark.parametrize("exit_code", [2, 127])
def test_a_failed_image_scan_fails_the_target_even_with_a_good_bom(
    tmp_path: Path, exit_code: int
) -> None:
    ws = image_workspace(tmp_path)
    commands = FakeCommands(image_exit=exit_code, scanner_stderr="pull failed")
    ws.run(commands)
    assert ws.status()["status"] == "failed"
    assert ws.status()["reason"] == (
        f"osv-scanner scan image failed (exit {exit_code}): pull failed"
    )
    assert commands.docker() == [["docker", "image", "rm", "ghcr.io/example/app:development"]]


def test_an_image_scan_output_of_an_unexpected_shape_fails_the_target(
    tmp_path: Path,
) -> None:
    ws = image_workspace(tmp_path)
    ws.run(FakeCommands(image_output={"unexpected": True}))
    assert ws.status()["status"] == "failed"
    assert "no valid results to merge" in ws.status()["reason"]


def test_a_bom_query_that_fails_before_the_image_scan_runs_no_docker(
    tmp_path: Path,
) -> None:
    # a failed convert or BOM query returns before scan image, so no image was
    # pulled and docker image rm must not be called
    ws = image_workspace(tmp_path)
    commands = FakeCommands(convert_exit=2)
    ws.run(commands)
    assert ws.status()["status"] == "failed"
    assert commands.scans("image") == []
    assert commands.docker() == []


def test_the_image_scan_flag_skips_only_the_image_scan(tmp_path: Path) -> None:
    ws = image_workspace(tmp_path, image_scan_disabled=True)
    commands = FakeCommands()
    ws.run(commands)
    assert len(commands.scans("source")) == 1
    assert commands.scans("image") == []
    assert commands.docker() == []
    merged = json.loads(ws.result().read_text(encoding="utf-8"))
    assert len(merged["results"]) == 1
    assert ws.status()["status"] == "ok"
    assert ws.status()["reason"] == (
        "osv image scan disabled for this repository (image too large for the "
        "runner disk): OS packages of the image are not checked by OSV"
    )
