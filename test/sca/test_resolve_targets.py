"""Tests for sca_resolve_targets/resolve_targets.py (fake transport, no network)."""

import json
import subprocess
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
import resolve_targets as rt

REPOSITORY = "example/app"
SHA = "a" * 40
ENV = {
    "GITHUB_RUN_ID": "42",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "example/caller",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_TRIGGERING_ACTOR": "octocat",
}
CALLER = "example/caller"


class FakeRunner:
    """Stands in for ``gh`` and ``oras``: routes the last argument (the API path or
    the image reference) to a canned output, and records every call.
    """

    def __init__(self) -> None:
        self.routes: dict[str, Any] = {}
        self.calls: list[tuple[list[str], str | None]] = []

    @property
    def urls(self) -> list[str]:
        return [argv[-1] for argv, _ in self.calls]

    def add(self, url: str, response: Any) -> None:
        """``response``: stdout, a ToolError or a list (consumed in order)."""
        self.routes[url] = response

    def __call__(self, argv: Sequence[str], stdin: str | None = None) -> str:
        self.calls.append((list(argv), stdin))
        route = self.routes.get(argv[-1])
        if route is None:
            raise rt.ToolError("unrouted")
        current = (
            (route.pop(0) if len(route) > 1 else route[0])
            if isinstance(route, list)
            else route
        )
        if isinstance(current, Exception):
            raise current
        return str(current)


def ok(payload: Any) -> str:
    """The stdout of ``gh api`` for a JSON response."""
    return json.dumps(payload)


def http_error(status: int) -> rt.ToolError:
    return rt.ToolError(f"gh: error (HTTP {status})")


def tags_out(tags: list[str]) -> str:
    """The stdout of ``oras repo tags``: one tag per line."""
    return "".join(f"{tag}\n" for tag in tags)


def tags_url(image: str, host: str = "ghcr.io") -> str:
    return f"{host}/{image}"


def github_routes(
    runner: FakeRunner,
    releases: list[dict[str, Any]] | None = None,
    releases_status: int | None = None,
    branch: str = "development",
) -> None:
    runner.add(f"repos/{REPOSITORY}", ok({"default_branch": branch}))
    quoted = urllib.parse.quote(branch, safe="")
    runner.add(f"repos/{REPOSITORY}/commits/{quoted}", ok({"sha": "a" * 40}))
    listing = f"repos/{REPOSITORY}/releases?per_page=100&page="
    if releases_status is not None:
        runner.add(f"{listing}1", http_error(releases_status))
    else:
        pages = [(releases or [])[i : i + 100] for i in range(0, len(releases or []), 100)]
        if not pages or len(pages[-1]) == 100:
            pages.append([])  # the page after a full last one is asked for too
        for number, page in enumerate(pages, 1):
            runner.add(f"{listing}{number}", ok(page))
        for release in releases or []:
            if not release.get("draft"):
                tag_routes(runner, release["tag_name"], "c" * 40)


def stable(tag: str, published_at: str) -> dict[str, Any]:
    """A GitHub release the repository published as a release."""
    return {
        "tag_name": tag,
        "prerelease": False,
        "draft": False,
        "published_at": published_at,
    }


def candidate(tag: str, published_at: str) -> dict[str, Any]:
    """A GitHub release the repository published as a prerelease."""
    return {
        "tag_name": tag,
        "prerelease": True,
        "draft": False,
        "published_at": published_at,
    }


def tag_routes(runner: FakeRunner, tag: str, sha: str) -> None:
    """A git tag at the commit ``sha`` (the API peels annotated tags itself)."""
    runner.add(f"repos/{REPOSITORY}/commits/refs/tags/{tag}", ok({"sha": sha}))


def run_resolve_targets(
    runner: FakeRunner,
    images: list[str],
    token: str | None = "tkn",
    scan_tag: str | None = None,
) -> dict[str, Any]:
    inputs = rt.Inputs(
        repository=REPOSITORY,
        caller_repository=CALLER,
        images=images,
        **({"scan_tag": scan_tag} if scan_tag else {}),
    )
    return rt.resolve_targets(
        inputs,
        rt.GitHubClient(runner),
        rt.RegistryClient(runner, "ghcr.io", token),
        ENV,
    )


def run_env(output_dir: Path, **overrides: str) -> dict[str, str]:
    """The environment the action passes to the script."""
    return {**ENV, "REPOSITORY": REPOSITORY, "OUTPUT_DIR": str(output_dir), **overrides}


def trivy(targets_doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The Trivy targets by id (every one has an OSV twin)."""
    return {t["id"]: t for t in targets_doc["targets"] if t["scanner"] == "trivy"}


TARGET_KEYS = {"id", "kind", "ref", "commit_sha"}


def by_id(targets_doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return trivy(targets_doc)


# --- targets ------------------------------------------------------------------


def test_latest_github_release_is_scanned() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(
        tags_url("example/app"),
        tags_out(["development", "1.1.14", "1.2.0", "1.1.13"]),
    )
    targets = by_id(run_resolve_targets(t, ["example/app"]))
    assert list(targets) == [
        "source-development",
        "source-1.1.14",
        "app-development",
        "app-1.1.14",
    ]
    assert targets["source-development"]["kind"] == "fs"
    assert targets["app-1.1.14"] == {
        "id": "app-1.1.14",
        "scanner": "trivy",
        "kind": "image",
        "image": "example/app",
        "tag": "1.1.14",
        "ref": "ghcr.io/example/app:1.1.14",
        "git_ref": None,
        "commit_sha": None,
        "status": "pending",
        "reason": None,
    }


def test_resolve_document_metadata() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    targets_doc = run_resolve_targets(t, [])
    assert targets_doc["repo"] == REPOSITORY
    assert targets_doc["default_branch"] == "development"
    assert targets_doc["commit_sha"] == "a" * 40
    assert targets_doc["run_id"] == "42"
    assert targets_doc["run_url"] == "https://github.com/example/caller/actions/runs/42"


def test_v_prefixed_candidate_tag_matches_the_unprefixed_image_tag() -> None:
    t = FakeRunner()
    github_routes(
        t,
        [
            stable("1.1.14", "2025-01-02T00:00:00Z"),
            candidate("v1.1.15-rc.1", "2025-01-03T00:00:00Z"),
        ],
    )
    t.add(
        tags_url("example/x"),
        tags_out(["development", "1.1.14", "1.1.15-rc.1"]),
    )
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-1.1.15-rc.1"]["status"] == "pending"
    assert targets["x-1.1.15-rc.1"]["ref"] == "ghcr.io/example/x:1.1.15-rc.1"


def test_release_tag_missing_for_image_is_not_applicable() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/app-bff"), tags_out(["development"]))
    targets = by_id(run_resolve_targets(t, ["example/app-bff"]))
    assert targets["app-bff-development"]["status"] == "pending"
    missing = targets["app-bff-1.1.14"]
    assert missing["status"] == "not_applicable"
    assert missing["reason"] == "release 1.1.14 not published for this image"


def test_missing_development_tag_is_not_applicable() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.0.0", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/x"), tags_out(["1.0.0"]))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-development"]["status"] == "not_applicable"
    assert targets["x-1.0.0"]["status"] == "pending"


def test_no_github_release_gives_single_not_applicable_release_target() -> None:
    t = FakeRunner()
    github_routes(t, [])
    t.add(tags_url("example/x"), tags_out(["development", "0.9.1", "1.0.0-rc.1"]))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-release"]["status"] == "not_applicable"
    assert targets["x-release"]["tag"] is None
    assert targets["x-release"]["ref"] is None
    assert targets["x-release"]["reason"] == "no GitHub release"
    assert "x-0.9.1" not in targets


def test_image_without_tags() -> None:
    t = FakeRunner()
    github_routes(t, [])
    t.add(tags_url("example/x"), tags_out([]))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-development"]["status"] == "not_applicable"
    assert targets["x-release"]["status"] == "not_applicable"


def test_registry_error_fails_only_that_image() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.0.0", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/bad"), http_error(404))
    t.add(tags_url("example/good"), tags_out(["development", "1.0.0"]))
    targets = by_id(run_resolve_targets(t, ["example/bad", "example/good"]))
    assert targets["bad-development"]["status"] == "failed"
    assert "HTTP 404" in targets["bad-development"]["reason"]
    assert targets["bad-1.0.0"]["status"] == "failed"
    assert targets["good-development"]["status"] == "pending"
    assert targets["good-1.0.0"]["status"] == "pending"


def test_registry_tool_failure_fails_image() -> None:
    t = FakeRunner()
    github_routes(t, [])
    t.add(tags_url("example/x"), rt.ToolError("boom"))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert targets["x-development"]["status"] == "failed"
    assert "boom" in targets["x-development"]["reason"]


def test_github_release_api_error_fails_the_run() -> None:
    t = FakeRunner()
    github_routes(t, releases_status=403)
    with pytest.raises(rt.ResolveError, match="HTTP 403"):
        run_resolve_targets(t, ["example/x"])


@pytest.mark.parametrize("missing", ["repo", "commit"])
def test_snapshot_failure_is_fatal(missing: str) -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(
        f"repos/{REPOSITORY}" + ("/commits/development" if missing == "commit" else ""),
        http_error(404),
    )
    with pytest.raises(rt.ResolveError, match="HTTP 404"):
        run_resolve_targets(t, [])


def test_snapshot_network_failure_is_fatal() -> None:
    t = FakeRunner()
    t.add(f"repos/{REPOSITORY}", rt.ToolError("down"))
    with pytest.raises(rt.ResolveError, match="down"):
        run_resolve_targets(t, [])


def test_empty_images_only_sources() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    targets_doc = run_resolve_targets(t, [])
    assert list(trivy(targets_doc)) == ["source-development", "source-1.1.14"]
    assert not any(url.startswith("ghcr.io/") for url in t.urls)


def test_the_same_image_twice_is_an_id_collision() -> None:
    t = FakeRunner()
    github_routes(t, [])
    t.add(tags_url("a/x"), tags_out(["development"]))
    with pytest.raises(rt.ResolveError, match="collision"):
        run_resolve_targets(t, ["a/x", "a/x"])


def test_images_with_the_same_last_segment_get_the_full_name_in_the_id() -> None:
    t = FakeRunner()
    github_routes(t, [])
    t.add(tags_url("a/x"), tags_out(["development"]))
    t.add(tags_url("b/x"), tags_out(["development"]))
    t.add(tags_url("c/y"), tags_out(["development"]))
    targets = by_id(run_resolve_targets(t, ["a/x", "b/x", "c/y"]))
    assert [i for i in targets if i.endswith("-development")] == [
        "source-development",
        "a-x-development",
        "b-x-development",
        "y-development",
    ]
    assert targets["b-x-development"]["ref"] == "ghcr.io/b/x:development"


def test_a_focus_run_names_colliding_images_by_the_full_name() -> None:
    t = FakeRunner()
    focus_routes(t, "0.22.0")
    t.add(tags_url("a/x"), tags_out(["0.22.0"]))
    t.add(tags_url("b/x"), tags_out(["0.22.0"]))
    targets = by_id(run_resolve_targets(t, ["a/x", "b/x"], scan_tag="0.22.0"))
    assert list(targets) == ["source-0.22.0", "a-x-0.22.0", "b-x-0.22.0"]


def test_matrix_has_only_pending_targets_without_status() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/bff"), tags_out(["development"]))
    matrix = rt.build_matrix(run_resolve_targets(t, ["example/bff"]))
    assert [m["id"] for m in matrix] == [
        "source-development",
        "source-1.1.14",
        "bff-development",
    ]
    assert all(set(m) == TARGET_KEYS for m in matrix)


def test_target_id_is_sanitized() -> None:
    def source(git_ref: str) -> str:
        return rt.make_target("pending", git_ref=git_ref)["id"]

    def image(name: str, tag: str) -> str:
        return rt.make_target("pending", image=name, tag=tag)["id"]

    assert source("development") == "source-development"
    assert source("release/1.2") == "source-release-1.2"
    assert source("feat/a b") == "source-feat-a-b"
    assert image("example/some_image", "1.2.3") == "some_image-1.2.3"
    assert image("example/x", "a b+c") == "x-a-b-c"


def test_source_target_id_sanitized_and_independent_of_sha() -> None:
    t = FakeRunner()
    github_routes(
        t, [stable("1.1.14", "2025-01-01T00:00:00Z")], branch="release/1.2"
    )
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-release-1.2", "source-1.1.14"]
    assert targets["source-release-1.2"]["git_ref"] == "release/1.2"
    assert "a" * 40 not in "".join(targets)


def test_fs_target_carries_git_ref_and_commit_sha() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    targets_doc = run_resolve_targets(t, [])
    assert trivy(targets_doc)["source-development"] == {
        "id": "source-development",
        "scanner": "trivy",
        "kind": "fs",
        "image": None,
        "tag": None,
        "ref": None,
        "git_ref": "development",
        "commit_sha": "a" * 40,
        "status": "pending",
        "reason": None,
    }
    assert targets_doc["default_branch"] == "development"
    assert targets_doc["commit_sha"] == "a" * 40


def test_target_schema_is_uniform() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/app"), tags_out(["development"]))
    targets_doc = run_resolve_targets(t, ["example/app"])
    kinds = {x["kind"] for x in targets_doc["targets"]}
    assert kinds == {"fs", "image"}
    for target in trivy(targets_doc).values():
        assert set(target) == TARGET_KEYS | {
            "scanner",
            "image",
            "tag",
            "git_ref",
            "status",
            "reason",
        }
        assert target["scanner"] == "trivy"
        if target["kind"] == "image":
            assert target["git_ref"] is None
            assert target["commit_sha"] is None
        else:
            assert target["git_ref"]
            assert target["commit_sha"]
    assert all(set(m) == TARGET_KEYS for m in rt.build_matrix(targets_doc))


def test_matrix_carries_commit_sha_of_fs_target() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    fs = rt.build_matrix(run_resolve_targets(t, []))[0]
    assert (fs["id"], fs["commit_sha"]) == ("source-development", "a" * 40)


# --- inputs -------------------------------------------------------------------


def test_parse_images_ignores_blank_lines_and_whitespace() -> None:
    assert rt.parse_images("\n  example/a  \n\n\texample/b\n  \n") == [
        "example/a",
        "example/b",
    ]
    assert rt.parse_images("") == []


@pytest.mark.parametrize(
    "bad", ["ghcr.io/example/a:1.0", "EXAMPLE/a", "example/a:tag", "../a", "example//a"]
)
def test_parse_images_rejects_invalid_names(bad: str) -> None:
    with pytest.raises(rt.ResolveError, match="invalid image name"):
        rt.parse_images(bad)


# --- registry (oras) ----------------------------------------------------------


def test_registry_lists_tags_anonymously_without_a_token() -> None:
    t = FakeRunner()
    t.add("ghcr.io/example/x", tags_out(["a", "b"]))
    assert rt.RegistryClient(t, "ghcr.io").tags("example/x") == ["a", "b"]
    assert t.calls == [(["oras", "repo", "tags", "ghcr.io/example/x"], None)]


def test_registry_logs_in_to_ghcr_with_the_github_token() -> None:
    t = FakeRunner()
    t.add("ghcr.io/example/x", tags_out(["development"]))
    assert rt.RegistryClient(t, "ghcr.io", "gh-token").tags("example/x") == [
        "development"
    ]
    argv, stdin = t.calls[0]
    assert argv == [
        "oras",
        "repo",
        "tags",
        "--username",
        "github-actions",
        "--password-stdin",
        "ghcr.io/example/x",
    ]
    assert stdin == "gh-token"
    assert "gh-token" not in " ".join(argv)


def test_github_token_not_sent_to_foreign_registry() -> None:
    t = FakeRunner()
    t.add("registry-1.docker.io/example/x", tags_out(["development"]))
    assert rt.RegistryClient(t, "docker.io", "gh-token").tags("example/x") == [
        "development"
    ]
    assert t.calls == [
        (["oras", "repo", "tags", "registry-1.docker.io/example/x"], None)
    ]


def test_docker_hub_official_images_use_library_namespace() -> None:
    t = FakeRunner()
    t.add("registry-1.docker.io/library/nginx", tags_out(["1.0.0"]))
    assert rt.RegistryClient(t, "docker.io").tags("nginx") == ["1.0.0"]


def test_registry_failure_is_a_resolve_error() -> None:
    t = FakeRunner()
    t.add("ghcr.io/example/x", rt.ToolError("response status code 401: unauthorized"))
    with pytest.raises(rt.ResolveError, match="listing tags of example/x.*401"):
        rt.RegistryClient(t, "ghcr.io").tags("example/x")


# --- GitHub (gh) --------------------------------------------------------------


def test_github_requests_go_through_gh_api() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    run_resolve_targets(t, [])
    for argv, stdin in t.calls:
        assert argv[:2] == ["gh", "api"]
        assert "X-GitHub-Api-Version: 2022-11-28" in argv
        assert stdin is None


# --- the runner (subprocess) --------------------------------------------------


class FakeProcesses:
    """Replaces ``subprocess.run``: one canned result per call, in order."""

    def __init__(self, *results: Any) -> None:
        self.results = list(results)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> Any:
        self.calls.append({"argv": argv, **kwargs})
        result = self.results.pop(0) if len(self.results) > 1 else self.results[0]
        if isinstance(result, Exception):
            raise result
        return result


def done(returncode: int = 0, stdout: str = "", stderr: str = "") -> Any:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def runner_with(
    monkeypatch: pytest.MonkeyPatch, *results: Any
) -> tuple[Any, FakeProcesses, list[float]]:
    processes = FakeProcesses(*results)
    monkeypatch.setattr(rt.subprocess, "run", processes)
    sleeps: list[float] = []
    return rt.make_runner("secret", sleep=sleeps.append), processes, sleeps


def test_runner_returns_stdout_and_passes_token_and_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, processes, sleeps = runner_with(monkeypatch, done(stdout="out"))
    assert run(["gh", "api", "x"], "input") == "out"
    (call,) = processes.calls
    assert call["env"]["GH_TOKEN"] == "secret"
    assert call["input"] == "input"
    assert call["timeout"] == rt.TOOL_TIMEOUT_SECONDS
    assert sleeps == []


def test_runner_retries_a_transient_failure_with_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, processes, sleeps = runner_with(
        monkeypatch,
        done(1, stderr="gh: Bad Gateway (HTTP 502)"),
        subprocess.TimeoutExpired("gh", 1),
        done(stdout="out"),
    )
    assert run(["gh", "api", "x"], None) == "out"
    assert len(processes.calls) == 3
    assert sleeps == [1.0, 2.0]


def test_runner_gives_up_after_the_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    run, processes, sleeps = runner_with(monkeypatch, done(1, stderr="HTTP 503"))
    with pytest.raises(rt.ToolError, match="HTTP 503"):
        run(["gh", "api", "x"], None)
    assert len(processes.calls) == rt.MAX_ATTEMPTS
    assert len(sleeps) == rt.MAX_ATTEMPTS - 1


@pytest.mark.parametrize("status", [401, 403, 404, 422])
def test_runner_does_not_retry_a_client_error(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    run, processes, _ = runner_with(
        monkeypatch, done(1, stderr=f"gh: x (HTTP {status})")
    )
    with pytest.raises(rt.ToolError, match=f"HTTP {status}"):
        run(["gh", "api", "x"], None)
    assert len(processes.calls) == 1


def test_runner_retries_rate_limiting(monkeypatch: pytest.MonkeyPatch) -> None:
    run, processes, _ = runner_with(
        monkeypatch, done(1, stderr="gh: slow down (HTTP 429)"), done(stdout="out")
    )
    assert run(["gh", "api", "x"], None) == "out"
    assert len(processes.calls) == 2


def test_runner_reports_a_missing_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    run, _, _ = runner_with(monkeypatch, FileNotFoundError("no oras"))
    with pytest.raises(rt.ToolError, match="cannot run oras"):
        run(["oras", "repo", "tags", "x"], None)


# --- output formatting and CLI ---------------------------------------------------


def parse_github_output(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines())


def test_run_writes_resolve_json_and_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    tag_routes(t, "1.1.14", "b" * 40)
    t.add(tags_url("example/x"), tags_out(["development"]))
    output_file = tmp_path / "github_output"
    env = run_env(
        tmp_path / "out",
        GITHUB_OUTPUT=str(output_file),
        GITHUB_TOKEN="tkn",
        IMAGES="example/x\n",
    )
    rt.run(env, t)

    targets_doc = json.loads(
        (tmp_path / "out" / "targets.json").read_text(encoding="utf-8")
    )
    assert list(trivy(targets_doc)) == [
        "source-development",
        "source-1.1.14",
        "x-development",
        "x-1.1.14",
    ]
    outputs = parse_github_output(output_file.read_text(encoding="utf-8"))
    assert outputs["targets-file"] == str(tmp_path / "out" / "targets.json")
    assert " " not in outputs["matrix"]
    assert [m["id"] for m in json.loads(outputs["matrix"])] == [
        "source-development",
        "source-1.1.14",
        "x-development",
    ]
    console = capsys.readouterr().out
    assert (
        "::notice title=Scan target x-1.1.14 skipped::release 1.1.14 not published"
        in console
    )
    assert "x-development" in console


def test_run_uses_token_from_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    tokens: list[str | None] = []
    monkeypatch.setattr(rt, "make_runner", lambda token: tokens.append(token) or t)
    rt.run(run_env(tmp_path, GITHUB_TOKEN="from-env"), None)
    assert tokens == ["from-env"]


@pytest.mark.parametrize(
    "extra",
    [
        {"REPOSITORY": "nope"},
        {"REPOSITORY": ""},
    ],
)
def test_run_rejects_invalid_inputs(tmp_path: Path, extra: dict[str, str]) -> None:
    with pytest.raises(rt.ResolveError):
        rt.run(run_env(tmp_path, **extra), FakeRunner())


def test_run_defaults_the_registry(tmp_path: Path) -> None:
    inputs = rt.Inputs.from_environ(run_env(tmp_path))
    assert inputs == rt.Inputs(repository=REPOSITORY, caller_repository=CALLER)
    assert inputs.registry == "ghcr.io"


def test_main_reports_fatal_error_and_exits_non_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    t = FakeRunner()
    t.add(f"repos/{REPOSITORY}", http_error(404))
    monkeypatch.setattr(rt, "make_runner", lambda token: t)
    for name, value in run_env(tmp_path).items():
        monkeypatch.setenv(name, value)
    code = rt.main()
    assert code == 1
    assert "::error" in capsys.readouterr().out
    assert not (tmp_path / "targets.json").exists()


def test_render_table_and_annotations() -> None:
    targets = [
        {
            "id": "source",
            "scanner": "trivy",
            "kind": "fs",
            "ref": None,
            "status": "pending",
            "reason": None,
        },
        {
            "id": "x-1",
            "scanner": "trivy",
            "kind": "image",
            "ref": "ghcr.io/x:1",
            "status": "failed",
            "reason": "boom",
        },
        {
            "id": "x-2",
            "scanner": "trivy",
            "kind": "image",
            "ref": "ghcr.io/x:2",
            "status": "not_applicable",
            "reason": "nope",
        },
    ]
    table = rt.render_table(targets)
    assert "source" in table
    assert "ghcr.io/x:1" in table
    assert rt.annotations(targets) == [
        "::warning title=Scan target x-1 failed to resolve::boom",
        "::notice title=Scan target x-2 skipped::nope",
    ]


# --- the release set ------------------------------------------------------------


def two_lines() -> list[dict[str, Any]]:
    """Newest first, as GitHub returns them: 0.22.0 shipped before the 0.21.4
    hotfix."""
    return [
        stable("0.21.4", "2025-03-01T00:00:00Z"),
        stable("0.22.0", "2025-02-01T00:00:00Z"),
        stable("0.21.3", "2025-01-01T00:00:00Z"),
        stable("0.20.9", "2024-12-01T00:00:00Z"),
    ]


def test_release_set_takes_the_newest_patch_of_each_line() -> None:
    t = FakeRunner()
    github_routes(t, two_lines())
    targets = by_id(run_resolve_targets(t, []))
    # the default cap is 2: the 0.20 line falls away, 0.21.4 beats 0.21.3
    assert list(targets) == ["source-development", "source-0.22.0", "source-0.21.4"]


def test_release_set_lines_are_ordered_numerically_not_lexically() -> None:
    t = FakeRunner()
    github_routes(
        t,
        [
            stable("0.9.1", "2025-01-01T00:00:00Z"),
            stable("0.10.0", "2024-12-01T00:00:00Z"),
        ],
    )
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-development", "source-0.10.0", "source-0.9.1"]


def test_release_set_hotfix_stays_in_its_own_line() -> None:
    t = FakeRunner()
    github_routes(t, two_lines()[:2])
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-development", "source-0.22.0", "source-0.21.4"]


def test_release_set_lines_beyond_the_cap_are_dropped() -> None:
    t = FakeRunner()
    github_routes(t, two_lines())
    targets_doc = rt.resolve_targets(
        rt.Inputs(
            repository=REPOSITORY,
            caller_repository=CALLER,
            release_lines=3,
        ),
        rt.GitHubClient(t),
        rt.RegistryClient(t, "ghcr.io"),
        ENV,
    )
    assert list(by_id(targets_doc)) == [
        "source-development",
        "source-0.22.0",
        "source-0.21.4",
        "source-0.20.9",
    ]


def test_release_set_fewer_lines_than_the_cap() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.0.0", "2025-01-01T00:00:00Z")])
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-development", "source-1.0.0"]


def test_release_set_a_tie_keeps_the_first_listed_release() -> None:
    t = FakeRunner()
    github_routes(
        t,
        [
            stable("0.21.4", "2025-01-01T00:00:00Z"),
            stable("0.21.3", "2025-01-01T00:00:00Z"),
        ],
    )
    targets = by_id(run_resolve_targets(t, []))
    # GitHub lists the newest first, so the first seen is the newest release
    assert list(targets) == ["source-development", "source-0.21.4"]


def test_release_set_no_releases_gives_the_source_release_placeholder() -> None:
    t = FakeRunner()
    github_routes(t, [])
    t.add(tags_url("example/x"), tags_out(["development", "0.9.1"]))
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    placeholder = targets["source-release"]
    assert placeholder["status"] == "not_applicable"
    assert placeholder["reason"] == "no GitHub release"
    assert placeholder["tag"] is None
    assert placeholder["git_ref"] is None
    assert targets["x-release"]["reason"] == "no GitHub release"


def test_release_set_candidate_older_than_the_newest_stable_is_dropped() -> None:
    t = FakeRunner()
    github_routes(
        t,
        [
            stable("0.22.0", "2025-02-01T00:00:00Z"),
            stable("0.21.4", "2025-03-01T00:00:00Z"),
            candidate("0.19.0-rc.2", "2024-11-01T00:00:00Z"),
        ],
    )
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-development", "source-0.22.0", "source-0.21.4"]


def test_release_set_rc_of_a_published_release_is_not_a_candidate() -> None:
    # the rc keeps its prerelease flag after the final release is out
    t = FakeRunner()
    github_routes(
        t,
        [
            stable("0.45.0", "2025-10-14T00:00:00Z"),
            candidate("0.45.0-rc.0", "2025-10-09T00:00:00Z"),
            stable("0.44.1", "2025-09-01T00:00:00Z"),
            candidate("0.44.0-rc.0", "2025-08-01T00:00:00Z"),
        ],
    )
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-development", "source-0.45.0", "source-0.44.1"]


def test_release_set_candidate_of_a_newer_version_is_scanned() -> None:
    t = FakeRunner()
    github_routes(
        t,
        [
            candidate("0.46.0-rc.0", "2025-10-20T00:00:00Z"),
            stable("0.45.0", "2025-10-14T00:00:00Z"),
        ],
    )
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-development", "source-0.45.0", "source-0.46.0-rc.0"]


def test_release_set_newest_candidate_wins() -> None:
    t = FakeRunner()
    github_routes(
        t,
        [
            stable("0.22.0", "2025-02-01T00:00:00Z"),
            candidate("0.23.0-rc.1", "2025-03-01T00:00:00Z"),
            candidate("0.23.1-rc.0", "2025-02-15T00:00:00Z"),
        ],
    )
    targets = by_id(run_resolve_targets(t, []))
    assert "source-0.23.1-rc.0" in targets
    assert "source-0.23.0-rc.1" not in targets


def test_release_set_candidates_are_ordered_by_version_not_by_date() -> None:
    # rc.10 is newer than rc.9 although it was published first
    t = FakeRunner()
    github_routes(
        t,
        [
            candidate("0.23.0-rc.9", "2025-03-02T00:00:00Z"),
            candidate("0.23.0-rc.10", "2025-03-01T00:00:00Z"),
            stable("0.22.0", "2025-02-01T00:00:00Z"),
        ],
    )
    targets = by_id(run_resolve_targets(t, []))
    assert "source-0.23.0-rc.10" in targets
    assert "source-0.23.0-rc.9" not in targets


def test_release_set_candidate_without_a_stable_is_scanned() -> None:
    t = FakeRunner()
    github_routes(t, [candidate("0.1.0-rc.1", "2025-03-01T00:00:00Z")])
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-development", "source-0.1.0-rc.1"]


def test_release_set_prerelease_with_an_unversioned_tag_is_ignored() -> None:
    t = FakeRunner()
    github_routes(
        t,
        [stable("0.22.0", "2025-02-01T00:00:00Z"), candidate("nightly", "2025-03-01T00:00:00Z")],
    )
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-development", "source-0.22.0"]


def test_release_set_unflagged_rc_is_left_out_with_one_notice(
    capsys: pytest.CaptureFixture[str],
) -> None:
    t = FakeRunner()
    github_routes(
        t,
        [
            stable("0.49.2", "2025-02-01T00:00:00Z"),
            {**candidate("0.49.0-rc.1", "2025-01-01T00:00:00Z"), "prerelease": False},
        ],
    )
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-development", "source-0.49.2"]
    notices = [
        line for line in capsys.readouterr().out.splitlines() if "::notice" in line
    ]
    assert notices == [
        "::notice title=Releases outside the X.Y.Z lines::1 stable release(s) not "
        "scanned, the tag is not X.Y.Z (newest: 0.49.0-rc.1)"
    ]


def test_release_set_stable_tags_of_another_shape_give_one_notice(
    capsys: pytest.CaptureFixture[str],
) -> None:
    t = FakeRunner()
    github_routes(
        t,
        [
            stable("0.22.0", "2025-02-01T00:00:00Z"),
            stable("dial-8.1.0", "2025-01-03T00:00:00Z"),
            stable("dial-admin-0.20.0", "2025-01-02T00:00:00Z"),
            stable("release-7", "2025-01-01T00:00:00Z"),
        ],
    )
    doc = run_resolve_targets(t, [])
    assert list(by_id(doc)) == ["source-development", "source-0.22.0"]
    assert len(doc["targets"]) == 4  # no row of an OSV twin for a skipped release
    out = capsys.readouterr().out
    assert out.count("::notice") == 1
    assert "3 stable release(s) not scanned" in out
    assert "(newest: dial-8.1.0)" in out


def test_release_set_without_such_releases_gives_no_notice(
    capsys: pytest.CaptureFixture[str],
) -> None:
    t = FakeRunner()
    github_routes(t, [stable("0.22.0", "2025-02-01T00:00:00Z")])
    run_resolve_targets(t, [])
    assert "::notice" not in capsys.readouterr().out


def test_release_set_only_unscannable_releases_have_no_placeholder() -> None:
    t = FakeRunner()
    github_routes(t, [stable("dial-8.1.0", "2025-01-01T00:00:00Z")])
    assert list(by_id(run_resolve_targets(t, []))) == ["source-development"]


def test_release_set_drafts_are_ignored() -> None:
    t = FakeRunner()
    github_routes(
        t,
        [
            stable("0.22.0", "2025-02-01T00:00:00Z"),
            {**stable("0.23.0", "2025-03-01T00:00:00Z"), "draft": True},
        ],
    )
    targets = by_id(run_resolve_targets(t, []))
    assert list(targets) == ["source-development", "source-0.22.0"]


def many_stables(count: int) -> list[dict[str, Any]]:
    """Newest first: 0.<count-1>.0 down to 0.0.0, one release per line."""
    return [
        stable(f"0.{count - 1 - i}.0", f"2025-01-01T00:00:{i % 60:02d}Z")
        for i in range(count)
    ]


def test_release_set_reads_every_page_of_the_listing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    t = FakeRunner()
    # the only candidate is on the third page
    releases = [*many_stables(220), candidate("1.0.0-rc.1", "2024-01-01T00:00:00Z")]
    github_routes(t, releases)
    targets = list(by_id(run_resolve_targets(t, [])))
    assert targets == [
        "source-development",
        "source-0.219.0",
        "source-0.218.0",
        "source-1.0.0-rc.1",
    ]
    assert [u for u in t.urls if "releases?" in u] == [
        f"repos/{REPOSITORY}/releases?per_page=100&page={n}" for n in (1, 2, 3)
    ]
    assert "::warning" not in capsys.readouterr().out


def test_release_set_a_full_last_page_asks_for_the_next_and_does_not_warn(
    capsys: pytest.CaptureFixture[str],
) -> None:
    t = FakeRunner()
    github_routes(t, many_stables(100))
    run_resolve_targets(t, [])
    assert t.urls.count(f"repos/{REPOSITORY}/releases?per_page=100&page=2") == 1
    assert "::warning" not in capsys.readouterr().out


def test_release_set_page_cap_warns_and_still_builds(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rt, "MAX_RELEASE_PAGES", 2)
    t = FakeRunner()
    github_routes(t, many_stables(250))
    targets = list(by_id(run_resolve_targets(t, [])))
    assert targets == ["source-development", "source-0.249.0", "source-0.248.0"]
    # the third page is never asked for (it is not routed)
    assert not any(u.endswith("page=3") for u in t.urls)
    assert (
        "::warning title=Release list truncated::the release set is built from the "
        "newest 200 releases" in capsys.readouterr().out
    )


def test_release_set_partial_page_does_not_warn(
    capsys: pytest.CaptureFixture[str],
) -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    run_resolve_targets(t, [])
    assert "::warning" not in capsys.readouterr().out


def test_release_set_one_tag_sha_failure_fails_only_that_tag() -> None:
    t = FakeRunner()
    github_routes(
        t,
        [
            stable("0.22.0", "2025-02-01T00:00:00Z"),
            stable("0.21.4", "2025-03-01T00:00:00Z"),
        ],
    )
    t.add(f"repos/{REPOSITORY}/commits/refs/tags/0.22.0", http_error(404))
    t.add(tags_url("example/app"), tags_out(["development", "0.21.4", "0.22.0"]))
    targets = by_id(run_resolve_targets(t, ["example/app"]))
    assert targets["source-0.22.0"]["status"] == "failed"
    assert "cannot resolve release tag 0.22.0" in targets["source-0.22.0"]["reason"]
    assert targets["source-0.21.4"]["status"] == "pending"
    assert targets["app-0.21.4"]["status"] == "pending"
    assert targets["app-0.22.0"]["status"] == "pending"


def test_release_set_listing_failure_is_fatal_without_placeholders() -> None:
    t = FakeRunner()
    github_routes(t, releases_status=502)
    with pytest.raises(rt.ResolveError, match="HTTP 502"):
        run_resolve_targets(t, ["example/x"])


def test_release_set_image_looks_up_every_release_tag() -> None:
    t = FakeRunner()
    github_routes(
        t,
        [
            stable("0.22.0", "2025-02-01T00:00:00Z"),
            stable("0.21.4", "2025-03-01T00:00:00Z"),
            candidate("v0.23.0-rc.1", "2025-03-15T00:00:00Z"),
        ],
    )
    t.add(
        tags_url("example/x"),
        tags_out(["development", "0.22.0", "0.21.4", "0.23.0-rc.1"]),
    )
    targets = by_id(run_resolve_targets(t, ["example/x"]))
    assert [(t2["id"], t2["tag"]) for t2 in targets.values()] == [
        ("source-development", None),
        ("source-0.22.0", "0.22.0"),
        ("source-0.21.4", "0.21.4"),
        ("source-v0.23.0-rc.1", "v0.23.0-rc.1"),
        ("x-development", "development"),
        ("x-0.22.0", "0.22.0"),
        ("x-0.21.4", "0.21.4"),
        ("x-0.23.0-rc.1", "0.23.0-rc.1"),
    ]


# --- release sources ----------------------------------------------------------


def test_release_source_target_of_latest_release() -> None:
    t = FakeRunner()
    github_routes(t, [stable("0.12.0", "2025-01-01T00:00:00Z")])
    tag_routes(t, "0.12.0", "c" * 40)
    t.add(tags_url("example/app"), tags_out(["development", "0.12.0"]))
    targets_doc = run_resolve_targets(t, ["example/app"])
    assert list(trivy(targets_doc)) == [
        "source-development",
        "source-0.12.0",
        "app-development",
        "app-0.12.0",
    ]
    assert by_id(targets_doc)["source-0.12.0"] == {
        "id": "source-0.12.0",
        "scanner": "trivy",
        "kind": "fs",
        "image": None,
        "tag": "0.12.0",
        "ref": None,
        "git_ref": "0.12.0",
        "commit_sha": "c" * 40,
        "status": "pending",
        "reason": None,
    }
    # the development source is not a release one
    assert by_id(targets_doc)["source-development"]["tag"] is None
    matrix = rt.build_matrix(targets_doc)
    assert all(set(m) == TARGET_KEYS for m in matrix)
    assert [m["id"] for m in matrix][:2] == ["source-development", "source-0.12.0"]
    # the GitHub release needs no git tag listing


def test_release_source_tag_that_cannot_be_resolved_is_a_failed_target() -> None:
    t = FakeRunner()
    github_routes(t, [stable("0.12.0", "2025-01-01T00:00:00Z")])
    t.add(f"repos/{REPOSITORY}/commits/refs/tags/0.12.0", http_error(404))
    targets_doc = run_resolve_targets(t, [])
    failed = by_id(targets_doc)["source-0.12.0"]
    assert failed["status"] == "failed"
    assert "cannot resolve release tag 0.12.0" in failed["reason"]
    assert "HTTP 404" in failed["reason"]
    assert (failed["kind"], failed["tag"], failed["git_ref"]) == (
        "fs",
        "0.12.0",
        "0.12.0",
    )
    assert [m["id"] for m in rt.build_matrix(targets_doc)] == ["source-development"]
    assert any(
        "source-0.12.0 failed to resolve" in line
        for line in rt.annotations(targets_doc["targets"])
    )


def test_release_source_listing_failure_is_fatal() -> None:
    t = FakeRunner()
    github_routes(t, releases_status=500)
    with pytest.raises(rt.ResolveError, match="HTTP 500"):
        run_resolve_targets(t, [])


def test_release_source_without_images_python_package() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.2.3", "2025-01-01T00:00:00Z")])
    tag_routes(t, "1.2.3", "a1" * 20)
    targets_doc = run_resolve_targets(t, [])
    assert list(trivy(targets_doc)) == ["source-development", "source-1.2.3"]
    assert not any(url.startswith("ghcr.io/") for url in t.urls)


def test_release_source_without_github_release_is_not_applicable() -> None:
    t = FakeRunner()
    github_routes(t, [])
    targets = by_id(run_resolve_targets(t, []))
    assert targets["source-release"]["status"] == "not_applicable"
    assert targets["source-release"]["reason"] == "no GitHub release"
    assert not any("/tags" in url for url in t.urls)


def test_release_source_id_sanitized() -> None:
    t = FakeRunner()
    focus_routes(t, "rel/1.0")
    targets = by_id(run_resolve_targets(t, [], scan_tag="rel/1.0"))
    assert targets["source-rel-1.0"]["git_ref"] == "rel/1.0"


# --- OSV targets --------------------------------------------------------------


def test_osv_target_is_the_twin_of_every_trivy_target() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/app"), tags_out(["development", "1.1.14"]))
    targets_doc = run_resolve_targets(t, ["example/app"])
    # Trivy targets as before, then the OSV twins in the same order
    assert [(x["scanner"], x["id"]) for x in targets_doc["targets"]] == [
        ("trivy", "source-development"),
        ("trivy", "source-1.1.14"),
        ("trivy", "app-development"),
        ("trivy", "app-1.1.14"),
        ("osv", "source-development"),
        ("osv", "source-1.1.14"),
        ("osv", "app-development"),
        ("osv", "app-1.1.14"),
    ]
    trivy_targets, osv = targets_doc["targets"][:4], targets_doc["targets"][4:]
    assert osv == [{**x, "scanner": "osv"} for x in trivy_targets]


def test_osv_twins_cover_release_sources_in_resolve_order() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    tag_routes(t, "1.1.14", "c" * 40)
    t.add(tags_url("example/app"), tags_out(["development", "1.1.14"]))
    targets_doc = run_resolve_targets(
        t, ["example/app"]
    )
    trivy_ids = ["source-development", "source-1.1.14", "app-development", "app-1.1.14"]
    assert [(x["scanner"], x["id"]) for x in targets_doc["targets"]] == [
        *(("trivy", i) for i in trivy_ids),
        *(("osv", i) for i in trivy_ids),
    ]
    by_identity = {(x["scanner"], x["id"]): x for x in targets_doc["targets"]}
    twin = by_identity[("osv", "source-1.1.14")]
    # the twin carries every field of its Trivy target, `tag` and `commit_sha` included
    assert twin == {**by_identity[("trivy", "source-1.1.14")], "scanner": "osv"}
    assert (twin["tag"], twin["git_ref"], twin["commit_sha"]) == (
        "1.1.14",
        "1.1.14",
        "c" * 40,
    )
    # a release source that failed to resolve has a not_applicable twin
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(f"repos/{REPOSITORY}/commits/refs/tags/1.1.14", http_error(404))
    failed = {
        (x["scanner"], x["id"]): x
        for x in run_resolve_targets(t, [])[
            "targets"
        ]
    }
    assert failed[("trivy", "source-1.1.14")]["status"] == "failed"
    assert failed[("osv", "source-1.1.14")]["status"] == "not_applicable"
    assert failed[("osv", "source-1.1.14")]["reason"] == "trivy target failed"


def test_osv_twin_of_a_trivy_target_that_will_not_be_scanned_is_not_applicable() -> (
    None
):
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    # No release tag in the registry: the release target is not_applicable
    t.add(tags_url("example/app"), tags_out(["development"]))
    targets_doc = run_resolve_targets(t, ["example/app"])
    by_identity = {(x["scanner"], x["id"]): x for x in targets_doc["targets"]}
    trivy = by_identity[("trivy", "app-1.1.14")]
    osv = by_identity[("osv", "app-1.1.14")]
    assert trivy["status"] == "not_applicable"
    assert osv["status"] == "not_applicable"
    assert osv["reason"] == "trivy target not_applicable"
    assert by_identity[("osv", "source-development")]["status"] == "pending"


def test_osv_twin_of_a_trivy_target_that_failed_to_resolve_is_not_applicable() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/app"), http_error(404))
    targets_doc = run_resolve_targets(t, ["example/app"])
    osv = [x for x in targets_doc["targets"] if x["scanner"] == "osv"]
    assert [(x["id"], x["status"]) for x in osv] == [
        ("source-development", "pending"),
        ("source-1.1.14", "pending"),
        ("app-development", "not_applicable"),
        ("app-1.1.14", "not_applicable"),
    ]
    assert {x["reason"] for x in osv[2:]} == {"trivy target failed"}


def test_matrix_holds_only_pending_trivy_targets() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/app"), tags_out(["development", "1.1.14"]))
    targets_doc = run_resolve_targets(t, ["example/app"])
    assert [m["id"] for m in rt.build_matrix(targets_doc)] == [
        "source-development",
        "source-1.1.14",
        "app-development",
        "app-1.1.14",
    ]


def test_osv_twins_are_not_annotated_twice() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/app"), tags_out(["development"]))
    targets_doc = run_resolve_targets(t, ["example/app"])
    lines = rt.annotations(targets_doc["targets"])
    assert len(lines) == 1
    assert "app-1.1.14" in lines[0]


def test_target_identity_is_scanner_and_id() -> None:
    same_id = {"id": "source-development", "scanner": "trivy"}
    rt.check_unique_ids([same_id, {**same_id, "scanner": "osv"}])
    with pytest.raises(rt.ResolveError, match="collision"):
        rt.check_unique_ids([same_id, dict(same_id)])


def test_render_table_names_the_scanner() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    table = rt.render_table(run_resolve_targets(t, [])["targets"])
    assert [line.split()[:2] for line in table.splitlines()] == [
        ["ID", "SCANNER"],
        ["source-development", "trivy"],
        ["source-1.1.14", "trivy"],
        ["source-development", "osv"],
        ["source-1.1.14", "osv"],
    ]


def test_run_adds_osv_twins(tmp_path: Path) -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    tag_routes(t, "1.1.14", "b" * 40)
    output_file = tmp_path / "github_output"
    env = {**ENV, "GITHUB_OUTPUT": str(output_file), "GITHUB_TOKEN": "tkn"}
    env = {**run_env(tmp_path / "out"), **env}
    rt.run(env, t)
    outputs = parse_github_output(output_file.read_text(encoding="utf-8"))
    assert [m["id"] for m in json.loads(outputs["matrix"])] == [
        "source-development",
        "source-1.1.14",
    ]
    targets_doc = json.loads(
        (tmp_path / "out" / "targets.json").read_text(encoding="utf-8")
    )
    assert [(x["scanner"], x["id"]) for x in targets_doc["targets"]] == [
        ("trivy", "source-development"),
        ("trivy", "source-1.1.14"),
        ("osv", "source-development"),
        ("osv", "source-1.1.14"),
    ]


# --- the image scan toggle ------------------------------------------------------


def osv_twins(targets_doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        t["id"]: t for t in targets_doc["targets"] if t["scanner"] == "osv"
    }


def test_image_scan_disabled_marks_only_image_osv_twins() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/app"), tags_out(["development", "1.1.14"]))
    inputs = rt.Inputs(
        repository=REPOSITORY,
        caller_repository=CALLER,
        images=["example/app"],
        image_scan=False,
    )
    twins = osv_twins(
        rt.resolve_targets(inputs, rt.GitHubClient(t), rt.RegistryClient(t, "ghcr.io"), ENV)
    )
    assert twins["source-development"].get("image_scan_disabled") is None
    assert twins["source-1.1.14"].get("image_scan_disabled") is None
    assert twins["app-development"]["image_scan_disabled"] is True
    assert twins["app-1.1.14"]["image_scan_disabled"] is True


@pytest.mark.parametrize("image_scan", [None, True])
def test_image_scan_enabled_leaves_no_flag_on_any_twin(image_scan: bool | None) -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/app"), tags_out(["development", "1.1.14"]))
    inputs = rt.Inputs(
        repository=REPOSITORY,
        caller_repository=CALLER,
        images=["example/app"],
        **({"image_scan": image_scan} if image_scan is not None else {}),
    )
    targets_doc = rt.resolve_targets(
        inputs, rt.GitHubClient(t), rt.RegistryClient(t, "ghcr.io"), ENV
    )
    assert not any("image_scan_disabled" in t for t in targets_doc["targets"])


def test_image_scan_disabled_does_not_change_the_target_statuses() -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/app"), tags_out(["development", "1.1.14"]))
    inputs = rt.Inputs(
        repository=REPOSITORY,
        caller_repository=CALLER,
        images=["example/app"],
        image_scan=False,
    )
    targets_doc = rt.resolve_targets(
        inputs, rt.GitHubClient(t), rt.RegistryClient(t, "ghcr.io"), ENV
    )
    assert {t["status"] for t in targets_doc["targets"]} == {"pending"}


def test_image_scan_input_parsing(tmp_path: Path) -> None:
    for raw, expected in [
        ("true", True),
        ("", True),
        ("True", True),
        ("false", False),
        ("False", False),
        ("0", False),
        ("no", False),
    ]:
        inputs = rt.Inputs.from_environ(run_env(tmp_path, IMAGE_SCAN=raw))
        assert inputs.image_scan is expected, raw


def test_release_lines_input_parsing(tmp_path: Path) -> None:
    for raw, expected in [("2", 2), ("1", 1), ("", 2), (" 3 ", 3), ("0", 1), ("-4", 1)]:
        inputs = rt.Inputs.from_environ(run_env(tmp_path, RELEASE_LINES=raw))
        assert inputs.release_lines == expected, raw
    with pytest.raises(rt.ResolveError, match="release-lines must be a number"):
        rt.Inputs.from_environ(run_env(tmp_path, RELEASE_LINES="abc"))


def test_release_lines_input_drives_the_set(tmp_path: Path) -> None:
    t = FakeRunner()
    github_routes(t, two_lines())
    inputs = rt.Inputs(
        repository=REPOSITORY, caller_repository=CALLER, release_lines=1
    )
    targets_doc = rt.resolve_targets(
        inputs, rt.GitHubClient(t), rt.RegistryClient(t, "ghcr.io"), ENV
    )
    assert list(by_id(targets_doc)) == ["source-development", "source-0.22.0"]


# --- the scan tag (a focus run on one tag) ---------------------------------------


def focus_routes(runner: FakeRunner, tag: str, sha: str = "d" * 40) -> None:
    github_routes(runner, [])
    tag_routes(runner, tag, sha)


def test_scan_tag_focuses_the_run_on_the_tag() -> None:
    t = FakeRunner()
    focus_routes(t, "0.22.0")
    t.add(tags_url("example/app"), tags_out(["development", "0.22.0", "0.21.4"]))
    targets_doc = run_resolve_targets(t, ["example/app"], scan_tag="0.22.0")
    assert list(by_id(targets_doc)) == ["source-0.22.0", "app-0.22.0"]
    source = by_id(targets_doc)["source-0.22.0"]
    assert source["kind"] == "fs"
    assert (source["tag"], source["git_ref"], source["commit_sha"]) == (
        "0.22.0",
        "0.22.0",
        "d" * 40,
    )
    assert source["status"] == "pending"
    image = by_id(targets_doc)["app-0.22.0"]
    assert image["ref"] == "ghcr.io/example/app:0.22.0"
    assert image["status"] == "pending"
    # the header keeps the default branch as context, the tag as the scan ref
    assert targets_doc["default_branch"] == "development"
    assert targets_doc["commit_sha"] == "a" * 40
    assert targets_doc["scan_ref"] == "0.22.0"


def test_focus_run_never_lists_releases_and_has_no_development_target() -> None:
    t = FakeRunner()
    focus_routes(t, "0.22.0")
    t.add(tags_url("example/app"), tags_out(["development", "0.22.0"]))
    targets_doc = run_resolve_targets(t, ["example/app"], scan_tag="0.22.0")
    assert not any("releases" in url for url in t.urls)
    assert "app-development" not in by_id(targets_doc)
    assert "source-development" not in by_id(targets_doc)
    matrix = rt.build_matrix(targets_doc)
    assert [m["id"] for m in matrix] == ["source-0.22.0", "app-0.22.0"]
    assert all(set(m) == TARGET_KEYS for m in matrix)


@pytest.mark.parametrize(
    ("git_tag", "registry_tag"), [("1.2.3", "1.2.3"), ("v1.2.3", "1.2.3")]
)
def test_focus_image_matches_the_v_stripped_registry_tag(
    git_tag: str, registry_tag: str
) -> None:
    t = FakeRunner()
    focus_routes(t, git_tag)
    t.add(tags_url("example/app"), tags_out(["development", registry_tag]))
    targets = by_id(run_resolve_targets(t, ["example/app"], scan_tag=git_tag))
    assert targets[f"app-{git_tag.removeprefix('v')}"]["status"] == "pending"


def test_focus_image_missing_the_tag_is_not_applicable() -> None:
    t = FakeRunner()
    focus_routes(t, "0.22.0")
    t.add(tags_url("example/app-bff"), tags_out(["development", "0.21.4"]))
    targets = by_id(run_resolve_targets(t, ["example/app-bff"], scan_tag="0.22.0"))
    missing = targets["app-bff-0.22.0"]
    assert missing["status"] == "not_applicable"
    assert missing["reason"] == "release 0.22.0 not published for this image"
    assert missing["ref"] == "ghcr.io/example/app-bff:0.22.0"


def test_focus_image_listing_failure_fails_the_image() -> None:
    t = FakeRunner()
    focus_routes(t, "0.22.0")
    t.add(tags_url("example/app"), http_error(404))
    targets = by_id(run_resolve_targets(t, ["example/app"], scan_tag="0.22.0"))
    failed = targets["app-0.22.0"]
    assert failed["status"] == "failed"
    assert "HTTP 404" in failed["reason"]


def test_focus_run_with_an_unresolvable_tag_fails() -> None:
    t = FakeRunner()
    github_routes(t, [])
    t.add(f"repos/{REPOSITORY}/commits/refs/tags/0.22.0", http_error(404))
    with pytest.raises(rt.ResolveError, match="HTTP 404"):
        run_resolve_targets(t, ["example/app"], scan_tag="0.22.0")


def test_focus_run_id_is_sanitized_and_unique(tmp_path: Path) -> None:
    t = FakeRunner()
    focus_routes(t, "release/1.0")
    t.add(tags_url("example/some_image"), tags_out(["release-1.0"]))
    targets_doc = run_resolve_targets(t, ["example/some_image"], scan_tag="release/1.0")
    assert list(by_id(targets_doc)) == ["source-release-1.0", "some_image-release-1.0"]
    ids = [t2["id"] for t2 in targets_doc["targets"]]
    assert len(ids) == 4
    assert len({(t2["scanner"], t2["id"]) for t2 in targets_doc["targets"]}) == 4


def test_focus_run_with_empty_images_is_source_only() -> None:
    t = FakeRunner()
    focus_routes(t, "0.22.0")
    targets_doc = run_resolve_targets(t, [], scan_tag="0.22.0")
    assert list(by_id(targets_doc)) == ["source-0.22.0"]
    assert not any(url.startswith("ghcr.io/") for url in t.urls)


@pytest.mark.parametrize("raw", ["", "   ", "\t\n"])
def test_whitespace_scan_tag_behaves_as_a_regular_run(tmp_path: Path, raw: str) -> None:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    inputs = rt.Inputs.from_environ(run_env(tmp_path, SCAN_TAG=raw))
    assert inputs.scan_tag is None
    targets_doc = rt.resolve_targets(
        inputs, rt.GitHubClient(t), rt.RegistryClient(t, "ghcr.io"), ENV
    )
    assert list(by_id(targets_doc)) == ["source-development", "source-1.1.14"]
    assert "scan_ref" not in targets_doc


@pytest.mark.parametrize(
    "missing", ["GITHUB_RUN_ID", "GITHUB_EVENT_NAME", "GITHUB_TRIGGERING_ACTOR"]
)
def test_run_without_the_event_header_fails(tmp_path: Path, missing: str) -> None:
    env = {k: v for k, v in ENV.items() if k != missing}
    t = FakeRunner()
    github_routes(t, [])
    inputs = rt.Inputs(repository=REPOSITORY, caller_repository=CALLER)
    with pytest.raises(rt.ResolveError, match=missing):
        rt.resolve_targets(
            inputs, rt.GitHubClient(t), rt.RegistryClient(t, "ghcr.io"), env
        )


def test_document_header_carries_event_actor_and_the_scan_ref() -> None:
    t = FakeRunner()
    github_routes(t, [])
    targets_doc = run_resolve_targets(t, [])
    assert targets_doc["event"] == "workflow_dispatch"
    assert targets_doc["actor"] == "octocat"
    assert "scan_ref" not in targets_doc
    t = FakeRunner()
    focus_routes(t, "0.22.0")
    focused = run_resolve_targets(t, [], scan_tag="0.22.0")
    assert focused["event"] == "workflow_dispatch"
    assert focused["actor"] == "octocat"
    assert focused["scan_ref"] == "0.22.0"


def test_focus_run_target_schema_is_uniform() -> None:
    t = FakeRunner()
    focus_routes(t, "0.22.0")
    t.add(tags_url("example/app"), tags_out(["development", "0.22.0"]))
    targets_doc = run_resolve_targets(t, ["example/app"], scan_tag="0.22.0")
    kinds = {x["kind"] for x in targets_doc["targets"]}
    assert kinds == {"fs", "image"}
    trivy_targets = list(trivy(targets_doc).values())
    matrix = rt.build_matrix(targets_doc)
    assert all(set(m) == {"id", "kind", "ref", "commit_sha"} for m in matrix)
    for target in trivy_targets:
        assert set(target) == TARGET_KEYS | {
            "scanner",
            "image",
            "tag",
            "git_ref",
            "status",
            "reason",
        }
        if target["kind"] == "image":
            assert target["git_ref"] is None
            assert target["commit_sha"] is None
        else:
            assert target["git_ref"]
            assert target["commit_sha"]
    twins = osv_twins(targets_doc)
    assert twins["source-0.22.0"]["status"] == "pending"
    assert twins["app-0.22.0"]["status"] == "pending"




# --- the forced image scan (a manual run on a repository that has the scan off) --


def resolve_with(
    image_scan: bool, force_image_scan: bool | None = None
) -> dict[str, Any]:
    t = FakeRunner()
    github_routes(t, [stable("1.1.14", "2025-01-01T00:00:00Z")])
    t.add(tags_url("example/app"), tags_out(["development", "1.1.14"]))
    inputs = rt.Inputs(
        repository=REPOSITORY,
        caller_repository=CALLER,
        images=["example/app"],
        image_scan=image_scan,
        **({} if force_image_scan is None else {"force_image_scan": force_image_scan}),
    )
    return rt.resolve_targets(
        inputs, rt.GitHubClient(t), rt.RegistryClient(t, "ghcr.io"), ENV
    )


def test_force_image_scan_runs_the_scan_and_marks_the_run() -> None:
    targets_doc = resolve_with(image_scan=False, force_image_scan=True)
    assert targets_doc["forced_image_scan"] is True
    assert not any("image_scan_disabled" in t for t in targets_doc["targets"])


def test_force_image_scan_on_a_repository_with_the_scan_on_marks_nothing() -> None:
    targets_doc = resolve_with(image_scan=True, force_image_scan=True)
    assert "forced_image_scan" not in targets_doc
    assert not any("image_scan_disabled" in t for t in targets_doc["targets"])


def test_without_force_the_disabled_scan_stays_disabled_and_unmarked() -> None:
    targets_doc = resolve_with(image_scan=False)
    assert "forced_image_scan" not in targets_doc
    assert any(t.get("image_scan_disabled") for t in targets_doc["targets"])


def test_force_image_scan_input_parsing(tmp_path: Path) -> None:
    for raw, expected in [
        ("true", True),
        ("True", True),
        (" true ", True),
        ("", False),
        ("false", False),
        ("0", False),
        ("anything", False),
    ]:
        inputs = rt.Inputs.from_environ(run_env(tmp_path, FORCE_IMAGE_SCAN=raw))
        assert inputs.force_image_scan is expected, raw
    assert rt.Inputs.from_environ(run_env(tmp_path)).force_image_scan is False


def test_run_writes_the_forced_image_scan_to_targets_json(tmp_path: Path) -> None:
    t = FakeRunner()
    github_routes(t, [])
    env = run_env(tmp_path / "out", IMAGE_SCAN="false", FORCE_IMAGE_SCAN="true")
    rt.run(env, t)
    doc = json.loads((tmp_path / "out" / "targets.json").read_text(encoding="utf-8"))
    assert doc["forced_image_scan"] is True
