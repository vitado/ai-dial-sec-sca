#!/usr/bin/env python3
"""Resolve the scan targets (source snapshot + container images) of one repository.

Used by the SCA scheduled scan. Asks the GitHub REST API through ``gh api`` and the
image registry through ``oras repo tags`` (both are on the runner). Standard library
only.

Every call of an external tool goes through a ``Runner`` (a callable
``(argv, stdin) -> stdout``), so the logic can be tested with a fake runner and no
network.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

from _sca_lib import append_text, dump_json, escape_command_data

GITHUB_API_VERSION = "2022-11-28"
GHCR_HOST = "ghcr.io"
DOCKER_HUB_HOST = "registry-1.docker.io"
# Docker Hub answers the registry API on another host than the one it goes by
HOST_ALIASES = {"docker.io": DOCKER_HUB_HOST, "index.docker.io": DOCKER_HUB_HOST}

TOOL_TIMEOUT_SECONDS = 120.0
MAX_ATTEMPTS = 4
BACKOFF_BASE_SECONDS = 1.0
RELEASES_PER_PAGE = 100

_NAME_PART = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
IMAGE_NAME = re.compile(rf"{_NAME_PART}(?:/{_NAME_PART})*", re.ASCII)
REPOSITORY_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
UNSAFE_ID_CHARS = re.compile(r"[^A-Za-z0-9._-]")
# A client error (not rate limiting) will not go away by itself: no retry.
PERMANENT_ERROR = re.compile(r"(?:HTTP|status code:?) (?!429)4\d\d", re.IGNORECASE)
NOT_FOUND = re.compile(r"(?:HTTP|status code:?) 404", re.IGNORECASE)


class ResolveError(Exception):
    """A GitHub or registry request that failed, or an input that is unusable."""


class ToolError(Exception):
    """An external tool (``gh``, ``oras``) failed; the message is its stderr."""


Runner = Callable[[Sequence[str], str | None], str]


def make_runner(
    token: str | None, sleep: Callable[[float], None] = time.sleep
) -> Runner:
    """The production runner: ``subprocess.run`` with a timeout and bounded retries.

    ``gh`` gets the token as ``GH_TOKEN``. A failure is retried with a growing delay
    unless it is a client error (HTTP 4xx other than 429).
    """
    env = {**os.environ, **({"GH_TOKEN": token} if token else {})}

    def run_tool(argv: Sequence[str], stdin: str | None = None) -> str:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                done = subprocess.run(
                    list(argv),
                    input=stdin,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=TOOL_TIMEOUT_SECONDS,
                )
                if done.returncode == 0:
                    return done.stdout
                message = done.stderr.strip() or f"{argv[0]} exited {done.returncode}"
            except subprocess.TimeoutExpired:
                message = f"{argv[0]} timed out after {TOOL_TIMEOUT_SECONDS:.0f}s"
            except OSError as err:
                raise ToolError(f"cannot run {argv[0]}: {err}") from err
            if attempt == MAX_ATTEMPTS or PERMANENT_ERROR.search(message):
                raise ToolError(message)
            sleep(BACKOFF_BASE_SECONDS * 2 ** (attempt - 1))

    return run_tool


class GitHubClient:
    """The GitHub REST API through ``gh api``."""

    def __init__(self, run: Runner) -> None:
        self._run = run

    def _get(self, path: str, missing_ok: bool = False) -> Any:
        """The JSON response of GET ``path``; None for HTTP 404 if ``missing_ok``."""
        argv = ["gh", "api", "-H", f"X-GitHub-Api-Version: {GITHUB_API_VERSION}", path]
        try:
            return json.loads(self._run(argv, None))
        except ToolError as err:
            if missing_ok and NOT_FOUND.search(str(err)):
                return None
            raise ResolveError(f"GitHub API GET {path} failed: {err}") from err

    def default_branch(self, repo: str) -> str:
        return self._get(f"repos/{repo}")["default_branch"]

    def commit_sha(self, repo: str, ref: str) -> str:
        quoted = urllib.parse.quote(ref, safe="")
        return self._get(f"repos/{repo}/commits/{quoted}")["sha"]

    def releases(self, repo: str) -> list[dict[str, Any]]:
        """The published releases, one page (newest first); a repository without
        releases has none, which is not an error."""
        releases = (
            self._get(
                f"repos/{repo}/releases?per_page={RELEASES_PER_PAGE}", missing_ok=True
            )
            or []
        )
        if len(releases) == RELEASES_PER_PAGE:
            print(
                f"::warning title=Release list truncated::the release set is built "
                f"from the newest {RELEASES_PER_PAGE} releases"
            )
        return releases

    def tag_commit_sha(self, repo: str, tag: str) -> str:
        """Commit a git tag points to (the API peels an annotated tag to its commit)."""
        quoted = urllib.parse.quote(tag, safe="/")
        return self._get(f"repos/{repo}/commits/refs/tags/{quoted}")["sha"]


class RegistryClient:
    """Lists image tags with ``oras repo tags`` (any OCI registry)."""

    def __init__(
        self, run: Runner, registry: str, github_token: str | None = None
    ) -> None:
        self.registry = registry
        self._run = run
        self._github_token = github_token

    def tags(self, image: str) -> list[str]:
        """All tags of an image; raises ResolveError on any failure."""
        host = HOST_ALIASES.get(self.registry, self.registry)
        repository = image
        if host == DOCKER_HUB_HOST and "/" not in image:
            repository = f"library/{image}"
        argv = ["oras", "repo", "tags"]
        stdin = None
        # Credentials go to ghcr.io only; every other registry is asked anonymously.
        if self._github_token and host == GHCR_HOST:
            argv += ["--username", "github-actions", "--password-stdin"]
            stdin = self._github_token
        try:
            return self._run([*argv, f"{host}/{repository}"], stdin).split()
        except ToolError as err:
            raise ResolveError(
                f"{self.registry}: listing tags of {image} failed: {err}"
            ) from err


def make_target(
    status: str,
    reason: str | None = None,
    *,
    image: str | None = None,
    tag: str | None = None,
    ref: str | None = None,
    git_ref: str | None = None,
    commit_sha: str | None = None,
) -> dict[str, Any]:
    """A Trivy target: an image (``ref`` is its reference), or the source at
    ``git_ref`` pinned to ``commit_sha`` (a release source has a ``tag`` too).

    The id names the subject and is stable across runs, so it never contains the
    SHA; without a known tag it ends with ``release``.
    """
    stem = image.rsplit("/", 1)[-1] if image else "source"
    return {
        "id": UNSAFE_ID_CHARS.sub("-", f"{stem}-{tag or git_ref or 'release'}"),
        "scanner": "trivy",
        "kind": "image" if image else "fs",
        "image": image,
        "tag": tag,
        "ref": ref,
        "git_ref": git_ref,
        "commit_sha": commit_sha,
        "status": status,
        "reason": reason,
    }


def make_osv_target(
    trivy_target: Mapping[str, Any], image_scan_disabled: bool = False
) -> dict[str, Any]:
    """The OSV twin of a Trivy target: OSV queries the packages Trivy found, so the
    twin has something to do only if the Trivy target is scanned. An image twin can
    carry ``image_scan_disabled``: the direct OSV image scan is switched off for the
    repository (an image too large for the runner disk), the BOM query stays.
    """
    twin = {**trivy_target, "scanner": "osv"}
    if image_scan_disabled and trivy_target["kind"] == "image":
        twin["image_scan_disabled"] = True
    if trivy_target["status"] != "pending":
        twin["status"] = "not_applicable"
        twin["reason"] = f"trivy target {trivy_target['status']}"
    return twin


def parse_images(raw: str) -> list[str]:
    images = [line.strip() for line in raw.splitlines() if line.strip()]
    for image in images:
        if not IMAGE_NAME.fullmatch(image):
            raise ResolveError(
                f"invalid image name {image!r}: "
                "expected a lowercase name without registry or tag"
            )
    return images


VERSION_TAG = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class Release(NamedTuple):
    """One GitHub release of the set; ``tag`` None is the placeholder for a
    repository with no releases at all."""

    tag: str | None
    published_at: str


NO_RELEASE = Release(None, "")


class ReleaseSet(NamedTuple):
    """The scan set of releases: the newest patch of each of the last N minor
    lines, at most one candidate, and stables whose tag matches no line."""

    stables: list[Release]
    candidate: Release | None
    unmatched: list[Release]


def release_line(tag: str) -> tuple[int, int] | None:
    """The ``X.Y`` minor line of an ``X.Y.Z`` tag."""
    if match := VERSION_TAG.fullmatch(tag):
        return int(match[1]), int(match[2])
    return None


def resolve_release_set(
    github: GitHubClient, repository: str, release_lines: int
) -> ReleaseSet:
    """The releases to scan, read from the flags the repository sets: a stable is
    a release with ``prerelease`` and ``draft`` false, drafts are ignored. A line's
    patch is its stable published last, so a hotfix lifts the patch, not the line."""
    stables_by_line: dict[tuple[int, int], Release] = {}
    candidates: list[Release] = []
    unmatched: list[Release] = []
    for item in github.releases(repository):
        if item["draft"]:
            continue
        release = Release(item["tag_name"], item["published_at"])
        if item["prerelease"]:
            candidates.append(release)
        elif line := release_line(release.tag):
            current = stables_by_line.get(line)
            # first seen wins a tie: GitHub returns the releases newest first
            if current is None or release.published_at > current.published_at:
                stables_by_line[line] = release
        else:
            unmatched.append(release)
    newest_lines = sorted(stables_by_line, reverse=True)[:release_lines]
    candidate = max(candidates, key=lambda r: r.published_at, default=None)
    return ReleaseSet(
        [stables_by_line[line] for line in newest_lines], candidate, unmatched
    )


def image_target(
    registry: RegistryClient,
    image: str,
    tag: str | None,
    status: str,
    reason: str | None = None,
) -> dict[str, Any]:
    """An image target of ``registry``: the reference is the image at ``tag``."""
    ref = f"{registry.registry}/{image}:{tag}" if tag else None
    return make_target(status, reason, image=image, tag=tag, ref=ref)


def resolve_image_targets(
    registry: RegistryClient, image: str, releases: Sequence[Release]
) -> list[dict[str, Any]]:
    """Targets of one image: the ``development`` tag and every release tag of the
    set (one tags listing per image, the ``development`` target once)."""
    try:
        tags = registry.tags(image)
    except ResolveError as err:
        return [
            image_target(registry, image, "development", "failed", str(err)),
            *[
                image_target(registry, image, r.tag, "failed", str(err))
                for r in releases
            ],
        ]

    if "development" in tags:
        targets = [image_target(registry, image, "development", "pending")]
    else:
        reason = "tag development not published for this image"
        targets = [
            image_target(registry, image, "development", "not_applicable", reason)
        ]

    for release in releases:
        if release.tag is None:
            targets.append(
                image_target(
                    registry, image, None, "not_applicable", "no GitHub release"
                )
            )
            continue
        # the registry tag may lack the ``v`` of the git tag
        candidates = (release.tag, release.tag.removeprefix("v"))
        if found := next((t for t in candidates if t in tags), None):
            targets.append(image_target(registry, image, found, "pending"))
        else:
            reason = f"release {release.tag} not published for this image"
            targets.append(
                image_target(registry, image, release.tag, "not_applicable", reason)
            )
    return targets


def resolve_release_source_target(
    github: GitHubClient, repository: str, release: Release
) -> dict[str, Any]:
    """The source target of one release: the repository at its git tag, so that
    repositories without images have a release scan too."""

    def source_target(status: str, reason: str | None = None, sha: str | None = None):
        return make_target(
            status, reason, tag=release.tag, git_ref=release.tag, commit_sha=sha
        )

    if release.tag is None:
        return source_target("not_applicable", "no GitHub release")
    try:
        sha = github.tag_commit_sha(repository, release.tag)
    except ResolveError as err:
        reason = f"cannot resolve release tag {release.tag}: {err}"
        return source_target("failed", reason)
    return source_target("pending", sha=sha)


def resolve_focus_image_targets(
    registry: RegistryClient, image: str, tag: str
) -> list[dict[str, Any]]:
    """The image targets of a focus run: the scan tag only, no ``development``
    (a manual run of one tag is not about the moving branch head)."""
    try:
        tags = registry.tags(image)
    except ResolveError as err:
        return [image_target(registry, image, tag, "failed", str(err))]
    # the registry tag may lack the ``v`` of the git tag
    candidates = (tag, tag.removeprefix("v"))
    if found := next((t for t in candidates if t in tags), None):
        return [image_target(registry, image, found, "pending")]
    reason = f"release {tag} not published for this image"
    return [image_target(registry, image, tag, "not_applicable", reason)]


def resolve_focus_targets(
    github: GitHubClient,
    registry: RegistryClient,
    repository: str,
    images: Sequence[str],
    tag: str,
) -> list[dict[str, Any]]:
    """The targets of a focus run on one tag: its source and, per image, the tag
    itself. An unresolvable tag fails the run: there is no set to fall back to."""
    sha = github.tag_commit_sha(repository, tag)
    targets = [make_target("pending", tag=tag, git_ref=tag, commit_sha=sha)]
    for image in images:
        targets.extend(resolve_focus_image_targets(registry, image, tag))
    return targets


def check_unique_ids(targets: Sequence[Mapping[str, Any]]) -> None:
    """A target is identified by its scanner and id (the id names the subject)."""
    seen: set[tuple[str, str]] = set()
    for target in targets:
        identity = (target["scanner"], target["id"])
        if identity in seen:
            raise ResolveError(f"target id collision: {target['id']!r}")
        seen.add(identity)


@dataclass(frozen=True)
class Inputs:
    """The inputs of the action (see ``action.yml``) and the calling workflow run."""

    repository: str
    caller_repository: str
    registry: str = GHCR_HOST
    images: Sequence[str] = ()
    image_scan: bool = True
    release_lines: int = 2
    token: str | None = None
    scan_tag: str | None = None

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> Inputs:
        """Read the inputs, which the action passes as environment variables
        (``REPOSITORY``, ``IMAGES``, ...)."""
        repository = environ["REPOSITORY"]
        if not REPOSITORY_NAME.fullmatch(repository):
            raise ResolveError(f"repository must be 'owner/name', got {repository!r}")

        raw_lines = (environ.get("RELEASE_LINES") or "2").strip()
        try:
            release_lines = int(raw_lines)
        except ValueError:
            raise ResolveError(
                f"release-lines must be a number, got {raw_lines!r}"
            ) from None

        return cls(
            repository=repository,
            caller_repository=environ["GITHUB_REPOSITORY"],
            registry=environ.get("REGISTRY") or GHCR_HOST,
            images=tuple(parse_images(environ.get("IMAGES", ""))),
            image_scan=(environ.get("IMAGE_SCAN") or "true").strip().lower()
            not in ("false", "0", "no"),
            release_lines=max(release_lines, 1),
            token=environ.get("GITHUB_TOKEN") or None,
            scan_tag=(environ.get("SCAN_TAG") or "").strip() or None,
        )


def resolve_release_targets(
    github: GitHubClient,
    registry: RegistryClient,
    repository: str,
    images: Sequence[str],
    release_lines: int,
    default_branch: str,
    commit_sha: str,
) -> list[dict[str, Any]]:
    """The targets of the release scan: the default-branch snapshot, the sources
    of the release set and, per image, its ``development`` and release tags."""
    release_set = resolve_release_set(github, repository, release_lines)
    if (
        not release_set.stables
        and release_set.candidate is None
        and not release_set.unmatched
    ):
        # the report must show that the repository publishes no releases at all
        release_set = ReleaseSet([NO_RELEASE], None, [])
    # an unmatched tag belongs to no release line, so no image is looked up for it
    image_releases: list[Release] = [*release_set.stables]
    if release_set.candidate is not None:
        image_releases.append(release_set.candidate)
    targets: list[dict[str, Any]] = [
        make_target("pending", git_ref=default_branch, commit_sha=commit_sha)
    ]
    for release in release_set.stables:
        targets.append(resolve_release_source_target(github, repository, release))
    if release_set.candidate is not None:
        targets.append(
            resolve_release_source_target(github, repository, release_set.candidate)
        )
    for release in release_set.unmatched:
        reason = (
            f"release tag {release.tag} is not X.Y.Z, so it belongs to no release line"
        )
        targets.append(
            make_target("not_applicable", reason, tag=release.tag, git_ref=release.tag)
        )
    for image in images:
        targets.extend(resolve_image_targets(registry, image, image_releases))
    return targets


def resolve_targets(
    inputs: Inputs,
    github: GitHubClient,
    registry: RegistryClient,
    environ: Mapping[str, str],
) -> dict[str, Any]:
    """Build the targets.json document. Raises ResolveError without a snapshot.

    A scan tag focuses the run on that one tag: its source and, per image, the tag
    itself. Otherwise the release set of ``release_lines`` minor lines is scanned:
    the source of each of its tags and, in every image, each of its tags. Every
    Trivy target has an OSV twin.

    Order: the development source, the release sources (newest line first, then
    the candidate, then the unmatched not-applicable ones), then the targets of
    each image in ``images`` order.
    """
    repository = inputs.repository
    default_branch = github.default_branch(repository)
    commit_sha = github.commit_sha(repository, default_branch)

    if inputs.scan_tag:
        # a manual run on one tag: the default branch stays in the header as context
        targets = resolve_focus_targets(
            github, registry, repository, inputs.images, inputs.scan_tag
        )
    else:
        targets = resolve_release_targets(
            github,
            registry,
            repository,
            inputs.images,
            inputs.release_lines,
            default_branch,
            commit_sha,
        )
    # After all trivy targets, in the same order
    disabled = not inputs.image_scan
    targets.extend([make_osv_target(t, image_scan_disabled=disabled) for t in targets])
    check_unique_ids(targets)

    run_id = environ["GITHUB_RUN_ID"]
    missing = [
        name
        for name in ("GITHUB_EVENT_NAME", "GITHUB_TRIGGERING_ACTOR")
        if not environ.get(name)
    ]
    if missing:
        raise ResolveError(f"missing environment variable(s): {', '.join(missing)}")
    event = environ["GITHUB_EVENT_NAME"]
    actor = environ["GITHUB_TRIGGERING_ACTOR"]
    run_url = f"{environ['GITHUB_SERVER_URL']}/{inputs.caller_repository}"
    return {
        "repo": repository,
        "default_branch": default_branch,
        "commit_sha": commit_sha,
        "run_id": run_id,
        "run_url": f"{run_url}/actions/runs/{run_id}",
        "event": event,
        "actor": actor,
        **({"scan_ref": inputs.scan_tag} if inputs.scan_tag else {}),
        "targets": targets,
    }


def build_matrix(targets_doc: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The pending Trivy targets (the matrix of the trivy job), with the fields the
    job uses."""
    keys = ("id", "kind", "ref", "commit_sha")
    return [
        {k: t[k] for k in keys}
        for t in targets_doc["targets"]
        if t["status"] == "pending" and t["scanner"] == "trivy"
    ]


def render_table(targets: Sequence[Mapping[str, Any]]) -> str:
    rows = [("ID", "SCANNER", "REF", "STATUS", "REASON")]
    rows += [
        (t["id"], t["scanner"], t["ref"] or t["kind"], t["status"], t["reason"] or "")
        for t in targets
    ]
    widths = [max(len(row[i]) for row in rows) for i in range(4)] + [0]
    return "\n".join(
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip()
        for row in rows
    )


def annotations(targets: Sequence[Mapping[str, Any]]) -> list[str]:
    """Annotations of the Trivy targets; an OSV twin only mirrors its Trivy target."""
    lines = []
    for target in targets:
        if target["scanner"] != "trivy":
            continue
        if target["status"] == "not_applicable":
            level, what = "notice", "skipped"
        elif target["status"] == "failed":
            level, what = "warning", "failed to resolve"
        else:
            continue
        lines.append(
            f"::{level} title=Scan target {target['id']} {what}"
            f"::{escape_command_data(target['reason'])}"
        )
    return lines


def run(environ: Mapping[str, str], runner: Runner | None = None) -> None:
    inputs = Inputs.from_environ(environ)
    run_tool = runner or make_runner(inputs.token)
    targets_doc = resolve_targets(
        inputs,
        GitHubClient(run_tool),
        RegistryClient(run_tool, inputs.registry, inputs.token),
        environ,
    )

    output_dir = Path(environ["OUTPUT_DIR"])
    output_dir.mkdir(parents=True, exist_ok=True)
    targets_file = output_dir / "targets.json"
    dump_json(targets_file, targets_doc)

    print(
        f"Repository {targets_doc['repo']} @ {targets_doc['default_branch']} "
        f"({targets_doc['commit_sha']})"
    )
    print(render_table(targets_doc["targets"]))
    for line in annotations(targets_doc["targets"]):
        print(line)

    if output_path := environ.get("GITHUB_OUTPUT"):
        matrix = json.dumps(build_matrix(targets_doc), separators=(",", ":"))
        append_text(output_path, f"matrix={matrix}\ntargets-file={targets_file}\n")


def main() -> int:
    try:
        run(os.environ)
    except ResolveError as err:
        print(
            f"::error title=Scan target resolution failed::{escape_command_data(err)}"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
