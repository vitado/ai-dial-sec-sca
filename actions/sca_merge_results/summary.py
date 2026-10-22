"""summary.md of the SCA merge: the vulnerable packages of every scanned version."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from normalize import SEVERITIES, norm

# GitHub rejects a step summary over 1 MiB; the rest of the limit is left for the
# parts of the job summary that are not this one
STEP_SUMMARY_LIMIT_BYTES = 1024 * 1024 - 16 * 1024

Finding = Mapping[str, Any]


def cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def short_time(value: str | None) -> str:
    return f"{value[:16]}Z" if value else "n/a"


def target_label(target: Mapping[str, Any], repo: str) -> str:
    """``src`` or the short name of the image (``chat``, ``bff``): where a package is
    seen within one version.
    """
    if target["kind"] == "fs":
        return "src"
    image = target["image"].split("/")[-1]
    if image == repo:
        return image.removeprefix("ai-dial-")
    return image.removeprefix(f"{repo}-")


def package_rows(
    findings: Sequence[Finding], source_ids: set[str]
) -> list[dict[str, Any]]:
    """One row per (class, normalized package name) - the version dropped for OS
    packages, which the scanners spell differently (dpkg epochs and revisions) - with
    its unique vulnerabilities merged over targets and scanners (Trivy's severity
    wins). Rows without a fix come last, development-only packages after the others,
    then worst severity first.
    """
    groups: dict[tuple[str, ...], list[Finding]] = {}
    for f in findings:
        key = (f["class"], norm(f["pkg"])) if f["class"] == "os" else (
            f["class"],
            norm(f["pkg"]),
            f["version"],
        )
        groups.setdefault(key, []).append(f)
    rows = []
    for key, fs in groups.items():
        cls = key[0]
        # an OS row keeps a version in its cell: the primary scanner's spelling
        # (Trivy's, else OSV's) - the scanners spell one dpkg version differently,
        # and both spellings in one cell would read as two installed versions
        version = (
            key[-1]
            if len(key) == 3
            else next((f for f in fs if f["scanner"] == "trivy"), fs[0])["version"]
        )
        # the name as written in a source target (lockfile), else the first seen
        pkg = next((f for f in fs if f["target"] in source_ids), fs[0])["pkg"]
        # findings of one vulnerability under different ids merge by shared aliases
        vulns: list[dict[str, Any]] = []
        for f in sorted(fs, key=lambda f: f["scanner"] != "trivy"):
            names = {f["id"], *f.get("aliases", [])}
            v = next((v for v in vulns if v["names"] & names), None)
            if v is None:
                v = {
                    "id": f["id"],
                    "names": set(),
                    "severity": f["severity"],
                    "url": f["url"],
                    "fixed": [],
                    "scanners": set(),
                }
                vulns.append(v)
            v["names"] |= names
            if f["id"].startswith("CVE-") and not v["id"].startswith("CVE-"):
                v["id"], v["url"] = f["id"], f["url"]
            v["fixed"] += [
                x.strip() for x in f["fixed_version"].split(",") if x.strip()
            ]
            v["scanners"].add(f["scanner"])
        ordered = sorted(
            vulns, key=lambda v: (SEVERITIES.index(v["severity"]), v["id"])
        )
        with_chain = next((f for f in fs if f["chain"]), None)
        in_source = [
            loc for f in fs if f["target"] in source_ids for loc in f["locations"]
        ]
        fixed = ", ".join(dict.fromkeys(x for v in ordered for x in v["fixed"]))
        scanners = "+".join(
            s[0].upper()
            for s in ("trivy", "osv")
            if any(s in v["scanners"] for v in ordered)
        )
        rows.append(
            {
                "class": cls,
                "pkg": pkg,
                "version": version,
                "vulns": ordered,
                "severity": ordered[0]["severity"],
                "fixed": fixed,
                "no_fix": not fixed,
                "chain": with_chain["chain"] if with_chain else [],
                "relationship": next(
                    (f["relationship"] for f in fs if f["relationship"]), None
                ),
                "dev": all(f["dev"] for f in fs),
                "where": in_source or [loc for f in fs for loc in f["locations"]],
                "targets": {f["target"] for f in fs},
                "scanners": scanners,
            }
        )
    return sorted(
        rows,
        key=lambda r: (
            r["no_fix"],
            r["dev"],
            SEVERITIES.index(r["severity"]),
            r["pkg"],
            r["version"],
        ),
    )


def where_cell(locations: Sequence[str]) -> str:
    parts = list(dict.fromkeys("/".join(loc.split("/")[-2:]) for loc in locations))
    return cell(
        ", ".join(parts[:2]) + (f" +{len(parts) - 2}" if len(parts) > 2 else "")
    )


def chain_cell(row: Mapping[str, Any]) -> str:
    chain = row["chain"]
    direct = "direct" if chain or row["relationship"] == "direct" else ""
    text = " → ".join(chain) if len(chain) > 1 else direct
    return cell(text)


def vulnerabilities_cell(row: Mapping[str, Any]) -> str:
    mixed = len({v["severity"] for v in row["vulns"]}) > 1
    return ", ".join(
        (v["severity"][0] + " " if mixed else "")
        + (f"[{cell(v['id'])}]({v['url']})" if v["url"] else cell(v["id"]))
        for v in row["vulns"]
    )


def package_table(
    rows: Sequence[Mapping[str, Any]],
    columns: Sequence[tuple[str, str]],
    libraries: bool,
) -> list[str]:
    head = ["Package@version", "Sev", "Fixed", "Vulnerabilities"]
    head += ["Chain", "Where"] if libraries else []
    head += ["Seen in", "Scanner"]
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
    for r in rows:
        cells = [
            cell(f"{r['pkg']}@{r['version']}") + (" `dev`" if r["dev"] else ""),
            r["severity"][0],
            cell(r["fixed"] or "no fix"),
            vulnerabilities_cell(r),
        ]
        if libraries:
            cells += [chain_cell(r), where_cell(r["where"])]
        cells += [
            ", ".join(label for label, tid in columns if tid in r["targets"]),
            r["scanners"],
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def totals(libraries: Sequence[Any], os_rows: Sequence[Any]) -> str:
    fixable = sum(1 for r in [*libraries, *os_rows] if not r["no_fix"])
    return ", ".join(
        [
            plural(len(libraries), "library", "libraries"),
            plural(len(os_rows), "OS package", "OS packages"),
            f"{fixable} fixable",
        ]
    )


def unique_vulnerabilities(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The vulnerabilities of package rows, each once by its id and package, whatever
    the package version (one vulnerability of a package in several versions or
    targets is one); findings under different ids merge by shared aliases.
    """
    found: list[dict[str, Any]] = []
    index: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for r in rows:
        by_name = index.setdefault((r["class"], norm(r["pkg"])), {})
        for v in r["vulns"]:
            u = next((by_name[n] for n in v["names"] if n in by_name), None)
            if u is None:
                u = {"severity": v["severity"], "fixable": False}
                found.append(u)
            u["fixable"] = u["fixable"] or bool(v["fixed"])
            by_name.update(dict.fromkeys(v["names"], u))
    return found


def severity_block(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Counts of the unique vulnerabilities of package rows: per severity and
    overall, ``all`` and ``fixable`` (a fixed version is known).
    """
    by = {s: {"all": 0, "fixable": 0} for s in SEVERITIES}
    for v in unique_vulnerabilities(rows):
        by[v["severity"]]["all"] += 1
        by[v["severity"]]["fixable"] += v["fixable"]
    return {
        "all": sum(b["all"] for b in by.values()),
        "fixable": sum(b["fixable"] for b in by.values()),
        "by_severity": by,
    }


def build_counts(report: Mapping[str, Any]) -> dict[str, Any]:
    """The ``counts`` block of report.json, from the same rows the summary lists.

    ``total`` counts the unique vulnerabilities of the repository (a finding present
    in several targets counts once); ``targets`` counts them per target id, so the
    targets do not sum to the total. A target that is not ``ok`` has its status only.
    The status of a target is its Trivy scan's, as in the summary.
    """
    findings = report["findings"]
    source_ids = {t["id"] for t in report["targets"] if t["kind"] == "fs"}
    targets: dict[str, Any] = {}
    for t in sorted(report["targets"], key=lambda t: t["scanner"] != "trivy"):
        targets.setdefault(t["id"], t)
    result: dict[str, Any] = {}
    for tid, t in targets.items():
        if t["status"] == "ok":
            rows = package_rows([f for f in findings if f["target"] == tid], source_ids)
            result[tid] = {"status": "ok", **severity_block(rows)}
        else:
            result[tid] = {"status": t["status"]}
    return {
        "total": severity_block(package_rows(findings, source_ids)),
        "targets": result,
        "versions": version_counts(report),
    }


def is_release(ref: str, default_branch: str | None) -> bool:
    """A real release: a plain semver tag, not the default branch and not a
    pre-release. A ref that does not parse as semver is not a release, so a
    non-semver tag never becomes the latest release.
    """
    if ref == default_branch or ref == "development":
        return False
    m = VERSION.fullmatch(ref)
    return m is not None and m[2] is None


def version_kind(ref: str, default_branch: str | None) -> str:
    """``development`` for the default branch or ``development``; ``candidate`` for a
    semver with a pre-release part (``0.50.0-rc.1``); ``release`` otherwise (a plain
    semver tag, or any other tag that is neither the branch nor a pre-release).
    """
    if ref == default_branch or ref == "development":
        return "development"
    m = VERSION.fullmatch(ref)
    if m and m[2] is not None:
        return "candidate"
    return "release"


SEVERITY_KEY = {
    "CRITICAL": "c",
    "HIGH": "h",
    "MEDIUM": "m",
    "LOW": "l",
    "UNKNOWN": "unknown",
}


def version_counts(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """One flat record per version of ``versions_of``, in that order: its kind, whether
    it is the latest release, its scan status, and the severity counts of its unique
    vulnerabilities. A version with any non-ok target is ``failed`` with zero counts,
    as ``build_counts`` leaves a non-ok target.

    ``latest`` marks the newest ``ok`` release so the notifier shows a live release as
    a repo's headline, not a failed one; if every release failed (or there is none),
    no record is ``latest`` and the notifier falls back to another version.
    """
    default_branch = report["default_branch"]
    findings = report["findings"]
    source_ids = {t["id"] for t in report["targets"] if t["kind"] == "fs"}
    by_id = {t["id"]: t for t in report["targets"]}
    records = []
    for ref, ids in versions_of(report):
        failed = any(by_id[tid]["status"] != "ok" for tid in ids)
        record: dict[str, Any] = {
            "ref": ref,
            "kind": version_kind(ref, default_branch),
            "latest": False,  # resolved below, once every status is known
            "status": "failed" if failed else "ok",
            **{key: 0 for key in SEVERITY_KEY.values()},
            "all": 0,
            "fixable": 0,
        }
        if not failed:
            block = severity_block(
                package_rows([f for f in findings if f["target"] in ids], source_ids)
            )
            for sev, key in SEVERITY_KEY.items():
                record[key] = block["by_severity"][sev]["all"]
            record["all"] = block["all"]
            record["fixable"] = block["fixable"]
        records.append(record)
    for record in records:
        if record["status"] == "ok" and is_release(record["ref"], default_branch):
            record["latest"] = True
            break
    return records


def scan_status(trivy: Mapping[str, Any], osv: Mapping[str, Any] | None) -> str:
    text = trivy["status"] + (f" ({trivy['reason']})" if trivy["reason"] else "")
    if trivy["status"] == "ok" and osv:
        if osv["status"] != "ok":
            detail = (
                f"failed: {osv['reason']}" if osv["status"] == "failed" else osv["status"]
            )
            text += f" · OSV {detail}"
        # an ok with a reason states an exclusion (the image scan disabled for the
        # repository); it must not read as a plain ok
        elif osv["reason"]:
            text += f" · OSV ok ({osv['reason']})"
    return text


def header(report: Mapping[str, Any]) -> list[str]:
    tools = report["tools"]
    parts = [
        f"commit `{(report['commit_sha'] or '')[:7]}`",
        f"default branch `{report['default_branch']}`",
        f"Trivy {tools['trivy']} (DB {short_time(tools['trivy_db'])}, "
        f"Java DB {short_time(tools['trivy_java_db'])})",
        f"osv-scanner {tools['osv_scanner']} (queried {tools['osv_queried_at'] or 'n/a'})",
    ]
    if report["run_url"]:
        parts.append(f"[run {report['run_id']}]({report['run_url']})")
    lines = [f"# SCA · {report['repo']}", "", " · ".join(parts), ""]
    one_offs = one_off_lines(report)
    if one_offs:
        lines += [*one_offs, ""]
    return lines


def one_off_lines(report: Mapping[str, Any]) -> list[str]:
    """What this run covers beyond the regular release set, when it does: a focus
    run on one tag, a direct OSV image scan forced for the run."""
    lines = []
    if scan_ref := report.get("scan_ref"):
        lines.append(f"Focused on tag `{scan_ref}` (a manual run on one tag).")
    if report.get("forced_image_scan"):
        lines.append(
            "The direct OSV image scan runs on this run although it is off for the "
            "repository."
        )
    return lines


VERSION = re.compile(r"(\d+(?:\.\d+)*)(-.+)?")


def version_order(version: str) -> tuple[int, Any]:
    """development first, then releases from the newest (a release candidate after
    its final version), then whatever is not a version, alphabetically.
    """
    if version == "development":
        return 0, ()
    if m := VERSION.fullmatch(version):
        return 1, (tuple(-int(n) for n in m[1].split(".")), m[2] is not None, m[2])
    return 2, version


def versions_of(report: Mapping[str, Any]) -> list[tuple[str, set[str]]]:
    """(version, ids of its targets) in display order. The source and the images of
    one version agree on it: a git tag may carry a ``v`` that a registry tag lacks.
    A target without a ref (its resolution failed) belongs to no version.
    """
    ids: dict[str, set[str]] = {}
    for t in report["targets"]:
        if t["ref"]:
            ids.setdefault(t["ref"].removeprefix("v"), set()).add(t["id"])
    return sorted(ids.items(), key=lambda item: version_order(item[0]))


def scan_cell(report: Mapping[str, Any], ids: set[str]) -> str:
    """ok, or failed when any scan of the version failed, and what was scanned."""
    targets = [t for t in report["targets"] if t["id"] in ids]

    def of(scanner: str, status: str) -> set[str]:
        return {
            t["id"]
            for t in targets
            if t["scanner"] == scanner and t["status"] == status
        }

    failed, skipped = of("trivy", "failed"), of("trivy", "not_applicable")
    osv_failed = of("osv", "failed") - failed
    scanned = {t["id"]: t["kind"] for t in targets if t["id"] not in failed | skipped}
    parts = ["source"] if "fs" in scanned.values() else []
    if images := sum(1 for kind in scanned.values() if kind == "image"):
        parts.append(plural(images, "image", "images"))
    for n, what in ((failed, "failed"), (osv_failed, "OSV failed"), (skipped, "n/a")):
        if n:
            parts.append(f"{len(n)} {what}")
    return f"{'failed' if failed or osv_failed else 'ok'} ({', '.join(parts)})"


def count_cell(n: int) -> str:
    return str(n) if n else "-"


def severity_columns(counts: Sequence[Mapping[str, int]]) -> list[str]:
    """Critical, High, Medium, Low, and Unknown only when something has it."""
    return [
        s
        for s in SEVERITIES
        if s != "UNKNOWN" or any(c.get(s, 0) for c in counts)
    ]


def table_lines(
    head: Sequence[str], rows: Sequence[Sequence[str]], text_columns: int = 1
) -> list[str]:
    """A table whose first ``text_columns`` columns are text, the rest numbers."""
    rule = "|" + "---|" * text_columns + "---:|" * (len(head) - text_columns)
    return [
        "| " + " | ".join(head) + " |",
        rule,
        *("| " + " | ".join(r) + " |" for r in rows),
    ]


def vulnerabilities_table(
    by_version: Sequence[tuple[str, set[str]]],
    version_rows: Mapping[str, Sequence[Mapping[str, Any]]],
    all_rows: Sequence[Mapping[str, Any]],
) -> list[str]:
    """Unique vulnerabilities per version and over all; the last row is what
    ``counts.total`` of report.json holds (the same function over the same rows).
    """
    blocks = [(v, severity_block(version_rows[v])) for v, _ in by_version]
    total = severity_block(all_rows)
    severities = severity_columns(
        [{s: b["by_severity"][s]["all"] for s in SEVERITIES} for _, b in blocks]
        + [{s: total["by_severity"][s]["all"] for s in SEVERITIES}]
    )

    def cells(block: Mapping[str, Any]) -> list[str]:
        return [
            *(count_cell(block["by_severity"][s]["all"]) for s in severities),
            count_cell(block["fixable"]),
        ]

    head = ["Branch / tag", *(s.capitalize() for s in severities), "Fixable"]
    rows = [[cell(v), *cells(b)] for v, b in blocks]
    rows.append(["**All (unique)**", *cells(total)])
    return [
        *table_lines(head, rows),
        "",
        "Each vulnerability counted once per row; one present in several branches/tags "
        "is counted once in the last row.",
    ]


def packages_table(
    report: Mapping[str, Any],
    by_version: Sequence[tuple[str, set[str]]],
    version_rows: Mapping[str, Sequence[Mapping[str, Any]]],
    unique: Sequence[Mapping[str, Any]],
) -> list[str]:
    severities = severity_columns(
        [{r["severity"]: 1 for r in unique if r["class"] == "lang"}]
    )

    def counts(rows: Sequence[Mapping[str, Any]]) -> list[str]:
        libs = [r for r in rows if r["class"] == "lang"]
        return [
            *(
                count_cell(sum(1 for r in libs if r["severity"] == s))
                for s in severities
            ),
            count_cell(len(rows) - len(libs)),
            count_cell(sum(1 for r in rows if not r["no_fix"])),
        ]

    head = ["Branch / tag", "Scan", *(s.capitalize() for s in severities)]
    head += ["OS packages", "Fixable"]
    rows = [
        [cell(v), cell(scan_cell(report, ids)), *counts(version_rows[v])]
        for v, ids in by_version
    ]
    rows.append(["**All (unique)**", "", *counts(unique)])
    return [
        *table_lines(head, rows, 2),
        "",
        "Vulnerable libraries by worst severity; a package in several branches/tags is "
        "counted once in the last row.",
    ]


def version_section(
    version: str,
    rows: Sequence[Mapping[str, Any]],
    columns: Sequence[tuple[str, str]],
) -> list[str]:
    libraries = [r for r in rows if r["class"] == "lang"]
    os_rows = [r for r in rows if r["class"] == "os"]
    lines = [f"## {cell(version)} - {totals(libraries, os_rows)}", ""]
    if libraries:
        lines += ["<details><summary>Libraries</summary>", ""]
        lines += [*package_table(libraries, columns, True), "", "</details>", ""]
    if os_rows:
        lines += ["<details><summary>Base image (OS packages)</summary>", ""]
        lines += [*package_table(os_rows, columns, False), "", "</details>", ""]
    return lines


def results_by_target(report: Mapping[str, Any]) -> list[str]:
    by_id: dict[str, list[Mapping[str, Any]]] = {}
    for t in report["targets"]:
        by_id.setdefault(t["id"], []).append(t)
    lines = [
        "<details><summary>Scan details by target</summary>",
        "",
        "| Target | Type | Version | Scan | Packages scanned |",
        "|---|---|---|---|---:|",
    ]
    for tid, ts in by_id.items():
        trivy = next((t for t in ts if t["scanner"] == "trivy"), ts[0])
        osv = next((t for t in ts if t["scanner"] == "osv"), None)
        ref = trivy["ref"] or "—"
        if trivy["kind"] == "fs" and trivy["commit_sha"]:
            ref = f"{ref}@{trivy['commit_sha'][:7]}"
        packages = (
            "–" if trivy["packages_scanned"] is None else trivy["packages_scanned"]
        )
        kind = "source" if trivy["kind"] == "fs" else "image"
        lines.append(
            f"| {cell(tid)} | {kind} | {cell(ref)} | {cell(scan_status(trivy, osv))} | "
            f"{packages} |"
        )
    return [*lines, "", "</details>"]


def build_summary(report: Mapping[str, Any]) -> str:
    short = report["repo"].split("/")[-1]
    columns, seen = [], set()
    for t in report["targets"]:
        if t["id"] not in seen:
            seen.add(t["id"])
            columns.append((target_label(t, short), t["id"]))
    source_ids = {t["id"] for t in report["targets"] if t["kind"] == "fs"}
    findings = report["findings"]
    by_version = versions_of(report)
    version_rows = {
        version: package_rows([f for f in findings if f["target"] in ids], source_ids)
        for version, ids in by_version
    }
    # a package is one installed version: the rows of the versions, deduplicated
    # (package_rows over all the findings would merge the OS packages of different
    # versions, which it keys without the version)
    unique = {
        (r["class"], norm(r["pkg"]), r["version"]): r
        for rows in reversed(version_rows.values())
        for r in rows
    }.values()
    all_rows = package_rows(findings, source_ids)
    lines = header(report) + ["## Vulnerabilities", ""]
    lines += [*vulnerabilities_table(by_version, version_rows, all_rows), ""]
    lines += ["## Packages to update", ""]
    lines += [*packages_table(report, by_version, version_rows, [*unique]), ""]
    for version, _ in by_version:
        if version_rows[version]:
            lines += version_section(version, version_rows[version], columns)
    lines += [*results_by_target(report), ""]
    lines += [
        "---",
        "Artifact `sca-report`: `report.json` plus native reports in "
        "`_native/trivy/` and `_native/osv/`.",
    ]
    return "\n".join(lines) + "\n"


def truncate_summary(text: str, run_url: str | None) -> str:
    """The summary as the job summary can take it: whole if it fits, else cut at a
    line, with the ``<details>`` the cut leaves open closed and a note on where the
    whole of it is.
    """
    data = text.encode("utf-8")
    if len(data) <= STEP_SUMMARY_LIMIT_BYTES:
        return text
    where = "the `sca-report` artifact of this run"
    if run_url:
        where = f"the `sca-report` artifact of [this run]({run_url})"
    note = (
        f"\n> The summary is cut: it is {len(data)} bytes and a job summary takes "
        f"1 MiB. The whole `summary.md` is in {where}.\n"
    )
    close = "</details>\n"
    room = STEP_SUMMARY_LIMIT_BYTES - len(note.encode("utf-8"))
    while True:
        kept = data[:room].decode("utf-8", errors="ignore")
        kept = kept[: kept.rfind("\n") + 1]
        closing = close * max(kept.count("<details") - kept.count("</details>"), 0)
        if len((kept + closing + note).encode("utf-8")) <= STEP_SUMMARY_LIMIT_BYTES:
            return kept + closing + note
        room -= len(close)
