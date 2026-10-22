"""The counts block of report.json: severity and fixability, from the summary's rows."""

from merge_results import SCHEMA_VERSION
from summary import build_counts, package_rows, severity_block, versions_of
from test_summary import finding, report, sample, target, two_versions

SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def zero():
    return {"all": 0, "fixable": 0}


def shape(by_severity=None, **overall):
    """An expected block: the severities given, the rest zero."""
    by = {s: zero() for s in SEVS}
    for s, (n, m) in (by_severity or {}).items():
        by[s] = {"all": n, "fixable": m}
    return {
        "all": sum(v["all"] for v in by.values()),
        "fixable": sum(v["fixable"] for v in by.values()),
        "by_severity": by,
        **overall,
    }


def test_schema_version_is_bumped():
    assert SCHEMA_VERSION == 3


def version(ref, kind, status="ok", latest=False, c=0, h=0, m=0, l=0, unknown=0,
            fixable=0):
    """An expected ``counts.versions`` record: the flat severities given, rest zero."""
    return {
        "ref": ref, "kind": kind, "latest": latest, "status": status,
        "c": c, "h": h, "m": m, "l": l, "unknown": unknown,
        "all": c + h + m + l + unknown, "fixable": fixable,
    }


def test_empty_report_has_zero_counts():
    counts = build_counts(report([target("src")], []))
    assert counts == {
        "total": shape(),
        "targets": {"src": shape(status="ok")},
        "versions": [version("development", "development")],
    }


def test_no_targets_no_findings():
    assert build_counts(report([], [])) == {
        "total": shape(),
        "targets": {},
        "versions": [],
    }


def test_mixed_severities_and_fixability():
    findings = [
        finding("src", "CVE-1", "a", "CRITICAL", fixed="2"),
        finding("src", "CVE-2", "b", "HIGH"),
        finding("src", "CVE-3", "c", "HIGH", fixed="3"),
        finding("src", "CVE-4", "d", "MEDIUM"),
        finding("src", "CVE-5", "e", "LOW", fixed="1"),
        finding("src", "CVE-6", "f", "UNKNOWN"),
    ]
    counts = build_counts(report([target("src")], findings))
    expected = shape(
        {
            "CRITICAL": (1, 1),
            "HIGH": (2, 1),
            "MEDIUM": (1, 0),
            "LOW": (1, 1),
            "UNKNOWN": (1, 0),
        }
    )
    assert counts["total"] == expected
    assert counts["total"]["all"] == 6 and counts["total"]["fixable"] == 3
    assert counts["targets"]["src"] == {**expected, "status": "ok"}


def test_fixable_is_a_known_fixed_version_on_any_scanner():
    # the same vulnerability: Trivy knows no fix, OSV does - the summary's rule is a
    # fixed version known to either, so it is fixable
    findings = [
        finding("src", "CVE-1", "a", "HIGH"),
        finding("src", "CVE-1", "a", "HIGH", scanner="osv", fixed="2"),
    ]
    counts = build_counts(report([target("src")], findings))
    assert counts["total"]["by_severity"]["HIGH"] == {"all": 1, "fixable": 1}


def test_trivy_severity_wins_over_osv():
    findings = [
        finding("src", "CVE-1", "a", "LOW", scanner="osv"),
        finding("src", "CVE-1", "a", "CRITICAL"),
    ]
    by = build_counts(report([target("src")], findings))["total"]["by_severity"]
    assert by["CRITICAL"]["all"] == 1 and by["LOW"]["all"] == 0


def test_duplicate_across_targets_counts_once_in_total_each_in_target():
    targets = [target("src"), target("img", kind="image", ref="1.0")]
    findings = [
        finding("src", "CVE-1", "a", "HIGH", fixed="2"),
        finding("img", "CVE-1", "a", "HIGH", fixed="2"),
        finding("img", "CVE-2", "z", "HIGH", cls="os"),
    ]
    counts = build_counts(report(targets, findings))
    assert counts["total"] == shape({"HIGH": (2, 1)})
    assert counts["targets"]["src"] == shape({"HIGH": (1, 1)}, status="ok")
    assert counts["targets"]["img"] == shape({"HIGH": (2, 1)}, status="ok")


def test_same_cve_in_another_package_is_another_vulnerability():
    findings = [
        finding("src", "CVE-1", "a", "HIGH"),
        finding("src", "CVE-1", "b", "HIGH"),
    ]
    counts = build_counts(report([target("src")], findings))
    assert counts["total"]["all"] == 2


def test_total_matches_the_summary_rows():
    rep = sample()
    counts = build_counts(rep)
    rows = package_rows(rep["findings"], {"source-development"})
    vulns = [v for r in rows for v in r["vulns"]]
    assert counts["total"]["all"] == len(vulns)
    assert counts["total"]["fixable"] == sum(1 for v in vulns if v["fixed"])


def test_failed_and_not_applicable_targets_are_listed_with_status_only():
    rep = sample()
    targets = counts_targets = build_counts(rep)["targets"]
    assert targets["app-1.0"]["status"] == "ok"  # the Trivy scan decides
    assert targets["app-2.0"] == {"status": "not_applicable"}
    failed = report(
        [target("img", kind="image", status="failed", reason="boom")],
        [],
    )
    assert build_counts(failed)["targets"] == {"img": {"status": "failed"}}
    assert counts_targets["source-development"]["status"] == "ok"


def test_findings_of_a_failed_target_do_not_leak_into_total_of_others():
    targets = [
        target("src"),
        target("img", kind="image", status="failed", reason="x"),
    ]
    findings = [finding("src", "CVE-1", "a", "HIGH")]
    counts = build_counts(report(targets, findings))
    assert counts["total"]["all"] == 1
    assert counts["targets"]["img"] == {"status": "failed"}


# --- counts.versions: one flat record per version, in versions_of order ---


def test_versions_follow_versions_of_order_and_name():
    rep = two_versions()
    versions = build_counts(rep)["versions"]
    assert [r["ref"] for r in versions] == [v for v, _ in versions_of(rep)]


def test_an_ok_version_matches_its_severity_block_and_its_counts_sum_to_all():
    rep = two_versions()
    by_version = dict(versions_of(rep))
    source_ids = {t["id"] for t in rep["targets"] if t["kind"] == "fs"}
    for record in build_counts(rep)["versions"]:
        if record["status"] != "ok":
            continue
        ids = by_version[record["ref"]]
        block = severity_block(
            package_rows([f for f in rep["findings"] if f["target"] in ids], source_ids)
        )
        by = block["by_severity"]
        assert record["c"] == by["CRITICAL"]["all"]
        assert record["h"] == by["HIGH"]["all"]
        assert record["m"] == by["MEDIUM"]["all"]
        assert record["l"] == by["LOW"]["all"]
        assert record["unknown"] == by["UNKNOWN"]["all"]
        assert record["all"] == block["all"] == record["c"] + record["h"] + record[
            "m"
        ] + record["l"] + record["unknown"]
        assert record["fixable"] == block["fixable"]


def test_kind_is_development_candidate_or_release():
    refs = ["development", "0.50.0-rc.1", "1.2.0", "v2.0.0"]
    doc = report([target(f"s{i}", ref=r) for i, r in enumerate(refs)], [])
    kinds = {r["ref"]: r["kind"] for r in build_counts(doc)["versions"]}
    assert kinds["development"] == "development"
    assert kinds["0.50.0-rc.1"] == "candidate"
    assert kinds["1.2.0"] == "release"
    assert kinds["2.0.0"] == "release"


def test_the_default_branch_is_development_kind_even_when_not_named_development():
    doc = report([target("s", ref="main")], [])
    doc["default_branch"] = "main"
    (record,) = build_counts(doc)["versions"]
    assert record["ref"] == "main" and record["kind"] == "development"


def test_exactly_one_latest_the_newest_release_when_a_release_exists():
    versions = build_counts(two_versions())["versions"]
    latest = [r for r in versions if r["latest"]]
    assert len(latest) == 1
    assert latest[0]["ref"] == "1.2.9" and latest[0]["kind"] == "release"


def test_no_latest_when_there_is_no_release():
    doc = report(
        [target("s0", ref="development"), target("s1", ref="0.1.0-rc.1")], []
    )
    versions = build_counts(doc)["versions"]
    assert all(not r["latest"] for r in versions)


def test_a_failed_version_has_zero_counts_and_failed_status():
    # sample(): 2.0 is not_applicable and 1.0 has a failed OSV scan - both failed,
    # both zeroed, as build_counts leaves a non-ok target
    records = {r["ref"]: r for r in build_counts(sample())["versions"]}
    for ref in ("2.0", "1.0"):
        r = records[ref]
        assert r["status"] == "failed"
        assert (r["c"], r["h"], r["m"], r["l"], r["unknown"]) == (0, 0, 0, 0, 0)
        assert r["all"] == 0 and r["fixable"] == 0


def test_a_version_is_failed_when_any_of_its_targets_is_not_ok():
    targets = [
        target("source-1.0", ref="1.0"),
        target("source-1.0", "osv", ref="1.0", status="failed", reason="x"),
    ]
    (record,) = build_counts(report(targets, []))["versions"]
    assert record["ref"] == "1.0" and record["status"] == "failed"
