# ai-dial-sec-sca

Composite GitHub Actions that run the software composition analysis (SCA) scan of AI DIAL repositories: [Trivy](https://trivy.dev/) finds known vulnerabilities in every target, [OSV](https://osv.dev/) then checks the language packages Trivy found plus, for image targets, the image itself (its OS packages included), and the results are merged into one report.

These actions are called by the `sca_scheduled.yml` workflow of [epam/ai-dial-ci](https://github.com/epam/ai-dial-ci). They are not meant to be used directly: repositories call that workflow, which orchestrates the scan and the actions below.

## Actions

- `actions/sca_resolve_targets`: builds the list of scan targets and resolves the releases: the default branch source, the source of each release of the release set, and, per image, `development` and the same release tags. The release set is the newest patch of each of the last `release-lines` (default 2) minor lines (`X.Y.Z` tags of non-prerelease, non-draft GitHub releases), plus at most one candidate. The candidate is the newest prerelease (by version, `X.Y.Z-pre`) whose base version is greater than the newest stable; a prerelease of an already published version is not scanned. A stable release whose tag is not `X.Y.Z` is left out of the set and counted in one notice. The release listing is read page by page (up to 1000 releases). Inputs: `scan-tag` focuses the run on one git tag (its source and the tag in every image, no `development`); `osv-image-scan` is the repository's own setting that switches the direct OSV image scan off; `force-image-scan` runs that scan anyway (a manual run) and marks the run with `forced_image_scan` in `targets.json` and `report.json`. Pass `osv-image-scan` as the repository sets it, not combined with the force flag: the action does the combining.
- `actions/sca_query_osv`: checks the language packages found by Trivy against OSV with osv-scanner; an image target also gets a direct `osv-scanner scan image`, which reads the image's own package database and so checks its OS packages against OSV correctly (a BOM cannot: OSV keys its records by the source package name). The BOM query runs either way, so a package either detector sees keeps its OSV check.
- `actions/sca_merge_results`: normalizes the Trivy and OSV reports, merges them into `report.json` and writes the `summary.md` job summary.
- `actions/generate_gradle_lockfiles`: generates Gradle lockfiles on the fly so Trivy can resolve Gradle dependencies (repository files are not modified).

The actions share the code in `actions/_sca_lib` (it is imported through `PYTHONPATH=${{ github.action_path }}/..`, so the `actions/` layout must stay as it is).

## Tests

```sh
python -m pip install pytest
python -m pytest test/sca
```

The tests need Python 3.12 and no network access. They run in GitHub Actions on every push and pull request to `main`.

## Versioning

Releases are git tags `vX.Y.Z`. Consumers pin a tag, for example:

```yml
- uses: epam/ai-dial-sec-sca/actions/sca_merge_results@v0.3.2
```

The third-party actions are pinned by commit SHA and osv-scanner by the sha256 of its binary (in `actions/sca_query_osv/action.yml`). Trivy is pinned by version only: `aquasecurity/setup-trivy` verifies the download against the checksums published with the same release, not against a value pinned here.

## License

Apache-2.0, see [LICENSE](LICENSE).
