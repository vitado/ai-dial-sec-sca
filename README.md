# ai-dial-sec-sca

Composite GitHub Actions that run the software composition analysis (SCA) scan of AI DIAL repositories: [Trivy](https://trivy.dev/) finds known vulnerabilities in every target, [OSV](https://osv.dev/) then checks the language packages Trivy found plus, for image targets, the image itself (its OS packages included), and the results are merged into one report.

These actions are called by the `sca_scheduled.yml` workflow of [epam/ai-dial-ci](https://github.com/epam/ai-dial-ci). They are not meant to be used directly: repositories call that workflow, which orchestrates the scan and the actions below.

## Actions

- `actions/sca_resolve_targets`: builds the list of scan targets (default branch source, latest release source, images) and resolves the release. Carries the `osv-image-scan` flag (per repository) that switches the direct OSV image scan off.
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
- uses: epam/ai-dial-sec-sca/actions/sca_merge_results@v0.1.0
```

## License

Apache-2.0, see [LICENSE](LICENSE).
