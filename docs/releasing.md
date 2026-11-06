# 🏷️ Releasing

How to cut a release of `dbx-nwp-helper`. Versioning is **tag-driven** (via
[`hatch-vcs`](https://github.com/ofek/hatch-vcs)): the git tag is the single source of truth, so
"a release" is just a `vX.Y.Z` tag on `main` — there is no version string to edit.

## Versioning model

- **[Semantic Versioning](https://semver.org).** For this CLI the "public API" is the command +
  flag surface: a breaking change bumps the **major**, a backward-compatible addition the
  **minor**, a fix the **patch**.
- The version is derived from the git tag. `dbx-nwp-helper --version` reports it. On a clean,
  tagged commit it's the exact number (`0.1.0`); between tags it's a PEP 440 dev version
  (`0.1.1.devN+g<sha>`); a dirty working tree adds a `.dYYYYMMDD` suffix.

## Steps

1. **Update the changelog.** In [`../CHANGELOG.md`](../CHANGELOG.md), move the entries under
   `[Unreleased]` into a new `[X.Y.Z] - YYYY-MM-DD` section, and update the link references at the
   bottom of the file.
2. **Land the changes on `main`** via the normal PR + review + merge flow.
3. **Tag `main` after the merge.** A squash/merge creates a *new* commit on `main`, so tag `main`
   itself — never the feature branch (that commit would be orphaned after the squash):
   ```bash
   git checkout main && git pull
   git tag -a vX.Y.Z -m "dbx-nwp-helper X.Y.Z"
   git push origin vX.Y.Z
   ```
4. **(Optional) Publish a GitHub Release** from the tag, so it shows up under *Releases* with notes:
   ```bash
   gh release create vX.Y.Z --title "vX.Y.Z" --verify-tag \
     --notes "…"        # or --notes-file, e.g. the CHANGELOG section
   ```
5. **Verify** the released version resolves cleanly (do this on a clean tree):
   ```bash
   git checkout vX.Y.Z
   uv sync && uv run dbx-nwp-helper --version   # -> dbx-nwp-helper X.Y.Z
   uv build                                     # -> dist/…-X.Y.Z-…whl
   ```

## Notes

- **Git pushes vs. the GitHub API.** Pushing commits and tags goes over **SSH** and works with
  whatever SSH key authenticates to the repo. The GitHub **API** operations (`gh pr create`,
  `gh release create`) authenticate with your active `gh` account instead — if that account is a
  GitHub **Enterprise Managed User (EMU)**, those calls are refused against a personal repo with
  *"Unauthorized: As an Enterprise Managed User, you cannot access this content."* Switch the
  active `gh` account to the repo owner for the API call, then switch back:
  ```bash
  gh auth switch -u <repo-owner-account>   # before gh pr/release create
  # … run the gh command …
  gh auth switch -u <your-default-account> # after
  ```
- **Build-dependency pins.** `build-system.requires` in [`../pyproject.toml`](../pyproject.toml)
  is deliberately upper-bounded (`hatchling<1.32`, `hatch-vcs>=0.4,<0.5`, `setuptools-scm<10`) so
  the build stays resolvable behind the internal PyPI mirror, which does not serve the newest
  `hatchling` or the `setuptools-scm` 10.x → `vcs-versioning` chain. Public PyPI (CI) resolves
  these fine. Relax the ceilings once the mirror approves the newer releases.
- **CI needs tags.** The CI workflow checks out with `fetch-depth: 0` so `hatch-vcs` can see tags;
  keep that if you touch [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml).
- **Raised policy limits (hidden flags).** `ingress` accepts hidden `--max-rules` / `--max-cidrs`
  options (env `DBX_NWP_MAX_RULES` / `DBX_NWP_MAX_CIDRS`) for accounts where Databricks has raised the
  50-rule / 2,000-CIDR per-policy caps. They are deliberately absent from `--help` and the README:
  share them one-to-one with a customer only once Databricks has confirmed the raised limit for their
  account, since the API rejects a policy over the platform caps.
