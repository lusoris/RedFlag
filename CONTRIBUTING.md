# Contributing to RedFlag

Thanks for helping expand the scan coverage! The easiest way to contribute is by adding a new container image to the scan list.

## Adding a project to the scan list

1. **Fork** this repo and create a branch
2. **Edit** `images.yaml` — add an entry at the end of the file:
   ```yaml
     - name: ProjectName
       image: owner/image:tag
   ```
3. **Verify** the image exists and is pullable (e.g. `docker pull owner/image:tag`)
4. **Open a PR** against `main`

### Requirements

- The image must be a **publicly available** container image on Docker Hub or GHCR
- The project should be a **self-hosted / homelab** tool (not a paid SaaS product)
- Use the most common stable tag (usually `latest`, or a major version if `latest` is deprecated)
- One entry per image — don't add multiple tags for the same project

### What happens when you open a PR

- CI will validate the YAML and run a **dry-run scan** against all images (including your addition)
- If the scan succeeds, the PR is ready for review
- Once merged, the image is included in all future scheduled scans and any new CVEs will be opened as Issues

## Reporting issues

If a scan result looks wrong or an image reference is broken, open an Issue describing the problem.

## Code changes

For changes to the Go scanner code, please open an Issue first to discuss the approach.
