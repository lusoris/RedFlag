# 🚩 RedFlag

[![Trivy CVE Scan](https://github.com/lusoris/RedFlag/actions/workflows/scan.yml/badge.svg)](https://github.com/lusoris/RedFlag/actions/workflows/scan.yml)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20this%20project-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/lusoris)

Automated [Trivy](https://github.com/aquasecurity/trivy) vulnerability scanner for homelab container images. Scans \*arr ecosystem projects and other self-hosted tools for CRITICAL and HIGH CVEs, then opens GitHub Issues with detailed findings.

## How it works

1. **GitHub Actions** runs on a schedule, on `images.yaml` changes, or manually
2. **Trivy** scans each configured container image for CRITICAL and HIGH vulnerabilities
3. **Diff engine** compares results against previously reported CVEs
4. **New findings** are posted as GitHub Issues with severity labels
5. **State** is tracked in `state.json` committed to the repo — no external database needed

## Currently scanned

<details>
<summary>25 images (click to expand)</summary>

| Project | Image |
|---------|-------|
| FileFlows | `revenz/fileflows:latest` |
| Tdarr | `haveagitgat/tdarr:latest` |
| Cleanuparr | `ghcr.io/cleanuparr/cleanuparr:latest` |
| Decluttarr | `ghcr.io/manimatter/decluttarr:latest` |
| Swaparr | `ghcr.io/thijmengthn/swaparr:latest` |
| Pulsarr | `lakker/pulsarr:latest` |
| Posterizarr | `ghcr.io/fscorrupt/posterizarr:latest` |
| Byparr | `ghcr.io/thephaseless/byparr:latest` |
| Calendarr | `ghcr.io/jordanlambrecht/calendarr:latest` |
| Trailarr | `nandyalu/trailarr:latest` |
| Lingarr | `ghcr.io/lingarr-translate/lingarr:latest` |
| Configarr | `ghcr.io/raydak-labs/configarr:latest` |
| Soularr | `ghcr.io/mrusse/soularr:latest` |
| iPlayarr | `nikorag/iplayarr:latest` |
| SuggestArr | `ciuse99/suggestarr:latest` |
| Managarr | `darkalex17/managarr:latest` |
| Seerr | `seerr/seerr:latest` |
| Homarr | `ghcr.io/homarr-labs/homarr:latest` |
| Maintainerr | `ghcr.io/maintainerr/maintainerr:latest` |
| Recyclarr | `ghcr.io/recyclarr/recyclarr:8` |
| Autobrr | `ghcr.io/autobrr/autobrr:latest` |
| Wizarr | `ghcr.io/wizarrrr/wizarr:latest` |
| Autopulse | `ghcr.io/dan-online/autopulse:latest` |
| Unpackerr | `ghcr.io/unpackerr/unpackerr:latest` |
| StashApp | `stashapp/stash:latest` |

</details>

## Quick start

### 1. Fork or clone this repo

```sh
git clone https://github.com/lusoris/RedFlag.git
cd RedFlag
```

### 2. Configure images

Edit `images.yaml` to add the container images you want to scan:

```yaml
images:
  - name: MyApp
    image: myorg/myapp:latest
```

### 3. Run

No secrets needed — `GITHUB_TOKEN` is provided automatically by GitHub Actions.

The scan triggers automatically on:
- **Schedule** — daily at 06:00 UTC, weekly on Mondays at 03:00 UTC
- **Config changes** — any push or merged PR that modifies `images.yaml`
- **Manual** — Actions > Trivy CVE Scan > Run workflow

### Local dry run

```sh
# Requires trivy installed locally
go build -o redflag ./cmd/redflag
./redflag --config images.yaml --state state.json --dry-run
```

## Contributing a project

Want to add a project to the scan list? PRs are welcome!

1. Fork this repo
2. Add your image to `images.yaml`:
   ```yaml
     - name: ProjectName
       image: owner/image:tag
   ```
3. Open a PR — the CI will validate the YAML and run a scan
4. Once merged, the project will be included in all future scans

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

## Project structure

```
cmd/redflag/main.go           CLI entrypoint
internal/
  config/config.go             YAML config loader
  scanner/scanner.go           Trivy execution + JSON parser
  diff/diff.go                 New CVE detection (vs previously posted)
  formatter/formatter.go       GitHub issue markdown builder
  notifier/github.go           GitHub Issues API client
  state/state.go               State file persistence
images.yaml                    Images to scan
state.json                     Auto-managed scan state (committed by CI)
.github/workflows/scan.yml     GitHub Actions workflow
```

## Support

If you find this useful, consider [buying me a coffee](https://ko-fi.com/lusoris) ☕

## License

MIT
