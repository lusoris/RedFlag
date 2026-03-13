# 🚩 RedFlag

Automated [Trivy](https://github.com/aquasecurity/trivy) CVE scanner for homelab container images that posts findings to Reddit.

## How it works

1. **GitHub Actions** runs on a daily/weekly schedule (or manually)
2. **Trivy** scans each configured container image for CRITICAL and HIGH vulnerabilities
3. **Diff engine** compares results against previously reported CVEs
4. **New findings** are posted as self-posts to configured subreddits (e.g. r/homelab, r/AppName)
5. **State** is tracked in `state.json` committed to the repo — no external database needed

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
  - name: FileFlows
    image: revenz/fileflows:latest
    subreddits: [homelab, FileFlows]

  - name: Tdarr
    image: haveagitgat/tdarr:latest
    subreddits: [homelab, Tdarr]
```

### 3. Create a Reddit "script" app

1. Go to https://www.reddit.com/prefs/apps
2. Click **"create another app..."**
3. Select **"script"**
4. Set redirect URI to `http://localhost:8080` (not used, but required)
5. Note down the **client ID** (under the app name) and **client secret**

### 4. Set up GitHub Secrets

In your repo's **Settings > Secrets and variables > Actions**, add:

| Secret | Description |
|--------|-------------|
| `REDDIT_CLIENT_ID` | Reddit app client ID |
| `REDDIT_CLIENT_SECRET` | Reddit app client secret |
| `REDDIT_USERNAME` | Reddit account username |
| `REDDIT_PASSWORD` | Reddit account password |

### 5. Run

The scan runs automatically via GitHub Actions (daily at 06:00 UTC, weekly on Mondays at 03:00 UTC).

To trigger manually: **Actions > Trivy CVE Scan > Run workflow**

### Local dry run

```sh
# Requires trivy installed locally
go build -o redflag ./cmd/redflag
./redflag --config images.yaml --state state.json --dry-run
```

## Project structure

```
cmd/redflag/main.go          CLI entrypoint
internal/
  config/config.go            YAML config loader
  scanner/scanner.go          Trivy execution + JSON parser
  diff/diff.go                New CVE detection (vs previously posted)
  formatter/formatter.go      Reddit markdown post builder
  reddit/client.go            Reddit OAuth2 client + post submission
  state/state.go              State file persistence
images.yaml                   Images to scan + target subreddits
state.json                    Auto-managed scan state (committed by CI)
.github/workflows/scan.yml    GitHub Actions workflow
```

## License

MIT
