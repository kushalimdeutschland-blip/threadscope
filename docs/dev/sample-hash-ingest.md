# Sample hash ingest (lab tier)

Lab-only pipeline: clone private malware sample repositories, hash every file (and zip members in RAM), and upsert **SHA256** indicators into SQLite via `bulk_upsert_feed_snapshot`. File bytes are **never executed** by ThreatScope.

## Prerequisites

- Git installed on the lab host
- `data/sample_repos.yaml` (copy from [`data/sample_repos.yaml.example`](../../data/sample_repos.yaml.example))
- Per-repo credentials in environment variables (names from `password_env` in the YAML — e.g. `SAMPLE_REPO_ACME_PASSWORD`). **Never commit passwords.**

## Configure repos

```yaml
repos:
  - name: acme-samples
    url: https://github.com/org/private-samples.git
    branch: main
    password_env: SAMPLE_REPO_ACME_PASSWORD
```

Optional `tag:` overrides `branch` for a shallow clone of that tag.

## Run locally

```bash
source venv/bin/activate
export SAMPLE_REPO_ACME_PASSWORD='your-token-or-password'
cp data/sample_repos.yaml.example data/sample_repos.yaml
# edit data/sample_repos.yaml

./scripts/ingest-sample-hashes.sh
./scripts/ingest-sample-hashes.sh --dry-run
./scripts/ingest-sample-hashes.sh --repo acme-samples --keep-clone
```

Clones land in `temp_repo_clones/<name>/` and are removed after ingest unless `--keep-clone`.

## Database shape

Each hash is stored as:

| Field | Value |
|-------|--------|
| `value` | SHA256 (canonical lookup key) |
| `type` | `hash` |
| `source` | `SampleRepo:<name>` |
| `meta` | `md5`, `sha1`, `inner_filename`, `repo` |

## Sync to production VPS

Production runs `THREATSCOPE_PUBLIC=1` and does **not** clone sample repos. After lab ingest:

1. Stop the app on the VPS: `systemctl stop threatscope`
2. Run [`scripts/sync-hash-db-to-production.sh`](../../scripts/sync-hash-db-to-production.sh) from the lab (or manual `rsync` of `data/threatscope.db`)
3. Fix ownership: `chown threatscope:threatscope /opt/threatscope/data/threatscope.db`
4. Start: `systemctl start threatscope`

See [architecture-two-tier.md](architecture-two-tier.md) for the full lab vs public split.

## Safety limits (`services/sample_repos.py`)

Zip archives are read entirely in RAM with caps on member count, per-file size, total inflated size, and compression ratio. Path traversal (`../`) inside zip entries is rejected.
