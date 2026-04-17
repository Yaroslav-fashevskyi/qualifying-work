# IP Intelligence Backend

FastAPI backend for IP, domain and ASN enrichment.

Current backend responsibilities:

- local-first GeoIP lookup from MaxMind MMDB files
- security flags from local TOR, VPN, proxy, datacenter and threat lists
- RDAP and reverse DNS enrichment
- SQLite-backed history and runtime stats
- dataset refresh scripts for GitHub-backed security lists

## Run

```bash
pip install -r requirements.txt
uvicorn src.app:app --host 127.0.0.1 --port 8000
```

`GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` must exist in `src/data/`.

If the frontend is served from another origin, set CORS explicitly:

```bash
export CORS_ALLOW_ORIGINS=http://127.0.0.1:3000,http://localhost:3000
```

## API

- `GET /`
- `GET /api/lookup?q=IP_or_domain`
- `GET /api/me`
- `GET /api/history?limit=50`
- `DELETE /api/history`
- `GET /api/history/export`
- `GET /api/stats`
- `GET /api/health`
- `GET /docs`

## Threat List Refresh

```bash
python scripts/update_datasets.py
python scripts/update_datasets.py --only vpn --only proxy
python scripts/update_datasets.py --dry-run
python scripts/update_datasets.py --allow-no-license --only vpn --only datacenter
```

Current sync sources:

- TOR exits from TorProject mirrors
- `X4BNet/lists_vpn` for `vpn.txt` and `datacenters.txt`
- `antoinevastel/avastel-bot-ips-lists` for `proxy.txt`
- `stamparm/ipsum` level 3 for `threat.txt`

GitHub-backed sources are fetched through the GitHub Contents API with ETag-based conditional requests.
If a repository does not expose an SPDX license, the source is skipped by default and recorded in `src/data/sources_manifest.json`.
Use `--allow-no-license` only when you have manually reviewed the repository terms and want to override that default.
