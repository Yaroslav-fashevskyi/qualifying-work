# IP Intelligence

Monorepo with two separate applications:

- `backend/`: FastAPI API for IP, domain and ASN enrichment
- `frontend/`: Nuxt 3 client for lookup, history and dashboard flows

## Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn src.app:app --host 127.0.0.1 --port 8000
```

Optional CORS override:

```bash
export CORS_ALLOW_ORIGINS=http://127.0.0.1:3000,http://localhost:3000
```

## Frontend

```bash
cd frontend
bun install
bun run dev
```

Optional backend override:

```bash
export NUXT_PUBLIC_BACKEND_ORIGIN=http://127.0.0.1:8000
```

## Current backend API

- `GET /api/lookup?q=IP_or_domain`
- `GET /api/me`
- `GET /api/history?limit=50`
- `DELETE /api/history`
- `GET /api/history/export`
- `GET /api/stats`
- `GET /api/health`

## Threat list refresh

```bash
cd backend
python scripts/update_datasets.py
python scripts/update_datasets.py --only vpn --only proxy
python scripts/update_datasets.py --dry-run
python scripts/update_datasets.py --allow-no-license --only vpn --only datacenter
```
