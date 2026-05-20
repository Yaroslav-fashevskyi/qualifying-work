# IP Intelligence

Monorepo with two separate applications:

- `backend/`: FastAPI API 
- `frontend/`: Nuxt 3 

## Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn src.app:app --host 127.0.0.1 --port 8000
```


Optional backend runtime overrides:

```bash
export APP_DB_PATH=/absolute/path/to/app.sqlite
export RDAP_DB_PATH=/absolute/path/to/rdap.sqlite
export CACHE_TTL_SEC=600
export CACHE_MAX_ENTRIES=5000
export RATE_LIMIT_WINDOW_SEC=300
export RATE_LIMIT_MAX=200
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

## Threat list refresh

```bash
cd backend
python scripts/update_datasets.py
python scripts/update_datasets.py --only vpn --only proxy
python scripts/update_datasets.py --dry-run
python scripts/update_datasets.py --allow-no-license --only vpn --only datacenter
```
