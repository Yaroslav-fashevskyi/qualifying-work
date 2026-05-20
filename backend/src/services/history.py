from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Dict, Any, AsyncIterator
import json

import aiosqlite


class HistoryService:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    @asynccontextmanager
    async def _connection(self) -> AsyncIterator[aiosqlite.Connection]:
        Path(self._db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(self._db_path, timeout=10)
        try:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute("PRAGMA busy_timeout=5000")
            yield db
        finally:
            await db.close()

    async def init_db(self) -> None:
        async with self._connection() as db:
            await db.execute(
                """CREATE TABLE IF NOT EXISTS history(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                query TEXT,
                query_type TEXT,
                domain TEXT,
                asn INTEGER,
                ip TEXT NOT NULL,
                resolved_ips TEXT,
                country_code TEXT,
                country_name TEXT,
                city TEXT,
                region TEXT,
                org TEXT,
                source TEXT,
                cached INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0,
                risk_level TEXT DEFAULT 'low',
                response_time_ms INTEGER,
                vpn INTEGER DEFAULT 0,
                proxy INTEGER DEFAULT 0,
                tor INTEGER DEFAULT 0,
                i2p INTEGER DEFAULT 0,
                datacenter INTEGER DEFAULT 0,
                threat INTEGER DEFAULT 0
            )"""
            )
            await self._migrate_history_columns(db)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_history_ts ON history(ts DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_history_query ON history(query)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_history_query_type ON history(query_type)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_history_country ON history(country_code)")
            await db.commit()

    async def _migrate_history_columns(self, db: aiosqlite.Connection) -> None:
        cursor = await db.execute("PRAGMA table_info(history)")
        rows = await cursor.fetchall()
        existing = {row[1] for row in rows}
        expected = {
            "query": "TEXT",
            "query_type": "TEXT DEFAULT 'ip'",
            "domain": "TEXT",
            "asn": "INTEGER",
            "resolved_ips": "TEXT",
            "country_code": "TEXT",
            "country_name": "TEXT",
            "city": "TEXT",
            "region": "TEXT",
            "org": "TEXT",
            "source": "TEXT",
            "cached": "INTEGER DEFAULT 0",
            "risk_score": "REAL DEFAULT 0",
            "risk_level": "TEXT DEFAULT 'low'",
            "response_time_ms": "INTEGER",
            "vpn": "INTEGER DEFAULT 0",
            "proxy": "INTEGER DEFAULT 0",
            "tor": "INTEGER DEFAULT 0",
            "i2p": "INTEGER DEFAULT 0",
            "datacenter": "INTEGER DEFAULT 0",
            "threat": "INTEGER DEFAULT 0",
        }
        for column, definition in expected.items():
            if column not in existing:
                await db.execute(f"ALTER TABLE history ADD COLUMN {column} {definition}")

    async def save(self, payload: Dict[str, Any]) -> None:
        security = payload.get("security") or {}
        if not isinstance(security, dict):
            security = {}

        resolved_ips = payload.get("resolved_ips") or []
        if not isinstance(resolved_ips, list):
            resolved_ips = []

        ip = payload.get("ip") or (resolved_ips[0] if resolved_ips else "")
        org = payload.get("org") or payload.get("rdap_org")
        asn_info = payload.get("asn_info") or {}
        if not org and isinstance(asn_info, dict):
            org = asn_info.get("holder") or asn_info.get("name")

        async with self._connection() as db:
            await db.execute(
                """INSERT INTO history(
                        ts, query, query_type, domain, asn, ip, resolved_ips,
                        country_code, country_name, city, region, org, source, cached,
                        risk_score, risk_level, response_time_ms,
                        vpn, proxy, tor, i2p, datacenter, threat
                    )
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    payload.get("ts"),
                    payload.get("query"),
                    payload.get("query_type"),
                    payload.get("domain"),
                    payload.get("asn"),
                    ip,
                    json.dumps(resolved_ips, ensure_ascii=False),
                    payload.get("country_code"),
                    payload.get("country_name"),
                    payload.get("city"),
                    payload.get("region"),
                    org,
                    payload.get("source"),
                    1 if payload.get("cached") else 0,
                    float(payload.get("risk_score") or 0),
                    payload.get("risk_level") or "low",
                    payload.get("response_time_ms"),
                    1 if security.get("vpn") else 0,
                    1 if security.get("proxy") else 0,
                    1 if security.get("tor") else 0,
                    1 if security.get("i2p") else 0,
                    1 if security.get("datacenter") else 0,
                    1 if security.get("threat") else 0,
                ),
            )
            await db.commit()

    async def recent(
        self,
        limit: int,
        *,
        query: str | None = None,
        query_type: str | None = None,
        flagged: bool | None = None,
    ) -> List[Dict[str, Any]]:
        filters: list[str] = []
        params: list[Any] = []

        if query:
            filters.append("(query LIKE ? OR ip LIKE ? OR domain LIKE ? OR org LIKE ?)")
            needle = f"%{query}%"
            params.extend([needle, needle, needle, needle])
        if query_type:
            filters.append("query_type = ?")
            params.append(query_type)
        if flagged is True:
            filters.append("(vpn = 1 OR proxy = 1 OR tor = 1 OR i2p = 1 OR datacenter = 1 OR threat = 1)")
        elif flagged is False:
            filters.append("(vpn = 0 AND proxy = 0 AND tor = 0 AND i2p = 0 AND datacenter = 0 AND threat = 0)")

        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
        sql = f"SELECT * FROM history {where_clause} ORDER BY id DESC LIMIT ?"
        params.append(limit)

        async with self._connection() as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(sql, params)
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def clear(self) -> None:
        async with self._connection() as db:
            await db.execute("DELETE FROM history")
            await db.commit()

    async def export_rows(self) -> AsyncIterator[Dict[str, Any]]:
        async with self._connection() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM history ORDER BY id DESC") as cursor:
                async for row in cursor:
                    yield dict(row)

    async def aggregate_by_country(self) -> Dict[str, int]:
        async with self._connection() as db:
            cur = await db.execute(
                "SELECT country_code, COUNT(*) FROM history GROUP BY country_code ORDER BY COUNT(*) DESC"
            )
            rows = await cur.fetchall()
        return {(row[0] or "??"): row[1] for row in rows}

    async def aggregate_by_query_type(self) -> Dict[str, int]:
        async with self._connection() as db:
            cur = await db.execute(
                "SELECT COALESCE(query_type, 'unknown'), COUNT(*) FROM history GROUP BY query_type ORDER BY COUNT(*) DESC"
            )
            rows = await cur.fetchall()
        return {row[0]: row[1] for row in rows}

    async def aggregate_security_hits(self) -> Dict[str, int]:
        async with self._connection() as db:
            cur = await db.execute(
                """SELECT
                    COALESCE(SUM(vpn), 0), COALESCE(SUM(proxy), 0), COALESCE(SUM(tor), 0),
                    COALESCE(SUM(i2p), 0), COALESCE(SUM(datacenter), 0), COALESCE(SUM(threat), 0)
                FROM history"""
            )
            row = await cur.fetchone()
        keys = ("vpn", "proxy", "tor", "i2p", "datacenter", "threat")
        return {key: int(value or 0) for key, value in zip(keys, row or [])}

    async def cache_summary(self) -> Dict[str, int]:
        async with self._connection() as db:
            cur = await db.execute(
                "SELECT COALESCE(SUM(cached), 0), COUNT(*) - COALESCE(SUM(cached), 0) FROM history"
            )
            row = await cur.fetchone()
        return {"hits": int(row[0] or 0), "misses": int(row[1] or 0)} if row else {"hits": 0, "misses": 0}

    async def summary(self) -> Dict[str, Any]:
        async with self._connection() as db:
            cur = await db.execute("SELECT COUNT(*), MAX(ts) FROM history")
            row = await cur.fetchone()
        return {"total_history": int(row[0] or 0), "latest_ts": row[1] if row else None}
