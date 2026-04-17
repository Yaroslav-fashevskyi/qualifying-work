from __future__ import annotations

from typing import List, Dict, Any, AsyncIterator
import aiosqlite


class HistoryService:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    async def init_db(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """CREATE TABLE IF NOT EXISTS history(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                query TEXT,
                query_type TEXT,
                ip TEXT NOT NULL,
                country_code TEXT,
                country_name TEXT,
                city TEXT,
                region TEXT,
                org TEXT,
                source TEXT,
                cached INTEGER,
                vpn INTEGER,
                proxy INTEGER,
                tor INTEGER,
                i2p INTEGER,
                datacenter INTEGER DEFAULT 0,
                threat INTEGER DEFAULT 0
            )"""
            )
            try:
                await db.execute(
                    "ALTER TABLE history ADD COLUMN proxy INTEGER DEFAULT 0"
                )
            except aiosqlite.OperationalError:
                pass
            try:
                await db.execute("ALTER TABLE history ADD COLUMN query TEXT")
            except aiosqlite.OperationalError:
                pass
            try:
                await db.execute(
                    "ALTER TABLE history ADD COLUMN query_type TEXT DEFAULT 'ip'"
                )
            except aiosqlite.OperationalError:
                pass
            try:
                await db.execute(
                    "ALTER TABLE history ADD COLUMN datacenter INTEGER DEFAULT 0"
                )
            except aiosqlite.OperationalError:
                pass
            try:
                await db.execute(
                    "ALTER TABLE history ADD COLUMN threat INTEGER DEFAULT 0"
                )
            except aiosqlite.OperationalError:
                pass
            await db.commit()

    async def save(self, payload: Dict[str, Any]) -> None:
        ip = payload.get("ip")
        if not ip:
            return
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT INTO history(
                        ts, query, query_type, ip, country_code, country_name, city, region,
                        org, source, cached, vpn, proxy, tor, i2p, datacenter, threat
                    )
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    payload.get("ts"),
                    payload.get("query"),
                    payload.get("query_type"),
                    ip,
                    payload.get("country_code"),
                    payload.get("country_name"),
                    payload.get("city"),
                    payload.get("region"),
                    payload.get("org") or payload.get("rdap_org"),
                    payload.get("source"),
                    1 if payload.get("cached") else 0,
                    1 if payload.get("security", {}).get("vpn") else 0,
                    1 if payload.get("security", {}).get("proxy") else 0,
                    1 if payload.get("security", {}).get("tor") else 0,
                    1 if payload.get("security", {}).get("i2p") else 0,
                    1 if payload.get("security", {}).get("datacenter") else 0,
                    1 if payload.get("security", {}).get("threat") else 0,
                ),
            )
            await db.commit()

    async def recent(self, limit: int) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT * FROM history ORDER BY id DESC LIMIT ?", (limit,)
            )
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def clear(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("DELETE FROM history")
            await db.commit()

    async def export_rows(self) -> AsyncIterator[Dict[str, Any]]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM history ORDER BY id DESC") as cursor:
                async for row in cursor:
                    yield dict(row)

    async def aggregate_by_country(self) -> Dict[str, int]:
        async with aiosqlite.connect(self._db_path) as db:
            cur = await db.execute(
                "SELECT country_code, COUNT(*) FROM history GROUP BY country_code"
            )
            rows = await cur.fetchall()
        return {(row[0] or "??"): row[1] for row in rows}
