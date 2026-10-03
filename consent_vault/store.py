"""SQLite 持久化层：密文与业务状态。"""

import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    record_id  TEXT PRIMARY KEY,
    key_id     INTEGER NOT NULL,
    payload    BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Store:
    """封装 credentials 表（密文）与 meta 表（轮换状态）。

    本层只做存取，不含业务规则；业务规则在 vault 层。
    """

    def __init__(self, db_path: str | Path) -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ---- credentials 表 ----

    def get_credential(self, record_id: str) -> tuple[int, bytes] | None:
        """返回 (key_id, payload)，不存在时返回 None。"""
        row = self._conn.execute(
            "SELECT key_id, payload FROM credentials WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            return None
        return int(row[0]), bytes(row[1])

    def insert_credential(self, record_id: str, key_id: int, payload: bytes) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO credentials (record_id, key_id, payload) VALUES (?, ?, ?)",
                (record_id, key_id, payload),
            )

    def fetch_old_key_records(
        self, current_key_id: int, limit: int
    ) -> list[tuple[str, int, bytes]]:
        """取至多 limit 条仍依赖非当前密钥的凭证，按 record_id 排序保证稳定。"""
        rows = self._conn.execute(
            "SELECT record_id, key_id, payload FROM credentials "
            "WHERE key_id != ? ORDER BY record_id LIMIT ?",
            (current_key_id, limit),
        ).fetchall()
        return [(str(r[0]), int(r[1]), bytes(r[2])) for r in rows]

    def count_old_key_records(self, current_key_id: int) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM credentials WHERE key_id != ?",
            (current_key_id,),
        ).fetchone()
        return int(row[0])

    def reencrypt_credential(
        self, record_id: str, new_key_id: int, new_payload: bytes
    ) -> None:
        """用新密文覆盖旧密文（仅换钥场景调用，原文不变）。"""
        with self._conn:
            self._conn.execute(
                "UPDATE credentials SET key_id = ?, payload = ? WHERE record_id = ?",
                (new_key_id, new_payload, record_id),
            )

    # ---- meta 表 ----

    def get_meta(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        return None if row is None else str(row[0])

    def set_meta(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def delete_meta(self, key: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM meta WHERE key = ?", (key,))
