"""同意凭证加密存储库主入口。"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import (
    ConsentStoreError,
    RecordConflictError,
    RecordNotFoundError,
    RotationConflictError,
)
from .keys import KeyDirectory

SCHEMA_VERSION = 1
NONCE_BYTES = 12  # AES-GCM 标准随机 nonce 长度

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
    record_id TEXT PRIMARY KEY,
    key_version INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    plaintext_hash BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS completed_rotations (
    rotation_id TEXT PRIMARY KEY,
    old_key_version INTEGER NOT NULL,
    new_key_version INTEGER NOT NULL,
    completed_at TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class RotationStatus:
    """一次轮换的当前状态。"""

    rotation_id: str
    done: bool
    remaining: int
    old_key_version: int
    new_key_version: int


class ConsentStore:
    """同意凭证加密存储库。

    密文与业务状态保存在 SQLite，明文密钥仅保存在调用方指定的
    本地密钥目录。上层每 90 天触发一次 :meth:`begin_rotation`，
    并用 :meth:`advance_rotation` 逐步迁移历史凭证。
    """

    def __init__(self, db_path: str | Path, key_dir: str | Path) -> None:
        self._db_path = Path(db_path)
        self._keys = KeyDirectory(key_dir)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.executescript(_SCHEMA)
        self._keys.ensure()
        if self._get_meta("current_key_version") is None:
            # 首次初始化：生成 1 号密钥作为当前写入密钥。
            self._keys.create(1)
            self._set_meta("schema_version", str(SCHEMA_VERSION))
            self._set_meta("current_key_version", "1")
            self._conn.commit()

    def close(self) -> None:
        """关闭数据库连接。"""
        self._conn.close()

    def __enter__(self) -> "ConsentStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def write_credential(self, record_id: str, plaintext: bytes) -> None:
        """写入凭证。重复写入相同ID与原文为幂等；同ID不同原文报错。"""
        if not record_id:
            raise ValueError("record_id 不能为空")
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise TypeError("plaintext 必须是字节串")
        plaintext = bytes(plaintext)
        digest = hashlib.sha256(plaintext).digest()
        row = self._conn.execute(
            "SELECT plaintext_hash FROM credentials WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if row is not None:
            if row[0] == digest:
                return  # 相同ID与相同原文：幂等，只保留一份。
            raise RecordConflictError(f"记录ID已存在且原文不同: {record_id}")
        version = self.current_key_version()
        nonce, ciphertext = self._encrypt(version, record_id, plaintext)
        with self._conn:
            self._conn.execute(
                "INSERT INTO credentials"
                " (record_id, key_version, nonce, ciphertext, plaintext_hash)"
                " VALUES (?, ?, ?, ?, ?)",
                (record_id, version, nonce, ciphertext, digest),
            )

    def read_credential(self, record_id: str) -> bytes:
        """按记录ID读回原文，与首次成功写入逐字节一致。"""
        row = self._conn.execute(
            "SELECT key_version, nonce, ciphertext FROM credentials"
            " WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"记录不存在: {record_id}")
        key_version, nonce, ciphertext = row
        return self._decrypt(key_version, record_id, nonce, ciphertext)

    def begin_rotation(self, rotation_id: str) -> RotationStatus:
        """发起一轮密钥轮换。同一编号重试幂等；已完成编号不再换钥。"""
        if not rotation_id:
            raise ValueError("rotation_id 不能为空")
        pending = self._pending_rotation()
        if pending is not None:
            if pending["rotation_id"] == rotation_id:
                return self._status(pending)
            raise RotationConflictError(
                f"存在未完成的轮换 {pending['rotation_id']}，"
                f"不能再发起 {rotation_id}"
            )
        done = self._completed_rotation(rotation_id)
        if done is not None:
            # 该编号早已完成：重试只代表同一轮，不得再次换钥。
            return RotationStatus(
                rotation_id=rotation_id,
                done=True,
                remaining=0,
                old_key_version=done["old_key_version"],
                new_key_version=done["new_key_version"],
            )
        old_version = self.current_key_version()
        new_version = old_version + 1
        self._keys.create(new_version)
        with self._conn:
            self._set_meta("current_key_version", str(new_version))
            self._set_meta("rotation_id", rotation_id)
            self._set_meta("rotation_old_version", str(old_version))
            self._set_meta("rotation_new_version", str(new_version))
        return self._status(self._pending_rotation())

    def advance_rotation(
        self, rotation_id: str, batch_size: int = 100
    ) -> RotationStatus:
        """推进轮换：迁移至多 batch_size 条旧凭证，返回当前状态。"""
        if batch_size < 1:
            raise ValueError("batch_size 必须为正整数")
        pending = self._pending_rotation()
        if pending is None:
            done = self._completed_rotation(rotation_id)
            if done is not None:
                return RotationStatus(
                    rotation_id=rotation_id,
                    done=True,
                    remaining=0,
                    old_key_version=done["old_key_version"],
                    new_key_version=done["new_key_version"],
                )
            raise ConsentStoreError(f"没有进行中的轮换: {rotation_id}")
        if pending["rotation_id"] != rotation_id:
            raise RotationConflictError(
                f"进行中的轮换是 {pending['rotation_id']}，不是 {rotation_id}"
            )
        new_version = pending["new_key_version"]
        rows = self._conn.execute(
            "SELECT record_id, key_version, nonce, ciphertext FROM credentials"
            " WHERE key_version != ? ORDER BY rowid LIMIT ?",
            (new_version, batch_size),
        ).fetchall()
        with self._conn:
            for record_id, key_version, nonce, ciphertext in rows:
                plaintext = self._decrypt(key_version, record_id, nonce, ciphertext)
                new_nonce, new_ciphertext = self._encrypt(
                    new_version, record_id, plaintext
                )
                self._conn.execute(
                    "UPDATE credentials SET key_version = ?, nonce = ?,"
                    " ciphertext = ? WHERE record_id = ?",
                    (new_version, new_nonce, new_ciphertext, record_id),
                )
        status = self._status(pending)
        if status.remaining == 0:
            self._finish_rotation(pending)
            status = RotationStatus(
                rotation_id=rotation_id,
                done=True,
                remaining=0,
                old_key_version=pending["old_key_version"],
                new_key_version=new_version,
            )
        return status

    def current_key_version(self) -> int:
        """当前用于写入新凭证的密钥版本。"""
        return int(self._get_meta("current_key_version"))

    # ---- 内部辅助 ----

    def _encrypt(
        self, key_version: int, record_id: str, plaintext: bytes
    ) -> tuple[bytes, bytes]:
        key = self._keys.load(key_version)
        nonce = os.urandom(NONCE_BYTES)
        # record_id 作为关联数据，密文与记录绑定，具备完整性校验。
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, record_id.encode("utf-8"))
        return nonce, ciphertext

    def _decrypt(
        self, key_version: int, record_id: str, nonce: bytes, ciphertext: bytes
    ) -> bytes:
        key = self._keys.load(key_version)
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, record_id.encode("utf-8"))
        except InvalidTag as exc:
            raise ConsentStoreError(f"密文完整性校验失败: {record_id}") from exc

    def _get_meta(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else None

    def _set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def _del_meta(self, key: str) -> None:
        self._conn.execute("DELETE FROM meta WHERE key = ?", (key,))

    def _pending_rotation(self) -> dict | None:
        rotation_id = self._get_meta("rotation_id")
        if rotation_id is None:
            return None
        return {
            "rotation_id": rotation_id,
            "old_key_version": int(self._get_meta("rotation_old_version")),
            "new_key_version": int(self._get_meta("rotation_new_version")),
        }

    def _completed_rotation(self, rotation_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT old_key_version, new_key_version FROM completed_rotations"
            " WHERE rotation_id = ?",
            (rotation_id,),
        ).fetchone()
        if row is None:
            return None
        return {"old_key_version": row[0], "new_key_version": row[1]}

    def _status(self, pending: dict) -> RotationStatus:
        remaining = self._conn.execute(
            "SELECT COUNT(*) FROM credentials WHERE key_version != ?",
            (pending["new_key_version"],),
        ).fetchone()[0]
        return RotationStatus(
            rotation_id=pending["rotation_id"],
            done=False,
            remaining=remaining,
            old_key_version=pending["old_key_version"],
            new_key_version=pending["new_key_version"],
        )

    def _finish_rotation(self, pending: dict) -> None:
        # 全部凭证已脱离旧密钥：清除旧密钥文件及一切无用副本，
        # 目录中只保留当前有效密钥。
        self._keys.keep_only(pending["new_key_version"])
        with self._conn:
            self._conn.execute(
                "INSERT INTO completed_rotations"
                " (rotation_id, old_key_version, new_key_version, completed_at)"
                " VALUES (?, ?, ?, ?)",
                (
                    pending["rotation_id"],
                    pending["old_key_version"],
                    pending["new_key_version"],
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._del_meta("rotation_id")
            self._del_meta("rotation_old_version")
            self._del_meta("rotation_new_version")
