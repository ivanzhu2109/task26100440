"""ConsentVault：对上层暴露的四种能力。"""

import json
from dataclasses import dataclass
from pathlib import Path

from consent_vault import crypto
from consent_vault.errors import (
    CredentialConflictError,
    CredentialNotFoundError,
    RotationConflictError,
    RotationStateError,
)
from consent_vault.keystore import KeyStore
from consent_vault.store import Store

_META_CURRENT_KEY_ID = "current_key_id"
_META_ROTATION = "rotation"
_META_COMPLETED_ROTATIONS = "completed_rotations"


@dataclass(frozen=True)
class RotationProgress:
    """一次推进的结果。"""

    rotation_id: str
    migrated: int
    remaining: int
    done: bool


class ConsentVault:
    """同意凭证加密存储库。

    - 密文与业务状态存 SQLite，明文密钥只存在于 key_dir 目录。
    - 凭证原文不可修改；同 ID 同原文幂等，同 ID 不同原文抛冲突。
    - 轮换由上层触发：begin_rotation 发起，advance_rotation 逐步推进。
    """

    def __init__(self, db_path: str | Path, key_dir: str | Path) -> None:
        self._store = Store(db_path)
        self._keys = KeyStore(key_dir)
        if self._store.get_meta(_META_CURRENT_KEY_ID) is None:
            key_id = self._keys.create_key()
            self._store.set_meta(_META_CURRENT_KEY_ID, str(key_id))

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "ConsentVault":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- 内部状态 ----

    @property
    def current_key_id(self) -> int:
        return int(self._store.get_meta(_META_CURRENT_KEY_ID))

    def _get_rotation(self) -> dict | None:
        raw = self._store.get_meta(_META_ROTATION)
        return None if raw is None else json.loads(raw)

    def _get_completed(self) -> list[str]:
        raw = self._store.get_meta(_META_COMPLETED_ROTATIONS)
        return [] if raw is None else list(json.loads(raw))

    # ---- 能力一：写入凭证 ----

    def write_credential(self, record_id: str, payload: bytes) -> None:
        """写入凭证；同 ID 同原文幂等，同 ID 不同原文抛 CredentialConflictError。"""
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("payload 必须为字节串")
        payload = bytes(payload)
        existing = self._store.get_credential(record_id)
        if existing is not None:
            key_id, blob = existing
            original = crypto.decrypt(self._keys.load_key(key_id), blob)
            if original != payload:
                raise CredentialConflictError(
                    f"记录 {record_id!r} 已存在且原文不同，拒绝覆盖"
                )
            return  # 同 ID 同原文：幂等，只保留一份
        key_id = self.current_key_id
        blob = crypto.encrypt(self._keys.load_key(key_id), payload)
        self._store.insert_credential(record_id, key_id, blob)

    # ---- 能力二：按记录 ID 读回 ----

    def read_credential(self, record_id: str) -> bytes:
        """按记录 ID 读回原文，逐字节等于首次写入。"""
        existing = self._store.get_credential(record_id)
        if existing is None:
            raise CredentialNotFoundError(f"记录不存在: {record_id!r}")
        key_id, blob = existing
        return crypto.decrypt(self._keys.load_key(key_id), blob)

    # ---- 能力三：发起轮换 ----

    def begin_rotation(self, rotation_id: str) -> None:
        """发起一轮密钥轮换。

        - 同编号重试（无论进行中还是已完成）均为幂等空操作。
        - 已有其他编号任务未完成时抛 RotationConflictError。
        """
        rotation = self._get_rotation()
        if rotation is not None:
            if rotation["rotation_id"] == rotation_id:
                return  # 同一轮的重试
            raise RotationConflictError(
                f"轮换 {rotation['rotation_id']!r} 未完成，拒绝发起 {rotation_id!r}"
            )
        if rotation_id in self._get_completed():
            return  # 旧轮换的重试：不再换钥
        new_key_id = self._keys.create_key()
        self._store.set_meta(_META_CURRENT_KEY_ID, str(new_key_id))
        self._store.set_meta(
            _META_ROTATION,
            json.dumps({"rotation_id": rotation_id, "new_key_id": new_key_id}),
        )

    # ---- 能力四：推进轮换 ----

    def advance_rotation(self, batch_size: int = 100) -> RotationProgress:
        """推进轮换：迁移至多 batch_size 条凭证，返回进度。

        全部凭证不再依赖旧密钥且旧密钥文件清除后，轮换完成。
        """
        rotation = self._get_rotation()
        if rotation is None:
            raise RotationStateError("当前没有进行中的轮换任务")
        rotation_id = rotation["rotation_id"]
        target_key_id = int(rotation["new_key_id"])
        new_key = self._keys.load_key(target_key_id)

        migrated = 0
        for record_id, old_key_id, blob in self._store.fetch_old_key_records(
            target_key_id, batch_size
        ):
            plaintext = crypto.decrypt(self._keys.load_key(old_key_id), blob)
            new_blob = crypto.encrypt(new_key, plaintext)
            self._store.reencrypt_credential(record_id, target_key_id, new_blob)
            migrated += 1

        remaining = self._store.count_old_key_records(target_key_id)
        done = remaining == 0
        if done:
            # 先确认 DB 中无旧密钥依赖，再清除旧密钥文件，最后落完成标记；
            # 任意时刻崩溃后重试均安全（keep_only 与完成标记均幂等）。
            self._keys.keep_only(target_key_id)
            completed = self._get_completed()
            if rotation_id not in completed:
                completed.append(rotation_id)
            self._store.set_meta(
                _META_COMPLETED_ROTATIONS, json.dumps(completed)
            )
            self._store.delete_meta(_META_ROTATION)
        return RotationProgress(
            rotation_id=rotation_id,
            migrated=migrated,
            remaining=remaining,
            done=done,
        )
