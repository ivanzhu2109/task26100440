"""ConsentStore 自动化测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from consent_store import (
    ConsentStore,
    ConsentStoreError,
    RecordConflictError,
    RecordNotFoundError,
    RotationConflictError,
)


@pytest.fixture()
def env(tmp_path: Path):
    db_path = tmp_path / "consent.db"
    key_dir = tmp_path / "keys"
    store = ConsentStore(db_path, key_dir)
    yield store, db_path, key_dir
    store.close()


def key_files(key_dir: Path) -> list[str]:
    return sorted(p.name for p in key_dir.iterdir())


class TestBasicReadWrite:
    def test_write_then_read_byte_identical(self, env):
        store, _, _ = env
        payload = b"\x00consent-proof\xff\xfe binary \x01\x02"
        store.write_credential("rec-1", payload)
        assert store.read_credential("rec-1") == payload

    def test_duplicate_same_payload_is_idempotent(self, env):
        store, db_path, _ = env
        store.write_credential("rec-1", b"proof")
        store.write_credential("rec-1", b"proof")
        count = store._conn.execute(
            "SELECT COUNT(*) FROM credentials WHERE record_id = 'rec-1'"
        ).fetchone()[0]
        assert count == 1
        assert store.read_credential("rec-1") == b"proof"

    def test_same_id_different_payload_rejected(self, env):
        store, _, _ = env
        store.write_credential("rec-1", b"proof-a")
        with pytest.raises(RecordConflictError):
            store.write_credential("rec-1", b"proof-b")
        assert store.read_credential("rec-1") == b"proof-a"

    def test_read_missing_record(self, env):
        store, _, _ = env
        with pytest.raises(RecordNotFoundError):
            store.read_credential("nope")

    def test_ciphertext_integrity_check(self, env):
        store, _, _ = env
        store.write_credential("rec-1", b"proof")
        store._conn.execute(
            "UPDATE credentials SET ciphertext = ? WHERE record_id = 'rec-1'",
            (b"\x00" * 32,),
        )
        store._conn.commit()
        with pytest.raises(ConsentStoreError):
            store.read_credential("rec-1")

    def test_plaintext_not_stored_in_db(self, env):
        store, db_path, _ = env
        secret = b"super-secret-consent-proof"
        store.write_credential("rec-1", secret)
        store.close()
        raw = db_path.read_bytes()
        assert secret not in raw


class TestRotation:
    def test_mixed_keys_then_full_migration(self, env):
        store, _, key_dir = env
        old_payloads = {f"old-{i}": f"old-proof-{i}".encode() for i in range(5)}
        for rid, payload in old_payloads.items():
            store.write_credential(rid, payload)

        status = store.begin_rotation("rot-1")
        assert not status.done
        assert status.remaining == 5
        assert status.old_key_version == 1
        assert status.new_key_version == 2

        # 新旧密钥混用期间写入新凭证。
        new_payloads = {f"new-{i}": f"new-proof-{i}".encode() for i in range(3)}
        for rid, payload in new_payloads.items():
            store.write_credential(rid, payload)

        # 新凭证必须使用新密钥，不依赖旧密钥。
        rows = store._conn.execute(
            "SELECT record_id, key_version FROM credentials"
        ).fetchall()
        versions = dict(rows)
        for rid in new_payloads:
            assert versions[rid] == 2
        for rid in old_payloads:
            assert versions[rid] == 1

        # 任务未完成期间所有凭证正常读写。
        for rid, payload in {**old_payloads, **new_payloads}.items():
            assert store.read_credential(rid) == payload

        # 小批量推进，进度逐步保留。
        status = store.advance_rotation("rot-1", batch_size=2)
        assert not status.done
        assert status.remaining == 3
        status = store.advance_rotation("rot-1", batch_size=2)
        assert not status.done
        assert status.remaining == 1
        status = store.advance_rotation("rot-1", batch_size=2)
        assert status.done
        assert status.remaining == 0

        # 全部原文逐字节一致。
        for rid, payload in {**old_payloads, **new_payloads}.items():
            assert store.read_credential(rid) == payload

        # 旧密钥不残留，目录中只剩当前有效密钥。
        assert key_files(key_dir) == ["key_2.key"]

    def test_begin_rotation_retry_is_idempotent(self, env):
        store, _, _ = env
        store.write_credential("rec-1", b"proof")
        first = store.begin_rotation("rot-1")
        again = store.begin_rotation("rot-1")
        assert again == first
        assert store.current_key_version() == 2

    def test_concurrent_rotation_rejected(self, env):
        store, _, _ = env
        store.begin_rotation("rot-1")
        with pytest.raises(RotationConflictError):
            store.begin_rotation("rot-2")

    def test_advance_without_pending_rotation(self, env):
        store, _, _ = env
        with pytest.raises(ConsentStoreError):
            store.advance_rotation("rot-x")

    def test_advance_wrong_rotation_id(self, env):
        store, _, _ = env
        store.begin_rotation("rot-1")
        with pytest.raises(RotationConflictError):
            store.advance_rotation("rot-2")

    def test_retry_completed_rotation_after_later_rotations(self, env):
        store, _, key_dir = env
        store.write_credential("rec-1", b"proof-1")

        # 完成第一轮。
        store.begin_rotation("rot-1")
        while not store.advance_rotation("rot-1", batch_size=10).done:
            pass
        assert store.current_key_version() == 2

        # 第一轮完成后写入，再完成第二轮。
        store.write_credential("rec-2", b"proof-2")
        store.begin_rotation("rot-2")
        while not store.advance_rotation("rot-2", batch_size=10).done:
            pass
        assert store.current_key_version() == 3
        assert key_files(key_dir) == ["key_3.key"]

        # 记录当前状态快照。
        snapshot = store._conn.execute(
            "SELECT record_id, key_version, nonce, ciphertext FROM credentials"
            " ORDER BY record_id"
        ).fetchall()
        keys_before = key_files(key_dir)

        # 重试第一轮编号：不得再次换钥，密钥与凭证均无变化。
        status = store.begin_rotation("rot-1")
        assert status.done
        assert status.remaining == 0
        assert store.current_key_version() == 3
        assert key_files(key_dir) == keys_before
        after = store._conn.execute(
            "SELECT record_id, key_version, nonce, ciphertext FROM credentials"
            " ORDER BY record_id"
        ).fetchall()
        assert after == snapshot

        # 重试已完成轮次的推进同样安全。
        status = store.advance_rotation("rot-1")
        assert status.done
        assert store.current_key_version() == 3

        # 凭证原文始终逐字节一致。
        assert store.read_credential("rec-1") == b"proof-1"
        assert store.read_credential("rec-2") == b"proof-2"

    def test_write_during_rotation_uses_new_key(self, env):
        store, _, _ = env
        store.begin_rotation("rot-1")
        store.write_credential("rec-new", b"fresh")
        version = store._conn.execute(
            "SELECT key_version FROM credentials WHERE record_id = 'rec-new'"
        ).fetchone()[0]
        assert version == 2

    def test_reopen_store_keeps_state(self, env):
        store, db_path, key_dir = env
        store.write_credential("rec-1", b"proof")
        store.begin_rotation("rot-1")
        store.close()

        reopened = ConsentStore(db_path, key_dir)
        try:
            assert reopened.current_key_version() == 2
            status = reopened.advance_rotation("rot-1")
            assert status.done
            assert reopened.read_credential("rec-1") == b"proof"
            assert key_files(key_dir) == ["key_2.key"]
        finally:
            reopened.close()
