"""ConsentVault 自动化测试。"""

import sqlite3

import pytest

from consent_vault import (
    ConsentVault,
    CredentialConflictError,
    CredentialNotFoundError,
    RotationConflictError,
    RotationStateError,
)
from consent_vault.crypto import IntegrityError


@pytest.fixture()
def env(tmp_path):
    db_path = tmp_path / "vault.db"
    key_dir = tmp_path / "keys"
    vault = ConsentVault(db_path, key_dir)
    yield vault, db_path, key_dir
    vault.close()


def key_files(key_dir):
    return sorted(p.name for p in key_dir.iterdir())


def raw_payload(db_path, record_id):
    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT key_id, payload FROM credentials WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        return (row[0], bytes(row[1])) if row else None
    finally:
        conn.close()


# ---- 基本读写语义 ----


class TestBasicReadWrite:
    def test_write_then_read_roundtrip_bytes(self, env):
        vault, _, _ = env
        payload = b"\x00consent-proof\xff\xfe binary \x01\x02"
        vault.write_credential("rec-1", payload)
        assert vault.read_credential("rec-1") == payload

    def test_duplicate_same_payload_is_idempotent(self, env):
        vault, db_path, _ = env
        vault.write_credential("rec-1", b"proof")
        before = raw_payload(db_path, "rec-1")
        vault.write_credential("rec-1", b"proof")
        after = raw_payload(db_path, "rec-1")
        assert before == after  # 只保留一份，密文未变

    def test_same_id_different_payload_rejected(self, env):
        vault, _, _ = env
        vault.write_credential("rec-1", b"proof-A")
        with pytest.raises(CredentialConflictError):
            vault.write_credential("rec-1", b"proof-B")
        assert vault.read_credential("rec-1") == b"proof-A"  # 原文未被覆盖

    def test_read_missing_record(self, env):
        vault, _, _ = env
        with pytest.raises(CredentialNotFoundError):
            vault.read_credential("nope")

    def test_ciphertext_is_not_plaintext(self, env):
        vault, db_path, _ = env
        payload = b"user-consented-to-terms-v1"
        vault.write_credential("rec-1", payload)
        _, blob = raw_payload(db_path, "rec-1")
        assert payload not in blob
        assert blob != payload

    def test_tampered_ciphertext_fails_integrity(self, env):
        vault, db_path, _ = env
        vault.write_credential("rec-1", b"proof")
        conn = sqlite3.connect(str(db_path))
        _, blob = raw_payload(db_path, "rec-1")
        tampered = blob[:-1] + bytes([blob[-1] ^ 0x01])
        conn.execute(
            "UPDATE credentials SET payload = ? WHERE record_id = 'rec-1'",
            (tampered,),
        )
        conn.commit()
        conn.close()
        with pytest.raises(IntegrityError):
            vault.read_credential("rec-1")


# ---- 场景一：混用期间写入 + 推进至完成 ----


class TestRotationMixedPeriod:
    def test_mixed_period_write_and_full_migration(self, env):
        vault, db_path, key_dir = env
        old_key_id = vault.current_key_id

        # 旧密钥下写入 5 条
        old_records = {f"old-{i}": f"old-proof-{i}".encode() for i in range(5)}
        for rid, payload in old_records.items():
            vault.write_credential(rid, payload)

        vault.begin_rotation("rot-1")
        new_key_id = vault.current_key_id
        assert new_key_id != old_key_id

        # 混用期间写入新凭证
        new_records = {f"new-{i}": f"new-proof-{i}".encode() for i in range(3)}
        for rid, payload in new_records.items():
            vault.write_credential(rid, payload)

        # 新凭证不依赖旧密钥
        for rid in new_records:
            key_id, _ = raw_payload(db_path, rid)
            assert key_id == new_key_id

        # 混用期间全部凭证可逐字节读回
        for rid, payload in {**old_records, **new_records}.items():
            assert vault.read_credential(rid) == payload

        # 分批推进：batch_size=2，进度逐步保留
        seen_migrated = 0
        while True:
            progress = vault.advance_rotation(batch_size=2)
            assert progress.migrated <= 2
            seen_migrated += progress.migrated
            if progress.done:
                break
        assert seen_migrated == 5  # 只有 5 条旧凭证需要迁移，不重复处理

        # 完成后：全部读回一致，目录只剩当前密钥文件
        for rid, payload in {**old_records, **new_records}.items():
            assert vault.read_credential(rid) == payload
        assert key_files(key_dir) == [f"key_{new_key_id}.key"]
        for rid in list(old_records) + list(new_records):
            key_id, _ = raw_payload(db_path, rid)
            assert key_id == new_key_id

    def test_write_during_rotation_uses_new_key(self, env):
        vault, db_path, _ = env
        vault.write_credential("before", b"p1")
        vault.begin_rotation("rot-1")
        vault.write_credential("after", b"p2")
        key_id, _ = raw_payload(db_path, "after")
        assert key_id == vault.current_key_id
        assert vault.read_credential("before") == b"p1"
        assert vault.read_credential("after") == b"p2"


# ---- 场景二：两轮完成后重试第一轮编号 ----


class TestRotationIdempotency:
    def test_retry_old_rotation_id_after_two_rounds(self, env):
        vault, db_path, key_dir = env
        records = {f"rec-{i}": f"payload-{i}".encode() for i in range(4)}
        for rid, payload in records.items():
            vault.write_credential(rid, payload)

        # 第一轮完整轮换
        vault.begin_rotation("rot-1")
        while not vault.advance_rotation(batch_size=2).done:
            pass
        key_after_rot1 = vault.current_key_id

        # 再写一条，然后第二轮完整轮换
        vault.write_credential("rec-extra", b"extra")
        vault.begin_rotation("rot-2")
        while not vault.advance_rotation(batch_size=1).done:
            pass
        key_after_rot2 = vault.current_key_id
        assert key_after_rot2 != key_after_rot1

        # 快照当前状态
        files_before = key_files(key_dir)
        blobs_before = {
            rid: raw_payload(db_path, rid) for rid in list(records) + ["rec-extra"]
        }

        # 重试第一轮编号：不得产生任何变化
        vault.begin_rotation("rot-1")
        assert vault.current_key_id == key_after_rot2
        assert key_files(key_dir) == files_before
        for rid, before in blobs_before.items():
            assert raw_payload(db_path, rid) == before
        for rid, payload in {**records, "rec-extra": b"extra"}.items():
            assert vault.read_credential(rid) == payload

        # 重试第二轮编号同样幂等
        vault.begin_rotation("rot-2")
        assert vault.current_key_id == key_after_rot2
        assert key_files(key_dir) == files_before

    def test_retry_inflight_rotation_id_is_noop(self, env):
        vault, _, key_dir = env
        vault.write_credential("rec-1", b"p")
        vault.begin_rotation("rot-1")
        key_id = vault.current_key_id
        vault.begin_rotation("rot-1")  # 同一轮重试
        assert vault.current_key_id == key_id
        assert len(key_files(key_dir)) == 2  # 旧+新，未生成第三个密钥

    def test_conflicting_rotation_rejected(self, env):
        vault, _, _ = env
        vault.begin_rotation("rot-1")
        with pytest.raises(RotationConflictError):
            vault.begin_rotation("rot-2")

    def test_advance_without_rotation_raises(self, env):
        vault, _, _ = env
        with pytest.raises(RotationStateError):
            vault.advance_rotation()

    def test_progress_not_reprocessed(self, env):
        vault, _, _ = env
        for i in range(5):
            vault.write_credential(f"rec-{i}", f"p-{i}".encode())
        vault.begin_rotation("rot-1")
        p1 = vault.advance_rotation(batch_size=3)
        assert (p1.migrated, p1.remaining, p1.done) == (3, 2, False)
        p2 = vault.advance_rotation(batch_size=3)
        assert (p2.migrated, p2.remaining, p2.done) == (2, 0, True)
        # 完成后再推进视为无任务
        with pytest.raises(RotationStateError):
            vault.advance_rotation()


# ---- 持久化与重开 ----


class TestPersistence:
    def test_reopen_vault_keeps_data(self, tmp_path):
        db_path = tmp_path / "vault.db"
        key_dir = tmp_path / "keys"
        vault = ConsentVault(db_path, key_dir)
        vault.write_credential("rec-1", b"durable-proof")
        vault.write_credential("rec-2", b"durable-proof-2")
        vault.begin_rotation("rot-1")
        progress = vault.advance_rotation(batch_size=1)
        assert not progress.done  # 尚有一条未迁移，任务未完成
        vault.close()

        # 重开后轮换状态与数据都在，可继续推进
        vault2 = ConsentVault(db_path, key_dir)
        assert vault2.read_credential("rec-1") == b"durable-proof"
        progress = vault2.advance_rotation(batch_size=1)
        assert progress.done
        assert vault2.read_credential("rec-2") == b"durable-proof-2"
        vault2.close()
