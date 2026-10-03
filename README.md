# ConsentVault — 同意凭证加密存储库

为 ConsentHub 提供不可修改同意凭证的长期加密存储。密文与业务状态存 SQLite，
明文密钥仅以文件形式存在于调用方指定的本地密钥目录。

## 能力

- `write_credential(record_id, payload)`：写入凭证。AES-256-GCM 加密（密文完整性校验）。
  同 ID 同原文幂等；同 ID 不同原文抛 `CredentialConflictError`。
- `read_credential(record_id)`：按记录 ID 读回，逐字节等于首次写入。
- `begin_rotation(rotation_id)`：发起密钥轮换。同编号重试幂等（含已完成轮次）；
  有其他任务未完成时抛 `RotationConflictError`。发起后新写入立即使用新密钥。
- `advance_rotation(batch_size)`：逐步迁移旧凭证，返回 `RotationProgress`；
  全部迁移且旧密钥文件清除后 `done=True`，密钥目录只保留当前有效密钥文件。

本库不实现定时器，每 90 天的轮换节奏由上层触发。

## 用法

```python
from consent_vault import ConsentVault

vault = ConsentVault(db_path="consent.db", key_dir="/path/to/keys")
vault.write_credential("rec-001", b"<上层准备好的同意证明字节>")
proof = vault.read_credential("rec-001")

vault.begin_rotation("rotation-2026-Q4")   # 上层每 90 天触发
while not vault.advance_rotation(batch_size=500).done:
    pass
vault.close()
```

## 测试

```bash
python3 -m pytest tests/ -q
```
