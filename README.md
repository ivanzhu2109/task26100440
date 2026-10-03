# task26100440

## ConsentHub 同意凭证加密存储库

密文与业务状态保存在 SQLite，明文密钥仅保存在调用方指定的本地密钥目录。
凭证原文使用 AES-256-GCM 加密（`record_id` 作为关联数据，具备密文完整性校验）。

### 使用示例

```python
from consent_store import ConsentStore

store = ConsentStore(db_path="consent.db", key_dir="/path/to/keys")

# 写入 / 读回
store.write_credential("record-001", b"...上层准备好的同意证明原文...")
proof = store.read_credential("record-001")

# 上层每 90 天触发一次轮换（本库不含定时器）
status = store.begin_rotation("rotation-2026-Q4")
while not status.done:
    status = store.advance_rotation("rotation-2026-Q4", batch_size=500)

store.close()
```

### 语义

- `write_credential`：相同 ID + 相同原文幂等；同 ID 不同原文抛 `RecordConflictError`；已写入原文不可修改。
- `read_credential`：始终与首次成功写入逐字节一致，与换钥无关。
- `begin_rotation`：同一编号重试幂等；已完成的编号（即使后续轮换已发生）不会再次换钥；同一时刻最多一轮未完成。
- `advance_rotation`：每次迁移至多 `batch_size` 条旧凭证并返回剩余数；进度持久化，可安全中断续跑；全部迁移完成后自动清除旧密钥文件，目录只保留当前有效密钥。

### 测试

```bash
python3 -m pytest tests/ -q
```
