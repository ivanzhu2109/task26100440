"""本地密钥目录管理：明文密钥仅以此处文件形式存在。"""

import os
import re
from pathlib import Path

from consent_vault import crypto

_KEY_FILE_RE = re.compile(r"^key_(\d+)\.key$")


class KeyNotFoundError(Exception):
    """指定编号的密钥文件不存在。"""


class KeyStore:
    """管理密钥目录中的 AES-256 密钥文件，文件名为 key_<编号>.key。"""

    def __init__(self, key_dir: str | Path) -> None:
        self._dir = Path(key_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def directory(self) -> Path:
        return self._dir

    def _path_for(self, key_id: int) -> Path:
        return self._dir / f"key_{key_id}.key"

    def create_key(self) -> int:
        """生成新密钥并落盘，返回密钥编号（单调递增）。"""
        existing = self.list_key_ids()
        key_id = (max(existing) + 1) if existing else 1
        path = self._path_for(key_id)
        # O_EXCL 防止并发下覆盖已有密钥文件；0600 仅属主可读写
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, crypto.generate_key())
        finally:
            os.close(fd)
        return key_id

    def load_key(self, key_id: int) -> bytes:
        """读取指定编号密钥，不存在时抛 KeyNotFoundError。"""
        path = self._path_for(key_id)
        if not path.is_file():
            raise KeyNotFoundError(f"密钥文件不存在: {path}")
        data = path.read_bytes()
        if len(data) != crypto.KEY_SIZE:
            raise KeyNotFoundError(f"密钥文件长度非法: {path}")
        return data

    def has_key(self, key_id: int) -> bool:
        return self._path_for(key_id).is_file()

    def list_key_ids(self) -> list[int]:
        ids: list[int] = []
        for entry in self._dir.iterdir():
            match = _KEY_FILE_RE.match(entry.name)
            if match and entry.is_file():
                ids.append(int(match.group(1)))
        return sorted(ids)

    def delete_key(self, key_id: int) -> None:
        """删除指定编号密钥文件；不存在时静默忽略。"""
        try:
            self._path_for(key_id).unlink()
        except FileNotFoundError:
            pass

    def keep_only(self, key_id: int) -> None:
        """删除目录中除指定编号外的全部密钥文件。"""
        for other in self.list_key_ids():
            if other != key_id:
                self.delete_key(other)
