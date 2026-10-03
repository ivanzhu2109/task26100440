"""本地密钥目录管理：密钥文件的生成、加载与清理。"""

from __future__ import annotations

import os
from pathlib import Path

KEY_FILE_PREFIX = "key_"
KEY_FILE_SUFFIX = ".key"
KEY_BYTES = 32  # AES-256


class KeyDirectory:
    """管理调用方指定的本地密钥目录。

    密钥以 ``key_<version>.key`` 命名的原始字节文件保存，
    明文密钥只落盘在该目录，绝不写入数据库。
    """

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)

    @property
    def directory(self) -> Path:
        return self._dir

    def ensure(self) -> None:
        """确保目录存在。"""
        self._dir.mkdir(parents=True, exist_ok=True)

    def key_path(self, version: int) -> Path:
        """返回指定版本密钥文件的路径。"""
        return self._dir / f"{KEY_FILE_PREFIX}{version}{KEY_FILE_SUFFIX}"

    def exists(self, version: int) -> bool:
        """指定版本的密钥文件是否存在。"""
        return self.key_path(version).is_file()

    def create(self, version: int) -> bytes:
        """生成并落盘一个新版本的随机密钥，返回密钥字节。"""
        self.ensure()
        path = self.key_path(version)
        if path.exists():
            raise FileExistsError(f"密钥文件已存在: {path}")
        key = os.urandom(KEY_BYTES)
        # 先写临时文件再原子替换，避免半截密钥文件。
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return key

    def load(self, version: int) -> bytes:
        """读取指定版本的密钥字节。"""
        data = self.key_path(version).read_bytes()
        if len(data) != KEY_BYTES:
            raise ValueError(f"密钥文件长度异常: {self.key_path(version)}")
        return data

    def list_versions(self) -> list[int]:
        """列出目录中所有密钥文件的版本号。"""
        if not self._dir.is_dir():
            return []
        versions: list[int] = []
        for entry in self._dir.iterdir():
            name = entry.name
            if name.startswith(KEY_FILE_PREFIX) and name.endswith(KEY_FILE_SUFFIX):
                stem = name[len(KEY_FILE_PREFIX) : -len(KEY_FILE_SUFFIX)]
                if stem.isdigit():
                    versions.append(int(stem))
        return sorted(versions)

    def remove(self, version: int) -> None:
        """删除指定版本的密钥文件（若存在）。"""
        self.key_path(version).unlink(missing_ok=True)

    def keep_only(self, version: int) -> None:
        """删除除指定版本外的所有密钥文件。"""
        for other in self.list_versions():
            if other != version:
                self.remove(other)
