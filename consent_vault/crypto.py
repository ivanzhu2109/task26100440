"""AES-256-GCM 加解密原语。"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # GCM 推荐 96 位随机 nonce


class IntegrityError(Exception):
    """密文完整性校验失败。"""


def generate_key() -> bytes:
    """生成一个全新的 AES-256 密钥。"""
    return os.urandom(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """用 32 字节密钥加密，返回 nonce || 密文||认证标签 的不透明字节串。"""
    if len(key) != KEY_SIZE:
        raise ValueError("密钥必须为 32 字节（AES-256）")
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(key: bytes, blob: bytes) -> bytes:
    """解密 encrypt 的输出，完整性校验失败时抛 IntegrityError。"""
    if len(key) != KEY_SIZE:
        raise ValueError("密钥必须为 32 字节（AES-256）")
    if len(blob) < NONCE_SIZE:
        raise IntegrityError("密文过短，缺少 nonce")
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise IntegrityError("密文完整性校验失败") from exc
