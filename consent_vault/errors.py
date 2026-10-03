"""库异常定义。"""


class ConsentVaultError(Exception):
    """本库所有异常的基类。"""


class CredentialConflictError(ConsentVaultError):
    """同一记录 ID 被不同原文重复写入。"""


class CredentialNotFoundError(ConsentVaultError):
    """按记录 ID 读取时记录不存在。"""


class RotationConflictError(ConsentVaultError):
    """已有其他轮换任务未完成，拒绝发起新轮换。"""


class RotationStateError(ConsentVaultError):
    """轮换状态不允许当前操作（如无进行中任务却推进）。"""
