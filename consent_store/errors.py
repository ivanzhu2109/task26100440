"""异常类型定义。"""


class ConsentStoreError(Exception):
    """本库所有异常的基类。"""


class RecordConflictError(ConsentStoreError):
    """同一记录ID被不同原文重复写入。"""


class RecordNotFoundError(ConsentStoreError):
    """按记录ID读回时记录不存在。"""


class RotationConflictError(ConsentStoreError):
    """已存在一轮未完成的轮换，不能发起新轮换。"""
