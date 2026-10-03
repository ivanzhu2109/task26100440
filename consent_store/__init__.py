"""同意凭证加密存储库。"""

from .errors import (
    ConsentStoreError,
    RecordConflictError,
    RecordNotFoundError,
    RotationConflictError,
)
from .store import ConsentStore, RotationStatus

__all__ = [
    "ConsentStore",
    "RotationStatus",
    "ConsentStoreError",
    "RecordConflictError",
    "RecordNotFoundError",
    "RotationConflictError",
]
