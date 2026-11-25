"""Process-scoped one-writer lock for the single DuckDB application."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from types import TracebackType
from typing import Self


class WriterLockError(RuntimeError):
    """Raised when another process owns the application writer lock."""


class WriterLock:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._descriptor: int | None = None

    def __enter__(self) -> Self:
        self.acquire()
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.release()

    def acquire(self) -> None:
        if self._descriptor is not None:
            raise WriterLockError("writer lock is already held by this process")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self._path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(descriptor)
            raise WriterLockError("another network-behaviour writer is active") from exc
        except Exception:
            os.close(descriptor)
            raise
        self._descriptor = descriptor

    def release(self) -> None:
        if self._descriptor is None:
            return
        fcntl.flock(self._descriptor, fcntl.LOCK_UN)
        os.close(self._descriptor)
        self._descriptor = None
