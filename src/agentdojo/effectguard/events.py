from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class GuardEvent:
    sequence: int
    decision: str
    reason: str
    mode: str
    tool: str
    nonce: str | None
    parent: str | None
    attempt: int


class EventSink(Protocol):
    def append(self, event: GuardEvent) -> None: ...


class NullEventSink:
    def append(self, event: GuardEvent) -> None:
        pass


class JsonlEventSink:
    """Process-local, append-only JSONL audit sink."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, event: GuardEvent) -> None:
        record: dict[str, Any] = asdict(event)
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with self._lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
