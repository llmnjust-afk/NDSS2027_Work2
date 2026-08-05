from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from decimal import Decimal
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel

Canonicalizer = Callable[[Any], Any]


def canonicalize_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return canonicalize_value(value.model_dump())
    if isinstance(value, Mapping):
        return {str(key): canonicalize_value(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [canonicalize_value(item) for item in value]
    if isinstance(value, Decimal):
        return format(value.normalize(), "f")
    if isinstance(value, str):
        return value.strip()
    return value


def canonicalize_email(value: Any) -> str:
    return str(value).strip().casefold()


def canonicalize_url(value: Any) -> str:
    parsed = urlsplit(str(value).strip())
    scheme = parsed.scheme.casefold()
    hostname = (parsed.hostname or "").casefold()
    port = parsed.port
    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        hostname = f"{hostname}:{port}"
    path = parsed.path or "/"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit((scheme, hostname, path, query, ""))


class CanonicalizerRegistry:
    def __init__(self) -> None:
        self._fields: dict[tuple[str, str], Canonicalizer] = {}

    def register(self, tool: str, field: str, canonicalizer: Canonicalizer) -> None:
        self._fields[(tool, field)] = canonicalizer

    def args(self, tool: str, values: Mapping[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key in sorted(values):
            canonicalizer = self._fields.get((tool, key), canonicalize_value)
            result[key] = canonicalizer(values[key])
        return result

    def target(self, tool: str, field: str | None, value: Any) -> str:
        canonicalizer = self._fields.get((tool, field or ""), canonicalize_value)
        return str(canonicalizer(value))
