"""HTTP 消息模型与默认脱敏策略。

隐私默认值（对应 plan.md 第 1 节"TLS 原文可能包含凭据与提示词，默认仅持久化
必要元数据；API key 不进入日志"）：

* 头部在**进入模型时**就已脱敏：敏感头的值被替换为占位符，原始值不保留。
* 请求目标（request target）中的敏感查询参数（``?key=`` 等）同样在入模型时
  就被替换。
* :meth:`HttpMessage.to_record` 是持久化视图，**不含**正文；即使显式请求
  正文，也只返回 SHA-256 摘要而非原文。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from agent_probe.llm.common import BodyFraming, MessageKind
from agent_probe.llm.diagnostics import Diagnostic

__all__ = [
    "REDACTED",
    "DEFAULT_SENSITIVE_HEADERS",
    "DEFAULT_SENSITIVE_SUBSTRINGS",
    "DEFAULT_SENSITIVE_VALUE_PATTERNS",
    "HeaderRedactionPolicy",
    "HttpMessage",
    "HttpRequest",
    "HttpResponse",
    "redact_target",
]

#: 敏感值的统一占位符。
REDACTED = "<redacted>"

#: 明确列出的敏感头（小写）。
DEFAULT_SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "authentication-info",
        "proxy-authentication-info",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "apikey",
        "x-auth-token",
        "x-access-token",
        "x-goog-api-key",
        "openai-api-key",
        "anthropic-api-key",
        "x-amz-security-token",
        "x-functions-key",
        "x-session-token",
    }
)

#: 头部名子串规则：宁可过度脱敏，也不泄露凭据。
DEFAULT_SENSITIVE_SUBSTRINGS: tuple[str, ...] = (
    "authorization",
    "auth",
    "api-key",
    "apikey",
    "api_key",
    "secret",
    "password",
    "passwd",
    "credential",
    "token",
    "cookie",
    "session",
)

#: 已知凭据"形状"模式。这些是**辅助**规则，不是通用秘密探测器：
#: 头名字匹配与 target 参数匹配才是主要机制。命中即脱敏（宁可过度脱敏）。
DEFAULT_SENSITIVE_VALUE_PATTERNS: tuple[str, ...] = (
    r"\bsk-[A-Za-z0-9_-]{16,}\b",
    r"\bAIza[0-9A-Za-z_-]{16,}\b",
    r"\bghp_[A-Za-z0-9]{16,}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
    r"\bAKIA[0-9A-Z]{12,}\b",
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
)

#: 请求目标中的敏感查询参数子串规则。
DEFAULT_SENSITIVE_QUERY_SUBSTRINGS: tuple[str, ...] = (
    "key",
    "token",
    "secret",
    "password",
    "credential",
    "sig",
)

_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def is_valid_header_name(name: str) -> bool:
    """RFC 7230 ``token`` 校验。"""
    return bool(name) and _TOKEN_RE.match(name) is not None


@dataclass(frozen=True)
class HeaderRedactionPolicy:
    """默认开启的脱敏策略。

    三道机制，命中任一即脱敏：

    1. ``sensitive_headers``：头名精确匹配；
    2. ``sensitive_substrings``：头名子串匹配；
    3. ``sensitive_value_patterns``：头**值**的已知凭据形状（如 ``sk-``）。

    调用方可以自定义前两项与第三项；但不能把三者都设空后再声称"默认安全"。
    """

    sensitive_headers: frozenset[str] = DEFAULT_SENSITIVE_HEADERS
    sensitive_substrings: tuple[str, ...] = DEFAULT_SENSITIVE_SUBSTRINGS
    sensitive_value_patterns: tuple[str, ...] = DEFAULT_SENSITIVE_VALUE_PATTERNS
    placeholder: str = REDACTED
    redact_target_query: bool = True
    sensitive_query_substrings: tuple[str, ...] = DEFAULT_SENSITIVE_QUERY_SUBSTRINGS
    _compiled: tuple[re.Pattern[str], ...] = field(
        default_factory=tuple, compare=False, repr=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_compiled",
            tuple(re.compile(pattern) for pattern in self.sensitive_value_patterns),
        )

    def is_sensitive(self, name: str) -> bool:
        lowered = name.strip().lower()
        if lowered in self.sensitive_headers:
            return True
        return any(token in lowered for token in self.sensitive_substrings)

    def value_looks_sensitive(self, value: str) -> bool:
        """头值是否命中已知凭据形状（辅助规则）。"""
        return any(pattern.search(value) for pattern in self._compiled)

    def is_sensitive_query(self, name: str) -> bool:
        lowered = name.strip().lower()
        return any(token in lowered for token in self.sensitive_query_substrings)

    def redact_headers(
        self, headers: tuple[tuple[str, str], ...]
    ) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]]:
        """返回 (脱敏后的头部, 被脱敏的头部名)。"""
        redacted: list[tuple[str, str]] = []
        names: list[str] = []
        for name, value in headers:
            if self.is_sensitive(name) or self.value_looks_sensitive(value):
                redacted.append((name, self.placeholder))
                lowered = name.strip().lower()
                if lowered not in names:
                    names.append(lowered)
            else:
                redacted.append((name, value))
        return tuple(redacted), tuple(names)


def redact_target(target: str, policy: HeaderRedactionPolicy) -> tuple[str, tuple[str, ...]]:
    """脱敏请求目标中的敏感查询参数。

    返回 ``(脱敏后的 target, 被脱敏的参数名)``。路径本身不改动；不做任何
    "猜测式"正则替换，只按参数名匹配。
    """
    if not policy.redact_target_query:
        return target, ()
    base, sep, query = target.partition("?")
    if not sep or not query:
        return target, ()
    fragment = ""
    if "#" in query:
        query, _, fragment = query.partition("#")
        fragment = "#" + fragment
    parts: list[str] = []
    redacted_names: list[str] = []
    for raw in query.split("&"):
        if not raw:
            continue
        name, eq, _value = raw.partition("=")
        if policy.is_sensitive_query(name):
            parts.append(f"{name}={policy.placeholder}" if eq else name)
            if name not in redacted_names:
                redacted_names.append(name)
        else:
            parts.append(raw)
    return f"{base}?{'&'.join(parts)}{fragment}", tuple(redacted_names)


@dataclass(frozen=True)
class HttpMessage:
    """一条已重建的 HTTP 消息（方向由 :class:`Http1Parser` 决定）。

    ``payload`` 是**解码后**的正文（identity 或已解压），仅存在于内存；
    它可能被上限截断，用 :attr:`payload_complete` 判断是否可用于后续 JSON
    解析。持久化请使用 :meth:`to_record`。
    """

    kind: MessageKind
    version: str
    message_index: int
    headers: tuple[tuple[str, str], ...]
    redacted_header_names: tuple[str, ...]
    body_framing: BodyFraming
    content_length: int | None
    transfer_encoding: str | None
    content_encoding: str | None
    connection_close: bool
    complete: bool
    incomplete_reason: str | None
    body_bytes: int
    payload: bytes | None
    payload_decoded: bool
    payload_truncated: bool
    stream_start_offset: int
    stream_end_offset: int
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)

    # ---- 访问器 ----

    def header_values(self, name: str) -> tuple[str, ...]:
        """大小写不敏感地取同名头的全部值。"""
        lowered = name.lower()
        return tuple(value for key, value in self.headers if key.lower() == lowered)

    def header(self, name: str) -> str | None:
        """取第一个同名头的值（敏感头返回占位符）。"""
        values = self.header_values(name)
        return values[0] if values else None

    @property
    def payload_complete(self) -> bool:
        """正文是否完整可用（消息分帧完整、未截断、未解码失败）。"""
        return (
            self.complete
            and self.payload is not None
            and self.payload_decoded
            and not self.payload_truncated
        )

    @property
    def content_type(self) -> str | None:
        raw = self.header("content-type")
        if raw is None:
            return None
        return raw.split(";", 1)[0].strip().lower() or None

    def has_diagnostic(self, code: object) -> bool:
        return any(d.code == code for d in self.diagnostics)

    # ---- 持久化 ----

    def to_record(self, *, include_payload_hash: bool = False) -> dict[str, object]:
        """默认持久化视图：不含正文、不含凭据。"""
        record: dict[str, object] = {
            "kind": self.kind.value,
            "version": self.version,
            "message_index": self.message_index,
            "headers": [[name, value] for name, value in self.headers],
            "redacted_header_names": list(self.redacted_header_names),
            "body_framing": self.body_framing.value,
            "content_length": self.content_length,
            "transfer_encoding": self.transfer_encoding,
            "content_encoding": self.content_encoding,
            "connection_close": self.connection_close,
            "complete": self.complete,
            "incomplete_reason": self.incomplete_reason,
            "body_bytes": self.body_bytes,
            "payload_available": self.payload is not None,
            "payload_decoded": self.payload_decoded,
            "payload_truncated": self.payload_truncated,
            "payload_length": None if self.payload is None else len(self.payload),
            "stream_start_offset": self.stream_start_offset,
            "stream_end_offset": self.stream_end_offset,
            "diagnostics": [d.to_record() for d in self.diagnostics],
        }
        if include_payload_hash:
            record["payload_sha256"] = (
                None if self.payload is None else hashlib.sha256(self.payload).hexdigest()
            )
        return record


@dataclass(frozen=True)
class HttpRequest(HttpMessage):
    """HTTP 请求。``target`` 已按策略脱敏。"""

    method: str = ""
    target: str = ""
    redacted_query_params: tuple[str, ...] = ()

    @property
    def target_redacted(self) -> bool:
        return bool(self.redacted_query_params)

    def to_record(self, *, include_payload_hash: bool = False) -> dict[str, object]:
        record = super().to_record(include_payload_hash=include_payload_hash)
        record["method"] = self.method
        record["target"] = self.target
        record["redacted_query_params"] = list(self.redacted_query_params)
        return record


@dataclass(frozen=True)
class HttpResponse(HttpMessage):
    """HTTP 响应。``request_method`` 在能确定时给出（用于 HEAD / CONNECT 语义）。"""

    status_code: int = 0
    reason_phrase: str = ""
    request_method: str | None = None
    is_informational: bool = False

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    def to_record(self, *, include_payload_hash: bool = False) -> dict[str, object]:
        record = super().to_record(include_payload_hash=include_payload_hash)
        record["status_code"] = self.status_code
        record["reason_phrase"] = self.reason_phrase
        record["request_method"] = self.request_method
        record["is_informational"] = self.is_informational
        return record
