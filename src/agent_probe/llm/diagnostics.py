"""类型化诊断。

设计约束（对应 M1 要求"协议不支持、截断和状态丢失必须可诊断"）：

* 解析器**不**用异常表达"数据不完整"这类正常流状态，而是返回诊断对象；
* 诊断是冻结值对象，带稳定枚举 ``code``，可直接在测试中断言；
* ``fatal=True`` 表示该方向已无法继续安全解析（例如 HTTP/2 preface、
  非法 chunk、头部语法错误），此时解析器进入 ``FAILED``，不再猜测字节边界；
* 任何诊断都不会包含原始正文或凭据，``detail`` 只允许写结构性描述。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - 仅用于类型标注
    from agent_probe.llm.common import Direction

__all__ = [
    "Severity",
    "DiagnosticCode",
    "Diagnostic",
    "DEFAULT_SEVERITY",
]


class Severity(str, Enum):
    """诊断严重级别。"""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class DiagnosticCode(str, Enum):
    """稳定的诊断码。

    码值属于对外契约：测试与后续里程碑的规则引擎依赖它们，**不应**重命名。
    """

    # --- 协议识别 / 起始行 ---
    HTTP2_PREFACE = "http2_preface"
    UNSUPPORTED_HTTP_VERSION = "unsupported_http_version"
    HTTP10_MESSAGE = "http10_message"
    MALFORMED_START_LINE = "malformed_start_line"
    START_LINE_TOO_LARGE = "start_line_too_large"

    # --- 头部 ---
    HEADER_SECTION_TOO_LARGE = "header_section_too_large"
    TOO_MANY_HEADERS = "too_many_headers"
    MALFORMED_HEADER = "malformed_header"
    OBSOLETE_LINE_FOLDING = "obsolete_line_folding"
    CONFLICTING_FRAMING = "conflicting_framing"
    MALFORMED_CONTENT_LENGTH = "malformed_content_length"
    UNSUPPORTED_TRANSFER_ENCODING = "unsupported_transfer_encoding"
    UNSUPPORTED_CONTENT_ENCODING = "unsupported_content_encoding"

    # --- 正文 ---
    BODY_TOO_LARGE = "body_too_large"
    DECOMPRESSED_TOO_LARGE = "decompressed_too_large"
    GZIP_DECODE_ERROR = "gzip_decode_error"
    GZIP_TRUNCATED = "gzip_truncated"
    GZIP_TRAILING_DATA = "gzip_trailing_data"
    INVALID_CHUNK_SIZE = "invalid_chunk_size"
    MALFORMED_CHUNK = "malformed_chunk"
    CHUNK_LINE_TOO_LARGE = "chunk_line_too_large"
    TRAILER_TOO_LARGE = "trailer_too_large"
    BODY_FRAMING_AMBIGUOUS = "body_framing_ambiguous"
    CONNECT_TUNNEL_UNSUPPORTED = "connect_tunnel_unsupported"

    # --- 生命周期 ---
    PREMATURE_EOF = "premature_eof"
    PARSE_FAILED = "parse_failed"
    MESSAGE_AFTER_CONNECTION_CLOSE = "message_after_connection_close"

    # --- 配对 ---
    RESPONSE_WITHOUT_REQUEST = "response_without_request"
    REQUEST_WITHOUT_RESPONSE = "request_without_response"
    DUPLICATE_PHYSICAL_REQUEST = "duplicate_physical_request"

    # --- SSE ---
    SSE_EVENT_TOO_LARGE = "sse_event_too_large"
    SSE_TRUNCATED = "sse_truncated"
    SSE_MISSING_DONE = "sse_missing_done"

    # --- usage ---
    USAGE_ABSENT = "usage_absent"
    USAGE_UNPARSEABLE = "usage_unparseable"
    USAGE_NOT_CAPTURED = "usage_not_captured"

    # --- 费用 ---
    MODEL_UNKNOWN = "model_unknown"
    MODEL_NOT_PRICED = "model_not_priced"
    CACHE_PRICE_MISSING = "cache_price_missing"
    CACHE_INCLUSION_UNKNOWN = "cache_inclusion_unknown"
    PRICE_TABLE_UNVERIFIED = "price_table_unverified"


#: 诊断码的默认严重级别；单条诊断可以在构造时覆盖。
DEFAULT_SEVERITY: dict[DiagnosticCode, Severity] = {
    DiagnosticCode.HTTP2_PREFACE: Severity.ERROR,
    DiagnosticCode.UNSUPPORTED_HTTP_VERSION: Severity.ERROR,
    DiagnosticCode.HTTP10_MESSAGE: Severity.INFO,
    DiagnosticCode.MALFORMED_START_LINE: Severity.ERROR,
    DiagnosticCode.START_LINE_TOO_LARGE: Severity.ERROR,
    DiagnosticCode.HEADER_SECTION_TOO_LARGE: Severity.ERROR,
    DiagnosticCode.TOO_MANY_HEADERS: Severity.ERROR,
    DiagnosticCode.MALFORMED_HEADER: Severity.ERROR,
    DiagnosticCode.OBSOLETE_LINE_FOLDING: Severity.WARNING,
    DiagnosticCode.CONFLICTING_FRAMING: Severity.ERROR,
    DiagnosticCode.MALFORMED_CONTENT_LENGTH: Severity.ERROR,
    DiagnosticCode.UNSUPPORTED_TRANSFER_ENCODING: Severity.ERROR,
    DiagnosticCode.UNSUPPORTED_CONTENT_ENCODING: Severity.ERROR,
    DiagnosticCode.BODY_TOO_LARGE: Severity.ERROR,
    DiagnosticCode.DECOMPRESSED_TOO_LARGE: Severity.ERROR,
    DiagnosticCode.GZIP_DECODE_ERROR: Severity.ERROR,
    DiagnosticCode.GZIP_TRUNCATED: Severity.ERROR,
    DiagnosticCode.GZIP_TRAILING_DATA: Severity.INFO,
    DiagnosticCode.INVALID_CHUNK_SIZE: Severity.ERROR,
    DiagnosticCode.MALFORMED_CHUNK: Severity.ERROR,
    DiagnosticCode.CHUNK_LINE_TOO_LARGE: Severity.ERROR,
    DiagnosticCode.TRAILER_TOO_LARGE: Severity.ERROR,
    DiagnosticCode.BODY_FRAMING_AMBIGUOUS: Severity.WARNING,
    DiagnosticCode.CONNECT_TUNNEL_UNSUPPORTED: Severity.ERROR,
    DiagnosticCode.PREMATURE_EOF: Severity.ERROR,
    DiagnosticCode.PARSE_FAILED: Severity.ERROR,
    DiagnosticCode.MESSAGE_AFTER_CONNECTION_CLOSE: Severity.WARNING,
    DiagnosticCode.RESPONSE_WITHOUT_REQUEST: Severity.WARNING,
    DiagnosticCode.REQUEST_WITHOUT_RESPONSE: Severity.WARNING,
    DiagnosticCode.DUPLICATE_PHYSICAL_REQUEST: Severity.WARNING,
    DiagnosticCode.SSE_EVENT_TOO_LARGE: Severity.ERROR,
    DiagnosticCode.SSE_TRUNCATED: Severity.ERROR,
    DiagnosticCode.SSE_MISSING_DONE: Severity.WARNING,
    DiagnosticCode.USAGE_ABSENT: Severity.WARNING,
    DiagnosticCode.USAGE_UNPARSEABLE: Severity.ERROR,
    DiagnosticCode.USAGE_NOT_CAPTURED: Severity.WARNING,
    DiagnosticCode.MODEL_UNKNOWN: Severity.WARNING,
    DiagnosticCode.MODEL_NOT_PRICED: Severity.WARNING,
    DiagnosticCode.CACHE_PRICE_MISSING: Severity.WARNING,
    DiagnosticCode.CACHE_INCLUSION_UNKNOWN: Severity.WARNING,
    DiagnosticCode.PRICE_TABLE_UNVERIFIED: Severity.INFO,
}


@dataclass(frozen=True)
class Diagnostic:
    """一条结构化诊断。

    ``detail`` 只描述结构与计数，绝不放正文片段或凭据。
    """

    code: DiagnosticCode
    detail: str
    severity: Severity = Severity.WARNING
    fatal: bool = False
    direction: Direction | None = None
    message_index: int | None = None
    stream_offset: int | None = None

    @classmethod
    def create(
        cls,
        code: DiagnosticCode,
        detail: str,
        *,
        severity: Severity | None = None,
        fatal: bool = False,
        direction: Direction | None = None,
        message_index: int | None = None,
        stream_offset: int | None = None,
    ) -> Diagnostic:
        """按诊断码的默认级别构造诊断。"""
        return cls(
            code=code,
            detail=detail,
            severity=severity if severity is not None else DEFAULT_SEVERITY.get(code, Severity.WARNING),
            fatal=fatal,
            direction=direction,
            message_index=message_index,
            stream_offset=stream_offset,
        )

    def to_record(self) -> dict[str, object]:
        """JSON 可序列化视图。"""
        return {
            "code": self.code.value,
            "severity": self.severity.value,
            "detail": self.detail,
            "fatal": self.fatal,
            "direction": None if self.direction is None else self.direction.value,
            "message_index": self.message_index,
            "stream_offset": self.stream_offset,
        }

    def __str__(self) -> str:  # pragma: no cover - 便于调试
        where = ""
        if self.direction is not None:
            where += f" dir={self.direction.value}"
        if self.message_index is not None:
            where += f" msg={self.message_index}"
        if self.stream_offset is not None:
            where += f" off={self.stream_offset}"
        flag = " fatal" if self.fatal else ""
        return f"[{self.severity.value}{flag}] {self.code.value}: {self.detail}{where}"
