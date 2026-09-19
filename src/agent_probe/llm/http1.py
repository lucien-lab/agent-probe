"""HTTP/1.1 有界增量解析器。

设计要点
--------

* **增量**：``feed(direction_bytes)`` 可以按任意分片调用（包括逐字节），解析器
  内部只保留未完成消息的缓冲；产出严格按"消息边界"发生。
* **连接复用**：一条消息结束后立即在同一缓冲区继续解析下一条消息，因此一个
  连接上的多次请求/响应会连续、按序产出。
* **有界**：头部、正文、解压结果、chunk 行、trailer、缓冲全部有上限。超限产出
  诊断；正文超限时**继续消费字节以保持分帧对齐**，只是不再缓冲（payload 标记
  截断），不会把截断内容伪装成完整消息。
* **不伪造**：任何解析失败都产出 ``complete=False`` 的消息与致命诊断，或干脆
  不产出消息。解析器绝不猜测字节边界（非法 chunk、非法头部即进入 ``FAILED``）。
* **限定 HTTP/1.1**：``HTTP/1.0`` 容忍但标注；HTTP/2 连接前言、
  ``Transfer-Encoding`` 非 ``chunked``、``Content-Encoding: br/deflate`` 等
  显式标记为不支持。

状态机
------

``START`` → 读取「起始行 + 头部块」（以空行结束）。
随后按分帧方式进入 ``FIXED_BODY`` / ``CHUNK_SIZE`` / ``EOF_BODY``，chunked 依次
经过 ``CHUNK_SIZE → CHUNK_DATA → CHUNK_DATA_CRLF → (CHUNK_TRAILER)``。
消息结束回到 ``START``。任何致命错误进入 ``FAILED``（此后 ``feed`` 不再产出，
``failed``/``failure`` 提供原因）。
"""

from __future__ import annotations

import zlib
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agent_probe.llm.common import BodyFraming, Direction, MessageKind
from agent_probe.llm.diagnostics import Diagnostic, DiagnosticCode, Severity
from agent_probe.llm.limits import ParserLimits
from agent_probe.llm.messages import (
    HeaderRedactionPolicy,
    HttpMessage,
    HttpRequest,
    HttpResponse,
    is_valid_header_name,
    redact_target,
)

__all__ = [
    "HTTP2_CONNECTION_PREFACE",
    "ParserState",
    "ParseBatch",
    "Http1Parser",
]

#: RFC 9113 §3.4 的 HTTP/2 连接前言。
HTTP2_CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_GZIP_ENCODINGS = frozenset({"gzip", "x-gzip"})
_IDENTITY_ENCODINGS = frozenset({"", "identity"})
_SUPPORTED_VERSIONS = frozenset({"HTTP/1.0", "HTTP/1.1"})
_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")



class ParserState(str, Enum):
    """解析器状态。"""

    START = "start"
    FIXED_BODY = "fixed_body"
    CHUNK_SIZE = "chunk_size"
    CHUNK_DATA = "chunk_data"
    CHUNK_DATA_CRLF = "chunk_data_crlf"
    CHUNK_TRAILER = "chunk_trailer"
    EOF_BODY = "eof_body"
    FAILED = "failed"


#: 需要逐字节推进的正文分帧状态。
_CHUNK_STATES = frozenset(
    {
        ParserState.CHUNK_SIZE,
        ParserState.CHUNK_DATA,
        ParserState.CHUNK_DATA_CRLF,
        ParserState.CHUNK_TRAILER,
    }
)


@dataclass(frozen=True)
class ParseBatch:
    """一次 ``feed``/``finish`` 的产出。"""

    messages: tuple[HttpMessage, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()

    def __bool__(self) -> bool:  # pragma: no cover - 便捷判断
        return bool(self.messages or self.diagnostics)


@dataclass
class _PendingMessage:
    """当前正在重建的消息的可变草稿。"""

    start_offset: int = 0
    version: str = ""
    method: str | None = None
    target: str = ""
    redacted_query_params: tuple[str, ...] = ()
    status_code: int | None = None
    reason_phrase: str = ""
    request_method: str | None = None
    is_informational: bool = False
    start_line_parsed: bool = False
    headers: list[tuple[str, str]] = field(default_factory=list)
    content_length: int | None = None
    transfer_encoding: str | None = None
    content_encoding: str | None = None
    decode_unsupported: bool = False
    connection_close: bool = False
    body_framing: BodyFraming = BodyFraming.NONE
    remaining: int = 0
    body_bytes: int = 0
    raw_body: bytearray = field(default_factory=bytearray)
    decoded: bytearray = field(default_factory=bytearray)
    decoder: Any | None = None
    body_truncated: bool = False
    decode_truncated: bool = False
    decode_error: bool = False
    body_limit_reported: bool = False
    trailer_bytes: int = 0
    diagnostics: list[Diagnostic] = field(default_factory=list)


class Http1Parser:
    """单方向 HTTP/1.1 增量解析器。

    ``direction`` 决定起始行语法（请求行 / 状态行）与正文分帧默认值
    （请求没有 close-delimited 正文，响应有）。
    """

    def __init__(
        self,
        direction: Direction,
        *,
        limits: ParserLimits | None = None,
        redaction: HeaderRedactionPolicy | None = None,
    ) -> None:
        self._direction = direction
        self._limits = limits if limits is not None else ParserLimits()
        self._redaction = redaction if redaction is not None else HeaderRedactionPolicy()

        self._buf = bytearray()
        self._state = ParserState.START
        self._total_consumed = 0
        self._messages_completed = 0
        self._header_scan = 0
        self._pending: _PendingMessage | None = None
        self._failure: Diagnostic | None = None
        self._finished = False
        self._closing = False
        self._close_warned = False
        self._pending_methods: deque[str] = deque(maxlen=self._limits.max_pending_requests)
        self._dropped_request_contexts = 0
        self._batch_messages: list[HttpMessage] = []
        self._batch_diagnostics: list[Diagnostic] = []

    # ------------------------------------------------------------------
    # 公开 API
    # ------------------------------------------------------------------

    @property
    def direction(self) -> Direction:
        return self._direction

    @property
    def state(self) -> ParserState:
        return self._state

    @property
    def failed(self) -> bool:
        return self._failure is not None

    @property
    def failure(self) -> Diagnostic | None:
        return self._failure

    @property
    def finished(self) -> bool:
        return self._finished

    @property
    def messages_completed(self) -> int:
        """已产出的消息数（即下一条消息的物理序号 - 1）。"""
        return self._messages_completed

    @property
    def expects_close(self) -> bool:
        """最近一条消息是否声明了 ``Connection: close``。"""
        return self._closing

    @property
    def buffered_bytes(self) -> int:
        return len(self._buf)

    @property
    def dropped_request_contexts(self) -> int:
        """因超过 ``max_pending_requests`` 被丢弃的请求上下文数量。"""
        return self._dropped_request_contexts

    def register_request(self, method: str) -> None:
        """登记一个已捕获请求的方法，供响应方向判定 HEAD/CONNECT 语义。

        必须与请求方向的产出**同序**调用（``ConnectionReconstructor`` 负责）。
        队列有界；超限丢弃最旧项并计入 :attr:`dropped_request_contexts`。
        """
        if len(self._pending_methods) == self._pending_methods.maxlen:
            self._dropped_request_contexts += 1
        self._pending_methods.append(method.upper())

    def feed(self, data: bytes | bytearray | memoryview) -> ParseBatch:
        """喂入任意分片，返回本次可确定产出的消息与诊断。"""
        if isinstance(data, memoryview):
            data = data.tobytes()
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"data 必须是 bytes-like，得到 {type(data).__name__}")
        if self._finished:
            raise RuntimeError("解析器已 finish，不能继续 feed")

        self._batch_messages = []
        self._batch_diagnostics = []
        if self._state is ParserState.FAILED:
            # 已无法安全重同步：丢弃字节，不再重复产出致命诊断。
            return ParseBatch()
        self._buf += bytes(data)
        self._run(eof=False)
        return ParseBatch(tuple(self._batch_messages), tuple(self._batch_diagnostics))

    def finish(self) -> ParseBatch:
        """声明该方向字节流结束（连接关闭）。

        close-delimited 响应在此完成；其余状态下产出「提前 EOF」诊断与
        ``complete=False`` 的消息。可安全重复调用（第二次返回空批次）。
        """
        if self._finished:
            return ParseBatch()
        self._finished = True
        self._batch_messages = []
        self._batch_diagnostics = []
        if self._state is not ParserState.FAILED:
            self._run(eof=True)
        return ParseBatch(tuple(self._batch_messages), tuple(self._batch_diagnostics))

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------

    def _consume(self, count: int) -> None:
        del self._buf[:count]
        self._total_consumed += count

    def _diag(
        self,
        code: DiagnosticCode,
        detail: str,
        *,
        severity: Severity | None = None,
        fatal: bool = False,
    ) -> Diagnostic:
        diagnostic = Diagnostic.create(
            code,
            detail,
            severity=severity,
            fatal=fatal,
            direction=self._direction,
            message_index=self._messages_completed + 1,
            stream_offset=self._total_consumed,
        )
        self._batch_diagnostics.append(diagnostic)
        if self._pending is not None:
            self._pending.diagnostics.append(diagnostic)
        return diagnostic

    def _fail(
        self,
        code: DiagnosticCode,
        detail: str,
        *,
        emit_message: bool = True,
        severity: Severity | None = None,
    ) -> None:
        """致命错误：可选地产出 ``complete=False`` 的部分消息，然后进入 FAILED。"""
        diagnostic = self._diag(code, detail, severity=severity, fatal=True)
        if emit_message and self._pending is not None and self._pending.start_line_parsed:
            message = self._build_message(complete=False, incomplete_reason=code.value)
            self._messages_completed += 1
            self._batch_messages.append(message)
        self._failure = diagnostic
        self._state = ParserState.FAILED
        self._pending = None
        self._buf.clear()

    def _find_header_end(self) -> tuple[int | None, int]:
        """定位起始行+头部块的终止符，返回 ``(块末索引, 终止符长度)``。"""
        start = self._header_scan
        crlf = self._buf.find(b"\r\n\r\n", start)
        lf = self._buf.find(b"\n\n", start)
        candidates = [index for index in (crlf, lf) if index != -1]
        if not candidates:
            self._header_scan = max(0, len(self._buf) - 3)
            return None, 0
        index = min(candidates)
        separator_length = 4 if index == crlf else 2
        self._header_scan = 0
        return index, separator_length

    def _find_line(self) -> tuple[bytes, int] | None:
        """取一行（含终止符在内一起消费），支持 CRLF 与裸 LF。"""
        index = self._buf.find(b"\n")
        if index == -1:
            return None
        if index > 0 and self._buf[index - 1] == 0x0D:
            return bytes(self._buf[: index - 1]), index + 1
        return bytes(self._buf[:index]), index + 1

    def _skip_empty_lines(self) -> None:
        while True:
            if self._buf.startswith(b"\r\n"):
                self._consume(2)
            elif self._buf.startswith(b"\n"):
                self._consume(1)
            else:
                return

    # ------------------------------------------------------------------
    # 主循环
    # ------------------------------------------------------------------

    def _run(self, *, eof: bool) -> None:
        while True:
            state = self._state
            if state is ParserState.FAILED:
                return
            if state is ParserState.START:
                if not self._advance_head(eof=eof):
                    return
            elif state is ParserState.EOF_BODY:
                if not self._advance_eof_body(eof=eof):
                    return
            elif state is ParserState.FIXED_BODY:
                if not self._advance_fixed_body():
                    if eof:
                        self._premature_eof()
                    return
            elif state in _CHUNK_STATES:
                if state is ParserState.CHUNK_SIZE:
                    progressed = self._advance_chunk_size()
                elif state is ParserState.CHUNK_DATA:
                    progressed = self._advance_chunk_data()
                elif state is ParserState.CHUNK_DATA_CRLF:
                    progressed = self._advance_chunk_data_crlf()
                else:
                    progressed = self._advance_chunk_trailer()
                if not progressed:
                    if eof:
                        self._premature_eof()
                    return
            else:  # pragma: no cover - 枚举已穷尽
                return

    def _premature_eof(self) -> None:
        """连接在正文结束前关闭：产出诊断 + ``complete=False`` 的消息。"""
        pending = self._pending
        detail = "连接在正文结束前关闭（分帧未完成）"
        if pending is not None and pending.body_framing is BodyFraming.CONTENT_LENGTH:
            detail = f"连接在正文结束前关闭：仍缺 {pending.remaining} 字节"
        self._diag(DiagnosticCode.PREMATURE_EOF, detail)
        self._finalize(truncated=True, reason=DiagnosticCode.PREMATURE_EOF.value)

    def _advance_head(self, *, eof: bool) -> bool:
        # 0 偏移处检测 HTTP/2 前言（必须在跳过空行之前）。
        if self._total_consumed == 0 and self._buf:
            length = min(len(self._buf), len(HTTP2_CONNECTION_PREFACE))
            if bytes(self._buf[:length]) == HTTP2_CONNECTION_PREFACE[:length]:
                if len(self._buf) < len(HTTP2_CONNECTION_PREFACE):
                    return False  # 等待更多字节以确认
                self._fail(
                    DiagnosticCode.HTTP2_PREFACE,
                    "检测到 HTTP/2 连接前言；本里程碑只支持 HTTP/1.1",
                    emit_message=False,
                )
                return False

        self._skip_empty_lines()
        if not self._buf:
            return False

        if self._closing and not self._close_warned:
            self._close_warned = True
            self._diag(
                DiagnosticCode.MESSAGE_AFTER_CONNECTION_CLOSE,
                "上一条消息声明 Connection: close，之后仍出现新消息",
            )

        index, separator_length = self._find_header_end()
        start_offset = self._total_consumed
        if index is not None and index > self._limits.max_header_bytes:
            self._fail(
                DiagnosticCode.HEADER_SECTION_TOO_LARGE,
                f"头部块 {index} 字节超过上限 {self._limits.max_header_bytes}",
                emit_message=False,
            )
            return False
        if index is None:
            if not eof:
                if len(self._buf) > self._limits.max_header_bytes:
                    self._fail(
                        DiagnosticCode.HEADER_SECTION_TOO_LARGE,
                        f"头部块超过上限 {self._limits.max_header_bytes} 字节",
                        emit_message=False,
                    )
                return False
            # EOF：把剩余字节当作未终止的头部块，产出部分消息。
            block = bytes(self._buf)
            self._consume(len(self._buf))
            self._begin_message(start_offset)
            self._parse_head(block, terminated=False)
            if self._state is ParserState.FAILED or self._pending is None:
                return False
            self._diag(
                DiagnosticCode.PREMATURE_EOF,
                "连接在头部块结束前关闭（起始行/头部可能不完整）",
            )
            self._finalize(truncated=True, reason=DiagnosticCode.PREMATURE_EOF.value)
            return False

        block = bytes(self._buf[:index])
        self._consume(index + separator_length)
        self._begin_message(start_offset)
        self._parse_head(block, terminated=True)
        if self._state is ParserState.FAILED:
            return False
        # 头部解析完成：可能已进入某个正文字段状态，也可能零正文立即结束。
        return True

    def _begin_message(self, start_offset: int) -> None:
        self._pending = _PendingMessage(start_offset=start_offset)

    # ------------------------------------------------------------------
    # 起始行 + 头部
    # ------------------------------------------------------------------

    def _parse_head(self, block: bytes, *, terminated: bool) -> None:
        pending = self._pending
        assert pending is not None

        lines = block.split(b"\n")
        first = lines[0]
        if first.endswith(b"\r"):
            first = first[:-1]
        if len(first) > self._limits.max_start_line_bytes:
            self._fail(
                DiagnosticCode.START_LINE_TOO_LARGE,
                f"起始行超过上限 {self._limits.max_start_line_bytes} 字节",
                emit_message=False,
            )
            return
        if not first.strip():
            self._fail(DiagnosticCode.MALFORMED_START_LINE, "起始行为空", emit_message=False)
            return

        if self._direction.is_request_direction:
            if not self._parse_request_line(first):
                return
        else:
            if not self._parse_status_line(first):
                return
        pending.start_line_parsed = True

        raw_headers: list[tuple[str, str]] = []
        for raw in lines[1:]:
            line = raw[:-1] if raw.endswith(b"\r") else raw
            if not line:
                continue
            if line[:1] in (b" ", b"\t"):
                if not raw_headers:
                    self._fail(
                        DiagnosticCode.MALFORMED_HEADER,
                        "首个头部行以空白开头（缺少被折行的头部）",
                    )
                    return
                name, value = raw_headers[-1]
                raw_headers[-1] = (name, f"{value} {line.strip().decode('latin-1')}")
                self._diag(DiagnosticCode.OBSOLETE_LINE_FOLDING, f"头部 {name} 使用了废弃的折行语法")
                continue
            colon = line.find(b":")
            if colon <= 0:
                self._fail(
                    DiagnosticCode.MALFORMED_HEADER,
                    "头部行缺少冒号分隔符",
                )
                return
            name = line[:colon].strip().decode("latin-1")
            value = line[colon + 1 :].strip(b" \t").decode("latin-1")
            if not is_valid_header_name(name):
                self._fail(
                    DiagnosticCode.MALFORMED_HEADER,
                    "头部名不是合法 token",
                )
                return
            raw_headers.append((name, value))

        if len(raw_headers) > self._limits.max_headers:
            self._fail(
                DiagnosticCode.TOO_MANY_HEADERS,
                f"头部条目数 {len(raw_headers)} 超过上限 {self._limits.max_headers}",
            )
            return

        pending.headers = raw_headers
        if not terminated:
            return
        self._plan_body()

    def _check_version(self, version: bytes) -> str | None:
        text = version.decode("latin-1")
        if text not in _SUPPORTED_VERSIONS:
            self._fail(
                DiagnosticCode.UNSUPPORTED_HTTP_VERSION,
                f"不支持的协议版本 {text!r}（仅支持 HTTP/1.1；HTTP/1.0 容忍并标注）",
                emit_message=False,
            )
            return None
        if text == "HTTP/1.0":
            self._diag(DiagnosticCode.HTTP10_MESSAGE, "HTTP/1.0 消息（容忍解析，连接语义按 1.0 处理）")
        return text

    def _parse_request_line(self, line: bytes) -> bool:
        parts = line.split(b" ")
        if len(parts) != 3 or not all(parts):
            self._fail(
                DiagnosticCode.MALFORMED_START_LINE,
                "请求行不是 'method SP target SP version' 三段式",
                emit_message=False,
            )
            return False
        pending = self._pending
        assert pending is not None
        method_text = parts[0].decode("latin-1")
        if not is_valid_header_name(method_text):
            self._fail(DiagnosticCode.MALFORMED_START_LINE, "请求方法不是合法 token", emit_message=False)
            return False
        version = self._check_version(parts[2])
        if version is None:
            return False
        target_text = parts[1].decode("latin-1")
        redacted_target, redacted_params = redact_target(target_text, self._redaction)
        pending.method = method_text.upper()
        pending.target = redacted_target
        pending.redacted_query_params = redacted_params
        pending.version = version
        return True

    def _parse_status_line(self, line: bytes) -> bool:
        parts = line.split(b" ", 2)
        if len(parts) < 2:
            self._fail(
                DiagnosticCode.MALFORMED_START_LINE,
                "状态行缺少状态码",
                emit_message=False,
            )
            return False
        version = self._check_version(parts[0])
        if version is None:
            return False
        status_text = parts[1]
        if len(status_text) != 3 or not status_text.isdigit():
            self._fail(
                DiagnosticCode.MALFORMED_START_LINE,
                "状态码不是三位数字",
                emit_message=False,
            )
            return False
        pending = self._pending
        assert pending is not None
        pending.version = version
        pending.status_code = int(status_text)
        pending.reason_phrase = parts[2].decode("latin-1") if len(parts) == 3 else ""
        pending.is_informational = 100 <= pending.status_code < 200
        if not pending.is_informational:
            if self._pending_methods:
                pending.request_method = self._pending_methods.popleft()
        return True

    # ------------------------------------------------------------------
    # 分帧判定
    # ------------------------------------------------------------------

    def _plan_body(self) -> None:
        pending = self._pending
        assert pending is not None

        headers = tuple(pending.headers)

        def values(name: str) -> list[str]:
            lowered = name.lower()
            return [value for key, value in headers if key.lower() == lowered]

        # --- Content-Encoding ---
        codings: list[str] = []
        for raw in values("content-encoding"):
            codings.extend(part.strip().lower() for part in raw.split(",") if part.strip())
        if codings:
            pending.content_encoding = codings[-1]
            if pending.content_encoding in _IDENTITY_ENCODINGS:
                pass
            elif pending.content_encoding in _GZIP_ENCODINGS:
                pending.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            else:
                pending.decode_unsupported = True
                self._diag(
                    DiagnosticCode.UNSUPPORTED_CONTENT_ENCODING,
                    f"不支持的 Content-Encoding {pending.content_encoding!r}（仅支持 gzip/identity）",
                )

        # --- Transfer-Encoding ---
        transfer_codings: list[str] = []
        for raw in values("transfer-encoding"):
            transfer_codings.extend(part.strip().lower() for part in raw.split(",") if part.strip())
        chunked = False
        if transfer_codings:
            pending.transfer_encoding = ", ".join(transfer_codings)
            if transfer_codings[-1] == "chunked":
                chunked = True
                other_codings = [
                    coding for coding in transfer_codings[:-1] if coding != "identity"
                ]
            elif "chunked" in transfer_codings:
                self._fail(
                    DiagnosticCode.UNSUPPORTED_TRANSFER_ENCODING,
                    "chunked 不是最后一个 transfer-coding，无法确定分帧",
                )
                return
            else:
                other_codings = [coding for coding in transfer_codings if coding != "identity"]
            if other_codings:
                pending.decode_unsupported = True
                self._diag(
                    DiagnosticCode.UNSUPPORTED_TRANSFER_ENCODING,
                    "不支持的 transfer-coding "
                    f"{', '.join(other_codings)!r}（仅支持 chunked/identity）；正文标记为不可用",
                )

        # --- Content-Length ---
        length_values: list[str] = []
        for raw in values("content-length"):
            length_values.extend(part.strip() for part in raw.split(",") if part.strip())
        if length_values:
            parsed: set[int] = set()
            for text in length_values:
                if not text.isdigit():
                    self._fail(
                        DiagnosticCode.MALFORMED_CONTENT_LENGTH,
                        "Content-Length 不是非负整数",
                        emit_message=False,
                    )
                    return
                parsed.add(int(text))
            if len(parsed) != 1:
                self._fail(
                    DiagnosticCode.MALFORMED_CONTENT_LENGTH,
                    "多个 Content-Length 取值不一致",
                    emit_message=False,
                )
                return
            pending.content_length = parsed.pop()

        if chunked and pending.content_length is not None:
            self._diag(
                DiagnosticCode.CONFLICTING_FRAMING,
                "同时出现 Transfer-Encoding: chunked 与 Content-Length；按 RFC 9112 以 chunked 为准",
            )

        # --- Connection ---
        close = False
        keep_alive = False
        for raw in values("connection"):
            for token in raw.split(","):
                token = token.strip().lower()
                if token == "close":
                    close = True
                elif token == "keep-alive":
                    keep_alive = True
        if pending.version == "HTTP/1.0" and not keep_alive:
            close = True
        pending.connection_close = close

        # --- 正文分帧 ---
        if self._direction.is_request_direction:
            no_body = not chunked and pending.content_length is None
            if no_body:
                pending.body_framing = BodyFraming.NONE
                self._finalize(truncated=False, reason=None)
                return
        else:
            status = pending.status_code or 0
            method = pending.request_method
            no_body = status < 200 or status in (204, 304) or method == "HEAD"
            if no_body:
                pending.body_framing = BodyFraming.NONE
                self._finalize(truncated=False, reason=None)
                return
            if method == "CONNECT" and 200 <= status < 300:
                pending.body_framing = BodyFraming.NONE
                self._diag(
                    DiagnosticCode.CONNECT_TUNNEL_UNSUPPORTED,
                    "CONNECT 隧道响应：后续字节不再是 HTTP，停止解析该方向",
                )
                self._finalize(truncated=False, reason=None)
                self._state = ParserState.FAILED
                self._failure = self._batch_diagnostics[-1]
                self._buf.clear()
                return

        if chunked:
            pending.body_framing = BodyFraming.CHUNKED
            self._state = ParserState.CHUNK_SIZE
            return
        if pending.content_length is not None:
            pending.body_framing = BodyFraming.CONTENT_LENGTH
            pending.remaining = pending.content_length
            self._state = ParserState.FIXED_BODY
            return
        # 既无 Content-Length 也无 chunked：仅响应可以 close-delimited。
        pending.body_framing = BodyFraming.CLOSE_DELIMITED
        if not pending.connection_close and pending.request_method is None:
            self._diag(
                DiagnosticCode.BODY_FRAMING_AMBIGUOUS,
                "响应既无 Content-Length 也无 chunked 且未捕获对应请求方法；正文按连接关闭界定，"
                "若连接被复用将无法正确定位下一条消息",
            )
        self._state = ParserState.EOF_BODY

    # ------------------------------------------------------------------
    # 正文推进
    # ------------------------------------------------------------------

    def _append_body(self, data: bytes) -> None:
        pending = self._pending
        assert pending is not None
        pending.body_bytes += len(data)
        self._feed_decoder(data)
        # 原始正文超限时立刻"转诊断"：继续消费但不缓冲（不伪装成完整正文）。
        if pending.body_truncated:
            return
        if len(pending.raw_body) + len(data) > self._limits.max_body_bytes:
            allowance = max(0, self._limits.max_body_bytes - len(pending.raw_body))
            if allowance:
                pending.raw_body.extend(data[:allowance])
            pending.body_truncated = True
            if not pending.body_limit_reported:
                pending.body_limit_reported = True
                self._diag(
                    DiagnosticCode.BODY_TOO_LARGE,
                    f"原始正文超过上限 {self._limits.max_body_bytes} 字节；继续消费但不再缓冲",
                )
            return
        pending.raw_body.extend(data)

    def _feed_decoder(self, data: bytes) -> None:
        pending = self._pending
        assert pending is not None
        decoder = pending.decoder
        if decoder is None or pending.decode_error or pending.decode_truncated:
            return
        allowance = max(0, self._limits.max_decompressed_bytes - len(pending.decoded))
        try:
            output = decoder.decompress(data, allowance + 1)
        except zlib.error as exc:
            pending.decode_error = True
            self._diag(
                DiagnosticCode.GZIP_DECODE_ERROR,
                f"gzip 解压失败（{type(exc).__name__}）；payload 保留解压前的已得部分并标记截断",
            )
            return
        if len(output) > allowance:
            pending.decoded.extend(output[:allowance])
            pending.decode_truncated = True
            self._diag(
                DiagnosticCode.DECOMPRESSED_TOO_LARGE,
                f"解压后正文超过上限 {self._limits.max_decompressed_bytes} 字节；停止解压",
            )
            return
        pending.decoded.extend(output)
        if decoder.unconsumed_tail:
            pending.decode_truncated = True
            self._diag(
                DiagnosticCode.DECOMPRESSED_TOO_LARGE,
                f"解压后正文超过上限 {self._limits.max_decompressed_bytes} 字节；停止解压",
            )

    def _finish_decoder(self) -> None:
        pending = self._pending
        assert pending is not None
        decoder = pending.decoder
        if decoder is None or pending.decode_error or pending.decode_truncated:
            return
        allowance = max(0, self._limits.max_decompressed_bytes - len(pending.decoded))
        try:
            output = decoder.flush()
        except zlib.error:
            pending.decode_error = True
            self._diag(DiagnosticCode.GZIP_DECODE_ERROR, "gzip 收尾失败")
            return
        if len(output) > allowance:
            pending.decoded.extend(output[:allowance])
            pending.decode_truncated = True
            self._diag(DiagnosticCode.DECOMPRESSED_TOO_LARGE, "解压后正文在收尾阶段超过上限")
            return
        pending.decoded.extend(output)
        if not decoder.eof:
            pending.decode_truncated = True
            self._diag(
                DiagnosticCode.GZIP_TRUNCATED,
                "gzip 流在正文结束时仍未结束（截断或非单成员 gzip）",
            )
        elif decoder.unused_data:
            self._diag(DiagnosticCode.GZIP_TRAILING_DATA, "gzip 流结束后仍有额外字节（未解析）")

    def _advance_fixed_body(self) -> bool:
        pending = self._pending
        assert pending is not None
        if self._buf:
            take = min(pending.remaining, len(self._buf))
            self._append_body(bytes(self._buf[:take]))
            self._consume(take)
            pending.remaining -= take
        if pending.remaining == 0:
            self._finalize(truncated=False, reason=None)
            return True
        return False

    def _advance_chunk_size(self) -> bool:
        pending = self._pending
        assert pending is not None
        line = self._find_line()
        if line is None:
            if len(self._buf) > self._limits.max_chunk_line_bytes:
                self._fail(
                    DiagnosticCode.CHUNK_LINE_TOO_LARGE,
                    f"chunk-size 行超过上限 {self._limits.max_chunk_line_bytes} 字节",
                )
            return False
        raw, consumed = line
        self._consume(consumed)
        if len(raw) > self._limits.max_chunk_line_bytes:
            self._fail(
                DiagnosticCode.CHUNK_LINE_TOO_LARGE,
                f"chunk-size 行 {len(raw)} 字节超过上限 {self._limits.max_chunk_line_bytes}",
            )
            return False
        size_text = raw.split(b";", 1)[0].strip()
        if not size_text or any(byte not in _HEX_DIGITS for byte in size_text):
            self._fail(
                DiagnosticCode.INVALID_CHUNK_SIZE,
                "chunk-size 不是十六进制数",
            )
            return False
        size = int(size_text, 16)
        if size == 0:
            pending.remaining = 0
            self._state = ParserState.CHUNK_TRAILER
            return True
        if size > self._limits.max_body_bytes or pending.body_truncated:
            pending.body_truncated = True
            if not pending.body_limit_reported:
                pending.body_limit_reported = True
                self._diag(
                    DiagnosticCode.BODY_TOO_LARGE,
                    f"chunk 大小 {size} 超过单条正文上限 {self._limits.max_body_bytes} 字节；继续消费但不缓冲",
                )
        pending.remaining = size
        self._state = ParserState.CHUNK_DATA
        return True

    def _advance_chunk_data(self) -> bool:
        pending = self._pending
        assert pending is not None
        if self._buf:
            take = min(pending.remaining, len(self._buf))
            self._append_body(bytes(self._buf[:take]))
            self._consume(take)
            pending.remaining -= take
        if pending.remaining == 0:
            self._state = ParserState.CHUNK_DATA_CRLF
            return True
        return False

    def _advance_chunk_data_crlf(self) -> bool:
        if not self._buf:
            return False
        if self._buf == b"\r":
            return False  # 可能是被拆开的 CRLF，等待更多字节
        if self._buf.startswith(b"\r\n"):
            self._consume(2)
            self._state = ParserState.CHUNK_SIZE
            return True
        if self._buf.startswith(b"\n"):
            self._consume(1)
            self._diag(DiagnosticCode.MALFORMED_CHUNK, "chunk 数据后使用裸 LF 终止（容忍）")
            self._state = ParserState.CHUNK_SIZE
            return True
        self._fail(
            DiagnosticCode.MALFORMED_CHUNK,
            "chunk 数据后缺少 CRLF 终止符",
        )
        return False

    def _advance_chunk_trailer(self) -> bool:
        pending = self._pending
        assert pending is not None
        line = self._find_line()
        if line is None:
            if len(self._buf) > self._limits.max_trailer_bytes:
                self._fail(
                    DiagnosticCode.TRAILER_TOO_LARGE,
                    f"trailer 超过上限 {self._limits.max_trailer_bytes} 字节",
                )
            return False
        raw, consumed = line
        self._consume(consumed)
        pending.trailer_bytes += consumed
        if not raw:
            self._finalize(truncated=False, reason=None)
            return True
        if pending.trailer_bytes > self._limits.max_trailer_bytes:
            self._fail(
                DiagnosticCode.TRAILER_TOO_LARGE,
                f"trailer 累计 {pending.trailer_bytes} 字节超过上限 "
                f"{self._limits.max_trailer_bytes}",
            )
            return False
        if not raw.strip():
            return True
        # trailer 字段本身不参与 usage 提取，只做语法容忍与长度限制。
        if b":" not in raw:
            self._diag(DiagnosticCode.MALFORMED_CHUNK, "trailer 行缺少冒号分隔符")
        if len(raw) > self._limits.max_header_bytes:
            self._fail(DiagnosticCode.TRAILER_TOO_LARGE, "单条 trailer 行超过上限")
            return False
        return True

    def _advance_eof_body(self, *, eof: bool) -> bool:
        pending = self._pending
        assert pending is not None
        if self._buf:
            self._append_body(bytes(self._buf))
            self._consume(len(self._buf))
        if eof:
            self._finalize(truncated=False, reason=None)
            return False
        return False

    # ------------------------------------------------------------------
    # 收尾
    # ------------------------------------------------------------------

    def _payload_snapshot(self) -> tuple[bytes | None, bool, bool]:
        pending = self._pending
        assert pending is not None
        if pending.decode_unsupported:
            return None, False, False
        if pending.decoder is not None:
            if pending.decode_error:
                return bytes(pending.decoded), True, True
            return bytes(pending.decoded), True, pending.decode_truncated
        return bytes(pending.raw_body), True, pending.body_truncated

    def _build_message(self, *, complete: bool, incomplete_reason: str | None) -> HttpMessage:
        pending = self._pending
        assert pending is not None
        headers, redacted_names = self._redaction.redact_headers(tuple(pending.headers))
        payload, payload_decoded, payload_truncated = self._payload_snapshot()
        if not complete and pending.body_framing is BodyFraming.NONE:
            # 分帧方式未知（头部语法错误等）：不声称正文为空，而是"未知"。
            payload, payload_decoded, payload_truncated = None, False, False
        common = {
            "version": pending.version,
            "message_index": self._messages_completed + 1,
            "headers": headers,
            "redacted_header_names": redacted_names,
            "body_framing": pending.body_framing,
            "content_length": pending.content_length,
            "transfer_encoding": pending.transfer_encoding,
            "content_encoding": pending.content_encoding,
            "connection_close": pending.connection_close,
            "complete": complete,
            "incomplete_reason": incomplete_reason,
            "body_bytes": pending.body_bytes,
            "payload": payload,
            "payload_decoded": payload_decoded,
            "payload_truncated": payload_truncated,
            "stream_start_offset": pending.start_offset,
            "stream_end_offset": self._total_consumed,
            "diagnostics": tuple(pending.diagnostics),
        }
        if self._direction.is_request_direction:
            return HttpRequest(
                kind=MessageKind.REQUEST,
                method=pending.method or "",
                target=pending.target,
                redacted_query_params=pending.redacted_query_params,
                **common,  # type: ignore[arg-type]
            )
        return HttpResponse(
            kind=MessageKind.RESPONSE,
            status_code=pending.status_code or 0,
            reason_phrase=pending.reason_phrase,
            request_method=pending.request_method,
            is_informational=pending.is_informational,
            **common,  # type: ignore[arg-type]
        )

    def _finalize(self, *, truncated: bool, reason: str | None) -> None:
        if not truncated:
            self._finish_decoder()
        message = self._build_message(complete=not truncated, incomplete_reason=reason)
        self._messages_completed += 1
        self._batch_messages.append(message)
        if message.connection_close:
            self._closing = True
        self._pending = None
        self._state = ParserState.START
