"""SSE（Server-Sent Events）帧解析。

遵循 WHATWG 事件流语义的子集：

* 行终止符支持 ``CRLF`` / ``LF`` / ``CR``，允许跨任意字节分片（包括逐字节）；
* ``data`` 字段多行时用 ``\\n`` 连接，事件以**空行**分帧；
* ``event`` / ``id`` / ``retry`` 字段保留；以 ``:`` 开头的注释行忽略；
* 流首 BOM 忽略；``id`` 含 NUL 时按规范忽略；
* ``data`` 为 ``[DONE]`` 时标记 :attr:`SseEvent.is_done`（OpenAI 兼容流终止符）。

重要语义（对应 M1"不能把所有非 stop 结果视为断流"）：

* 事件是否**分帧完整**与 ``finish_reason`` 无关，这里只看字节流是否给出了
  终止证据（``[DONE]`` 或空行分帧完整）。
* EOF 时未分帧的残留事件按规范**丢弃**，并产出 ``SSE_TRUNCATED``，
  不会把半个事件当成完整事件。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_probe.llm.diagnostics import Diagnostic, DiagnosticCode
from agent_probe.llm.limits import SseLimits

__all__ = ["SseEvent", "SseFinish", "SseParser", "DONE_SENTINEL"]

#: OpenAI 兼容流的终止哨兵。
DONE_SENTINEL = "[DONE]"

_BOM = b"\xef\xbb\xbf"


@dataclass(frozen=True)
class SseEvent:
    """一个已分帧的 SSE 事件。"""

    index: int
    data: str
    data_lines: tuple[str, ...]
    event: str | None = None
    id: str | None = None
    retry: int | None = None
    is_done: bool = False

    def to_record(self) -> dict[str, object]:
        return {
            "index": self.index,
            "event": self.event,
            "id": self.id,
            "retry": self.retry,
            "is_done": self.is_done,
            "data_lines": len(self.data_lines),
            "data_length": len(self.data),
            # 默认不持久化 data 原文：它可能包含提示词补全内容。
        }


@dataclass(frozen=True)
class SseFinish:
    """``SseParser.finish()`` 的结果。

    ``events`` 是收尾阶段（例如以裸 CR 结束时）才得以分帧的事件。
    """

    event_count: int
    saw_done: bool
    truncated: bool
    pending_bytes: int
    pending_data_lines: int
    events: tuple[SseEvent, ...] = field(default_factory=tuple)
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)


class SseParser:
    """增量 SSE 解析器。非线程安全，按连接方向单独实例化。"""

    def __init__(self, limits: SseLimits | None = None) -> None:
        self._limits = limits if limits is not None else SseLimits()
        self._buf = bytearray()
        self._scan = 0
        self._data_lines: list[str] = []
        self._event: str | None = None
        self._last_id: str | None = None
        self._retry: int | None = None
        self._event_index = 0
        self._pending_bytes = 0
        self._saw_done = False
        self._bom_checked = False
        self._failed = False
        self._finished = False
        self._diagnostics: list[Diagnostic] = []

    # ------------------------------------------------------------------
    # 属性
    # ------------------------------------------------------------------

    @property
    def event_count(self) -> int:
        return self._event_index

    @property
    def saw_done(self) -> bool:
        return self._saw_done

    @property
    def last_event_id(self) -> str | None:
        return self._last_id

    @property
    def failed(self) -> bool:
        return self._failed

    @property
    def pending_bytes(self) -> int:
        return len(self._buf)

    @property
    def diagnostics(self) -> tuple[Diagnostic, ...]:
        return tuple(self._diagnostics)

    # ------------------------------------------------------------------
    # 公开 API
    # ------------------------------------------------------------------

    def feed(self, data: bytes | bytearray | memoryview | str) -> tuple[SseEvent, ...]:
        """喂入任意分片，返回本次可确定分帧的事件。"""
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif isinstance(data, memoryview):
            data = data.tobytes()
        elif not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"data 必须是 bytes/str，得到 {type(data).__name__}")
        if self._finished:
            raise RuntimeError("SSE 解析器已 finish，不能继续 feed")
        if self._failed:
            return ()
        self._buf += bytes(data)
        events = self._drain(final=False)
        self._check_size()
        return tuple(events)

    def finish(self) -> SseFinish:
        """声明字节流结束，产出截断/终止证据诊断。"""
        diagnostics: list[Diagnostic] = []
        events: tuple[SseEvent, ...] = ()
        if not self._finished:
            self._finished = True
            if not self._failed:
                events = tuple(self._drain(final=True))
                self._check_size()
        truncated = self._failed or bool(self._buf) or bool(self._data_lines)
        if truncated:
            diagnostics.append(
                Diagnostic.create(
                    DiagnosticCode.SSE_TRUNCATED,
                    "SSE 流结束时仍有未分帧数据（残留事件按规范丢弃）",
                )
            )
        if not self._saw_done:
            diagnostics.append(
                Diagnostic.create(
                    DiagnosticCode.SSE_MISSING_DONE,
                    "未观察到 [DONE] 终止哨兵；流是否完整需由 finish_reason 或其他证据判断",
                )
            )
        self._diagnostics.extend(diagnostics)
        return SseFinish(
            event_count=self._event_index,
            saw_done=self._saw_done,
            truncated=truncated,
            pending_bytes=len(self._buf),
            pending_data_lines=len(self._data_lines),
            events=events,
            diagnostics=tuple(diagnostics),
        )

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    def _consume(self, count: int) -> None:
        del self._buf[:count]
        self._scan = 0

    def _next_line(self, *, final: bool) -> tuple[bytes, int] | None:
        buffer = self._buf
        length = len(buffer)
        index = self._scan
        while index < length:
            char = buffer[index]
            if char == 0x0A:
                return bytes(buffer[:index]), index + 1
            if char == 0x0D:
                if index + 1 < length:
                    if buffer[index + 1] == 0x0A:
                        return bytes(buffer[:index]), index + 2
                    return bytes(buffer[:index]), index + 1
                if final:
                    return bytes(buffer[:index]), index + 1
                self._scan = index
                return None
            index += 1
        self._scan = length
        return None

    def _drain(self, *, final: bool) -> list[SseEvent]:
        events: list[SseEvent] = []
        while not self._failed:
            found = self._next_line(final=final)
            if found is None:
                break
            line, consumed = found
            self._consume(consumed)
            event = self._process_line(line)
            if event is not None:
                events.append(event)
        return events

    def _process_line(self, raw_line: bytes) -> SseEvent | None:
        line = raw_line
        if not self._bom_checked:
            self._bom_checked = True
            if line.startswith(_BOM):
                line = line[len(_BOM) :]
        text = line.decode("utf-8", errors="replace")
        if text == "":
            return self._dispatch()
        if text.startswith(":"):
            return None
        field_name, separator, value = text.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field_name == "data":
            self._data_lines.append(value)
            self._pending_bytes += len(value) + 1
        elif field_name == "event":
            self._event = value
        elif field_name == "id":
            if "\x00" not in value:
                self._last_id = value
        elif field_name == "retry":
            if value.isdigit():
                self._retry = int(value)
        # 其他字段按规范忽略。
        self._check_size()
        return None

    def _dispatch(self) -> SseEvent | None:
        if not self._data_lines:
            self._event = None
            return None
        data = "\n".join(self._data_lines)
        self._event_index += 1
        event = SseEvent(
            index=self._event_index,
            data=data,
            data_lines=tuple(self._data_lines),
            event=self._event,
            id=self._last_id,
            retry=self._retry,
            is_done=data.strip() == DONE_SENTINEL,
        )
        self._data_lines = []
        self._event = None
        self._pending_bytes = 0
        if event.is_done:
            self._saw_done = True
        return event

    def _check_size(self) -> None:
        if self._failed:
            return
        too_many_lines = len(self._data_lines) > self._limits.max_data_lines
        too_many_bytes = self._pending_bytes > self._limits.max_event_bytes
        buffered_too_much = len(self._buf) > self._limits.max_event_bytes
        if not (too_many_lines or too_many_bytes or buffered_too_much):
            return
        self._failed = True
        self._buf.clear()
        self._data_lines = []
        self._pending_bytes = 0
        self._diagnostics.append(
            Diagnostic.create(
                DiagnosticCode.SSE_EVENT_TOO_LARGE,
                f"SSE 事件超过上限（max_event_bytes={self._limits.max_event_bytes}, "
                f"max_data_lines={self._limits.max_data_lines}）；停止解析该流",
            )
        )
