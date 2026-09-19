"""从已重建的 HTTP 消息中判断"流是否完整"并汇总 usage。

两个**不同**的概念必须分开（对应 M1 / M4 的"中断检测"口径）：

``StreamCompletion``（传输层）
    字节流是否给出了终止证据。只有以下情况才判 ``TRUNCATED``：

    * HTTP 消息本身不完整（提前 EOF、非法 chunk、头部超限……）；
    * 正文被上限截断；
    * SSE 流在 EOF 时仍有未分帧残留。

``StopKind``（提供方语义）
    ``finish_reason`` 的语义分类。``length`` / ``content_filter`` / ``tool_calls``
    都是**正常**的提供方终止，绝不能被当成断流；它们只影响"为什么停止"的解释。

因此 ``[DONE]``、``message_stop``、``finish_reason`` 等任一条终止证据出现，即判
``COMPLETE``；没有终止证据且字节流干净结束时判 ``UNKNOWN``，不臆断为断流。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from agent_probe.llm.diagnostics import Diagnostic
from agent_probe.llm.limits import SseLimits
from agent_probe.llm.messages import HttpMessage
from agent_probe.llm.sse import SseEvent, SseFinish, SseParser
from agent_probe.llm.usage import (
    UsageExtraction,
    UsageStatus,
    extract_usage_from_json_object,
    extract_usage_from_message,
    extract_usage_from_sse_events,
    is_event_stream,
)

__all__ = [
    "StreamCompletion",
    "StopKind",
    "ContentKind",
    "CompletionAnalysis",
    "PayloadAnalysis",
    "classify_stop",
    "analyze_payload",
]


class StreamCompletion(str, Enum):
    """传输层完整性。"""

    COMPLETE = "complete"
    TRUNCATED = "truncated"
    UNKNOWN = "unknown"


class StopKind(str, Enum):
    """``finish_reason`` 的语义分类（与传输完整性无关）。"""

    STOP = "stop"
    LENGTH = "length"
    TOOL_CALLS = "tool_calls"
    CONTENT_FILTER = "content_filter"
    ERROR = "error"
    OTHER = "other"
    UNKNOWN = "unknown"


class ContentKind(str, Enum):
    """正文形态。"""

    SSE = "sse"
    JSON = "json"
    EMPTY = "empty"
    UNAVAILABLE = "unavailable"


_STOP_ALIASES: dict[str, StopKind] = {
    "stop": StopKind.STOP,
    "end_turn": StopKind.STOP,
    "stop_sequence": StopKind.STOP,
    "eos": StopKind.STOP,
    "complete": StopKind.STOP,
    "completed": StopKind.STOP,
    "length": StopKind.LENGTH,
    "max_tokens": StopKind.LENGTH,
    "max_output_tokens": StopKind.LENGTH,
    "max_completion_tokens": StopKind.LENGTH,
    "tool_calls": StopKind.TOOL_CALLS,
    "tool_use": StopKind.TOOL_CALLS,
    "function_call": StopKind.TOOL_CALLS,
    "content_filter": StopKind.CONTENT_FILTER,
    "content-filter": StopKind.CONTENT_FILTER,
    "safety": StopKind.CONTENT_FILTER,
    "recitation": StopKind.CONTENT_FILTER,
    "prohibited_content": StopKind.CONTENT_FILTER,
    "blocked": StopKind.CONTENT_FILTER,
    "error": StopKind.ERROR,
    "failed": StopKind.ERROR,
    "cancelled": StopKind.ERROR,
    "canceled": StopKind.ERROR,
}

_TERMINAL_EVENT_TYPES = frozenset(
    {
        "message_stop",
        "response.completed",
        "response.incomplete",
        "response.failed",
    }
)

_TERMINAL_SSE_EVENT_NAMES = frozenset({"message_stop"})


def classify_stop(finish_reason: str | None) -> StopKind:
    """把提供方的 ``finish_reason`` 映射为语义分类。"""
    if not finish_reason:
        return StopKind.UNKNOWN
    return _STOP_ALIASES.get(finish_reason.strip().lower(), StopKind.OTHER)


def _collect_finish_reasons(obj: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []

    def add(value: object) -> None:
        if isinstance(value, str) and value and value not in reasons:
            reasons.append(value)

    choices = obj.get("choices")
    if isinstance(choices, list):
        for choice in choices:
            if isinstance(choice, Mapping):
                add(choice.get("finish_reason"))
                delta = choice.get("delta")
                if isinstance(delta, Mapping):
                    add(delta.get("finish_reason"))
    add(obj.get("finish_reason"))
    add(obj.get("stop_reason"))
    delta = obj.get("delta")
    if isinstance(delta, Mapping):
        add(delta.get("stop_reason"))
    incomplete = obj.get("incomplete_details")
    if isinstance(incomplete, Mapping):
        reason = incomplete.get("reason")
        if reason == "max_output_tokens":
            add("length")
        else:
            add(reason)
    return reasons


@dataclass(frozen=True)
class CompletionAnalysis:
    """一条消息的完整性判定与证据。"""

    completion: StreamCompletion
    finish_reasons: tuple[str, ...] = ()
    stop_kinds: tuple[StopKind, ...] = ()
    terminal_evidence: tuple[str, ...] = ()
    truncated_reasons: tuple[str, ...] = ()
    saw_done: bool = False

    @property
    def is_truncated(self) -> bool:
        return self.completion is StreamCompletion.TRUNCATED

    def to_record(self) -> dict[str, object]:
        return {
            "completion": self.completion.value,
            "saw_done": self.saw_done,
            "finish_reasons": list(self.finish_reasons),
            "stop_kinds": [kind.value for kind in self.stop_kinds],
            "terminal_evidence": list(self.terminal_evidence),
            "truncated_reasons": list(self.truncated_reasons),
        }


@dataclass(frozen=True)
class PayloadAnalysis:
    """一条消息的正文分析结果（usage + 完整性 + 诊断）。"""

    content_kind: ContentKind
    completion: CompletionAnalysis
    usage: UsageExtraction
    model: str | None = None
    sse_events: tuple[SseEvent, ...] = ()
    sse_finish: SseFinish | None = None
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)

    @property
    def usage_status(self) -> UsageStatus:
        return self.usage.status

    def to_record(self) -> dict[str, object]:
        return {
            "content_kind": self.content_kind.value,
            "model": self.model,
            "completion": self.completion.to_record(),
            "usage": self.usage.to_record(),
            "sse_event_count": len(self.sse_events),
            "sse": None
            if self.sse_finish is None
            else {
                "event_count": self.sse_finish.event_count,
                "saw_done": self.sse_finish.saw_done,
                "truncated": self.sse_finish.truncated,
                "pending_bytes": self.sse_finish.pending_bytes,
                "pending_data_lines": self.sse_finish.pending_data_lines,
            },
            "diagnostics": [d.to_record() for d in self.diagnostics],
        }


def _analysis(
    *,
    completion: StreamCompletion,
    finish_reasons: Sequence[str] = (),
    terminal_evidence: Sequence[str] = (),
    truncated_reasons: Sequence[str] = (),
    saw_done: bool = False,
) -> CompletionAnalysis:
    kinds: list[StopKind] = []
    for reason in finish_reasons:
        kind = classify_stop(reason)
        if kind not in kinds:
            kinds.append(kind)
    return CompletionAnalysis(
        completion=completion,
        finish_reasons=tuple(finish_reasons),
        stop_kinds=tuple(kinds),
        terminal_evidence=tuple(terminal_evidence),
        truncated_reasons=tuple(truncated_reasons),
        saw_done=saw_done,
    )


def analyze_payload(message: HttpMessage, *, sse_limits: SseLimits | None = None) -> PayloadAnalysis:
    """分析一条消息的正文：usage、完整性、模型名与诊断。"""
    limits = sse_limits if sse_limits is not None else SseLimits()
    message_incomplete = not message.complete

    if message.payload is None:
        truncated_reasons = ()
        completion = StreamCompletion.UNKNOWN
        if message_incomplete:
            completion = StreamCompletion.TRUNCATED
            truncated_reasons = (message.incomplete_reason or "http_incomplete",)
        usage = extract_usage_from_message(message, truncated=message_incomplete)
        return PayloadAnalysis(
            content_kind=ContentKind.UNAVAILABLE,
            completion=_analysis(completion=completion, truncated_reasons=truncated_reasons),
            usage=usage,
            model=None,
            diagnostics=usage.diagnostics,
        )

    payload_truncated = not message.payload_complete
    if payload_truncated and not message_incomplete:
        truncated_reasons_base = ("payload_truncated",)
    elif message_incomplete:
        truncated_reasons_base = (message.incomplete_reason or "http_incomplete",)
    else:
        truncated_reasons_base = ()

    if is_event_stream(message):
        parser = SseParser(limits)
        events = list(parser.feed(message.payload))
        finish = parser.finish()
        events.extend(finish.events)
        event_tuple = tuple(events)

        evidence: list[str] = []
        if finish.saw_done:
            evidence.append("sse_done")
        finish_reasons: list[str] = []
        for event in event_tuple:
            if event.event in _TERMINAL_SSE_EVENT_NAMES:
                if "sse_terminal_event" not in evidence:
                    evidence.append("sse_terminal_event")
            text = event.data.strip()
            if not text.startswith("{") or event.is_done:
                continue
            try:
                parsed: Any = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, Mapping):
                continue
            event_type = parsed.get("type")
            if isinstance(event_type, str) and event_type in _TERMINAL_EVENT_TYPES:
                if "sse_terminal_event" not in evidence:
                    evidence.append("sse_terminal_event")
            for reason in _collect_finish_reasons(parsed):
                if reason not in finish_reasons:
                    finish_reasons.append(reason)
        if finish_reasons:
            evidence.append("finish_reason")

        truncated_reasons = list(truncated_reasons_base)
        if finish.truncated:
            truncated_reasons.append("sse_truncated")
        # 只有"流自己的结束标记"（[DONE] / message_stop 等）才能压过字节层截断；
        # finish_reason 只是内容侧的停止信号，若字节随后被截断，仍属截断。
        explicit_end = finish.saw_done or "sse_terminal_event" in evidence
        if explicit_end:
            completion_status = StreamCompletion.COMPLETE
        elif truncated_reasons:
            completion_status = StreamCompletion.TRUNCATED
        elif finish_reasons:
            completion_status = StreamCompletion.COMPLETE
        else:
            completion_status = StreamCompletion.UNKNOWN

        usage = extract_usage_from_sse_events(
            event_tuple,
            truncated=bool(truncated_reasons),
            model_hint=None,
        )
        diagnostics: tuple[Diagnostic, ...] = tuple(parser.diagnostics) + usage.diagnostics
        return PayloadAnalysis(
            content_kind=ContentKind.SSE if message.payload else ContentKind.EMPTY,
            completion=_analysis(
                completion=completion_status,
                finish_reasons=finish_reasons,
                terminal_evidence=evidence,
                truncated_reasons=truncated_reasons,
                saw_done=finish.saw_done,
            ),
            usage=usage,
            model=usage.model_name,
            sse_events=event_tuple,
            sse_finish=finish,
            diagnostics=diagnostics,
        )

    # ---- JSON（或未知形态） ----
    if not message.payload.strip():
        usage = extract_usage_from_message(message, truncated=message_incomplete)
        return PayloadAnalysis(
            content_kind=ContentKind.EMPTY,
            completion=_analysis(
                completion=(
                    StreamCompletion.TRUNCATED
                    if truncated_reasons_base
                    else StreamCompletion.UNKNOWN
                ),
                truncated_reasons=truncated_reasons_base,
            ),
            usage=usage,
            model=None,
            diagnostics=usage.diagnostics,
        )

    try:
        parsed_json = json.loads(message.payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        usage = extract_usage_from_message(message, truncated=message_incomplete)
        return PayloadAnalysis(
            content_kind=ContentKind.JSON,
            completion=_analysis(
                completion=(
                    StreamCompletion.TRUNCATED
                    if truncated_reasons_base
                    else StreamCompletion.UNKNOWN
                ),
                truncated_reasons=truncated_reasons_base,
            ),
            usage=usage,
            model=None,
            diagnostics=usage.diagnostics,
        )

    if not isinstance(parsed_json, Mapping):
        usage = extract_usage_from_message(message, truncated=message_incomplete)
        return PayloadAnalysis(
            content_kind=ContentKind.JSON,
            completion=_analysis(
                completion=StreamCompletion.UNKNOWN,
                truncated_reasons=("json_top_level_not_object",),
            ),
            usage=usage,
            model=None,
            diagnostics=usage.diagnostics,
        )

    finish_reasons = _collect_finish_reasons(parsed_json)
    evidence = []
    if finish_reasons:
        evidence.append("finish_reason")
    if payload_truncated or message_incomplete:
        completion_status = StreamCompletion.TRUNCATED
    elif evidence or message.complete:
        # 非流式响应：HTTP 正文分帧完整即视为完整（没有别的终止信号）。
        evidence.append("http_message_complete")
        completion_status = StreamCompletion.COMPLETE
    else:
        completion_status = StreamCompletion.UNKNOWN

    usage = extract_usage_from_json_object(parsed_json)
    return PayloadAnalysis(
        content_kind=ContentKind.JSON,
        completion=_analysis(
            completion=completion_status,
            finish_reasons=finish_reasons,
            terminal_evidence=evidence,
            truncated_reasons=truncated_reasons_base,
        ),
        usage=usage,
        model=usage.model_name,
        diagnostics=usage.diagnostics,
    )
