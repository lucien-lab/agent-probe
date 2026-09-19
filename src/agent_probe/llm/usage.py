"""provider-neutral 的 token usage 模型与提取。

模型约定
--------

* 缺失即 ``None``，**绝不填零**：只有提供方明确返回过的字段才会被赋值，
  ``fields_reported`` 记录到底上报了哪些字段。
* 明细字段（缓存 / 推理）额外记录**是否已包含在总量中**，三态：
  ``True``（已包含，如 OpenAI ``prompt_tokens_details.cached_tokens``）、
  ``False``（未包含，如 Anthropic ``cache_read_input_tokens``）、
  ``None``（未知，计费时必须显式标记不完整）。
* usage 缺失的三种原因在 :class:`UsageStatus` 中分开：
  ``ABSENT``（提供方未返回）、``UNPARSEABLE``（拿到了正文但解析失败）、
  ``NOT_CAPTURED``（正文未捕获/被截断，无法判断提供方是否返回过）。

支持的字段别名（OpenAI 兼容 chat completions / responses、Anthropic Messages）：

* 输入：``prompt_tokens`` / ``input_tokens``
* 输出：``completion_tokens`` / ``output_tokens``
* 总量：``total_tokens``
* 缓存读：``prompt_tokens_details.cached_tokens`` /
  ``input_tokens_details.cached_tokens`` / ``cache_read_input_tokens``
* 缓存写：``cache_creation_input_tokens``
* 推理：``completion_tokens_details.reasoning_tokens`` /
  ``output_tokens_details.reasoning_tokens``

扩展新提供方只需扩展下面的别名/明细表，不需要改模型。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from agent_probe.llm.diagnostics import Diagnostic, DiagnosticCode
from agent_probe.llm.messages import HttpMessage
from agent_probe.llm.sse import SseEvent, SseParser

__all__ = [
    "UsageStatus",
    "TokenUsage",
    "UsageExtraction",
    "extract_usage_from_json",
    "extract_usage_from_json_object",
    "extract_usage_from_sse_events",
    "extract_usage_from_message",
    "is_event_stream",
]

_INPUT_KEYS = ("prompt_tokens", "input_tokens", "prompt_tokens_count")
_OUTPUT_KEYS = ("completion_tokens", "output_tokens")
_TOTAL_KEYS = ("total_tokens",)


class UsageStatus(str, Enum):
    """usage 的可得性。"""

    PRESENT = "present"
    ABSENT = "absent"
    UNPARSEABLE = "unparseable"
    NOT_CAPTURED = "not_captured"


@dataclass(frozen=True)
class TokenUsage:
    """一次调用的 token 用量（provider-neutral）。"""

    model: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    cache_read_tokens: int | None = None
    cache_write_tokens: int | None = None
    reasoning_tokens: int | None = None
    cache_read_included_in_input: bool | None = None
    cache_write_included_in_input: bool | None = None
    reasoning_included_in_output: bool | None = None
    provider: str | None = None
    fields_reported: frozenset[str] = frozenset()
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False)

    @property
    def is_empty(self) -> bool:
        """是否一个 token 计数字段都没有（仅有一个空 usage 容器）。"""
        return not any(
            value is not None
            for value in (
                self.input_tokens,
                self.output_tokens,
                self.total_tokens,
                self.cache_read_tokens,
                self.cache_write_tokens,
                self.reasoning_tokens,
            )
        )

    def to_record(self) -> dict[str, object]:
        return {
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "cache_read_included_in_input": self.cache_read_included_in_input,
            "cache_write_included_in_input": self.cache_write_included_in_input,
            "reasoning_included_in_output": self.reasoning_included_in_output,
            "provider": self.provider,
            "fields_reported": sorted(self.fields_reported),
            "raw": dict(self.raw),
        }


@dataclass(frozen=True)
class UsageExtraction:
    """usage 提取结果：状态 + 值 + 证据。"""

    status: UsageStatus
    usage: TokenUsage | None = None
    model: str | None = None
    detail: str | None = None
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)

    @property
    def present(self) -> bool:
        return self.status is UsageStatus.PRESENT and self.usage is not None

    @property
    def model_name(self) -> str | None:
        """优先取 usage 自带的模型名，其次取正文顶层模型名。"""
        if self.usage is not None and self.usage.model:
            return self.usage.model
        return self.model

    def to_record(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "detail": self.detail,
            "model": self.model_name,
            "usage": None if self.usage is None else self.usage.to_record(),
            "diagnostics": [d.to_record() for d in self.diagnostics],
        }


# ----------------------------------------------------------------------
# 明细字段来源表：路径 + "是否已包含在对应总量中"
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class _DetailSource:
    path: tuple[str, ...]
    included: bool | None


_CACHE_READ_SOURCES: tuple[_DetailSource, ...] = (
    _DetailSource(("prompt_tokens_details", "cached_tokens"), True),
    _DetailSource(("input_tokens_details", "cached_tokens"), True),
    _DetailSource(("cache_read_input_tokens",), False),
)

_CACHE_WRITE_SOURCES: tuple[_DetailSource, ...] = (
    _DetailSource(("cache_creation_input_tokens",), False),
    _DetailSource(("prompt_tokens_details", "cache_creation_tokens"), True),
)

_REASONING_SOURCES: tuple[_DetailSource, ...] = (
    _DetailSource(("completion_tokens_details", "reasoning_tokens"), True),
    _DetailSource(("output_tokens_details", "reasoning_tokens"), True),
)


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and float(value).is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
    return None


def _dig(mapping: Mapping[str, Any], path: Sequence[str]) -> object:
    current: object = mapping
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _first_of(container: Mapping[str, Any], keys: Sequence[str]) -> tuple[int | None, str | None]:
    for key in keys:
        if key in container:
            parsed = _as_int(container[key])
            if parsed is not None:
                return parsed, key
    return None, None


def _first_detail(
    container: Mapping[str, Any], sources: Sequence[_DetailSource]
) -> tuple[int | None, str | None, bool | None]:
    for source in sources:
        value = _as_int(_dig(container, source.path))
        if value is not None:
            return value, ".".join(source.path), source.included
    return None, None, None


def _detect_provider(container: Mapping[str, Any]) -> str | None:
    if "prompt_tokens" in container or "completion_tokens" in container:
        return "openai"
    if "cache_read_input_tokens" in container or "cache_creation_input_tokens" in container:
        return "anthropic"
    if "input_tokens" in container or "output_tokens" in container:
        return "openai-compatible"
    return None


def _extract_model(mapping: Mapping[str, Any]) -> str | None:
    for key in ("model", "model_name"):
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value
    message = mapping.get("message")
    if isinstance(message, Mapping):
        value = message.get("model")
        if isinstance(value, str) and value:
            return value
    return None


def _build_usage(
    container: Mapping[str, Any], *, model: str | None, merged_raw: Mapping[str, Any]
) -> TokenUsage:
    reported: set[str] = set()
    input_tokens, input_key = _first_of(container, _INPUT_KEYS)
    if input_key:
        reported.add("input_tokens")
    output_tokens, output_key = _first_of(container, _OUTPUT_KEYS)
    if output_key:
        reported.add("output_tokens")
    total_tokens, total_key = _first_of(container, _TOTAL_KEYS)
    if total_key:
        reported.add("total_tokens")

    cache_read, cache_read_key, cache_read_included = _first_detail(container, _CACHE_READ_SOURCES)
    if cache_read_key:
        reported.add("cache_read_tokens")
    cache_write, cache_write_key, cache_write_included = _first_detail(
        container, _CACHE_WRITE_SOURCES
    )
    if cache_write_key:
        reported.add("cache_write_tokens")
    reasoning, reasoning_key, reasoning_included = _first_detail(container, _REASONING_SOURCES)
    if reasoning_key:
        reported.add("reasoning_tokens")

    return TokenUsage(
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        cache_read_tokens=cache_read,
        cache_write_tokens=cache_write,
        reasoning_tokens=reasoning,
        cache_read_included_in_input=cache_read_included,
        cache_write_included_in_input=cache_write_included,
        reasoning_included_in_output=reasoning_included,
        provider=_detect_provider(container),
        fields_reported=frozenset(reported),
        raw=dict(merged_raw),
    )


#: usage 容器可能出现的键（顶层 / message.usage / response.usage）。
_USAGE_CONTAINER_PATHS: tuple[tuple[str, ...], ...] = (
    ("usage",),
    ("message", "usage"),
    ("response", "usage"),
)


def _usage_containers(mapping: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    found: list[Mapping[str, Any]] = []
    for path in _USAGE_CONTAINER_PATHS:
        candidate = _dig(mapping, path)
        if isinstance(candidate, Mapping):
            found.append(candidate)
    return found


def extract_usage_from_json_object(
    mapping: Mapping[str, Any], *, model_hint: str | None = None
) -> UsageExtraction:
    """从已解析的 JSON 对象提取 usage。"""
    containers = _usage_containers(mapping)
    model = _extract_model(mapping) or model_hint
    if not containers:
        return UsageExtraction(
            status=UsageStatus.ABSENT,
            model=model,
            detail="响应 JSON 中没有 usage 字段",
            diagnostics=(
                Diagnostic.create(DiagnosticCode.USAGE_ABSENT, "提供方未返回 usage 字段"),
            ),
        )
    merged: dict[str, Any] = {}
    for container in containers:
        merged.update(container)
    if not merged:
        return UsageExtraction(
            status=UsageStatus.ABSENT,
            model=model,
            detail="usage 字段存在但为空对象",
            diagnostics=(Diagnostic.create(DiagnosticCode.USAGE_ABSENT, "usage 为空对象"),),
        )
    return UsageExtraction(
        status=UsageStatus.PRESENT,
        usage=_build_usage(merged, model=model, merged_raw=merged),
        model=model,
    )


def extract_usage_from_json(
    payload: bytes | str | Mapping[str, Any], *, model_hint: str | None = None
) -> UsageExtraction:
    """从 JSON 正文（bytes/str/已解析对象）提取 usage。"""
    if isinstance(payload, Mapping):
        return extract_usage_from_json_object(payload, model_hint=model_hint)
    try:
        text = payload.decode("utf-8") if isinstance(payload, (bytes, bytearray)) else payload
    except UnicodeDecodeError:
        return UsageExtraction(
            status=UsageStatus.UNPARSEABLE,
            model=model_hint,
            detail="正文不是 UTF-8",
            diagnostics=(
                Diagnostic.create(DiagnosticCode.USAGE_UNPARSEABLE, "正文不是 UTF-8"),
            ),
        )
    if not text.strip():
        return UsageExtraction(
            status=UsageStatus.UNPARSEABLE,
            model=model_hint,
            detail="正文为空",
            diagnostics=(Diagnostic.create(DiagnosticCode.USAGE_UNPARSEABLE, "正文为空"),),
        )
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return UsageExtraction(
            status=UsageStatus.UNPARSEABLE,
            model=model_hint,
            detail=f"JSON 解析失败：{exc.msg}",
            diagnostics=(
                Diagnostic.create(
                    DiagnosticCode.USAGE_UNPARSEABLE,
                    f"JSON 解析失败（第 {exc.lineno} 行第 {exc.colno} 列）",
                ),
            ),
        )
    if not isinstance(parsed, Mapping):
        return UsageExtraction(
            status=UsageStatus.UNPARSEABLE,
            model=model_hint,
            detail="JSON 顶层不是对象",
            diagnostics=(
                Diagnostic.create(DiagnosticCode.USAGE_UNPARSEABLE, "JSON 顶层不是对象"),
            ),
        )
    return extract_usage_from_json_object(parsed, model_hint=model_hint)


# ----------------------------------------------------------------------
# SSE
# ----------------------------------------------------------------------


def extract_usage_from_sse_events(
    events: Iterable[SseEvent],
    *,
    truncated: bool = False,
    model_hint: str | None = None,
) -> UsageExtraction:
    """从 SSE 事件序列提取 usage。

    合并策略：按事件顺序做**浅合并**，后到的非空字段覆盖先到的。OpenAI 兼容流
    只在最后一个 chunk 带完整 usage；Anthropic 把输入放在 ``message_start``、
    输出放在 ``message_delta``，两者字段不相交，浅合并即可。
    """
    merged: dict[str, Any] = {}
    model: str | None = model_hint
    found_container = False
    json_looking = 0
    parse_failures = 0

    for event in events:
        if event.is_done or not event.data.strip():
            continue
        text = event.data.strip()
        if not text.startswith("{"):
            continue
        json_looking += 1
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parse_failures += 1
            continue
        if not isinstance(parsed, Mapping):
            continue
        candidate_model = _extract_model(parsed)
        if candidate_model and not model:
            model = candidate_model
        containers = _usage_containers(parsed)
        if containers:
            found_container = True
            for container in containers:
                merged.update(container)

    if merged:
        return UsageExtraction(
            status=UsageStatus.PRESENT,
            usage=_build_usage(merged, model=model, merged_raw=merged),
            model=model,
        )
    if found_container:
        return UsageExtraction(
            status=UsageStatus.ABSENT,
            model=model,
            detail="usage 容器存在但为空对象",
            diagnostics=(Diagnostic.create(DiagnosticCode.USAGE_ABSENT, "SSE usage 为空对象"),),
        )
    if truncated:
        return UsageExtraction(
            status=UsageStatus.NOT_CAPTURED,
            model=model,
            detail="SSE 流被截断，usage 可能位于丢失的尾部 chunk",
            diagnostics=(
                Diagnostic.create(
                    DiagnosticCode.USAGE_NOT_CAPTURED,
                    "SSE 流截断，无法判断提供方是否返回过 usage",
                ),
            ),
        )
    if json_looking and parse_failures == json_looking:
        return UsageExtraction(
            status=UsageStatus.UNPARSEABLE,
            model=model,
            detail="所有 JSON 形态的 SSE data 都无法解析",
            diagnostics=(
                Diagnostic.create(DiagnosticCode.USAGE_UNPARSEABLE, "SSE data 全部解析失败"),
            ),
        )
    return UsageExtraction(
        status=UsageStatus.ABSENT,
        model=model,
        detail="SSE 流中没有携带 usage 的 chunk（如未开启 stream_options.include_usage）",
        diagnostics=(
            Diagnostic.create(
                DiagnosticCode.USAGE_ABSENT,
                "SSE 流中未出现 usage（常见于未开启 include_usage）",
            ),
        ),
    )


# ----------------------------------------------------------------------
# 高层：从一条 HTTP 消息提取
# ----------------------------------------------------------------------


def is_event_stream(message: HttpMessage) -> bool:
    content_type = message.content_type
    if content_type is None:
        return False
    return content_type == "text/event-stream" or content_type.startswith("text/event-stream")


def extract_usage_from_message(
    message: HttpMessage, *, sse_events: Sequence[SseEvent] | None = None, truncated: bool = False
) -> UsageExtraction:
    """从一条已重建的消息提取 usage（按 Content-Type 分派）。"""
    if message.payload is None:
        return UsageExtraction(
            status=UsageStatus.NOT_CAPTURED,
            detail="正文不可用（未捕获或 Content-Encoding 不受支持）",
            diagnostics=(
                Diagnostic.create(
                    DiagnosticCode.USAGE_NOT_CAPTURED,
                    "正文不可用，usage 既未捕获也无法解析",
                ),
            ),
        )
    if is_event_stream(message):
        if sse_events is None:
            parser = SseParser()
            collected = list(parser.feed(message.payload))
            finish = parser.finish()
            collected.extend(finish.events)
            sse_events = tuple(collected)
            truncated = truncated or finish.truncated
        return extract_usage_from_sse_events(sse_events, truncated=truncated)
    extraction = extract_usage_from_json(message.payload)
    if extraction.status is UsageStatus.UNPARSEABLE and (truncated or not message.payload_complete):
        return UsageExtraction(
            status=UsageStatus.NOT_CAPTURED,
            model=extraction.model,
            detail="正文被截断且无法解析，按捕获失败处理",
            diagnostics=(
                Diagnostic.create(
                    DiagnosticCode.USAGE_NOT_CAPTURED,
                    "正文截断导致 JSON 不完整，无法判断提供方是否返回过 usage",
                ),
            ),
        )
    return extraction
