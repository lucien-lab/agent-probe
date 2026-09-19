"""``agent_probe.llm``：M1 的离线协议重建与计账核心。

模块划分
--------

``common``
    方向与消息种类等最小枚举。
``diagnostics``
    稳定诊断码与 ``Diagnostic`` 值对象（不抛异常表达"数据不完整"）。
``limits``
    头部/正文/解压/chunk/SSE 的硬上限。
``messages``
    HTTP 消息模型 + **默认开启**的头部与 target 脱敏。
``http1``
    HTTP/1.1 有界增量解析器（Content-Length / chunked / gzip / 连接复用）。
``sse``
    SSE 增量分帧（空行分帧、多行 data、``[DONE]``、截断检测）。
``usage``
    provider-neutral usage 模型与提取（缺失为 ``None``，不填零）。
``completion``
    传输完整性（``StreamCompletion``）与提供方停止原因（``StopKind``）分离。
``pricing``
    ``Decimal`` 版本化价格表与费用估算（缺失即 unknown，绝不当作 0）。
``calls``
    ``logical_call_id`` / ``physical_request_id``、显式重试登记与去重计账。
``reconstruct``
    连接级重建门面（单连接 / 多连接）。

最小用法::

    from agent_probe.llm import Direction, MultiConnectionReconstructor

    reconstructor = MultiConnectionReconstructor(price_table=DEFAULT_PRICE_TABLE)
    reconstructor.feed("conn-1", Direction.CLIENT_TO_SERVER, request_bytes)
    batch = reconstructor.feed("conn-1", Direction.SERVER_TO_CLIENT, response_bytes)
    record = batch.records[0]
    record.usage, record.cost

隐私默认值：消息模型中的敏感头/target 参数在**进入模型时**已被替换为
``<redacted>``；``to_record()`` 是唯一推荐的持久化视图，不含正文。
"""

from __future__ import annotations

from agent_probe.llm.calls import (
    AccountingLedger,
    AccountingSummary,
    CallIdentity,
    LlmCallRecord,
    ModelAggregate,
    RetryCycleError,
    RetryEvidence,
    RetryRegistry,
)
from agent_probe.llm.common import BodyFraming, Direction, MessageKind
from agent_probe.llm.completion import (
    CompletionAnalysis,
    ContentKind,
    PayloadAnalysis,
    StopKind,
    StreamCompletion,
    analyze_payload,
    classify_stop,
)
from agent_probe.llm.diagnostics import Diagnostic, DiagnosticCode, Severity
from agent_probe.llm.http1 import HTTP2_CONNECTION_PREFACE, Http1Parser, ParseBatch, ParserState
from agent_probe.llm.limits import ParserLimits, SseLimits
from agent_probe.llm.messages import (
    REDACTED,
    HeaderRedactionPolicy,
    HttpMessage,
    HttpRequest,
    HttpResponse,
    redact_target,
)
from agent_probe.llm.pricing import (
    DEFAULT_PRICE_TABLE,
    CostComponent,
    CostEstimate,
    CostUnknownReason,
    ModelPrice,
    PriceTable,
    PricingUnit,
    estimate_cost,
)
from agent_probe.llm.reconstruct import (
    ConnectionReconstructor,
    MultiConnectionReconstructor,
    ReconstructionBatch,
    connection_id_for,
)
from agent_probe.llm.sse import DONE_SENTINEL, SseEvent, SseFinish, SseParser
from agent_probe.llm.usage import (
    TokenUsage,
    UsageExtraction,
    UsageStatus,
    extract_usage_from_json,
    extract_usage_from_json_object,
    extract_usage_from_message,
    extract_usage_from_sse_events,
    is_event_stream,
)

__all__ = [
    # common
    "BodyFraming",
    "Direction",
    "MessageKind",
    # diagnostics
    "Diagnostic",
    "DiagnosticCode",
    "Severity",
    # limits
    "ParserLimits",
    "SseLimits",
    # messages
    "REDACTED",
    "HeaderRedactionPolicy",
    "HttpMessage",
    "HttpRequest",
    "HttpResponse",
    "redact_target",
    # http1
    "HTTP2_CONNECTION_PREFACE",
    "Http1Parser",
    "ParseBatch",
    "ParserState",
    # sse
    "DONE_SENTINEL",
    "SseEvent",
    "SseFinish",
    "SseParser",
    # usage
    "TokenUsage",
    "UsageExtraction",
    "UsageStatus",
    "extract_usage_from_json",
    "extract_usage_from_json_object",
    "extract_usage_from_message",
    "extract_usage_from_sse_events",
    "is_event_stream",
    # completion
    "CompletionAnalysis",
    "ContentKind",
    "PayloadAnalysis",
    "StopKind",
    "StreamCompletion",
    "analyze_payload",
    "classify_stop",
    # pricing
    "DEFAULT_PRICE_TABLE",
    "CostComponent",
    "CostEstimate",
    "CostUnknownReason",
    "ModelPrice",
    "PriceTable",
    "PricingUnit",
    "estimate_cost",
    # calls
    "AccountingLedger",
    "AccountingSummary",
    "CallIdentity",
    "LlmCallRecord",
    "ModelAggregate",
    "RetryCycleError",
    "RetryEvidence",
    "RetryRegistry",
    # reconstruct
    "ConnectionReconstructor",
    "MultiConnectionReconstructor",
    "ReconstructionBatch",
    "connection_id_for",
]
