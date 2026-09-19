"""连接级重建：把两个方向的字节流拼成 LLM 调用记录。

一条 TLS 连接 = 两个 :class:`~agent_probe.llm.http1.Http1Parser`
（请求方向 / 响应方向）+ 一个待配对请求队列。产出顺序完全由"消息边界"决定：

* 请求方向每产出一条请求消息，就分配一个**确定性**的 ``physical_request_id``
  （``f"{connection_id}:req:{request_index}"``）并入队，同时把方法登记给响应
  解析器（用于 HEAD / CONNECT 分帧判定）。
* 响应方向每产出一条非 1xx 响应消息，就与队首请求配对，产出一条
  :class:`~agent_probe.llm.calls.LlmCallRecord`。连接复用时同一连接上的多次
  往返会**按序连续**产出，不会串味。
* 响应方向先到（请求未被捕获）时，产出 ``request=None`` 的记录并给出
  ``RESPONSE_WITHOUT_REQUEST`` 诊断；连接结束时仍有未配对请求，则产出
  ``response=None`` 的记录与 ``REQUEST_WITHOUT_RESPONSE`` 诊断。两种情况都
  显式暴露捕获缺口，不会静默丢弃。

本模块不做重试推断；重试关系只能由调用方通过
:class:`~agent_probe.llm.calls.RetryRegistry` 显式声明。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable

from agent_probe.llm.calls import CallIdentity, LlmCallRecord, RetryRegistry
from agent_probe.llm.common import Direction
from agent_probe.llm.completion import PayloadAnalysis, analyze_payload
from agent_probe.llm.diagnostics import Diagnostic, DiagnosticCode
from agent_probe.llm.http1 import Http1Parser
from agent_probe.llm.limits import ParserLimits, SseLimits
from agent_probe.llm.messages import (
    HeaderRedactionPolicy,
    HttpMessage,
    HttpRequest,
    HttpResponse,
)
from agent_probe.llm.pricing import CostEstimate, PriceTable, estimate_cost

__all__ = [
    "ReconstructionBatch",
    "ConnectionReconstructor",
    "MultiConnectionReconstructor",
    "connection_id_for",
]


def connection_id_for(sequence: int) -> str:
    """确定性连接标识（从 1 开始），便于回放测试复现。"""
    if sequence < 1:
        raise ValueError("sequence 从 1 开始")
    return f"conn-{sequence}"


@dataclass(frozen=True)
class ReconstructionBatch:
    """一次 ``feed``/``finish`` 的产出。"""

    messages: tuple[HttpMessage, ...] = ()
    records: tuple[LlmCallRecord, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()

    def __bool__(self) -> bool:  # pragma: no cover - 便捷判断
        return bool(self.messages or self.records or self.diagnostics)


@dataclass
class _PendingRequest:
    identity: CallIdentity
    request: HttpRequest


class ConnectionReconstructor:
    """单条连接（一个 TLS 生命周期）的重建器。"""

    def __init__(
        self,
        connection_id: str = "conn-1",
        *,
        limits: ParserLimits | None = None,
        redaction: HeaderRedactionPolicy | None = None,
        price_table: PriceTable | None = None,
        sse_limits: SseLimits | None = None,
        retry_registry: RetryRegistry | None = None,
    ) -> None:
        if not connection_id:
            raise ValueError("connection_id 不能为空")
        self._connection_id = connection_id
        self._limits = limits if limits is not None else ParserLimits()
        self._redaction = redaction if redaction is not None else HeaderRedactionPolicy()
        self._price_table = price_table
        self._sse_limits = sse_limits
        self._retry_registry = retry_registry
        self._request_parser = Http1Parser(
            Direction.CLIENT_TO_SERVER, limits=self._limits, redaction=self._redaction
        )
        self._response_parser = Http1Parser(
            Direction.SERVER_TO_CLIENT, limits=self._limits, redaction=self._redaction
        )
        self._pending: deque[_PendingRequest] = deque()
        self._records: list[LlmCallRecord] = []
        self._diagnostics: list[Diagnostic] = []
        self._finished = False

    # ------------------------------------------------------------------
    # 属性
    # ------------------------------------------------------------------

    @property
    def connection_id(self) -> str:
        return self._connection_id

    @property
    def request_parser(self) -> Http1Parser:
        return self._request_parser

    @property
    def response_parser(self) -> Http1Parser:
        return self._response_parser

    @property
    def records(self) -> tuple[LlmCallRecord, ...]:
        return tuple(self._records)

    @property
    def diagnostics(self) -> tuple[Diagnostic, ...]:
        return tuple(self._diagnostics)

    @property
    def pending_request_count(self) -> int:
        return len(self._pending)

    @property
    def finished(self) -> bool:
        return self._finished

    # ------------------------------------------------------------------
    # 公开 API
    # ------------------------------------------------------------------

    def feed(self, direction: Direction, data: bytes | bytearray | memoryview) -> ReconstructionBatch:
        """按方向喂入任意分片。"""
        if self._finished:
            raise RuntimeError("连接已 finish，不能继续 feed")
        if not isinstance(direction, Direction):
            direction = Direction(direction)
        parser = self._request_parser if direction.is_request_direction else self._response_parser
        batch = parser.feed(data)
        messages: list[HttpMessage] = []
        records: list[LlmCallRecord] = []
        diagnostics = list(batch.diagnostics)
        for message in batch.messages:
            messages.append(message)
            records.extend(self._handle_message(message, diagnostics))
        self._records.extend(records)
        self._diagnostics.extend(diagnostics)
        return ReconstructionBatch(tuple(messages), tuple(records), tuple(diagnostics))

    def finish(self) -> ReconstructionBatch:
        """连接结束：冲刷两个方向并产出未配对请求的记录。"""
        if self._finished:
            return ReconstructionBatch()
        self._finished = True
        records: list[LlmCallRecord] = []
        diagnostics: list[Diagnostic] = []
        messages: list[HttpMessage] = []
        for parser in (self._request_parser, self._response_parser):
            batch = parser.finish()
            messages.extend(batch.messages)
            diagnostics.extend(batch.diagnostics)
            for message in batch.messages:
                records.extend(self._handle_message(message, diagnostics))
        while self._pending:
            pending = self._pending.popleft()
            diagnostic = Diagnostic.create(
                DiagnosticCode.REQUEST_WITHOUT_RESPONSE,
                "连接结束时该物理请求仍未配对到响应",
                direction=Direction.SERVER_TO_CLIENT,
                message_index=pending.request.message_index,
            )
            diagnostics.append(diagnostic)
            records.append(
                self._build_record(
                    pending.identity, pending.request, response=None, extra=(diagnostic,)
                )
            )
        self._records.extend(records)
        self._diagnostics.extend(diagnostics)
        return ReconstructionBatch(tuple(messages), tuple(records), tuple(diagnostics))

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    def _handle_message(
        self, message: HttpMessage, diagnostics: list[Diagnostic]
    ) -> list[LlmCallRecord]:
        if isinstance(message, HttpRequest):
            physical_request_id = f"{self._connection_id}:req:{message.message_index}"
            identity = (
                self._retry_registry.resolve(physical_request_id)
                if self._retry_registry is not None
                else CallIdentity(
                    physical_request_id=physical_request_id, logical_call_id=physical_request_id
                )
            )
            self._pending.append(_PendingRequest(identity=identity, request=message))
            # 供响应方向判定 HEAD / CONNECT：必须与产出同序。
            self._response_parser.register_request(message.method)
            return []
        assert isinstance(message, HttpResponse)
        if message.is_informational:
            return []
        pending = self._pending.popleft() if self._pending else None
        if pending is None:
            diagnostic = Diagnostic.create(
                DiagnosticCode.RESPONSE_WITHOUT_REQUEST,
                "响应没有对应的已捕获请求（请求方向捕获缺口）",
                direction=Direction.CLIENT_TO_SERVER,
                message_index=message.message_index,
            )
            diagnostics.append(diagnostic)
            identity = CallIdentity(
                physical_request_id=f"{self._connection_id}:unmatched-response:{message.message_index}",
                logical_call_id=f"{self._connection_id}:unmatched-response:{message.message_index}",
            )
            return [self._build_record(identity, None, message, (diagnostic,))]
        return [self._build_record(pending.identity, pending.request, message, ())]

    def _build_record(
        self,
        identity: CallIdentity,
        request: HttpRequest | None,
        response: HttpResponse | None,
        extra: Iterable[Diagnostic],
    ) -> LlmCallRecord:
        analysis: PayloadAnalysis | None = None
        cost: CostEstimate | None = None
        if response is not None:
            analysis = analyze_payload(response, sse_limits=self._sse_limits)
            if self._price_table is not None:
                cost = estimate_cost(
                    usage=analysis.usage.usage,
                    usage_status=analysis.usage.status,
                    price_table=self._price_table,
                    model=analysis.model,
                )
        diagnostics: list[Diagnostic] = []
        if request is not None:
            diagnostics.extend(request.diagnostics)
        if response is not None:
            diagnostics.extend(response.diagnostics)
        if analysis is not None:
            diagnostics.extend(analysis.diagnostics)
        diagnostics.extend(extra)
        return LlmCallRecord(
            identity=identity,
            connection_id=self._connection_id,
            request=request,
            response=response,
            analysis=analysis,
            cost=cost,
            diagnostics=tuple(diagnostics),
        )


class MultiConnectionReconstructor:
    """按 ``connection_id`` 复用 :class:`ConnectionReconstructor` 的门面。

    对应 M1 的"按 TLS 连接生命周期维护状态"：每条连接独立的分帧状态与请求序号，
    连接之间不共享缓冲，也不会把一条连接的字节粘到另一条。
    """

    def __init__(
        self,
        *,
        limits: ParserLimits | None = None,
        redaction: HeaderRedactionPolicy | None = None,
        price_table: PriceTable | None = None,
        sse_limits: SseLimits | None = None,
        retry_registry: RetryRegistry | None = None,
    ) -> None:
        self._limits = limits
        self._redaction = redaction
        self._price_table = price_table
        self._sse_limits = sse_limits
        self._retry_registry = retry_registry
        self._connections: dict[str, ConnectionReconstructor] = {}
        self._records: list[LlmCallRecord] = []

    @property
    def connection_ids(self) -> tuple[str, ...]:
        return tuple(self._connections)

    @property
    def records(self) -> tuple[LlmCallRecord, ...]:
        return tuple(self._records)

    def connection(self, connection_id: str) -> ConnectionReconstructor:
        existing = self._connections.get(connection_id)
        if existing is None:
            existing = ConnectionReconstructor(
                connection_id,
                limits=self._limits,
                redaction=self._redaction,
                price_table=self._price_table,
                sse_limits=self._sse_limits,
                retry_registry=self._retry_registry,
            )
            self._connections[connection_id] = existing
        return existing

    def feed(
        self, connection_id: str, direction: Direction, data: bytes | bytearray | memoryview
    ) -> ReconstructionBatch:
        batch = self.connection(connection_id).feed(direction, data)
        self._records.extend(batch.records)
        return batch

    def close(self, connection_id: str) -> ReconstructionBatch:
        """结束一条连接（TCP/TLS 关闭）。未知连接返回空批次。"""
        reconstructor = self._connections.get(connection_id)
        if reconstructor is None:
            return ReconstructionBatch()
        batch = reconstructor.finish()
        self._records.extend(batch.records)
        return batch

    def close_all(self) -> tuple[ReconstructionBatch, ...]:
        return tuple(self.close(connection_id) for connection_id in tuple(self._connections))
