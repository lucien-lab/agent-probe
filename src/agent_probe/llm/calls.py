"""调用标识、显式重试关系与计账汇总。

标识
----

* ``physical_request_id``：一次**物理** HTTP 请求（一次真实的 TLS 往返）。
* ``logical_call_id``：一组重试共享的**逻辑**调用。

默认情况下两者相同（即"不做任何推断"）。只有调用方**显式**声明关系时才会合并：

* :meth:`RetryRegistry.link_retry`：声明 ``X 是 Y 的重试``，必须给出 reason 与
  evidence（``explicit_caller`` / ``application_marker``）。
* :meth:`RetryRegistry.declare_logical_call`：直接指定某个物理请求的 logical id。

本模块**不**根据时间间隔、请求相似度或状态码自动推断重试；也没有任何"猜测"
入口。理由：M1 明确要求"不要凭时间自动推断重试"，误判会直接污染
"重试单列"这类指标。

防重复计账
----------

:class:`AccountingLedger` 以 ``physical_request_id`` 去重：同一条物理请求被
重复投递（重放、重复事件）时只计一次，并把重复次数单独暴露出来。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from decimal import Decimal
from enum import Enum

from agent_probe.llm.completion import (
    CompletionAnalysis,
    ContentKind,
    PayloadAnalysis,
    StreamCompletion,
)
from agent_probe.llm.diagnostics import Diagnostic
from agent_probe.llm.messages import HttpRequest, HttpResponse
from agent_probe.llm.pricing import CostEstimate
from agent_probe.llm.usage import UsageExtraction, UsageStatus

__all__ = [
    "RetryEvidence",
    "CallIdentity",
    "RetryCycleError",
    "RetryRegistry",
    "LlmCallRecord",
    "ModelAggregate",
    "AccountingSummary",
    "AccountingLedger",
]


class RetryEvidence(str, Enum):
    """重试关系的证据来源。**不存在**"按时间推断"这一档。"""

    NONE = "none"
    EXPLICIT_CALLER = "explicit_caller"
    APPLICATION_MARKER = "application_marker"


class RetryCycleError(ValueError):
    """显式重试关系形成环。"""


@dataclass(frozen=True)
class CallIdentity:
    """一次物理请求的标识与其逻辑调用归属。"""

    physical_request_id: str
    logical_call_id: str
    attempt_index: int = 1
    retry_of: str | None = None
    retry_reason: str | None = None
    retry_evidence: RetryEvidence = RetryEvidence.NONE

    @property
    def is_retry(self) -> bool:
        return self.retry_of is not None

    def to_record(self) -> dict[str, object]:
        return {
            "physical_request_id": self.physical_request_id,
            "logical_call_id": self.logical_call_id,
            "attempt_index": self.attempt_index,
            "retry_of": self.retry_of,
            "retry_reason": self.retry_reason,
            "retry_evidence": self.retry_evidence.value,
            "is_retry": self.is_retry,
        }


@dataclass(frozen=True)
class _RetryLink:
    retry_of: str
    reason: str
    evidence: RetryEvidence


class RetryRegistry:
    """显式重试/逻辑调用登记表。"""

    def __init__(self) -> None:
        self._links: dict[str, _RetryLink] = {}
        self._logical: dict[str, str] = {}

    # ---- 声明 ----

    def declare_logical_call(self, physical_request_id: str, logical_call_id: str) -> None:
        """把某个物理请求显式归属到一个逻辑调用（例如来自应用标记）。"""
        if not physical_request_id or not logical_call_id:
            raise ValueError("physical_request_id 与 logical_call_id 都不能为空")
        self._logical[physical_request_id] = logical_call_id

    def link_retry(
        self,
        *,
        physical_request_id: str,
        retry_of: str,
        reason: str,
        evidence: RetryEvidence = RetryEvidence.EXPLICIT_CALLER,
    ) -> None:
        """显式声明重试关系。必须是调用方提供的证据，不做任何推断。"""
        if not physical_request_id or not retry_of:
            raise ValueError("physical_request_id 与 retry_of 都不能为空")
        if physical_request_id == retry_of:
            raise ValueError("物理请求不能重试自身")
        if evidence is RetryEvidence.NONE:
            raise ValueError("重试关系必须给出证据来源，不能用 NONE")
        if not reason:
            raise ValueError("重试关系必须给出 reason")
        self._links[physical_request_id] = _RetryLink(
            retry_of=retry_of, reason=reason, evidence=evidence
        )

    # ---- 查询 ----

    @property
    def linked_physical_request_ids(self) -> tuple[str, ...]:
        return tuple(self._links)

    def chain(self, physical_request_id: str) -> tuple[str, ...]:
        """返回从**最早**到目标的重试链（唯一向上路径）。"""
        chain = [physical_request_id]
        seen = {physical_request_id}
        current = physical_request_id
        while True:
            link = self._links.get(current)
            if link is None:
                break
            if link.retry_of in seen:
                raise RetryCycleError(f"重试关系成环：{link.retry_of!r} 已在链中")
            seen.add(link.retry_of)
            chain.append(link.retry_of)
            current = link.retry_of
        chain.reverse()
        return tuple(chain)

    def component(self, physical_request_id: str) -> tuple[str, ...]:
        """返回与目标处于同一重试家族的节点（根优先、子节点名排序，确定性）。"""
        root = self.chain(physical_request_id)[0]
        children: dict[str, list[str]] = {}
        for child, link in self._links.items():
            children.setdefault(link.retry_of, []).append(child)
        for values in children.values():
            values.sort()
        order: list[str] = []
        seen: set[str] = set()
        queue = [root]
        while queue:
            node = queue.pop(0)
            if node in seen:
                continue
            seen.add(node)
            order.append(node)
            queue.extend(children.get(node, ()))
        return tuple(order)

    def resolve(self, physical_request_id: str) -> CallIdentity:
        """解析出标识；无显式声明时 ``logical_call_id == physical_request_id``。

        逻辑调用名取**同一重试家族内**第一个被显式声明的名字，否则退化为家族根。
        这样"在某个重试节点上声明 logical id"会覆盖整个家族，不会把一个逻辑
        调用拆成两个。
        """
        chain = self.chain(physical_request_id)
        root = chain[0]
        position = chain.index(physical_request_id)
        family = self.component(physical_request_id)
        logical = next((self._logical[node] for node in family if node in self._logical), root)
        link = self._links.get(physical_request_id)
        return CallIdentity(
            physical_request_id=physical_request_id,
            logical_call_id=logical,
            attempt_index=position + 1,
            retry_of=chain[position - 1] if position > 0 else None,
            retry_reason=None if link is None else link.reason,
            retry_evidence=RetryEvidence.NONE if link is None else link.evidence,
        )


@dataclass(frozen=True)
class LlmCallRecord:
    """一条完整的计账记录：请求 + 响应 + usage + 完整性 + 费用。

    默认持久化视图 :meth:`to_record` 不含任何正文，也不含 Authorization/API key。
    ``request`` 为 ``None`` 表示只捕获到响应（请求捕获缺失），此时该记录**不**计入
    物理请求捕获率分子，只作为缺口证据保留。
    """

    identity: CallIdentity
    connection_id: str
    request: HttpRequest | None = None
    response: HttpResponse | None = None
    analysis: PayloadAnalysis | None = None
    cost: CostEstimate | None = None
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.request is None and self.response is None:
            raise ValueError("LlmCallRecord 至少要有请求或响应之一")

    # ---- 便捷访问器 ----

    @property
    def is_paired(self) -> bool:
        return self.request is not None and self.response is not None

    @property
    def physical_request_id(self) -> str:
        return self.identity.physical_request_id

    @property
    def logical_call_id(self) -> str:
        return self.identity.logical_call_id

    @property
    def request_index(self) -> int | None:
        return None if self.request is None else self.request.message_index

    @property
    def response_index(self) -> int | None:
        return None if self.response is None else self.response.message_index

    @property
    def method(self) -> str | None:
        return None if self.request is None else self.request.method

    @property
    def target(self) -> str | None:
        return None if self.request is None else self.request.target

    @property
    def status_code(self) -> int | None:
        return None if self.response is None else self.response.status_code

    @property
    def usage(self) -> UsageExtraction | None:
        return None if self.analysis is None else self.analysis.usage

    @property
    def completion(self) -> CompletionAnalysis | None:
        return None if self.analysis is None else self.analysis.completion

    @property
    def model(self) -> str | None:
        if self.analysis is not None and self.analysis.model:
            return self.analysis.model
        if self.usage is not None:
            return self.usage.model_name
        return None

    @property
    def is_transport_truncated(self) -> bool:
        completion = self.completion
        return completion is not None and completion.completion is StreamCompletion.TRUNCATED

    def with_identity(self, identity: CallIdentity) -> LlmCallRecord:
        return replace(self, identity=identity)

    def with_cost(self, cost: CostEstimate) -> LlmCallRecord:
        return replace(self, cost=cost)

    def to_record(self) -> dict[str, object]:
        return {
            "identity": self.identity.to_record(),
            "connection_id": self.connection_id,
            "paired": self.is_paired,
            "physical_request_index": self.request_index,
            "response_index": self.response_index,
            "method": self.method,
            "target": self.target,
            "status_code": self.status_code,
            "model": self.model,
            "request": None if self.request is None else self.request.to_record(),
            "response": None if self.response is None else self.response.to_record(),
            "analysis": None if self.analysis is None else self.analysis.to_record(),
            "usage": None if self.usage is None else self.usage.to_record(),
            "completion": None if self.completion is None else self.completion.to_record(),
            "cost": None if self.cost is None else self.cost.to_record(),
            "diagnostics": [d.to_record() for d in self.diagnostics],
        }


@dataclass(frozen=True)
class ModelAggregate:
    """按模型聚合的小计。"""

    model: str
    physical_requests: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    estimated_cost: Decimal | None = None
    cost_complete: bool = False

    def to_record(self) -> dict[str, object]:
        return {
            "model": self.model,
            "physical_requests": self.physical_requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost": None if self.estimated_cost is None else str(self.estimated_cost),
            "cost_complete": self.cost_complete,
        }


@dataclass(frozen=True)
class AccountingSummary:
    """计账汇总。

    * ``estimated_cost is None`` 表示没有任何可计价记录；``cost_complete=False``
      表示存在未知/不完整项，此时 ``estimated_cost`` 只是**下界**。
    * 未知 usage 与截断计数不会被隐藏，且是 M1 指标的分母来源
      （见 :meth:`to_record` 与 docs/01-llm.md）。
    """

    physical_requests: int = 0
    logical_calls: int = 0
    retried_physical_requests: int = 0
    duplicate_physical_requests: int = 0
    requests_with_response: int = 0
    requests_without_response: int = 0
    responses_with_payload: int = 0
    sse_responses: int = 0
    json_responses: int = 0
    usage_present: int = 0
    usage_absent: int = 0
    usage_unparseable: int = 0
    usage_not_captured: int = 0
    transport_truncated: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    cache_read_tokens: int | None = None
    cache_write_tokens: int | None = None
    reasoning_tokens: int | None = None
    estimated_cost: Decimal | None = None
    cost_complete: bool = False
    unpriced_physical_requests: int = 0
    currency: str | None = None
    price_table_version: str | None = None
    by_model: tuple[ModelAggregate, ...] = ()

    @property
    def usage_known(self) -> int:
        return self.usage_present

    def to_record(self) -> dict[str, object]:
        return {
            "physical_requests": self.physical_requests,
            "logical_calls": self.logical_calls,
            "retried_physical_requests": self.retried_physical_requests,
            "duplicate_physical_requests": self.duplicate_physical_requests,
            "requests_with_response": self.requests_with_response,
            "requests_without_response": self.requests_without_response,
            "responses_with_payload": self.responses_with_payload,
            "sse_responses": self.sse_responses,
            "json_responses": self.json_responses,
            "usage_present": self.usage_present,
            "usage_absent": self.usage_absent,
            "usage_unparseable": self.usage_unparseable,
            "usage_not_captured": self.usage_not_captured,
            "transport_truncated": self.transport_truncated,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "estimated_cost": None if self.estimated_cost is None else str(self.estimated_cost),
            "cost_complete": self.cost_complete,
            "unpriced_physical_requests": self.unpriced_physical_requests,
            "currency": self.currency,
            "price_table_version": self.price_table_version,
            "by_model": [entry.to_record() for entry in self.by_model],
        }


def _sum_observed(values: list[int | None]) -> int | None:
    observed = [value for value in values if value is not None]
    if not observed:
        return None
    return sum(observed)


class AccountingLedger:
    """按 ``physical_request_id`` 去重的计账账本。"""

    def __init__(self, *, retry_registry: RetryRegistry | None = None) -> None:
        self._retry_registry = retry_registry if retry_registry is not None else RetryRegistry()
        self._records: list[LlmCallRecord] = []
        self._seen: set[str] = set()
        self._duplicates = 0

    @property
    def retry_registry(self) -> RetryRegistry:
        return self._retry_registry

    @property
    def records(self) -> tuple[LlmCallRecord, ...]:
        return tuple(self._records)

    @property
    def duplicate_physical_requests(self) -> int:
        return self._duplicates

    def record(self, call: LlmCallRecord) -> bool:
        """记录一条调用；重复的 ``physical_request_id`` 返回 ``False`` 且不重复计账。"""
        key = call.identity.physical_request_id
        if key in self._seen:
            self._duplicates += 1
            return False
        self._seen.add(key)
        self._records.append(call.with_identity(self._retry_registry.resolve(key)))
        return True

    def extend(self, calls: list[LlmCallRecord] | tuple[LlmCallRecord, ...]) -> int:
        return sum(1 for call in calls if self.record(call))

    def summary(self) -> AccountingSummary:
        records = self._records
        price_table_version: str | None = None
        currency: str | None = None
        for record in records:
            if record.cost is not None:
                price_table_version = record.cost.price_table_version
                currency = record.cost.currency
                break

        usage_statuses = [record.usage.status if record.usage is not None else None for record in records]
        costs = [record.cost for record in records]
        complete_costs = [
            cost.total_cost for cost in costs if cost is not None and cost.complete and cost.total_cost is not None
        ]
        estimated_cost = sum(complete_costs, Decimal(0)) if complete_costs else None
        unpriced = sum(1 for cost in costs if cost is None or not cost.complete)

        input_values: list[int | None] = []
        output_values: list[int | None] = []
        total_values: list[int | None] = []
        cache_read_values: list[int | None] = []
        cache_write_values: list[int | None] = []
        reasoning_values: list[int | None] = []
        for record in records:
            usage = record.usage
            value = usage.usage if usage is not None and usage.present else None
            input_values.append(None if value is None else value.input_tokens)
            output_values.append(None if value is None else value.output_tokens)
            total_values.append(None if value is None else value.total_tokens)
            cache_read_values.append(None if value is None else value.cache_read_tokens)
            cache_write_values.append(None if value is None else value.cache_write_tokens)
            reasoning_values.append(None if value is None else value.reasoning_tokens)

        by_model: list[ModelAggregate] = []
        for model in sorted({record.model for record in records if record.model}):
            subset = [record for record in records if record.model == model]
            subset_complete = [
                record.cost.total_cost
                for record in subset
                if record.cost is not None and record.cost.complete and record.cost.total_cost is not None
            ]
            by_model.append(
                ModelAggregate(
                    model=model,
                    physical_requests=len(subset),
                    input_tokens=_sum_observed(
                        [None if r.usage is None or not r.usage.present else r.usage.usage.input_tokens for r in subset]
                    ),
                    output_tokens=_sum_observed(
                        [None if r.usage is None or not r.usage.present else r.usage.usage.output_tokens for r in subset]
                    ),
                    total_tokens=_sum_observed(
                        [None if r.usage is None or not r.usage.present else r.usage.usage.total_tokens for r in subset]
                    ),
                    estimated_cost=sum(subset_complete, Decimal(0)) if subset_complete else None,
                    cost_complete=bool(subset) and all(
                        record.cost is not None and record.cost.complete for record in subset
                    ),
                )
            )

        return AccountingSummary(
            physical_requests=len(records),
            logical_calls=len({record.identity.logical_call_id for record in records}),
            retried_physical_requests=sum(1 for record in records if record.identity.is_retry),
            duplicate_physical_requests=self._duplicates,
            requests_with_response=sum(1 for record in records if record.response is not None),
            requests_without_response=sum(1 for record in records if record.response is None),
            responses_with_payload=sum(
                1
                for record in records
                if record.response is not None and record.response.payload_complete
            ),
            sse_responses=sum(
                1
                for record in records
                if record.analysis is not None and record.analysis.content_kind is ContentKind.SSE
            ),
            json_responses=sum(
                1
                for record in records
                if record.analysis is not None and record.analysis.content_kind is ContentKind.JSON
            ),
            usage_present=sum(1 for status in usage_statuses if status is UsageStatus.PRESENT),
            usage_absent=sum(1 for status in usage_statuses if status is UsageStatus.ABSENT),
            usage_unparseable=sum(1 for status in usage_statuses if status is UsageStatus.UNPARSEABLE),
            usage_not_captured=sum(1 for status in usage_statuses if status is UsageStatus.NOT_CAPTURED),
            transport_truncated=sum(1 for record in records if record.is_transport_truncated),
            input_tokens=_sum_observed(input_values),
            output_tokens=_sum_observed(output_values),
            total_tokens=_sum_observed(total_values),
            cache_read_tokens=_sum_observed(cache_read_values),
            cache_write_tokens=_sum_observed(cache_write_values),
            reasoning_tokens=_sum_observed(reasoning_values),
            estimated_cost=estimated_cost,
            cost_complete=bool(records) and unpriced == 0,
            unpriced_physical_requests=unpriced,
            currency=currency,
            price_table_version=price_table_version,
            by_model=tuple(by_model),
        )
