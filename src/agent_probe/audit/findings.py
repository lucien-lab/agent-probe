"""可重算、可解释的审计结论。

审计层不能把未观测到行为写成合规。因此每条 finding 都保留三态 verdict：
``pass``、``violation``、``insufficient_evidence``。后者不是错误或忽略项，报告
必须原样计数和展示。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping, Sequence

from .errors import AuditInputError

__all__ = ["Verdict", "AuditFinding", "stable_finding_id"]


class Verdict(StrEnum):
    PASS = "pass"
    VIOLATION = "violation"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


def _canonical(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise AuditInputError("finding 的证据必须是 JSON 可序列化值") from exc


def stable_finding_id(
    *, rule_id: str, verdict: Verdict | str, event_ids: Sequence[str], evidence: Mapping[str, Any]
) -> str:
    """由已规范化内容生成稳定 ID；输入顺序不会影响同一 finding。"""

    payload = {
        "rule_id": rule_id,
        "verdict": Verdict(verdict).value,
        "event_ids": sorted(set(event_ids)),
        "evidence": evidence,
    }
    return "finding-" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()[:20]


@dataclass(frozen=True, slots=True)
class AuditFinding:
    """某条规则对一组原始事件所得的可解释结论。"""

    finding_id: str
    rule_id: str
    verdict: Verdict
    summary: str
    event_ids: tuple[str, ...]
    evidence: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.rule_id or not self.summary:
            raise AuditInputError("finding 的 rule_id 和 summary 不能为空")
        object.__setattr__(self, "verdict", Verdict(self.verdict))
        normalized_ids = tuple(sorted(set(self.event_ids)))
        if any(not isinstance(item, str) or not item for item in normalized_ids):
            raise AuditInputError("finding 的 event_ids 必须是非空字符串")
        object.__setattr__(self, "event_ids", normalized_ids)
        expected = stable_finding_id(
            rule_id=self.rule_id,
            verdict=self.verdict,
            event_ids=normalized_ids,
            evidence=self.evidence,
        )
        if self.finding_id != expected:
            raise AuditInputError("finding_id 与规范化后的 rule/verdict/evidence 不一致")

    @classmethod
    def create(
        cls,
        *,
        rule_id: str,
        verdict: Verdict | str,
        summary: str,
        event_ids: Sequence[str] = (),
        evidence: Mapping[str, Any] | None = None,
    ) -> "AuditFinding":
        normalized_evidence = {} if evidence is None else dict(evidence)
        normalized_ids = tuple(sorted(set(event_ids)))
        parsed_verdict = Verdict(verdict)
        return cls(
            finding_id=stable_finding_id(
                rule_id=rule_id,
                verdict=parsed_verdict,
                event_ids=normalized_ids,
                evidence=normalized_evidence,
            ),
            rule_id=rule_id,
            verdict=parsed_verdict,
            summary=summary,
            event_ids=normalized_ids,
            evidence=normalized_evidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "verdict": self.verdict.value,
            "summary": self.summary,
            "event_ids": list(self.event_ids),
            "evidence": dict(self.evidence),
        }
