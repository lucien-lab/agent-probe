"""M6 实验清单验证：检查计划约束，不捏造缺失运行。"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import StrEnum

from .errors import EvaluationInputError

__all__ = ["ExperimentKind", "ExperimentRun", "ManifestIssue", "validate_manifest"]


class ExperimentKind(StrEnum):
    REAL_TASK = "real_task"
    INJECTED_ANOMALY = "injected_anomaly"
    ABLATION = "ablation"
    PERFORMANCE = "performance"


@dataclass(frozen=True, slots=True)
class ExperimentRun:
    """一个已执行或离线夹具运行；``is_real_agent`` 不能由名称推断。"""
    task_id: str
    agent_id: str
    repetition: int
    kind: ExperimentKind
    input_digest: str | None
    environment_id: str | None
    policy_id: str | None
    model_config_id: str | None
    is_real_agent: bool
    outcome_recorded: bool
    missing_inputs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.task_id or not self.agent_id:
            raise EvaluationInputError("task_id 和 agent_id 不能为空")
        if isinstance(self.repetition, bool) or not isinstance(self.repetition, int) or self.repetition < 1:
            raise EvaluationInputError("repetition 必须是从 1 开始的整数")
        if not isinstance(self.is_real_agent, bool) or not isinstance(self.outcome_recorded, bool):
            raise EvaluationInputError("is_real_agent 与 outcome_recorded 必须是 bool")


@dataclass(frozen=True, slots=True)
class ManifestIssue:
    code: str
    message: str
    task_id: str | None = None
    agent_id: str | None = None


def validate_manifest(runs: list[ExperimentRun], *, required_real_tasks: int = 20,
                      required_agents: int = 2, min_tasks_per_agent: int = 10,
                      min_repetitions: int = 3) -> tuple[ManifestIssue, ...]:
    """校验计划的最低样本门槛，返回问题而非把不完整清单称为通过。"""
    if min(value for value in (required_real_tasks, required_agents, min_tasks_per_agent, min_repetitions)) < 1:
        raise EvaluationInputError("所有最低门槛必须至少为 1")
    issues: list[ManifestIssue] = []
    real = [run for run in runs if run.kind is ExperimentKind.REAL_TASK and run.is_real_agent]
    tasks = {(run.agent_id, run.task_id) for run in real}
    unique_task_ids = {run.task_id for run in real}
    if len(unique_task_ids) < required_real_tasks:
        issues.append(ManifestIssue("real_task_count", f"真实任务数 {len(unique_task_ids)} 小于要求的 {required_real_tasks}"))
    agents = {run.agent_id for run in real}
    if len(agents) < required_agents:
        issues.append(ManifestIssue("agent_count", f"真实 agent 数 {len(agents)} 小于要求的 {required_agents}"))
    per_agent = Counter(agent for agent, _ in tasks)
    for agent in sorted(agents):
        if per_agent[agent] < min_tasks_per_agent:
            issues.append(ManifestIssue("tasks_per_agent", f"agent {agent} 仅有 {per_agent[agent]} 个真实任务", agent_id=agent))
    repetitions = Counter((run.agent_id, run.task_id) for run in real)
    for (agent, task), count in sorted(repetitions.items()):
        if count < min_repetitions:
            issues.append(ManifestIssue("repetitions", f"{agent}/{task} 仅有 {count} 次运行", task, agent))
    for run in runs:
        required = {"input_digest": run.input_digest, "environment_id": run.environment_id,
                    "policy_id": run.policy_id, "model_config_id": run.model_config_id}
        missing = [name for name, value in required.items() if not value] + list(run.missing_inputs)
        if missing:
            issues.append(ManifestIssue("missing_reproducibility_input", f"缺少可复现输入: {', '.join(sorted(set(missing)))}", run.task_id, run.agent_id))
        if not run.outcome_recorded:
            issues.append(ManifestIssue("outcome_missing", "运行结果未记录", run.task_id, run.agent_id))
    return tuple(issues)
