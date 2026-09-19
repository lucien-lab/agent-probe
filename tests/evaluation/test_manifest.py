from __future__ import annotations

from agent_probe.evaluation import ExperimentKind, ExperimentRun, validate_manifest


def run(task: str, repetition: int, *, agent: str = "agent-a", real: bool = True, digest: str | None = "sha256:x") -> ExperimentRun:
    return ExperimentRun(task, agent, repetition, ExperimentKind.REAL_TASK, digest, "ubuntu-arm64", "policy-v1", "model-v1", real, True)


def test_manifest_flags_incomplete_real_task_plan_without_claiming_success() -> None:
    issues = validate_manifest([run("one", 1), run("one", 2)], required_real_tasks=2, required_agents=2,
        min_tasks_per_agent=1, min_repetitions=3)
    assert {issue.code for issue in issues} >= {"real_task_count", "agent_count", "repetitions"}


def test_manifest_accepts_complete_small_reproducible_plan() -> None:
    runs = [run("one", repetition, agent="agent-a") for repetition in range(1, 4)]
    runs += [run("two", repetition, agent="agent-b") for repetition in range(1, 4)]
    assert validate_manifest(runs, required_real_tasks=2, required_agents=2, min_tasks_per_agent=1, min_repetitions=3) == ()


def test_fixture_is_not_counted_as_real_agent_and_missing_inputs_are_visible() -> None:
    fixture = run("fixture", 1, real=False, digest=None)
    issues = validate_manifest([fixture], required_real_tasks=1, required_agents=1, min_tasks_per_agent=1, min_repetitions=1)
    assert {issue.code for issue in issues} >= {"real_task_count", "agent_count", "missing_reproducibility_input"}
