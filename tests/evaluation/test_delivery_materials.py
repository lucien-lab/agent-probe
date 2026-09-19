from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_m6_manifest_template_is_valid_json_and_declares_all_required_studies() -> None:
    manifest = json.loads((ROOT / "docs/benchmark-manifest.example.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["execution_status"] == "planned"
    assert manifest["requirements"] == {
        "unique_real_task_ids": 20,
        "real_agents": 2,
        "tasks_per_agent": 10,
        "repetitions_per_agent_task": 3,
        "comparison_arms": ["application_logs", "external_only", "external_with_markers"],
        "anomaly_categories": ["subprocess", "container", "concurrency_2_and_5", "temporary_file_replacement", "retry", "stream_interruption", "overload", "out_of_bounds"],
        "ablation_stages": ["time_window", "process_lineage", "container_mapping", "auxiliary_markers"],
        "performance_profiles": ["no_probe", "system_probe", "system_probe_tls", "full_audit", "control_enabled"],
    }
    agents = manifest["agents"]
    assert len(agents) == 2
    assert {slot for agent in agents for slot in agent["task_slots"]} == {f"task-{index:02d}" for index in range(1, 21)}
    template = manifest["run_record_template"]
    assert template["outcome_recorded"] is False
    assert set(template["artifact_paths"]) == {"input", "raw_events", "truth", "result", "failure"}


def test_m6_docs_explicitly_separate_templates_from_unrun_claims_and_real_kernel_evidence() -> None:
    evaluation = (ROOT / "docs/evaluation.md").read_text(encoding="utf-8")
    demo = (ROOT / "docs/demo.md").read_text(encoding="utf-8")
    for text in (evaluation, demo):
        assert "不得" in text
        assert "真实" in text
    assert "不会读取 JSON" in " ".join(evaluation.split())
    assert "辅助标记不得是唯一真值" in evaluation
    assert "真实系统调用返回和保护文件内容不变" in demo
    assert "没有加载内核 BPF" in demo
