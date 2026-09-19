"""M6 离线对照、性能与实验清单评估。"""

from .errors import EvaluationInputError
from .manifest import ExperimentKind, ExperimentRun, ManifestIssue, validate_manifest
from .metrics import ConfusionMatrix, Metric, PerformanceSummary, binary_metrics, classify, performance_summary, wilson_interval

__all__ = [
    "ConfusionMatrix", "EvaluationInputError", "ExperimentKind", "ExperimentRun", "ManifestIssue",
    "Metric", "PerformanceSummary", "binary_metrics", "classify", "performance_summary",
    "validate_manifest", "wilson_interval",
]
