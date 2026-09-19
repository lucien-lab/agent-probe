"""可复现的二分类与性能指标。

本模块只从调用方给出的真值和预测计算指标；它不会把未观测事件、未知标签或
离线夹具冒充为真实 agent 的结果。置信区间采用确定性的 Wilson score interval，
不依赖随机 bootstrap，因此相同输入必定得到相同输出。
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .errors import EvaluationInputError

__all__ = [
    "ConfusionMatrix", "Metric", "PerformanceSummary", "binary_metrics",
    "classify", "performance_summary", "wilson_interval",
]


@dataclass(frozen=True, slots=True)
class ConfusionMatrix:
    """二分类混淆矩阵，四格始终显式保留。"""

    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    true_negative: int = 0

    def __post_init__(self) -> None:
        for name in ("true_positive", "false_positive", "false_negative", "true_negative"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EvaluationInputError(f"{name} 必须是非负整数")

    @property
    def total(self) -> int:
        return self.true_positive + self.false_positive + self.false_negative + self.true_negative


@dataclass(frozen=True, slots=True)
class Metric:
    """一个比例指标及其 Wilson 置信区间。

    当分母为零，``value`` 和区间为 ``None``；这不是 0，也不是通过。
    """

    numerator: int
    denominator: int
    value: float | None
    ci_low: float | None
    ci_high: float | None
    unavailable_reason: str | None = None


def wilson_interval(successes: int, trials: int, *, z: float = 1.959963984540054) -> tuple[float, float] | None:
    """返回双侧约 95% Wilson score 区间；``trials=0`` 返回 ``None``。"""
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (successes, trials)):
        raise EvaluationInputError("successes 和 trials 必须是非负整数")
    if successes > trials:
        raise EvaluationInputError("successes 不能大于 trials")
    if trials == 0:
        return None
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    radius = z * math.sqrt((p * (1 - p) + z * z / (4 * trials)) / trials) / denominator
    return (max(0.0, centre - radius), min(1.0, centre + radius))


def _metric(numerator: int, denominator: int, *, undefined: str) -> Metric:
    interval = wilson_interval(numerator, denominator)
    if interval is None:
        return Metric(numerator, denominator, None, None, None, undefined)
    return Metric(numerator, denominator, numerator / denominator, *interval)


def binary_metrics(matrix: ConfusionMatrix) -> Mapping[str, Metric]:
    """计算 precision、recall、FPR、specificity、accuracy；绝不隐藏 TN。"""
    tp, fp, fn, tn = matrix.true_positive, matrix.false_positive, matrix.false_negative, matrix.true_negative
    return {
        "precision": _metric(tp, tp + fp, undefined="没有预测为阳性的样本"),
        "recall": _metric(tp, tp + fn, undefined="没有真值阳性的样本"),
        "false_positive_rate": _metric(fp, fp + tn, undefined="没有真值阴性的样本"),
        "specificity": _metric(tn, fp + tn, undefined="没有真值阴性的样本"),
        "accuracy": _metric(tp + tn, matrix.total, undefined="没有已标注样本"),
    }


def classify(labels: Iterable[tuple[bool | None, bool | None]]) -> tuple[ConfusionMatrix, int]:
    """从 ``(truth, prediction)`` 计算矩阵与排除数。

    ``None`` 必须代表缺失，不会被强行归进 TN；返回的第二项是缺失真值或预测的
    样本数，调用方应写入报告。
    """
    tp = fp = fn = tn = missing = 0
    for truth, prediction in labels:
        if truth is None or prediction is None:
            missing += 1
        elif not isinstance(truth, bool) or not isinstance(prediction, bool):
            raise EvaluationInputError("标签只能是 bool 或 None")
        elif truth and prediction:
            tp += 1
        elif prediction:
            fp += 1
        elif truth:
            fn += 1
        else:
            tn += 1
    return ConfusionMatrix(tp, fp, fn, tn), missing


@dataclass(frozen=True, slots=True)
class PerformanceSummary:
    """性能样本汇总，单位由字段名固定，样本不足时保留原因。"""

    sample_count: int
    elapsed_ms_p50: float | None
    elapsed_ms_p95: float | None
    cpu_time_ms_p50: float | None
    cpu_time_ms_p95: float | None
    peak_memory_bytes_max: int | None
    unavailable_reason: str | None = None


def _quantile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    # 线性插值定义与 statistics.quantiles/numpy 默认差异无关，跨版本稳定。
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] if lower == upper else ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def performance_summary(samples: Iterable[tuple[float | None, float | None, int | None]]) -> PerformanceSummary:
    """汇总 ``(elapsed_ms, cpu_time_ms, peak_memory_bytes)``，三项缺失逐样本剔除。"""
    frozen = list(samples)
    elapsed = [float(item[0]) for item in frozen if item[0] is not None]
    cpu = [float(item[1]) for item in frozen if item[1] is not None]
    memory = [item[2] for item in frozen if item[2] is not None]
    for value in elapsed + cpu:
        if not math.isfinite(value) or value < 0:
            raise EvaluationInputError("耗时与 CPU 时间必须是有限的非负数")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in memory):
        raise EvaluationInputError("峰值内存必须是非负整数或 None")
    reason = None if frozen else "没有性能样本"
    return PerformanceSummary(len(frozen), _quantile(elapsed, .5), _quantile(elapsed, .95),
        _quantile(cpu, .5), _quantile(cpu, .95), max(memory) if memory else None, reason)
