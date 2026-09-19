from __future__ import annotations

import pytest

from agent_probe.evaluation import ConfusionMatrix, binary_metrics, classify, performance_summary, wilson_interval


def test_binary_metrics_keep_all_confusion_cells_and_deterministic_ci() -> None:
    matrix = ConfusionMatrix(true_positive=8, false_positive=2, false_negative=1, true_negative=9)
    metrics = binary_metrics(matrix)
    assert matrix.total == 20
    assert metrics["precision"].numerator == 8
    assert metrics["precision"].denominator == 10
    assert metrics["precision"].value == 0.8
    assert metrics["recall"].value == pytest.approx(8 / 9)
    assert metrics["false_positive_rate"].value == pytest.approx(2 / 11)
    assert metrics["precision"].ci_low == pytest.approx(wilson_interval(8, 10)[0])  # type: ignore[index]


def test_missing_labels_are_reported_not_silently_counted_as_negative() -> None:
    matrix, excluded = classify(((True, True), (False, True), (None, False), (True, None), (False, False)))
    assert matrix == ConfusionMatrix(true_positive=1, false_positive=1, true_negative=1)
    assert excluded == 2


def test_undefined_ratio_is_not_zero() -> None:
    precision = binary_metrics(ConfusionMatrix())['precision']
    assert precision.value is None
    assert precision.denominator == 0
    assert precision.unavailable_reason


def test_performance_quantiles_and_partial_measurements_are_explicit() -> None:
    result = performance_summary(((10.0, 2.0, 100), (20.0, None, 300), (30.0, 6.0, None)))
    assert result.sample_count == 3
    assert result.elapsed_ms_p50 == 20.0
    assert result.elapsed_ms_p95 == pytest.approx(29.0)
    assert result.cpu_time_ms_p50 == 4.0
    assert result.peak_memory_bytes_max == 300


def test_invalid_confusion_counts_and_interval_are_rejected() -> None:
    with pytest.raises(ValueError):
        ConfusionMatrix(true_positive=-1)
    with pytest.raises(ValueError):
        wilson_interval(3, 2)
