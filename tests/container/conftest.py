"""``tests/container`` 共享夹具。

设计原则：

* **不执行 docker、不联网、不依赖宿主平台**：容器真值全部来自
  ``fake_container_query.FakeContainerQuery`` 的内存数据。
* **确定性**：时间用显式常量（``BASE_NS``），``observed_monotonic_ns`` 由测试传入，
  不出现 ``time.time()`` 或随机值。
* **显式期望**：期望值在测试里独立声明，不复用被测代码的默认值。
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from agent_probe.container import ContainerTaskMapper

from fake_container_query import LABEL, LABEL_KEY, FakeContainerQuery, inspect_payload

#: 每个映射都显式使用的观测时刻（单调时钟纳秒）。
NOW_NS = 9_000_000_000


@pytest.fixture
def now_ns() -> int:
    return NOW_NS


@pytest.fixture
def label() -> str:
    return LABEL


@pytest.fixture
def label_key() -> str:
    return LABEL_KEY


@pytest.fixture
def fake_query() -> FakeContainerQuery:
    """默认 fake 查询：一个 running 容器带标准任务标签，无挂载。"""

    return FakeContainerQuery()


@pytest.fixture
def make_mapper() -> Callable[..., ContainerTaskMapper]:
    """构造 :class:`ContainerTaskMapper`（可覆盖 label_key / max_candidates）。"""

    def _make(query: object, **kwargs: object) -> ContainerTaskMapper:
        return ContainerTaskMapper(query, **kwargs)  # type: ignore[arg-type]

    return _make


@pytest.fixture
def single_container_query() -> FakeContainerQuery:
    """一个 running 容器 + 标准标签的 fake 查询。"""

    query = FakeContainerQuery()
    query.add(inspect_payload("1" * 64, labels={LABEL_KEY: LABEL}))
    return query
