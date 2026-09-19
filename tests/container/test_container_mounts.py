"""挂载视图解析：目录边界、最长前缀、双向 round-trip、不可映射必须返回 None。"""

from __future__ import annotations

from typing import Any

import pytest

from agent_probe.container import (
    ContainerMapping,
    ContainerMount,
    ContainerState,
    ContainerValidationError,
    MappingOutcome,
    MountResolver,
    MountType,
    is_clean_absolute_path,
    join_path,
    normalize_path,
    relative_to,
)

from fake_container_query import LABEL, container_id

FULL_ID = container_id(0xA1)


def bind(source: str, destination: str, *, rw: bool = True) -> ContainerMount:
    return ContainerMount(
        mount_type=MountType.BIND,
        source=source,
        destination=destination,
        read_write=rw,
        raw_type="bind",
    )


def volume(source: str, destination: str, *, rw: bool = True) -> ContainerMount:
    return ContainerMount(
        mount_type=MountType.VOLUME,
        source=source,
        destination=destination,
        read_write=rw,
        raw_type="volume",
    )


def tmpfs(destination: str) -> ContainerMount:
    return ContainerMount(
        mount_type=MountType.TMPFS,
        source=None,
        destination=destination,
        read_write=True,
        raw_type="tmpfs",
    )


def other(source: str | None, destination: str, *, raw_type: str = "npipe") -> ContainerMount:
    return ContainerMount(
        mount_type=MountType.OTHER,
        source=source,
        destination=destination,
        read_write=True,
        raw_type=raw_type,
    )


# --------------------------------------------------------------------------- #
# 路径原语
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/data/", "/data"),
        ("/data//x", "/data/x"),
        ("/data/./x", "/data/x"),
        ("/", "/"),
        ("//", "/"),
    ],
)
def test_normalize_path_cleans_cosmetic_variants(path: str, expected: str) -> None:
    normalized, reason = normalize_path(path, what="p")
    assert normalized == expected
    assert reason is None


@pytest.mark.parametrize(
    "path",
    ["", "relative/path", "/data/../etc", "/..", "a/b", "\x00/data"],
)
def test_normalize_path_rejects_unmappable_input(path: str) -> None:
    normalized, reason = normalize_path(path, what="p")
    assert normalized is None
    assert reason


def test_normalize_path_reports_non_string() -> None:
    normalized, reason = normalize_path(42, what="p")  # type: ignore[arg-type]
    assert normalized is None
    assert reason is not None and "int" in reason


@pytest.mark.parametrize(
    ("child", "parent", "expected"),
    [
        ("/data", "/data", ""),
        ("/data/x", "/data", "x"),
        ("/data/x/y", "/data", "x/y"),
        ("/database", "/data", None),
        ("/database/x", "/data", None),
        ("/data", "/", "data"),
        ("/", "/", ""),
        ("/other", "/data", None),
    ],
)
def test_relative_to_respects_directory_boundary(
    child: str, parent: str, expected: str | None
) -> None:
    assert relative_to(child, parent) == expected


def test_relative_to_rejects_unclean_inputs() -> None:
    with pytest.raises(ContainerValidationError):
        relative_to("/data/", "/data")


def test_join_path_keeps_root_single_slash() -> None:
    assert join_path("/host", "x") == "/host/x"
    assert join_path("/host", "") == "/host"
    assert join_path("/", "x") == "/x"


def test_is_clean_absolute_path() -> None:
    assert is_clean_absolute_path("/")
    assert is_clean_absolute_path("/data/x")
    assert not is_clean_absolute_path("/data/")
    assert not is_clean_absolute_path("/data//x")
    assert not is_clean_absolute_path("/data/../x")
    assert not is_clean_absolute_path("data")
    assert not is_clean_absolute_path("")


# --------------------------------------------------------------------------- #
# 容器内 → 宿主
# --------------------------------------------------------------------------- #


def test_bind_mount_maps_container_path_to_host() -> None:
    resolver = MountResolver([bind("/host/data", "/data")], container_id=FULL_ID)
    assert resolver.container_to_host("/data/report.json") == "/host/data/report.json"
    assert resolver.container_to_host("/data") == "/host/data"
    assert resolver.to_host("/data/sub/") == "/host/data/sub"


def test_volume_mount_maps_container_path_to_host() -> None:
    resolver = MountResolver(
        [volume("/var/lib/docker/volumes/task/_data", "/work")]
    )
    assert resolver.to_host("/work/a.txt") == "/var/lib/docker/volumes/task/_data/a.txt"


def test_directory_boundary_data_does_not_match_database() -> None:
    resolver = MountResolver([bind("/host/data", "/data")])
    assert resolver.to_host("/database/x") is None
    assert any("/database/x 不在任何挂载" in note for note in resolver.evidence)


def test_longest_destination_wins() -> None:
    resolver = MountResolver(
        [
            bind("/host/data", "/data"),
            bind("/host/special", "/data/special"),
        ]
    )
    assert resolver.to_host("/data/special/x") == "/host/special/x"
    assert resolver.to_host("/data/other") == "/host/data/other"


def test_duplicate_destination_is_ambiguous_not_first_match() -> None:
    resolver = MountResolver(
        [bind("/host/a", "/data"), bind("/host/b", "/data")]
    )
    assert resolver.to_host("/data/x") is None
    assert any("无法唯一确定" in note for note in resolver.evidence)


def test_tmpfs_is_unmappable_with_reason() -> None:
    resolver = MountResolver([tmpfs("/tmp/cache")])
    assert resolver.to_host("/tmp/cache/x") is None
    assert any("tmpfs" in note for note in resolver.evidence)


def test_other_mount_type_is_unmappable_with_reason() -> None:
    resolver = MountResolver([other("/host/pipe", "/pipe", raw_type="npipe")])
    assert resolver.to_host("/pipe/x") is None
    assert any("other" in note and "npipe" in note for note in resolver.evidence)


def test_bind_without_source_is_unmappable_with_reason() -> None:
    resolver = MountResolver(
        [
            ContainerMount(
                mount_type=MountType.BIND,
                source=None,
                destination="/data",
                read_write=True,
                raw_type="bind",
            )
        ]
    )
    assert resolver.to_host("/data/x") is None
    assert any("没有宿主 source" in note for note in resolver.evidence)


def test_container_path_not_under_any_mount_returns_none() -> None:
    resolver = MountResolver([bind("/host/data", "/data")])
    assert resolver.to_host("/etc/passwd") is None
    assert any("/etc/passwd 不在任何挂载" in note for note in resolver.evidence)


@pytest.mark.parametrize("path", ["relative/path", "/data/../etc", ""])
def test_unmappable_container_paths_return_none_with_reason(path: str) -> None:
    resolver = MountResolver([bind("/host/data", "/data")])
    assert resolver.to_host(path) is None
    assert resolver.evidence


def test_empty_mount_list_maps_nothing() -> None:
    resolver = MountResolver(())
    assert resolver.to_host("/data/x") is None
    assert resolver.to_container("/host/data/x") is None


def test_non_string_path_returns_none_with_reason() -> None:
    resolver = MountResolver([bind("/host/data", "/data")])
    assert resolver.to_host(None) is None  # type: ignore[arg-type]
    assert any("必须是字符串" in note for note in resolver.evidence)


# --------------------------------------------------------------------------- #
# 宿主 → 容器（双向 round-trip）
# --------------------------------------------------------------------------- #


def test_host_to_container_maps_back() -> None:
    resolver = MountResolver([bind("/host/data", "/data")])
    assert resolver.host_to_container("/host/data/report.json") == "/data/report.json"
    assert resolver.to_container("/host/data") == "/data"


def test_host_to_container_ignores_non_host_mount_types() -> None:
    resolver = MountResolver([tmpfs("/tmp/cache"), other("/host/pipe", "/pipe")])
    assert resolver.host_to_container("/host/pipe/x") is None
    assert resolver.host_to_container("/tmp/cache") is None
    assert any("不在任何 bind/volume" in note for note in resolver.evidence)


def test_host_to_container_duplicate_source_is_ambiguous() -> None:
    resolver = MountResolver(
        [bind("/host/data", "/a"), bind("/host/data", "/b")]
    )
    assert resolver.host_to_container("/host/data/x") is None
    assert any("无法唯一确定" in note for note in resolver.evidence)


def test_bidirectional_roundtrip_for_bind_and_volume() -> None:
    mounts = [
        bind("/host/data", "/data"),
        volume("/var/lib/docker/volumes/t/_data", "/work"),
    ]
    resolver = MountResolver(mounts)
    for container_path in (
        "/data",
        "/data/",
        "//data//a/b.txt",
        "/work/log.txt",
        "/work/deep/nested/file",
    ):
        host = resolver.to_host(container_path)
        assert host is not None
        assert resolver.to_container(host) is not None
    # 精确 round-trip（规范化后的形式）
    for container_path, host_path in (
        ("/data/a.txt", "/host/data/a.txt"),
        ("/work/a.txt", "/var/lib/docker/volumes/t/_data/a.txt"),
    ):
        assert resolver.to_host(container_path) == host_path
        assert resolver.to_container(host_path) == container_path
        assert resolver.to_host(resolver.to_container(host_path)) == host_path


def test_read_only_mount_is_resolvable_and_evidence_reports_rw() -> None:
    resolver = MountResolver([bind("/host/data", "/data", rw=False)])
    assert resolver.to_host("/data/x") == "/host/data/x"
    assert resolver.mounts[0].read_write is False
    assert any("rw=False" in note for note in resolver.evidence)


def test_host_to_container_longest_source_wins() -> None:
    resolver = MountResolver(
        [bind("/host/data", "/data"), bind("/host/data/secret", "/secret")]
    )
    assert resolver.host_to_container("/host/data/secret/x") == "/secret/x"
    assert resolver.host_to_container("/host/data/x") == "/data/x"


def test_root_destination_mount_maps_whole_container() -> None:
    resolver = MountResolver([bind("/host/root", "/")])
    assert resolver.to_host("/etc/passwd") == "/host/root/etc/passwd"
    assert resolver.to_host("/") == "/host/root"
    assert resolver.to_container("/host/root/etc/passwd") == "/etc/passwd"


# --------------------------------------------------------------------------- #
# resolver 的构造与 evidence
# --------------------------------------------------------------------------- #


def test_resolver_rejects_non_mount_items() -> None:
    with pytest.raises(ContainerValidationError, match="ContainerMount"):
        MountResolver(["/data"])  # type: ignore[list-item]


def test_resolver_rejects_non_sequence() -> None:
    with pytest.raises(ContainerValidationError):
        MountResolver("bind")  # type: ignore[arg-type]


def test_resolver_rejects_bad_container_id() -> None:
    with pytest.raises(ContainerValidationError):
        MountResolver((), container_id="not-an-id")


def test_resolver_evidence_is_bounded() -> None:
    resolver = MountResolver([bind("/host/data", "/data")])
    for index in range(200):
        assert resolver.to_host(f"/etc/file{index}") is None
    evidence = resolver.evidence
    assert len(evidence) <= 65
    assert any("已截断" in note for note in evidence)


def test_resolver_to_dict_snapshot() -> None:
    resolver = MountResolver([bind("/host/data", "/data", rw=False)], container_id=FULL_ID)
    assert resolver.to_host("/data/x") == "/host/data/x"
    data: dict[str, Any] = resolver.to_dict()
    assert data["container_id"] == FULL_ID
    assert data["mounts"] == [resolver.mounts[0].to_dict()]
    assert any("→ 宿主" in note for note in data["evidence"])


# --------------------------------------------------------------------------- #
# resolver_for
# --------------------------------------------------------------------------- #


def test_resolver_for_requires_mapped_outcome() -> None:
    from agent_probe.container import ContainerInfo, ContainerTaskMapper

    class _Query:
        def list_container_ids(self) -> tuple[str, ...]:
            return ()

        def inspect(self, container_id_value: str) -> Any:
            raise AssertionError("不应被调用")

    mapper = ContainerTaskMapper(_Query())
    unmapped = ContainerMapping(
        outcome=MappingOutcome.UNMAPPED,
        task_label=LABEL,
        mapping=None,
        candidates=(),
        mounts=(),
        evidence=("无候选",),
        reason="无候选",
        observed_monotonic_ns=1,
    )
    with pytest.raises(ContainerValidationError, match="只有 outcome=mapped"):
        mapper.resolver_for(unmapped)

    info = ContainerInfo(
        container_id=FULL_ID,
        name="task",
        labels={"agent-probe.task": LABEL},
        state=ContainerState.RUNNING,
        host_pid=1,
    )
    mapped = ContainerMapping(
        outcome=MappingOutcome.MAPPED,
        task_label=LABEL,
        mapping=info,
        candidates=(info,),
        mounts=(bind("/host/data", "/data"),),
        evidence=(),
        reason=None,
        observed_monotonic_ns=1,
    )
    resolver = mapper.resolver_for(mapped)
    assert resolver.container_id == FULL_ID
    assert resolver.to_host("/data/x") == "/host/data/x"


def test_resolver_for_rejects_non_mapping() -> None:
    from agent_probe.container import ContainerTaskMapper

    class _Query:
        def list_container_ids(self) -> tuple[str, ...]:
            return ()

        def inspect(self, container_id_value: str) -> Any:
            raise AssertionError("不应被调用")

    mapper = ContainerTaskMapper(_Query())
    with pytest.raises(ContainerValidationError):
        mapper.resolver_for("mapped")  # type: ignore[arg-type]
