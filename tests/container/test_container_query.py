"""``DockerCli``（可注入 runner）与 ``SubprocessRunner``：绝不执行真实 docker。"""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from agent_probe.container import (
    CGROUP_ID_KEY,
    CGROUP_PATH_KEY,
    CGROUP_NOTE_KEY,
    ContainerInfo,
    ContainerNotFoundError,
    ContainerQueryError,
    ContainerQuery,
    ContainerState,
    ContainerTimeoutError,
    ContainerValidationError,
    CgroupRecord,
    DockerCli,
    NullCgroupReader,
    ProcCgroupReader,
    RunnerResult,
    SubprocessRunner,
)

from fake_container_query import (
    LABEL,
    LABEL_KEY,
    container_id,
    inspect_payload,
    inspect_result,
    mount_entry,
    ps_result,
    short_id,
)

FULL_ID = container_id(0x51)
OTHER_ID = container_id(0x52)

PS_ARGV = ("docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}}")


def inspect_argv(container_id_value: str) -> tuple[str, ...]:
    return ("docker", "inspect", container_id_value)


# --------------------------------------------------------------------------- #
# list_container_ids
# --------------------------------------------------------------------------- #


def test_list_container_ids_parses_lines_and_dedupes() -> None:
    cli = DockerCli(runner=lambda argv: ps_result(FULL_ID, OTHER_ID, FULL_ID))
    assert cli.list_container_ids() == (FULL_ID, OTHER_ID)


def test_list_container_ids_includes_exited_containers() -> None:
    # docker ps -a 是固定命令：已退出容器必须可见（短命任务的真值来源）。
    runner = _RecordingRunner(ps_result(FULL_ID))
    DockerCli(runner=runner).list_container_ids()
    assert runner.calls == [PS_ARGV]
    assert "-a" in PS_ARGV


def test_list_container_ids_empty_output_is_empty_tuple() -> None:
    cli = DockerCli(runner=lambda argv: ps_result())
    assert cli.list_container_ids() == ()


def test_list_container_ids_tolerates_blank_lines_and_trailing_spaces() -> None:
    cli = DockerCli(runner=lambda argv: (0, f"\n  {FULL_ID}  \n\n", ""))
    assert cli.list_container_ids() == (FULL_ID,)


def test_list_container_ids_nonzero_exit_raises_with_stderr() -> None:
    cli = DockerCli(
        runner=lambda argv: (1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
    )
    with pytest.raises(ContainerQueryError) as excinfo:
        cli.list_container_ids()
    assert "退出码 1" in str(excinfo.value)
    assert "Cannot connect to the Docker daemon" in str(excinfo.value)


def test_list_container_ids_accepts_runner_result_dataclass() -> None:
    cli = DockerCli(
        runner=lambda argv: RunnerResult(argv=PS_ARGV, returncode=0, stdout=FULL_ID + "\n")
    )
    assert cli.list_container_ids() == (FULL_ID,)


def test_list_container_ids_rejects_invalid_id_shape() -> None:
    cli = DockerCli(runner=lambda argv: ps_result("not-a-container-id"))
    with pytest.raises(ContainerQueryError, match="非法容器 ID"):
        cli.list_container_ids()


def test_runner_returning_none_returncode_is_a_query_error() -> None:
    cli = DockerCli(runner=lambda argv: (None, "", "killed after timeout"))
    with pytest.raises(ContainerQueryError, match="未产生退出码"):
        cli.list_container_ids()


def test_runner_returning_bad_shape_is_a_query_error() -> None:
    cli = DockerCli(runner=lambda argv: {"returncode": 0})
    with pytest.raises(ContainerQueryError, match="RunnerResult"):
        cli.list_container_ids()


# --------------------------------------------------------------------------- #
# inspect
# --------------------------------------------------------------------------- #


def test_inspect_returns_docker_inspect_equivalent_mapping() -> None:
    payload = inspect_payload(FULL_ID, labels={LABEL_KEY: LABEL}, mounts=(mount_entry(),))
    cli = DockerCli(runner=_RecordingRunner(inspect_result(payload)))
    data = cli.inspect(FULL_ID)
    assert data["Id"] == FULL_ID
    assert data["Config"]["Labels"][LABEL_KEY] == LABEL
    info = ContainerInfo.from_inspect(data)
    assert info.state is ContainerState.RUNNING
    assert info.host_pid == 4242


def test_inspect_accepts_short_id_and_checks_prefix_identity() -> None:
    payload = inspect_payload(FULL_ID, labels={LABEL_KEY: LABEL})
    runner = _RecordingRunner()
    runner.set(("docker", "inspect", short_id(FULL_ID)), inspect_result(payload))
    cli = DockerCli(runner=runner)
    assert cli.inspect(short_id(FULL_ID))["Id"] == FULL_ID


def test_inspect_accepts_bare_object_payload() -> None:
    payload = inspect_payload(FULL_ID, labels={LABEL_KEY: LABEL})
    cli = DockerCli(runner=lambda argv: (0, json.dumps(payload), ""))
    assert cli.inspect(FULL_ID)["Id"] == FULL_ID


def test_inspect_rejects_id_mismatch() -> None:
    payload = inspect_payload(OTHER_ID, labels={LABEL_KEY: LABEL})
    cli = DockerCli(runner=lambda argv: inspect_result(payload))
    with pytest.raises(ContainerQueryError, match="不一致"):
        cli.inspect(FULL_ID)


def test_inspect_empty_array_raises_not_found() -> None:
    cli = DockerCli(runner=lambda argv: (0, "[]", ""))
    with pytest.raises(ContainerNotFoundError):
        cli.inspect(FULL_ID)


def test_inspect_multiple_objects_is_an_error() -> None:
    payload = inspect_payload(FULL_ID)
    other = inspect_payload(OTHER_ID)
    cli = DockerCli(runner=lambda argv: inspect_result(payload, other))
    with pytest.raises(ContainerQueryError, match="期望 1 个"):
        cli.inspect(FULL_ID)


def test_inspect_non_json_is_an_error() -> None:
    cli = DockerCli(runner=lambda argv: (0, "<html>not json</html>", ""))
    with pytest.raises(ContainerQueryError, match="不是合法 JSON"):
        cli.inspect(FULL_ID)


def test_inspect_empty_stdout_is_an_error() -> None:
    cli = DockerCli(runner=lambda argv: (0, "   \n", ""))
    with pytest.raises(ContainerQueryError, match="stdout 为空"):
        cli.inspect(FULL_ID)


def test_inspect_json_scalar_is_an_error() -> None:
    cli = DockerCli(runner=lambda argv: (0, '"container"', ""))
    with pytest.raises(ContainerQueryError, match="既不是对象也不是数组"):
        cli.inspect(FULL_ID)


def test_inspect_nonzero_exit_is_an_error() -> None:
    cli = DockerCli(runner=lambda argv: (1, "", f"Error: No such object: {FULL_ID}"))
    with pytest.raises(ContainerQueryError) as excinfo:
        cli.inspect(FULL_ID)
    assert "No such object" in str(excinfo.value)


def test_inspect_missing_required_field_is_an_error() -> None:
    payload = inspect_payload(FULL_ID)
    payload.pop("State")
    cli = DockerCli(runner=lambda argv: (0, json.dumps([payload]), ""))
    with pytest.raises(ContainerQueryError, match="State"):
        cli.inspect(FULL_ID)


def test_inspect_missing_config_is_not_an_error() -> None:
    payload = inspect_payload(FULL_ID, include_config=False)
    cli = DockerCli(runner=lambda argv: (0, json.dumps([payload]), ""))
    assert ContainerInfo.from_inspect(cli.inspect(FULL_ID)).labels == {}


def test_inspect_invalid_argument_id_is_rejected_before_running() -> None:
    runner = _RecordingRunner()
    cli = DockerCli(runner=runner)
    with pytest.raises(ContainerValidationError):
        cli.inspect("not-an-id")
    assert runner.calls == []


def test_inspect_timeout_propagates_and_is_not_treated_as_no_result() -> None:
    cli = DockerCli(runner=_RaisingRunner(ContainerTimeoutError("docker inspect 超时（10s）")))
    with pytest.raises(ContainerTimeoutError):
        cli.inspect(FULL_ID)


def test_inspect_query_error_from_runner_propagates() -> None:
    cli = DockerCli(runner=_RaisingRunner(ContainerQueryError("docker 未安装")))
    with pytest.raises(ContainerQueryError, match="docker 未安装"):
        cli.inspect(FULL_ID)


# --------------------------------------------------------------------------- #
# cgroup 增强
# --------------------------------------------------------------------------- #


class _FakeCgroupReader:
    """内存 cgroup reader（测试不读 /proc）。"""

    def __init__(self, record: CgroupRecord) -> None:
        self.record = record
        self.calls: list[int] = []

    def read(self, pid: int) -> CgroupRecord:
        self.calls.append(pid)
        return self.record


def test_no_cgroup_reader_means_no_extension_keys() -> None:
    payload = inspect_payload(FULL_ID, labels={LABEL_KEY: LABEL})
    cli = DockerCli(runner=lambda argv: inspect_result(payload))
    data = cli.inspect(FULL_ID)
    assert CGROUP_ID_KEY not in data
    assert CGROUP_PATH_KEY not in data
    assert ContainerInfo.from_inspect(data).cgroup_id is None


def test_cgroup_reader_adds_extension_keys() -> None:
    payload = inspect_payload(FULL_ID, labels={LABEL_KEY: LABEL}, pid=4242)
    reader = _FakeCgroupReader(
        CgroupRecord(pid=4242, cgroup_path="/system.slice/docker-x.scope", cgroup_id=77)
    )
    cli = DockerCli(
        runner=lambda argv: inspect_result(payload), cgroup_reader=reader
    )
    data = cli.inspect(FULL_ID)
    assert data[CGROUP_PATH_KEY] == "/system.slice/docker-x.scope"
    assert data[CGROUP_ID_KEY] == 77
    info = ContainerInfo.from_inspect(data)
    assert info.cgroup_id == 77
    assert info.cgroup_path == "/system.slice/docker-x.scope"
    assert reader.calls == [4242]


def test_cgroup_reader_note_flows_into_extension_key() -> None:
    payload = inspect_payload(FULL_ID, labels={LABEL_KEY: LABEL}, pid=4242)
    reader = _FakeCgroupReader(
        CgroupRecord(pid=4242, note="无法读取 /proc/4242/cgroup（No such file or directory）")
    )
    cli = DockerCli(runner=lambda argv: inspect_result(payload), cgroup_reader=reader)
    data = cli.inspect(FULL_ID)
    assert CGROUP_NOTE_KEY in data
    assert ContainerInfo.from_inspect(data).cgroup_id is None


def test_null_cgroup_reader_reports_disabled_without_values() -> None:
    payload = inspect_payload(FULL_ID, labels={LABEL_KEY: LABEL}, pid=4242)
    cli = DockerCli(
        runner=lambda argv: inspect_result(payload), cgroup_reader=NullCgroupReader()
    )
    data = cli.inspect(FULL_ID)
    assert CGROUP_ID_KEY not in data
    assert "未启用" in data[CGROUP_NOTE_KEY]


def test_cgroup_reader_is_not_called_when_pid_is_zero() -> None:
    payload = inspect_payload(FULL_ID, labels={LABEL_KEY: LABEL}, status="exited", pid=0)
    reader = _FakeCgroupReader(CgroupRecord(pid=0, cgroup_id=1))
    cli = DockerCli(runner=lambda argv: inspect_result(payload), cgroup_reader=reader)
    data = cli.inspect(FULL_ID)
    assert reader.calls == []
    assert CGROUP_ID_KEY not in data


def test_exited_container_without_pid_has_no_invented_cgroup() -> None:
    payload = inspect_payload(FULL_ID, status="exited", pid=None)
    cli = DockerCli(
        runner=lambda argv: inspect_result(payload),
        cgroup_reader=_FakeCgroupReader(CgroupRecord(pid=1, cgroup_id=3)),
    )
    data = cli.inspect(FULL_ID)
    assert data["State"].get("Pid") is None
    assert CGROUP_ID_KEY not in data


# --------------------------------------------------------------------------- #
# ProcCgroupReader（用 tmp_path 构造内存视图，不读真实 /proc）
# --------------------------------------------------------------------------- #


def test_proc_cgroup_reader_reads_v2_unified_hierarchy(tmp_path: Any) -> None:
    proc_root = tmp_path / "proc"
    cgroup_root = tmp_path / "cgroup"
    cgroup_dir = cgroup_root / "system.slice" / "docker-abc.scope"
    cgroup_dir.mkdir(parents=True)
    pid_dir = proc_root / "4242"
    pid_dir.mkdir(parents=True)
    (pid_dir / "cgroup").write_text(
        "0::/system.slice/docker-abc.scope\n", encoding="utf-8"
    )

    reader = ProcCgroupReader(proc_root=proc_root, cgroup_root=cgroup_root)
    record = reader.read(4242)
    assert record.cgroup_path == str(cgroup_dir)
    assert record.cgroup_id == cgroup_dir.stat().st_ino
    assert record.note is not None and "v2" in record.note


def test_proc_cgroup_reader_prefers_systemd_on_v1(tmp_path: Any) -> None:
    proc_root = tmp_path / "proc"
    cgroup_root = tmp_path / "cgroup"
    cgroup_dir = cgroup_root / "docker" / FULL_ID
    cgroup_dir.mkdir(parents=True)
    pid_dir = proc_root / "7"
    pid_dir.mkdir(parents=True)
    (pid_dir / "cgroup").write_text(
        "11:pids:/docker/other\n"
        f"12:name=systemd:/docker/{FULL_ID}\n",
        encoding="utf-8",
    )

    record = ProcCgroupReader(proc_root=proc_root, cgroup_root=cgroup_root).read(7)
    assert record.cgroup_path == str(cgroup_dir)
    assert record.cgroup_id == cgroup_dir.stat().st_ino
    assert record.note is not None and "name=systemd" in record.note


def test_proc_cgroup_reader_missing_pid_file_returns_note(tmp_path: Any) -> None:
    reader = ProcCgroupReader(proc_root=tmp_path / "proc", cgroup_root=tmp_path / "cgroup")
    record = reader.read(999)
    assert record.cgroup_path is None
    assert record.cgroup_id is None
    assert record.note is not None and "无法读取" in record.note


def test_proc_cgroup_reader_unparsable_file_returns_note(tmp_path: Any) -> None:
    proc_root = tmp_path / "proc"
    pid_dir = proc_root / "5"
    pid_dir.mkdir(parents=True)
    (pid_dir / "cgroup").write_text("garbage\n\n", encoding="utf-8")
    reader = ProcCgroupReader(proc_root=proc_root, cgroup_root=tmp_path / "cgroup")
    record = reader.read(5)
    assert record.cgroup_id is None
    assert record.note is not None and "层级行" in record.note


def test_proc_cgroup_reader_stat_failure_keeps_path_with_note(tmp_path: Any) -> None:
    proc_root = tmp_path / "proc"
    pid_dir = proc_root / "6"
    pid_dir.mkdir(parents=True)
    (pid_dir / "cgroup").write_text("0::/docker/gone\n", encoding="utf-8")
    reader = ProcCgroupReader(proc_root=proc_root, cgroup_root=tmp_path / "cgroup")
    record = reader.read(6)
    assert record.cgroup_path is not None and record.cgroup_path.endswith("/docker/gone")
    assert record.cgroup_id is None
    assert record.note is not None and "stat" in record.note


def test_proc_cgroup_reader_root_cgroup_is_reported_as_is(tmp_path: Any) -> None:
    proc_root = tmp_path / "proc"
    cgroup_root = tmp_path / "cgroup"
    cgroup_root.mkdir()
    pid_dir = proc_root / "8"
    pid_dir.mkdir(parents=True)
    (pid_dir / "cgroup").write_text("0::/\n", encoding="utf-8")
    record = ProcCgroupReader(proc_root=proc_root, cgroup_root=cgroup_root).read(8)
    assert record.cgroup_path == str(cgroup_root)
    assert record.cgroup_id == cgroup_root.stat().st_ino


# --------------------------------------------------------------------------- #
# 委托模式与构造校验
# --------------------------------------------------------------------------- #


class _DelegatingQuery:
    def __init__(self) -> None:
        self.payload = inspect_payload(FULL_ID, labels={LABEL_KEY: LABEL})
        self.list_calls = 0
        self.inspect_calls: list[str] = []

    def list_container_ids(self) -> tuple[str, ...]:
        self.list_calls += 1
        return (FULL_ID,)

    def inspect(self, container_id_value: str) -> dict[str, Any]:
        self.inspect_calls.append(container_id_value)
        return self.payload


def test_docker_cli_can_delegate_to_upstream_query() -> None:
    upstream = _DelegatingQuery()
    cli = DockerCli(upstream)
    assert isinstance(cli, ContainerQuery)
    assert cli.list_container_ids() == (FULL_ID,)
    assert cli.inspect(FULL_ID)["Id"] == FULL_ID
    assert upstream.list_calls == 1
    assert upstream.inspect_calls == [FULL_ID]


def test_delegate_requires_sortable_query_error() -> None:
    class _Broken:
        def list_container_ids(self) -> tuple[str, ...]:
            raise ContainerQueryError("upstream down")

    with pytest.raises(ContainerValidationError, match="inspect"):
        DockerCli(_Broken())  # type: ignore[arg-type]


def test_query_and_runner_are_mutually_exclusive() -> None:
    with pytest.raises(ContainerValidationError, match="互斥"):
        DockerCli(_DelegatingQuery(), runner=lambda argv: (0, "", ""))


@pytest.mark.parametrize("value", [0, -1.0, "10"])
def test_timeout_must_be_positive_number(value: Any) -> None:
    with pytest.raises(ContainerValidationError):
        DockerCli(runner=lambda argv: (0, "", ""), timeout_s=value)


def test_docker_binary_must_be_non_empty_string() -> None:
    with pytest.raises(ContainerValidationError):
        DockerCli(docker_binary="")


def test_docker_binary_is_used_in_argv() -> None:
    runner = _RecordingRunner(ps_result(FULL_ID))
    DockerCli(runner=runner, docker_binary="/usr/bin/docker").list_container_ids()
    assert runner.calls[0][0] == "/usr/bin/docker"


# --------------------------------------------------------------------------- #
# SubprocessRunner（真实子进程，但不是 docker；离线、无网络）
# --------------------------------------------------------------------------- #


def test_subprocess_runner_executes_and_captures_output() -> None:
    runner = SubprocessRunner(timeout_s=30)
    result = runner([sys.executable, "-c", "print('hello')"])
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert result.argv[0] == sys.executable


def test_subprocess_runner_reports_nonzero_exit() -> None:
    runner = SubprocessRunner(timeout_s=30)
    result = runner([sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"])
    assert result.returncode == 3
    assert "boom" in result.stderr


def test_subprocess_runner_timeout_raises_timeout_error() -> None:
    runner = SubprocessRunner(timeout_s=0.3)
    with pytest.raises(ContainerTimeoutError):
        runner([sys.executable, "-c", "import time; time.sleep(30)"])


def test_subprocess_runner_missing_binary_raises_query_error() -> None:
    runner = SubprocessRunner(timeout_s=5)
    with pytest.raises(ContainerQueryError, match="无法启动"):
        runner(("/nonexistent/docker-binary-for-tests", "ps"))


def test_subprocess_runner_rejects_empty_argv() -> None:
    with pytest.raises(ContainerQueryError, match="空 argv"):
        SubprocessRunner()(())


@pytest.mark.parametrize("value", [0, -1, "x"])
def test_subprocess_runner_validates_timeout(value: Any) -> None:
    with pytest.raises(ContainerValidationError):
        SubprocessRunner(timeout_s=value)


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #


class _RecordingRunner:
    """记录调用并返回固定结果的 runner。"""

    def __init__(self, result: Any = None) -> None:
        self.result = (0, "", "") if result is None else result
        self.calls: list[tuple[str, ...]] = []
        self.overrides: dict[str, Any] = {}

    def set(self, argv: tuple[str, ...], result: Any) -> None:
        self.overrides[" ".join(argv)] = result

    def __call__(self, argv: Any) -> Any:
        call = tuple(str(part) for part in argv)
        self.calls.append(call)
        return self.overrides.get(" ".join(call), self.result)


class _RaisingRunner:
    """总是抛出给定异常的 runner。"""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Any) -> Any:
        self.calls.append(tuple(str(part) for part in argv))
        raise self.exc
