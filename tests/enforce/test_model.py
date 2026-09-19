from __future__ import annotations

import pytest

from agent_probe.enforce import (
    EnforcementMode, FileOperation, InstallationCapabilities, LsmHook, OperationRequest,
    ProtectedDirectoryPolicy, RefusalReason, evaluate_operation, validate_installation,
)


def policy(mode: EnforcementMode = EnforcementMode.ENFORCE, operations=frozenset(FileOperation)) -> ProtectedDirectoryPolicy:
    return ProtectedDirectoryPolicy(mode, ("/workspace/protected",), operations)


@pytest.mark.parametrize("operation,kwargs", [
    (FileOperation.WRITE, {}), (FileOperation.CREATE, {}), (FileOperation.TRUNCATE, {}),
    (FileOperation.UNLINK, {}),
    (FileOperation.RENAME, {"source_path": "/tmp/a"}),
    (FileOperation.LINK, {"source_path": "/tmp/a"}),
])
def test_enforce_rejects_every_supported_operation_on_protected_target(operation, kwargs) -> None:
    decision = evaluate_operation(policy(), OperationRequest(operation, "/workspace/protected/a", **kwargs))
    assert not decision.allowed
    assert decision.would_deny
    assert decision.reason is RefusalReason.PROTECTED_DIRECTORY


@pytest.mark.parametrize("operation", [FileOperation.RENAME, FileOperation.LINK])
def test_rename_and_link_also_protect_source_path(operation) -> None:
    decision = evaluate_operation(policy(), OperationRequest(operation, "/tmp/new", "/workspace/protected/old"))
    assert not decision.allowed
    assert decision.protected_paths == ("/workspace/protected/old",)


def test_audit_marks_would_deny_but_never_blocks() -> None:
    decision = evaluate_operation(policy(EnforcementMode.AUDIT), OperationRequest(FileOperation.WRITE, "/workspace/protected/a"))
    assert decision.allowed and decision.would_deny
    assert "仅记录" in decision.detail


def test_nonmatching_directory_boundary_and_unsupported_operation_do_not_claim_protection() -> None:
    decision = evaluate_operation(policy(operations=frozenset({FileOperation.WRITE})), OperationRequest(FileOperation.CREATE, "/workspace/protectedness/a"))
    assert decision.allowed and not decision.would_deny
    assert decision.reason is RefusalReason.UNSUPPORTED_OPERATION


def test_invalid_or_ambiguous_paths_are_rejected_before_decision() -> None:
    with pytest.raises(ValueError, match="'..'"):
        OperationRequest(FileOperation.WRITE, "/workspace/protected/../outside")
    with pytest.raises(ValueError, match="source_path"):
        OperationRequest(FileOperation.RENAME, "/workspace/protected/a")
    with pytest.raises(ValueError, match="根目录"):
        ProtectedDirectoryPolicy(EnforcementMode.ENFORCE, ("/",))


def test_installation_validation_refuses_enforce_without_lsm_or_required_hook() -> None:
    disabled = validate_installation(policy(), InstallationCapabilities(False, frozenset()))
    assert not disabled.ready
    assert disabled.issues[0].code is RefusalReason.INSTALLATION_NOT_READY

    missing = validate_installation(policy(), InstallationCapabilities(True, frozenset({LsmHook.FILE_PERMISSION})))
    assert not missing.ready
    assert LsmHook.INODE_LINK in missing.issues[0].missing_hooks


def test_installation_validation_is_ready_only_when_every_hook_is_available() -> None:
    checked = validate_installation(policy(), InstallationCapabilities(True, frozenset(LsmHook)))
    assert checked.ready
    assert not checked.issues

    audit = validate_installation(policy(EnforcementMode.AUDIT), InstallationCapabilities(False, frozenset()))
    assert audit.ready  # audit 无需 BPF LSM，但仍不能代表 enforce 已安装。
