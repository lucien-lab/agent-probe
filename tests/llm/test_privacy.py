"""隐私默认值测试：默认数据结构不得持久化 Authorization / API key / 正文。"""

from __future__ import annotations

import json

from agent_probe.llm.calls import AccountingLedger
from agent_probe.llm.common import Direction
from agent_probe.llm.messages import REDACTED, HeaderRedactionPolicy, redact_target
from agent_probe.llm.pricing import DEFAULT_PRICE_TABLE
from agent_probe.llm.reconstruct import ConnectionReconstructor
from agent_probe.llm.sse import SseParser

from llm.fixtures import http_request, http_response, openai_json_body, openai_sse_body

CLIENT = Direction.CLIENT_TO_SERVER
SERVER = Direction.SERVER_TO_CLIENT

#: 若干"看起来像凭据"的夹具值；任何持久化视图里都不允许出现。
AUTH_SECRET = "Bearer sk-live-AAAAAAAAAAAAAAAA"
API_KEY_SECRET = "sk-proj-BBBBBBBBBBBBBBBBBBBB"
QUERY_SECRET = "AIzaCCCCCCCCCCCCCCCCCCCC"
COOKIE_SECRET = "session=DDDDDDDDDDDDDDDD"
PROMPT_SECRET = "PROMPT-SECRET-EEEEEEEE"
COMPLETION_SECRET = "COMPLETION-SECRET-FFFFFFFF"
#: 放在头名无害的头部里，用于检验"凭据形状"辅助规则。
VALUE_SHAPED_SECRET = "sk-meta-FFFFFFFFFFFFFFFFFFFF"

SECRETS = (
    AUTH_SECRET,
    API_KEY_SECRET,
    QUERY_SECRET,
    COOKIE_SECRET,
    PROMPT_SECRET,
    COMPLETION_SECRET,
    VALUE_SHAPED_SECRET,
)


def build_record():
    reconstructor = ConnectionReconstructor("conn-1", price_table=DEFAULT_PRICE_TABLE)
    request = http_request(
        target=f"/v1/chat/completions?key={QUERY_SECRET}&alt=json",
        body=json.dumps(
            {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": PROMPT_SECRET}],
            }
        ).encode(),
        headers=(
            ("Authorization", AUTH_SECRET),
            ("OpenAI-Api-Key", API_KEY_SECRET),
            ("Cookie", COOKIE_SECRET),
            ("X-Request-Id", "req-1"),
        ),
    )
    response = http_response(
        openai_json_body(content=COMPLETION_SECRET),
        headers=(
            ("Content-Type", "application/json"),
            ("Set-Cookie", COOKIE_SECRET),
            ("X-Response-Meta", VALUE_SHAPED_SECRET),
        ),
    )
    reconstructor.feed(CLIENT, request)
    reconstructor.feed(SERVER, response)
    return reconstructor.records[0]


def assert_no_secrets(text: str) -> None:
    for secret in SECRETS:
        assert secret not in text, f"持久化视图中出现敏感值: {secret!r}"


def test_record_view_contains_no_secrets_and_no_bodies() -> None:
    record = build_record()
    serialized = json.dumps(record.to_record(), ensure_ascii=False, sort_keys=True)
    assert_no_secrets(serialized)
    assert PROMPT_SECRET not in serialized
    assert COMPLETION_SECRET not in serialized


def test_authorization_and_api_key_headers_are_redacted_but_named() -> None:
    record = build_record()
    request_record = record.to_record()["request"]
    headers = dict(request_record["headers"])
    assert headers["Authorization"] == REDACTED
    assert headers["OpenAI-Api-Key"] == REDACTED
    assert headers["Cookie"] == REDACTED
    assert headers["X-Request-Id"] == "req-1"
    assert set(request_record["redacted_header_names"]) == {
        "authorization",
        "openai-api-key",
        "cookie",
    }


def test_response_set_cookie_is_redacted() -> None:
    record = build_record()
    response_record = record.to_record()["response"]
    headers = dict(response_record["headers"])
    assert headers["Set-Cookie"] == REDACTED
    assert "set-cookie" in response_record["redacted_header_names"]


def test_value_shaped_credentials_are_redacted_even_with_a_benign_header_name() -> None:
    record = build_record()
    response_record = record.to_record()["response"]
    headers = dict(response_record["headers"])
    assert headers["X-Response-Meta"] == REDACTED
    assert "x-response-meta" in response_record["redacted_header_names"]
    assert VALUE_SHAPED_SECRET not in json.dumps(response_record)


def test_sensitive_query_parameters_are_redacted_in_target() -> None:
    record = build_record()
    request_record = record.to_record()["request"]
    assert QUERY_SECRET not in request_record["target"]
    assert request_record["target"].endswith("key=<redacted>&alt=json")
    assert request_record["redacted_query_params"] == ["key"]


def test_payload_hash_is_opt_in_and_leaks_nothing() -> None:
    record = build_record()
    plain = record.to_record()
    assert "payload_sha256" not in plain
    hashed = record.request.to_record(include_payload_hash=True)
    assert hashed["payload_sha256"] is not None
    assert_no_secrets(json.dumps(hashed, ensure_ascii=False))


def test_in_memory_payload_is_available_for_parsing_only() -> None:
    record = build_record()
    # 解析需要正文，因此内存里保留；但记录视图不暴露它。
    assert record.request is not None
    assert record.request.payload is not None
    assert PROMPT_SECRET.encode() in record.request.payload
    assert record.response is not None and record.response.payload is not None
    assert COMPLETION_SECRET.encode() in record.response.payload
    assert PROMPT_SECRET not in json.dumps(record.to_record())
    assert COMPLETION_SECRET not in json.dumps(record.to_record())


def test_diagnostics_never_embed_payload_or_credentials() -> None:
    reconstructor = ConnectionReconstructor("conn-1")
    reconstructor.feed(
        CLIENT,
        http_request(
            target=f"/v1?key={QUERY_SECRET}",
            body=b"not-json-" + PROMPT_SECRET.encode(),
            headers=(("Authorization", AUTH_SECRET),),
        ),
    )
    reconstructor.feed(SERVER, http_response(b"not-json-" + COMPLETION_SECRET.encode()))
    for record in reconstructor.records:
        for diagnostic in record.diagnostics:
            assert_no_secrets(json.dumps(diagnostic.to_record(), ensure_ascii=False))


def test_summary_view_contains_no_secrets() -> None:
    ledger = AccountingLedger()
    ledger.record(build_record())
    serialized = json.dumps(ledger.summary().to_record(), ensure_ascii=False)
    assert_no_secrets(serialized)


def test_sse_event_records_do_not_include_data() -> None:
    parser = SseParser()
    events = list(parser.feed(openai_sse_body(chunks=((COMPLETION_SECRET, None),), include_usage=True)))
    events.extend(parser.finish().events)
    for event in events:
        assert COMPLETION_SECRET not in json.dumps(event.to_record(), ensure_ascii=False)


def test_substring_matching_redacts_unknown_credential_headers() -> None:
    policy = HeaderRedactionPolicy()
    for name in (
        "X-Company-Secret-Token",
        "X-Custom-Api-Key",
        "Authentication-Info",
        "X-Session-Id",
    ):
        assert policy.is_sensitive(name), name
    for name in ("Content-Type", "Accept", "User-Agent", "X-Request-Id", "Retry-After"):
        assert not policy.is_sensitive(name), name


def test_redact_target_handles_missing_query_and_fragment() -> None:
    policy = HeaderRedactionPolicy()
    assert redact_target("/v1/chat/completions", policy) == ("/v1/chat/completions", ())
    assert redact_target("/v1?token=abc#frag", policy) == ("/v1?token=<redacted>#frag", ("token",))
    assert redact_target("/v1?a=1&b=2", policy) == ("/v1?a=1&b=2", ())


def test_redaction_policy_can_be_overridden_explicitly() -> None:
    policy = HeaderRedactionPolicy(
        sensitive_headers=frozenset({"authorization"}),
        sensitive_substrings=(),
        sensitive_value_patterns=(),
        redact_target_query=False,
    )
    assert policy.is_sensitive("authorization")
    assert not policy.is_sensitive("openai-api-key")
    assert not policy.value_looks_sensitive("sk-live-AAAAAAAAAAAAAAAA")
    assert redact_target("/v1?key=abc", policy) == ("/v1?key=abc", ())


def test_value_pattern_rule_does_not_over_redact_normal_values() -> None:
    policy = HeaderRedactionPolicy()
    for value in ("req-1", "application/json", "gzip", "task-runner-1", "abc123", "en-US"):
        assert not policy.value_looks_sensitive(value), value
    for value in ("sk-live-AAAAAAAAAAAAAAAA", "AIzaCCCCCCCCCCCCCCCCCCCC", "Bearer xyz1234567890abcdef"):
        assert policy.value_looks_sensitive(value), value
