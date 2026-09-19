"""本地字节夹具与分片工具。

原则：

* 全部是**内存字节**，不读网络、不读磁盘；
* gzip 使用 ``mtime=0``，保证二进制确定性；
* 提供"任意字节分片"生成器，用于确定性回放测试。

LLM 正文夹具一律用 ``json.dumps`` 构造，避免手写花括号出错。
"""

from __future__ import annotations

import gzip as _gzip
import json as _json
from typing import Any, Mapping, Sequence

__all__ = [
    "byte_chunks",
    "fixed_chunks",
    "two_way_splits",
    "all_splits",
    "chunked_body",
    "gzip_bytes",
    "http_response",
    "http_request",
    "raw_response",
    "sse_frame",
    "openai_json_body",
    "openai_sse_body",
    "anthropic_json_body",
    "anthropic_sse_body",
]

# ----------------------------------------------------------------------
# 分片
# ----------------------------------------------------------------------


def byte_chunks(data: bytes) -> list[bytes]:
    """逐字节分片（最极端的分片方式）。"""
    return [data[index : index + 1] for index in range(len(data))]


def fixed_chunks(data: bytes, size: int) -> list[bytes]:
    if size < 1:
        raise ValueError("size 必须 >= 1")
    return [data[index : index + size] for index in range(0, len(data), size)]


def two_way_splits(data: bytes):
    """所有单点切分：检验"任意分片点"。"""
    for index in range(len(data) + 1):
        yield [data[:index], data[index:]]


def all_splits(data: bytes, *, sizes: Sequence[int] = (1, 2, 3, 5, 7, 13, 64)) -> list[list[bytes]]:
    """逐字节 + 所有单点切分 + 若干固定块长。"""
    splits: list[list[bytes]] = []
    splits.append(byte_chunks(data))
    splits.extend(two_way_splits(data))
    splits.extend(fixed_chunks(data, size) for size in sizes)
    return splits


# ----------------------------------------------------------------------
# 编码
# ----------------------------------------------------------------------


def gzip_bytes(data: bytes) -> bytes:
    """确定性 gzip（固定 mtime、无文件名）。"""
    return _gzip.compress(data, mtime=0)


def chunked_body(
    data: bytes,
    *,
    chunk_size: int = 7,
    extensions: bool = False,
    trailer: Sequence[tuple[str, str]] = (),
) -> bytes:
    """按 ``chunk_size`` 切成 chunked 编码。"""
    pieces: list[bytes] = []
    for index, start in enumerate(range(0, len(data), chunk_size)):
        piece = data[start : start + chunk_size]
        extension = f";c={index}" if extensions else ""
        pieces.append(f"{len(piece):x}{extension}\r\n".encode("ascii"))
        pieces.append(piece)
        pieces.append(b"\r\n")
    pieces.append(b"0\r\n")
    for name, value in trailer:
        pieces.append(f"{name}: {value}\r\n".encode("ascii"))
    pieces.append(b"\r\n")
    return b"".join(pieces)


# ----------------------------------------------------------------------
# 消息构造
# ----------------------------------------------------------------------


def http_response(
    body: bytes = b"",
    *,
    status: int = 200,
    reason: str = "OK",
    headers: Sequence[tuple[str, str]] = (),
    framing: str = "content_length",
    version: str = "HTTP/1.1",
    encoding: str | None = None,
    chunk_size: int = 7,
    chunk_extensions: bool = False,
    trailer: Sequence[tuple[str, str]] = (),
    header_terminator: bytes = b"\r\n",
) -> bytes:
    """构造响应字节。

    ``framing`` ∈ ``{"content_length", "chunked", "close", "none"}``；
    ``encoding`` ∈ ``{None, "gzip"}``。先编码，再分帧。
    """
    payload = body
    header_lines = list(headers)
    if encoding == "gzip":
        payload = gzip_bytes(body)
        header_lines.append(("Content-Encoding", "gzip"))
    if framing == "content_length":
        header_lines.append(("Content-Length", str(len(payload))))
    elif framing == "chunked":
        payload = chunked_body(
            payload, chunk_size=chunk_size, extensions=chunk_extensions, trailer=trailer
        )
        header_lines.append(("Transfer-Encoding", "chunked"))
    elif framing == "close":
        header_lines.append(("Connection", "close"))
    elif framing == "none":
        pass
    else:  # pragma: no cover - 夹具自身参数错误
        raise ValueError(f"未知 framing: {framing}")

    head = f"{version} {status} {reason}\r\n"
    head += "".join(f"{name}: {value}\r\n" for name, value in header_lines)
    return head.encode("latin-1") + header_terminator + payload


def raw_response(
    payload: bytes,
    *,
    headers: Sequence[tuple[str, str]] = (),
    status: int = 200,
    reason: str = "OK",
) -> bytes:
    """直接给出正文原始字节（Content-Length 由 payload 长度决定）。

    用于构造故意损坏的压缩正文等场景；:func:`http_response` 会自行压缩。
    """
    header_lines = list(headers) + [("Content-Length", str(len(payload)))]
    head = f"HTTP/1.1 {status} {reason}\r\n"
    head += "".join(f"{name}: {value}\r\n" for name, value in header_lines)
    return head.encode("latin-1") + b"\r\n" + payload


def http_request(
    target: str = "/v1/chat/completions",
    body: bytes | None = b"{}",
    *,
    method: str = "POST",
    headers: Sequence[tuple[str, str]] = (),
    framing: str = "content_length",
    version: str = "HTTP/1.1",
    encoding: str | None = None,
    chunk_size: int = 5,
) -> bytes:
    """构造请求字节；``body=None`` 表示无正文。"""
    payload = body if body is not None else b""
    header_lines: list[tuple[str, str]] = [("Host", "api.example.test")]
    header_lines.extend(headers)
    if body is None:
        framing = "none"
    elif encoding == "gzip":
        payload = gzip_bytes(payload)
        header_lines.append(("Content-Encoding", "gzip"))
    if framing == "content_length":
        header_lines.append(("Content-Length", str(len(payload))))
        header_lines.append(("Content-Type", "application/json"))
    elif framing == "chunked":
        payload = chunked_body(payload, chunk_size=chunk_size)
        header_lines.append(("Transfer-Encoding", "chunked"))
        header_lines.append(("Content-Type", "application/json"))
    elif framing not in ("none",):
        raise ValueError(f"未知 framing: {framing}")

    head = f"{method} {target} {version}\r\n"
    head += "".join(f"{name}: {value}\r\n" for name, value in header_lines)
    return head.encode("latin-1") + b"\r\n" + payload


# ----------------------------------------------------------------------
# LLM 正文夹具
# ----------------------------------------------------------------------


def sse_frame(payload: Mapping[str, Any], *, event: str | None = None) -> str:
    """构造一帧 SSE（``json.dumps`` 保证合法 JSON）。"""
    prefix = f"event: {event}\n" if event else ""
    return f"{prefix}data: {_json.dumps(payload, separators=(',', ':'), ensure_ascii=False)}\n\n"


def openai_json_body(
    *,
    model: str = "gpt-4o-mini",
    prompt_tokens: int = 120,
    completion_tokens: int = 30,
    finish_reason: str = "stop",
    cached_tokens: int | None = None,
    reasoning_tokens: int | None = None,
    content: str = "ok",
) -> bytes:
    """OpenAI 兼容的非流式 chat completion 正文。"""
    usage: dict[str, Any] = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
    }
    if cached_tokens is not None:
        usage["prompt_tokens_details"] = {"cached_tokens": cached_tokens}
    if reasoning_tokens is not None:
        usage["completion_tokens_details"] = {"reasoning_tokens": reasoning_tokens}
    payload = {
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": finish_reason,
            }
        ],
        "usage": usage,
    }
    return _json.dumps(payload, separators=(",", ":")).encode("utf-8")


def openai_sse_body(
    *,
    model: str = "gpt-4o-mini",
    chunks: Sequence[tuple[str, str | None]] = (
        ("Hello", None),
        (" world", None),
        ("", "stop"),
    ),
    prompt_tokens: int = 120,
    completion_tokens: int = 30,
    include_usage: bool = True,
    cached_tokens: int | None = None,
    sentinel: bool = True,
) -> bytes:
    """OpenAI 兼容的流式 chat completion（SSE）。"""
    frames: list[str] = []
    for content, finish_reason in chunks:
        frames.append(
            sse_frame(
                {
                    "id": "chatcmpl-fixture",
                    "object": "chat.completion.chunk",
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": content},
                            "finish_reason": finish_reason,
                        }
                    ],
                }
            )
        )
    if include_usage:
        usage: dict[str, Any] = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }
        if cached_tokens is not None:
            usage["prompt_tokens_details"] = {"cached_tokens": cached_tokens}
        frames.append(
            sse_frame(
                {
                    "id": "chatcmpl-fixture",
                    "object": "chat.completion.chunk",
                    "model": model,
                    "choices": [],
                    "usage": usage,
                }
            )
        )
    if sentinel:
        frames.append("data: [DONE]\n\n")
    return "".join(frames).encode("utf-8")


def anthropic_json_body(
    *,
    model: str = "claude-3-5-sonnet-20241022",
    input_tokens: int = 200,
    output_tokens: int = 40,
    cache_read: int = 0,
    cache_creation: int = 0,
    stop_reason: str = "end_turn",
) -> bytes:
    """Anthropic Messages 非流式正文（cache 明细不计入 input_tokens）。"""
    payload = {
        "id": "msg_fixture",
        "type": "message",
        "role": "assistant",
        "model": model,
        "stop_reason": stop_reason,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_input_tokens": cache_read,
            "cache_creation_input_tokens": cache_creation,
        },
    }
    return _json.dumps(payload, separators=(",", ":")).encode("utf-8")


def anthropic_sse_body(
    *,
    model: str = "claude-3-5-sonnet-20241022",
    input_tokens: int = 200,
    output_tokens: int = 40,
    cache_read: int = 12,
    cache_creation: int = 8,
    stop_reason: str = "end_turn",
    terminal: bool = True,
) -> bytes:
    """Anthropic 流式：输入在 message_start，输出在 message_delta。"""
    frames = [
        sse_frame(
            {
                "type": "message_start",
                "message": {
                    "id": "msg_fixture",
                    "model": model,
                    "usage": {
                        "input_tokens": input_tokens,
                        "output_tokens": 1,
                        "cache_read_input_tokens": cache_read,
                        "cache_creation_input_tokens": cache_creation,
                    },
                },
            },
            event="message_start",
        ),
        sse_frame(
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "hi"}},
            event="content_block_delta",
        ),
        sse_frame(
            {
                "type": "message_delta",
                "usage": {"output_tokens": output_tokens},
                "delta": {"stop_reason": stop_reason},
            },
            event="message_delta",
        ),
    ]
    if terminal:
        frames.append(sse_frame({"type": "message_stop"}, event="message_stop"))
    return "".join(frames).encode("utf-8")
