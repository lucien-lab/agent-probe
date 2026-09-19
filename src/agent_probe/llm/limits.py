"""解析与缓冲上限。

M1 要求"限制连接缓存、单请求内容和解压大小"。所有上限都在解析器构造函数里
显式给出，并有模块级默认值；任何超限都会产出诊断，而不是静默截断。
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["ParserLimits", "SseLimits"]


@dataclass(frozen=True)
class ParserLimits:
    """HTTP/1.1 增量解析器的资源上限（单位均为字节，除非另有说明）。"""

    #: 单条起始行的上限。
    max_start_line_bytes: int = 8 * 1024
    #: 起始行 + 头部的整块上限（含 CRLF）。
    max_header_bytes: int = 64 * 1024
    #: 单条消息的头部条目数上限。
    max_headers: int = 256
    #: 单条消息原始正文字节上限；超过后继续消费字节但不再缓冲（保持连接对齐）。
    max_body_bytes: int = 8 * 1024 * 1024
    #: 单条消息解压后正文上限；超过后停止解压并标记 payload 截断。
    max_decompressed_bytes: int = 32 * 1024 * 1024
    #: chunk-size 行的上限。
    max_chunk_line_bytes: int = 1024
    #: chunked trailer 整块上限。
    max_trailer_bytes: int = 8 * 1024
    #: 响应解析器为识别 HEAD 而缓存"待配对请求方法"的深度上限。
    max_pending_requests: int = 64

    def __post_init__(self) -> None:
        for name in (
            "max_start_line_bytes",
            "max_header_bytes",
            "max_headers",
            "max_body_bytes",
            "max_decompressed_bytes",
            "max_chunk_line_bytes",
            "max_trailer_bytes",
            "max_pending_requests",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} 必须是正整数，得到 {value!r}")


@dataclass(frozen=True)
class SseLimits:
    """SSE 帧解析上限。"""

    #: 单个事件缓冲（未遇到空行前的累计字节）上限。
    max_event_bytes: int = 1024 * 1024
    #: 单个事件的 data 行数上限。
    max_data_lines: int = 4096

    def __post_init__(self) -> None:
        for name in ("max_event_bytes", "max_data_lines"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} 必须是正整数，得到 {value!r}")
