"""跨模块共享的最小枚举。

单独成模块是为了打断 ``diagnostics`` ↔ ``messages`` 的循环依赖：
诊断对象需要标注方向，而消息对象需要携带诊断。
"""

from __future__ import annotations

from enum import Enum


class Direction(str, Enum):
    """TLS 连接上的字节流方向。

    请求走 ``CLIENT_TO_SERVER``，响应走 ``SERVER_TO_CLIENT``。解析器只按方向
    选择起始行的语法（请求行 / 状态行），不做任何"猜测方向"的启发式判断。
    """

    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"

    @property
    def is_request_direction(self) -> bool:
        return self is Direction.CLIENT_TO_SERVER

    @property
    def is_response_direction(self) -> bool:
        return self is Direction.SERVER_TO_CLIENT


class MessageKind(str, Enum):
    """HTTP 消息种类。"""

    REQUEST = "request"
    RESPONSE = "response"


class BodyFraming(str, Enum):
    """消息正文的分帧方式（决定"正文何时结束"）。"""

    NONE = "none"
    CONTENT_LENGTH = "content_length"
    CHUNKED = "chunked"
    CLOSE_DELIMITED = "close_delimited"
