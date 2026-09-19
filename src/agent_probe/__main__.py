"""支持 ``python -m agent_probe``，与 ``probe`` 控制台脚本行为一致。"""

from __future__ import annotations

import sys

from agent_probe.cli import main

if __name__ == "__main__":
    sys.exit(main())
