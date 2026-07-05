from __future__ import annotations

from ..frame import CanFrame
from ..socketcan_bus import SocketCanBus


def send_example(config_path: str | None, arbitration_id: int = 0x123, payload: bytes = b"\x11\x22\x33\x44") -> None:
    with SocketCanBus.from_config(config_path=config_path) as bus:
        bus.send(CanFrame(arbitration_id=arbitration_id, data=payload))
