from __future__ import annotations

from ..frame import CanFrame
from ..socketcan_bus import SocketCanBus


def send_frame(config_path: str | None, arbitration_id: int, data: bytes) -> CanFrame:
    frame = CanFrame(arbitration_id=arbitration_id, data=data)
    with SocketCanBus.from_config(config_path=config_path) as bus:
        bus.send(frame)
    return frame
