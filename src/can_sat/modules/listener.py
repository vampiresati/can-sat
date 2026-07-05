from __future__ import annotations

from ..frame import CanFrame
from ..socketcan_bus import SocketCanBus


def listen(config_path: str | None, count: int = 1, timeout: float | None = None) -> list[CanFrame]:
    frames = []
    with SocketCanBus.from_config(config_path=config_path) as bus:
        while len(frames) < count:
            frame = bus.recv(timeout=timeout)
            if frame is None:
                break
            frames.append(frame)
    return frames
