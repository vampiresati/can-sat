from __future__ import annotations

from pathlib import Path
import time

from ..frame import CanFrame
from ..socketcan_bus import SocketCanBus


def frame_to_candump(frame: CanFrame) -> str:
    return "({0:.6f}) {1} {2}".format(frame.timestamp, frame.channel or "can0", frame.to_cansend().lower())


def dump_frames(
    config_path: str | None,
    *,
    whitelist: set[int] | None = None,
    count: int = 0,
    timeout: float = 1.0,
    candump_format: bool = False,
    output_file: str | None = None,
) -> list[str]:
    lines: list[str] = []
    if whitelist is None:
        whitelist = set()

    with SocketCanBus.from_config(config_path=config_path) as bus:
        while True:
            frame = bus.recv(timeout=timeout)
            if frame is None:
                break
            if whitelist and frame.arbitration_id not in whitelist:
                continue
            line = frame_to_candump(frame) if candump_format else "{0:.6f} {1} {2}".format(
                frame.timestamp, frame.channel, frame.to_cansend()
            )
            lines.append(line)
            if count and len(lines) >= count:
                break

    if output_file is not None:
        Path(output_file).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return lines
