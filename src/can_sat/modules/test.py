from __future__ import annotations

from ..frame import CanFrame


def frame_round_trip_smoke() -> bool:
    frame = CanFrame(arbitration_id=0x123, data=b"\x01\x02\x03")
    restored = CanFrame.from_socketcan_bytes(frame.to_socketcan_bytes(), channel="vcan0")
    return restored.arbitration_id == frame.arbitration_id and restored.data == frame.data
