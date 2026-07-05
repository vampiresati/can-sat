from __future__ import annotations

from dataclasses import dataclass, field
import struct
import time

from .constants import CAN_EFF_FLAG, CAN_EFF_MASK, CAN_ERR_FLAG, CAN_FRAME_SIZE, CAN_MAX_DLEN, CAN_RTR_FLAG, CAN_SFF_MASK
from .exceptions import FrameFormatError


CAN_FRAME_STRUCT = struct.Struct("=IB3x8s")


@dataclass(slots=True)
class CanFrame:
    arbitration_id: int
    data: bytes = field(default_factory=bytes)
    is_extended_id: bool = False
    is_remote_frame: bool = False
    is_error_frame: bool = False
    channel: str | None = None
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not 0 <= len(self.data) <= CAN_MAX_DLEN:
            raise FrameFormatError("CAN payload must contain 0-8 bytes")
        if self.is_extended_id:
            if not 0 <= self.arbitration_id <= CAN_EFF_MASK:
                raise FrameFormatError("extended arbitration ID out of range")
        else:
            if not 0 <= self.arbitration_id <= CAN_SFF_MASK:
                raise FrameFormatError("standard arbitration ID out of range")

    def to_socketcan_bytes(self) -> bytes:
        can_id = self.arbitration_id
        if self.is_extended_id:
            can_id |= CAN_EFF_FLAG
        if self.is_remote_frame:
            can_id |= CAN_RTR_FLAG
        if self.is_error_frame:
            can_id |= CAN_ERR_FLAG
        return CAN_FRAME_STRUCT.pack(can_id, len(self.data), self.data.ljust(CAN_MAX_DLEN, b"\x00"))

    @classmethod
    def from_socketcan_bytes(cls, raw: bytes, channel: str | None = None) -> "CanFrame":
        if len(raw) < CAN_FRAME_SIZE:
            raise FrameFormatError("raw CAN frame too short: {0}".format(len(raw)))
        can_id, dlc, data = CAN_FRAME_STRUCT.unpack(raw[:CAN_FRAME_SIZE])
        is_extended_id = bool(can_id & CAN_EFF_FLAG)
        is_remote_frame = bool(can_id & CAN_RTR_FLAG)
        is_error_frame = bool(can_id & CAN_ERR_FLAG)
        arbitration_id = can_id & (CAN_EFF_MASK if is_extended_id else CAN_SFF_MASK)
        return cls(
            arbitration_id=arbitration_id,
            data=data[:dlc],
            is_extended_id=is_extended_id,
            is_remote_frame=is_remote_frame,
            is_error_frame=is_error_frame,
            channel=channel,
        )

    def to_cansend(self) -> str:
        return "{0:03X}#{1}".format(self.arbitration_id, self.data.hex().upper())
