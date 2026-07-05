from __future__ import annotations

from dataclasses import dataclass
import select
import socket
import time

from .config_loader import CanSatConfig, load_config
from .exceptions import SocketCanError
from .frame import CanFrame


@dataclass(slots=True)
class SocketCanBus:
    channel: str
    receive_own_messages: bool = False
    local_loopback: bool = True
    timeout: float = 0.5

    def __post_init__(self) -> None:
        self._socket = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self._socket.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_LOOPBACK, int(self.local_loopback))
        self._socket.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_RECV_OWN_MSGS, int(self.receive_own_messages))
        self._socket.bind((self.channel,))

    @classmethod
    def from_config(cls, config_path: str | None = None, section: str = "default") -> "SocketCanBus":
        config = load_config(config_path=config_path, section=section)
        return cls.from_loaded_config(config)

    @classmethod
    def from_loaded_config(cls, config: CanSatConfig) -> "SocketCanBus":
        return cls(
            channel=config.channel,
            receive_own_messages=config.receive_own_messages,
            local_loopback=config.local_loopback,
            timeout=config.timeout,
        )

    def close(self) -> None:
        self._socket.close()

    def __enter__(self) -> "SocketCanBus":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def send(self, frame: CanFrame) -> None:
        payload = frame.to_socketcan_bytes()
        _, writable, _ = select.select([], [self._socket], [], self.timeout)
        if not writable:
            raise SocketCanError("timed out waiting to send CAN frame")
        try:
            sent = self._socket.send(payload)
        except OSError as exc:
            raise SocketCanError("failed to send CAN frame: {0}".format(exc)) from exc
        if sent != len(payload):
            raise SocketCanError("partial CAN frame send: {0}/{1}".format(sent, len(payload)))

    def recv(self, timeout: float | None = None) -> CanFrame | None:
        effective_timeout = self.timeout if timeout is None else timeout
        readable, _, _ = select.select([self._socket], [], [], effective_timeout)
        if not readable:
            return None
        try:
            raw = self._socket.recv(16)
        except OSError as exc:
            raise SocketCanError("failed to receive CAN frame: {0}".format(exc)) from exc
        frame = CanFrame.from_socketcan_bytes(raw, channel=self.channel)
        frame.timestamp = time.time()
        return frame
