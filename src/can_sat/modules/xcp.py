from __future__ import annotations

import time

from ..frame import CanFrame
from ..socketcan_bus import SocketCanBus


XCP_COMMAND_CODES = [
    (0xFF, "CONNECT"),
    (0xFE, "DISCONNECT"),
    (0xFD, "GET_STATUS"),
    (0xFB, "GET_COMM_MODE_INFO"),
    (0xFA, "GET_ID"),
    (0xF8, "GET_SEED"),
    (0xF7, "UNLOCK"),
    (0xF6, "SET_MTA"),
    (0xF5, "UPLOAD"),
    (0xF4, "SHORT_UPLOAD"),
]


def xcp_discovery(config_path: str | None, min_id: int = 0x000, max_id: int = 0x7FF,
                  timeout: float = 0.02) -> list[tuple[int, int, bytes]]:
    matches: list[tuple[int, int, bytes]] = []
    with SocketCanBus.from_config(config_path=config_path) as bus:
        for request_id in range(min_id, max_id + 1):
            bus.send(CanFrame(arbitration_id=request_id, data=b"\xFF"))
            end_time = time.time() + timeout
            while time.time() < end_time:
                response = bus.recv(timeout=max(0, end_time - time.time()))
                if response is None:
                    continue
                if len(response.data) > 0 and response.data[0] in (0xFF, 0xFE):
                    matches.append((request_id, response.arbitration_id, bytes(response.data)))
                    break
    return matches


def xcp_connect(config_path: str | None, request_id: int, response_id: int, timeout: float = 0.5) -> CanFrame | None:
    with SocketCanBus.from_config(config_path=config_path) as bus:
        bus.send(CanFrame(arbitration_id=request_id, data=bytes([0xFF, 0, 0, 0, 0, 0, 0, 0])))
        end_time = time.time() + timeout
        while time.time() < end_time:
            response = bus.recv(timeout=max(0, end_time - time.time()))
            if response is not None and response.arbitration_id == response_id:
                return response
    return None


def xcp_command_discovery(config_path: str | None, request_id: int, response_id: int,
                          timeout: float = 0.2) -> list[tuple[int, str, bool]]:
    results: list[tuple[int, str, bool]] = []
    with SocketCanBus.from_config(config_path=config_path) as bus:
        for command_code, command_name in XCP_COMMAND_CODES[1:]:
            bus.send(CanFrame(arbitration_id=request_id, data=bytes([0xFF, 0, 0, 0, 0, 0, 0, 0])))
            connected = False
            end_time = time.time() + timeout
            while time.time() < end_time:
                response = bus.recv(timeout=max(0, end_time - time.time()))
                if response is not None and response.arbitration_id == response_id:
                    connected = True
                    break
            if not connected:
                results.append((command_code, command_name, False))
                continue

            bus.send(CanFrame(arbitration_id=request_id, data=bytes([command_code, 0, 0, 0, 0, 0, 0, 0])))
            success = False
            end_time = time.time() + timeout
            while time.time() < end_time:
                response = bus.recv(timeout=max(0, end_time - time.time()))
                if response is not None and response.arbitration_id == response_id:
                    success = bool(response.data) and response.data[0] != 0xFE
                    break
            results.append((command_code, command_name, success))
    return results
