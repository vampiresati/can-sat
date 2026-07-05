from __future__ import annotations

import time

from ..frame import CanFrame
from ..socketcan_bus import SocketCanBus


DCM_SERVICE_NAMES = {
    0x10: "DIAGNOSTIC_SESSION_CONTROL",
    0x11: "ECU_RESET",
    0x14: "CLEAR_DIAGNOSTIC_INFORMATION",
    0x19: "READ_DTC_INFORMATION",
    0x22: "READ_DATA_BY_IDENTIFIER",
    0x23: "READ_MEMORY_BY_ADDRESS",
    0x27: "SECURITY_ACCESS",
    0x28: "COMMUNICATION_CONTROL",
    0x2E: "WRITE_DATA_BY_IDENTIFIER",
    0x31: "ROUTINE_CONTROL",
    0x34: "REQUEST_DOWNLOAD",
    0x35: "REQUEST_UPLOAD",
    0x36: "TRANSFER_DATA",
    0x37: "REQUEST_TRANSFER_EXIT",
    0x3E: "TESTER_PRESENT",
    0x7F: "NEGATIVE_RESPONSE",
}


def with_length(payload: bytes) -> bytes:
    if len(payload) > 7:
        raise ValueError("single-frame DCM payload must be at most 7 bytes")
    return bytes([len(payload)]) + payload


def request_response(config_path: str | None, request_id: int, response_id: int, payload: bytes,
                     timeout: float = 0.2) -> CanFrame | None:
    frame = CanFrame(arbitration_id=request_id, data=with_length(payload))
    with SocketCanBus.from_config(config_path=config_path) as bus:
        bus.send(frame)
        end_time = time.time() + timeout
        while time.time() < end_time:
            response = bus.recv(timeout=max(0, end_time - time.time()))
            if response is not None and response.arbitration_id == response_id:
                return response
    return None


def discover(config_path: str | None, min_id: int = 0x000, max_id: int = 0x7FF,
             timeout: float = 0.02) -> list[tuple[int, int]]:
    matches: list[tuple[int, int]] = []
    with SocketCanBus.from_config(config_path=config_path) as bus:
        for request_id in range(min_id, max_id + 1):
            bus.send(CanFrame(arbitration_id=request_id, data=with_length(bytes([0x10, 0x01]))))
            end_time = time.time() + timeout
            while time.time() < end_time:
                response = bus.recv(timeout=max(0, end_time - time.time()))
                if response is None:
                    continue
                if len(response.data) >= 2 and response.data[1] in (0x50, 0x7F):
                    matches.append((request_id, response.arbitration_id))
                    break
    return matches


def service_discovery(config_path: str | None, request_id: int, response_id: int,
                      timeout: float = 0.05) -> list[int]:
    supported: list[int] = []
    with SocketCanBus.from_config(config_path=config_path) as bus:
        for service_id in range(0x00, 0x100):
            bus.send(CanFrame(arbitration_id=request_id, data=bytes([0x01, service_id])))
            response = bus.recv(timeout=timeout)
            if response is None or response.arbitration_id != response_id or len(response.data) < 4:
                continue
            if response.data[3] == 0x11:
                continue
            supported.append(response.data[2] if response.data[1] == 0x7F else response.data[1] - 0x40)
    return supported


def subfunction_discovery(config_path: str | None, request_id: int, response_id: int,
                          service_id: int, timeout: float = 0.05) -> list[tuple[int, bytes]]:
    found: list[tuple[int, bytes]] = []
    with SocketCanBus.from_config(config_path=config_path) as bus:
        for subfunction in range(0x00, 0x100):
            payload = with_length(bytes([service_id, subfunction, 0x00]))
            bus.send(CanFrame(arbitration_id=request_id, data=payload))
            response = bus.recv(timeout=timeout)
            if response is None or response.arbitration_id != response_id or len(response.data) < 2:
                continue
            positive = response.data[1] == ((service_id + 0x40) & 0xFF)
            informative_negative = (
                len(response.data) >= 4 and response.data[1] == 0x7F and response.data[2] == service_id
                and response.data[3] not in (0x11, 0x12, 0x31, 0x78)
            )
            if positive or informative_negative:
                found.append((subfunction, bytes(response.data)))
    return found


def dtc(config_path: str | None, request_id: int, response_id: int, clear: bool = False,
        timeout: float = 0.5) -> CanFrame | None:
    payload = bytes([0x04]) if clear else bytes([0x03])
    return request_response(config_path, request_id, response_id, payload, timeout=timeout)
