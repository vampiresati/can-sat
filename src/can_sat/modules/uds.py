from __future__ import annotations

import time

from . import dcm


UDS_SERVICE_NAMES = dcm.DCM_SERVICE_NAMES


def uds_discovery(config_path: str | None, min_id: int = 0x000, max_id: int = 0x7FF,
                  timeout: float = 0.02) -> list[tuple[int, int]]:
    return dcm.discover(config_path, min_id=min_id, max_id=max_id, timeout=timeout)


def service_discovery(config_path: str | None, request_id: int, response_id: int,
                      timeout: float = 0.05) -> list[int]:
    return dcm.service_discovery(config_path, request_id, response_id, timeout=timeout)


def subservice_discovery(config_path: str | None, request_id: int, response_id: int, service_id: int,
                         timeout: float = 0.05) -> list[tuple[int, bytes]]:
    return dcm.subfunction_discovery(config_path, request_id, response_id, service_id, timeout=timeout)


def tester_present(config_path: str | None, request_id: int, delay: float = 0.5, count: int = 0) -> int:
    sent = 0
    from ..frame import CanFrame
    from ..socketcan_bus import SocketCanBus

    with SocketCanBus.from_config(config_path=config_path) as bus:
        while True:
            bus.send(CanFrame(arbitration_id=request_id, data=dcm.with_length(bytes([0x3E, 0x00]))))
            sent += 1
            if count and sent >= count:
                break
            time.sleep(delay)
    return sent


def ecu_reset(config_path: str | None, request_id: int, response_id: int, reset_type: int = 0x01,
              timeout: float = 0.5):
    return dcm.request_response(config_path, request_id, response_id, bytes([0x11, reset_type]), timeout=timeout)
