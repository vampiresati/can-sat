from __future__ import annotations

from dataclasses import dataclass
import socket
import struct


DOIP_UDP_PORT = 13400
DOIP_TCP_PORT = 13400
DOIP_PROTOCOL_VERSION = 0x02
DOIP_INVERSE_VERSION = 0xFD
PT_VEHICLE_IDENT_REQUEST = 0x0001
PT_VEHICLE_IDENT_RESPONSE = 0x0004
PT_ROUTING_ACTIVATION_REQUEST = 0x0005
PT_ROUTING_ACTIVATION_RESPONSE = 0x0006
PT_DIAGNOSTIC_MESSAGE = 0x8001


@dataclass(slots=True)
class DoipMessage:
    payload_type: int
    payload: bytes

    def to_bytes(self) -> bytes:
        header = struct.pack("!BBHI", DOIP_PROTOCOL_VERSION, DOIP_INVERSE_VERSION, self.payload_type, len(self.payload))
        return header + self.payload


def parse_doip_message(raw: bytes) -> DoipMessage:
    if len(raw) < 8:
        raise ValueError("DoIP frame too short")
    _, _, payload_type, payload_length = struct.unpack("!BBHI", raw[:8])
    payload = raw[8:8 + payload_length]
    return DoipMessage(payload_type=payload_type, payload=payload)


def discover(timeout: float = 1.0, target_host: str = "255.255.255.255", port: int = DOIP_UDP_PORT) -> list[tuple[str, DoipMessage]]:
    request = DoipMessage(payload_type=PT_VEHICLE_IDENT_REQUEST, payload=b"")
    results: list[tuple[str, DoipMessage]] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.sendto(request.to_bytes(), (target_host, port))
        while True:
            try:
                raw, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            results.append((addr[0], parse_doip_message(raw)))
    return results


def send_diagnostic(host: str, source_address: int, target_address: int, payload: bytes,
                    port: int = DOIP_TCP_PORT, timeout: float = 2.0) -> bytes:
    message_payload = struct.pack("!HH", source_address, target_address) + payload
    message = DoipMessage(payload_type=PT_DIAGNOSTIC_MESSAGE, payload=message_payload)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(message.to_bytes())
        response = sock.recv(4096)
    return response
