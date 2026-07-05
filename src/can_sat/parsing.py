from __future__ import annotations

import argparse


def parse_arb_id(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def parse_hex_payload(value: str) -> bytes:
    normalized = value.replace(".", "").replace(" ", "")
    if len(normalized) % 2 != 0:
        raise argparse.ArgumentTypeError("payload hex must have an even number of characters")
    try:
        payload = bytes.fromhex(normalized)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if len(payload) > 8:
        raise argparse.ArgumentTypeError("payload must be at most 8 bytes")
    return payload


def parse_payload_list(values: list[str]) -> bytes:
    if not values:
        raise argparse.ArgumentTypeError("at least one byte is required")
    normalized = "".join(value.replace("0x", "").replace(".", "").replace(" ", "") for value in values)
    if len(normalized) % 2 != 0:
        raise argparse.ArgumentTypeError("payload hex must have an even number of characters")
    payload = bytes.fromhex(normalized)
    if len(payload) > 8:
        raise argparse.ArgumentTypeError("payload must be at most 8 bytes")
    return payload
