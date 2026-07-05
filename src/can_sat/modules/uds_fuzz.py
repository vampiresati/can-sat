from __future__ import annotations

from .fuzzer import FuzzResult, bruteforce_fuzz, identify_fuzz, mutate_fuzz, parse_directives_from_file, random_fuzz, replay_fuzz


def random_uds_fuzz(config_path: str | None, request_id: int, count: int, *,
                    base_data: bytes | None = None, payload_length: int = 8,
                    min_byte: int = 0x00, max_byte: int = 0xFF, delay: float = 0.1,
                    seed: int | None = None, log_path: str | None = None) -> FuzzResult:
    return random_fuzz(
        config_path,
        request_id,
        count,
        base_data=base_data,
        payload_length=payload_length,
        min_byte=min_byte,
        max_byte=max_byte,
        delay=delay,
        seed=seed,
        log_path=log_path,
    )


__all__ = [
    "FuzzResult",
    "bruteforce_fuzz",
    "identify_fuzz",
    "mutate_fuzz",
    "parse_directives_from_file",
    "random_uds_fuzz",
    "random_fuzz",
    "replay_fuzz",
]
