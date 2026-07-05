from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from pathlib import Path
import random
import time

from ..frame import CanFrame
from ..socketcan_bus import SocketCanBus


BYTE_MIN = 0x00
BYTE_MAX = 0xFF
ARBITRATION_ID_MIN = 0x000
ARBITRATION_ID_MAX = 0x7FF
MIN_DATA_LENGTH = 1
MAX_DATA_LENGTH = 8
DEFAULT_SEED_MAX = 2 ** 16
REPLAY_NUMBER_OF_SUB_LISTS = 5


@dataclass(slots=True)
class FuzzResult:
    seed: int | None
    frames: list[CanFrame]
    log_path: str | None = None


def _resolve_seed(seed: int | None) -> int:
    if seed is None:
        seed = random.randint(0, DEFAULT_SEED_MAX)
    random.seed(seed)
    return seed


def directive_str(arbitration_id: int, data: bytes) -> str:
    return "{0:03X}#{1}".format(arbitration_id, data.hex().upper())


def parse_directive(directive: str) -> tuple[int, bytes]:
    parts = directive.strip().split("#", 1)
    if len(parts) != 2:
        raise ValueError("directive must contain '#'")
    arbitration_id = int(parts[0], 16)
    data = bytes.fromhex(parts[1])
    if len(data) > 8:
        raise ValueError("directive payload must be at most 8 bytes")
    return arbitration_id, data


def parse_directives_from_file(filename: str) -> list[tuple[int, bytes]]:
    directives = []
    for line_number, line in enumerate(Path(filename).read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            directives.append(parse_directive(line))
        except ValueError as exc:
            raise ValueError("failed to parse directive on line {0}: {1}".format(line_number, exc)) from exc
    return directives


def append_directive_log(log_path: str | None, arbitration_id: int, data: bytes) -> None:
    if log_path is None:
        return
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write("{0}\n".format(directive_str(arbitration_id, data)))


def hex_str_to_nibble_list(value: str) -> list[int]:
    return [int(nibble, 16) for nibble in value]


def nibbles_to_bytes(nibbles: list[int]) -> bytes:
    output = bytearray()
    for index in range(0, len(nibbles), 2):
        output.append((nibbles[index] << 4) + nibbles[index + 1])
    return bytes(output)


def int_from_byte_list(values: list[int]) -> int:
    result = 0
    for value in values:
        result = (result << 8) | value
    return result


def pad_to_even_length(values: list[int | None], padding: int = 0x0) -> list[int | None]:
    if len(values) % 2 == 1:
        values.insert(0, padding)
    return values


def parse_hex_and_dot_indices(values: str, dot_index_marker: str = ".") -> tuple[list[int | None], list[bool]]:
    parsed_values: list[int | None] = []
    bitmap: list[bool] = []

    if len(values) % 2 == 1:
        parsed_values.append(0)
        bitmap.append(False)

    for nibble in values:
        is_marked = nibble == dot_index_marker
        bitmap.append(is_marked)
        parsed_values.append(None if is_marked else int(nibble, 16))
    return parsed_values, bitmap


def apply_fuzzed_data(initial_data: list[int | None], fuzzed_nibbles: tuple[int, ...] | list[int], bitmap: list[bool]) -> bytes:
    fuzz_index = 0
    output = bytearray()
    for index in range(0, len(bitmap), 2):
        if bitmap[index]:
            high_nibble = fuzzed_nibbles[fuzz_index]
            fuzz_index += 1
        else:
            high_nibble = initial_data[index]

        if bitmap[index + 1]:
            low_nibble = fuzzed_nibbles[fuzz_index]
            fuzz_index += 1
        else:
            low_nibble = initial_data[index + 1]

        output.append((int(high_nibble) << 4) + int(low_nibble))
    return bytes(output)


def split_lists(full_list: list[tuple[int, bytes]], pieces: int):
    length = len(full_list)
    for index in range(pieces):
        sub_list = full_list[index * length // pieces:(index + 1) * length // pieces]
        if sub_list:
            yield sub_list


def _send_frame(bus: SocketCanBus, frame: CanFrame, delay: float, log_path: str | None) -> None:
    bus.send(frame)
    append_directive_log(log_path, frame.arbitration_id, frame.data)
    if delay > 0:
        time.sleep(delay)


def random_fuzz(
    config_path: str | None,
    arbitration_id: int | None,
    count: int,
    *,
    base_data: bytes | None = None,
    payload_length: int = 8,
    min_byte: int = BYTE_MIN,
    max_byte: int = BYTE_MAX,
    min_id: int = ARBITRATION_ID_MIN,
    max_id: int = ARBITRATION_ID_MAX,
    delay: float = 0.1,
    seed: int | None = None,
    log_path: str | None = None,
) -> FuzzResult:
    if count < 1:
        raise ValueError("count must be at least 1")
    if not 0 <= min_byte <= max_byte <= 0xFF:
        raise ValueError("byte range must stay within 0x00-0xFF")
    if arbitration_id is None and not 0 <= min_id <= max_id <= ARBITRATION_ID_MAX:
        raise ValueError("arbitration ID range must stay within 0x000-0x7FF")
    if base_data is not None and len(base_data) > 8:
        raise ValueError("base_data must be at most 8 bytes")
    if base_data is None and not 1 <= payload_length <= 8:
        raise ValueError("payload_length must be in the range 1-8")

    resolved_seed = _resolve_seed(seed)
    frames = []

    with SocketCanBus.from_config(config_path=config_path) as bus:
        for _ in range(count):
            current_arb_id = arbitration_id if arbitration_id is not None else random.randint(min_id, max_id)
            if base_data is None:
                payload = bytes(random.randint(min_byte, max_byte) for _ in range(payload_length))
            else:
                mutable = bytearray(base_data)
                for index in range(len(mutable)):
                    mutable[index] = random.randint(min_byte, max_byte)
                payload = bytes(mutable)
            frame = CanFrame(arbitration_id=current_arb_id, data=payload)
            _send_frame(bus, frame, delay, log_path)
            frames.append(frame)
    return FuzzResult(seed=resolved_seed, frames=frames, log_path=log_path)


def bruteforce_fuzz(
    config_path: str | None,
    arbitration_id: int,
    template: str,
    *,
    start_index: int = 0,
    delay: float = 0.01,
    log_path: str | None = None,
) -> FuzzResult:
    initial_data, data_bitmap = parse_hex_and_dot_indices(template)
    if not 2 <= len(initial_data) <= 16 or len(initial_data) % 2 != 0:
        raise ValueError("template must contain 1-8 bytes of nibble data")

    nibble_count = sum(data_bitmap)
    frames = []

    with SocketCanBus.from_config(config_path=config_path) as bus:
        for message_index, fuzzed_nibbles in enumerate(product(range(16), repeat=nibble_count)):
            if message_index < start_index:
                continue
            payload = apply_fuzzed_data(initial_data, fuzzed_nibbles, data_bitmap)
            frame = CanFrame(arbitration_id=arbitration_id, data=payload)
            _send_frame(bus, frame, delay, log_path)
            frames.append(frame)
    return FuzzResult(seed=None, frames=frames, log_path=log_path)


def mutate_fuzz(
    config_path: str | None,
    arbitration_template: str,
    data_template: str,
    count: int,
    *,
    start_index: int = 0,
    delay: float = 0.01,
    seed: int | None = None,
    log_path: str | None = None,
) -> FuzzResult:
    if count < 1:
        raise ValueError("count must be at least 1")

    initial_arb_id, arb_id_bitmap = parse_hex_and_dot_indices(arbitration_template)
    initial_data, data_bitmap = parse_hex_and_dot_indices(data_template)
    if len(initial_arb_id) > 4:
        raise ValueError("arbitration template must fit within 11-bit standard ID space")

    resolved_seed = _resolve_seed(seed)
    frames = []

    with SocketCanBus.from_config(config_path=config_path) as bus:
        for index in range(count):
            if index < start_index:
                continue
            fuzzed_arb_nibbles = [random.randint(0, 0xF) for _ in range(sum(arb_id_bitmap))]
            fuzzed_data_nibbles = [random.randint(0, 0xF) for _ in range(sum(data_bitmap))]
            arbitration_id = int_from_byte_list(list(apply_fuzzed_data(initial_arb_id, fuzzed_arb_nibbles, arb_id_bitmap)))
            payload = apply_fuzzed_data(initial_data, fuzzed_data_nibbles, data_bitmap)
            frame = CanFrame(arbitration_id=arbitration_id, data=payload)
            _send_frame(bus, frame, delay, log_path)
            frames.append(frame)
    return FuzzResult(seed=resolved_seed, frames=frames, log_path=log_path)


def replay_fuzz(
    config_path: str | None,
    directives: list[tuple[int, bytes]],
    *,
    delay: float = 0.01,
) -> list[CanFrame]:
    frames = []
    with SocketCanBus.from_config(config_path=config_path) as bus:
        for arbitration_id, data in directives:
            frame = CanFrame(arbitration_id=arbitration_id, data=data)
            _send_frame(bus, frame, delay, log_path=None)
            frames.append(frame)
    return frames


def identify_fuzz(
    config_path: str | None,
    directives: list[tuple[int, bytes]],
    *,
    delay: float = 0.01,
) -> str | None:
    with SocketCanBus.from_config(config_path=config_path) as bus:
        batches = split_lists(directives, 1)
        repeat = False
        current_batch: list[tuple[int, bytes]] | None = None
        while True:
            if not repeat:
                try:
                    current_batch = next(batches)
                except StopIteration:
                    print("\nNo match was found.")
                    return None
            repeat = False
            assert current_batch is not None

            print()
            for index, (arbitration_id, data) in enumerate(current_batch, start=1):
                frame = CanFrame(arbitration_id=arbitration_id, data=data)
                bus.send(frame)
                print("Sending ({0}/{1}) {2}".format(index, len(current_batch), frame.to_cansend()))
                if delay > 0:
                    time.sleep(delay)

            print("\nWas the desired effect observed?")
            while True:
                response = input("(y)es | (n)o | (r)eplay | (q)uit: ").strip().lower()
                if response == "y":
                    if len(current_batch) == 1:
                        arbitration_id, data = current_batch[0]
                        result = directive_str(arbitration_id, data)
                        print("\nMatch found! Message causing effect: {0}".format(result))
                        return result
                    batches = split_lists(current_batch, REPLAY_NUMBER_OF_SUB_LISTS)
                    break
                if response == "n":
                    break
                if response == "r":
                    repeat = True
                    break
                if response == "q":
                    return None
                print("Invalid choice")
