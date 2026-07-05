from __future__ import annotations

import argparse

from .modules import bruteforce_fuzz, dcm, doip, dump, identify_fuzz, listen, mutate_fuzz, parse_directives_from_file, random_fuzz, replay_fuzz, send_frame, uds, uds_fuzz, xcp
from .parsing import parse_arb_id, parse_hex_payload, parse_payload_list


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="can-sat", description="Project-local SocketCAN utility")
    parser.add_argument("-c", "--config", default=None, help="path to config file; defaults to project can_sat.ini")

    subparsers = parser.add_subparsers(dest="command", required=True)

    send_parser = subparsers.add_parser("send", help="send one CAN frame")
    send_parser.add_argument("arb_id", help="arbitration ID, decimal or 0x-prefixed hex")
    send_parser.add_argument("data", type=parse_hex_payload, help="payload hex, e.g. DEADBEEF or DE.AD.BE.EF")

    recv_parser = subparsers.add_parser("recv", help="receive CAN frames")
    recv_parser.add_argument("-n", "--count", type=int, default=1, help="number of frames to receive")
    recv_parser.add_argument("-t", "--timeout", type=float, default=None, help="override receive timeout in seconds")

    listener_parser = subparsers.add_parser("listener", help="listen and print incoming CAN frames")
    listener_parser.add_argument("-n", "--count", type=int, default=0, help="number of frames to receive; 0 means until timeout")
    listener_parser.add_argument("-t", "--timeout", type=float, default=1.0, help="receive timeout in seconds")

    dump_parser = subparsers.add_parser("dump", help="dump CAN traffic to stdout or a file")
    dump_parser.add_argument("whitelist", nargs="*", help="optional arbitration ID whitelist")
    dump_parser.add_argument("-n", "--count", type=int, default=0, help="number of frames to capture; 0 means until timeout")
    dump_parser.add_argument("-t", "--timeout", type=float, default=1.0, help="receive timeout in seconds")
    dump_parser.add_argument("-f", "--file", default=None, help="optional output file")
    dump_parser.add_argument("-c", "--candump-format", action="store_true", help="emit candump-style output")

    fuzzer_parser = subparsers.add_parser("fuzzer", help="fuzzing commands")
    fuzzer_subparsers = fuzzer_parser.add_subparsers(dest="fuzzer_command", required=True)

    random_parser = fuzzer_subparsers.add_parser("random", help="send random payloads to one arbitration ID")
    random_parser.add_argument("arb_id", nargs="?", default=None,
                               help="optional arbitration ID, decimal or 0x-prefixed hex")
    random_parser.add_argument("-n", "--count", type=int, default=100, help="number of frames to send")
    random_parser.add_argument("-l", "--length", type=int, default=8, help="payload length when no base data is given")
    random_parser.add_argument("-data", nargs="+", default=None, help="optional base payload bytes")
    random_parser.add_argument("-min", dest="min_byte", type=parse_arb_id, default=0x00, help="minimum byte value")
    random_parser.add_argument("-max", dest="max_byte", type=parse_arb_id, default=0xFF, help="maximum byte value")
    random_parser.add_argument("-d", "--delay", type=float, default=0.1, help="delay between frames in seconds")
    random_parser.add_argument("-s", "--seed", type=parse_arb_id, default=None, help="seed for deterministic fuzzing")
    random_parser.add_argument("-f", "--file", default=None, help="optional log file for cansend directives")
    random_parser.add_argument("-id-min", dest="min_id", type=parse_arb_id, default=0x000,
                               help="minimum arbitration ID when no static ID is supplied")
    random_parser.add_argument("-id-max", dest="max_id", type=parse_arb_id, default=0x7FF,
                               help="maximum arbitration ID when no static ID is supplied")

    brute_parser = fuzzer_subparsers.add_parser("brute", help="brute force selected nibbles in a payload")
    brute_parser.add_argument("arb_id", help="arbitration ID, decimal or 0x-prefixed hex")
    brute_parser.add_argument("template", help="payload template with '.' wildcards, e.g. 12AB..78")
    brute_parser.add_argument("-i", "--index", type=int, default=0, help="start index for resumed sessions")
    brute_parser.add_argument("-d", "--delay", type=float, default=0.01, help="delay between frames in seconds")
    brute_parser.add_argument("-f", "--file", default=None, help="optional log file for cansend directives")

    mutate_parser = fuzzer_subparsers.add_parser("mutate", help="mutate selected nibbles in arbitration ID and payload")
    mutate_parser.add_argument("arb_id_template", help="arbitration template with '.' wildcards, e.g. 7F..")
    mutate_parser.add_argument("data_template", help="payload template with '.' wildcards, e.g. 12AB....")
    mutate_parser.add_argument("-n", "--count", type=int, default=100, help="number of frames to generate")
    mutate_parser.add_argument("-i", "--index", type=int, default=0, help="start index for resumed sessions")
    mutate_parser.add_argument("-d", "--delay", type=float, default=0.01, help="delay between frames in seconds")
    mutate_parser.add_argument("-s", "--seed", type=parse_arb_id, default=None, help="seed for deterministic fuzzing")
    mutate_parser.add_argument("-f", "--file", default=None, help="optional log file for cansend directives")

    replay_parser = fuzzer_subparsers.add_parser("replay", help="replay directives from a log file")
    replay_parser.add_argument("filename", help="input directive file")
    replay_parser.add_argument("-d", "--delay", type=float, default=0.01, help="delay between frames in seconds")

    identify_parser = fuzzer_subparsers.add_parser("identify", help="interactive isolate-message workflow from a log file")
    identify_parser.add_argument("filename", help="input directive file")
    identify_parser.add_argument("-d", "--delay", type=float, default=0.01, help="delay between frames in seconds")

    dcm_parser = subparsers.add_parser("dcm", help="basic DCM diagnostics commands")
    dcm_subparsers = dcm_parser.add_subparsers(dest="dcm_command", required=True)
    dcm_discovery = dcm_subparsers.add_parser("discovery", help="scan arbitration IDs for diagnostics")
    dcm_discovery.add_argument("-min", dest="min_id", type=parse_arb_id, default=0x000)
    dcm_discovery.add_argument("-max", dest="max_id", type=parse_arb_id, default=0x7FF)
    dcm_discovery.add_argument("-t", "--timeout", type=float, default=0.02)
    dcm_services = dcm_subparsers.add_parser("services", help="discover supported services")
    dcm_services.add_argument("src")
    dcm_services.add_argument("dst")
    dcm_services.add_argument("-t", "--timeout", type=float, default=0.05)
    dcm_subfunc = dcm_subparsers.add_parser("subfunc", help="discover service subfunctions")
    dcm_subfunc.add_argument("src")
    dcm_subfunc.add_argument("dst")
    dcm_subfunc.add_argument("service")
    dcm_subfunc.add_argument("-t", "--timeout", type=float, default=0.05)
    dcm_dtc = dcm_subparsers.add_parser("dtc", help="request or clear diagnostic trouble codes")
    dcm_dtc.add_argument("src")
    dcm_dtc.add_argument("dst")
    dcm_dtc.add_argument("--clear", action="store_true")
    dcm_dtc.add_argument("-t", "--timeout", type=float, default=0.5)

    uds_parser = subparsers.add_parser("uds", help="basic UDS commands")
    uds_subparsers = uds_parser.add_subparsers(dest="uds_command", required=True)
    uds_discovery = uds_subparsers.add_parser("discovery", help="scan arbitration IDs for UDS")
    uds_discovery.add_argument("-min", dest="min_id", type=parse_arb_id, default=0x000)
    uds_discovery.add_argument("-max", dest="max_id", type=parse_arb_id, default=0x7FF)
    uds_discovery.add_argument("-t", "--timeout", type=float, default=0.02)
    uds_services = uds_subparsers.add_parser("services", help="discover supported UDS services")
    uds_services.add_argument("src")
    uds_services.add_argument("dst")
    uds_services.add_argument("-t", "--timeout", type=float, default=0.05)
    uds_subservices = uds_subparsers.add_parser("subservices", help="discover supported UDS subservices")
    uds_subservices.add_argument("src")
    uds_subservices.add_argument("dst")
    uds_subservices.add_argument("service")
    uds_subservices.add_argument("-t", "--timeout", type=float, default=0.05)
    uds_tester = uds_subparsers.add_parser("tester-present", help="send TesterPresent requests")
    uds_tester.add_argument("src")
    uds_tester.add_argument("-d", "--delay", type=float, default=0.5)
    uds_tester.add_argument("-n", "--count", type=int, default=1)
    uds_reset = uds_subparsers.add_parser("ecu-reset", help="send ECU reset")
    uds_reset.add_argument("src")
    uds_reset.add_argument("dst")
    uds_reset.add_argument("-r", "--reset-type", type=parse_arb_id, default=0x01)
    uds_reset.add_argument("-t", "--timeout", type=float, default=0.5)

    xcp_parser = subparsers.add_parser("xcp", help="basic XCP commands")
    xcp_subparsers = xcp_parser.add_subparsers(dest="xcp_command", required=True)
    xcp_discovery = xcp_subparsers.add_parser("discovery", help="scan arbitration IDs for XCP")
    xcp_discovery.add_argument("-min", dest="min_id", type=parse_arb_id, default=0x000)
    xcp_discovery.add_argument("-max", dest="max_id", type=parse_arb_id, default=0x7FF)
    xcp_discovery.add_argument("-t", "--timeout", type=float, default=0.02)
    xcp_commands = xcp_subparsers.add_parser("commands", help="check which common XCP commands respond")
    xcp_commands.add_argument("src")
    xcp_commands.add_argument("dst")
    xcp_commands.add_argument("-t", "--timeout", type=float, default=0.2)

    doip_parser = subparsers.add_parser("doip", help="basic DoIP commands")
    doip_subparsers = doip_parser.add_subparsers(dest="doip_command", required=True)
    doip_discover = doip_subparsers.add_parser("discover", help="send a DoIP vehicle identification request")
    doip_discover.add_argument("-t", "--timeout", type=float, default=1.0)
    doip_discover.add_argument("--host", default="255.255.255.255")
    doip_discover.add_argument("--port", type=int, default=13400)
    doip_send = doip_subparsers.add_parser("send", help="send a raw diagnostic DoIP payload")
    doip_send.add_argument("host")
    doip_send.add_argument("source_address", type=parse_arb_id)
    doip_send.add_argument("target_address", type=parse_arb_id)
    doip_send.add_argument("data", type=parse_hex_payload)
    doip_send.add_argument("--port", type=int, default=13400)
    doip_send.add_argument("-t", "--timeout", type=float, default=2.0)

    uds_fuzz_parser = subparsers.add_parser("uds-fuzz", help="UDS-flavored fuzzing commands")
    uds_fuzz_subparsers = uds_fuzz_parser.add_subparsers(dest="uds_fuzz_command", required=True)
    uds_fuzz_random = uds_fuzz_subparsers.add_parser("random", help="send random UDS payloads to one arbitration ID")
    uds_fuzz_random.add_argument("arb_id")
    uds_fuzz_random.add_argument("-n", "--count", type=int, default=100)
    uds_fuzz_random.add_argument("-l", "--length", type=int, default=8)
    uds_fuzz_random.add_argument("-data", nargs="+", default=None)
    uds_fuzz_random.add_argument("-min", dest="min_byte", type=parse_arb_id, default=0x00)
    uds_fuzz_random.add_argument("-max", dest="max_byte", type=parse_arb_id, default=0xFF)
    uds_fuzz_random.add_argument("-d", "--delay", type=float, default=0.1)
    uds_fuzz_random.add_argument("-s", "--seed", type=parse_arb_id, default=None)
    uds_fuzz_random.add_argument("-f", "--file", default=None)

    return parser


def cmd_send(args: argparse.Namespace) -> int:
    frame = send_frame(args.config, parse_arb_id(args.arb_id), args.data)
    print("Sent {0}".format(frame.to_cansend()))
    return 0


def cmd_recv(args: argparse.Namespace) -> int:
    frames = listen(args.config, count=args.count, timeout=args.timeout)
    if len(frames) < args.count:
        for frame in frames:
            print("{0:.6f} {1} {2}".format(frame.timestamp, frame.channel, frame.to_cansend()))
        print("Timed out waiting for frame")
        return 1
    for frame in frames:
        print("{0:.6f} {1} {2}".format(frame.timestamp, frame.channel, frame.to_cansend()))
    return 0


def cmd_listener(args: argparse.Namespace) -> int:
    received = 0
    while True:
        frames = listen(args.config, count=1, timeout=args.timeout)
        if not frames:
            if args.count == 0 or received >= args.count:
                return 0
            print("Timed out waiting for frame")
            return 1
        frame = frames[0]
        print("{0:.6f} {1} {2}".format(frame.timestamp, frame.channel, frame.to_cansend()))
        received += 1
        if args.count and received >= args.count:
            return 0


def cmd_dump(args: argparse.Namespace) -> int:
    whitelist = {parse_arb_id(value) for value in args.whitelist}
    lines = dump.dump_frames(
        args.config,
        whitelist=whitelist,
        count=args.count,
        timeout=args.timeout,
        candump_format=args.candump_format,
        output_file=args.file,
    )
    for line in lines:
        print(line)
    return 0


def cmd_fuzzer_random(args: argparse.Namespace) -> int:
    base_data = parse_payload_list(args.data) if args.data is not None else None
    result = random_fuzz(
        args.config,
        parse_arb_id(args.arb_id) if args.arb_id is not None else None,
        args.count,
        base_data=base_data,
        payload_length=args.length,
        min_byte=args.min_byte,
        max_byte=args.max_byte,
        min_id=args.min_id,
        max_id=args.max_id,
        delay=args.delay,
        seed=args.seed,
        log_path=args.file,
    )
    print("Seed: {0} (0x{0:x})".format(result.seed))
    for index, frame in enumerate(result.frames, start=1):
        print("Sent {0}/{1} {2}".format(index, len(result.frames), frame.to_cansend()))
    return 0


def cmd_fuzzer_brute(args: argparse.Namespace) -> int:
    result = bruteforce_fuzz(
        args.config,
        parse_arb_id(args.arb_id),
        args.template,
        start_index=args.index,
        delay=args.delay,
        log_path=args.file,
    )
    print("Brute force finished: {0} frames".format(len(result.frames)))
    return 0


def cmd_fuzzer_mutate(args: argparse.Namespace) -> int:
    result = mutate_fuzz(
        args.config,
        args.arb_id_template,
        args.data_template,
        args.count,
        start_index=args.index,
        delay=args.delay,
        seed=args.seed,
        log_path=args.file,
    )
    print("Seed: {0} (0x{0:x})".format(result.seed))
    print("Mutate finished: {0} frames".format(len(result.frames)))
    return 0


def cmd_fuzzer_replay(args: argparse.Namespace) -> int:
    directives = parse_directives_from_file(args.filename)
    frames = replay_fuzz(args.config, directives, delay=args.delay)
    print("Replay finished: {0} frames".format(len(frames)))
    return 0


def cmd_fuzzer_identify(args: argparse.Namespace) -> int:
    directives = parse_directives_from_file(args.filename)
    result = identify_fuzz(args.config, directives, delay=args.delay)
    if result is None:
        return 1
    print(result)
    return 0


def cmd_dcm(args: argparse.Namespace) -> int:
    if args.dcm_command == "discovery":
        matches = dcm.discover(args.config, min_id=args.min_id, max_id=args.max_id, timeout=args.timeout)
        for request_id, response_id in matches:
            print("Found diagnostics at request 0x{0:03X}, response 0x{1:03X}".format(request_id, response_id))
        return 0
    if args.dcm_command == "services":
        services = dcm.service_discovery(args.config, parse_arb_id(args.src), parse_arb_id(args.dst), timeout=args.timeout)
        for service_id in services:
            print("Supported service 0x{0:02X}: {1}".format(service_id, dcm.DCM_SERVICE_NAMES.get(service_id, "Unknown")))
        return 0
    if args.dcm_command == "subfunc":
        found = dcm.subfunction_discovery(
            args.config, parse_arb_id(args.src), parse_arb_id(args.dst), parse_arb_id(args.service), timeout=args.timeout
        )
        for subfunction, response in found:
            print("Subfunction 0x{0:02X}: {1}".format(subfunction, response.hex().upper()))
        return 0
    if args.dcm_command == "dtc":
        response = dcm.dtc(args.config, parse_arb_id(args.src), parse_arb_id(args.dst), clear=args.clear, timeout=args.timeout)
        print("No response" if response is None else response.to_cansend())
        return 0
    return 2


def cmd_uds(args: argparse.Namespace) -> int:
    if args.uds_command == "discovery":
        matches = uds.uds_discovery(args.config, min_id=args.min_id, max_id=args.max_id, timeout=args.timeout)
        for request_id, response_id in matches:
            print("Found UDS at request 0x{0:03X}, response 0x{1:03X}".format(request_id, response_id))
        return 0
    if args.uds_command == "services":
        services = uds.service_discovery(args.config, parse_arb_id(args.src), parse_arb_id(args.dst), timeout=args.timeout)
        for service_id in services:
            print("Supported UDS service 0x{0:02X}: {1}".format(service_id, uds.UDS_SERVICE_NAMES.get(service_id, "Unknown")))
        return 0
    if args.uds_command == "subservices":
        found = uds.subservice_discovery(
            args.config, parse_arb_id(args.src), parse_arb_id(args.dst), parse_arb_id(args.service), timeout=args.timeout
        )
        for subservice, response in found:
            print("Subservice 0x{0:02X}: {1}".format(subservice, response.hex().upper()))
        return 0
    if args.uds_command == "tester-present":
        sent = uds.tester_present(args.config, parse_arb_id(args.src), delay=args.delay, count=args.count)
        print("TesterPresent sent: {0}".format(sent))
        return 0
    if args.uds_command == "ecu-reset":
        response = uds.ecu_reset(
            args.config, parse_arb_id(args.src), parse_arb_id(args.dst), reset_type=args.reset_type, timeout=args.timeout
        )
        print("No response" if response is None else response.to_cansend())
        return 0
    return 2


def cmd_xcp(args: argparse.Namespace) -> int:
    if args.xcp_command == "discovery":
        matches = xcp.xcp_discovery(args.config, min_id=args.min_id, max_id=args.max_id, timeout=args.timeout)
        for request_id, response_id, data in matches:
            print("Found XCP at request 0x{0:03X}, response 0x{1:03X}: {2}".format(request_id, response_id, data.hex().upper()))
        return 0
    if args.xcp_command == "commands":
        results = xcp.xcp_command_discovery(args.config, parse_arb_id(args.src), parse_arb_id(args.dst), timeout=args.timeout)
        for command_code, command_name, success in results:
            print("0x{0:02X} {1}: {2}".format(command_code, command_name, success))
        return 0
    return 2


def cmd_doip(args: argparse.Namespace) -> int:
    if args.doip_command == "discover":
        results = doip.discover(timeout=args.timeout, target_host=args.host, port=args.port)
        for host, message in results:
            print("{0} type=0x{1:04X} payload={2}".format(host, message.payload_type, message.payload.hex().upper()))
        return 0
    if args.doip_command == "send":
        response = doip.send_diagnostic(
            args.host,
            args.source_address,
            args.target_address,
            args.data,
            port=args.port,
            timeout=args.timeout,
        )
        print(response.hex().upper())
        return 0
    return 2


def cmd_uds_fuzz(args: argparse.Namespace) -> int:
    if args.uds_fuzz_command == "random":
        base_data = parse_payload_list(args.data) if args.data is not None else None
        result = uds_fuzz.random_uds_fuzz(
            args.config,
            parse_arb_id(args.arb_id),
            args.count,
            base_data=base_data,
            payload_length=args.length,
            min_byte=args.min_byte,
            max_byte=args.max_byte,
            delay=args.delay,
            seed=args.seed,
            log_path=args.file,
        )
        print("Seed: {0} (0x{0:x})".format(result.seed))
        print("UDS fuzz finished: {0} frames".format(len(result.frames)))
        return 0
    return 2


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "send":
        return cmd_send(args)
    if args.command == "recv":
        return cmd_recv(args)
    if args.command == "listener":
        return cmd_listener(args)
    if args.command == "dump":
        return cmd_dump(args)
    if args.command == "fuzzer" and args.fuzzer_command == "random":
        return cmd_fuzzer_random(args)
    if args.command == "fuzzer" and args.fuzzer_command == "brute":
        return cmd_fuzzer_brute(args)
    if args.command == "fuzzer" and args.fuzzer_command == "mutate":
        return cmd_fuzzer_mutate(args)
    if args.command == "fuzzer" and args.fuzzer_command == "replay":
        return cmd_fuzzer_replay(args)
    if args.command == "fuzzer" and args.fuzzer_command == "identify":
        return cmd_fuzzer_identify(args)
    if args.command == "dcm":
        return cmd_dcm(args)
    if args.command == "uds":
        return cmd_uds(args)
    if args.command == "xcp":
        return cmd_xcp(args)
    if args.command == "doip":
        return cmd_doip(args)
    if args.command == "uds-fuzz":
        return cmd_uds_fuzz(args)
    parser.error("unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
