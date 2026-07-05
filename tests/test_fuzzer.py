from can_sat.modules.fuzzer import apply_fuzzed_data, directive_str, parse_directive, parse_hex_and_dot_indices


def test_directive_round_trip():
    directive = directive_str(0x123, bytes.fromhex("11223344"))
    arbitration_id, data = parse_directive(directive)
    assert arbitration_id == 0x123
    assert data == bytes.fromhex("11223344")


def test_parse_hex_and_dot_indices():
    values, bitmap = parse_hex_and_dot_indices("12AB..78")
    assert values == [1, 2, 10, 11, None, None, 7, 8]
    assert bitmap == [False, False, False, False, True, True, False, False]


def test_apply_fuzzed_data():
    values, bitmap = parse_hex_and_dot_indices("12AB..78")
    payload = apply_fuzzed_data(values, (0xC, 0xD), bitmap)
    assert payload == bytes.fromhex("12ABCD78")
