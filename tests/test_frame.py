from can_sat.frame import CanFrame


def test_frame_round_trip():
    frame = CanFrame(arbitration_id=0x123, data=b"\x11\x22\x33\x44")
    raw = frame.to_socketcan_bytes()
    restored = CanFrame.from_socketcan_bytes(raw, channel="vcan0")

    assert restored.arbitration_id == 0x123
    assert restored.data == b"\x11\x22\x33\x44"
    assert restored.channel == "vcan0"
