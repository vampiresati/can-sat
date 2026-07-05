from can_sat import CanFrame, SocketCanBus


with SocketCanBus.from_config() as bus:
    bus.send(CanFrame(arbitration_id=0x123, data=bytes.fromhex("11223344")))
    frame = bus.recv()
    if frame is not None:
        print(frame.to_cansend())
