# can-sat

Standalone SocketCAN utilities owned by this repository.

This project intentionally does not depend on `python-can` for the core bus
operations. It provides:

- local configuration via `configparser`
- a small `CanFrame` model
- a raw `SocketCanBus` implementation
- simple send/receive CLI commands

Configuration is loaded from `can_sat.ini` in the project root by default,
