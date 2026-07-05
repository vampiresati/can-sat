class CanSatError(Exception):
    """Base exception for can-sat."""


class ConfigurationError(CanSatError):
    """Raised when the project configuration is invalid."""


class FrameFormatError(CanSatError):
    """Raised when a CAN frame cannot be parsed or encoded."""


class SocketCanError(CanSatError):
    """Raised for raw SocketCAN send/receive failures."""
