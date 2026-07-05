from __future__ import annotations

from configparser import ConfigParser
from dataclasses import dataclass
from pathlib import Path

from .exceptions import ConfigurationError


@dataclass(frozen=True)
class CanSatConfig:
    interface: str
    channel: str
    receive_own_messages: bool = False
    local_loopback: bool = True
    timeout: float = 0.5


def resolve_config_path(config_path: str | None = None) -> Path:
    if config_path is not None:
        return Path(config_path).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "can_sat.ini"


def load_config(config_path: str | None = None, section: str = "default") -> CanSatConfig:
    path = resolve_config_path(config_path)
    parser = ConfigParser()

    if not path.exists():
        raise ConfigurationError("config file not found: {0}".format(path))

    parser.read(path)
    if not parser.has_section(section):
        raise ConfigurationError("missing config section [{0}] in {1}".format(section, path))

    interface = parser.get(section, "interface", fallback="socketcan").strip()
    channel = parser.get(section, "channel", fallback="vcan0").strip()
    receive_own_messages = parser.getboolean(section, "receive_own_messages", fallback=False)
    local_loopback = parser.getboolean(section, "local_loopback", fallback=True)
    timeout = parser.getfloat(section, "timeout", fallback=0.5)

    if interface != "socketcan":
        raise ConfigurationError("unsupported interface '{0}'; only 'socketcan' is supported".format(interface))
    if not channel:
        raise ConfigurationError("channel must not be empty")
    if timeout < 0:
        raise ConfigurationError("timeout must be >= 0")

    return CanSatConfig(
        interface=interface,
        channel=channel,
        receive_own_messages=receive_own_messages,
        local_loopback=local_loopback,
        timeout=timeout,
    )
