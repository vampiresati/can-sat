from pathlib import Path

from can_sat.config_loader import load_config


def test_load_default_project_config():
    config = load_config()
    assert config.interface == "socketcan"
    assert config.channel == "vcan0"


def test_load_custom_config(tmp_path: Path):
    config_file = tmp_path / "custom.ini"
    config_file.write_text(
        "[default]\n"
        "interface = socketcan\n"
        "channel = can1\n"
        "receive_own_messages = true\n"
        "local_loopback = false\n"
        "timeout = 1.25\n",
        encoding="utf-8",
    )

    config = load_config(str(config_file))
    assert config.channel == "can1"
    assert config.receive_own_messages is True
    assert config.local_loopback is False
    assert config.timeout == 1.25
