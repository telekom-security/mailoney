"""
Configuration handling for Mailoney.

Settings are loaded with this precedence:

    defaults < TOML config file < MAILONEY_* environment variables < CLI flags

The CLI layer applies the final override step in ``mailoney.core``.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]


DEFAULT_CONFIG_FILE = "mailoney.toml"


class ListenerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    bind_ip: str = "0.0.0.0"
    port: int = 25
    name: str = "smtp"
    starttls: bool = True
    implicit_tls: bool = False


def _default_listeners() -> List[ListenerConfig]:
    return [
        ListenerConfig(name="smtp", bind_ip="0.0.0.0", port=25, starttls=True),
        ListenerConfig(name="submission", bind_ip="0.0.0.0", port=587, starttls=True),
        ListenerConfig(
            name="smtps",
            bind_ip="0.0.0.0",
            port=465,
            starttls=False,
            implicit_tls=True,
        ),
    ]


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    server_name: str = "mail01.localdomain"
    conn_timeout: int = 30
    max_connections: int = 100
    max_mail_body_bytes: int = 10_485_760
    banner: str = "ESMTP Postfix"
    max_session_seconds: int = 300
    max_connections_per_ip: int = 10
    max_recipients: int = 100
    max_mails_per_session: int = 20
    max_concurrent_data: int = 10
    listeners: List[ListenerConfig] = Field(default_factory=_default_listeners)


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    log_file: str = "log/log.json"
    log_level: str = "INFO"


class StorageConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    mail_dir: str = "log/mails"
    save_mail_bodies: bool = True
    save_attachments: bool = True
    max_attachments_per_mail: int = 50
    max_mail_dir_bytes: int = 1_073_741_824

    @property
    def extract_attachments(self) -> bool:
        return self.save_attachments


class TlsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    auto_generate: bool = True
    cert_file: str = "log/tls/server.crt"
    key_file: str = "log/tls/server.key"


class RateLimitConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    window_seconds: int = 3600
    block_seconds: int = 3600
    max_messages_per_ip: int = 100
    max_messages_per_sender: int = 25
    log_block_once: bool = True
    state_file: str = "log/rate_limit_state.json"
    max_keys: int = 10_000


class Settings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    server: ServerConfig = Field(default_factory=ServerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    tls: TlsConfig = Field(default_factory=TlsConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)


ENV_MAP = {
    "MAILONEY_BIND_IP": ("server", "bind_ip"),
    "MAILONEY_SERVER_BIND_IP": ("server", "bind_ip"),
    "MAILONEY_BIND_PORT": ("server", "bind_port"),
    "MAILONEY_SERVER_BIND_PORT": ("server", "bind_port"),
    "MAILONEY_SERVER_NAME": ("server", "server_name"),
    "MAILONEY_CONN_TIMEOUT": ("server", "conn_timeout"),
    "MAILONEY_SERVER_CONN_TIMEOUT": ("server", "conn_timeout"),
    "MAILONEY_MAX_CONNECTIONS": ("server", "max_connections"),
    "MAILONEY_SERVER_MAX_CONNECTIONS": ("server", "max_connections"),
    "MAILONEY_MAX_MAIL_BODY_BYTES": ("server", "max_mail_body_bytes"),
    "MAILONEY_SERVER_MAX_MAIL_BODY_BYTES": ("server", "max_mail_body_bytes"),
    "MAILONEY_BANNER": ("server", "banner"),
    "MAILONEY_SERVER_BANNER": ("server", "banner"),
    "MAILONEY_MAX_SESSION_SECONDS": ("server", "max_session_seconds"),
    "MAILONEY_SERVER_MAX_SESSION_SECONDS": ("server", "max_session_seconds"),
    "MAILONEY_MAX_CONNECTIONS_PER_IP": ("server", "max_connections_per_ip"),
    "MAILONEY_SERVER_MAX_CONNECTIONS_PER_IP": ("server", "max_connections_per_ip"),
    "MAILONEY_MAX_RECIPIENTS": ("server", "max_recipients"),
    "MAILONEY_SERVER_MAX_RECIPIENTS": ("server", "max_recipients"),
    "MAILONEY_MAX_MAILS_PER_SESSION": ("server", "max_mails_per_session"),
    "MAILONEY_SERVER_MAX_MAILS_PER_SESSION": ("server", "max_mails_per_session"),
    "MAILONEY_MAX_CONCURRENT_DATA": ("server", "max_concurrent_data"),
    "MAILONEY_SERVER_MAX_CONCURRENT_DATA": ("server", "max_concurrent_data"),
    "MAILONEY_LOG_FILE": ("logging", "log_file"),
    "MAILONEY_LOGGING_LOG_FILE": ("logging", "log_file"),
    "MAILONEY_LOG_LEVEL": ("logging", "log_level"),
    "MAILONEY_LOGGING_LOG_LEVEL": ("logging", "log_level"),
    "MAILONEY_MAIL_DIR": ("storage", "mail_dir"),
    "MAILONEY_STORAGE_MAIL_DIR": ("storage", "mail_dir"),
    "MAILONEY_SAVE_MAIL_BODIES": ("storage", "save_mail_bodies"),
    "MAILONEY_STORAGE_SAVE_MAIL_BODIES": ("storage", "save_mail_bodies"),
    "MAILONEY_SAVE_ATTACHMENTS": ("storage", "save_attachments"),
    "MAILONEY_STORAGE_SAVE_ATTACHMENTS": ("storage", "save_attachments"),
    "MAILONEY_EXTRACT_ATTACHMENTS": ("storage", "save_attachments"),
    "MAILONEY_STORAGE_EXTRACT_ATTACHMENTS": ("storage", "save_attachments"),
    "MAILONEY_MAX_ATTACHMENTS_PER_MAIL": ("storage", "max_attachments_per_mail"),
    "MAILONEY_STORAGE_MAX_ATTACHMENTS_PER_MAIL": (
        "storage",
        "max_attachments_per_mail",
    ),
    "MAILONEY_MAX_MAIL_DIR_BYTES": ("storage", "max_mail_dir_bytes"),
    "MAILONEY_STORAGE_MAX_MAIL_DIR_BYTES": ("storage", "max_mail_dir_bytes"),
    "MAILONEY_TLS_ENABLED": ("tls", "enabled"),
    "MAILONEY_TLS_AUTO_GENERATE": ("tls", "auto_generate"),
    "MAILONEY_TLS_CERT_FILE": ("tls", "cert_file"),
    "MAILONEY_TLS_KEY_FILE": ("tls", "key_file"),
    "MAILONEY_RATE_LIMIT_ENABLED": ("rate_limit", "enabled"),
    "MAILONEY_RATE_LIMIT_WINDOW_SECONDS": ("rate_limit", "window_seconds"),
    "MAILONEY_RATE_LIMIT_BLOCK_SECONDS": ("rate_limit", "block_seconds"),
    "MAILONEY_RATE_LIMIT_MAX_MESSAGES_PER_IP": ("rate_limit", "max_messages_per_ip"),
    "MAILONEY_RATE_LIMIT_MAX_MESSAGES_PER_SENDER": (
        "rate_limit",
        "max_messages_per_sender",
    ),
    "MAILONEY_RATE_LIMIT_LOG_BLOCK_ONCE": ("rate_limit", "log_block_once"),
    "MAILONEY_RATE_LIMIT_STATE_FILE": ("rate_limit", "state_file"),
    "MAILONEY_RATE_LIMIT_MAX_KEYS": ("rate_limit", "max_keys"),
}


def _legacy_listener_from(data: Dict[str, Any]) -> Dict[str, Any]:
    server = data.get("server", {})
    return {
        "name": "smtp",
        "bind_ip": server.get("bind_ip", "0.0.0.0"),
        "port": server.get("bind_port", 25),
        "starttls": True,
        "implicit_tls": False,
    }


def _has_legacy_listener_config(config: Dict[str, Any]) -> bool:
    server = config.get("server")
    return isinstance(server, dict) and (
        "bind_ip" in server or "bind_port" in server
    )


def _has_explicit_listeners(config: Dict[str, Any]) -> bool:
    server = config.get("server")
    return isinstance(server, dict) and "listeners" in server


def _has_legacy_listener_env() -> bool:
    return any(
        env_name in os.environ
        for env_name in (
            "MAILONEY_BIND_IP",
            "MAILONEY_SERVER_BIND_IP",
            "MAILONEY_BIND_PORT",
            "MAILONEY_SERVER_BIND_PORT",
        )
    )


def _normalize_legacy_storage(config: Dict[str, Any]) -> None:
    storage = config.get("storage")
    if not isinstance(storage, dict):
        return
    if "extract_attachments" in storage and "save_attachments" not in storage:
        storage["save_attachments"] = storage["extract_attachments"]


def _deep_update(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_update(base[key], value)
        else:
            base[key] = value
    return base


def _coerce_env_value(value: str) -> Any:
    lowered = value.strip().lower()
    if lowered in {"true", "1", "yes", "on"}:
        return True
    if lowered in {"false", "0", "no", "off"}:
        return False
    try:
        return int(value)
    except ValueError:
        return value


def _env_overrides() -> Dict[str, Any]:
    overrides: Dict[str, Any] = {}
    for env_name, (section, field) in ENV_MAP.items():
        if env_name not in os.environ:
            continue
        overrides.setdefault(section, {})[field] = _coerce_env_value(
            os.environ[env_name]
        )
    return overrides


def load_toml_config(config_file: Optional[str]) -> Dict[str, Any]:
    if not config_file:
        return {}

    path = Path(config_file)
    if not path.exists():
        return {}

    with path.open("rb") as f:
        data = tomllib.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid config file: {config_file}")
    return data


def get_settings(config_file: Optional[str] = None) -> Settings:
    """
    Load settings from defaults, TOML, and environment variables.
    """
    selected_config = (
        config_file
        if config_file is not None
        else os.environ.get("MAILONEY_CONFIG", DEFAULT_CONFIG_FILE)
    )

    toml_config = load_toml_config(selected_config)
    _normalize_legacy_storage(toml_config)
    env_config = _env_overrides()
    explicit_listeners = _has_explicit_listeners(toml_config)
    legacy_listener = not explicit_listeners and (
        _has_legacy_listener_config(toml_config) or _has_legacy_listener_env()
    )

    data = Settings().model_dump()
    _deep_update(data, toml_config)
    _deep_update(data, env_config)
    if legacy_listener:
        data.setdefault("server", {})["listeners"] = [_legacy_listener_from(data)]
    return Settings.model_validate(data)


def configure_logging(level: Optional[str] = None) -> None:
    """
    Configure process logging for operational messages.
    """
    if level is None:
        level = get_settings().logging.log_level

    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level}")

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        force=True,
    )
