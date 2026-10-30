"""
Tests for the limits and fixes of the 3.1 review.
"""
import base64
import json
import os
import socket
import stat
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509

import mailoney.core as core
from mailoney import mail_storage
from mailoney.config import RateLimitConfig, Settings, TlsConfig
from mailoney.core import ConnectionTracker, SMTPLineReader, SessionTranscript
from mailoney.mail_storage import MailDirQuota, store_mail_message
from mailoney.rate_limiter import RateLimiter, source_key
from mailoney.tls import ensure_tls_material
from tests.conftest import read_jsonl
from tests.test_core import _honeypot, _recv_until, _run_session
from tests.test_data_handling import FakeSocket


def _events(tmp_path):
    return read_jsonl(tmp_path / "log" / "log.json")


# Log volume


def test_transcript_caps_bytes_and_line_length(monkeypatch):
    monkeypatch.setattr(core, "MAX_LOGGED_INPUT_BYTES", 3000)
    transcript = SessionTranscript()
    transcript.record_input("x" * 5000)
    assert len(transcript.lines[0].encode()) == core.MAX_LOGGED_LINE_BYTES
    for _ in range(10):
        transcript.record_input("y" * 1000)
    assert transcript.full and transcript.truncated
    assert transcript.logged_bytes <= 3000
    assert transcript.count == 11


def test_auth_events_are_capped_per_session(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "MAX_AUTH_EVENTS_PER_SESSION", 3)
    honeypot = _honeypot(tmp_path)
    token = base64.b64encode(b"\x00user\x00pass").decode()

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(b"EHLO client\r\n" + f"AUTH PLAIN {token}\r\n".encode() * 8 + b"QUIT\r\n")
        assert b"221" in _recv_until(client_sock, b"221")

    _run_session(honeypot, script)
    events = _events(tmp_path)
    assert [e["event.type"] for e in events].count("auth") == 3
    session = next(e for e in events if e["event.type"] == "session")
    assert any("5 AUTH attempts not logged" in error for error in session["errors"])


# Session limits


def test_recipients_are_capped(tmp_path):
    honeypot = _honeypot(tmp_path, max_recipients=2)

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(
            b"EHLO c\r\nMAIL FROM:<a@x.test>\r\n"
            + b"".join(f"RCPT TO:<r{i}@x.test>\r\n".encode() for i in range(4))
            + b"QUIT\r\n"
        )
        data = _recv_until(client_sock, b"221")
        assert data.count(b"250 2.1.5 Ok") == 2
        assert data.count(b"452 4.5.3") == 2

    _run_session(honeypot, script)


def test_mails_per_session_are_capped(tmp_path):
    honeypot = _honeypot(tmp_path, max_mails_per_session=1)
    mail = b"MAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\nDATA\r\nSubject: s\r\n\r\nhi\r\n.\r\n"

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(b"EHLO c\r\n" + mail + b"MAIL FROM:<a@x.test>\r\n")
        assert b"421 4.7.0" in _recv_until(client_sock, b"421")

    _run_session(honeypot, script)
    events = _events(tmp_path)
    assert [e["event.type"] for e in events] == ["mail"]
    assert events[0]["session_outcome"] == "limit"


def test_command_count_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "MAX_COMMANDS_PER_SESSION", 5)
    honeypot = _honeypot(tmp_path)

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(b"NOOP\r\n" * 10)
        assert b"421 4.7.0" in _recv_until(client_sock, b"421")

    _run_session(honeypot, script)
    assert _events(tmp_path)[0]["session_outcome"] == "limit"


def test_session_time_limit_ends_a_trickling_client(tmp_path):
    honeypot = _honeypot(tmp_path, max_session_seconds=1, conn_timeout=30)

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        start = time.monotonic()
        data = b""
        client_sock.settimeout(0.2)
        while b"421" not in data and time.monotonic() - start < 4:
            try:
                client_sock.sendall(b"N")
            except OSError:
                break
            try:
                data += client_sock.recv(1024)
            except socket.timeout:
                pass
        assert b"421 4.4.2" in data
        assert time.monotonic() - start < 3

    _run_session(honeypot, script)
    event = _events(tmp_path)[0]
    assert event["session_outcome"] == "timeout"
    assert any("session time limit" in error for error in event["errors"])


def test_connection_tracker_limits_per_source_and_groups_ipv6():
    tracker = ConnectionTracker(2)
    assert tracker.acquire("2001:db8::1")
    assert tracker.acquire("2001:db8::2")
    assert not tracker.acquire("2001:db8::3")
    assert tracker.acquire("2001:db8:0:1::1")
    tracker.release("2001:db8::1")
    assert tracker.acquire("2001:db8::4")
    assert source_key("::ffff:198.51.100.4") == "198.51.100.4"


def test_data_is_refused_without_a_free_slot(tmp_path):
    slots = threading.BoundedSemaphore(1)
    slots.acquire()
    honeypot = _honeypot(tmp_path, data_slots=slots)

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(b"EHLO c\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\nDATA\r\nQUIT\r\n")
        data = _recv_until(client_sock, b"221")
        assert b"451 4.3.0" in data and b"354" not in data

    _run_session(honeypot, script)


# Protocol


def test_command_order_is_enforced(tmp_path):
    honeypot = _honeypot(tmp_path)

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(
            b"AUTH PLAIN AHUAcA==\r\n"
            b"EHLO c\r\n"
            b"RCPT TO:<b@x.test>\r\n"
            b"DATA\r\n"
            b"MAIL FROM:<a@x.test>\r\n"
            b"MAIL FROM:<a@x.test>\r\n"
            b"DATA\r\n"
            b"QUIT\r\n"
        )
        data = _recv_until(client_sock, b"221")
        assert b"503 5.5.1 Error: send HELO/EHLO first" in data
        assert b"503 5.5.1 Error: need MAIL command" in data
        assert data.count(b"503 5.5.1 Error: need RCPT command") == 2
        assert b"503 5.5.1 Error: nested MAIL command" in data

    _run_session(honeypot, script)
    assert not any(e["event.type"] == "auth" for e in _events(tmp_path))


def test_postfix_like_replies(tmp_path):
    honeypot = _honeypot(tmp_path)

    def script(client_sock):
        greeting = client_sock.recv(1024)
        assert greeting == b"220 test.example.com ESMTP Postfix\r\n"
        client_sock.sendall(b"EHLO c\r\nAUTH PLAIN !!!\r\nQUIT\r\n")
        data = _recv_until(client_sock, b"221")
        assert b"250-ENHANCEDSTATUSCODES\r\n" in data
        assert b"501 5.5.2 Cannot decode response" in data
        assert data.endswith(b"221 2.0.0 Bye\r\n")

    _run_session(honeypot, script)
    auth = next(e for e in _events(tmp_path) if e["event.type"] == "auth")
    assert auth["auth.raw"] == "!!!"


def test_read_data_undoes_dot_stuffing_and_takes_bare_lf():
    reader = SMTPLineReader(FakeSocket(b"..dot\r\nline\r\n.\r\nNEXT"))
    assert reader.read_data(1000) == (b".dot\r\nline", True)
    assert reader.buffer == b"NEXT"

    reader = SMTPLineReader(FakeSocket(b"a\n..b\n.\n"))
    assert reader.read_data(1000) == (b"a\n.b", True)

    # once CRLF was seen a bare LF dot line does not end the body
    reader = SMTPLineReader(FakeSocket(b"a\r\nb\n.\nc\r\n.\r\n"))
    assert reader.read_data(1000) == (b"a\r\nb\n\nc", True)

    reader = SMTPLineReader(FakeSocket(b".\r\n"))
    assert reader.read_data(1000) == (b"", True)


def test_read_data_large_body_is_linear():
    chunks = [b"x" * 65536 for _ in range(160)] + [b"\r\n.\r\n"]
    reader = SMTPLineReader(FakeSocket(*chunks))
    start = time.monotonic()
    body, done = reader.read_data(20 * 1024 * 1024)
    assert done and len(body) == 160 * 65536
    assert time.monotonic() - start < 2


# Storage


def test_store_mail_survives_lone_surrogates_and_long_names(tmp_path):
    long_name = "a" * 400 + ".exe"
    raw = (
        b"Subject: =?utf-7?Q?+2D3-?=\r\n"
        b"From: x@y.test\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        b"--B\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
        b"--B\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename*=utf-7''%2B2D3-x.bin\r\n\r\nAAAA\r\n"
        b"--B\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="' + long_name.encode() + b'"\r\n\r\nBBBB\r\n'
        b"--B--\r\n"
    )
    meta = store_mail_message(str(tmp_path), "198.51.100.1", "s", "m", raw)
    json.dumps(meta, ensure_ascii=False).encode("utf-8")
    assert meta["header_from"] == "x@y.test"
    assert len(meta["attachments"]) == 2
    for attachment in meta["attachments"]:
        path = tmp_path / attachment["path"]
        assert path.exists()
        assert len(path.name.encode()) < 255
    assert meta["attachments"][1]["path"].endswith(".exe")


def test_attachments_per_mail_are_capped(tmp_path):
    parts = b"".join(
        b"--B\r\nContent-Disposition: attachment; filename=\"f%d.bin\"\r\n\r\nX\r\n" % i
        for i in range(5)
    )
    raw = b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n' + parts + b"--B--\r\n"
    meta = store_mail_message(str(tmp_path), "198.51.100.1", "s", "m", raw, max_attachments=2)
    assert len(meta["attachments"]) == 2
    assert any("3 attachments not saved" in error for error in meta["errors"])


def test_mail_dir_quota_stops_writes_and_rescans(tmp_path, monkeypatch):
    quota = MailDirQuota(str(tmp_path), 100)
    first = store_mail_message(str(tmp_path), "198.51.100.1", "s", "m1", b"x" * 80, quota=quota)
    assert first.get("eml_file")
    second = store_mail_message(str(tmp_path), "198.51.100.1", "s", "m2", b"y" * 80, quota=quota)
    assert "eml_file" not in second
    assert any("mail folder limit" in error for error in second["errors"])

    for path in tmp_path.rglob("*.eml"):
        path.unlink()
    monkeypatch.setattr(mail_storage, "QUOTA_RESCAN_SECONDS", 0)
    third = store_mail_message(str(tmp_path), "198.51.100.1", "s", "m3", b"z" * 80, quota=quota)
    assert third.get("eml_file")


def test_storage_failure_still_logs_and_acknowledges(tmp_path, monkeypatch):
    honeypot = _honeypot(tmp_path)

    def broken(*args, **kwargs):
        raise UnicodeEncodeError("utf-8", "x", 0, 1, "surrogates not allowed")

    monkeypatch.setattr(core, "store_mail_message", broken)

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(b"EHLO c\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n")
        data = _recv_until(client_sock, b"221")
        assert b"250 2.0.0 Ok: queued as " in data

    _run_session(honeypot, script)
    event = _events(tmp_path)[0]
    assert event["event.type"] == "mail"
    assert any("mail storage failed" in error for error in event["errors"])


# Rate limiter


def _limiter(tmp_path, clock, **kwargs):
    config = RateLimitConfig(
        state_file=str(tmp_path / "state.json"),
        window_seconds=100,
        block_seconds=100,
        **kwargs,
    )
    return RateLimiter(config, clock=clock)


def test_rate_limiter_keeps_no_empty_keys_and_prunes(tmp_path):
    now = [1000.0]
    limiter = _limiter(tmp_path, lambda: now[0])
    for i in range(50):
        assert limiter.check("sender", f"s{i}@x.test").allowed
    assert limiter.key_count("sender") == 0

    limiter.record_message("198.51.100.1", "a@x.test")
    assert limiter.key_count("sender") == 1
    now[0] += 1000
    limiter.check("ip", "198.51.100.2")
    assert limiter.key_count("sender") == 0
    assert limiter.key_count("ip") == 0


def test_rate_limiter_caps_keys_and_groups_ipv6(tmp_path):
    now = [1000.0]
    limiter = _limiter(tmp_path, lambda: now[0], max_keys=10, max_messages_per_ip=2)
    for i in range(30):
        limiter.record_message(f"198.51.100.{i}", f"s{i}@x.test")
    assert limiter.key_count("ip") == 10
    assert limiter.key_count("sender") == 10

    limiter.record_message("2001:db8::1", None)
    limiter.record_message("2001:db8::2", None)
    decision = limiter.check("ip", "2001:db8::3")
    assert not decision.allowed
    assert decision.key == "2001:db8::/64"


def test_rate_limiter_throttles_state_writes(tmp_path):
    now = [1000.0]
    limiter = _limiter(tmp_path, lambda: now[0])
    state = tmp_path / "state.json"
    limiter.record_message("198.51.100.1", None)
    assert state.exists()
    first = state.read_text()
    limiter.record_message("198.51.100.1", None)
    assert state.read_text() == first
    limiter.flush()
    assert state.read_text() != first
    assert stat.S_IMODE(state.stat().st_mode) == 0o640


def test_rate_limited_session_keeps_auth_and_mail_events(tmp_path):
    config = RateLimitConfig(
        max_messages_per_sender=1,
        state_file=str(tmp_path / "log" / "rate_limit_state.json"),
    )
    limiter = RateLimiter(config)
    honeypot = _honeypot(tmp_path, rate_limiter=limiter)
    token = base64.b64encode(b"\x00user\x00pass").decode()
    mail = b"MAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\nDATA\r\nhi\r\n.\r\n"

    def script(client_sock):
        assert client_sock.recv(1024).startswith(b"220 ")
        client_sock.sendall(b"EHLO c\r\n" + f"AUTH PLAIN {token}\r\n".encode() + mail + b"MAIL FROM:<a@x.test>\r\n")
        assert b"421 4.7.0" in _recv_until(client_sock, b"421")

    _run_session(honeypot, script)
    types = sorted(e["event.type"] for e in _events(tmp_path))
    # the session summary rides on the auth and mail events
    assert types == ["auth", "mail", "rate_limit_block"]


# TLS and config


def test_tls_material_is_private_and_not_freshly_dated(tmp_path):
    config = TlsConfig(
        cert_file=str(tmp_path / "tls" / "server.crt"),
        key_file=str(tmp_path / "tls" / "server.key"),
    )
    material = ensure_tls_material(config, "mail.example.test")
    assert stat.S_IMODE(os.stat(material.key_file).st_mode) == 0o600
    certificate = x509.load_pem_x509_certificate(open(material.cert_file, "rb").read())
    now = datetime.now(timezone.utc)
    assert certificate.not_valid_before_utc <= now - timedelta(days=1)
    assert certificate.not_valid_after_utc - certificate.not_valid_before_utc == timedelta(days=3650)

    os.chmod(material.key_file, 0o644)
    ensure_tls_material(config, "mail.example.test")
    assert stat.S_IMODE(os.stat(material.key_file).st_mode) == 0o600


def test_new_settings_have_defaults_and_env(monkeypatch):
    settings = Settings()
    assert settings.server.banner == "ESMTP Postfix"
    assert settings.server.max_session_seconds == 300
    assert settings.storage.max_mail_dir_bytes == 1_073_741_824
    assert settings.rate_limit.max_keys == 10_000

    monkeypatch.setenv("MAILONEY_MAX_RECIPIENTS", "7")
    from mailoney.config import get_settings

    assert get_settings("/nonexistent.toml").server.max_recipients == 7


def test_servers_share_limits(tmp_path):
    settings = Settings.model_validate(
        {
            "storage": {"mail_dir": str(tmp_path / "mails")},
            "logging": {"log_file": str(tmp_path / "log.json")},
        }
    )
    servers = core._build_honeypot_servers(
        settings,
        rate_limiter=None,
        json_logger=core.JsonlLogger(str(tmp_path / "log.json")),
        tls_context=None,
        tls_material=None,
    )
    assert len(servers) == 2
    assert servers[0].connection_tracker is servers[1].connection_tracker
    assert servers[0].data_slots is servers[1].data_slots
    assert servers[0].mail_quota is servers[1].mail_quota is not None
