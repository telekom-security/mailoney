"""
Core functionality for the Mailoney SMTP honeypot.
"""
from __future__ import annotations

import argparse
import base64
import logging
import queue
import random
import signal
import re
import socket
import ssl
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .config import DEFAULT_CONFIG_FILE, ListenerConfig, Settings, configure_logging, get_settings
from .json_logger import JsonlLogger
from .mail_storage import MailDirQuota, store_mail_message
from .rate_limiter import RateLimitDecision, RateLimiter, source_key
from .tls import TlsMaterial, build_server_context, ensure_tls_material

logger = logging.getLogger(__name__)

DEFAULT_CONN_TIMEOUT = 30
DEFAULT_MAX_MAIL_BODY_BYTES = 10_485_760
DEFAULT_MAX_SESSION_SECONDS = 300
DEFAULT_MAX_CONNECTIONS_PER_IP = 10
DEFAULT_MAX_RECIPIENTS = 100
DEFAULT_MAX_MAILS_PER_SESSION = 20
DEFAULT_MAX_CONCURRENT_DATA = 10
DEFAULT_BANNER = "ESMTP Postfix"
MAX_COMMAND_LINE_BYTES = 16_384
# Every event carries the SMTP input of its session, so the transcript is
# capped by lines, by bytes and per line. Commands such as NOOP or RSET
# reset the error counter, without the caps a client could grow every
# JSON line that repeats the transcript without bound.
MAX_LOGGED_INPUT_LINES = 200
MAX_LOGGED_INPUT_BYTES = 32_768
MAX_LOGGED_LINE_BYTES = 1_024
# AUTH attempts logged per session; the ones beyond it are answered, counted
# in smtp_input_count and named in errors, but get no event of their own.
MAX_AUTH_EVENTS_PER_SESSION = 20
# Commands per session before the session is closed.
MAX_COMMANDS_PER_SESSION = 1_000
# Upper bound in seconds for a TLS handshake (STARTTLS and implicit TLS), so
# a peer that never completes it cannot pin a handler thread. A smaller
# conn_timeout takes precedence. It bounds the whole handshake, not each read.
TLS_HANDSHAKE_TIMEOUT_SECONDS = 10

_DATA_READ_CHUNK = 65_536
_DOT_STUFFING_RE = re.compile(rb"(\A|\n)\.")
_SMTP_PATH_RE = re.compile(r":\s*(?:<([^>]*)>|([^\s]+))", re.IGNORECASE)
_QUEUE_ID_ALPHABET = "0123456789ABCDEF"


class SessionTimeLimit(socket.timeout):
    """The absolute time limit of a session (not the idle timeout) is reached."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def isoformat_epoch(value: Optional[float]) -> Optional[str]:
    if value is None:
        return None
    return isoformat_utc(datetime.fromtimestamp(value, timezone.utc))


def _decode_line(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def _bytes_to_text(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def _extract_smtp_path(raw_line: str) -> Optional[str]:
    match = _SMTP_PATH_RE.search(raw_line)
    if not match:
        return None
    value = match.group(1) if match.group(1) is not None else match.group(2)
    return value.strip() if value is not None else None


def _decode_base64_bytes(value: str) -> Tuple[Optional[bytes], Optional[str]]:
    if value == "=":
        return b"", None
    try:
        padded = value + ("=" * (-len(value) % 4))
        return base64.b64decode(padded.encode("ascii"), validate=False), None
    except Exception as exc:
        return None, str(exc)


def _decode_auth_plain(value: str) -> Dict[str, Optional[str]]:
    decoded, error = _decode_base64_bytes(value)
    if error or decoded is None:
        return {"username": None, "password": None, "decode_error": error}

    parts = decoded.split(b"\x00")
    if len(parts) >= 3:
        username = _bytes_to_text(parts[-2])
        password = _bytes_to_text(parts[-1])
        return {"username": username, "password": password, "decode_error": None}
    if len(parts) == 2:
        return {
            "username": _bytes_to_text(parts[0]),
            "password": _bytes_to_text(parts[1]),
            "decode_error": None,
        }
    return {
        "username": None,
        "password": None,
        "decode_error": "decoded AUTH PLAIN response has no username/password separators",
    }


def _decode_auth_login(username_b64: str, password_b64: str) -> Dict[str, Optional[str]]:
    username_bytes, username_error = _decode_base64_bytes(username_b64)
    password_bytes, password_error = _decode_base64_bytes(password_b64)
    errors = [error for error in (username_error, password_error) if error]
    return {
        "username": _bytes_to_text(username_bytes or b"") if username_error is None else None,
        "password": _bytes_to_text(password_bytes or b"") if password_error is None else None,
        "decode_error": "; ".join(errors) if errors else None,
    }


class SMTPLineReader:
    """
    Buffered CRLF reader that preserves bytes already received after a line.
    This is what lets the server handle SMTP PIPELINING correctly.
    """

    def __init__(
        self,
        sock: socket.socket,
        deadline: Optional[float] = None,
        idle_timeout: Optional[float] = None,
    ):
        self.sock = sock
        self.buffer = b""
        # time.monotonic() value at which the session ends, None for no limit
        self.deadline = deadline
        self.idle_timeout = idle_timeout

    def _recv(self, size: int) -> bytes:
        if self.deadline is None:
            return self.sock.recv(size)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise SessionTimeLimit("session time limit reached")
        timeout = remaining if self.idle_timeout is None else min(self.idle_timeout, remaining)
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(size)
        except socket.timeout:
            if time.monotonic() >= self.deadline:
                raise SessionTimeLimit("session time limit reached") from None
            raise

    def readline(self) -> Optional[bytes]:
        while b"\n" not in self.buffer:
            chunk = self._recv(4096)
            if not chunk:
                return None
            self.buffer += chunk
            if len(self.buffer) > MAX_COMMAND_LINE_BYTES and b"\n" not in self.buffer:
                raise ValueError("SMTP command line too long")

        line, _, rest = self.buffer.partition(b"\n")
        self.buffer = rest
        if line.endswith(b"\r"):
            line = line[:-1]
        if len(line) > MAX_COMMAND_LINE_BYTES:
            raise ValueError("SMTP command line too long")
        return line

    def read_data(self, max_bytes: int) -> Tuple[bytes, bool]:
        """
        Read a DATA body up to <CRLF>.<CRLF> and undo the dot-stuffing.

        A client that sends bare LF line ends throughout may end with
        <LF>.<LF>; once a CRLF was seen only <CRLF>.<CRLF> ends the body, so
        a bare <LF>.<LF> inside a CRLF message stays part of it. Only the new
        bytes of each read are searched (with an overlap of 4 bytes), the
        body is never copied while it grows.
        """
        # A leading CRLF lets a terminator at the very start match as well.
        body = bytearray(b"\r\n")
        crlf_seen = False

        while len(body) - 2 < max_bytes:
            remaining = max_bytes - (len(body) - 2)
            if self.buffer:
                chunk = self.buffer[: min(len(self.buffer), remaining, _DATA_READ_CHUNK)]
                self.buffer = self.buffer[len(chunk) :]
            else:
                chunk = self._recv(min(_DATA_READ_CHUNK, remaining))

            if not chunk:
                break

            search_start = max(0, len(body) - 4)
            body.extend(chunk)

            end: Optional[int] = None
            end_length = 0
            crlf_end = body.find(b"\r\n.\r\n", search_start)
            if crlf_end != -1:
                end, end_length = crlf_end, 5
            if not crlf_seen:
                first_crlf = body.find(b"\r\n", max(2, search_start))
                lf_end = body.find(b"\n.\n", search_start)
                if lf_end != -1 and (first_crlf == -1 or first_crlf > lf_end):
                    if end is None or lf_end < end:
                        end, end_length = lf_end, 3
                crlf_seen = first_crlf != -1

            if end is not None:
                self.buffer = bytes(body[end + end_length :]) + self.buffer
                return _undo_dot_stuffing(bytes(body[2:end])), True

        return _undo_dot_stuffing(bytes(body[2:])), False


def _undo_dot_stuffing(body: bytes) -> bytes:
    """Remove the leading dot the client added to every line starting with a dot."""
    return _DOT_STUFFING_RE.sub(rb"\1", body)


class SessionTranscript:
    """
    Per-session record of SMTP input lines, the last reply code and the
    session outcome.
    """

    def __init__(self) -> None:
        self.lines: List[str] = []
        self.count = 0
        self.logged_bytes = 0
        self.full = False
        self.truncated = False
        self.last_response_code: Optional[int] = None
        self.outcome = "ok"
        self.auth_dropped = 0

    def record_input(self, line: str) -> None:
        self.count += 1
        if self.full or len(self.lines) >= MAX_LOGGED_INPUT_LINES:
            self.full = True
            self.truncated = True
            return
        encoded = line.encode("utf-8", errors="replace")
        if len(encoded) > MAX_LOGGED_LINE_BYTES:
            line = encoded[:MAX_LOGGED_LINE_BYTES].decode("utf-8", errors="ignore")
            encoded = line.encode("utf-8")
            self.truncated = True
        # +1 for the newline that joins the lines
        if self.logged_bytes + len(encoded) + 1 > MAX_LOGGED_INPUT_BYTES:
            self.full = True
            self.truncated = True
            return
        self.lines.append(line)
        self.logged_bytes += len(encoded) + 1

    def record_response(self, response: str) -> None:
        try:
            self.last_response_code = int(response[:3])
        except ValueError:
            pass


class ConnectionTracker:
    """
    Open connections per source (IPv4 address, IPv6 /64), shared by the
    listeners, so one source cannot take every connection slot.
    """

    def __init__(self, max_per_source: int):
        self.max_per_source = max_per_source
        self._lock = threading.Lock()
        self._open: Dict[str, int] = {}

    def acquire(self, src_ip: str) -> bool:
        if not self.max_per_source or self.max_per_source <= 0:
            return True
        key = source_key(src_ip)
        with self._lock:
            count = self._open.get(key, 0)
            if count >= self.max_per_source:
                return False
            self._open[key] = count + 1
            return True

    def release(self, src_ip: str) -> None:
        if not self.max_per_source or self.max_per_source <= 0:
            return
        key = source_key(src_ip)
        with self._lock:
            count = self._open.get(key, 0) - 1
            if count > 0:
                self._open[key] = count
            else:
                self._open.pop(key, None)


def _queue_id() -> str:
    """A queue id as Postfix prints it after an accepted mail."""
    return "".join(random.choice(_QUEUE_ID_ALPHABET) for _ in range(10))


class SMTPHoneypot:
    """
    Low-interaction SMTP honeypot server.
    """

    def __init__(
        self,
        bind_ip: str = "0.0.0.0",
        bind_port: int = 25,
        server_name: str = "mail01.localdomain",
        log_file: str = "log/log.json",
        mail_dir: str = "log/mails",
        save_mail_bodies: bool = True,
        save_attachments: bool = True,
        extract_attachments: Optional[bool] = None,
        conn_timeout: int = DEFAULT_CONN_TIMEOUT,
        max_connections: int = 100,
        max_mail_body_bytes: int = DEFAULT_MAX_MAIL_BODY_BYTES,
        listener_name: str = "smtp",
        advertise_starttls: bool = False,
        implicit_tls: bool = False,
        tls_context: Optional[ssl.SSLContext] = None,
        tls_cert_file: Optional[str] = None,
        rate_limiter: Optional[RateLimiter] = None,
        json_logger: Optional[JsonlLogger] = None,
        banner: str = DEFAULT_BANNER,
        max_session_seconds: int = DEFAULT_MAX_SESSION_SECONDS,
        max_connections_per_ip: int = DEFAULT_MAX_CONNECTIONS_PER_IP,
        max_recipients: int = DEFAULT_MAX_RECIPIENTS,
        max_mails_per_session: int = DEFAULT_MAX_MAILS_PER_SESSION,
        max_attachments_per_mail: int = 50,
        connection_tracker: Optional["ConnectionTracker"] = None,
        data_slots: Optional[threading.Semaphore] = None,
        mail_quota: Optional[MailDirQuota] = None,
    ):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.server_name = server_name
        self.log_file = log_file
        self.mail_dir = mail_dir
        if extract_attachments is not None:
            save_attachments = extract_attachments
        self.save_mail_bodies = save_mail_bodies
        self.save_attachments = save_attachments
        self.conn_timeout = conn_timeout
        self.max_connections = max_connections
        self.max_mail_body_bytes = max_mail_body_bytes
        self.listener_name = listener_name
        self.advertise_starttls = advertise_starttls
        self.implicit_tls = implicit_tls
        self.tls_context = tls_context
        self.tls_cert_file = tls_cert_file
        self.rate_limiter = rate_limiter
        self.json_logger = json_logger or JsonlLogger(log_file)
        self.banner = banner
        self.max_session_seconds = max_session_seconds
        self.max_recipients = max_recipients
        self.max_mails_per_session = max_mails_per_session
        self.max_attachments_per_mail = max_attachments_per_mail
        self.connection_tracker = connection_tracker or ConnectionTracker(
            max_connections_per_ip
        )
        self.data_slots = data_slots or threading.BoundedSemaphore(
            DEFAULT_MAX_CONCURRENT_DATA
        )
        self.mail_quota = mail_quota
        self.socket: Optional[socket.socket] = None
        self._stopping = threading.Event()
        self._connection_slots = (
            threading.BoundedSemaphore(max_connections)
            if max_connections and max_connections > 0
            else None
        )

    @property
    def ehlo_response(self) -> str:
        return self._ehlo_response(tls_active=self.implicit_tls)

    @property
    def listener_tls_mode(self) -> str:
        if self.implicit_tls:
            return "implicit"
        if self.advertise_starttls:
            return "starttls"
        return "plain"

    def _ehlo_response(self, tls_active: bool = False) -> str:
        lines = [
            f"250-{self.server_name}",
            "250-PIPELINING",
            f"250-SIZE {self.max_mail_body_bytes}",
        ]
        if self.advertise_starttls and self.tls_context is not None and not tls_active:
            lines.append("250-STARTTLS")
        lines.extend(
            ["250-AUTH PLAIN LOGIN", "250-ENHANCEDSTATUSCODES", "250 8BITMIME"]
        )
        return (
            "\r\n".join(lines)
            + "\r\n"
        )

    def start(self) -> None:
        """
        Start the SMTP honeypot server.
        """
        try:
            self._stopping.clear()
            if ":" in self.bind_ip:
                family = socket.AF_INET6
                dualstack = self.bind_ip in ("::", "::0") and socket.has_dualstack_ipv6()
            else:
                family = socket.AF_INET
                dualstack = False

            backlog = self.max_connections if self.max_connections > 0 else 100
            self.socket = socket.create_server(
                (self.bind_ip, self.bind_port),
                family=family,
                backlog=backlog,
                dualstack_ipv6=dualstack,
            )

            logger.info(
                "SMTP listener ready: %s on %s:%s (%s)",
                self.listener_name,
                self.bind_ip,
                self.bind_port,
                self.listener_tls_mode,
            )
            self._accept_connections()
        except Exception as exc:
            logger.error("Error starting server: %s", exc)
            if self.socket:
                self.socket.close()
            raise

    def _accept_connections(self) -> None:
        while not self._stopping.is_set():
            try:
                assert self.socket is not None
                client, addr = self.socket.accept()
                logger.info(
                    "Connection from %s:%s to %s:%s",
                    addr[0],
                    addr[1],
                    self.bind_ip,
                    self.bind_port,
                )

                if self._connection_slots and not self._connection_slots.acquire(False):
                    self._refuse(client, "421 4.3.2 Service not available, too many connections\r\n")
                    continue

                if not self.connection_tracker.acquire(str(addr[0])):
                    if self._connection_slots:
                        self._connection_slots.release()
                    self._refuse(
                        client,
                        f"421 4.7.0 {self.server_name} Error: too many connections "
                        f"from {addr[0]}\r\n",
                    )
                    continue

                client_handler = threading.Thread(
                    target=self._handle_client_with_slot_release,
                    args=(client, addr),
                    daemon=True,
                )
                client_handler.start()
            except Exception as exc:
                if self._stopping.is_set():
                    break
                logger.error("Error accepting connection: %s", exc)

    def _refuse(self, client: socket.socket, response: str) -> None:
        """Turn a connection away; an implicit TLS listener closes it without a plain text reply."""
        try:
            if not self.implicit_tls:
                client.settimeout(1)
                client.sendall(response.encode("ascii", errors="replace"))
        except OSError:
            pass
        finally:
            client.close()

    def _tls_handshake(self, client_socket: socket.socket) -> ssl.SSLSocket:
        """
        Run the server side TLS handshake within _handshake_timeout() in total.
        The socket timeout only bounds each read, a watchdog shuts the socket
        down when the whole handshake takes longer.
        """
        timeout = self._handshake_timeout()

        def _abort() -> None:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        watchdog = threading.Timer(timeout, _abort)
        watchdog.daemon = True
        client_socket.settimeout(timeout)
        watchdog.start()
        try:
            assert self.tls_context is not None
            tls_socket = self.tls_context.wrap_socket(client_socket, server_side=True)
        finally:
            watchdog.cancel()
        tls_socket.settimeout(self._idle_timeout())
        return tls_socket

    def _handle_client_with_slot_release(
        self, client_socket: socket.socket, addr: Tuple[Any, ...]
    ) -> None:
        try:
            if self.implicit_tls:
                if self.tls_context is None:
                    logger.error(
                        "Implicit TLS listener %s:%s has no TLS context",
                        self.bind_ip,
                        self.bind_port,
                    )
                    client_socket.close()
                    return
                try:
                    client_socket = self._tls_handshake(client_socket)
                except (ssl.SSLError, OSError) as exc:
                    logger.info(
                        "Implicit TLS handshake failed from %s:%s: %s",
                        addr[0],
                        addr[1],
                        exc,
                    )
                    client_socket.close()
                    return
            self._handle_client(client_socket, addr)
        finally:
            self.connection_tracker.release(str(addr[0]))
            if self._connection_slots:
                self._connection_slots.release()

    def _idle_timeout(self) -> Optional[float]:
        """Socket timeout for the SMTP dialogue; None disables it."""
        if self.conn_timeout and self.conn_timeout > 0:
            return self.conn_timeout
        return None

    def _handshake_timeout(self) -> float:
        """TLS handshake timeout; never looser than the idle timeout."""
        idle = self._idle_timeout()
        if idle is None:
            return TLS_HANDSHAKE_TIMEOUT_SECONDS
        return min(TLS_HANDSHAKE_TIMEOUT_SECONDS, idle)

    def _destination_from_socket(self, client_socket: socket.socket) -> Tuple[str, int]:
        try:
            dest = client_socket.getsockname()
            return str(dest[0]), int(dest[1])
        except Exception:
            return self.bind_ip, self.bind_port

    def _send(
        self,
        client_socket: socket.socket,
        response: str,
        transcript: SessionTranscript,
    ) -> None:
        client_socket.sendall(response.encode("ascii", errors="replace"))
        transcript.record_response(response)

    def _tls_event_fields(
        self,
        client_socket: socket.socket,
        tls_active: bool,
    ) -> Dict[str, Any]:
        fields: Dict[str, Any] = {"tls.used": tls_active}
        if not tls_active:
            return fields

        if isinstance(client_socket, ssl.SSLSocket):
            fields["tls.version"] = client_socket.version()
            cipher = client_socket.cipher()
            if cipher:
                fields["tls.cipher"] = cipher[0]
        fields["tls.server_name"] = self.server_name
        fields["tls.cert_file"] = self.tls_cert_file
        return fields

    def _read_client_line(
        self,
        reader: SMTPLineReader,
        transcript: SessionTranscript,
    ) -> Optional[str]:
        raw = reader.readline()
        if raw is None:
            return None
        line = _decode_line(raw)
        transcript.record_input(line)
        logger.debug("Client: %s", line)
        return line

    def _base_event(
        self,
        *,
        event_type: str,
        timestamp: datetime,
        session_id: str,
        src_ip: str,
        src_port: int,
        dest_ip: str,
        dest_port: int,
        session_start: datetime,
        session_end: datetime,
        transcript: SessionTranscript,
        errors: List[str],
        tls_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        event: Dict[str, Any] = {
            "event.type": event_type,
            "timestamp": isoformat_utc(timestamp),
            "session_id": session_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "session_start": isoformat_utc(session_start),
            "session_end": isoformat_utc(session_end),
            "session_duration": round(
                max(0.0, (session_end - session_start).total_seconds()), 6
            ),
            "server_name": self.server_name,
            "listener.name": self.listener_name,
            "listener.port": self.bind_port,
            "listener.tls_mode": self.listener_tls_mode,
            "smtp_input": "\n".join(transcript.lines),
            "smtp_input_count": transcript.count,
            "smtp_input_truncated": transcript.truncated,
            "session_outcome": transcript.outcome,
            "session_last_response_code": transcript.last_response_code,
        }
        if tls_info:
            event.update(tls_info)
        if errors:
            event["errors"] = list(errors)
        return event

    def _write_rate_limit_event(
        self,
        decision: RateLimitDecision,
        *,
        session_id: str,
        src_ip: str,
        src_port: int,
        dest_ip: str,
        dest_port: int,
        session_start: datetime,
        transcript: SessionTranscript,
        errors: List[str],
        tls_info: Optional[Dict[str, Any]],
    ) -> None:
        if not decision.should_log:
            return

        now = utc_now()
        event = self._base_event(
            event_type="rate_limit_block",
            timestamp=now,
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            session_start=session_start,
            session_end=now,
            transcript=transcript,
            errors=errors,
            tls_info=tls_info,
        )
        event.update(
            {
                "rate_limit.scope": decision.scope,
                "rate_limit.key": decision.key,
                "rate_limit.limit": decision.limit,
                "rate_limit.window_seconds": decision.window_seconds,
                "rate_limit.block_seconds": decision.block_seconds,
                "rate_limit.blocked_from": isoformat_epoch(decision.blocked_from),
                "rate_limit.blocked_until": isoformat_epoch(decision.blocked_until),
            }
        )
        self.json_logger.write(event)

    def _rate_limit_denied(
        self,
        client_socket: socket.socket,
        decision: RateLimitDecision,
        *,
        session_id: str,
        src_ip: str,
        src_port: int,
        dest_ip: str,
        dest_port: int,
        session_start: datetime,
        transcript: SessionTranscript,
        errors: List[str],
        tls_info: Optional[Dict[str, Any]],
    ) -> bool:
        if decision.allowed:
            return False

        transcript.outcome = "rate_limited"
        self._write_rate_limit_event(
            decision,
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            session_start=session_start,
            transcript=transcript,
            errors=errors,
            tls_info=tls_info,
        )
        self._send(client_socket, "421 4.7.0 Rate limit exceeded\r\n", transcript)
        return True

    def _store_and_describe_mail(
        self,
        *,
        src_ip: str,
        session_id: str,
        message_id: str,
        body: bytes,
    ) -> Dict[str, Any]:
        return store_mail_message(
            self.mail_dir,
            src_ip,
            session_id,
            message_id,
            body,
            save_mail_body=self.save_mail_bodies,
            save_attachments=self.save_attachments,
            max_attachments=self.max_attachments_per_mail,
            quota=self.mail_quota,
        )

    def _handle_auth_plain(
        self,
        client_socket: socket.socket,
        reader: SMTPLineReader,
        raw_line: str,
        auth_events: List[Dict[str, Any]],
        transcript: SessionTranscript,
    ) -> bool:
        parts = raw_line.split(None, 2)
        auth_value: Optional[str] = parts[2] if len(parts) >= 3 else None
        if auth_value is None:
            self._send(client_socket, "334 \r\n", transcript)
            auth_value = self._read_client_line(reader, transcript)
            if auth_value is None:
                return False
            if auth_value == "*":
                self._send(
                    client_socket,
                    "501 5.7.0 Authentication cancelled\r\n",
                    transcript,
                )
                return True

        decoded = _decode_auth_plain(auth_value)
        self._record_auth(
            auth_events,
            transcript,
            {
                "timestamp": isoformat_utc(utc_now()),
                "method": "plain",
                "raw": auth_value,
                "username": decoded["username"],
                "password": decoded["password"],
                "decode_error": decoded["decode_error"],
            },
        )
        self._send(client_socket, self._auth_response(decoded), transcript)
        return True

    def _handle_auth_login(
        self,
        client_socket: socket.socket,
        reader: SMTPLineReader,
        raw_line: str,
        auth_events: List[Dict[str, Any]],
        transcript: SessionTranscript,
    ) -> bool:
        parts = raw_line.split(None, 2)
        username_b64: Optional[str] = parts[2] if len(parts) >= 3 else None
        if username_b64 is None:
            self._send(client_socket, "334 VXNlcm5hbWU6\r\n", transcript)
            username_b64 = self._read_client_line(reader, transcript)
            if username_b64 is None:
                return False

        if username_b64 == "*":
            self._send(
                client_socket,
                "501 5.7.0 Authentication cancelled\r\n",
                transcript,
            )
            return True

        self._send(client_socket, "334 UGFzc3dvcmQ6\r\n", transcript)
        password_b64 = self._read_client_line(reader, transcript)
        if password_b64 is None:
            return False
        if password_b64 == "*":
            self._send(
                client_socket,
                "501 5.7.0 Authentication cancelled\r\n",
                transcript,
            )
            return True

        decoded = _decode_auth_login(username_b64, password_b64)
        self._record_auth(
            auth_events,
            transcript,
            {
                "timestamp": isoformat_utc(utc_now()),
                "method": "login",
                "raw": f"{username_b64}:{password_b64}",
                "username": decoded["username"],
                "password": decoded["password"],
                "decode_error": decoded["decode_error"],
            },
        )
        self._send(client_socket, self._auth_response(decoded), transcript)
        return True

    @staticmethod
    def _record_auth(
        auth_events: List[Dict[str, Any]],
        transcript: SessionTranscript,
        auth: Dict[str, Any],
    ) -> None:
        if len(auth_events) >= MAX_AUTH_EVENTS_PER_SESSION:
            transcript.auth_dropped += 1
            return
        auth_events.append(auth)

    @staticmethod
    def _auth_response(decoded: Dict[str, Optional[str]]) -> str:
        """Every login succeeds, a response that cannot be decoded fails as on a real server."""
        if decoded["username"] is None and decoded["password"] is None:
            return "501 5.5.2 Cannot decode response\r\n"
        if decoded["decode_error"]:
            return "535 5.7.8 Error: authentication failed\r\n"
        return "235 2.7.0 Authentication successful\r\n"

    def _emit_final_events(
        self,
        *,
        session_id: str,
        src_ip: str,
        src_port: int,
        dest_ip: str,
        dest_port: int,
        session_start: datetime,
        session_end: datetime,
        transcript: SessionTranscript,
        auth_events: List[Dict[str, Any]],
        mail_events: List[Dict[str, Any]],
        errors: List[str],
        tls_info: Dict[str, Any],
    ) -> None:
        for index, auth in enumerate(auth_events, start=1):
            event = self._base_event(
                event_type="auth",
                timestamp=session_end,
                session_id=session_id,
                src_ip=src_ip,
                src_port=src_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                session_start=session_start,
                session_end=session_end,
                transcript=transcript,
                errors=errors,
                tls_info=tls_info,
            )
            event.update(
                {
                    "auth.sequence": index,
                    "auth.timestamp": auth["timestamp"],
                    "auth.method": auth["method"],
                    "auth.raw": auth["raw"],
                    "auth.username": auth["username"],
                    "auth.password": auth["password"],
                    "auth.decode_error": auth["decode_error"],
                }
            )
            self.json_logger.write(event)

        for mail in mail_events:
            attachments = mail.get("attachments", [])
            event = self._base_event(
                event_type="mail",
                timestamp=session_end,
                session_id=session_id,
                src_ip=src_ip,
                src_port=src_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                session_start=session_start,
                session_end=session_end,
                transcript=transcript,
                errors=errors,
                tls_info=tls_info,
            )
            event.update({key: value for key, value in mail.items() if key != "attachments"})
            event.update(
                {
                    "attachment.count": len(attachments),
                    "attachment.files": [item["path"] for item in attachments],
                    "attachment.filenames": [item["filename"] for item in attachments],
                    "attachment.sha256": [item["sha256"] for item in attachments],
                }
            )
            self.json_logger.write(event)

        if not mail_events:
            event = self._base_event(
                event_type="session",
                timestamp=session_end,
                session_id=session_id,
                src_ip=src_ip,
                src_port=src_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                session_start=session_start,
                session_end=session_end,
                transcript=transcript,
                errors=errors,
                tls_info=tls_info,
            )
            event["auth.count"] = len(auth_events)
            self.json_logger.write(event)

    def _handle_client(self, client_socket: socket.socket, addr: Tuple[Any, ...]) -> None:
        session_id = str(uuid.uuid4())
        session_start = utc_now()
        src_ip = str(addr[0])
        src_port = int(addr[1])
        dest_ip, dest_port = self._destination_from_socket(client_socket)
        transcript = SessionTranscript()
        auth_events: List[Dict[str, Any]] = []
        mail_events: List[Dict[str, Any]] = []
        errors: List[str] = []
        tls_active = self.implicit_tls
        tls_info = self._tls_event_fields(client_socket, tls_active)

        helo_name: Optional[str] = None
        greeted = False
        mail_started = False
        envelope_from: Optional[str] = None
        envelope_to: List[str] = []

        if self.conn_timeout and self.conn_timeout > 0:
            client_socket.settimeout(self.conn_timeout)

        deadline = (
            time.monotonic() + self.max_session_seconds
            if self.max_session_seconds and self.max_session_seconds > 0
            else None
        )
        reader = SMTPLineReader(client_socket, deadline, self._idle_timeout())

        def rate_limited(decision: RateLimitDecision) -> bool:
            return self._rate_limit_denied(
                client_socket,
                decision,
                session_id=session_id,
                src_ip=src_ip,
                src_port=src_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                session_start=session_start,
                transcript=transcript,
                errors=errors,
                tls_info=tls_info,
            )

        try:
            self._send(
                client_socket,
                f"220 {self.server_name} {self.banner}\r\n",
                transcript,
            )
            error_count = 0
            command_count = 0

            while True:
                if error_count >= 10:
                    self._send(
                        client_socket,
                        f"421 4.7.0 {self.server_name} Error: too many errors\r\n",
                        transcript,
                    )
                    transcript.outcome = "error"
                    break
                try:
                    raw_line = self._read_client_line(reader, transcript)
                    if raw_line is None:
                        break

                    stripped = raw_line.strip()
                    if not stripped:
                        continue

                    command_count += 1
                    if command_count > MAX_COMMANDS_PER_SESSION:
                        errors.append(
                            f"command limit of {MAX_COMMANDS_PER_SESSION} reached"
                        )
                        self._send(
                            client_socket,
                            f"421 4.7.0 {self.server_name} Error: too many commands\r\n",
                            transcript,
                        )
                        transcript.outcome = "limit"
                        break

                    upper = stripped.upper()
                    command = stripped.split(None, 1)[0].upper()

                    if command in {"EHLO", "HELO"}:
                        parts = stripped.split(None, 1)
                        if len(parts) < 2:
                            self._send(
                                client_socket,
                                f"501 Syntax: {command} hostname\r\n",
                                transcript,
                            )
                            error_count += 1
                            continue
                        helo_name = parts[1]
                        greeted = True
                        mail_started = False
                        envelope_from = None
                        envelope_to = []
                        response = (
                            self._ehlo_response(tls_active=tls_active)
                            if command == "EHLO"
                            else f"250 {self.server_name}\r\n"
                        )
                        self._send(client_socket, response, transcript)
                        error_count = 0

                    elif upper.startswith("MAIL FROM"):
                        if mail_started:
                            self._send(
                                client_socket,
                                "503 5.5.1 Error: nested MAIL command\r\n",
                                transcript,
                            )
                            error_count += 1
                            continue
                        if (
                            self.max_mails_per_session
                            and self.max_mails_per_session > 0
                            and len(mail_events) >= self.max_mails_per_session
                        ):
                            errors.append(
                                "mail limit of "
                                f"{self.max_mails_per_session} per session reached"
                            )
                            self._send(
                                client_socket,
                                f"421 4.7.0 {self.server_name} Error: too many "
                                "messages in this session\r\n",
                                transcript,
                            )
                            transcript.outcome = "limit"
                            break
                        envelope_from = _extract_smtp_path(stripped)
                        envelope_to = []
                        if self.rate_limiter and envelope_from:
                            decision = self.rate_limiter.check("sender", envelope_from)
                            if rate_limited(decision):
                                break
                        mail_started = True
                        self._send(client_socket, "250 2.1.0 Ok\r\n", transcript)
                        error_count = 0

                    elif upper.startswith("RCPT TO"):
                        if not mail_started:
                            self._send(
                                client_socket,
                                "503 5.5.1 Error: need MAIL command\r\n",
                                transcript,
                            )
                            error_count += 1
                            continue
                        if (
                            self.max_recipients
                            and self.max_recipients > 0
                            and len(envelope_to) >= self.max_recipients
                        ):
                            self._send(
                                client_socket,
                                "452 4.5.3 Error: too many recipients\r\n",
                                transcript,
                            )
                            error_count += 1
                            continue
                        recipient = _extract_smtp_path(stripped)
                        if recipient:
                            envelope_to.append(recipient)
                        self._send(client_socket, "250 2.1.5 Ok\r\n", transcript)
                        error_count = 0

                    elif command == "DATA":
                        if not mail_started or not envelope_to:
                            self._send(
                                client_socket,
                                "503 5.5.1 Error: need RCPT command\r\n",
                                transcript,
                            )
                            error_count += 1
                            continue
                        if self.rate_limiter:
                            if rate_limited(self.rate_limiter.check("ip", src_ip)):
                                break
                            if rate_limited(
                                self.rate_limiter.check("sender", envelope_from)
                            ):
                                break

                        if not self.data_slots.acquire(False):
                            errors.append("DATA refused: too many mails in transfer")
                            self._send(
                                client_socket,
                                "451 4.3.0 Error: queue file write error\r\n",
                                transcript,
                            )
                            error_count += 1
                            continue
                        try:
                            self._send(
                                client_socket,
                                "354 End data with <CR><LF>.<CR><LF>\r\n",
                                transcript,
                            )
                            body, terminator_found = reader.read_data(
                                self.max_mail_body_bytes
                            )
                            self._capture_mail(
                                mail_events,
                                errors,
                                src_ip=src_ip,
                                session_id=session_id,
                                helo_name=helo_name,
                                envelope_from=envelope_from,
                                envelope_to=envelope_to,
                                body=body,
                                terminator_found=terminator_found,
                            )
                        finally:
                            self.data_slots.release()

                        if self.rate_limiter:
                            self.rate_limiter.record_message(src_ip, envelope_from)

                        if terminator_found:
                            self._send(
                                client_socket,
                                f"250 2.0.0 Ok: queued as {_queue_id()}\r\n",
                                transcript,
                            )
                            mail_started = False
                            envelope_from = None
                            envelope_to = []
                            error_count = 0
                        elif len(body) >= self.max_mail_body_bytes:
                            self._send(
                                client_socket,
                                "552 5.3.4 Error: message file too big\r\n",
                                transcript,
                            )
                            transcript.outcome = "error"
                            break
                        else:
                            self._send(
                                client_socket,
                                f"421 4.4.2 {self.server_name} Error: timeout exceeded\r\n",
                                transcript,
                            )
                            transcript.outcome = "error"
                            break

                    elif command == "AUTH":
                        if not greeted:
                            self._send(
                                client_socket,
                                "503 5.5.1 Error: send HELO/EHLO first\r\n",
                                transcript,
                            )
                            error_count += 1
                            continue
                        parts = stripped.split(None, 2)
                        mechanism = parts[1].upper() if len(parts) >= 2 else ""
                        if mechanism == "PLAIN":
                            if not self._handle_auth_plain(
                                client_socket,
                                reader,
                                stripped,
                                auth_events,
                                transcript,
                            ):
                                break
                            error_count = 0
                        elif mechanism == "LOGIN":
                            if not self._handle_auth_login(
                                client_socket,
                                reader,
                                stripped,
                                auth_events,
                                transcript,
                            ):
                                break
                            error_count = 0
                        else:
                            self._send(
                                client_socket,
                                "535 5.7.8 Error: authentication failed: "
                                "Invalid authentication mechanism\r\n",
                                transcript,
                            )
                            error_count += 1

                    elif command == "RSET":
                        mail_started = False
                        envelope_from = None
                        envelope_to = []
                        self._send(client_socket, "250 2.0.0 Ok\r\n", transcript)
                        error_count = 0

                    elif command == "NOOP":
                        self._send(client_socket, "250 2.0.0 Ok\r\n", transcript)
                        error_count = 0

                    elif command == "VRFY":
                        parts = stripped.split(None, 1)
                        if len(parts) < 2:
                            self._send(
                                client_socket,
                                "501 5.5.4 Syntax: VRFY address\r\n",
                                transcript,
                            )
                            error_count += 1
                            continue
                        self._send(
                            client_socket,
                            f"252 2.0.0 {parts[1][:256]}\r\n",
                            transcript,
                        )
                        error_count = 0

                    elif command == "STARTTLS":
                        if tls_active:
                            self._send(
                                client_socket,
                                "554 5.5.1 Error: TLS already active\r\n",
                                transcript,
                            )
                            error_count += 1
                            continue
                        if not self.advertise_starttls or self.tls_context is None:
                            self._send(
                                client_socket,
                                "502 5.5.1 Error: command not implemented\r\n",
                                transcript,
                            )
                            error_count += 1
                            continue

                        self._send(
                            client_socket,
                            "220 2.0.0 Ready to start TLS\r\n",
                            transcript,
                        )
                        try:
                            client_socket = self._tls_handshake(client_socket)
                        except (ssl.SSLError, OSError) as exc:
                            errors.append(f"STARTTLS handshake failed: {exc}")
                            logger.info(
                                "STARTTLS handshake failed from %s:%s: %s",
                                src_ip,
                                src_port,
                                exc,
                            )
                            transcript.outcome = "tls_failed"
                            break

                        tls_active = True
                        tls_info = self._tls_event_fields(client_socket, tls_active)
                        # Plain text pipelined behind STARTTLS is dropped (RFC 3207)
                        reader = SMTPLineReader(client_socket, deadline, self._idle_timeout())
                        helo_name = None
                        greeted = False
                        mail_started = False
                        envelope_from = None
                        envelope_to = []
                        error_count = 0

                    elif command == "QUIT":
                        self._send(client_socket, "221 2.0.0 Bye\r\n", transcript)
                        break

                    else:
                        self._send(
                            client_socket,
                            "502 5.5.2 Error: command not recognized\r\n",
                            transcript,
                        )
                        error_count += 1

                except SessionTimeLimit:
                    errors.append(
                        f"session time limit of {self.max_session_seconds}s reached"
                    )
                    logger.info(
                        "Connection from %s:%s reached the session time limit of %ss",
                        src_ip,
                        src_port,
                        self.max_session_seconds,
                    )
                    try:
                        self._send(
                            client_socket,
                            f"421 4.4.2 {self.server_name} Error: timeout exceeded\r\n",
                            transcript,
                        )
                    except OSError:
                        pass
                    transcript.outcome = "timeout"
                    break
                except socket.timeout:
                    errors.append(f"connection timed out after {self.conn_timeout}s")
                    logger.info(
                        "Connection from %s:%s timed out after %ss of inactivity",
                        src_ip,
                        src_port,
                        self.conn_timeout,
                    )
                    try:
                        self._send(
                            client_socket,
                            f"421 4.4.2 {self.server_name} Error: timeout exceeded\r\n",
                            transcript,
                        )
                    except OSError:
                        pass
                    transcript.outcome = "timeout"
                    break
                except ValueError as exc:
                    errors.append(str(exc))
                    transcript.outcome = "error"
                    self._send(
                        client_socket,
                        "500 5.5.2 Error: line too long\r\n",
                        transcript,
                    )
                    break
                except OSError as exc:
                    errors.append(f"client disconnected: {exc}")
                    transcript.outcome = "error"
                    logger.info(
                        "Connection from %s:%s closed during SMTP handling: %s",
                        src_ip,
                        src_port,
                        exc,
                    )
                    break
                except Exception as exc:
                    errors.append(f"handler error: {exc}")
                    transcript.outcome = "error"
                    logger.error("Error handling client request: %s", exc)
                    error_count += 1
        except OSError as exc:
            errors.append(f"client disconnected: {exc}")
            transcript.outcome = "error"
            logger.info("Client %s:%s disconnected: %s", src_ip, src_port, exc)
        except Exception as exc:
            errors.append(f"client handler failed: {exc}")
            transcript.outcome = "error"
            logger.error("Error in client handler: %s", exc)
        finally:
            try:
                client_socket.close()
            finally:
                session_end = utc_now()
                if transcript.auth_dropped:
                    errors.append(
                        f"{transcript.auth_dropped} AUTH attempts not logged "
                        f"(limit {MAX_AUTH_EVENTS_PER_SESSION} per session)"
                    )
                # A rate limited session without logins and mails is only the
                # rate_limit_block event (logged once with log_block_once)
                if transcript.outcome != "rate_limited" or auth_events or mail_events:
                    try:
                        self._emit_final_events(
                            session_id=session_id,
                            src_ip=src_ip,
                            src_port=src_port,
                            dest_ip=dest_ip,
                            dest_port=dest_port,
                            session_start=session_start,
                            session_end=session_end,
                            transcript=transcript,
                            auth_events=auth_events,
                            mail_events=mail_events,
                            errors=errors,
                            tls_info=tls_info,
                        )
                    except Exception as exc:
                        logger.error("Failed to write JSON event: %s", exc)
                logger.info(
                    "Connection closed for %s:%s (dest: %s:%s)",
                    src_ip,
                    src_port,
                    dest_ip,
                    dest_port,
                )

    def _capture_mail(
        self,
        mail_events: List[Dict[str, Any]],
        errors: List[str],
        *,
        src_ip: str,
        session_id: str,
        helo_name: Optional[str],
        envelope_from: Optional[str],
        envelope_to: List[str],
        body: bytes,
        terminator_found: bool,
    ) -> None:
        """Store a received mail and keep its event for the end of the session; never raises."""
        message_id = str(uuid.uuid4())
        message_timestamp = utc_now()
        storage: Dict[str, Any] = {}
        try:
            storage = self._store_and_describe_mail(
                src_ip=src_ip,
                session_id=session_id,
                message_id=message_id,
                body=body,
            )
        except Exception as exc:
            errors.append(f"mail storage failed: {exc}")
            logger.error("Failed to store mail: %s", exc)
        for problem in storage.get("errors", []):
            errors.append(problem)

        mail_events.append(
            {
                "mail.message_id": message_id,
                "mail.timestamp": isoformat_utc(message_timestamp),
                "mail.sequence": len(mail_events) + 1,
                "mail.envelope_from": envelope_from,
                "mail.envelope_to": list(envelope_to),
                "mail.header_from": storage.get("header_from"),
                "mail.header_to": storage.get("header_to"),
                "mail.subject": storage.get("subject"),
                "mail.sending_mailserver": helo_name,
                "mail.eml_file": storage.get("eml_file"),
                "mail.eml_size": storage.get("eml_size"),
                "mail.truncated": not terminator_found,
                "attachments": storage.get("attachments", []),
            }
        )

    def stop(self) -> None:
        self._stopping.set()
        if self.socket:
            self.socket.close()
            logger.info("SMTP Honeypot server stopped")


class SMTPServerGroup:
    def __init__(self, servers: List[SMTPHoneypot]):
        self.servers = servers
        self._threads: List[threading.Thread] = []
        self._errors: "queue.Queue[BaseException]" = queue.Queue()

    def start(self) -> None:
        if not self.servers:
            raise RuntimeError("No SMTP listeners configured")
        if len(self.servers) == 1:
            self.servers[0].start()
            return

        for server in self.servers:
            thread = threading.Thread(
                target=self._run_server,
                args=(server,),
                name=f"mailoney-{server.listener_name}-{server.bind_port}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

        while any(thread.is_alive() for thread in self._threads):
            try:
                exc = self._errors.get_nowait()
            except queue.Empty:
                pass
            else:
                self.stop()
                raise exc
            for thread in self._threads:
                thread.join(timeout=1)

        try:
            exc = self._errors.get_nowait()
        except queue.Empty:
            return
        raise exc

    def _run_server(self, server: SMTPHoneypot) -> None:
        try:
            server.start()
        except BaseException as exc:
            self._errors.put(exc)

    def stop(self) -> None:
        for server in self.servers:
            server.stop()


def _build_honeypot_servers(
    settings: Settings,
    *,
    rate_limiter: RateLimiter,
    json_logger: JsonlLogger,
    tls_context: Optional[ssl.SSLContext],
    tls_material: Optional[TlsMaterial],
) -> List[SMTPHoneypot]:
    servers: List[SMTPHoneypot] = []
    # Shared by all listeners, a source cannot multiply its limits over the ports
    connection_tracker = ConnectionTracker(settings.server.max_connections_per_ip)
    data_slots = threading.BoundedSemaphore(max(1, settings.server.max_concurrent_data))
    mail_quota = (
        MailDirQuota(settings.storage.mail_dir, settings.storage.max_mail_dir_bytes)
        if settings.storage.max_mail_dir_bytes > 0
        else None
    )
    for listener in settings.server.listeners:
        if listener.implicit_tls and tls_context is None:
            logger.warning(
                "Skipping implicit TLS listener %s:%s because TLS is disabled",
                listener.bind_ip,
                listener.port,
            )
            continue

        servers.append(
            SMTPHoneypot(
                bind_ip=listener.bind_ip,
                bind_port=listener.port,
                server_name=settings.server.server_name,
                log_file=settings.logging.log_file,
                mail_dir=settings.storage.mail_dir,
                save_mail_bodies=settings.storage.save_mail_bodies,
                save_attachments=settings.storage.save_attachments,
                conn_timeout=settings.server.conn_timeout,
                max_connections=settings.server.max_connections,
                max_mail_body_bytes=settings.server.max_mail_body_bytes,
                listener_name=listener.name,
                advertise_starttls=(
                    listener.starttls
                    and not listener.implicit_tls
                    and tls_context is not None
                ),
                implicit_tls=listener.implicit_tls,
                tls_context=tls_context,
                tls_cert_file=tls_material.cert_file if tls_material else None,
                rate_limiter=rate_limiter,
                json_logger=json_logger,
                banner=settings.server.banner,
                max_session_seconds=settings.server.max_session_seconds,
                max_recipients=settings.server.max_recipients,
                max_mails_per_session=settings.server.max_mails_per_session,
                max_attachments_per_mail=settings.storage.max_attachments_per_mail,
                connection_tracker=connection_tracker,
                data_slots=data_slots,
                mail_quota=mail_quota,
            )
        )
    return servers


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument(
        "--config",
        default=None,
        help=f"TOML config file path (default: {DEFAULT_CONFIG_FILE})",
    )
    pre_args, _ = pre_parser.parse_known_args(argv)
    get_settings(pre_args.config)

    parser = argparse.ArgumentParser(
        description="Mailoney - A Simple SMTP Honeypot",
        parents=[pre_parser],
    )
    parser.add_argument("-i", "--ip", default=None, help=argparse.SUPPRESS)
    parser.add_argument("-p", "--port", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("-s", "--server-name", default=None)
    parser.add_argument("--conn-timeout", type=int, default=None)
    parser.add_argument(
        "--max-mail-body-bytes",
        type=int,
        default=None,
    )
    parser.add_argument("--max-connections", type=int, default=None)
    parser.add_argument("--banner", default=None)
    parser.add_argument("--max-session-seconds", type=int, default=None)
    parser.add_argument("--max-connections-per-ip", type=int, default=None)
    parser.add_argument("--max-recipients", type=int, default=None)
    parser.add_argument("--max-mails-per-session", type=int, default=None)
    parser.add_argument("--max-concurrent-data", type=int, default=None)
    parser.add_argument("--max-attachments-per-mail", type=int, default=None)
    parser.add_argument("--max-mail-dir-bytes", type=int, default=None)
    parser.add_argument("--log-file", default=None)
    parser.add_argument("--log-level", default=None)
    parser.add_argument("--mail-dir", default=None)
    parser.add_argument(
        "--save-mail-bodies",
        dest="save_mail_bodies",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--no-save-mail-bodies",
        dest="save_mail_bodies",
        action="store_false",
    )
    parser.add_argument(
        "--save-attachments",
        dest="save_attachments",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--no-save-attachments",
        dest="save_attachments",
        action="store_false",
    )
    parser.add_argument(
        "--extract-attachments",
        dest="save_attachments",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-extract-attachments",
        dest="save_attachments",
        action="store_false",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--tls-enabled",
        dest="tls_enabled",
        action="store_true",
        default=None,
    )
    parser.add_argument("--no-tls", dest="tls_enabled", action="store_false")
    parser.add_argument(
        "--tls-auto-generate",
        dest="tls_auto_generate",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--no-tls-auto-generate",
        dest="tls_auto_generate",
        action="store_false",
    )
    parser.add_argument("--tls-cert-file", default=None)
    parser.add_argument("--tls-key-file", default=None)
    parser.add_argument(
        "--rate-limit-enabled",
        dest="rate_limit_enabled",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--no-rate-limit",
        dest="rate_limit_enabled",
        action="store_false",
    )
    parser.add_argument(
        "--rate-limit-window-seconds",
        type=int,
        default=None,
    )
    parser.add_argument(
        "--rate-limit-block-seconds",
        type=int,
        default=None,
    )
    parser.add_argument(
        "--rate-limit-max-messages-per-ip",
        type=int,
        default=None,
    )
    parser.add_argument(
        "--rate-limit-max-messages-per-sender",
        type=int,
        default=None,
    )
    parser.add_argument(
        "--rate-limit-state-file",
        default=None,
    )
    parser.add_argument(
        "--rate-limit-log-block-once",
        dest="rate_limit_log_block_once",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--rate-limit-log-every-blocked-attempt",
        dest="rate_limit_log_block_once",
        action="store_false",
    )
    return parser.parse_args(argv)


def _format_banner(version: str, width: int = 68) -> str:
    title = f"Mailoney - A Simple SMTP Honeypot - Version: {version}"
    inner_width = max(width - 2, len(title) + 2)
    border = "*" * (inner_width + 2)
    return "\n".join((border, f"*{title.center(inner_width)}*", border))


def display_banner() -> None:
    from . import __version__

    print(_format_banner(__version__), flush=True)


def _settings_from_args(args: argparse.Namespace) -> Settings:
    settings = get_settings(getattr(args, "config", None))
    data = settings.model_dump()

    legacy_cli_listener = False
    first_listener = settings.server.listeners[0] if settings.server.listeners else ListenerConfig()
    legacy_bind_ip = first_listener.bind_ip
    legacy_bind_port = first_listener.port
    if args.ip is not None:
        legacy_bind_ip = args.ip
        legacy_cli_listener = True
    if args.port is not None:
        legacy_bind_port = args.port
        legacy_cli_listener = True
    if legacy_cli_listener:
        data["server"]["listeners"] = [
            ListenerConfig(
                name="smtp",
                bind_ip=legacy_bind_ip,
                port=legacy_bind_port,
                starttls=True,
                implicit_tls=False,
            ).model_dump()
        ]

    optional_overrides = (
        ("server", "server_name", "server_name"),
        ("server", "conn_timeout", "conn_timeout"),
        ("server", "max_connections", "max_connections"),
        ("server", "max_mail_body_bytes", "max_mail_body_bytes"),
        ("server", "banner", "banner"),
        ("server", "max_session_seconds", "max_session_seconds"),
        ("server", "max_connections_per_ip", "max_connections_per_ip"),
        ("server", "max_recipients", "max_recipients"),
        ("server", "max_mails_per_session", "max_mails_per_session"),
        ("server", "max_concurrent_data", "max_concurrent_data"),
        ("storage", "max_attachments_per_mail", "max_attachments_per_mail"),
        ("storage", "max_mail_dir_bytes", "max_mail_dir_bytes"),
        ("logging", "log_file", "log_file"),
        ("logging", "log_level", "log_level"),
        ("storage", "mail_dir", "mail_dir"),
        ("storage", "save_mail_bodies", "save_mail_bodies"),
        ("storage", "save_attachments", "save_attachments"),
        ("tls", "enabled", "tls_enabled"),
        ("tls", "auto_generate", "tls_auto_generate"),
        ("tls", "cert_file", "tls_cert_file"),
        ("tls", "key_file", "tls_key_file"),
        ("rate_limit", "enabled", "rate_limit_enabled"),
        ("rate_limit", "window_seconds", "rate_limit_window_seconds"),
        ("rate_limit", "block_seconds", "rate_limit_block_seconds"),
        ("rate_limit", "max_messages_per_ip", "rate_limit_max_messages_per_ip"),
        (
            "rate_limit",
            "max_messages_per_sender",
            "rate_limit_max_messages_per_sender",
        ),
        ("rate_limit", "log_block_once", "rate_limit_log_block_once"),
        ("rate_limit", "state_file", "rate_limit_state_file"),
    )
    for section, field, attr in optional_overrides:
        value = getattr(args, attr, None)
        if value is not None:
            data[section][field] = value

    return Settings.model_validate(data)


def run_server() -> None:
    args = parse_args()
    settings = _settings_from_args(args)
    configure_logging(settings.logging.log_level)
    display_banner()
    server_group: Optional[SMTPServerGroup] = None
    rate_limiter: Optional[RateLimiter] = None

    def _terminate(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    # docker stop sends SIGTERM, shut down as on Ctrl+C
    signal.signal(signal.SIGTERM, _terminate)

    try:
        rate_limiter = RateLimiter(settings.rate_limit)
        json_logger = JsonlLogger(settings.logging.log_file)
        tls_material = ensure_tls_material(
            settings.tls,
            settings.server.server_name,
        )
        tls_context = build_server_context(tls_material) if tls_material else None
        servers = _build_honeypot_servers(
            settings,
            rate_limiter=rate_limiter,
            json_logger=json_logger,
            tls_context=tls_context,
            tls_material=tls_material,
        )
        server_group = SMTPServerGroup(servers)

        logger.info(
            "Starting SMTP Honeypot on %s listener(s): %s",
            len(servers),
            ", ".join(
                (
                    f"{server.listener_name}={server.bind_ip}:{server.bind_port}"
                    f" ({server.listener_tls_mode})"
                )
                for server in servers
            ),
        )
        server_group.start()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        if server_group is not None:
            server_group.stop()
        if rate_limiter is not None:
            rate_limiter.flush()
    except Exception as exc:
        logger.error("Error running server: %s", exc)
        sys.exit(1)
