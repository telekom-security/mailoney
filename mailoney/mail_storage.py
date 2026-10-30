"""
Filesystem storage for captured SMTP messages and attachments.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote_to_bytes

logger = logging.getLogger(__name__)


def _safe_ip_segment(src_ip: str) -> str:
    cleaned = "".join(c for c in src_ip if c.isalnum() or c in ".:%_-")
    return cleaned or "unknown"


MAX_FILENAME_BYTES = 150
QUOTA_RESCAN_SECONDS = 60.0


def _clean_text(value: Optional[str]) -> Optional[str]:
    """Text that encodes as UTF-8, lone surrogates (e.g. from UTF-7) are replaced."""
    if value is None:
        return None
    return str(value).encode("utf-8", errors="replace").decode("utf-8")


def _safe_filename(name: str, fallback: str = "attachment.bin") -> str:
    name = Path(_clean_text(name) or fallback).name
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip(" .")
    if not name:
        return fallback
    if len(name) > MAX_FILENAME_BYTES:
        stem, dot, suffix = name.rpartition(".")
        if dot and stem and len(suffix) <= 16:
            name = f"{stem[: MAX_FILENAME_BYTES - len(suffix) - 1]}.{suffix}"
        else:
            name = name[:MAX_FILENAME_BYTES]
    return name


class MailDirQuota:
    """
    Upper bound for the bytes below the mail folder. The folder is measured at
    the start and again (at most every QUOTA_RESCAN_SECONDS) when a write would
    exceed the bound, so files removed from outside free the space again.
    """

    def __init__(self, mail_dir: str, max_bytes: int):
        self.mail_dir = Path(mail_dir)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._used = self._measure()
        self._measured_at = time.monotonic()

    def _measure(self) -> int:
        total = 0
        stack = [self.mail_dir]
        while stack:
            directory = stack.pop()
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(Path(entry.path))
                            elif entry.is_file(follow_symlinks=False):
                                total += entry.stat(follow_symlinks=False).st_size
                        except OSError:
                            continue
            except OSError:
                continue
        return total

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    def reserve(self, size: int) -> bool:
        """Count size bytes as written if they fit, False if they do not."""
        if self.max_bytes <= 0:
            return True
        with self._lock:
            if self._used + size > self.max_bytes:
                now = time.monotonic()
                if now - self._measured_at >= QUOTA_RESCAN_SECONDS:
                    self._used = self._measure()
                    self._measured_at = now
            if self._used + size > self.max_bytes:
                return False
            self._used += size
            return True

    def release(self, size: int) -> None:
        with self._lock:
            self._used = max(0, self._used - size)


def _today_segment() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _decode_header_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    try:
        return _clean_text(str(make_header(decode_header(value))))
    except Exception:
        return _clean_text(value)


def _header(msg: Any, name: str) -> Optional[str]:
    """A header as text; a header the email package cannot parse falls back to its raw value."""
    try:
        return _decode_header_value(msg.get(name))
    except Exception:
        pass
    try:
        for key, value in msg.raw_items():
            if key.lower() == name.lower():
                return _clean_text(str(value))
    except Exception:
        pass
    return None


_RAW_PARAM_RE = re.compile(r"""(?:^|;)\s*(file)?name(\*)?(?:\*0\*?)?\s*=\s*("([^"]*)"|[^;\s]+)""", re.I)


def _raw_header(part: Any, name: str) -> Optional[str]:
    try:
        for key, value in part.raw_items():
            if key.lower() == name:
                return str(value)
    except Exception:
        pass
    return None


def _raw_filename(part: Any) -> Optional[str]:
    """The filename read from the raw headers, for parameters the email package rejects."""
    for header in ("content-disposition", "content-type"):
        value = _raw_header(part, header)
        if not value:
            continue
        match = _RAW_PARAM_RE.search(value)
        if not match:
            continue
        text = match.group(4) if match.group(4) is not None else match.group(3)
        if match.group(2):
            # RFC 2231: charset'language'percent-encoded
            encoded = text.split("'", 2)[-1]
            text = unquote_to_bytes(encoded).decode("utf-8", errors="replace")
        return text
    return None


def _attachment_filename(part: Any) -> Optional[str]:
    try:
        filename = part.get_filename()
    except Exception:
        filename = _raw_filename(part)
    if not filename:
        return None
    return _decode_header_value(str(filename))


def _content_disposition(part: Any) -> Optional[str]:
    try:
        return part.get_content_disposition()
    except Exception:
        value = _raw_header(part, "content-disposition")
        if value:
            return value.split(";", 1)[0].strip().lower()
        return None


def _payload_bytes(part) -> bytes:
    payload = part.get_payload(decode=True)
    if payload is not None:
        return payload
    raw_payload = part.get_payload()
    if isinstance(raw_payload, str):
        charset = part.get_content_charset() or "utf-8"
        try:
            return raw_payload.encode(charset, errors="replace")
        except LookupError:
            return raw_payload.encode("utf-8", errors="replace")
    if raw_payload is None:
        return b""
    return bytes(raw_payload)


def _unique_path(directory: Path, filename: str) -> Path:
    candidate = directory / filename
    if not candidate.exists():
        return candidate

    stem = candidate.stem
    suffix = candidate.suffix
    counter = 2
    while True:
        candidate = directory / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def _write_restricted(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o640)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def store_mail_message(
    mail_dir: str,
    src_ip: str,
    session_id: str,
    message_id: str,
    raw_message: bytes,
    extract_attachments: Optional[bool] = None,
    save_mail_body: bool = True,
    save_attachments: Optional[bool] = None,
    max_attachments: int = 0,
    quota: Optional[MailDirQuota] = None,
) -> Dict[str, Any]:
    """
    Parse a full RFC 5322 message and optionally persist it as ``.eml`` and
    extract attachments.

    Returns metadata ready to be mapped into flat ``mail.*`` and
    ``attachment.*`` JSON fields by the caller. Problems that cost data
    (quota, attachment limit, parts that cannot be read) are listed in
    ``errors``; the headers are kept in any case.
    """
    if save_attachments is None:
        save_attachments = extract_attachments if extract_attachments is not None else True

    root = Path(mail_dir)
    rel_dir = Path(_today_segment()) / _safe_ip_segment(src_ip) / session_id
    abs_dir = root / rel_dir

    attachments: List[Dict[str, Any]] = []
    errors: List[str] = []
    metadata: Dict[str, Any] = {
        "header_from": None,
        "header_to": None,
        "subject": None,
        "attachments": attachments,
        "errors": errors,
    }

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_message)
    except Exception as exc:
        msg = None
        errors.append(f"mail could not be parsed: {exc}")
    if msg is not None:
        metadata["header_from"] = _header(msg, "From")
        metadata["header_to"] = _header(msg, "To")
        metadata["subject"] = _header(msg, "Subject")

    if save_mail_body:
        if quota is not None and not quota.reserve(len(raw_message)):
            errors.append(
                f"mail body not saved: mail folder limit of {quota.max_bytes} bytes reached"
            )
        else:
            eml_name = _safe_filename(f"{message_id}.eml", "message.eml")
            rel_eml = rel_dir / eml_name
            try:
                abs_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
                _write_restricted(root / rel_eml, raw_message)
            except OSError as exc:
                if quota is not None:
                    quota.release(len(raw_message))
                errors.append(f"mail body not saved: {exc}")
                logger.error("Failed to write mail body: %s", exc)
            else:
                metadata["eml_file"] = str(rel_eml)
                metadata["eml_size"] = len(raw_message)
                logger.info("Stored mail body (%s bytes) at %s", len(raw_message), rel_eml)

    if save_attachments and msg is not None:
        _store_attachments(
            msg,
            root=root,
            rel_dir=rel_dir,
            message_id=message_id,
            attachments=attachments,
            errors=errors,
            max_attachments=max_attachments,
            quota=quota,
        )

    return metadata


def _store_attachments(
    msg: Any,
    *,
    root: Path,
    rel_dir: Path,
    message_id: str,
    attachments: List[Dict[str, Any]],
    errors: List[str],
    max_attachments: int,
    quota: Optional[MailDirQuota],
) -> None:
    rel_attachment_dir = rel_dir / "attachments"
    attachment_dir = root / rel_attachment_dir
    over_limit = 0
    over_quota = 0

    try:
        parts = list(msg.walk())
    except Exception as exc:
        errors.append(f"attachments could not be read: {exc}")
        return

    for index, part in enumerate(parts, start=1):
        try:
            if part.is_multipart():
                continue
            filename = _attachment_filename(part)
            disposition = _content_disposition(part)
            if disposition != "attachment" and not filename:
                continue

            if max_attachments > 0 and len(attachments) >= max_attachments:
                over_limit += 1
                continue

            data = _payload_bytes(part)
            if quota is not None and not quota.reserve(len(data)):
                over_quota += 1
                continue

            safe_name = _safe_filename(
                filename or f"attachment-{index}.bin",
                f"attachment-{index}.bin",
            )
            safe_name = f"{message_id}-{index}-{safe_name}"
            try:
                attachment_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
                abs_attachment = _unique_path(attachment_dir, safe_name)
                _write_restricted(abs_attachment, data)
            except OSError:
                if quota is not None:
                    quota.release(len(data))
                raise

            try:
                content_type = part.get_content_type()
            except Exception:
                content_type = "application/octet-stream"
            attachments.append(
                {
                    "filename": filename or abs_attachment.name,
                    "path": str(rel_attachment_dir / abs_attachment.name),
                    "content_type": content_type,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        except Exception as exc:
            errors.append(f"attachment {index} not saved: {exc}")
            logger.error("Failed to store attachment %s: %s", index, exc)

    if over_limit:
        errors.append(
            f"{over_limit} attachments not saved (limit {max_attachments} per mail)"
        )
    if over_quota:
        errors.append(
            f"{over_quota} attachments not saved: mail folder limit of "
            f"{quota.max_bytes if quota else 0} bytes reached"
        )
