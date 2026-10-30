"""
Sliding-window rate limiting for Mailoney.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import RateLimitConfig

logger = logging.getLogger(__name__)

MAX_KEY_LENGTH = 320
PRUNE_INTERVAL_SECONDS = 60.0
SAVE_INTERVAL_SECONDS = 10.0


def source_key(src_ip: str) -> str:
    """IPv4 (also IPv4-mapped IPv6) as is, IPv6 as its /64 network."""
    try:
        address = ipaddress.ip_address(src_ip.split("%", 1)[0])
    except ValueError:
        return src_ip
    if address.version == 6:
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


@dataclass
class RateLimitDecision:
    allowed: bool
    scope: Optional[str] = None
    key: Optional[str] = None
    limit: Optional[int] = None
    window_seconds: Optional[int] = None
    block_seconds: Optional[int] = None
    blocked_from: Optional[float] = None
    blocked_until: Optional[float] = None
    should_log: bool = False


class RateLimiter:
    """
    Sliding window per source (IPv6 per /64) and per envelope sender. Keys
    without events in the window are dropped, at most config.max_keys keys
    are kept per scope (the oldest go first), and the state is written at
    most every SAVE_INTERVAL_SECONDS, at once when a block starts.
    """

    def __init__(
        self,
        config: RateLimitConfig,
        clock: Callable[[], float] = time.time,
    ):
        self.config = config
        self._clock = clock
        self._lock = threading.Lock()
        self._events: Dict[str, Dict[str, List[float]]] = {"ip": {}, "sender": {}}
        self._blocks: Dict[str, Dict[str, Dict[str, float]]] = {
            "ip": {},
            "sender": {},
        }
        self._pruned_at = 0.0
        self._saved_at = 0.0
        self._dirty = False
        self._load_state()
        with self._lock:
            self._prune(self._clock())

    def check(self, scope: str, key: Optional[str]) -> RateLimitDecision:
        if not self.config.enabled or not key:
            return RateLimitDecision(allowed=True)

        normalized_key = self._normalize_key(scope, key)
        limit = self._limit_for_scope(scope)
        if limit <= 0:
            return RateLimitDecision(allowed=True)

        now = self._clock()
        with self._lock:
            self._maybe_prune(now)
            block = self._blocks[scope].get(normalized_key)
            if block and block["until"] > now:
                return RateLimitDecision(
                    allowed=False,
                    scope=scope,
                    key=normalized_key,
                    limit=limit,
                    window_seconds=self.config.window_seconds,
                    block_seconds=self.config.block_seconds,
                    blocked_from=block["from"],
                    blocked_until=block["until"],
                    should_log=not self.config.log_block_once,
                )

            if block:
                self._blocks[scope].pop(normalized_key, None)
                self._dirty = True

            events = self._active_events(scope, normalized_key, now)
            if len(events) >= limit:
                blocked_until = now + self.config.block_seconds
                self._blocks[scope][normalized_key] = {
                    "from": now,
                    "until": blocked_until,
                }
                self._cap(self._blocks[scope])
                self._dirty = True
                self._save_state(force=True)
                return RateLimitDecision(
                    allowed=False,
                    scope=scope,
                    key=normalized_key,
                    limit=limit,
                    window_seconds=self.config.window_seconds,
                    block_seconds=self.config.block_seconds,
                    blocked_from=now,
                    blocked_until=blocked_until,
                    should_log=True,
                )

            self._store_events(scope, normalized_key, events)
            return RateLimitDecision(allowed=True)

    def record_message(self, src_ip: str, sender: Optional[str]) -> None:
        if not self.config.enabled:
            return

        now = self._clock()
        with self._lock:
            self._maybe_prune(now)
            self._record("ip", src_ip, now)
            if sender:
                self._record("sender", sender, now)
            self._dirty = True
            self._save_state()

    def flush(self) -> None:
        """Write pending changes, e.g. when the server stops."""
        with self._lock:
            self._save_state(force=True)

    def key_count(self, scope: str) -> int:
        with self._lock:
            return len(self._events[scope])

    def _record(self, scope: str, key: str, now: float) -> None:
        normalized_key = self._normalize_key(scope, key)
        events = self._active_events(scope, normalized_key, now)
        events.append(now)
        # Newest key last, so the cap drops the keys that were quiet longest
        self._events[scope].pop(normalized_key, None)
        self._store_events(scope, normalized_key, events)

    def _store_events(self, scope: str, key: str, events: List[float]) -> None:
        scope_events = self._events[scope]
        if not events:
            if scope_events.pop(key, None) is not None:
                self._dirty = True
            return
        if scope_events.get(key) != events:
            self._dirty = True
        scope_events[key] = events
        self._cap(scope_events)

    def _cap(self, entries: Dict[str, Any]) -> None:
        limit = self.config.max_keys
        if limit <= 0:
            return
        while len(entries) > limit:
            entries.pop(next(iter(entries)))
            self._dirty = True

    def _active_events(self, scope: str, key: str, now: float) -> List[float]:
        cutoff = now - self.config.window_seconds
        limit = max(self._limit_for_scope(scope), 0)
        events = [ts for ts in self._events[scope].get(key, []) if ts >= cutoff]
        # More than limit events in the window change no decision
        return events[-limit:] if limit else events

    def _maybe_prune(self, now: float) -> None:
        if now - self._pruned_at >= PRUNE_INTERVAL_SECONDS:
            self._prune(now)

    def _prune(self, now: float) -> None:
        self._pruned_at = now
        cutoff = now - self.config.window_seconds
        for scope in ("ip", "sender"):
            events = self._events[scope]
            for key in list(events):
                active = [ts for ts in events[key] if ts >= cutoff]
                if active:
                    events[key] = active
                else:
                    del events[key]
                    self._dirty = True
            blocks = self._blocks[scope]
            for key in [k for k, v in blocks.items() if v["until"] <= now]:
                del blocks[key]
                self._dirty = True
            self._cap(events)
            self._cap(blocks)

    def _limit_for_scope(self, scope: str) -> int:
        if scope == "ip":
            return self.config.max_messages_per_ip
        if scope == "sender":
            return self.config.max_messages_per_sender
        raise ValueError(f"Unknown rate limit scope: {scope}")

    def _normalize_key(self, scope: str, key: str) -> str:
        if scope == "sender":
            return key.strip().lower()[:MAX_KEY_LENGTH]
        return source_key(key.strip())[:MAX_KEY_LENGTH]

    def _load_state(self) -> None:
        if not self.config.state_file:
            return

        path = Path(self.config.state_file)
        if not path.exists():
            return

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            events = data.get("events", {})
            blocks = data.get("blocks", {})
            if isinstance(events, dict):
                for scope in ("ip", "sender"):
                    scope_events = events.get(scope, {})
                    if isinstance(scope_events, dict):
                        self._events[scope] = {
                            str(key)[:MAX_KEY_LENGTH]: [float(ts) for ts in value]
                            for key, value in scope_events.items()
                            if isinstance(value, list) and value
                        }
            if isinstance(blocks, dict):
                for scope in ("ip", "sender"):
                    scope_blocks = blocks.get(scope, {})
                    if isinstance(scope_blocks, dict):
                        self._blocks[scope] = {
                            str(key)[:MAX_KEY_LENGTH]: {
                                "from": float(value["from"]),
                                "until": float(value["until"]),
                            }
                            for key, value in scope_blocks.items()
                            if isinstance(value, dict)
                            and "from" in value
                            and "until" in value
                        }
        except Exception as exc:
            logger.warning("Could not load rate limit state: %s", exc)

    def _save_state(self, force: bool = False) -> None:
        if not self.config.state_file or not self._dirty:
            return
        now = time.monotonic()
        if not force and now - self._saved_at < SAVE_INTERVAL_SECONDS:
            return

        path = Path(self.config.state_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            data = {"events": self._events, "blocks": self._blocks}
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=True, sort_keys=True)
                    f.write("\n")
                os.chmod(tmp_name, 0o640)
                os.replace(tmp_name, path)
            finally:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
        except OSError as exc:
            logger.warning("Could not save rate limit state: %s", exc)
            return
        self._saved_at = now
        self._dirty = False
