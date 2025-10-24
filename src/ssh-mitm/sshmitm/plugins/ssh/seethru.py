import datetime
import os
import threading
import time
from typing import Dict, List, Optional

from sshmitm.forwarders.ssh import SSHForwarder

ENABLE_MODIFY = False
BLOCKED_STRINGS = []
MODIFY = "Success"

FLUSH_INTERVAL = 1
MAX_BUFFER = 1024

def _bytes_to_str(data: bytes) -> str:
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _str_to_bytes(text: str) -> bytes:
    return (text or "").encode("utf-8")


def _search_in_str(data: str, needles: List[str]) -> bool:
    if not data or not needles:
        return False
    return any(needle in data for needle in needles)


class _AsyncFileLogger:
    """Asynchronously persist payloads to rotating text files."""

    def __init__(self, mirror_stdout: bool = False) -> None:
        self._queue: List[tuple[str, str]] = []
        self._cond = threading.Condition()
        self._alive = True
        self._mirror = mirror_stdout
        self._worker = threading.Thread(target=self._run, name="ssh-seethru-writer", daemon=True)
        self._worker.start()

    def log(self, path: str, payload: str) -> None:
        if not payload:
            return
        with self._cond:
            self._queue.append((path, payload))
            self._cond.notify()

    def stop(self) -> None:
        with self._cond:
            self._alive = False
            self._cond.notify()
        self._worker.join(timeout=1.0)

    def _run(self) -> None:
        while True:
            with self._cond:
                while self._alive and not self._queue:
                    self._cond.wait(timeout=0.5)
                if not self._alive and not self._queue:
                    return
                path, payload = self._queue.pop(0)

            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "a", encoding="utf-8") as handle:
                    handle.write(payload)
                if self._mirror:
                    print(payload, end="")
            except Exception as exc:  # noqa: PIE786
                print(f"[sshmitm.seethru] log write failed for {path}: {exc}")


class _FlagCache:
    """Cache for flags read from a directory with optional base64 variants."""

    def __init__(self, flags_dir: Optional[str], max_age_sec: float = 5.0) -> None:
        self._flags_dir = flags_dir
        self._max_age = max_age_sec
        self._flags: List[str] = []
        self._last_load = 0.0
        self._lock = threading.Lock()

    def get_flags(self) -> List[str]:
        now = time.time()
        with self._lock:
            if now - self._last_load < self._max_age:
                return list(self._flags)
            self._last_load = now
        return self._reload()

    def _reload(self) -> List[str]:
        flags: List[str] = []
        if not self._flags_dir or not os.path.isdir(self._flags_dir):
            with self._lock:
                self._flags = []
            return []
        try:
            candidates = sorted(os.listdir(self._flags_dir))[-2:]
        except Exception:
            candidates = []
        for filename in candidates:
            path = os.path.join(self._flags_dir, filename)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    for line in handle:
                        line = line.rstrip("\n")
                        if not line:
                            continue
                        flags.append(line)
                        try:
                            import base64

                            enc1 = base64.b64encode(line.encode("utf-8")).decode("ascii")
                            flags.append(enc1)
                            enc2 = base64.b64encode(enc1.encode("ascii")).decode("ascii")
                            flags.append(enc2)
                        except Exception:
                            pass
            except Exception:
                continue
        with self._lock:
            self._flags = flags
            return list(self._flags)


class SSHSeethruForwarder(SSHForwarder):
    """
    SSH forwarder that stores cleartext traffic in rotating text files.

    Environment variables:
        LOG_DIR_BASE   - main output directory (default: /scripts/logs)
        LOG_FILE       - base filename for regular traffic logs (default: log_ssh)
        LEAK_LOG_FILE  - base filename for leak alerts (default: leak_ssh)
        ENABLE_MODIFY  - when "true"/"1" replaces flagged secrets instead of dropping the session
        MODIFIED       - replacement string when modification is enabled (default: SUCCESS)
        BLOCKED_STRINGS- comma separated list of sensitive tokens to watch for
        FLAGS_DIR      - directory with recent flag strings (default: /flags)
    """

    def __init__(self, session: "sshmitm.session.Session") -> None:  # type: ignore[name-defined]
        super().__init__(session)
        base_dir = os.environ.get("LOG_DIR_BASE", "/opt/ssh-mitm/logs")
        self.log_file = os.path.join(base_dir, os.environ.get("LOG_FILE", "log_ssh"))
        self.leak_file = os.path.join(base_dir, os.environ.get("LEAK_LOG_FILE", "leak_ssh"))

        self.enable_modify = ENABLE_MODIFY
        self.modified_value = MODIFY
        self.blocked = BLOCKED_STRINGS

        self.flags_dir = os.environ.get("FLAGS_DIR", "/flags")
        self.flag_cache = _FlagCache(self.flags_dir)
        self.logger = _AsyncFileLogger(mirror_stdout=False)
        self._last_client_msg: str = ""
        self._last_server_msg: str= ""
        now = time.time()
        self._buffers: Dict[str, str] = {"client": "", "server": ""}
        self._last_flush: Dict[str, float] = {"client": now, "server": now}
        self._buffer_lock = threading.Lock()
        self._flush_interval = FLUSH_INTERVAL
        self._max_buffer = MAX_BUFFER

        self._priv_messages = []

    def _log_path(self, base: str) -> str:
        suffix = time.strftime("%H%M")
        return f"{base}_{suffix}.txt"

    def _flow_header(self, direction: str) -> str:
        addr_cli = (
            f"{self.session.client_address[0]}:{self.session.client_address[1]}"
            if isinstance(self.session.client_address, tuple)
            else str(self.session.client_address)
        )
        addr_srv = f"{self.session.remote_address[0]}:{self.session.remote_address[1]}"
        return "\n".join(
            [
                "-" * 20,
                f"Timestamp: {datetime.datetime.now().isoformat()}",
                f"Flow: {addr_cli} <-> {addr_srv}",
                f"Direction: {direction}",
            ]
        )

    def _log_client(self, text: str) -> None:
        self._enqueue_log("client", text)

    def _log_server(self, text: str) -> None:
        self._enqueue_log("server", text)

    def _log_leak(self, messages: List[str], is_ws: bool = False) -> None:
        entries: List[str] = []
        for msg in messages:
            entries.extend(
                [
                    msg
                ]
            )
        entries.append("=" * 33 + "\n\n")
        self.logger.log(self._log_path(self.leak_file), "\n".join(entries))

    def _replace_if_needed(self, message: str) -> str:
        if not self.enable_modify:
            return message
        return _search_in_str(message, self.blocked + self.flag_cache.get_flags()) and self.modified_value or message

    def _enqueue_log(self, direction: str, text: str) -> None:
        if not text:
            return
        flow = "CLIENT -> SERVER" if direction == "client" else "SERVER -> CLIENT"
        with self._buffer_lock:
            buffer = self._buffers[direction] + text
            flushed: List[str] = []
            # while True:
            #     idx = buffer.find("\n")
            #     if idx == -1:
            #         break
            #     flushed.append(buffer[: idx + 1])
            #     buffer = buffer[idx + 1 :]

            now = time.time()
            if buffer and (
                len(buffer) >= self._max_buffer
                or now - self._last_flush[direction] >= self._flush_interval
            ):
                flushed.append(buffer)
                buffer = ""

            for chunk in flushed:
                payload = self._flow_header(flow) + f"\nData (raw):\n{chunk}\n\n"
                self.logger.log(self._log_path(self.log_file), payload)
                self._last_flush[direction] = now
                self._priv_messages.append(payload)

            self._buffers[direction] = buffer

    def stdin(self, text: bytes) -> bytes:
        message = _bytes_to_str(text)
        self._last_client_msg = message
        if message != self._last_server_msg:
            self._log_client(message)
        # sensitive_markers = self.blocked + self.flag_cache.get_flags()
        # if sensitive_markers and _search_in_str(message, sensitive_markers):
        #     if not self.enable_modify:
        #         if self.client_channel is not None:
        #             self.close_session(self.client_channel)
        #         if self.session.ssh_remote_channel is not None:
        #             self.session.ssh_remote_channel.close()
        #         self._log_leak([message])
        #         return b""
        #     self._log_leak([message])
        #     return _str_to_bytes(self._replace_if_needed(message))
        return text

    def stdout(self, text: bytes) -> bytes:
        message = _bytes_to_str(text)
        self._last_server_msg = message
        if message != self._last_client_msg:
            self._log_server(message)
        sensitive = self.flag_cache.get_flags()
        if sensitive and _search_in_str(message, sensitive):
            # self._priv_messages.append(message)
            self._log_leak(self._priv_messages)
            # if self.enable_modify:
            #     message = message.replace(self._last_client_msg, self.modified_value)
            #     return _str_to_bytes(message)
        return text

    def stderr(self, text: bytes) -> bytes:
        message = _bytes_to_str(text)
        self._log_server(message)
        return text

    def close_session(self, channel) -> None:  # type: ignore[override]
        try:
            self._flush_pending_logs()
            super().close_session(channel)
        finally:
            self.logger.stop()

    def _flush_pending_logs(self) -> None:
        with self._buffer_lock:
            for direction in ("client", "server"):
                buffer = self._buffers[direction]
                if not buffer:
                    continue
                flow = "CLIENT -> SERVER" if direction == "client" else "SERVER -> CLIENT"
                payload = self._flow_header(flow) + f"\nData (raw):\n{buffer}\n\n"
                self.logger.log(self._log_path(self.log_file), payload)
                self._buffers[direction] = ""
                self._last_flush[direction] = time.time()
