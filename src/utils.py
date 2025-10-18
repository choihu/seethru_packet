import re, os, time
import binascii
import pickle
import json
import threading
import queue
from pathlib import Path
from base64 import b64encode, b64decode
from typing import Any, Callable, List, Optional, Tuple

FLAG_DIR = Path("/flags")
ENCRYPTED = True

def decrypt(raw: any) -> any:
    if not ENCRYPTED:
        return raw
    plain = raw
    return plain


def encrypt(raw: any) -> any:
    if not ENCRYPTED:
        return raw
    cypher = raw
    return cypher

class AsyncFileLogger:
    """Write log payloads asynchronously using a background worker thread."""

    def __init__(
        self,
        mirror_stdout: bool = False,
        name: str = "async-log-writer",
        max_queue_size: int = 2048,
    ) -> None:
        self._queue: "queue.Queue[tuple[Any, str]]" = queue.Queue(maxsize=max_queue_size)
        self._mirror_stdout = mirror_stdout
        self._max_queue_size = max_queue_size
        self._dropped = 0
        self._last_drop_warning = 0.0
        self._drop_notice_interval = 5.0
        self._worker = threading.Thread(target=self._consume_queue, name=name, daemon=True)
        self._worker.start()

    def enable_stdout_mirror(self) -> None:
        self._mirror_stdout = True

    def log(self, path: Any, payload: str) -> None:
        if not payload:
            return

        log_path = Path(path)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            print(f"Failed to create log directory {log_path.parent}: {exc}")
            return
        try:
            self._queue.put_nowait((log_path, payload))
        except queue.Full:
            self._dropped += 1
            now = time.time()
            if now - self._last_drop_warning >= self._drop_notice_interval:
                print(
                    f"AsyncFileLogger queue full (maxsize={self._max_queue_size}); "
                    f"dropped {self._dropped} log entries so far."
                )
                self._last_drop_warning = now

    def _consume_queue(self) -> None:
        while True:
            path, payload = self._queue.get()
            if path is None:
                break
            try:
                with open(path, "a", encoding="utf-8") as log_file:
                    log_file.write(payload)
                if self._mirror_stdout:
                    print(payload, end="", flush=True)
            except Exception as exc:
                print(f"Failed to log message to {path}: {exc}")


def stop_async_logger(logger: AsyncFileLogger) -> None:
    """Signal the async logger to stop. Mostly useful for tests."""
    try:
        while True:
            try:
                logger._queue.put_nowait((None, ""))  # type: ignore[arg-type]
                break
            except queue.Full:
                try:
                    logger._queue.get_nowait()
                except queue.Empty:
                    pass
    except Exception:
        pass


class FlagCache:
    """Asynchronously refreshes flag files without blocking the main thread."""

    def __init__(
        self,
        max_age: float = 5.0,
        num_latest_rounds: int = 2,
        loader: Optional[Callable[[int], Tuple[float, List[Any]]]] = None,
        name: str = "flag-cache-reloader",
    ) -> None:
        self._max_age = max_age
        self._num_latest_rounds = num_latest_rounds
        self._loader = loader or get_latest_flags  # type: ignore[assignment]
        self._flags: List[Any] = []
        self._last_load = 0.0
        self._loading = False
        self._state_lock = threading.Lock()
        self._data_lock = threading.Lock()
        self._thread_name = name

    def refresh_if_needed(self) -> None:
        now = time.time()
        with self._state_lock:
            if now - self._last_load < self._max_age:
                return
            if self._loading:
                return
            self._loading = True
        threading.Thread(target=self._reload, name=self._thread_name, daemon=True).start()

    def get_flags(self) -> List[Any]:
        self.refresh_if_needed()
        with self._data_lock:
            return list(self._flags)

    def _reload(self) -> None:
        try:
            loaded_at, flags = self._loader(self._num_latest_rounds)
            with self._data_lock:
                self._flags = flags or []
                self._last_load = loaded_at or time.time()
        except Exception as exc:
            print(f"Failed to refresh flags: {exc}")
            with self._data_lock:
                self._last_load = time.time()
        finally:
            with self._state_lock:
                self._loading = False


'''
read bytes data and parse it with 4 bytes. Each 4 bytes presents ipv4 format data.
'''
def decrypt_bytes_to_ip(raw: any) -> any:
    seen = list()
    for i in range(0, len(raw), 4):
        ip = bytes_to_decimals(raw[i:i+4])
        if not ip in seen:
            seen.append(ip)
    return ','.join(seen)


def bytes_to_decimals(data: bytes):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    return '.'.join([str(b) for b in data])
    # return ':'.join([f"0x{byte:02x}" for byte in data])


def deserialized(raw: str) -> Any:
    """Simplified decoder: hex -> bytes -> pickle | JSON | text.

    - Strips all non-hex chars from input
    - Unhexlifies to bytes
    - Tries pickle first (imports mooncomms so class refs resolve)
    - Falls back to JSON, then UTF-8 text
    """
    if not isinstance(raw, str):
        raise TypeError("raw must be a str")

    # Keep only hex chars; drop last nibble if odd length
    hexstr = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(hexstr) % 2:
        hexstr = hexstr[:-1]

    data = binascii.unhexlify(hexstr)

    # Make MoonLink classes available for pickle
    try:
        try:
            import mooncomms  # noqa: F401
        except Exception:
            from moonlink import mooncomms as _mooncomms  # noqa: F401
    except Exception:
        pass

    # 1) pickle
    try:
        return pickle.loads(data)
    except Exception:
        pass

    # 2) JSON
    text = data.decode("utf-8", errors="ignore")
    try:
        return json.loads(text)
    except Exception:
        pass

    # 3) plain text
    return text


def serialized(raw: str) -> Any:
    return binascii.hexlify(pickle.dumps(raw, fix_imports=False)).decode()


def search_in_str(string: any, search_list: list) -> bool:
    """
    string: origin str message, search_list: list of strings to find 
    If founded, return True. Else return False
    """
    string = bytes_to_str(string)
    if not string or not search_list:
        return False
    if any(s in string for s in search_list):
        return True
    return False


def bytes_to_str(data) -> str:
    # Accept bytes or str; return str safely
    if isinstance(data, str):
        return data
    try:
        return data.decode('utf-8', errors='ignore')
    except Exception:
        return ""


def str_to_bytes(string: str) -> bytes:
    if isinstance(string, bytes):
        return string
    return (string or "").encode('utf-8')


def get_latest_flags(num_latest_rounds: int) -> Tuple[float, List[str]]:
    now = time.time()
    if not FLAG_DIR.is_dir():
        return now, []

    latest_flags: List[str] = []
    try:
        latest_flag_files = sorted(os.listdir(FLAG_DIR))[-num_latest_rounds:]
    except FileNotFoundError:
        return now, []

    for flag_file in latest_flag_files:
        try:
            with open(FLAG_DIR / flag_file, "r", encoding="utf-8", errors="ignore") as f:
                for raw_line in f:
                    line = raw_line.rstrip("\n")
                    if not line:
                        continue
                    latest_flags.append(line)
                    try:
                        encoded = b64encode(line.encode("utf-8")).decode("ascii")
                        latest_flags.append(encoded)
                        latest_flags.append(b64encode(encoded.encode("ascii")).decode("ascii"))
                        latest_flags.append(b64encode(b64encode(encoded.encode("ascii")).decode("ascii")))
                    except Exception:
                        continue
        except Exception:
            continue
    return now, latest_flags
