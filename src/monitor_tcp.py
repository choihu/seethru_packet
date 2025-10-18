from mitmproxy import tcp
import datetime
import os
import time
from utils import AsyncFileLogger, FlagCache, search_in_str, str_to_bytes, decrypt, encrypt

#BLOCKED_STRINGS = ["--", "/*", "*/", ";", "\\", "\\x00", '"', "'"]
BLOCKED_STRINGS = []

ENABLE_MODIFY = False
MODIFIED = "SUCCESS"

LOG_FILE_PATH = os.path.join("/scripts/logs", os.getenv("LOG_FILE", "log_tcp"))
LEAK_LOG_FILE_PATH = os.path.join("/scripts/logs", os.getenv("LEAK_LOG_FILE", "leak_tcp"))

LOGGER = AsyncFileLogger(mirror_stdout=True, name="tcp-log-writer")
FLAG_CACHE = FlagCache()
_BLOCK_METADATA_KEY = "tcp_flow_blocked"

def log_tcp_flow(flow: tcp.TCPFlow):
    '''
    Log TCP Flow
    '''
    if not flow.messages:
        return

    message = flow.messages[-1]
    direction = "CLIENT -> SERVER" if message.from_client else "SERVER -> CLIENT"

    try:
        c_host, c_port = flow.client_conn.peername
    except Exception:
        c_host, c_port = ("?", "?")
    try:
        s_host, s_port = flow.server_conn.address
    except Exception:
        s_host, s_port = ("?", "?")

    payload = (
        "-" * 20 + "\n"
        + f"Timestamp: {datetime.datetime.now().isoformat()}\n"
        + f"Flow: {c_host}:{c_port} <-> {s_host}:{s_port}\n"
        + f"Direction: {direction}\n"
        + f"Data (raw):\n{decrypt(message.content)}\n\n"
    )

    log_path = f"{LOG_FILE_PATH}_{time.strftime('%H%M')}.txt"
    LOGGER.log(log_path, payload)

def log_leak_tcp_flow(flow: tcp.TCPFlow):
    if not flow.messages:
        return

    try:
        c_host, c_port = flow.client_conn.peername
    except Exception:
        c_host, c_port = ("?", "?")
    try:
        s_host, s_port = flow.server_conn.address
    except Exception:
        s_host, s_port = ("?", "?")

    log_entries = []
    for message in flow.messages:
        direction = "CLIENT -> SERVER" if message.from_client else "SERVER -> CLIENT"
        log_entries.append("-" * 20 + "\n")
        log_entries.append(f"Timestamp: {datetime.datetime.now().isoformat()}\n")
        log_entries.append(f"Flow: {c_host}:{c_port} <-> {s_host}:{s_port}\n")
        log_entries.append(f"Direction: {direction}\n")
        log_entries.append(f"Data (hex):\n{message.content.hex()}\n")
        log_entries.append(f"Data (raw):\n{decrypt(message.content)}\n\n")

    log_entries.append("=================================\n")
    log_entries.append("=================================\n\n")

    log_path = f"{LEAK_LOG_FILE_PATH}_{time.strftime('%H%M')}.txt"
    LOGGER.log(log_path, "".join(log_entries))


def tcp_message(flow: tcp.TCPFlow):
    log_tcp_flow(flow)

    # Always safe-guard early messages: the first callback has only one message
    if len(flow.messages) == 0:
        return

    message_obj = flow.messages[-1]

    if flow.metadata.get(_BLOCK_METADATA_KEY) and not message_obj.from_client:
        message_obj.content = b""
        flow.kill()
        return

    message = decrypt(message_obj.content)
    flags = FLAG_CACHE.get_flags()
    LEAKED = False

    if search_in_str(message, flags):
        log_leak_tcp_flow(flow)
        LEAKED = True

    if ENABLE_MODIFY:
        if LEAKED:
            for msg in flow.messages:
                if not msg.from_client:
                    continue

                try:
                    plain_prev_msg = decrypt(msg.content)
                except:
                    continue

                if search_in_str(plain_prev_msg, BLOCKED_STRINGS):
                    for f in flags:
                        message = message.replace(f, MODIFIED)
                    message_obj = str_to_bytes(encrypt(message))
                    break
    else:
        if message_obj.from_client and search_in_str(message, BLOCKED_STRINGS):
            flow.metadata[_BLOCK_METADATA_KEY] = True
            message_obj.content = str_to_bytes(encrypt("no hack"))
            flow.kill()
