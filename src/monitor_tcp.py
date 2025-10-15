from mitmproxy import tcp
import datetime
import os
import time
from pathlib import Path
from utils import search_in_str, bytes_to_str, str_to_bytes, decrypt, encrypt

#BLOCKED_STRINGS = ["--", "/*", "*/", ";", "\\", "\\x00", '"', "'"]
BLOCKED_STRINGS = []

ENABLE_MODIFY = False
MODIFIED = "SUCCESS"

LOG_FILE_PATH = os.path.join("/scripts/logs", os.getenv("LOG_FILE", "log_tcp"))
LEAK_LOG_FILE_PATH = os.path.join("/scripts/logs", os.getenv("LEAK_LOG_FILE", "leak_tcp"))

# BASE_DIR = Path(__file__).parent.resolve()
# FLAG_DIR = BASE_DIR / "flags"

service_name = os.path.basename(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = Path(__file__).parent.parent.resolve()
FLAG_DIR = BASE_DIR / "flags" / service_name
FLAG = []
_last_load = 0

def refresh_flags(max_age: int = 5, num_latest_rounds: int = 2):
    global FLAG, _last_load
    now = time.time()
    if now - _last_load < max_age:
        return
    
    # Ensure flags directory exists and handle absence gracefully
    try:
        os.makedirs(FLAG_DIR, exist_ok=True)
    except Exception:
        pass

    latest_flags = list()
    try:
        latest_flag_files = sorted(os.listdir(FLAG_DIR))[-num_latest_rounds:]
    except FileNotFoundError:
        FLAG = []
        _last_load = now
        return
    for flag_file in latest_flag_files:
        try:
            with open(FLAG_DIR / flag_file, "r", encoding="utf-8", errors="ignore") as f:
                latest_flags.extend([line.rstrip('\n') for line in f.readlines()])
        except Exception:
            continue

    FLAG = latest_flags
    _last_load = now

def log_tcp_flow(flow: tcp.TCPFlow):
    '''
    Log TCP Flow
    '''
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

    try:
        with open(f"{LOG_FILE_PATH}_{time.strftime('%H%M')}.txt", "a") as log_file:
            log_file.write("-" * 20 + "\n")
            log_file.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n")
            log_file.write(f"Flow: {c_host}:{c_port} <-> {s_host}:{s_port}\n")
            log_file.write(f"Direction: {direction}\n")
            log_file.write(f"Data (raw):\n{decrypt(bytes_to_str(message.content))}\n\n")

    except Exception as e:
        print(f"Failed to log TCP message: {e}")

def log_leak_tcp_flow(flow: tcp.TCPFlow):
    try:
        c_host, c_port = flow.client_conn.peername
    except Exception:
        c_host, c_port = ("?", "?")
    try:
        s_host, s_port = flow.server_conn.address
    except Exception:
        s_host, s_port = ("?", "?")

    try:
        with open(f"{LEAK_LOG_FILE_PATH}_{time.strftime('%H%M')}.txt", "a") as log_file:
            for message in flow.messages:
                direction = "CLIENT -> SERVER" if message.from_client else "SERVER -> CLIENT"
                log_file.write("-" * 20 + "\n")
                log_file.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n")
                log_file.write(f"Flow: {c_host}:{c_port} <-> {s_host}:{s_port}\n")
                log_file.write(f"Direction: {direction}\n")
                log_file.write(f"Data (hex):\n{message.content.hex()}\n")
                log_file.write(f"Data (raw):\n{decrypt(bytes_to_str(message.content))}\n\n")

            log_file.write(f"=================================\n")
            log_file.write(f"=================================\n\n")
    except Exception as e:
        print(f"Failed to log TCP message: {e}")


def tcp_message(flow: tcp.TCPFlow):
    log_tcp_flow(flow)

    # Always safe-guard early messages: the first callback has only one message
    if len(flow.messages) == 0:
        return

    message = decrypt(bytes_to_str(flow.messages[-1].content))
    LEAKED = False

    refresh_flags(5, 2)
    if search_in_str(message, FLAG):
        log_leak_tcp_flow(flow)
        LEAKED = True

    if ENABLE_MODIFY:
        if LEAKED:
            for msg in flow.messages:
                if not msg.from_client:
                    continue

                try:
                    plain_prev_msg = decrypt(bytes_to_str(msg.content))
                except:
                    continue

                if search_in_str(plain_prev_msg, BLOCKED_STRINGS):
                    for f in FLAG:
                        message = message.replace(f, MODIFIED)
                    flow.messages[-1].content = str_to_bytes(encrypt(message))
                    break
    else:
        if search_in_str(message, BLOCKED_STRINGS):
            flow.messages[-1].content = b"no hack"
