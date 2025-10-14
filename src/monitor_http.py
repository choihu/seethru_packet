from mitmproxy import http
import urllib.parse
import datetime
import os, time
from pathlib import Path
from utils import search_in_str, bytes_to_str, str_to_bytes, decrypt, encrypt

#BLOCKED_STRINGS = ["app.js", "--", "..", "file:"]
BLOCKED_STRINGS = []

ENABLE_MODIFY = False
MODIFIED = "SUCCESS"

LOG_FILE_PATH = os.path.join("/scripts/logs", os.getenv("LOG_FILE", "log_http"))
LEAK_LOG_FILE_PATH = os.path.join("/scripts/logs", os.getenv("LEAK_LOG_FILE", "leak_http"))

BASE_DIR = Path(__file__).parent.resolve()
FLAG_DIR = BASE_DIR / "flags"

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

def log_http_flow(flow: http.HTTPFlow, log_file_path: str) -> None:
    '''
    Log Http Flow
    '''
    try:
        with open(log_file_path, "a") as log_file:
            log_file.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n")
            log_file.write(f"-------------- REQUSET --------------\n")
            log_file.write(f"URL: {flow.request.pretty_url}\n")
            log_file.write(f"Method: {flow.request.method}\n")
            log_file.write(f"Headers: {dict(flow.request.headers)}\n")
            log_file.write(f"Query Params: {dict(flow.request.query)}\n")
            if flow.request.method in ["POST", "PUT", "PATCH"] and flow.request.content:
                log_file.write(f"Body: {decrypt(flow.request.text)}\n\n")
            
            log_file.write("=" * 50 +"\n\n\n")
    except Exception as e:
        print(f"Failed to log request: {e}")

def search_in_parameters(query: dict, param_values_dict: dict) -> bool:
    for param, values in param_values_dict.items():
        if param in query.keys():
            query_value = query[param]
            if values in url_decode(url_decode(query_value.lower())):
                return True
    return False

def url_decode(data: str) -> str:
    return urllib.parse.unquote(data)

def search_in_request_flow(flow: http.HTTPFlow, search_strings) -> bool:
    '''
    filtered = {
        "id": ["(", ")", "--", "'", '"'],
        "username": ["(", ")", "--", "'", '"'],
        "password": ["(", ")", "--", "'", '"'],
        "page" : ["--"]
    }

    filtered = {}
    if search_in_parameters(dict(flow.request.query), filtered):
        return True
    '''

    # Decode URL twice and search string in URL
    decoded_url = url_decode(url_decode(flow.request.pretty_url.lower()))
    if search_in_str(decoded_url, search_strings):
        return True

    # Search string in request text
    if flow.request.method in ["POST", "PUT", "PATCH"] and flow.request.content:
        decoded_content = url_decode(url_decode(flow.request.content.lower()))
        
        if search_in_str(decoded_content, search_strings):
            return True

    return False

def search_in_response_flow(flow: http.HTTPFlow, search_strings) -> bool:
    for _, values in dict(flow.response.headers).items():
        if search_in_str(values, search_strings):
            return True

    if search_in_str(decrypt(flow.response.text), search_strings):
        return True
    
    return False

def response(flow: http.HTTPFlow) -> None:
    flow.request.scheme = "http"
    # Log Every HTTP Packet
    log_http_flow(flow, f"{LOG_FILE_PATH}_{time.strftime('%H%M')}.txt")
    refresh_flags(5, 2)

    LEAKED = False
    # Log HTTP Packet when FLAG Leaked in Response
    if search_in_response_flow(flow, FLAG):
        log_http_flow(flow, f"{LEAK_LOG_FILE_PATH}_{time.strftime('%H%M')}.txt")
        LEAKED = True

    if ENABLE_MODIFY:
        if search_in_request_flow(flow, BLOCKED_STRINGS):
            if LEAKED:
                modified_header = flow.response.headers
                for keys, _ in dict(modified_header).items():
                    for f in FLAG:
                        modified_header[keys] = modified_header[keys].replace(f, MODIFIED)
                flow.response.headers = modified_header

                if flow.response.content:
                    modified_body = decrypt(flow.response.content)
                    for f in FLAG:
                        flow.response.content = encrypt(modified_body.replace(str_to_bytes(f), str_to_bytes(MODIFIED)))
    else:
        if search_in_request_flow(flow, BLOCKED_STRINGS):
            flow.response = http.Response.make(
                403,
                b"no hack",
                {"Content-Type": "text/plain"}
            )

def log_websocket_flow(flow: http.HTTPFlow) -> None:
    try:
        with open(f"{LOG_FILE_PATH}_{time.strftime('%H%M')}.txt", "a") as log_file:
            message = flow.websocket.messages[-1]
            direction = "Client -> Server" if message.from_client else "Server -> Client"

            log_file.write(f"WebSocket Message ({direction}):\n")
            decoded_content = decrypt(bytes_to_str(message.content))
            log_file.write(f"  Decoded Text: {decoded_content}\n")
            log_file.write("-" * 20 + "\n")

    except Exception as e:
        print(f"!!! Exception in websocket_message: {e} !!!")

def log_leak_websocket_flow(flow: http.HTTPFlow):
    try:
        with open(f"{LEAK_LOG_FILE_PATH}_{time.strftime('%H%M')}.txt", "a") as log_file:
            for message in flow.messages:
                direction = "CLIENT -> SERVER" if message.from_client else "SERVER -> CLIENT"

                log_file.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n")
                log_file.write(f"--- TCP Message ---\n")
                log_file.write(f"Flow: {flow.client_conn.peername[0]}:{flow.client_conn.peername[1]} <-> {flow.server_conn.address[0]}:{flow.server_conn.address[1]}\n")
                log_file.write(f"Direction: {direction}\n")
                log_file.write(f"Data (raw):\n{decrypt(message.content)}\n")
                log_file.write(f"Data (hex):\n{message.content.hex()}\n")

            log_file.write(f"=================================\n")
            log_file.write(f"=================================\n\n")
    except Exception as e:
        print(f"Failed to log TCP message: {e}")

def websocket_start(flow: http.HTTPFlow) -> None:
    """
    Called when a client and server have completed the WebSocket handshake.
    """
    try:
        with open(f"{LOG_FILE_PATH}_{time.strftime('%H%M')}.txt", "a") as log_file:
            log_file.write(f"WebSocket Connection Started: {flow.request.pretty_url}\n")
            log_file.write("-" * 20 + "\n")
    except Exception as e:
        print(f"Failed to log WebSocket start: {e}")

def websocket_message(flow: http.HTTPFlow) -> None:
    """
    Called when a WebSocket message is sent or received.
    """
    log_websocket_flow(flow)
    
    if len(flow.websocket.messages) == 0:
        return
    LEAKED = False
    message = decrypt(bytes_to_str(flow.websocket.messages[-1].content))

    refresh_flags(5, 2)
    if search_in_str(message, FLAG):
        LEAKED = True
        log_leak_websocket_flow(flow)

    if ENABLE_MODIFY:
        if LEAKED:
            for m in flow.websocket.messages:
                if m.from_client and search_in_str(decrypt(bytes_to_str(m.content)), BLOCKED_STRINGS):
                    for f in FLAG:
                        flow.websocket.messages[-1].content = str_to_bytes(encrypt(message.replace(f, MODIFIED)))
    else:
        if search_in_str(message, BLOCKED_STRINGS):
            flow.websocket.messages[-1].content = b"no hack"

def websocket_end(flow: http.HTTPFlow) -> None:
    """
    Called when a WebSocket connection is closed.
    """
    try:
        with open(f"{LOG_FILE_PATH}_{time.strftime('%H%M')}.txt", "a") as log_file:
            log_file.write(f"WebSocket Connection Ended: {flow.request.pretty_url}\n")
            log_file.write("=" * 20 + "\n")
    except Exception as e:
        print(f"Failed to log WebSocket end: {e}")
