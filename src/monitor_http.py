from mitmproxy import http
import urllib.parse
import datetime
import os, time
from utils import (
    AsyncFileLogger,
    FlagCache,
    search_in_str,
    str_to_bytes,
    decrypt,
    encrypt,
)

#BLOCKED_STRINGS = ["app.js", "--", "..", "file:"]
BLOCKED_STRINGS = []

ENABLE_MODIFY = False
MODIFIED = "SUCCESS"

LOG_FILE_PATH = os.path.join("/scripts/logs", os.getenv("LOG_FILE", "log_http"))
LEAK_LOG_FILE_PATH = os.path.join("/scripts/logs", os.getenv("LEAK_LOG_FILE", "leak_http"))

LOGGER = AsyncFileLogger(mirror_stdout=True, name="http-log-writer")
FLAG_CACHE = FlagCache()
_BLOCK_METADATA_KEY = "tcp_flow_blocked"

def log_http_flow(flow: http.HTTPFlow, log_file_path: str) -> None:
    '''
    Log Http Flow
    '''
    try:
        payload_parts = [
            f"Timestamp: {datetime.datetime.now().isoformat()}\n",
            "-------------- REQUSET --------------\n",
            f"URL: {flow.request.pretty_url}\n",
            f"Method: {flow.request.method}\n",
            f"Headers: {dict(flow.request.headers)}\n",
            f"Query Params:\n"
        ]
        for key, value in dict(flow.request.query).items():
            payload_parts.append(f"  {key}: {decrypt(value)}\n")
        payload_parts.append("\n")

        if flow.request.method in ["POST", "PUT", "PATCH"] and flow.request.content:
            payload_parts.append(f"Body: {decrypt(flow.request.text)}\n\n")
        payload_parts.append("=" * 50 + "\n\n\n")
        LOGGER.log(log_file_path, "".join(payload_parts))
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

    # Search string in GET paremeter
    for key, value in dict(flow.request.query).items():
        if search_in_str(key, search_strings):
            return True
        if search_in_str(decrypt(value), search_strings):
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
    flags = FLAG_CACHE.get_flags()

    LEAKED = False
    # Log HTTP Packet when FLAG Leaked in Response
    if search_in_response_flow(flow, flags):
        log_http_flow(flow, f"{LEAK_LOG_FILE_PATH}_{time.strftime('%H%M')}.txt")
        LEAKED = True

    if ENABLE_MODIFY:
        if search_in_request_flow(flow, BLOCKED_STRINGS):
            if LEAKED:
                modified_header = flow.response.headers
                for keys, _ in dict(modified_header).items():
                    for f in flags:
                        modified_header[keys] = modified_header[keys].replace(f, MODIFIED)
                flow.response.headers = modified_header

                if flow.response.content:
                    modified_body = decrypt(flow.response.content)
                    for f in flags:
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
        message = flow.websocket.messages[-1]
        direction = "Client -> Server" if message.from_client else "Server -> Client"
        payload = (
            "-" * 20 + "\n"
            + f"Timestamp: {datetime.datetime.now().isoformat()}\n"
            + f"Direction: {direction}\n"
            + f"Data (raw):\n{decrypt(message.content)}\n"
        )
        LOGGER.log(f"{LOG_FILE_PATH}_{time.strftime('%H%M')}.txt", payload)

    except Exception as e:
        print(f"!!! Exception in websocket_message: {e} !!!")

def log_leak_websocket_flow(flow: http.HTTPFlow):
    try:
        entries = []
        for message in flow.websocket.messages:
            direction = "CLIENT -> SERVER" if message.from_client else "SERVER -> CLIENT"
            entries.append("-" * 20 + "\n")
            entries.append(f"Timestamp: {datetime.datetime.now().isoformat()}\n")
            entries.append(f"Direction: {direction}\n")
            entries.append(f"Data (hex):\n{message.content.hex()}\n")
            entries.append(f"Data (raw):\n{decrypt(message.content)}\n")
        entries.append("=================================\n")
        entries.append("=================================\n\n")
        LOGGER.log(f"{LEAK_LOG_FILE_PATH}_{time.strftime('%H%M')}.txt", "".join(entries))
    except Exception as e:
        print(f"Failed to log TCP message: {e}")

def websocket_start(flow: http.HTTPFlow) -> None:
    """
    Called when a client and server have completed the WebSocket handshake.
    """
    try:
        LOGGER.log(
            f"{LOG_FILE_PATH}_{time.strftime('%H%M')}.txt",
            f"WebSocket Connection Started: {flow.request.pretty_url}\n" + "-" * 20 + "\n",
        )
    except Exception as e:
        print(f"Failed to log WebSocket start: {e}")

def websocket_message(flow: http.HTTPFlow):
    """
    Called when a WebSocket message is sent or received.
    """
    log_websocket_flow(flow)

    if len(flow.websocket.messages) == 0:
        return

    message_obj = flow.websocket.messages[-1]

    if flow.metadata.get(_BLOCK_METADATA_KEY) and not message_obj.from_client:
        message_obj.content = b""
        flow.websocket.kill()
        return

    message = decrypt(message_obj.content)
    flags = FLAG_CACHE.get_flags()
    LEAKED = False

    if search_in_str(message, flags):
        log_leak_websocket_flow(flow)
        LEAKED = True

    if ENABLE_MODIFY:
        if LEAKED:
            for msg in flow.websocket.messages:
                if not msg.from_client:
                    continue

                try:
                    plain_prev_msg = decrypt(msg.content)
                except:
                    continue

                if search_in_str(plain_prev_msg, BLOCKED_STRINGS):
                    for f in flags:
                        message = message.replace(f, MODIFIED)
                    message_obj.content = str_to_bytes(encrypt(message))
                    break
    else:
        if message_obj.from_client and search_in_str(message, BLOCKED_STRINGS):
            flow.metadata[_BLOCK_METADATA_KEY] = True
            message_obj.content = str_to_bytes(encrypt("no hack"))
            flow.webosocket.kill()


def websocket_end(flow: http.HTTPFlow) -> None:
    """
    Called when a WebSocket connection is closed.
    """
    try:
        LOGGER.log(
            f"{LOG_FILE_PATH}_{time.strftime('%H%M')}.txt",
            f"WebSocket Connection Ended: {flow.request.pretty_url}\n" + "=" * 20 + "\n",
        )
    except Exception as e:
        print(f"Failed to log WebSocket end: {e}")
