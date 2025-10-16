import re, os, time
import binascii
import pickle
import json
from pathlib import Path
from base64 import b64encode, b64decode
from typing import Any

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


def get_latest_flags(num_latest_rounds):
    now = time.time()
    if not FLAG_DIR.is_dir():
        return
    
    latest_flags = list()
    try:
        latest_flag_files = sorted(os.listdir(FLAG_DIR))[-num_latest_rounds:]
    except FileNotFoundError:
        return now, list()
    for flag_file in latest_flag_files:
        try:
            with open(FLAG_DIR / flag_file, "r", encoding="utf-8", errors="ignore") as f:
                data = f.readlines()
                latest_flags.extend([line.rstrip('\n') for line in data])
                latest_flags.extend([b64encode(line.rstrip('\n')) for line in data])
                latest_flags.extend([b64encode.b64encode(line.rstrip('\n')) for line in data])
        except Exception:
            continue
    return now, latest_flags