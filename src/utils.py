import re
import binascii
import pickle
import json
from typing import Any

def decrypt(raw: str) -> str:
    plain = raw
    return plain

def encrypt(raw: str) -> str:
    cypher = raw
    return cypher

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

def search_in_str(string: str, search_list: list) -> bool:
    """
    string: origin str message, search_list: list of strings to find 
    If founded, return True. Else return False
    """
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