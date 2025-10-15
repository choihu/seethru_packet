import pathlib

from utils.timing import get_current_round, pause
from utils.flag import update_flag

import json

PROB_NAME = "aquagate"

def get_latest_flag():
    records_dir = pathlib.Path("/cs/data/aquagate/records")
    if not records_dir.is_dir():
        raise FileNotFoundError(f"records directory not found: {records_dir}")

    operator_ids = []
    for p in records_dir.iterdir():
        if not p.is_file():
            continue
        try:
            raw = p.read_text(encoding="utf-8").strip()
            rec = json.loads(raw)
        except Exception:
            continue

        role = str(rec.get("role", ""))
        active = bool(rec.get("active", False))
        kid = rec.get("id")
        if active and role.lower() == "operator" and isinstance(kid, str) and kid:
            operator_ids.append(kid)

    return operator_ids

def main():
    while True:
        pause()
        latest_flag = get_latest_flag()
        if update_flag(PROB_NAME, latest_flag):
            print("update required")
            current_round = get_current_round()
            new_flag_file = FLAG_DIR / str(current_round)
            with open(new_flag_file, "w") as f:
                print(f"Writing to {new_flag_file.as_posix()}...")
                f.write(latest_flag)


if __name__ == "__main__":
    TARGET_FILE = "/cs/data/cargotracker/database.sql"
    FLAG_DIR = pathlib.Path(__file__).parent.parent.resolve() / PROB_NAME / "flags"
    print(FLAG_DIR)
    if not FLAG_DIR.is_dir():
        FLAG_DIR.mkdir(parents=True, exist_ok=True)
    main()