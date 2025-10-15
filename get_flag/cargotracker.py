import pathlib

from utils.timing import get_current_round, pause
from utils.flag import update_flag

PROB_NAME = "cargotracker"

def get_latest_flag():
    with open(TARGET_FILE, "r") as f:
        data = f.read()

    flag = data.split("VALUES (3020, '")[1].split("'")[0]
    return flag

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
    FLAG_DIR = pathlib.Path(__file__).parent.parent.resolve() / "flags" / PROB_NAME
    print(FLAG_DIR)
    if not FLAG_DIR.is_dir():
        FLAG_DIR.mkdir(parents=True, exist_ok=True)
    main()