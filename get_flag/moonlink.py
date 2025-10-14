import pathlib
import json

from utils.timing import get_current_round, pause
from utils.flag import update_flag

PROB_NAME = "moonlink"

def get_latest_flag():
    with open('data/moonlink/data.json') as f:
        data = json.load(f)

    flag = next(u['location'] for u in data['users'] if u['name'].lower() == 'kenobi')
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
    TARGET_FILE = "/cs/data/monnlink/data.json"
    FLAG_DIR = pathlib.Path(__file__).parent.parent.resolve() / PROB_NAME / "flags"
    print(FLAG_DIR)
    if not FLAG_DIR.is_dir():
        FLAG_DIR.mkdir(parents=True, exist_ok=True)
    main()