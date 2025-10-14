import pathlib


BASE_DIR = pathlib.Path(__file__).parent.parent.resolve()

def update_flag(name: str, flag: str) -> None:
    FLAG_DIRS = BASE_DIR / "flags" / name
    if not FLAG_DIRS.is_dir():
        FLAG_DIRS.mkdir(parents=True, exist_ok=True)
    flags = [f for f in FLAG_DIRS.iterdir() if f.is_file()]
    if not flags:
        return True
    else:
        latest_flag_file = sorted(flags)[-1]
        with open(latest_flag_file, "r") as f:
            latest_flag = f.read()
        return latest_flag != flag