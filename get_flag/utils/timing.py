import datetime
import pathlib
import pytz
import time
import yaml


BASE_DIR = pathlib.Path(__file__).parent.parent.parent.resolve()
SETTINGS_PATH = BASE_DIR / 'settings.yml'

with open(SETTINGS_PATH, 'r') as f:
    SETTINGS = yaml.safe_load(f)


def now() -> datetime.datetime:
    return datetime.datetime.now(pytz.timezone(SETTINGS["TZ"]))


def get_current_round() -> int:
    now_dt = now()
    round_period = datetime.timedelta(seconds=SETTINGS["round_period"])
    begin_dt = pytz.timezone(SETTINGS["TZ"]).localize(
        datetime.datetime.strptime(SETTINGS["schedules"]["begin"], "%Y-%m-%d %H:%M"))
    current_round = (now_dt - begin_dt) // round_period + 1
    return current_round


def pause():
    time.sleep(SETTINGS["get_flag_interval"])